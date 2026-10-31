// src/utils.cpp

#include "utils.hpp"
#include "coverage.hpp"
#include "log.hpp"
#include <ctime>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <deque>
#include <string>
#include <utility>
#include <unistd.h>
#include <errno.h>
#include <charconv>
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sched.h>

namespace utils {

uint64_t get_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)(ts.tv_sec) * 1000ULL + (uint64_t)(ts.tv_nsec) / 1000000ULL;
}

void sleep_ms(int ms) {
    if (ms <= 0) return;
    struct timespec req;
    req.tv_sec = ms / 1000;
    req.tv_nsec = (ms % 1000) * 1000000L;
    
    // Handle potential interruptions by nanosleep
    while (nanosleep(&req, &req) == -1 && errno == EINTR) {
        // Continue sleeping the remaining time
    }
}

namespace {

// Directory that receives the termination dump pair. Overridden by
// set_data_dir() from the --data-dir CLI flag.
std::string g_data_dir = "afl-cassowire-data";

// Instance tag ("normal", "cmplog", "test") appended to termination dump file
// names and embedded into the .msg content. Empty by default (see
// set_instance_tag()).
std::string g_instance_tag;

// Current 1-based iteration of the proxy's __AFL_LOOP at the moment
// crash_proxy()/abort_proxy() fire; written as a dedicated "iteration: N"
// line into the .msg dump. 0 (the default) means the termination happened
// outside the loop (start-up path) or in test mode; see
// set_current_iteration().
uint64_t g_current_iteration = 0;

// One entry per retained completed iteration: the raw AFL testcase, the built
// payload, and the iteration's presence edge ids (only collected when history
// dedup is enabled). Written to the dump directory as .data/.input pairs.
struct DumpRingEntry {
    std::vector<uint8_t> raw;
    std::vector<uint8_t> payload;
    std::vector<uint32_t> edges;
};

// Retained entries of the last completed iterations, oldest first. Written
// alongside a termination dump as <stem>.-1.data/.input (most recent), -2, ...
// so a deferred/async crash detected one iteration late still preserves the
// input that likely caused it. Bounded by g_dump_history_max; empty when
// disabled.
std::deque<DumpRingEntry> g_dump_history;
std::size_t g_dump_history_max = 0;

// afl.history_dedup: filter the retained entries by coverage footprint at dump
// time (see set_history_dedup()).
bool g_history_dedup = false;

// Unstable-edge mask registered by run_proxy_mode(); may be null.
const coverage::VarBytesMask* g_var_bytes_mask = nullptr;

// Maximum number of bytes of a captured warn/error history line embedded into
// the .msg file. History lines are short in practice (repeated per-iteration
// failures are throttled by the callers); the cap is purely defensive.
constexpr size_t k_recent_line_cap = 2048;

// Creates g_data_dir recursively. Best-effort: a failure is logged but never
// aborts the dump attempt (or the process).
void ensure_data_dir() {
    std::error_code ec;
    std::filesystem::create_directories(g_data_dir, ec);
    if (ec) {
        PROXY_LOG_ERROR("termination dump: cannot create data dir '{}': {}",
                        g_data_dir, ec.message());
    }
}

// Builds a filesystem-safe, sortable wall-clock timestamp:
//   YYYYmmdd-HHMMSS-mmm
std::string make_timestamp() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm_buf;
    localtime_r(&ts.tv_sec, &tm_buf);

    char buf[32];
    size_t n = std::strftime(buf, sizeof(buf), "%Y%m%d-%H%M%S", &tm_buf);
    std::snprintf(buf + n, sizeof(buf) - n, "-%03ld",
                  static_cast<long>(ts.tv_nsec / 1000000L));
    return std::string(buf);
}

// write(2) loop for an already-open fd. EINTR is retried; other failures are
// logged and reported to the caller.
bool write_all(int fd, const void* data, size_t len, const std::string& path) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    size_t off = 0;
    while (off < len) {
        ssize_t w = ::write(fd, p + off, len - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            PROXY_LOG_ERROR("termination dump: write '{}' failed: {}", path,
                            std::strerror(errno));
            return false;
        }
        off += static_cast<size_t>(w);
    }
    return true;
}

// Creates/truncates `path` and writes `len` bytes to it. Best-effort.
void write_named_file(const std::string& path, const void* data, size_t len) {
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        PROXY_LOG_ERROR("termination dump: cannot open '{}': {}", path,
                        std::strerror(errno));
        return;
    }
    FdGuard guard{fd};
    write_all(fd, data, len, path);
}

// 64-bit FNV-1a over the edge ids. Collisions are handled by comparing the
// filtered edge lists themselves, so this only has to be cheap and stable.
uint64_t footprint_hash(std::span<const uint32_t> edges) {
    uint64_t hash = 1469598103934665603ULL;
    for (const uint32_t edge : edges) {
        for (int shift = 0; shift < 32; shift += 8) {
            hash ^= (edge >> shift) & 0xFFu;
            hash *= 1099511628211ULL;
        }
    }
    return hash;
}

// Drops edge ids the mask marks unstable. Edge ids past the mask are kept: the
// var_bytes bitmap may be shorter than the coverage view (it is sized by the
// fuzzer's map, which can differ while the target is being respawned).
std::vector<uint32_t> apply_mask(std::span<const uint32_t> edges,
                                 const std::vector<uint8_t>& mask) {
    std::vector<uint32_t> out;
    out.reserve(edges.size());
    for (const uint32_t edge : edges) {
        if (edge < mask.size() && mask[edge] != 0) continue;
        out.push_back(edge);
    }
    return out;
}

// Writes the termination pair into g_data_dir. The `.data` file is created
// first with O_EXCL to reserve a unique timestamp; on collision the stem gets
// a numeric suffix so `.msg` and `.data` always share one stem. The instance
// tag (when set) is appended to the stem and embedded into the `.msg` content
// so dumps from concurrent instances stay attributable. Best-effort: no
// failure here prevents the subsequent signal.
void dump_termination_data(std::string_view kind, std::string_view message,
                           std::span<const uint8_t> data,
                           std::span<const uint8_t> raw,
                           std::span<const uint32_t> edges) {
    ensure_data_dir();

    std::string stem;
    FdGuard data_fd;
    for (int attempt = 0; attempt < 1000; ++attempt) {
        stem = g_data_dir + "/" + make_timestamp();
        if (!g_instance_tag.empty()) {
            stem += "-" + g_instance_tag;
        }
        if (attempt > 0) {
            stem += "-" + std::to_string(attempt);
        }
        int fd = ::open((stem + ".data").c_str(),
                        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
        if (fd >= 0) {
            data_fd = FdGuard{fd};
            break;
        }
        if (errno != EEXIST) {
            PROXY_LOG_ERROR("termination dump: cannot create '{}.data': {}", stem,
                            std::strerror(errno));
            return;
        }
    }
    if (data_fd.get() < 0) {
        PROXY_LOG_ERROR("termination dump: could not allocate a unique name in '{}'",
                        g_data_dir);
        return;
    }

    write_all(data_fd.get(), data.data(), data.size(), stem + ".data");
    // The raw testcase (what `test --input` and AFL itself consume) next to the
    // built payload, so dumps stay replayable through prefix/suffix/sequence
    // configuration without reconstructing it by hand. Written even when the
    // testcase is empty (a zero-length input is a valid AFL testcase).
    write_named_file(stem + ".input", raw.data(), raw.size());

    const std::size_t n = g_dump_history.size();

    // Unstable-edge mask (afl.var_bytes_method). Loaded lazily: the afl-fuzz
    // bitmap grows over the campaign, so a mask read at dump time is the most
    // complete one available.
    std::vector<uint8_t> mask;
    bool have_mask = false;
    if (g_history_dedup && n > 0 && g_var_bytes_mask != nullptr) {
        have_mask = g_var_bytes_mask->load(mask);
    }

    // Footprints: presence edges minus the unstable-edge mask.
    std::vector<std::vector<uint32_t>> footprints(n);
    std::vector<uint64_t> hashes(n, 0);
    bool any_edges = false;
    for (std::size_t i = 0; i < n; ++i) {
        if (have_mask) {
            footprints[i] = apply_mask(g_dump_history[i].edges, mask);
        } else {
            footprints[i].assign(g_dump_history[i].edges.begin(),
                                 g_dump_history[i].edges.end());
        }
        hashes[i] = footprint_hash(footprints[i]);
        if (!footprints[i].empty()) any_edges = true;
    }

    // Retention: every footprint contributes its oldest and its newest
    // iteration (so a repeated input that triggers a state-dependent crash in
    // an older/newer incarnation survives), and the two newest entries are
    // always kept (deferred-crash window). With no coverage information at all
    // the filter would only guess, so everything is kept.
    std::vector<bool> keep(n, true);
    std::vector<std::string> notes(n);
    if (g_history_dedup && n > 0 && any_edges) {
        keep.assign(n, false);

        // Group equal footprints (hash prefilter, exact list compare).
        std::vector<std::vector<std::size_t>> groups;
        for (std::size_t i = 0; i < n; ++i) {
            bool placed = false;
            for (auto& members : groups) {
                const std::size_t rep = members.front();
                if (hashes[rep] == hashes[i] && footprints[rep] == footprints[i]) {
                    members.push_back(i);
                    placed = true;
                    break;
                }
            }
            if (!placed) groups.push_back({i});
        }

        for (const auto& members : groups) {
            keep[members.front()] = true;
            keep[members.back()] = true;
            if (members.size() > 1) {
                const std::string first = " (first of footprint)";
                const std::string last = " (last of footprint)";
                notes[members.front()] += first;
                notes[members.back()] += last;
            }
        }
        keep[n - 1] = true;
        notes[n - 1] += " (newest)";
        if (n >= 2) {
            keep[n - 2] = true;
            notes[n - 2] += " (2nd newest)";
        }
    }

    // History: the retained iterations, newest first, as <stem>.-N.data /
    // <stem>.-N.input. These are the inputs that preceded the current one,
    // kept because a deferred/async crash is detected one iteration late and
    // the current payload may not be the culprit.
    std::size_t history_written = 0;
    std::size_t history_dropped = 0;
    for (std::size_t i = 0; i < n; ++i) {
        const std::size_t distance = n - i;  // .-1 = newest previous iteration
        const std::string suffix = ".-" + std::to_string(distance);
        if (!keep[i]) {
            ++history_dropped;
            continue;
        }
        const DumpRingEntry& entry = g_dump_history[i];
        write_named_file(stem + suffix + ".data", entry.payload.data(), entry.payload.size());
        write_named_file(stem + suffix + ".input", entry.raw.data(), entry.raw.size());
        ++history_written;
    }

    std::string msg = std::string(kind);
    if (!g_instance_tag.empty()) {
        msg += "[" + g_instance_tag + "]";
    }
    msg += ": " + std::string(message) + "\n";

    // Current __AFL_LOOP iteration (1-based; 0 = termination outside the
    // loop). Lets a dump be correlated with the periodic heartbeat lines,
    // which count completed iterations.
    msg += "iteration: " + std::to_string(g_current_iteration) + "\n";
    if (!raw.empty()) {
        msg += "current input: " + std::to_string(raw.size()) + " raw byte(s) in .input\n";
    }
    if (!edges.empty()) {
        msg += "current coverage: " + std::to_string(edges.size()) + " edge(s)\n";
    }

    // Map the retained history files to their iteration numbers so a dump can
    // be read without knowing the file layout: .-1.data is the most recent
    // previous iteration, .-2.data the one before that, and so on.
    if (n > 0) {
        msg += "\n--- dump history (previous iterations; .data = built payload, "
               ".input = raw testcase) ---\n";
        if (g_history_dedup) {
            msg += "dedup: on (afl.history_dedup)";
            if (g_var_bytes_mask == nullptr) {
                msg += ", mask: not registered";
            } else if (have_mask) {
                msg += ", mask: ";
                msg += g_var_bytes_mask->source_name();
                if (g_var_bytes_mask->source() == coverage::VarBytesMask::Source::stats &&
                    !g_var_bytes_mask->stats_path().empty()) {
                    msg += " (" + g_var_bytes_mask->stats_path() + ")";
                }
                msg += ", " + std::to_string(mask.size()) + " byte(s)";
            } else if (g_var_bytes_mask->source() == coverage::VarBytesMask::Source::off) {
                msg += ", mask: off";
            } else {
                msg += ", mask: ";
                msg += g_var_bytes_mask->source_name();
                msg += " (unavailable; unmasked footprints)";
            }
            msg += "\n";
            msg += "kept " + std::to_string(history_written) + " of " + std::to_string(n) +
                   " history entr" + (n == 1 ? "y" : "ies") + "\n";
        } else {
            msg += "dedup: off\n";
        }
        for (std::size_t i = 0; i < n; ++i) {
            const std::size_t distance = n - i;
            const uint64_t hist_iter =
                g_current_iteration >= distance ? g_current_iteration - distance : 0;
            msg += ".-" + std::to_string(distance) + ".data = iteration " +
                   std::to_string(hist_iter) + ", " +
                   std::to_string(g_dump_history[i].edges.size()) + " edge(s), fp " +
                   std::to_string(hashes[i]);
            if (keep[i]) {
                msg += " [kept]" + notes[i];
            } else {
                msg += " [dropped: same footprint as an older/newer entry]";
            }
            msg += "\n";
        }
    }

    // Embed the recent warn/error history (oldest first, captured by the
    // logger's ring sink) so the dump carries the context that preceded the
    // termination. The final termination line itself is deliberately not part
    // of the history - it is the reason line above.
    const std::vector<std::string> recent = casslog::recent_lines();
    if (!recent.empty()) {
        msg += "\n--- last warn/error lines (oldest first) ---\n";
        for (const std::string& line : recent) {
            msg += line.substr(0, k_recent_line_cap);
            if (line.size() > k_recent_line_cap) {
                msg += "...";
            }
            if (msg.back() != '\n') {
                msg += '\n';
            }
        }
    }
    write_named_file(stem + ".msg", msg.data(), msg.size());

    if (n > 0) {
        PROXY_LOG_INFO("termination dump written: {}.msg / {}.data / {}.input / {} history entr{} ({} dropped)",
                       stem, stem, stem, history_written, history_written == 1 ? "y" : "ies",
                       history_dropped);
    } else {
        PROXY_LOG_INFO("termination dump written: {}.msg / {}.data / {}.input",
                       stem, stem, stem);
    }
}

// Shared implementation of crash_proxy()/abort_proxy(): dump, log, then raise
// `sig` (with abort()/_exit() fallbacks in case the signal is blocked/ignored).
[[noreturn]] void terminate_proxy(int sig, int exit_code, std::string_view kind,
                                  std::string_view message,
                                  std::span<const uint8_t> input,
                                  std::span<const uint8_t> raw,
                                  std::span<const std::uint32_t> edges) {
    dump_termination_data(kind, message, input, raw, edges);
    if (g_instance_tag.empty()) {
        PROXY_LOG_ERROR("{}: {}", kind, message);
    } else {
        PROXY_LOG_ERROR("{}[{}]: {}", kind, g_instance_tag, message);
    }
    raise(sig);
    abort();
    _exit(exit_code);
}

} // namespace

void set_data_dir(std::string dir) {
    if (dir.empty()) return;
    g_data_dir = std::move(dir);
    ensure_data_dir();
}

void set_instance_tag(std::string tag) {
    g_instance_tag = std::move(tag);
}

void set_current_iteration(uint64_t n) {
    g_current_iteration = n;
}

void set_dump_history_size(std::size_t n) {
    g_dump_history_max = n;
    while (g_dump_history.size() > g_dump_history_max) {
        g_dump_history.pop_front();
    }
}

void set_history_dedup(bool enabled) {
    g_history_dedup = enabled;
}

void set_var_bytes_mask(const coverage::VarBytesMask* mask) {
    g_var_bytes_mask = mask;
}

void record_dump_input(std::span<const uint8_t> raw,
                       std::span<const uint8_t> payload,
                       std::span<const std::uint32_t> edges) {
    if (g_dump_history_max == 0) return;
    DumpRingEntry entry;
    entry.raw.assign(raw.begin(), raw.end());
    entry.payload.assign(payload.begin(), payload.end());
    entry.edges.assign(edges.begin(), edges.end());
    g_dump_history.push_back(std::move(entry));
    while (g_dump_history.size() > g_dump_history_max) {
        g_dump_history.pop_front();
    }
}

[[noreturn]] void crash_proxy(std::string_view message, std::span<const uint8_t> input,
                              std::span<const uint8_t> raw,
                              std::span<const std::uint32_t> edges) {
    terminate_proxy(SIGSEGV, 139, "crash_proxy", message, input, raw, edges);
}

[[noreturn]] void abort_proxy(std::string_view message, std::span<const uint8_t> input,
                              std::span<const uint8_t> raw,
                              std::span<const std::uint32_t> edges) {
    terminate_proxy(SIGABRT, 134, "abort_proxy", message, input, raw, edges);
}

namespace {

template <typename T>
std::variant<T, ParseError> parse_uint_impl(std::string_view s, int base) {
    T value = 0;
    const char* const end = s.data() + s.size();
    auto [ptr, ec] = std::from_chars(s.data(), end, value, base);

    if (ec != std::errc{})  return ParseError{ec};
    if (ptr != end)         return ParseError{CustomParseError::TrailingCharacters};
    return value;
}

} // namespace

[[nodiscard]] ParseResult parse_u64_strict(std::string_view s, int base) {
    return parse_uint_impl<std::uint64_t>(s, base);
}

[[nodiscard]] U8ParseResult parse_u8_strict(std::string_view s, int base) {
    return parse_uint_impl<std::uint8_t>(s, base);
}

[[nodiscard]] U16ParseResult parse_u16_strict(std::string_view s, int base) {
    return parse_uint_impl<std::uint16_t>(s, base);
}

[[nodiscard]] U32ParseResult parse_u32_strict(std::string_view s, int base) {
    return parse_uint_impl<std::uint32_t>(s, base);
}


ReadResult read_fd(int fd, size_t max_bytes) {
    std::vector<uint8_t> buffer;
    uint8_t chunk[4096];

    for (;;) {
        ssize_t n = ::read(fd, chunk, sizeof(chunk));
        if (n > 0) {
            if (buffer.size() + static_cast<size_t>(n) > max_bytes)
                return std::make_error_code(std::errc::file_too_large);
            buffer.insert(buffer.end(), chunk, chunk + n);
        } else if (n == 0) {
            break;
        } else {
            if (errno == EINTR) continue;
            return std::error_code(errno, std::system_category());
        }
    }
    return buffer;
}

ReadResult read_file(std::string_view path, size_t max_bytes) {
    if (path.find('\0') != std::string_view::npos)
        return std::make_error_code(std::errc::invalid_argument);

    int fd = ::open(std::string(path).c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return std::error_code(errno, std::system_category());

    FdGuard guard{fd};
    return read_fd(fd, max_bytes);
}

ReadResult read_stdin(size_t max_bytes) {
    return read_fd(STDIN_FILENO, max_bytes);
}

ReadResult read_input_file(std::string_view path, size_t max_bytes) {
    return (path == "-") ? read_stdin(max_bytes) : read_file(path, max_bytes);
}

std::string get_cpu_affinity() {
    cpu_set_t set;
    if (sched_getaffinity(0, sizeof(cpu_set_t), &set) != 0) {
        return "<unavailable>";
    }
    
    std::string result;
    bool first = true;
    for (int i = 0; i < CPU_SETSIZE; ++i) {
        if (CPU_ISSET(i, &set)) {
            if (!first) {
                result += ",";
            }
            result += std::to_string(i);
            first = false;
        }
    }
    
    if (result.empty()) {
        return "none";
    }
    return result;
}

} // namespace utils