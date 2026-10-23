// src/utils.cpp

#include "utils.hpp"
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

// Retained payloads of the last completed iterations, oldest first. Written
// alongside a termination dump as <stem>.-1.data (most recent), -2, ... so a
// deferred/async crash detected one iteration late still preserves the input
// that likely caused it. Bounded by g_dump_history_max; empty when disabled.
std::deque<std::vector<uint8_t>> g_dump_history;
std::size_t g_dump_history_max = 0;

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

// Writes the termination pair into g_data_dir. The `.data` file is created
// first with O_EXCL to reserve a unique timestamp; on collision the stem gets
// a numeric suffix so `.msg` and `.data` always share one stem. The instance
// tag (when set) is appended to the stem and embedded into the `.msg` content
// so dumps from concurrent instances stay attributable. Best-effort: no
// failure here prevents the subsequent signal.
void dump_termination_data(std::string_view kind, std::string_view message,
                           std::span<const uint8_t> data) {
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

    // History: the payloads of the last completed iterations, newest first, as
    // <stem>.-1.data, <stem>.-2.data, ... These are the inputs that preceded the
    // current one, kept because a deferred/async crash is detected one iteration
    // late and the current payload may not be the culprit.
    std::size_t history_written = 0;
    for (auto it = g_dump_history.rbegin(); it != g_dump_history.rend(); ++it) {
        const std::string path = stem + ".-" + std::to_string(history_written + 1) + ".data";
        write_named_file(path, it->data(), it->size());
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

    // Map the retained history files to their iteration numbers so a dump can be
    // read without knowing the file layout: .-1.data is the most recent previous
    // iteration, .-2.data the one before that, and so on.
    if (history_written > 0) {
        msg += "\n--- dump history (previous iterations, same payload format as .data) ---\n";
        for (std::size_t i = 1; i <= history_written; ++i) {
            const uint64_t hist_iter =
                g_current_iteration >= i ? g_current_iteration - static_cast<uint64_t>(i) : 0;
            msg += ".-" + std::to_string(i) + ".data = iteration "
                   + std::to_string(hist_iter) + "\n";
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

    if (history_written > 0) {
        PROXY_LOG_INFO("termination dump written: {}.msg / {}.data / {} history file(s) (.-1.data ... .-{}.data)",
                       stem, stem, history_written, history_written);
    } else {
        PROXY_LOG_INFO("termination dump written: {}.msg / {}.data", stem, stem);
    }
}

// Shared implementation of crash_proxy()/abort_proxy(): dump, log, then raise
// `sig` (with abort()/_exit() fallbacks in case the signal is blocked/ignored).
[[noreturn]] void terminate_proxy(int sig, int exit_code, std::string_view kind,
                                  std::string_view message,
                                  std::span<const uint8_t> input) {
    dump_termination_data(kind, message, input);
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

void record_dump_input(std::span<const uint8_t> input) {
    if (g_dump_history_max == 0) return;
    g_dump_history.emplace_back(input.begin(), input.end());
    while (g_dump_history.size() > g_dump_history_max) {
        g_dump_history.pop_front();
    }
}

[[noreturn]] void crash_proxy(std::string_view message, std::span<const uint8_t> input) {
    terminate_proxy(SIGSEGV, 139, "crash_proxy", message, input);
}

[[noreturn]] void abort_proxy(std::string_view message, std::span<const uint8_t> input) {
    terminate_proxy(SIGABRT, 134, "abort_proxy", message, input);
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