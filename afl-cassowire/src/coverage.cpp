// src/coverage.cpp

#include "coverage.hpp"

#include "log.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <limits>
#include <string_view>
#include <sys/ipc.h>
#include <sys/shm.h>

namespace coverage {

std::vector<std::uint32_t> presence_edges(const std::uint8_t* map, std::size_t len) {
    std::vector<std::uint32_t> edges;
    if (map == nullptr) return edges;
    for (std::size_t i = 0; i < len; ++i) {
        if (map[i] != 0) {
            edges.push_back(static_cast<std::uint32_t>(i));
        }
    }
    return edges;
}

namespace {

/// @brief shmat()s a SysV segment and returns its size via shmctl().
///
/// @param shm_id   Numeric SysV id.
/// @param out_ptr  Receives the mapping base on success.
/// @param out_size Receives the segment size in bytes on success.
/// @param error    Receives the reason on failure.
/// @return true on success.
bool attach_segment(int shm_id, std::uint8_t*& out_ptr, std::size_t& out_size, std::string& error) {
    if (shm_id < 0) {
        error = "invalid SysV shm id";
        return false;
    }

    struct shmid_ds ds {};
    if (shmctl(shm_id, IPC_STAT, &ds) != 0) {
        error = std::string("shmctl(IPC_STAT) failed: ") + std::strerror(errno);
        return false;
    }

    void* ptr = shmat(shm_id, nullptr, 0);
    if (ptr == reinterpret_cast<void*>(-1)) {
        error = std::string("shmat failed: ") + std::strerror(errno);
        return false;
    }

    out_ptr = static_cast<std::uint8_t*>(ptr);
    out_size = static_cast<std::size_t>(ds.shm_segsz);
    return true;
}

} // namespace

MapWindow::~MapWindow() {
    detach();
}

bool MapWindow::attach_cov(int shm_id, std::size_t announced_map_size, std::string& error) {
    const std::size_t len = map_view_size(announced_map_size);
    if (len == 0) {
        error = "announced map size is zero";
        return false;
    }

    std::uint8_t* ptr = nullptr;
    std::size_t seg_size = 0;
    if (!attach_segment(shm_id, ptr, seg_size, error)) {
        return false;
    }

    if (len > seg_size) {
        (void)shmdt(ptr);
        error = "coverage map view of " + std::to_string(len) +
                " bytes does not fit the " + std::to_string(seg_size) + "-byte segment";
        return false;
    }

    cov_ptr_ = ptr;
    cov_len_ = len;
    cov_snapshot_.resize(len);
    return true;
}

bool MapWindow::attach_cmp(int shm_id, std::string& error) {
    std::uint8_t* ptr = nullptr;
    std::size_t seg_size = 0;
    if (!attach_segment(shm_id, ptr, seg_size, error)) {
        return false;
    }

    // Exact match: the offsets below are pinned to the struct layout of the
    // AFL++ this proxy is built against. A different size means the layout
    // moved; refuse rather than snapshot the wrong bytes.
    if (seg_size != kCmpMapBytes) {
        (void)shmdt(ptr);
        error = "cmplog map is " + std::to_string(seg_size) + " bytes, expected " +
                std::to_string(kCmpMapBytes) + " (AFL++ struct cmp_map layout mismatch)";
        return false;
    }

    cmp_ptr_ = ptr;
    cmp_snapshot_.resize(kCmpHeaderBytes);
    return true;
}

void MapWindow::capture() {
    if (cov_ptr_ != nullptr) {
        std::memcpy(cov_snapshot_.data(), cov_ptr_, cov_len_);
    }
    if (cmp_ptr_ != nullptr) {
        std::memcpy(cmp_snapshot_.data(), cmp_ptr_, kCmpHeaderBytes);
    }
}

void MapWindow::restore() {
    if (cov_ptr_ != nullptr && cov_restore_) {
        std::memcpy(cov_ptr_, cov_snapshot_.data(), cov_len_);
    }
    if (cmp_ptr_ != nullptr) {
        std::memcpy(cmp_ptr_, cmp_snapshot_.data(), kCmpHeaderBytes);
    }
}

void MapWindow::detach() noexcept {
    if (cov_ptr_ != nullptr) {
        (void)shmdt(cov_ptr_);
        cov_ptr_ = nullptr;
        cov_len_ = 0;
    }
    if (cmp_ptr_ != nullptr) {
        (void)shmdt(cmp_ptr_);
        cmp_ptr_ = nullptr;
    }
}

// ---------------------------------------------------------------------------
// VarBytesMask
// ---------------------------------------------------------------------------

namespace {

// Upper bound for the stats bitmap. The coverage view is at most a few MiB; a
// fuzzer_stats line that asks for more is treated as corrupt instead of
// allocating an attacker-controlled buffer.
constexpr std::uint32_t kMaxMaskIndex = (1u << 24) - 1;

// Parses one whitespace-separated decimal u32. Returns false on overflow or
// trailing junk.
bool parse_u32(std::string_view token, std::uint32_t& out) {
    if (token.empty()) return false;
    std::uint32_t value = 0;
    for (char c : token) {
        if (c < '0' || c > '9') return false;
        const std::uint32_t digit = static_cast<std::uint32_t>(c - '0');
        if (value > (std::numeric_limits<std::uint32_t>::max() - digit) / 10) return false;
        value = value * 10 + digit;
    }
    out = value;
    return true;
}

} // namespace

VarBytesMask::~VarBytesMask() {
    detach();
}

void VarBytesMask::use_off() noexcept {
    detach();
    source_ = Source::off;
    stats_path_.clear();
}

void VarBytesMask::use_stats(std::string stats_path) {
    detach();
    source_ = Source::stats;
    stats_path_ = std::move(stats_path);
}

bool VarBytesMask::attach_shm(int shm_id, std::string& error) {
    detach();
    std::uint8_t* ptr = nullptr;
    std::size_t seg_size = 0;
    if (!attach_segment(shm_id, ptr, seg_size, error)) {
        source_ = Source::off;
        return false;
    }
    shm_ = ptr;
    shm_len_ = seg_size;
    source_ = Source::shm;
    return true;
}

const char* VarBytesMask::source_name() const noexcept {
    switch (source_) {
    case Source::shm: return "shm";
    case Source::stats: return "stats";
    case Source::off: break;
    }
    return "off";
}

bool VarBytesMask::load(std::vector<std::uint8_t>& out) const {
    out.clear();
    switch (source_) {
    case Source::off:
        return false;
    case Source::shm:
        if (shm_ == nullptr) return false;
        out.assign(shm_, shm_ + shm_len_);
        return true;
    case Source::stats:
        return load_stats(out);
    }
    return false;
}

bool VarBytesMask::load_stats(std::vector<std::uint8_t>& out) const {
    out.clear();
    if (stats_path_.empty()) {
        if (!warn_once_) {
            warn_once_ = true;
            PROXY_LOG_WARN("history dedup: var_bytes_method is 'stats' but neither "
                           "afl.var_bytes_stats_path nor AFL_CASSOWIRE_STATS_PATH is set; "
                           "history dedup runs unmasked");
        }
        return false;
    }

    std::ifstream in(stats_path_);
    if (!in) {
        if (!warn_once_) {
            warn_once_ = true;
            PROXY_LOG_WARN("history dedup: cannot open fuzzer_stats '{}'; "
                           "history dedup runs unmasked", stats_path_);
        }
        return false;
    }

    std::string line;
    while (std::getline(in, line)) {
        std::size_t pos = line.find_first_not_of(" \t\r");
        if (pos == std::string::npos) continue;
        std::string_view rest(line.data() + pos, line.size() - pos);
        constexpr std::string_view key = "var_bytes";
        if (rest.substr(0, key.size()) != key) continue;
        rest.remove_prefix(key.size());
        pos = rest.find_first_not_of(" \t\r");
        if (pos == std::string::npos || rest[pos] != ':') continue;
        rest.remove_prefix(pos + 1);

        std::vector<std::uint32_t> indices;
        while (true) {
            pos = rest.find_first_not_of(" \t\r");
            if (pos == std::string::npos) break;
            rest.remove_prefix(pos);
            const std::size_t end = rest.find_first_of(" \t\r");
            const std::string_view token = rest.substr(0, end);
            std::uint32_t index = 0;
            if (!parse_u32(token, index) || index > kMaxMaskIndex) {
                if (!warn_once_) {
                    warn_once_ = true;
                    PROXY_LOG_WARN("history dedup: malformed var_bytes entry '{}' in '{}'; "
                                   "history dedup runs unmasked",
                                   std::string(token), stats_path_);
                }
                return false;
            }
            indices.push_back(index);
            if (end == std::string_view::npos) break;
            rest.remove_prefix(end);
        }

        if (indices.empty()) return true;  // mask present but empty: nothing unstable
        const std::uint32_t max_index = *std::max_element(indices.begin(), indices.end());
        out.assign(static_cast<std::size_t>(max_index) + 1, 0);
        for (std::uint32_t index : indices) {
            out[index] = 1;
        }
        return true;
    }

    if (!warn_once_) {
        warn_once_ = true;
        PROXY_LOG_WARN("history dedup: no 'var_bytes' line in '{}' (stock AFL++ emits it "
                       "only with AFL_DEBUG=1); history dedup runs unmasked", stats_path_);
    }
    return false;
}

void VarBytesMask::detach() noexcept {
    if (shm_ != nullptr) {
        (void)shmdt(shm_);
        shm_ = nullptr;
        shm_len_ = 0;
    }
}

} // namespace coverage
