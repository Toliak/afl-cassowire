// src/coverage.hpp

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace coverage {

/// AFL++ rounds the announced map size up to this granularity before using it
/// as the per-execution memset()/has_new_bits() window. A snapshot must cover
/// exactly that range and never more: the 4-byte persistent-sync word lives
/// right past it in the same SysV segment.
constexpr std::size_t kMapSizeGranule = 64;

/// @brief Size of the coverage view afl-fuzz reads for an announced map size.
///
/// The runtime announces `__afl_final_loc + 1`; afl-fuzz rounds that up to
/// `kMapSizeGranule` and uses the result for both its per-execution memset and
/// its novelty scan. Anything past it (the futex sync word) must not be
/// snapshotted.
constexpr std::size_t map_view_size(std::size_t announced) {
    return (announced + (kMapSizeGranule - 1)) & ~(kMapSizeGranule - 1);
}

// struct cmp_map layout (aflpp/src/include/cmplog.h):
//   struct cmp_header   headers[CMP_MAP_W];             // packed, 2 bytes
//   struct cmp_operands log[CMP_MAP_W][CMP_MAP_H];      // packed, 72 bytes
//   u32                 site_ids[CMP_MAP_W];
//   u16                 attributes[CMP_MAP_W];
//
// Only the metadata is snapshotted: the `hits` counter in each header gates
// how many log slots the fuzzer reads, while the log is written through a
// per-key cursor that lives inside the target process and cannot be rewound
// from here. Rewinding `hits` therefore hides the probe's comparisons from
// redqueen without touching the 151 MB log; the touched keys re-align within
// a bounded number of records (and at the next colorization clear).
constexpr std::size_t kCmpMapW = 65536;
constexpr std::size_t kCmpMapH = 32;
constexpr std::size_t kCmpHeaderBytes = kCmpMapW * 2;
constexpr std::size_t kCmpOperandsBytes = 72;
constexpr std::size_t kCmpLogBytes = kCmpMapW * kCmpMapH * kCmpOperandsBytes;
constexpr std::size_t kCmpSiteIdBytes = kCmpMapW * 4;
constexpr std::size_t kCmpAttributeBytes = kCmpMapW * 2;
constexpr std::size_t kCmpMapBytes =
    kCmpHeaderBytes + kCmpLogBytes + kCmpSiteIdBytes + kCmpAttributeBytes;

/**
 * @brief Snapshot window over the shared coverage / compare-log maps.
 *
 * afl-fuzz creates the SysV segment and both the proxy and the target map it;
 * the target is the only coverage writer. The proxy attaches the same segment
 * itself (shmat on `__AFL_SHM_ID`) so it can snapshot the map as the input
 * exchange left it and restore it after the post-response quiescence probe and
 * health checks, which must not be attributed to the testcase.
 *
 * `attach_cov()`/`attach_cmp()` are best-effort: on any mismatch (e.g. an
 * AFL++ version whose cmp_map layout differs) they return false with a
 * message, and the caller continues without that part of the window.
 *
 * Not thread-safe; the proxy is single-threaded.
 */
class MapWindow {
public:
    MapWindow() = default;
    ~MapWindow();

    MapWindow(const MapWindow&) = delete;
    MapWindow& operator=(const MapWindow&) = delete;

    /**
     * @brief Attaches the coverage segment and sizes the snapshot buffer.
     *
     * @param shm_id           Numeric SysV id from `__AFL_SHM_ID`.
     * @param announced_map_size Map size the runtime announced to afl-fuzz
     *                           (`__afl_final_loc + 1`).
     * @param error            Receives the reason on failure.
     * @return true when the window is armed.
     */
    bool attach_cov(int shm_id, std::size_t announced_map_size, std::string& error);

    /**
     * @brief Attaches the compare-log segment and sizes the metadata buffer.
     *
     * @param shm_id Numeric SysV id from `__AFL_CMPLOG_SHM_ID`.
     * @param error  Receives the reason on failure.
     * @return true when the compare-log metadata window is armed.
     */
    bool attach_cmp(int shm_id, std::string& error);

    /// @brief True when the coverage snapshot is armed.
    [[nodiscard]] bool cov_attached() const noexcept { return cov_ptr_ != nullptr; }
    /// @brief True when the compare-log metadata snapshot is armed.
    [[nodiscard]] bool cmp_attached() const noexcept { return cmp_ptr_ != nullptr; }
    /// @brief True when at least one snapshot is armed.
    [[nodiscard]] bool active() const noexcept { return cov_attached() || cmp_attached(); }

    /// @brief Size of the armed coverage snapshot in bytes (0 when disarmed).
    [[nodiscard]] std::size_t cov_len() const noexcept { return cov_len_; }

    /// @brief Copies the current map(s) into the snapshot buffers.
    void capture();

    /// @brief Writes the snapshots back into the shared map(s).
    void restore();

private:
    void detach() noexcept;

    std::uint8_t* cov_ptr_ = nullptr;
    std::size_t cov_len_ = 0;
    std::vector<std::uint8_t> cov_snapshot_;

    std::uint8_t* cmp_ptr_ = nullptr;
    std::vector<std::uint8_t> cmp_snapshot_;
};

} // namespace coverage
