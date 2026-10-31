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

/// @brief Edge ids (map indices) whose byte is non-zero in a coverage view.
///
/// afl-fuzz bucketizes hit counts in the map bytes, so a non-zero byte means
/// "edge hit at least once". Presence (rather than the raw byte value) is what
/// the history-dedup footprints compare: hit counts change between otherwise
/// identical executions far more often than presence does.
///
/// @param map Coverage view (may be null when @p len is zero).
/// @param len Number of bytes in @p map.
/// @return Ascending edge ids.
std::vector<std::uint32_t> presence_edges(const std::uint8_t* map, std::size_t len);

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
// Only the headers are snapshotted: the `hits` counter in each header gates
// how many log slots the fuzzer reads, so restoring the 128 KB header array is
// enough to hide the probe's comparisons from redqueen. site_ids/attributes
// are deliberately left alone: the target's cmplog_reserve() only writes them
// when a key's hits is 0, so the probe cannot change them for keys the exchange
// touched; for probe-only keys the restored hits is 0, so the fuzzer does not
// read them and the next comparison re-initialises the key. Copying all
// metadata (512 KB) instead would quadruple the per-iteration cost.
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
     * @brief Attaches the compare-log segment and sizes the header snapshot.
     *
     * @param shm_id Numeric SysV id from `__AFL_CMPLOG_SHM_ID`.
     * @param error  Receives the reason on failure.
     * @return true when the compare-log header window is armed.
     */
    bool attach_cmp(int shm_id, std::string& error);

    /// @brief True when the coverage snapshot is armed.
    [[nodiscard]] bool cov_attached() const noexcept { return cov_ptr_ != nullptr; }
    /// @brief True when the compare-log header snapshot is armed.
    [[nodiscard]] bool cmp_attached() const noexcept { return cmp_ptr_ != nullptr; }
    /// @brief True when at least one snapshot is armed.
    [[nodiscard]] bool active() const noexcept { return cov_attached() || cmp_attached(); }

    /// @brief Size of the armed coverage snapshot in bytes (0 when disarmed).
    [[nodiscard]] std::size_t cov_len() const noexcept { return cov_len_; }

    /// @brief Copies the current map(s) into the snapshot buffers.
    void capture();

    /// @brief Writes the snapshots back into the shared map(s).
    ///
    /// The coverage part can be disabled with set_cov_restore(): the history
    /// dedup needs the snapshot after every exchange but must not rewrite the
    /// map when the probe window is not in use (nothing wrote to it).
    void restore();

    /// @brief Enables/disables the coverage snapshot restore (default on).
    void set_cov_restore(bool enabled) noexcept { cov_restore_ = enabled; }

    /// @brief Last captured coverage snapshot, or null when nothing was captured.
    [[nodiscard]] const std::uint8_t* cov_snapshot() const noexcept {
        return cov_ptr_ != nullptr ? cov_snapshot_.data() : nullptr;
    }

private:
    void detach() noexcept;

    std::uint8_t* cov_ptr_ = nullptr;
    std::size_t cov_len_ = 0;
    bool cov_restore_ = true;
    std::vector<std::uint8_t> cov_snapshot_;

    std::uint8_t* cmp_ptr_ = nullptr;
    std::vector<std::uint8_t> cmp_snapshot_;
};

/**
 * @brief Unstable-edge mask published by afl-fuzz, read lazily at dump time.
 *
 * afl-fuzz retires an edge as variable (`var_bytes`) during calibration when
 * its bucketized hit count differs between re-executions of the same queue
 * entry. The bitmap is global, monotonic and conflationary (stateful targets
 * also trip it), but it is the only instability signal available to the proxy,
 * so it is used to mask edge ids out of the history-dedup footprints.
 *
 * Sources (afl.var_bytes_method, no implicit default):
 *  - `shm`:   the SysV segment afl-fuzz publishes as __AFL_VARBYTES_SHM_ID
 *             (added by aflpp/patch/var_bytes_shm.patch); live, exact.
 *  - `stats`: the `var_bytes : <indices>` line of afl-fuzz's fuzzer_stats
 *             (stock AFL++ emits it only with AFL_DEBUG=1; refreshed every
 *             60 s, so it lags the live bitmap).
 *  - `off`:   no mask (empty footprints are the raw presence edge sets).
 *
 * Not thread-safe; the proxy is single-threaded.
 */
class VarBytesMask {
public:
    enum class Source { off, shm, stats };

    VarBytesMask() = default;
    ~VarBytesMask();

    VarBytesMask(const VarBytesMask&) = delete;
    VarBytesMask& operator=(const VarBytesMask&) = delete;

    /// @brief Selects the `off` source (no mask).
    void use_off() noexcept;

    /// @brief Selects the `stats` source with the given fuzzer_stats path.
    void use_stats(std::string stats_path);

    /**
     * @brief Attaches the SysV segment afl-fuzz published.
     *
     * @param shm_id Numeric id from `__AFL_VARBYTES_SHM_ID`.
     * @param error  Receives the reason on failure.
     * @return true when the `shm` source is ready.
     */
    bool attach_shm(int shm_id, std::string& error);

    /**
     * @brief Loads the current mask bitmap.
     *
     * @param out Receives the bitmap (index i set when edge i is unstable).
     * @return true when a mask was produced; false when the source is `off`
     *         or unavailable (parse/layout error, already warned about).
     */
    bool load(std::vector<std::uint8_t>& out) const;

    /// @brief Configured source.
    [[nodiscard]] Source source() const noexcept { return source_; }
    /// @brief Human-readable source name ("off", "shm", "stats").
    [[nodiscard]] const char* source_name() const noexcept;
    /// @brief fuzzer_stats path for the `stats` source (may be empty).
    [[nodiscard]] const std::string& stats_path() const noexcept { return stats_path_; }

private:
    void detach() noexcept;
    bool load_stats(std::vector<std::uint8_t>& out) const;

    Source source_ = Source::off;
    std::string stats_path_;
    std::uint8_t* shm_ = nullptr;
    std::size_t shm_len_ = 0;
    mutable bool warn_once_ = false;
};

} // namespace coverage
