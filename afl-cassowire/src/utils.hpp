// src/utils.hpp

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <unistd.h>
#include <variant>
#include <vector>
#include <sched.h>

namespace coverage {
class VarBytesMask;
}

namespace utils {

    /**
     * @brief Gets the current CPU affinity mask as a comma-separated list of CPU numbers.
     *
     * @return std::string Comma-separated CPU numbers, "none" if no CPUs are set,
     *         or "<unavailable>" if the operation fails.
     */
    std::string get_cpu_affinity();
    /**
     * @brief Move-only RAII wrapper around a file descriptor.
     *
     * Takes ownership of a raw descriptor and closes it on destruction
     * (unless it is negative or was moved away). Copying is disabled to
     * prevent double-close; ownership can only be transferred by moving.
     */
    class [[nodiscard]] FdGuard {
    public:
        /// @brief Creates an empty guard that owns no descriptor.
        FdGuard() noexcept : fd(-1) {}

        /// @brief Takes ownership of an existing descriptor (may be negative).
        explicit FdGuard(int f) noexcept : fd(f) {}

        FdGuard(const FdGuard&) = delete;
        FdGuard& operator=(const FdGuard&) = delete;

        /// @brief Transfers ownership from @p other, leaving it empty.
        FdGuard(FdGuard&& other) noexcept : fd(other.fd) { other.fd = -1; }

        /// @brief Transfers ownership from @p other, closing any owned fd first.
        FdGuard& operator=(FdGuard&& other) noexcept {
            if (this != &other) {
                reset();
                fd = other.fd;
                other.fd = -1;
            }
            return *this;
        }

        /// @brief Closes the owned descriptor, if any.
        ~FdGuard() {
            if (fd >= 0) ::close(fd);
        }

        /// @brief Returns the owned descriptor without releasing ownership.
        [[nodiscard]] int get() const noexcept { return fd; }

        /// @brief Closes the owned descriptor (if any) and leaves the guard empty.
        void reset() noexcept {
            if (fd >= 0) {
                ::close(fd);
                fd = -1;
            }
        }

    private:
        int fd;
    };

    /**
     * @brief Gets the current monotonic time in milliseconds.
     *
     * @return uint64_t Current time in ms.
     */
    uint64_t get_time_ms();

    /**
     * @brief Sleeps for a specified number of milliseconds.
     * 
     * @param ms The duration to sleep in milliseconds.
     */
    void sleep_ms(int ms);

    /**
     * @brief Sets the directory used for termination dumps.
     *
     * crash_proxy()/abort_proxy() write a `.msg` (reason), a `.data` (the full
     * payload built for the failing iteration) and, when
     * set_dump_history_size() > 0, the retained previous-iteration payloads as
     * `.-1.data`, `.-2.data`, ... into this directory.
     * The path is used as-is (relative paths resolve against the process's
     * cwd); the directory is created recursively if it does not exist.
     * Creation failure is logged but not fatal.
     *
     * @param dir Destination directory (default: "afl-cassowire-data").
     */
    void set_data_dir(std::string dir);

    /**
     * @brief Sets the instance tag embedded into termination dumps.
     *
     * The tag identifies which proxy instance produced a dump ("normal",
     * "cmplog", or "test"): it is appended to the dump file stem
     * ("<timestamp>-<tag>.msg/.data") and embedded into the .msg content and
     * the termination log line ("<kind>[<tag>]: <reason>"). The normal and the
     * cmplog proxy can run concurrently against the same data dir, so dumps
     * stay attributable. An empty tag (the default) keeps the plain
     * "<timestamp>" stem and the "<kind>: <reason>" format.
     *
     * @param tag Instance tag ("" disables tagging).
     */
    void set_instance_tag(std::string tag);

    /**
     * @brief Sets the __AFL_LOOP iteration embedded into termination dumps.
     *
     * The counter is the current 1-based iteration of the proxy's AFL loop
     * at the moment crash_proxy()/abort_proxy() fire; it is written as a
     * dedicated "iteration: N" line into the .msg file so a termination can
     * be correlated with the heartbeat lines (which report completed
     * iterations). The default of 0 means the termination happened outside
     * the loop (start-up path) or in test mode. The proxy is
     * single-threaded, so a plain non-atomic store suffices.
     *
     * @param n Current 1-based iteration number (0 = not inside the loop).
     */
    void set_current_iteration(uint64_t n);

    /**
     * @brief Sets how many completed-iteration payloads are retained for dumps.
     *
     * record_dump_input() keeps the last @p n iterations of completed proxy
     * loop passes. When crash_proxy()/abort_proxy() later fire, the retained
     * entries are written next to the current one as "<stem>.-1.data" /
     * "<stem>.-1.input" (most recent previous iteration), ".-2", ... A
     * deferred/async crash is detected one iteration late, so the current
     * payload may not be the input that caused it; the history preserves the
     * likely culprit. 0 disables the history (only the current ".data"/".input"
     * are written). The proxy is single-threaded, so a plain non-atomic store
     * suffices.
     *
     * @param n Number of previous iterations to retain (0 = disabled).
     */
    void set_dump_history_size(std::size_t n);

    /**
     * @brief Enables/disables coverage-footprint dedup of the dump history.
     *
     * When enabled, dump_termination_data() keeps only one entry per coverage
     * footprint: the oldest and the newest iteration of each footprint, plus
     * the two newest entries regardless. A footprint is the set of edges the
     * iteration hit, minus the edges the registered VarBytesMask marks
     * unstable. The current iteration's dump is never filtered.
     *
     * @param enabled Whether afl.history_dedup is on.
     */
    void set_history_dedup(bool enabled);

    /**
     * @brief Registers the unstable-edge mask used by history dedup.
     *
     * The mask is loaded lazily at dump time (the afl-fuzz bitmap changes over
     * time). The object must outlive the process; it may be null to disable
     * masking (dedup then compares the raw presence edge sets).
     *
     * @param mask Pointer owned by the caller (run_proxy_mode), or null.
     */
    void set_var_bytes_mask(const coverage::VarBytesMask* mask);

    /**
     * @brief Records one completed iteration for the termination dump.
     *
     * Called by the proxy loop after each completed iteration (see
     * set_dump_history_size()). No-op when the history is disabled. Both the
     * raw testcase and the built payload, plus the iteration's presence edge
     * ids, are copied, so the caller may reuse its buffers immediately.
     *
     * @param raw     Raw AFL testcase (what `test --input` / AFL expect).
     * @param payload Built payload actually sent (prefix + input + suffix, or
     *                the whole sequence session).
     * @param edges   Presence edge ids of the iteration, or empty when dedup
     *                is disabled.
     */
    void record_dump_input(std::span<const std::uint8_t> raw,
                           std::span<const std::uint8_t> payload,
                           std::span<const std::uint32_t> edges);

    /**
     * @brief Crashes the proxy intentionally (e.g., to trigger AFL respawn).
     * Raises SIGSEGV.
     *
     * Before raising the signal, the reason and the failing payload are dumped
     * to the configured data directory (see set_data_dir()). The .msg file
     * also embeds the last warn/error messages captured by the proxy logger
     * (casslog::recent_lines()) - the context that preceded the termination.
     * When a history is enabled (set_dump_history_size()), the retained
     * previous-iteration entries are dumped as .-1.data/.input, .-2.data/.input,
     * ... (filtered by set_history_dedup()).
     *
     * @param message Human-readable reason for the crash.
     * @param input The full payload built for the failing iteration.
     * @param raw The raw testcase of the failing iteration (may be empty).
     * @param edges Presence edge ids of the failing iteration (may be empty).
     */
    [[noreturn]] void crash_proxy(std::string_view message, std::span<const uint8_t> input,
                                  std::span<const uint8_t> raw = {},
                                  std::span<const std::uint32_t> edges = {});

    /**
     * @brief Aborts the proxy intentionally (e.g., when the target exited
     *        normally or its state is unknown). Raises SIGABRT.
     *
     * Before raising the signal, the reason and the failing payload are dumped
     * to the configured data directory (see set_data_dir()). The .msg file
     * also embeds the last warn/error messages captured by the proxy logger
     * (casslog::recent_lines()) - the context that preceded the termination.
     * When a history is enabled (set_dump_history_size()), the retained
     * previous-iteration entries are dumped as .-1.data/.input, .-2.data/.input,
     * ... (filtered by set_history_dedup()).
     *
     * @param message Human-readable reason for the abort.
     * @param input The full payload built for the failing iteration.
     * @param raw The raw testcase of the failing iteration (may be empty).
     * @param edges Presence edge ids of the failing iteration (may be empty).
     */
    [[noreturn]] void abort_proxy(std::string_view message, std::span<const uint8_t> input,
                                  std::span<const uint8_t> raw = {},
                                  std::span<const std::uint32_t> edges = {});

    /**
     * @brief Detail carried by ParseError: characters left unconsumed after a
     *        successful numeric conversion (e.g. "12abc").
     */
    enum class CustomParseError { TrailingCharacters };

    /**
     * @brief Parse failure detail: either a std::errc reported by
     *        std::from_chars (invalid input, out of range) or a trailing
     *        characters failure.
     */
    using ParseError = std::variant<std::errc, CustomParseError>;

    /**
     * @brief Result of parse_u64_strict(): the parsed value on success, a
     *        ParseError otherwise.
     */
    using ParseResult = std::variant<std::uint64_t, ParseError>;

    /// @brief Result of parse_u8_strict(): the parsed value or a ParseError.
    using U8ParseResult = std::variant<std::uint8_t, ParseError>;

    /// @brief Result of parse_u16_strict(): the parsed value or a ParseError.
    using U16ParseResult = std::variant<std::uint16_t, ParseError>;

    /// @brief Result of parse_u32_strict(): the parsed value or a ParseError.
    using U32ParseResult = std::variant<std::uint32_t, ParseError>;

    /**
     * @brief Strictly parses an unsigned decimal integer of the given width.
     *
     * Accepts only non-empty strings of ASCII digits in the given base
     * (2-36, default 10) that fit into the target type (no sign, no
     * whitespace, no "0x" prefix, no overflow). The entire string must be
     * consumed.
     *
     * @param s The string to parse.
     * @param base Numeric base accepted by std::from_chars (2-36).
     * @return ParseResult The parsed value, or a ParseError describing the
     *         failure.
     */
    [[nodiscard]] ParseResult parse_u64_strict(std::string_view s, int base = 10);

    /**
     * @brief Strictly parses an unsigned 8-bit integer (see parse_u64_strict).
     *
     * @param s The string to parse.
     * @param base Numeric base accepted by std::from_chars (2-36).
     * @return U8ParseResult The parsed value, or a ParseError.
     */
    [[nodiscard]] U8ParseResult parse_u8_strict(std::string_view s, int base = 10);

    /**
     * @brief Strictly parses an unsigned 16-bit integer (see parse_u64_strict).
     *
     * @param s The string to parse.
     * @param base Numeric base accepted by std::from_chars (2-36).
     * @return U16ParseResult The parsed value, or a ParseError.
     */
    [[nodiscard]] U16ParseResult parse_u16_strict(std::string_view s, int base = 10);

    /**
     * @brief Strictly parses an unsigned 32-bit integer (see parse_u64_strict).
     *
     * @param s The string to parse.
     * @param base Numeric base accepted by std::from_chars (2-36).
     * @return U32ParseResult The parsed value, or a ParseError.
     */
    [[nodiscard]] U32ParseResult parse_u32_strict(std::string_view s, int base = 10);

    /**
     * @brief Result of read_input_file(): the file/stdin contents on success,
     *        or an std::error_code describing the failure.
     */
    using ReadResult = std::variant<std::vector<uint8_t>, std::error_code>;

    /**
     * @brief Reads an input file into a buffer ("-" reads from stdin).
     *
     * Distinguishes read errors (returned as std::error_code) from a
     * successful but empty read (empty vector). EINTR on read() is retried.
     *
     * @param path File path, or "-" for stdin.
     * @param max_bytes Maximum number of bytes to read; exceeding it yields
     *        std::errc::file_too_large.
     * @return ReadResult The contents, or an std::error_code.
     */
    [[nodiscard]] ReadResult read_input_file(std::string_view path,
                                             size_t max_bytes = SIZE_MAX);

} // namespace utils