// src/log.hpp

#pragma once

#include <cstdint>
#include <optional>
#include <spdlog/spdlog.h>
#include <string>
#include <string_view>
#include <vector>

// Thin wrappers over the SPDLOG_* macros so that all call sites share the
// compile-time gating done by SPDLOG_ACTIVE_LEVEL (see meson_options.txt).
// When SPDLOG_ACTIVE_LEVEL is raised (strip_low_logs=true), the trace and
// debug calls below compile to no-ops.
#define PROXY_LOG_TRACE(...) SPDLOG_TRACE(__VA_ARGS__)
#define PROXY_LOG_DEBUG(...) SPDLOG_DEBUG(__VA_ARGS__)
#define PROXY_LOG_INFO(...)  SPDLOG_INFO(__VA_ARGS__)
#define PROXY_LOG_WARN(...)  SPDLOG_WARN(__VA_ARGS__)
#define PROXY_LOG_ERROR(...) SPDLOG_ERROR(__VA_ARGS__)

namespace log {

    /**
     * @brief Initializes the default "proxy" logger.
     *
     * Creates a single-threaded (no sink locking) stdout logger, installs the
     * message pattern (timestamps are provided by the pattern, so call sites
     * must not prepend their own), enables flushing on warnings and errors
     * (so messages survive raise(SIGSEGV) when the proxy self-crashes to
     * report a target crash to AFL), and installs the logger as the default
     * one used by the PROXY_LOG_* macros.
     *
     * Must be called before any logging takes place and before fork_target()
     * (the child inherits the logger state; no spdlog calls are allowed
     * between fork() and execve()). Safe to call multiple times (e.g. once
     * with defaults at startup, again after parsing --log-level); each call
     * replaces the previous logger.
     *
     * @param level Runtime log level (typically from the --log-level flag).
     */
    void init(spdlog::level::level_enum level);

    /**
     * @brief Returns the recent warn/error messages captured by the logger.
     *
     * The "proxy" logger carries a warn-level ringbuffer sink (capacity 16)
     * alongside the console sink; every warning/error that reaches the logger
     * is captured there, even when the runtime --log-level hides it from
     * stdout (the console sink applies the runtime level, the logger level is
     * floored at warn). The history survives repeated init() calls.
     *
     * @return Formatted log lines (console-style pattern, each ending with a
     *         newline), oldest first; empty if nothing was captured yet.
     */
    [[nodiscard]] std::vector<std::string> recent_lines();

    /**
     * @brief Parses a log level name accepted by the --log-level flag.
     *
     * Accepted (case-sensitive): trace, debug, info, warn, warning, error,
     * err, critical, off.
     *
     * @param name Level name.
     * @return The parsed level, or std::nullopt if the name is not accepted.
     */
    [[nodiscard]] std::optional<spdlog::level::level_enum> parse_level(std::string_view name);

    /**
     * @brief Renders raw bytes as an escaped one-line string for logging.
     *
     * Printable ASCII bytes are kept as-is; every other byte is emitted as
     * "\xHH". If the input is longer than @p limit bytes, the output is
     * truncated after @p limit bytes and "..." is appended.
     *
     * @param data Byte buffer (may be binary).
     * @param limit Maximum number of input bytes rendered before truncation
     *              (default: unlimited).
     * @return Escaped string suitable for a single log line.
     */
    [[nodiscard]] std::string escape_bytes(const std::vector<uint8_t>& data,
                                           size_t limit = SIZE_MAX);

    /**
     * @brief Rate limiter for repeated per-iteration log messages.
     *
     * Call allow() once per occurrence. The first @p first_n occurrences are
     * always allowed; after that, at most one occurrence per @p interval_ms is
     * allowed. This keeps a hot loop's error logging (connect/send/wait
     * failures against a slow or dead target) from flooding the log while the
     * per-stage WARNs/heartbeat still describe what is happening. Not
     * thread-safe (the proxy is single-threaded).
     */
    class Throttle {
    public:
        /**
         * @param first_n Number of leading occurrences always allowed.
         * @param interval_ms Minimum spacing between later allowed occurrences.
         */
        explicit Throttle(uint64_t first_n = 3, uint64_t interval_ms = 5000);

        /// @brief Consume one occurrence; true if it should be logged.
        [[nodiscard]] bool allow();

        /// @brief Occurrences dropped since the previous allowed occurrence
        ///        (the count belonging to the line just allowed).
        [[nodiscard]] uint64_t suppressed() const { return reported_; }

    private:
        uint64_t first_n_;
        uint64_t interval_ms_;
        uint64_t count_ = 0;
        uint64_t dropped_ = 0;
        uint64_t reported_ = 0;
        uint64_t last_allow_ms_ = 0;
    };

    /**
     * @brief Suffix describing throttled occurrences, for the allowed log line.
     *
     * Empty when nothing was suppressed, otherwise e.g. " (suppressed 42
     * similar)". Append it (including its leading space) to the message.
     */
    [[nodiscard]] std::string throttle_suffix(const Throttle& throttle);

} // namespace log
