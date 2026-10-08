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

} // namespace log
