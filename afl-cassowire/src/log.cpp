// src/log.cpp

#include "log.hpp"

#include <spdlog/sinks/ringbuffer_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <memory>
#include <string>

namespace casslog {

    namespace {

        // Capacity of the warn/error ring sink: the last 16 captured lines
        // are embedded into termination dumps (.msg) by utils::terminate_proxy().
        constexpr size_t k_recent_capacity = 16;

        // Created on the first init() and reused afterwards so that the
        // second init(--log-level) does not wipe the captured history.
        std::shared_ptr<spdlog::sinks::ringbuffer_sink_st> g_recent_sink;

    } // namespace

    void init(spdlog::level::level_enum console_level, spdlog::level::level_enum crash_msg_level) {
        // The logger is constructed manually (not via the stdout_color_st
        // factory) so that init() is idempotent: the factory would try to
        // register the name "proxy" in the global registry on every call and
        // throw spdlog_ex on the second one (main() calls init() several
        // times: once with defaults, once after parsing --log-level, and once
        // after the config provides afl.msg_log_level).
        if (!g_recent_sink) {
            g_recent_sink = std::make_shared<spdlog::sinks::ringbuffer_sink_st>(k_recent_capacity);
        }
        // Applied on every init(): the first call installs the default, the
        // second (after the config is loaded) applies afl.msg_log_level. Doing
        // this only on creation would silently ignore the configured level.
        g_recent_sink->set_level(crash_msg_level);
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_st>();
        // The console sink applies the runtime --log-level; the logger level
        // is floored at warn so that the ring sink keeps capturing warnings
        // even when the runtime level hides them from stdout (warn/error are
        // rare and throttled, so the extra formatting is negligible).
        console_sink->set_level(console_level);
        auto logger = std::make_shared<spdlog::logger>(
            "proxy", spdlog::sinks_init_list{std::move(console_sink), g_recent_sink});
        logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
        logger->flush_on(spdlog::level::warn);
        logger->set_level(std::min(console_level, spdlog::level::warn));
        spdlog::set_default_logger(std::move(logger));
    }

    std::vector<std::string> recent_lines() {
        if (!g_recent_sink) return {};
        return g_recent_sink->last_formatted();
    }

    std::optional<spdlog::level::level_enum> parse_level(std::string_view name) {
        // spdlog::level::from_str() is not used because it does not accept the
        // "warn"/"err" aliases and is itself documented as case-sensitive.
        if (name == "trace")    return spdlog::level::trace;
        if (name == "debug")    return spdlog::level::debug;
        if (name == "info")     return spdlog::level::info;
        if (name == "warn" || name == "warning") return spdlog::level::warn;
        if (name == "error" || name == "err")    return spdlog::level::err;
        if (name == "critical") return spdlog::level::critical;
        if (name == "off")      return spdlog::level::off;
        return std::nullopt;
    }

    std::string escape_bytes(const std::vector<uint8_t>& data, size_t limit) {
        const size_t n = std::min(data.size(), limit);
        std::string out;
        out.reserve(n * 4 + 4);
        for (size_t i = 0; i < n; ++i) {
            const uint8_t c = data[i];
            if (c >= 0x20 && c < 0x7f) {
                out.push_back(static_cast<char>(c));
            } else {
                char buf[5];
                std::snprintf(buf, sizeof(buf), "\\x%02x", static_cast<unsigned>(c));
                out += buf;
            }
        }
        if (data.size() > limit) {
            out += "...";
        }
        return out;
    }

    namespace {
        uint64_t monotonic_ms() {
            return static_cast<uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch())
                    .count());
        }
    } // namespace

    Throttle::Throttle(uint64_t first_n, uint64_t interval_ms)
        : first_n_(first_n), interval_ms_(interval_ms) {}

    bool Throttle::allow() {
        ++count_;
        const uint64_t now = monotonic_ms();

        if (count_ <= first_n_ || now - last_allow_ms_ >= interval_ms_) {
            last_allow_ms_ = now;
            reported_ = dropped_;
            dropped_ = 0;
            return true;
        }
        ++dropped_;
        return false;
    }

    std::string throttle_suffix(const Throttle& throttle) {
        const uint64_t n = throttle.suppressed();
        if (n == 0) return {};
        return " (suppressed " + std::to_string(n) + " similar)";
    }

} // namespace casslog
