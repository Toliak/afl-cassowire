// src/log.cpp

#include "log.hpp"

#include <spdlog/sinks/stdout_color_sinks.h>

#include <algorithm>
#include <cstdio>
#include <memory>
#include <string>

namespace log {

    void init(spdlog::level::level_enum level) {
        // The logger is constructed manually (not via the stdout_color_st
        // factory) so that init() is idempotent: the factory would try to
        // register the name "proxy" in the global registry on every call and
        // throw spdlog_ex on the second one (main() calls init() twice: once
        // with defaults, once after parsing --log-level).
        auto sink = std::make_shared<spdlog::sinks::stdout_color_sink_st>();
        auto logger = std::make_shared<spdlog::logger>("proxy", std::move(sink));
        logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
        logger->flush_on(spdlog::level::warn);
        logger->set_level(level);
        spdlog::set_default_logger(std::move(logger));
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

} // namespace log
