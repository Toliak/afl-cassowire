// src/config.cpp

#include "config.hpp"
#include <yaml-cpp/yaml.h>
#include <sstream>
#include <regex>
#include <iostream>
#include <filesystem>

std::string ConfigError::to_string() const {
    std::stringstream ss;
    ss << "Configuration error";
    if (!path.empty()) {
        ss << " at '" << path << "'";
    }
    ss << ": " << message;
    if (!expected.empty()) {
        ss << " (expected: " << expected;
        if (!actual.empty()) {
            ss << ", got: " << actual;
        }
        ss << ")";
    }
    return ss.str();
}

std::variant<Config, ConfigError> load_config(const std::string& path) {
    Config cfg;
    
    try {
        // TODO(claude): spec 4.2 says the loader "strictly validates", but unknown/misspelled keys at any level
        //   (e.g. `netwrok:`, `timeout:`) are silently ignored. Consider rejecting unknown keys.
        // TODO(claude): spec 4 says "without exceptions", yet this whole function relies on try/catch around
        //   yaml-cpp. Acceptable for yaml-cpp, but the catch-all hides which key failed (path is empty).
        YAML::Node root = YAML::LoadFile(path);
        if (!root.IsMap()) {
            return ConfigError{"", "Root node must be a map", "map", root.Type() == YAML::NodeType::Null ? "null" : "other"};
        }

        // --- Parse target ---
        if (!root["target"] || !root["target"].IsMap()) {
            return ConfigError{"target", "Missing or invalid 'target' section", "map", "missing/invalid"};
        }
        YAML::Node target_node = root["target"];
        
        if (!target_node["binary"] || !target_node["binary"].IsScalar()) {
            return ConfigError{"target.binary", "Missing or invalid 'binary'", "string", "missing/invalid"};
        }
        cfg.target.binary = target_node["binary"].as<std::string>();
        
        if (target_node["args"]) {
            if (!target_node["args"].IsSequence()) {
                return ConfigError{"target.args", "Invalid 'args'", "list of strings", "not a list"};
            }
            for (const auto& arg : target_node["args"]) {
                if (!arg.IsScalar()) {
                    return ConfigError{"target.args", "Invalid element in 'args'", "string", "not a string"};
                }
                cfg.target.args.push_back(arg.as<std::string>());
            }
        } else {
            // TODO(claude): an explicit empty list `args: []` is accepted and yields argv == {nullptr} in execve
            //   (no argv[0]; some programs crash/misbehave). Require >= 1 element. Also the "default to
            //   [binary]" behaviour is not described in the spec.

            // Default to [binary] if args is omitted
            cfg.target.args.push_back(cfg.target.binary);
        }

        // --- Parse target.env ---
        if (target_node["env"]) {
            if (!target_node["env"].IsMap()) {
                return ConfigError{"target.env", "Invalid 'env' section", "map of strings", "not a map"};
            }
            YAML::Node env_node = target_node["env"];
            for (YAML::Node::iterator it = env_node.begin(); it != env_node.end(); ++it) {
                if (!it->first.IsScalar() || !it->second.IsScalar()) {
                    return ConfigError{"target.env", "Invalid key-value pair", "string key -> string value", "invalid type"};
                }
                cfg.target.env[it->first.as<std::string>()] = it->second.as<std::string>();
            }
        }
        // --- Parse target.env_preserve ---
        if (target_node["env_preserve"]) {
            try {
                cfg.target.env_preserve = target_node["env_preserve"].as<bool>();
            } catch (const YAML::BadConversion&) {
                return ConfigError{"target.env_preserve", "Invalid type", "boolean", target_node["env_preserve"].Scalar()};
            }
        }

        if (target_node["log"]) {
            if (!target_node["log"].IsMap()) {
                return ConfigError{"target.log", "Invalid 'log' section", "map", "not a map"};
            }
            YAML::Node log_node = target_node["log"];
            if (log_node["stdout"]) {
                if (!log_node["stdout"].IsScalar()) return ConfigError{"target.log.stdout", "Invalid type", "string", "not a string"};
                cfg.target.log.stdout_path = log_node["stdout"].as<std::string>();
            }
            if (log_node["stderr"]) {
                if (!log_node["stderr"].IsScalar()) return ConfigError{"target.log.stderr", "Invalid type", "string", "not a string"};
                cfg.target.log.stderr_path = log_node["stderr"].as<std::string>();
            }
        }

        // --- Parse network ---
        if (!root["network"] || !root["network"].IsMap()) {
            return ConfigError{"network", "Missing or invalid 'network' section", "map", "missing/invalid"};
        }
        YAML::Node net_node = root["network"];
        
        if (net_node["host"]) {
            if (!net_node["host"].IsScalar()) return ConfigError{"network.host", "Invalid type", "string", "not a string"};
            // TODO(claude): host is not validated, but network.cpp connect_target() uses inet_pton(AF_INET) only:
            //   "localhost", hostnames and IPv6 literals are accepted here and then fail at connect time.
            //   Validate here (IPv4 literal) or resolve with getaddrinfo().
            // SOLUTION: write comment that we not support ipv6
            cfg.network.host = net_node["host"].as<std::string>();
        }
        
        if (!net_node["port"] || !net_node["port"].IsScalar()) {
            return ConfigError{"network.port", "Missing or invalid 'port'", "integer 1-65535", "missing/invalid"};
        }
        try {
            cfg.network.port = net_node["port"].as<int>();
            if (cfg.network.port < 1 || cfg.network.port > 65535) {
                return ConfigError{"network.port", "Port out of range", "integer 1-65535", std::to_string(cfg.network.port)};
            }
        } catch (const YAML::BadConversion&) {
            return ConfigError{"network.port", "Invalid port type", "integer 1-65535", net_node["port"].Scalar()};
        }

        if (net_node["timeout_ms"]) {
            try {
                cfg.network.timeout_ms = net_node["timeout_ms"].as<int>();
                if (cfg.network.timeout_ms <= 0) {
                    return ConfigError{"network.timeout_ms", "Must be > 0", "integer > 0", std::to_string(cfg.network.timeout_ms)};
                }
            } catch (const YAML::BadConversion&) {
                return ConfigError{"network.timeout_ms", "Invalid type", "integer > 0", net_node["timeout_ms"].Scalar()};
            }
        }

        if (net_node["initial_ms"]) {
            try {
                cfg.network.initial_ms = net_node["initial_ms"].as<int>();
                if (cfg.network.initial_ms <= 0) {
                    return ConfigError{"network.initial_ms", "Must be > 0", "integer > 0", std::to_string(cfg.network.initial_ms)};
                }
            } catch (const YAML::BadConversion&) {
                return ConfigError{"network.initial_ms", "Invalid type", "integer > 0", net_node["initial_ms"].Scalar()};
            }
        }

        // --- Parse afl ---
        if (root["afl"]) {
            if (!root["afl"].IsMap()) {
                return ConfigError{"afl", "Invalid 'afl' section", "map", "not a map"};
            }
            YAML::Node afl_node = root["afl"];
            if (afl_node["loop_count"]) {
                try {
                    // TODO(claude): no range validation: 0 or negative loop_count is accepted and passed to __AFL_LOOP().
                    //   Require > 0 (the spec only gives a default, but a non-positive value is meaningless).
                    cfg.afl.loop_count = afl_node["loop_count"].as<int>();
                } catch (const YAML::BadConversion&) {
                    return ConfigError{"afl.loop_count", "Invalid type", "integer", afl_node["loop_count"].Scalar()};
                }
            }
            if (afl_node["enable_cmplog"]) {
                try {
                    cfg.afl.enable_cmplog = afl_node["enable_cmplog"].as<bool>();
                } catch (const YAML::BadConversion&) {
                    return ConfigError{"afl.enable_cmplog", "Invalid type", "boolean", afl_node["enable_cmplog"].Scalar()};
                }
            }
        }

        // --- Parse port_detection ---
        if (root["port_detection"]) {
            if (!root["port_detection"].IsMap()) {
                return ConfigError{"port_detection", "Invalid 'port_detection' section", "map", "not a map"};
            }
            YAML::Node pd_node = root["port_detection"];
            if (pd_node["primary"]) {
                if (!pd_node["primary"].IsScalar()) return ConfigError{"port_detection.primary", "Invalid type", "string", "not a string"};
                std::string primary = pd_node["primary"].as<std::string>();
                if (primary != "procfs" && primary != "ptrace" && primary != "seccomp") {
                    return ConfigError{"port_detection.primary", "Invalid enum value", "procfs, ptrace, or seccomp", primary};
                }
                cfg.port_detection.primary = primary;
            }
        }

        // --- Parse cleanup ---
        if (root["cleanup"]) {
            if (!root["cleanup"].IsMap()) {
                return ConfigError{"cleanup", "Invalid 'cleanup' section", "map", "not a map"};
            }
            YAML::Node clean_node = root["cleanup"];
            if (clean_node["force_kill_ms"]) {
                try {
                    cfg.cleanup.force_kill_ms = clean_node["force_kill_ms"].as<int>();
                    if (cfg.cleanup.force_kill_ms <= 0) {
                        return ConfigError{"cleanup.force_kill_ms", "Must be > 0", "integer > 0", std::to_string(cfg.cleanup.force_kill_ms)};
                    }
                } catch (const YAML::BadConversion&) {
                    return ConfigError{"cleanup.force_kill_ms", "Invalid type", "integer > 0", clean_node["force_kill_ms"].Scalar()};
                }
            }

            if (clean_node["kill_pattern"]) {
                YAML::Node kp_node = clean_node["kill_pattern"];
                KillPattern kp;
                if (kp_node.IsScalar()) {
                    kp.type = "comm";
                    // TODO(claude): /proc/<pid>/comm is truncated by the kernel to 15 chars (TASK_COMM_LEN-1). A comm
                    //   value longer than 15 chars can never match; warn/reject it here.
                    // SOLUTION: yes, that is intended when the user selects "comm"
                    kp.value = kp_node.as<std::string>();
                    kp.target = "comm";
                } else if (kp_node.IsMap()) {
                    if (!kp_node["type"] || !kp_node["value"]) {
                        return ConfigError{"cleanup.kill_pattern", "Missing 'type' or 'value'", "object with type and value", "missing fields"};
                    }
                    if (!kp_node["type"].IsScalar() || !kp_node["value"].IsScalar()) {
                         return ConfigError{"cleanup.kill_pattern", "Invalid type for 'type' or 'value'", "strings", "not strings"};
                    }
                    kp.type = kp_node["type"].as<std::string>();
                    kp.value = kp_node["value"].as<std::string>();
                    
                    if (kp.type == "comm") {
                        kp.target = "comm";
                    } else if (kp.type == "regexp") {
                        if (!kp_node["target"]) {
                            return ConfigError{"cleanup.kill_pattern.target", "Missing 'target' for regexp", "comm, argv0, or argv", "missing"};
                        }
                        if (!kp_node["target"].IsScalar()) {
                            return ConfigError{"cleanup.kill_pattern.target", "Invalid type for 'target'", "string", "not a string"};
                        }
                        kp.target = kp_node["target"].as<std::string>();
                        if (kp.target != "comm" && kp.target != "argv0" && kp.target != "argv") {
                            return ConfigError{"cleanup.kill_pattern.target", "Invalid target for regexp", "comm, argv0, or argv", kp.target};
                        }
                        // Validate regex syntax
                        try {
                            // TODO(claude): `type: comm` objects silently ignore an extra `target` key, and the regex is
                            //   compiled with the default ECMAScript flavour (spec only says "standard C++ regex").
                            //   Also an empty/over-broad pattern (e.g. `.*` with target argv) would match every
                            //   process - see the self/parent-protection TODO in process.cpp.
                            // SOLUTION: yes, error empty pattern. But broad pattern i don't care, if the user sets it.
                            //           ECMAScript is ok for it.
                            std::regex r(kp.value);
                        } catch (const std::regex_error&) {
                            return ConfigError{"cleanup.kill_pattern.value", "Invalid regular expression", "valid regex", kp.value};
                        }
                    } else {
                        return ConfigError{"cleanup.kill_pattern.type", "Invalid type", "comm or regexp", kp.type};
                    }
                } else {
                    return ConfigError{"cleanup.kill_pattern", "Invalid type", "string or object", "other"};
                }
                cfg.cleanup.kill_pattern = kp;
            }
        }

    } catch (const YAML::BadFile& e) {
        return ConfigError{"", "Failed to load YAML file: " + std::string(e.what()), "valid file", path};
    } catch (const std::exception& e) {
        return ConfigError{"", "Unexpected error parsing config: " + std::string(e.what()), "valid config", "exception"};
    }

    return cfg;
}