// src/config.cpp

#include "config.hpp"
#include <yaml-cpp/yaml.h>
#include <sstream>
#include <regex>
#include <iostream>
#include <filesystem>
#include <unordered_set>

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

// Builds the final payload transmitted to the target:
//   prefix + fuzz input + suffix
std::vector<uint8_t> PayloadConfig::wrap(const uint8_t* data, size_t len) const {
    std::vector<uint8_t> out;
    out.reserve(prefix.size() + len + suffix.size());
    out.insert(out.end(), prefix.begin(), prefix.end());
    if (len > 0) {
        out.insert(out.end(), data, data + len);
    }
    out.insert(out.end(), suffix.begin(), suffix.end());
    return out;
}


std::variant<Config, ConfigError> load_config(const std::string& path) {
    Config cfg;
    
    try {
        YAML::Node root = YAML::LoadFile(path);
        if (!root.IsMap()) {
            return ConfigError{"", "Root node must be a map", "map", root.Type() == YAML::NodeType::Null ? "null" : "other"};
        }
        // Helper function to check for unknown keys in a YAML map node
        auto check_unknown_keys = [&](const YAML::Node& node, const std::unordered_set<std::string>& allowed, const std::string& prefix) -> ConfigError {
            for (YAML::const_iterator it = node.begin(); it != node.end(); ++it) {
                std::string key = it->first.as<std::string>();
                if (allowed.find(key) == allowed.end()) {
                    std::string full_key = prefix.empty() ? key : prefix + "." + key;
                    return ConfigError{full_key, "Unknown key: " + full_key, "", ""};
                }
            }
            return ConfigError{"", "", "", ""}; // no error
        };

        // --- Check for unknown keys at root ---
        {
            static const std::unordered_set<std::string> root_allowed = {"target", "network", "afl", "port_detection", "cleanup", "payload"};
            ConfigError err = check_unknown_keys(root, root_allowed, "");
            if (!err.message.empty()) {
                return err;
            }
        }


        // --- Parse target ---
        if (!root["target"] || !root["target"].IsMap()) {
            return ConfigError{"target", "Missing or invalid 'target' section", "map", "missing/invalid"};
        }
        YAML::Node target_node = root["target"];
        // --- Check for unknown keys in target ---
        {
            static const std::unordered_set<std::string> target_allowed = {"binary", "args", "env", "env_preserve"};
            ConfigError err = check_unknown_keys(target_node, target_allowed, "target");
            if (!err.message.empty()) {
                return err;
            }
        }

        
        if (!target_node["binary"] || !target_node["binary"].IsScalar()) {
            return ConfigError{"target.binary", "Missing or invalid 'binary'", "string", "missing/invalid"};
        }
        cfg.target.binary = target_node["binary"].as<std::string>();
        
        if (target_node["args"]) {
            if (!target_node["args"].IsSequence()) {
                return ConfigError{"target.args", "Invalid 'args'", "list of strings", "not a list"};
            }
            if (target_node["args"].size() == 0) {
                return ConfigError{"target.args", "Must have at least one element", "list of strings with at least one element", "empty list"};
            }
            for (const auto& arg : target_node["args"]) {
                if (!arg.IsScalar()) {
                    return ConfigError{"target.args", "Invalid element in 'args'", "string", "not a string"};
                }
                cfg.target.args.push_back(arg.as<std::string>());
            }
        } else {
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
            if (!target_node["env_preserve"].IsScalar()) {
                return ConfigError{"target.env_preserve", "Invalid type", "string", "not a string"};
            }
            std::string env_preserve = target_node["env_preserve"].as<std::string>();
            if (env_preserve == "nothing") {
                cfg.target.env_preserve = TargetConfig::EnvPreserveLevel::nothing;
            } else if (env_preserve == "afl_only") {
                cfg.target.env_preserve = TargetConfig::EnvPreserveLevel::afl_only;
            } else if (env_preserve == "all") {
                cfg.target.env_preserve = TargetConfig::EnvPreserveLevel::all;
            } else {
                return ConfigError{"target.env_preserve", "Invalid enum value", "nothing, afl_only, or all", env_preserve};
            }
        }

        // --- Parse network ---
        if (!root["network"] || !root["network"].IsMap()) {
            return ConfigError{"network", "Missing or invalid 'network' section", "map", "missing/invalid"};
        }
        YAML::Node net_node = root["network"];
        // --- Check for unknown keys in network ---
        {
            static const std::unordered_set<std::string> network_allowed = {"host", "port", "timeout_ms", "initial_ms"};
            ConfigError err = check_unknown_keys(net_node, network_allowed, "network");
            if (!err.message.empty()) {
                return err;
            }
        }

        
        if (net_node["host"]) {
            if (!net_node["host"].IsScalar()) return ConfigError{"network.host", "Invalid type", "string", "not a string"};
            // WARN: host is not validated beyond being a string; network.cpp connect_target() uses inet_pton(AF_INET) only:
            //   IPv4 literals work, but hostnames, IPv6 literals, and invalid strings are accepted here and may fail at connect time.
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
        // --- Check for unknown keys in afl ---
        {
            static const std::unordered_set<std::string> afl_allowed = {"loop_count", "enable_cmplog"};
            ConfigError err = check_unknown_keys(afl_node, afl_allowed, "afl");
            if (!err.message.empty()) {
                return err;
            }
        }

            if (afl_node["loop_count"]) {
                try {
                    cfg.afl.loop_count = afl_node["loop_count"].as<int>();
                    if (cfg.afl.loop_count <= 0) {
                        return ConfigError{"afl.loop_count", "Must be > 0", "integer > 0", std::to_string(cfg.afl.loop_count)};
                    }
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
        // --- Check for unknown keys in port_detection ---
        {
            static const std::unordered_set<std::string> pd_allowed = {"primary"};
            ConfigError err = check_unknown_keys(pd_node, pd_allowed, "port_detection");
            if (!err.message.empty()) {
                return err;
            }
        }

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
        // --- Check for unknown keys in cleanup ---
        {
            static const std::unordered_set<std::string> cleanup_allowed = {"force_kill_ms", "kill_pattern"};
            ConfigError err = check_unknown_keys(clean_node, cleanup_allowed, "cleanup");
            if (!err.message.empty()) {
                return err;
            }
        }

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
             // WARN: /proc/<pid>/comm is truncated by the kernel to 15 chars (TASK_COMM_LEN-1). A comm
             //   value longer than 15 chars can never match; this is intentional when the user selects "comm"
             kp.value = kp_node.as<std::string>();
             kp.target = "comm";
         } else if (kp_node.IsMap()) {

              // --- Check for unknown keys in cleanup.kill_pattern (if it's a map) ---
              {
                  std::unordered_set<std::string> kp_allowed = {"type", "value"};
                  if (kp.type == "regexp") {
                      kp_allowed.insert("target");
                  }
                  ConfigError err = check_unknown_keys(kp_node, kp_allowed, "cleanup.kill_pattern");
                  if (!err.message.empty()) {
                      return err;
                  }
              }

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
                     // WARN: `type: comm` objects silently ignore an extra `target` key, and the regex is
                     //   compiled with the default ECMAScript flavour (spec only says "standard C++ regex").
                     //   Note: we do not validate against empty or over-broad patterns (e.g. `.*` with target argv)
                     //   as that is the user's responsibility; see the self/parent-protection TODO in process.cpp.
                     if (kp.value.empty()) {
                         return ConfigError{"cleanup.kill_pattern.value", "Pattern must not be empty", "non-empty string", ""};
                     }
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
          // --- Parse payload ---
           if (root["payload"]) {
               if (root["payload"].IsNull()) {
                   // null payload section is treated as empty (same as omitting the section)
               } else if (!root["payload"].IsMap()) {
                   return ConfigError{"payload", "Invalid 'payload' section", "map", "not a map"};
               } else {
                   YAML::Node payload_node = root["payload"];
                   // --- Check for unknown keys in payload ---
                   {
                       static const std::unordered_set<std::string> payload_allowed = {"prefix", "suffix"};
                       ConfigError err = check_unknown_keys(payload_node, payload_allowed, "payload");
                       if (!err.message.empty()) {
                           return err;
                       }
                   }

                   if (payload_node["prefix"]) {
                       if (!payload_node["prefix"].IsScalar() && !payload_node["prefix"].IsNull()) {
                           return ConfigError{"payload.prefix", "Invalid type", "string or binary", "not a string or binary"};
                       }
                       // Handle both string and binary YAML types
                       if (payload_node["prefix"].IsScalar()) {
                           std::string prefix_str = payload_node["prefix"].as<std::string>();
                           cfg.payload.prefix = std::vector<uint8_t>(prefix_str.begin(), prefix_str.end());
                       } else {
                           // This handles !!binary and other binary formats
                           cfg.payload.prefix = payload_node["prefix"].as<std::vector<uint8_t>>();
                       }
                   }

                   if (payload_node["suffix"]) {
                       if (!payload_node["suffix"].IsScalar() && !payload_node["suffix"].IsNull()) {
                           return ConfigError{"payload.suffix", "Invalid type", "string or binary", "not a string or binary"};
                       }
                       // Handle both string and binary YAML types
                       if (payload_node["suffix"].IsScalar()) {
                           std::string suffix_str = payload_node["suffix"].as<std::string>();
                           cfg.payload.suffix = std::vector<uint8_t>(suffix_str.begin(), suffix_str.end());
                       } else {
                           // This handles !!binary and other binary formats
                           cfg.payload.suffix = payload_node["suffix"].as<std::vector<uint8_t>>();
                       }
                   }
               }
           }
 

    } catch (const YAML::BadFile& e) {
        return ConfigError{"", "Failed to load YAML file: " + std::string(e.what()), "valid file", path};
    } catch (const std::exception& e) {
        return ConfigError{path, "Unexpected error parsing config: " + std::string(e.what()), "valid config", "exception"};
    }

    return cfg;
}