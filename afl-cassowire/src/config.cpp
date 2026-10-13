// src/config.cpp

#include "config.hpp"
#include <yaml-cpp/yaml.h>
#include <sstream>
#include <regex>
#include <iostream>
#include <filesystem>
#include <unordered_set>
#include <vector>

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


namespace {

// Root-level helper keys start with "__" and carry no meaning for the proxy;
// they exist so configs can anchor reusable fragments (e.g. `__net: &net`).
bool is_helper_key(const std::string& key) {
    return key.rfind("__", 0) == 0;
}

// Returns a ConfigError with an empty message when every key is allowed.
// When `ignore_helpers` is true, "__"-prefixed keys are skipped; it is used
// for the root node only, so nested sections stay strict.
ConfigError check_unknown_keys(const YAML::Node& node, const std::unordered_set<std::string>& allowed,
                               const std::string& prefix, bool ignore_helpers = false) {
    for (YAML::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first.as<std::string>();
        if (ignore_helpers && is_helper_key(key)) {
            continue;
        }
        if (allowed.find(key) == allowed.end()) {
            std::string full_key = prefix.empty() ? key : prefix + "." + key;
            return ConfigError{full_key, "Unknown key: " + full_key, "", ""};
        }
    }
    return ConfigError{"", "", "", ""}; // no error
}

// Forward declaration for circular reference detection
static thread_local std::vector<YAML::Node>* g_merge_key_visiting = nullptr;

// Recursively resolves YAML 1.2 merge keys (<<) in a mapping node.
// Supports:
//   <<: *anchor                    (scalar alias)
//   <<: [*anchor1, *anchor2]       (sequence of aliases, later wins)
//   <<: { key: value }             (inline mapping)
// Removes the << key after merging. Throws ConfigError on cycles or invalid types.
void resolve_merge_keys(YAML::Node& node, const std::string& path) {
    if (!node.IsMap()) {
        return;
    }

    // Initialize visiting tracker on first call
    std::vector<YAML::Node> visiting_storage;
    if (!g_merge_key_visiting) {
        g_merge_key_visiting = &visiting_storage;
    }

    // Check for circular reference: does this node's underlying data
    // match any node currently being visited?
    for (const auto& visiting : *g_merge_key_visiting) {
        if (node.is(visiting)) {
            throw ConfigError{path, "Circular merge key reference", "acyclic merge keys", "cycle detected"};
        }
    }

    g_merge_key_visiting->push_back(node);

    // First, recurse into all values (depth-first) to resolve nested merge keys
    for (YAML::iterator it = node.begin(); it != node.end(); ++it) {
        YAML::Node& value = it->second;
        std::string child_path = path.empty() ? it->first.as<std::string>() : path + "." + it->first.as<std::string>();
        resolve_merge_keys(value, child_path);
    }

    // Now process merge keys at this level
    // We need to collect merge keys first since we'll modify the map while iterating
    struct MergeSource {
        YAML::Node source;
        std::string source_path;
    };
    std::vector<MergeSource> merge_sources;
    std::vector<std::string> merge_keys_to_remove;

    for (YAML::const_iterator it = node.begin(); it != node.end(); ++it) {
        std::string key = it->first.as<std::string>();
        if (key == "<<") {
            merge_keys_to_remove.push_back(key);
            YAML::Node merge_value = it->second;
            std::string mp = path.empty() ? "<<": path + ".<<";

            if (merge_value.IsNull()) {
                throw ConfigError{mp, "Merge key references undefined anchor", "alias or mapping", "null"};
            }

            if (merge_value.IsMap()) {
                // Inline mapping: <<: { key: value }
                merge_sources.push_back({merge_value, mp});
            } else if (merge_value.IsSequence()) {
                // Sequence of aliases: <<: [*a, *b]
                for (size_t i = 0; i < merge_value.size(); ++i) {
                    YAML::Node item = merge_value[i];
                    std::string item_path = mp + "[" + std::to_string(i) + "]";
                    if (item.IsNull()) {
                        throw ConfigError{item_path, "Merge key references undefined anchor", "alias", "null"};
                    }
                    if (!item.IsMap()) {
                        throw ConfigError{item_path, "Merge key sequence item must be a mapping", "mapping", "other"};
                    }
                    merge_sources.push_back({item, item_path});
                }
            } else if (merge_value.IsScalar()) {
                // Scalar alias: <<: *anchor (yaml-cpp resolves aliases at load time,
                // so this would be the aliased node, which should be a map)
                if (!merge_value.IsMap()) {
                    throw ConfigError{mp, "Merge key alias must resolve to a mapping", "mapping", "other"};
                }
                merge_sources.push_back({merge_value, mp});
            } else {
                throw ConfigError{mp, "Invalid merge key value", "map, sequence of mappings, or alias", "other"};
            }
        }
    }

    // Apply merges in order (later sources override earlier for keys not already present)
    for (const auto& ms : merge_sources) {
        const YAML::Node& source = ms.source;
        for (YAML::const_iterator it = source.begin(); it != source.end(); ++it) {
            std::string key = it->first.as<std::string>();
            // Only insert if key doesn't already exist in target (YAML 1.2 spec)
            if (!node[key]) {
                node[key] = it->second;
            }
        }
    }

    // Remove the << keys
    for (const auto& key : merge_keys_to_remove) {
        node.remove(key);
    }

    g_merge_key_visiting->pop_back();
}

// Parses a target-shaped section ("binary"/"args"/"env"/"env_preserve"). `prefix`
// is the config path used in errors (e.g. "target", "target_cmplog"). Sections
// are standalone: no values are inherited from any other section.
// Returns a ConfigError with an empty message on success.
ConfigError parse_target_section(const YAML::Node& node, const std::string& prefix, TargetConfig& out) {
    static const std::unordered_set<std::string> target_allowed = {"binary", "args", "env", "env_preserve"};
    ConfigError err = check_unknown_keys(node, target_allowed, prefix);
    if (!err.message.empty()) {
        return err;
    }

    if (!node["binary"] || !node["binary"].IsScalar()) {
        return ConfigError{prefix + ".binary", "Missing or invalid 'binary'", "string", "missing/invalid"};
    }
    out.binary = node["binary"].as<std::string>();

    if (node["args"]) {
        if (!node["args"].IsSequence()) {
            return ConfigError{prefix + ".args", "Invalid 'args'", "list of strings", "not a list"};
        }
        if (node["args"].size() == 0) {
            return ConfigError{prefix + ".args", "Must have at least one element", "list of strings with at least one element", "empty list"};
        }
        for (const auto& arg : node["args"]) {
            if (!arg.IsScalar()) {
                return ConfigError{prefix + ".args", "Invalid element in 'args'", "string", "not a string"};
            }
            out.args.push_back(arg.as<std::string>());
        }
    } else {
        // Default to [binary] if args is omitted
        out.args.push_back(out.binary);
    }

    if (node["env"]) {
        if (!node["env"].IsMap()) {
            return ConfigError{prefix + ".env", "Invalid 'env' section", "map of strings", "not a map"};
        }
        YAML::Node env_node = node["env"];
        for (YAML::Node::iterator it = env_node.begin(); it != env_node.end(); ++it) {
            if (!it->first.IsScalar() || !it->second.IsScalar()) {
                return ConfigError{prefix + ".env", "Invalid key-value pair", "string key -> string value", "invalid type"};
            }
            out.env[it->first.as<std::string>()] = it->second.as<std::string>();
        }
    }

    if (node["env_preserve"]) {
        if (!node["env_preserve"].IsScalar()) {
            return ConfigError{prefix + ".env_preserve", "Invalid type", "string", "not a string"};
        }
        std::string env_preserve = node["env_preserve"].as<std::string>();
        if (env_preserve == "nothing") {
            out.env_preserve = TargetConfig::EnvPreserveLevel::nothing;
        } else if (env_preserve == "afl_only") {
            out.env_preserve = TargetConfig::EnvPreserveLevel::afl_only;
        } else if (env_preserve == "all") {
            out.env_preserve = TargetConfig::EnvPreserveLevel::all;
        } else {
            return ConfigError{prefix + ".env_preserve", "Invalid enum value", "nothing, afl_only, or all", env_preserve};
        }
    }

    return ConfigError{"", "", "", ""}; // no error
}

// Parses a network-shaped section ("host"/"port"/"timeout_ms"/"initial_ms"/"probe").
// `prefix` is the config path used in errors (e.g. "network", "network_cmplog").
// Sections are standalone: no values are inherited from any other section.
// Returns a ConfigError with an empty message on success.
ConfigError parse_network_section(const YAML::Node& node, const std::string& prefix, NetworkConfig& out) {
    static const std::unordered_set<std::string> network_allowed = {"host", "port", "timeout_ms", "initial_ms", "probe", "probe_retry_ms"};
    ConfigError err = check_unknown_keys(node, network_allowed, prefix);
    if (!err.message.empty()) {
        return err;
    }

    if (node["host"]) {
        if (!node["host"].IsScalar()) return ConfigError{prefix + ".host", "Invalid type", "string", "not a string"};
        // WARN: host is not validated beyond being a string; network.cpp connect_target() uses inet_pton(AF_INET) only:
        //   IPv4 literals work, but hostnames, IPv6 literals, and invalid strings are accepted here and may fail at connect time.
        out.host = node["host"].as<std::string>();
    }

    if (!node["port"] || !node["port"].IsScalar()) {
        return ConfigError{prefix + ".port", "Missing or invalid 'port'", "integer 1-65535", "missing/invalid"};
    }
    try {
        out.port = node["port"].as<int>();
        if (out.port < 1 || out.port > 65535) {
            return ConfigError{prefix + ".port", "Port out of range", "integer 1-65535", std::to_string(out.port)};
        }
    } catch (const YAML::BadConversion&) {
        return ConfigError{prefix + ".port", "Invalid port type", "integer 1-65535", node["port"].Scalar()};
    }

    if (node["timeout_ms"]) {
        try {
            out.timeout_ms = node["timeout_ms"].as<int>();
            if (out.timeout_ms <= 0) {
                return ConfigError{prefix + ".timeout_ms", "Must be > 0", "integer > 0", std::to_string(out.timeout_ms)};
            }
        } catch (const YAML::BadConversion&) {
            return ConfigError{prefix + ".timeout_ms", "Invalid type", "integer > 0", node["timeout_ms"].Scalar()};
        }
    }

    if (node["initial_ms"]) {
        try {
            out.initial_ms = node["initial_ms"].as<int>();
            if (out.initial_ms <= 0) {
                return ConfigError{prefix + ".initial_ms", "Must be > 0", "integer > 0", std::to_string(out.initial_ms)};
            }
        } catch (const YAML::BadConversion&) {
            return ConfigError{prefix + ".initial_ms", "Invalid type", "integer > 0", node["initial_ms"].Scalar()};
        }
    }

    if (node["probe"]) {
        try {
            out.probe = node["probe"].as<bool>();
        } catch (const YAML::BadConversion&) {
            return ConfigError{prefix + ".probe", "Invalid type", "boolean", node["probe"].Scalar()};
        }
    }

    if (node["probe_retry_ms"]) {
        try {
            out.probe_retry_ms = node["probe_retry_ms"].as<int>();
            if (out.probe_retry_ms < 0) {
                return ConfigError{prefix + ".probe_retry_ms", "Must be >= 0", "integer >= 0", std::to_string(out.probe_retry_ms)};
            }
        } catch (const YAML::BadConversion&) {
            return ConfigError{prefix + ".probe_retry_ms", "Invalid type", "integer >= 0", node["probe_retry_ms"].Scalar()};
        }
    }

    return ConfigError{"", "", "", ""}; // no error
}

} // namespace

std::variant<Config, ConfigError> load_config(const std::string& path) {
    Config cfg;
    
    try {
        YAML::Node root = YAML::LoadFile(path);
        if (!root.IsMap()) {
            return ConfigError{"", "Root node must be a map", "map", root.Type() == YAML::NodeType::Null ? "null" : "other"};
        }

        // Resolve YAML merge keys (<<) before validation
        resolve_merge_keys(root, "");

        // --- Check for unknown keys at root ---
        // Root keys starting with "__" are ignored: they are reserved for
        // helper fragments anchored for reuse (aliases / merge keys) below.
        {
            static const std::unordered_set<std::string> root_allowed = {"target", "target_cmplog", "network", "network_cmplog", "afl", "port_detection", "cleanup", "payload"};
            ConfigError err = check_unknown_keys(root, root_allowed, "", true);
            if (!err.message.empty()) {
                return err;
            }
        }


        // --- Parse target ---
        if (!root["target"] || !root["target"].IsMap()) {
            return ConfigError{"target", "Missing or invalid 'target' section", "map", "missing/invalid"};
        }
        {
            ConfigError err = parse_target_section(root["target"], "target", cfg.target);
            if (!err.message.empty()) {
                return err;
            }
        }

        // --- Parse afl (must come before target_cmplog/network_cmplog so they are
        //   only required when enable_cmplog is true) ---
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

        // --- Parse target_cmplog and network_cmplog (only when enable_cmplog is true) ---
        if (cfg.afl.enable_cmplog) {
            if (!root["target_cmplog"] || !root["target_cmplog"].IsMap()) {
                return ConfigError{"target_cmplog", "Missing or invalid 'target_cmplog' section", "map", "missing/invalid"};
            }
            {
                ConfigError err = parse_target_section(root["target_cmplog"], "target_cmplog", cfg.target_cmplog);
                if (!err.message.empty()) {
                    return err;
                }
            }
            // Standalone section: nothing is inherited from `network`; the cmplog
            // target may listen on a different host/port and use different timeouts.
            if (!root["network_cmplog"] || !root["network_cmplog"].IsMap()) {
                return ConfigError{"network_cmplog", "Missing or invalid 'network_cmplog' section", "map", "missing/invalid"};
            }
            {
                ConfigError err = parse_network_section(root["network_cmplog"], "network_cmplog", cfg.network_cmplog);
                if (!err.message.empty()) {
                    return err;
                }
            }
        }

        // --- Parse network ---
        if (!root["network"] || !root["network"].IsMap()) {
            return ConfigError{"network", "Missing or invalid 'network' section", "map", "missing/invalid"};
        }
        {
            ConfigError err = parse_network_section(root["network"], "network", cfg.network);
            if (!err.message.empty()) {
                return err;
            }
        }

        // afl parsing moved earlier (before target_cmplog/network_cmplog) so that
        // the cmplog sections are only required when afl.enable_cmplog is true

        // --- Parse port_detection ---
        if (root["port_detection"]) {
            if (!root["port_detection"].IsMap()) {
                return ConfigError{"port_detection", "Invalid 'port_detection' section", "map", "not a map"};
            }
            YAML::Node pd_node = root["port_detection"];
        // --- Check for unknown keys in port_detection ---
        {
            static const std::unordered_set<std::string> pd_allowed = {"primary", "defork"};
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

            if (pd_node["defork"]) {
                try {
                    cfg.port_detection.defork = pd_node["defork"].as<bool>();
                } catch (const YAML::BadConversion&) {
                    return ConfigError{"port_detection.defork", "Invalid type", "boolean", pd_node["defork"].Scalar()};
                }
            }

            // De-forking is implemented purely in the seccomp BPF filter and
            // is meaningless (and unsafe) in the other port-detection modes.
            if (cfg.port_detection.defork && cfg.port_detection.primary != "seccomp") {
                return ConfigError{"port_detection.defork", "Defork requires seccomp port detection",
                                   "port_detection.primary == \"seccomp\"", cfg.port_detection.primary};
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
    } catch (const ConfigError& e) {
        return e;
    } catch (const std::exception& e) {
        return ConfigError{path, "Unexpected error parsing config: " + std::string(e.what()), "valid config", "exception"};
    }

    return cfg;
}