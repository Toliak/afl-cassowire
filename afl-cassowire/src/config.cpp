// src/config.cpp

#include "config.hpp"
#include <yaml-cpp/yaml.h>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <unordered_set>
#include <vector>
#include <arpa/inet.h>

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

// Reads a byte-oriented scalar: a plain string keeps its bytes, a YAML
// `!!binary` tagged scalar is base64-decoded by yaml-cpp, and a null node is
// an empty value. Used by payload prefix/suffix and the sequence section.
// Returns false for non-scalar nodes (sequences/maps).
bool read_bytes_value(const YAML::Node& node, std::vector<uint8_t>& out) {
    out.clear();
    if (!node || node.IsNull()) {
        return true;
    }
    if (!node.IsScalar()) {
        return false;
    }
    const std::string tag = node.Tag();
    static const std::string kBinarySuffix = ":binary";
    if (tag.size() >= kBinarySuffix.size() &&
        tag.compare(tag.size() - kBinarySuffix.size(), kBinarySuffix.size(), kBinarySuffix) == 0) {
        try {
            const YAML::Binary bin = node.as<YAML::Binary>();
            if (bin.size() > 0) {
                out.assign(bin.data(), bin.data() + bin.size());
            }
        } catch (const YAML::Exception&) {
            return false;
        }
        return true;
    }
    const std::string s = node.as<std::string>();
    out.assign(s.begin(), s.end());
    return true;
}

// Parses a target-shaped section ("binary"/"args"/"env"/"env_preserve"). `prefix`
// is the config path used in errors (e.g. "target", "target_cmplog"). Sections
// are standalone: no values are inherited from any other section.
// Returns a ConfigError with an empty message on success.
ConfigError parse_target_section(const YAML::Node& node, const std::string& prefix, TargetConfig& out) {
    static const std::unordered_set<std::string> target_allowed = {"binary", "args", "env", "env_preserve", "stdin_path"};
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

    if (node["stdin_path"]) {
        if (!node["stdin_path"].IsScalar()) {
            return ConfigError{prefix + ".stdin_path", "Invalid type", "string", "not a string"};
        }
        std::string stdin_path = node["stdin_path"].as<std::string>();
        if (stdin_path.empty()) {
            return ConfigError{prefix + ".stdin_path", "Must not be empty", "non-empty path", "empty string"};
        }
        // Existence is deliberately not checked here: the file (e.g. a fifo)
        // may be created by the surrounding setup after the config is loaded.
        // An unopenable path fails at spawn time with a clear error instead.
        out.stdin_path = stdin_path;
    }

    return ConfigError{"", "", "", ""}; // no error
}

// Parses a network-shaped section ("host"/"port"/"timeout_ms"/"initial_ms"/"probe").
// `prefix` is the config path used in errors (e.g. "network", "network_cmplog").
// Sections are standalone: no values are inherited from any other section.
// Returns a ConfigError with an empty message on success.
ConfigError parse_network_section(const YAML::Node& node, const std::string& prefix, NetworkConfig& out) {
    static const std::unordered_set<std::string> network_allowed = {"host", "port", "timeout_ms", "initial_ms", "probe", "probe_retry_ms", "probe_attempts"};
    ConfigError err = check_unknown_keys(node, network_allowed, prefix);
    if (!err.message.empty()) {
        return err;
    }

    if (node["host"]) {
        if (!node["host"].IsScalar()) return ConfigError{prefix + ".host", "Invalid type", "string", "not a string"};
        // The client (network.cpp connect_target()) resolves the host with
        // inet_pton(AF_INET) only, so reject anything that is not an IPv4
        // dotted-quad literal here instead of failing later at connect time.
        const std::string host = node["host"].as<std::string>();
        struct in_addr addr = {};
        if (inet_pton(AF_INET, host.c_str(), &addr) != 1) {
            return ConfigError{prefix + ".host", "Not an IPv4 dotted-quad address",
                               "IPv4 dotted-quad address (e.g. 127.0.0.1)", host};
        }
        out.host = host;
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

    if (node["probe_attempts"]) {
        try {
            out.probe_attempts = node["probe_attempts"].as<int>();
            if (out.probe_attempts < 1) {
                return ConfigError{prefix + ".probe_attempts", "Must be >= 1", "integer >= 1", std::to_string(out.probe_attempts)};
            }
        } catch (const YAML::BadConversion&) {
            return ConfigError{prefix + ".probe_attempts", "Invalid type", "integer >= 1", node["probe_attempts"].Scalar()};
        }
    }

    return ConfigError{"", "", "", ""}; // no error
}

// Parses the optional sequence section. All keys are type/range-checked
// whenever the section exists; `delimiter` is required (and non-empty) only
// when enabled. Returns a ConfigError with an empty message on success.
ConfigError parse_sequence_section(const YAML::Node& node, SequenceConfig& out) {
    static const std::unordered_set<std::string> sequence_allowed = {
        "enabled", "delimiter", "keep_delimiter", "response_poll_us",
        "initial_poll_us", "final_poll_us", "max_messages",
        "message_prefix", "message_suffix"};
    ConfigError err = check_unknown_keys(node, sequence_allowed, "sequence");
    if (!err.message.empty()) {
        return err;
    }

    if (node["enabled"]) {
        try {
            out.enabled = node["enabled"].as<bool>();
        } catch (const YAML::BadConversion&) {
            return ConfigError{"sequence.enabled", "Invalid type", "boolean", node["enabled"].Scalar()};
        }
    }

    if (node["delimiter"] && !read_bytes_value(node["delimiter"], out.delimiter)) {
        return ConfigError{"sequence.delimiter", "Invalid type", "string or !!binary bytes",
                           "not a string or binary"};
    }
    if (out.enabled && (!node["delimiter"] || out.delimiter.empty())) {
        return ConfigError{"sequence.delimiter",
                           "Missing or empty delimiter in sequence mode",
                           "non-empty string or !!binary bytes",
                           node["delimiter"] ? "empty" : "missing"};
    }

    if (node["keep_delimiter"]) {
        try {
            out.keep_delimiter = node["keep_delimiter"].as<bool>();
        } catch (const YAML::BadConversion&) {
            return ConfigError{"sequence.keep_delimiter", "Invalid type", "boolean",
                               node["keep_delimiter"].Scalar()};
        }
    }

    // Poll windows: [0, 5s] in microseconds. 0 disables the wait (one
    // non-blocking drain only).
    const auto parse_poll_us = [&](const char* key, int& value) -> ConfigError {
        YAML::Node n = node[key];
        if (!n) return ConfigError{"", "", "", ""};
        try {
            const int v = n.as<int>();
            if (v < 0 || v > 5000000) {
                return ConfigError{std::string("sequence.") + key, "Out of range",
                                   "integer 0-5000000 (microseconds)", std::to_string(v)};
            }
            value = v;
        } catch (const YAML::BadConversion&) {
            return ConfigError{std::string("sequence.") + key, "Invalid type",
                               "integer 0-5000000 (microseconds)", n.Scalar()};
        }
        return ConfigError{"", "", "", ""};
    };
    struct PollKey {
        const char* key;
        int* value;
    };
    const PollKey poll_keys[] = {
        {"response_poll_us", &out.response_poll_us},
        {"initial_poll_us", &out.initial_poll_us},
        {"final_poll_us", &out.final_poll_us},
    };
    for (const auto& item : poll_keys) {
        ConfigError e = parse_poll_us(item.key, *item.value);
        if (!e.message.empty()) return e;
    }

    if (node["max_messages"]) {
        try {
            const int v = node["max_messages"].as<int>();
            if (v < 1 || v > 1024) {
                return ConfigError{"sequence.max_messages", "Out of range", "integer 1-1024",
                                   std::to_string(v)};
            }
            out.max_messages = v;
        } catch (const YAML::BadConversion&) {
            return ConfigError{"sequence.max_messages", "Invalid type", "integer 1-1024",
                               node["max_messages"].Scalar()};
        }
    }

    if (node["message_prefix"] && !read_bytes_value(node["message_prefix"], out.message_prefix)) {
        return ConfigError{"sequence.message_prefix", "Invalid type", "string or !!binary bytes",
                           "not a string or binary"};
    }
    if (node["message_suffix"] && !read_bytes_value(node["message_suffix"], out.message_suffix)) {
        return ConfigError{"sequence.message_suffix", "Invalid type", "string or !!binary bytes",
                           "not a string or binary"};
    }

    return ConfigError{"", "", "", ""}; // no error
}

// Reads the config file as raw text and expands environment variables before
// any YAML parsing happens. Supported syntax:
//   $$               -> literal '$' (escape, prevents accidental expansion)
//   ${NAME}          -> value of NAME; unset NAME is a hard error
//                       (use ${NAME:-} for an empty fallback)
//   ${NAME:-word}    -> value of NAME, or `word` when NAME is unset or empty
//   ${NAME:?message} -> value of NAME; unset/empty NAME is a ConfigError
//                       whose message ends with `message`
// `word`/`message` are used verbatim (no nested expansion, a `}` cannot be
// part of them). A lone '$' not followed by '{' or '$' is kept verbatim.
// Expansion is a plain textual substitution applied to the whole file, so
// quoted YAML values should be used when a substituted value could change the
// scalar type (e.g. port: "${PORT}").
std::variant<std::string, ConfigError> read_and_expand_env(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        return ConfigError{"", "Failed to load YAML file: cannot open file", "valid file", path};
    }
    std::stringstream ss;
    ss << in.rdbuf();
    std::string text = ss.str();

    std::string out;
    out.reserve(text.size());

    size_t pos = 0;
    while (pos < text.size()) {
        size_t dollar = text.find('$', pos);
        if (dollar == std::string::npos) {
            out.append(text, pos, std::string::npos);
            break;
        }
        out.append(text, pos, dollar - pos);
        pos = dollar;

        if (pos + 1 < text.size() && text[pos + 1] == '$') {
            out += '$'; // "$$" escape
            pos += 2;
            continue;
        }
        if (pos + 1 >= text.size() || text[pos + 1] != '{') {
            out += '$'; // lone '$', kept verbatim
            pos += 1;
            continue;
        }

        size_t close = text.find('}', pos + 2);
        if (close == std::string::npos) {
            return ConfigError{"", "Unterminated '${' in config file", "'}'", "missing"};
        }

        std::string inner = text.substr(pos + 2, close - pos - 2);
        std::string name = inner;
        char op = '\0'; // '\0' = plain ${NAME}, '-' = ${NAME:-word}, '?' = ${NAME:?msg}
        std::string word;
        size_t colon = inner.find(':');
        if (colon != std::string::npos) {
            name = inner.substr(0, colon);
            std::string rest = inner.substr(colon + 1);
            if (!rest.empty() && (rest[0] == '-' || rest[0] == '?')) {
                op = rest[0];
                word = rest.substr(1);
            } else {
                return ConfigError{"", "Invalid parameter expansion '${" + inner + "}'",
                                   "${NAME}, ${NAME:-word}, or ${NAME:?message}", inner};
            }
        }

        if (name.empty() || name.find_first_not_of(
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") != std::string::npos) {
            return ConfigError{"", "Invalid environment variable name in '${" + inner + "}'",
                               "[A-Za-z0-9_]+", name.empty() ? "(empty)" : name};
        }

        const char* value = getenv(name.c_str());
        bool missing = (value == nullptr) || value[0] == '\0';
        if (missing && op == '-') {
            out += word; // ${NAME:-word}: use fallback on unset or empty
        } else if (missing && op == '?') {
            std::string message = "Environment variable '" + name + "' is not set or empty";
            if (!word.empty()) {
                message += ": " + word;
            }
            return ConfigError{"", message, "set environment variable '" + name + "'", "unset/empty"};
        } else if (missing) {
            return ConfigError{"", "Environment variable '" + name + "' is not set",
                               "set it, use ${" + name + ":-fallback}, or ${" + name + ":?message}", "unset"};
        } else {
            out += value;
        }
        pos = close + 1;
    }
    return out;
}

} // namespace

std::variant<Config, ConfigError> load_config(const std::string& path) {
    Config cfg;
    
    try {
        // Expand environment variables (${NAME}, ${NAME:-word}, ${NAME:?msg})
        // in the raw file text before YAML parsing.
        auto expanded = read_and_expand_env(path);
        if (std::holds_alternative<ConfigError>(expanded)) {
            return std::get<ConfigError>(expanded);
        }
        YAML::Node root = YAML::Load(std::get<std::string>(expanded));
        if (!root.IsMap()) {
            return ConfigError{"", "Root node must be a map", "map", root.Type() == YAML::NodeType::Null ? "null" : "other"};
        }

        // Resolve YAML merge keys (<<) before validation
        resolve_merge_keys(root, "");

        // --- Check for unknown keys at root ---
        // Root keys starting with "__" are ignored: they are reserved for
        // helper fragments anchored for reuse (aliases / merge keys) below.
        {
            static const std::unordered_set<std::string> root_allowed = {"target", "target_cmplog", "network", "network_cmplog", "afl", "port_detection", "cleanup", "payload", "sequence"};
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
                static const std::unordered_set<std::string> afl_allowed = {"loop_count", "enable_cmplog",
                                                                            "cov_discard_init", "dump_history",
                                                                            "msg_log_level"};
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
            if (afl_node["cov_discard_init"]) {
                try {
                    cfg.afl.cov_discard_init = afl_node["cov_discard_init"].as<bool>();
                } catch (const YAML::BadConversion&) {
                    return ConfigError{"afl.cov_discard_init", "Invalid type", "boolean", afl_node["cov_discard_init"].Scalar()};
                }
            }
            if (afl_node["dump_history"]) {
                try {
                    const int v = afl_node["dump_history"].as<int>();
                    if (v < 0 || v > 64) {
                        return ConfigError{"afl.dump_history", "Must be 0-64", "integer 0-64", std::to_string(v)};
                    }
                    cfg.afl.dump_history = static_cast<std::size_t>(v);
                } catch (const YAML::BadConversion&) {
                    return ConfigError{"afl.dump_history", "Invalid type", "integer", afl_node["dump_history"].Scalar()};
                }
            }
            if (afl_node["msg_log_level"]) {
                // Only the type is checked here: the level *name* is validated
                // in main() via casslog::parse_level(). config.cpp cannot include
                // log.hpp — yaml-cpp pulls in <cmath>, whose ::log collides
                // with the `log` namespace.
                if (!afl_node["msg_log_level"].IsScalar()) {
                    return ConfigError{"afl.msg_log_level", "Invalid type", "log level name", "not a string"};
                }
                cfg.afl.msg_log_level = afl_node["msg_log_level"].as<std::string>();
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
            static const std::unordered_set<std::string> pd_allowed = {"primary", "verify_ownership"};
            ConfigError err = check_unknown_keys(pd_node, pd_allowed, "port_detection");
            if (!err.message.empty()) {
                return err;
            }
        }

            if (pd_node["primary"]) {
                if (!pd_node["primary"].IsScalar()) return ConfigError{"port_detection.primary", "Invalid type", "string", "not a string"};
                std::string primary = pd_node["primary"].as<std::string>();
                if (primary != "procfs" && primary != "seccomp") {
                    return ConfigError{"port_detection.primary", "Invalid enum value", "procfs or seccomp", primary};
                }
                cfg.port_detection.primary = primary;
            }

            if (pd_node["verify_ownership"]) {
                try {
                    cfg.port_detection.verify_ownership = pd_node["verify_ownership"].as<bool>();
                } catch (const YAML::BadConversion&) {
                    return ConfigError{"port_detection.verify_ownership", "Invalid type", "boolean", pd_node["verify_ownership"].Scalar()};
                }
                // Only meaningful for procfs: seccomp(user-notif) watches the
                // target's own bind()/listen() notifications and therefore
                // verifies ownership by construction. Silently ignored there.
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
                static const std::unordered_set<std::string> cleanup_allowed = {"enabled", "on_port_conflict"};
                ConfigError err = check_unknown_keys(clean_node, cleanup_allowed, "cleanup");
                if (!err.message.empty()) {
                    return err;
                }
            }

            if (clean_node["enabled"]) {
                if (!clean_node["enabled"].IsScalar()) {
                    return ConfigError{"cleanup.enabled", "Invalid type", "boolean", "not a scalar"};
                }
                try {
                    cfg.cleanup.enabled = clean_node["enabled"].as<bool>();
                } catch (const YAML::BadConversion&) {
                    return ConfigError{"cleanup.enabled", "Invalid type", "boolean", clean_node["enabled"].Scalar()};
                }
            }

            if (clean_node["on_port_conflict"]) {
                if (!clean_node["on_port_conflict"].IsScalar()) {
                    return ConfigError{"cleanup.on_port_conflict", "Invalid type", "error or kill_orphan", "not a string"};
                }
                const std::string policy = clean_node["on_port_conflict"].as<std::string>();
                if (policy == "error") {
                    cfg.cleanup.on_port_conflict = CleanupConfig::PortConflictPolicy::error;
                } else if (policy == "kill_orphan") {
                    cfg.cleanup.on_port_conflict = CleanupConfig::PortConflictPolicy::kill_orphan;
                } else {
                    return ConfigError{"cleanup.on_port_conflict", "Invalid enum value", "error or kill_orphan", policy};
                }
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

                   if (payload_node["prefix"] &&
                       !read_bytes_value(payload_node["prefix"], cfg.payload.prefix)) {
                       return ConfigError{"payload.prefix", "Invalid type", "string or binary",
                                          "not a string or binary"};
                   }

                   if (payload_node["suffix"] &&
                       !read_bytes_value(payload_node["suffix"], cfg.payload.suffix)) {
                       return ConfigError{"payload.suffix", "Invalid type", "string or binary",
                                          "not a string or binary"};
                   }
               }
           }

        // --- Parse sequence (AFLNet-style message sequences) ---
        if (root["sequence"]) {
            if (root["sequence"].IsNull()) {
                // null section is treated as empty (same as omitting it)
            } else if (!root["sequence"].IsMap()) {
                return ConfigError{"sequence", "Invalid 'sequence' section", "map", "not a map"};
            } else {
                ConfigError err = parse_sequence_section(root["sequence"], cfg.sequence);
                if (!err.message.empty()) {
                    return err;
                }
            }
        }

        // Sequence mode wraps each message with sequence.message_prefix/suffix;
        // the legacy payload wrappers are ambiguous there (double delimiters),
        // so reject the combination instead of silently applying both.
        if (cfg.sequence.enabled && (!cfg.payload.prefix.empty() || !cfg.payload.suffix.empty())) {
            return ConfigError{"payload",
                               "payload.prefix/suffix cannot be combined with sequence.enabled",
                               "omit the payload section in sequence mode; use "
                               "sequence.message_prefix/message_suffix",
                               "payload is set"};
        }

    } catch (const ConfigError& e) {
        return e;
    } catch (const std::exception& e) {
        return ConfigError{path, "Unexpected error parsing config: " + std::string(e.what()), "valid config", "exception"};
    }

    return cfg;
}