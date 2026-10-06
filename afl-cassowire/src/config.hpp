// src/config.hpp

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <variant>
#include <optional>
#include <unordered_map>

struct ConfigError {
    std::string path;     // e.g., "network.port"
    std::string message;  // Human readable error
    std::string expected; // e.g., "integer 1-65535"
    std::string actual;   // e.g., "string 'eighty'"
    
    std::string to_string() const;
};

struct TargetLog {
    std::string stdout_path;
    std::string stderr_path;
};

struct TargetConfig {
    std::string binary;
    std::vector<std::string> args;
    TargetLog log;
    // Environment variable handling for the target process.
    enum class EnvPreserveLevel {
        nothing,   // Inherit no environment variables
        afl_only,  // Inherit only PATH, __AFL_SHM_ID, and __AFL_CMPLOG_SHM_ID
        all        // Inherit the entire parent environment
    };
    std::unordered_map<std::string, std::string> env;  // Environment variables for target
    EnvPreserveLevel env_preserve = EnvPreserveLevel::afl_only;  // How to handle parent environment
};

struct NetworkConfig {
    std::string host = "127.0.0.1";
    int port = 0;
    int timeout_ms = 200;
    int initial_ms = 200;
};

struct AflConfig {
    int loop_count = 50000;
    bool enable_cmplog = false;
};

struct PortDetectionConfig {
    std::string primary = "procfs"; // "procfs", "ptrace", "seccomp"
};

struct KillPattern {
    std::string type;   // "comm" or "regexp"
    std::string value;  // Pattern or string
    std::string target; // "comm", "argv0", "argv" (used if type == "regexp")
};

struct CleanupConfig {
    int force_kill_ms = 2000;
    std::optional<KillPattern> kill_pattern;
};

// Optional prefix/suffix wrapped around every payload sent to the target
// (both in `proxy` and `test` mode). The data transmitted over TCP is:
//   prefix + fuzz input + suffix
// Values are raw bytes; in YAML they may be plain strings or `!!binary`.
struct PayloadConfig {
    std::vector<uint8_t> prefix;  // Prepended to each payload (empty if unset)
    std::vector<uint8_t> suffix;  // Appended to each payload (empty if unset)

    // Builds the final payload from the fuzz input buffer.
    std::vector<uint8_t> wrap(const uint8_t* data, size_t len) const;
};

struct Config {
    TargetConfig target;
    NetworkConfig network;
    AflConfig afl;
    PortDetectionConfig port_detection;
    CleanupConfig cleanup;
    PayloadConfig payload;
};

// Loads and strictly validates the YAML configuration file.
// Returns a Config on success, or a ConfigError on failure.
std::variant<Config, ConfigError> load_config(const std::string& path);