// src/config.hpp

#pragma once

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
    // TODO(claude): `env` and `env_preserve` are not in the spec's YAML schema (sec. 4.2) - either document
    //   them in the spec or remove. Also: with env_preserve=false the target gets ONLY PATH + __AFL_SHM_ID
    //   (see process.cpp), which is a surprising default for an AFL harness.
    // SOLUTION: yes, let's change from bool to enum: `nothing`, `afl-only`, `all`.
    //           nothing -- literally no variables. 
    //           afl-only -- `PATH`, `__AFL_SHM_ID` and `__AFL_CMPLOG_SHM_ID`. 
    //           all -- everything.
    std::unordered_map<std::string, std::string> env;  // Environment variables for target
    bool env_preserve = false;  // Preserve parent environment variables
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

struct Config {
    TargetConfig target;
    NetworkConfig network;
    AflConfig afl;
    PortDetectionConfig port_detection;
    CleanupConfig cleanup;
};

// Loads and strictly validates the YAML configuration file.
// Returns a Config on success, or a ConfigError on failure.
std::variant<Config, ConfigError> load_config(const std::string& path);