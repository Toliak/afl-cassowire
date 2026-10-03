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
    std::unordered_map<std::string, std::string> env;  // Environment variables for target
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