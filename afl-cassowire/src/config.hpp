// src/config.hpp

#pragma once

#include <cstddef>
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

struct TargetConfig {
    std::string binary;
    std::vector<std::string> args;
    // Environment variable handling for the target process.
    enum class EnvPreserveLevel {
        nothing,   // Inherit no environment variables
        afl_only,  // Inherit only PATH, __AFL_SHM_ID, __AFL_CMPLOG_SHM_ID, and
                   // ___AFL_EINS_ZWEI_POLIZEI___ (QEMU CmpLog trigger) when set
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
    // Post-response quiescence probe (see network::probe_target): after each
    // exchange, a throwaway connection is opened and the proxy waits until the
    // target services it. Disabled for targets that rate-limit connections or
    // cannot tolerate an extra short-lived connection per iteration.
    bool probe = true;
    // Delay in milliseconds between probe retries when the first probe fails.
    // Set to 0 for no delay.
    int probe_retry_ms = 5;
    // Total number of probe attempts per iteration (first attempt + retries).
    // Must be >= 1. Default 2 preserves the historical two-strike behavior:
    // a failed probe is retried once before the proxy aborts. Higher values
    // tolerate flaky listeners at the cost of up to
    // (probe_attempts - 1) * (timeout_ms + probe_retry_ms) added latency.
    int probe_attempts = 2;
};

struct AflConfig {
    int loop_count = 50000;
    bool enable_cmplog = false;
    // Discard all coverage collected before the first __AFL_LOOP() pass (proxy
    // startup + the target's initialization, both written into the shared
    // coverage map) via __AFL_COVERAGE_DISCARD() right before the loop, so
    // afl-fuzz does not attribute the startup snapshot to the first fuzzed
    // testcase (low stability).
    bool cov_discard_init = true;
    // Number of completed iterations whose payloads are retained and written
    // alongside a termination dump (crash_proxy()/abort_proxy()) as
    // <stem>.-1.data, <stem>.-2.data, ... (-1 = most recent previous
    // iteration). A deferred/async crash is detected one iteration late, so the
    // current payload may not be the input that caused it; the retained history
    // preserves the likely culprit. 0 disables the history (only <stem>.data is
    // written). Must be 0-64.
    std::size_t dump_history = 1;
    // Log level for the warn/error ring sink whose captured lines are embedded
    // into termination .msg dumps (see casslog::recent_lines()). Only affects the
    // dump content, not the console (that is --log-level). Must be a level name
    // accepted by casslog::parse_level(); the type is checked by load_config(), the
    // name by main() (config.cpp cannot include log.hpp). Default warn.
    std::string msg_log_level = "warn";
};

struct PortDetectionConfig {
    std::string primary = "procfs"; // "procfs" or "seccomp"
    // "seccomp": the target runs with a SECCOMP_RET_USER_NOTIF filter on
    // bind()/listen() installed before its execve(); the proxy polls the
    // notification fd, which aggregates those syscalls from every thread and
    // forked descendant (kernel >= 5.0).
    // procfs only (silently ignored by seccomp, which verifies ownership by
    // construction): require the matched LISTEN socket's inode to be held by the
    // target or one of its descendants (/proc/<pid>/fd readlinks), so a stale or
    // foreign listener no longer satisfies port detection. When the fd directory
    // of a target-tree pid is unreadable (EACCES/EPERM, e.g. a setuid target that
    // dropped privileges), the port is accepted unverified with a WARN.
    // Independent of this flag, the procfs loop checks waitpid(WNOHANG) every
    // pass, so a target that dies during startup reports TargetDied.
    bool verify_ownership = true;
};

struct CleanupConfig {
    // Pre-spawn handling of the configured listening port. Disabled by default:
    // the proxy then never scans /proc and any conflict surfaces through normal
    // target/port-detection failure.
    bool enabled = false;
    enum class PortConflictPolicy {
        error,      // report the conflicting listener and refuse to start
        kill_orphan // SIGKILL orphaned holders of this port (see process.cpp)
    };
    PortConflictPolicy on_port_conflict = PortConflictPolicy::error;
};

// Optional prefix/suffix wrapped around every payload sent to the target
// (both in `proxy` and `test` mode). The data transmitted over TCP is:
//   prefix + fuzz input + suffix
// Values are raw bytes; in YAML they may be plain strings or `!!binary`.
struct PayloadConfig {
    std::vector<uint8_t> prefix;  // Prepended to each payload (empty if unset)
    std::vector<uint8_t> suffix;  // Appended to each payload (empty if unset)
};

struct Config {
    TargetConfig target;
    TargetConfig target_cmplog;  // compare-mode target, used instead of `target` when __AFL_CMPLOG_SHM_ID is set
    NetworkConfig network;
    NetworkConfig network_cmplog;  // compare-mode network, used instead of `network` when __AFL_CMPLOG_SHM_ID is set
                                   // (self-contained: no keys fall back to `network`)
    AflConfig afl;
    PortDetectionConfig port_detection;
    CleanupConfig cleanup;
    PayloadConfig payload;
};

// Loads and strictly validates the YAML configuration file.
// Returns a Config on success, or a ConfigError on failure.
std::variant<Config, ConfigError> load_config(const std::string& path);