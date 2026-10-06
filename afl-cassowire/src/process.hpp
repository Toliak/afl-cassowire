// src/process.hpp - rewritten API
// src/process.hpp
// src/process.hpp

#pragma once

#include "config.hpp"
#include <sys/types.h>
#include <vector>
#include <optional>
#include <cstdint>
#include <csignal>

namespace process {

    /**
     * @brief Iterates through /proc to find and kill stale processes matching the cleanup pattern.
     * 
     * Sends SIGTERM, waits for the configured force_kill_ms, and sends SIGKILL if the process 
     * is still alive.
     * 
     * @param cleanup_cfg The cleanup configuration containing the kill pattern and timeouts.
     * */
    void cleanup_stale_processes(const CleanupConfig& cleanup_cfg);

    enum class SpawnMode {
        ProxyMode,   // persistent AFL++ proxy mode
        PlainTest,   // test mode Pass 2 (single iteration)
        MapSizePass  // test mode Pass 1 (map size extraction)
    };

    /**
     * @brief Prepared target execution environment (argv, envp) built in the parent before fork().
     * 
     * All pointers in argv and envp are valid across fork() because they point into
     * owned storage (argv points into cfg.target.args, envp points into env_strings).
     * No heap allocations occur in the child between fork() and execve().
     */
    struct TargetPrepared {
        std::vector<char*> argv;          // nullptr-terminated; points into cfg.target.args
        std::vector<std::string> env_strings; // owns environment strings
        std::vector<char*> envp;          // nullptr-terminated; points into env_strings
    };

    /**
     * @brief Result of fork_target(): the child PID and, for MapSizePass, the read end of the pipe.
     */
    struct SpawnedTarget {
        pid_t pid = -1;                   // -1 indicates failure
        int map_size_fd = -1;             // read end of the pipe for map size; -1 otherwise
    };

    /**
     * @brief Build the child's execution environment (argv, envp) from cfg.
     * 
     * @param cfg global configuration
     * @param mode selects which environment variations to apply (e.g. AFL_DUMP_MAP_SIZE for MapSizePass)
     * @return TargetPrepared on success, std::nullopt on failure (e.g. pipe creation for MapSizePass)
     */
    std::optional<TargetPrepared> prepare_target(const Config& cfg, SpawnMode mode);

    /**
     * @brief Fork the child process, set up its file descriptors and process group, then arm ptrace/seccomp.
     * 
     * The child never returns; on success it execve()s the target binary.
     * 
     * @param cfg global configuration
     * @param prep output from prepare_target()
     * @param mode selects redirection rules and other mode-specific behavior
     * @param publish_pid if non-null, written with the child's PID before any blocking operation
     *                    (intended for g_child_pid in main.cpp to make signal handlers safe)
     * @return SpawnedTarget containing the child PID and, for MapSizePass, the pipe file descriptor
     *         (caller must close map_size_fd after use). On failure, pid == -1.
     */
    SpawnedTarget fork_target(const Config& cfg, const TargetPrepared& prep, SpawnMode mode,
                              volatile sig_atomic_t* publish_pid);

    /**
     * @brief Parent-side tracer handshake after fork_target().
     * 
     * Blocks until the child stops via SIGSTOP (from arm_tracer()), then configures
     * ptrace options and resumes the child with PTRACE_CONT.
     * 
     * @param pid child process ID (must match the value returned by fork_target())
     * @param cfg global configuration (needed for port_detection.primary)
     */
    void handshake_tracer(pid_t pid, const Config& cfg);

    /**
     * @brief Read and parse the map size from the pipe created for MapSizePass.
     * 
     * Consumes exactly one line of output, expects a decimal integer, prints it to stdout.
     * On failure prints an error to stderr but does not return an error code (matches legacy behavior).
     * 
     * @param pipe_read_fd read end of the pipe (will be closed by this function)
     */
    void collect_map_size(int pipe_read_fd);

} // namespace process