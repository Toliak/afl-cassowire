// src/process.hpp

#pragma once

#include "config.hpp"
#include <sys/types.h>

namespace process {

    /**
     * @brief Iterates through /proc to find and kill stale processes matching the cleanup pattern.
     * 
     * Sends SIGTERM, waits for the configured force_kill_ms, and sends SIGKILL if the process 
     * is still alive.
     * 
     * @param cleanup_cfg The cleanup configuration containing the kill pattern and timeouts.
     */
    void cleanup_stale_processes(const CleanupConfig& cleanup_cfg);

    /**
     * @brief Forks and executes the target application with appropriate environment and stream redirection.
     * 
     * Handles ptrace/seccomp setup in the child process before execve() if configured.
     * 
     * @param cfg The global configuration.
     * @param is_map_size_pass If true (Test Mode Pass 1), sets up a pipe for stdout to capture 
     *                         AFL_DUMP_MAP_SIZE output. The function will block to read/parse 
     *                         the map size, print it to the console, and close the pipe before returning.
     * @param is_proxy_mode If true, redirects stdout/stderr to configured log files. 
     *                      If false (and not map size pass), inherits the proxy's stdout/stderr.
     * @return pid_t The PID of the spawned child process, or -1 on failure.
     */
    pid_t spawn_target(const Config& cfg, bool is_map_size_pass, bool is_proxy_mode);

} // namespace process