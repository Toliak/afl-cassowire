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

    /**
     * @brief Collect @p root and all of its descendants (the "target tree").
     *
     * BFS over the process tree: for each pid the children are read from
     * /proc/<pid>/task/<tid>/children (one file per thread, because clone()
     * makes a child a child of the *thread* that created it); when those files
     * are unavailable (kernel built without CONFIG_PROC_CHILDREN) or unreadable,
     * each pid falls back to a /proc scan matching the ppid field of
     * /proc/<pid>/stat (which misses children created by non-leader threads -
     * a best-effort fallback only). Used by procfs port detection to attribute
     * a listening socket inode to the target or one of its workers
     * (NGINX-style).
     *
     * Best-effort: a pid that vanishes mid-scan contributes no children, and
     * pid reuse can theoretically graft a foreign (short-lived) subtree onto
     * the result - which can only produce a false-positive ownership match,
     * never a missed one.
     *
     * @param root The pid to start from (included in the result).
     * @return The tree in BFS order (root first), duplicates removed.
     */
    std::vector<pid_t> collect_pid_tree(pid_t root);

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
     * @brief Result of fork_target(): the child PID, the map-size pipe (Pass 1),
     *        and the seccomp notification listener fd when applicable.
     */
    struct SpawnedTarget {
        pid_t pid = -1;                   // -1 indicates failure
        int map_size_fd = -1;             // read end of the pipe for map size; -1 otherwise
        int notif_fd = -1;                // SECCOMP_RET_USER_NOTIF listener for the target;
                                          // -1 when port_detection.primary != "seccomp"
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
     * @brief Fork the child process, set up its file descriptors and process group,
     *        and (in seccomp mode) hand the target's notification listener to the parent.
     *
     * The child never returns; on success it execve()s the target binary.
     *
     * Stdin is always redirected to /dev/null. The child's stdout/stderr are
     * forwarded to the proxy's descriptors when @p forward_output is true,
     * and sent to /dev/null otherwise. MapSizePass ignores @p forward_output:
     * its stdout is a pipe carrying the map size and its stderr goes to
     * /dev/null.
     *
     * With port_detection.primary == "seccomp" (every mode except MapSizePass,
     * which performs no port detection) the child installs the bind()/listen()
     * SECCOMP_RET_USER_NOTIF filter (SECCOMP_FILTER_FLAG_NEW_LISTENER) before
     * execve(), passes the returned listener fd to the parent over a private
     * socketpair via SCM_RIGHTS, and waits for a 1-byte ack; the parent returns
     * with SpawnedTarget::notif_fd set (non-blocking, owned by the caller). No
     * ptrace is involved. A failed handshake kills+reaps the child and returns
     * pid == -1.
     *
     * @param cfg global configuration
     * @param prep output from prepare_target()
     * @param mode selects redirection rules and other mode-specific behavior
     * @param forward_output forward the child's stdout/stderr to the proxy's
     *                       descriptors (--child-output flag) instead of /dev/null
     * @param publish_pid if non-null, written with the child's PID before any blocking operation
     *                    (intended for g_child_pid in main.cpp to make signal handlers safe)
     * @return SpawnedTarget containing the child PID, the map-size pipe fd for
     *         MapSizePass (caller must close it after use), and the seccomp
     *         notification listener fd in seccomp mode. On failure, pid == -1.
     */
    SpawnedTarget fork_target(const Config& cfg, const TargetPrepared& prep, SpawnMode mode,
                              bool forward_output, volatile sig_atomic_t* publish_pid);

    /**
     * @brief Result of wait_target_exit().
     */
    struct TargetExit {
        bool exited = false; ///< true when the child was reaped; status is then valid
        int status = 0;      ///< raw waitpid() status, valid only when exited == true
    };

    /**
     * @brief Wait (bounded) for the target child to exit.
     *
     * Polls waitpid(WNOHANG) with a short sleep so @p timeout_ms is always
     * enforced; the target is NOT killed here. The child is never ptraced
     * anymore, so waitpid cannot report ptrace stops (WUNTRACED is not set and
     * group-stops are not observed).
     *
     * @param pid Target pid (must be our direct child).
     * @param timeout_ms Upper bound on the total wait.
     * @return TargetExit with exited == true and the raw status when the child died;
     *         exited == false on timeout, waitpid failure, or a non-child pid (ECHILD).
     */
    [[nodiscard]] TargetExit wait_target_exit(pid_t pid, uint64_t timeout_ms);

    /**
     * @brief Read and parse the map size from the pipe created for MapSizePass.
     *
     * Consumes exactly one line of output, expects a decimal integer, logs it.
     * On failure logs an error but does not return an error code (matches legacy behavior).
     *
     * @param pipe_read_fd read end of the pipe (will be closed by this function)
     */
    void collect_map_size(int pipe_read_fd);

    /**
     * @brief Open a pollable PID file descriptor for an existing process.
     *
     * Wraps pidfd_open(2) (there is no glibc wrapper). The returned descriptor
     * becomes readable (POLLIN) once the task terminates and turns into a
     * zombie, and reports hang-up (POLLHUP) once it is reaped. This lets the
     * caller block on process death with poll() instead of sleeping or busy
     * polling, and also pins the pid against PID reuse.
     *
     * @param pid The process to obtain a pidfd for.
     * @return >=0 The pidfd on success (caller owns it, close when done),
     *         -1 on failure with errno set (e.g. ESRCH, ENOSYS on < 5.3).
     */
    [[nodiscard]] int open_pidfd(pid_t pid);

    /**
     * @brief Observed state of the target process at a point in time.
     */
    struct TargetState {
        enum class Kind {
            Alive,    ///< still running (the normal case; nothing to report)
            Crashed,  ///< terminated by a signal (status holds the waitpid status)
            Exited,   ///< terminated normally via exit() (status holds the waitpid status)
            Unknown,  ///< not our child / already reaped elsewhere (ECHILD)
        };

        Kind kind = Kind::Alive;
        int status = 0;  ///< raw waitpid() status for Crashed/Exited, 0 otherwise

        /// @brief Human-readable description of the state.
        std::string to_string() const;
    };

    /**
     * @brief Determine whether the target is alive, crashed, or exited.
     *
     * Race-free replacement for a bare waitpid(WNOHANG) health check. The
     * problem it solves: do_exit() closes the process's file descriptors
     * before it makes the task a waitable zombie, so a crash-triggered socket
     * EOF/RST can be observed a moment before waitpid(WNOHANG) would succeed.
     * A single WNOHANG poll right after the response therefore misses the
     * crash and attributes it to the wrong (next) input.
     *
     * Sequence:
     *   1. waitpid(WNOHANG): if the target is already a zombie, classify it.
     *   2. Otherwise read the `flags` field of /proc/<pid>/stat (and, for a
     *      threaded target, each /proc/<pid>/task/tid/stat). PF_EXITING or PF_SIGNALED
     *      is set at the start of fatal-signal/exit handling, i.e. BEFORE file
     *      descriptors are torn down, so it tells us the target is dying even
     *      while waitpid(WNOHANG) still reports it alive.
     *   3. If dying flags are seen, block on the pidfd until the task becomes
     *      a zombie (bounded by grace_ms, so a hung coredump cannot wedge the
     *      proxy), then reap and classify.
     *   4. Otherwise the target is alive.
     *
     * @param pid       Target pid (the direct child; fork-less targets only).
     * @param pidfd     Pollable pidfd from open_pidfd(), or -1 to disable the
     *                  bounded wait (then a dying-but-not-yet-zombie target is
     *                  reported Alive and retried on the next call).
     * @param grace_ms  Upper bound on how long to wait for the death to
     *                  materialise after dying flags are observed.
     * @return TargetState The observed state.
     */
    [[nodiscard]] TargetState check_target_state(pid_t pid, int pidfd, int grace_ms);

} // namespace process