// src/process.hpp - rewritten API
// src/process.hpp
// src/process.hpp

#pragma once

#include "config.hpp"
#include <sys/types.h>
#include <vector>
#include <optional>
#include <cstdint>

namespace process {

    /**
     * @brief Pre-spawn handling of a listener already bound to the configured port.
     *
     * No-op when cleanup.enabled is false. Otherwise resolves the LISTEN socket
     * inode from /proc/net/tcp{,6} and the processes holding it:
     *  - a holder with a live parent (cmplog target, another campaign, a
     *    service) is never touched; the preflight refuses to start;
     *  - with on_port_conflict=error, an orphaned holder is reported and the
     *    preflight refuses to start;
     *  - with on_port_conflict=kill_orphan, an orphaned holder that matches the
     *    configured target binary/argv[0] is SIGKILLed together with its
     *    process tree. There is no SIGTERM/grace phase; the port is re-checked
     *    briefly afterwards.
     *
     * Called only in proxy mode, after the AFL environment has been validated
     * and the normal/cmplog config has been selected, before __AFL_INIT().
     *
     * @param cfg The resolved configuration (target/network already reflect
     *            normal vs cmplog mode).
     * @return true if the proxy may proceed (port free or successfully freed),
     *         false if it must not start.
     */
    bool handle_port_conflict(const Config& cfg);

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
        // Descriptor for cfg.target.stdin_path, opened by prepare_target()
        // (ProxyMode/PlainTest only - MapSizePass never opens it, so an
        // external fifo writer cannot deliver data a pass that never reads
        // stdin would lose) and dup2()ed onto the child's fd 0 by
        // fork_target(); -1 when stdin_path is unset. fork_target() closes the
        // parent's copy after the fork, so this field is invalid afterwards.
        int stdin_fd = -1;
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
     * @return TargetPrepared on success, std::nullopt on failure (e.g. pipe creation for
     *         MapSizePass or an unopenable target.stdin_path)
     */
    std::optional<TargetPrepared> prepare_target(const Config& cfg, SpawnMode mode);

    /**
     * @brief Fork the child process, set up its file descriptors and process group,
     *        and (in seccomp mode) hand the target's notification listener to the parent.
     *
     * The child never returns; on success it execve()s the target binary.
     *
     * Stdin comes from cfg.target.stdin_path when set (opened by
     * prepare_target(), handed over via TargetPrepared::stdin_fd); otherwise
     * it is /dev/null. MapSizePass always keeps /dev/null on stdin. The
     * child's stdout/stderr are
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
     * @return SpawnedTarget containing the child PID, the map-size pipe fd for
     *         MapSizePass (caller must close it after use), and the seccomp
     *         notification listener fd in seccomp mode. On failure, pid == -1.
     */
    SpawnedTarget fork_target(const Config& cfg, const TargetPrepared& prep, SpawnMode mode,
                              bool forward_output);

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
     * Drains the pipe after the Pass 1 target has exited, then accepts only a
     * single decimal integer after trimming leading/trailing whitespace. A
     * prefix, trailing text, empty output, an unreadable pipe, or an oversized
     * dump is an error.
     *
     * @param pipe_read_fd read end of the pipe (will be closed by this function)
     * @return The parsed map size on success, std::nullopt on failure.
     */
    [[nodiscard]] std::optional<uint64_t> collect_map_size(int pipe_read_fd);

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