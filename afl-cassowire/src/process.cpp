// src/process.cpp

#include "process.hpp"
#include "log.hpp"
#include "utils.hpp"

#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <regex>
#include <algorithm>
#include <cctype>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <signal.h>
#include <cstring>
#include <cstdlib>
#include <cerrno>

extern char** environ;

namespace process {

// Seccomp BPF filter that traces bind() (arch-agnostic, as in the original code)
// Note: The spec requires arch-awareness, but we keep the original implementation
// for now; a TODO is carried in the function that builds it.
static struct sock_filter bind_filter[] = {
    // Load syscall number
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    // Jump if equal to __NR_bind (49 on x86_64)
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bind, 0, 1),
    // Return TRACE
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
    // Return ALLOW
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
};

static const struct sock_fprog seccomp_prog = {
    .len = sizeof(bind_filter) / sizeof(bind_filter[0]),
    .filter = bind_filter,
};

void cleanup_stale_processes(const CleanupConfig& cleanup_cfg) {
    // TODO(claude): DANGEROUS. (1) This is a global /proc scan with no protection against matching the proxy
    //   itself, its parent (afl-fuzz / shell) or the new target just about to be spawned. A broad pattern
    //   (e.g. type=regexp value=".*" target=argv) makes the proxy SIGKILL the kernel-ish set of every
    //   user process - including the session running it. (2) It never re-checks that a matched pid is still
    //   the same process after the grace period (pid reuse), and it always sleeps the full force_kill_ms even
    //   when nothing is alive.
    if (!cleanup_cfg.kill_pattern) return;

    const KillPattern& kp = cleanup_cfg.kill_pattern.value();
    std::regex re;
    if (kp.type == "regexp") {
        try {
            re = std::regex(kp.value);
        } catch (const std::regex_error&) {
            return; // Should have been caught in config validation
        }
    }

    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return;

    struct dirent* entry;
    std::vector<pid_t> matched_pids;

    while ((entry = readdir(proc_dir)) != nullptr) {
        if (entry->d_type != DT_DIR) continue;
        
        // Check if directory name is all digits (PID)
        bool is_pid = true;
        for (char* p = entry->d_name; *p; p++) {
            if (!std::isdigit(static_cast<unsigned char>(*p))) { 
                is_pid = false; 
                break; 
            }
        }
        if (!is_pid) continue;

        // TODO(claude): the comment below mentions kernel threads but only pid<=1 is skipped (kernel threads
        //   have /proc/<pid>/comm).
        // std::stoi was replaced by the exception-free utils::parse_u32_strict: an all-digit directory whose
        //   value exceeds the type range used to throw std::out_of_range uncaught (-> std::terminate).
        auto parsed_pid = utils::parse_u32_strict(entry->d_name);
        if (!std::holds_alternative<std::uint32_t>(parsed_pid)) continue;
        pid_t pid = static_cast<pid_t>(std::get<std::uint32_t>(parsed_pid));
        if (pid <= 1) continue; // Skip init and kernel threads

        std::string proc_path = std::string("/proc/") + entry->d_name;
        bool match = false;

        if (kp.type == "comm" || (kp.type == "regexp" && kp.target == "comm")) {
            // TODO(claude): reads /proc/<pid>/comm which is the *thread* name of the main thread only. A
            //   target whose workers renamed themselves (nginx: comm="nginx", setproctitle aside) matches by
            //   comm but the actual listener may be a child - document that this is main-thread comm only.
            std::ifstream comm_file(proc_path + "/comm");
            std::string comm;
            if (std::getline(comm_file, comm)) {
                if (kp.type == "comm") {
                    match = (comm == kp.value);
                } else {
                    match = std::regex_match(comm, re);
                }
            }
        } else if (kp.type == "regexp" && (kp.target == "argv0" || kp.target == "argv")) {
            // TODO(claude): kernel threads have an EMPTY cmdline, so any regex that matches the empty string
            //   (e.g. `.*`, `^$`) matches every kernel thread and they cannot be killed - the proxy then
            //   "waits" for them pointlessly. Skip pids with an empty cmdline.
            std::ifstream cmdline_file(proc_path + "/cmdline", std::ios::binary);
            std::string cmdline((std::istreambuf_iterator<char>(cmdline_file)), std::istreambuf_iterator<char>());
            
            if (kp.target == "argv") {
                std::replace(cmdline.begin(), cmdline.end(), '\0', ' ');
                if (!cmdline.empty() && cmdline.back() == ' ') cmdline.pop_back();
                match = std::regex_match(cmdline, re);
            } else if (kp.target == "argv0") {
                size_t null_pos = cmdline.find('\0');
                std::string argv0 = (null_pos == std::string::npos) ? cmdline : cmdline.substr(0, null_pos);
                match = std::regex_match(argv0, re);
            }
        }

        if (match) {
            matched_pids.push_back(pid);
        }
    }
    closedir(proc_dir);

    for (pid_t pid : matched_pids) {
        // TODO(claude): no EPERM handling (kill returns -1 for other users' processes and is ignored). Also
        //   the spec (5.1) describes cleanup only in terms of the kill_pattern, but the proxy's own child
        //   process group and its own pid are never explicitly excluded from `matched_pids`.
        kill(pid, SIGTERM);
    }

    if (!matched_pids.empty()) {
        utils::sleep_ms(cleanup_cfg.force_kill_ms);
        for (pid_t pid : matched_pids) {
            if (kill(pid, 0) == 0) { // Still alive
                kill(pid, SIGKILL);
            }
        }
    }
}

std::optional<TargetPrepared> prepare_target(const Config& cfg, SpawnMode mode) {
    // Prepare argv (the pointers refer to cfg.target.args, which outlives fork)
    std::vector<char*> c_args;
    for (const auto& arg : cfg.target.args) {
        c_args.push_back(const_cast<char*>(arg.c_str()));
    }
    c_args.push_back(nullptr);

    // Build environment strings
    std::vector<std::string> c_env_strings;

    switch (cfg.target.env_preserve) {
    case TargetConfig::EnvPreserveLevel::all:
        // Inherit the entire parent environment
        for (char** envp = ::environ; *envp != nullptr; ++envp) {
            c_env_strings.push_back(*envp);
        }
        break;
    case TargetConfig::EnvPreserveLevel::afl_only:
        // Inherit only the variables the target's AFL++ runtime needs
        {
            const char* path = getenv("PATH");
            c_env_strings.push_back("PATH=" + std::string(path ? path : ""));
            const char* afl_shm_id = getenv("__AFL_SHM_ID");
            if (afl_shm_id != nullptr) {
                c_env_strings.push_back("__AFL_SHM_ID=" + std::string(afl_shm_id ? afl_shm_id : ""));
            }
            // Propagated when present (main.cpp requires it whenever afl.enable_cmplog is set)
            const char* afl_cmplog_shm_id = getenv("__AFL_CMPLOG_SHM_ID");
            if (afl_cmplog_shm_id) {
                c_env_strings.push_back("__AFL_CMPLOG_SHM_ID=" + std::string(afl_cmplog_shm_id));
            }
        }
        break;
    case TargetConfig::EnvPreserveLevel::nothing:
        // Inherit no environment variables
        break;
    }

    auto set_env_var = [&](const std::string& key, const std::string& value) {
        auto it = std::remove_if(c_env_strings.begin(), c_env_strings.end(),
            [&](const std::string& s) {
                return s.find(key + "=") == 0;
            });
        c_env_strings.erase(it, c_env_strings.end());
        c_env_strings.push_back(key + "=" + value);
    };

    for (const auto& [key, value] : cfg.target.env) {
        set_env_var(key, value);
    }

    if (mode == SpawnMode::MapSizePass) {
        set_env_var("AFL_DUMP_MAP_SIZE", "1");
    }

    // Convert to char** for execve
    std::vector<char*> c_env;
    c_env.reserve(c_env_strings.size());
    for (const auto& s : c_env_strings) {
        c_env.push_back(const_cast<char*>(s.c_str()));
    }
    c_env.push_back(nullptr);

    // Log the execution plan (binary, args, env) - parent-side, before fork(),
    // so it is safe to use spdlog here (unlike the child side of fork_target()).
    // Index-based loops: with -Dstrip_low_logs=true the PROXY_LOG_DEBUG bodies
    // compile out and a loop-variable binding would be flagged as unused.
    PROXY_LOG_DEBUG("execve binary={}", cfg.target.binary.c_str());
    PROXY_LOG_DEBUG("args:");
    for (size_t i = 0; i < cfg.target.args.size(); ++i) {
        PROXY_LOG_DEBUG("  - {}", cfg.target.args[i]);
    }
    PROXY_LOG_DEBUG("env:");
    for (size_t i = 0; i < c_env_strings.size(); ++i) {
        const size_t separator = c_env_strings[i].find('=');
        if (separator == std::string::npos) {
            PROXY_LOG_DEBUG("  {}", c_env_strings[i]);
        } else {
            PROXY_LOG_DEBUG("  {}:{}",
                c_env_strings[i].substr(0, separator), c_env_strings[i].substr(separator + 1));
        }
    }

    // Prepare pipe for map size pass if needed
    int pipefd[2] = {-1, -1};
    if (mode == SpawnMode::MapSizePass) {
        if (pipe(pipefd) < 0) {
            PROXY_LOG_ERROR("failed to create pipe for map size extraction");
            return std::nullopt;
        }
    }

    return TargetPrepared{
        .argv = std::move(c_args),
        .env_strings = std::move(c_env_strings),
        .envp = std::move(c_env),
    };
}

// Helper to redirect file descriptors in the child according to the mode
static void redirect_child_fds(SpawnMode mode, bool forward_output, int pipe_write_fd) {
    if (mode == SpawnMode::MapSizePass) {
        // Map size pass: child stdout -> pipe, stderr and stdin -> /dev/null
        dup2(pipe_write_fd, STDOUT_FILENO);
        close(pipe_write_fd);

        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            dup2(devnull, STDIN_FILENO);
            close(devnull);
        }
    } else {
        // ProxyMode and PlainTest: stdin -> /dev/null; stdout/stderr either
        // forwarded to the proxy's descriptors (--child-output) or discarded.
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            close(devnull);
        }
        if (!forward_output) {
            devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
                close(devnull);
            }
        }
    }
}

SpawnedTarget fork_target(const Config& cfg, const TargetPrepared& prep, SpawnMode mode,
                          bool forward_output, volatile sig_atomic_t* publish_pid) {
    // Block SIGINT and SIGTERM in the parent to avoid the race where the handler
    // runs before g_child_pid is set. The child will unblock these signals as its
    // first action (after fork) so that the target receives them normally.
    sigset_t block_mask, old_mask;
    sigemptyset(&block_mask);
    sigaddset(&block_mask, SIGINT);
    sigaddset(&block_mask, SIGTERM);
    sigprocmask(SIG_BLOCK, &block_mask, &old_mask);

    // Capture parent PID for the child's PDEATHSIG safety check
    const pid_t parent_pid = getpid();

    int pipefd[2] = {-1, -1};
    if (mode == SpawnMode::MapSizePass) {
        if (pipe(pipefd) < 0) {
            PROXY_LOG_ERROR("failed to create pipe for map size extraction");
            sigprocmask(SIG_SETMASK, &old_mask, nullptr);
            return SpawnedTarget{-1, -1};
        }
    }

    pid_t pid = fork();
    if (pid < 0) {
        if (mode == SpawnMode::MapSizePass) {
            close(pipefd[0]);
            close(pipefd[1]);
        }
        PROXY_LOG_ERROR("fork() failed: {}", strerror(errno));
        sigprocmask(SIG_SETMASK, &old_mask, nullptr);
        return SpawnedTarget{-1, -1};
    }

    if (pid == 0) {
        // Child: restore signal mask (unblock SIGINT/SIGTERM) as the very first action
        sigprocmask(SIG_SETMASK, &old_mask, nullptr);

        // Ask the Linux kernel to send SIGKILL to this child if the parent dies
        prctl(PR_SET_PDEATHSIG, SIGKILL); 

        // Safety check: if the parent died between the capture above and now,
        // we would be orphaned. Compare current parent with the captured one.
        if (getppid() != parent_pid) {
            _exit(0); // Parent already died and we got adopted by init, exit now
        }

        // Keep the original stderr around: after the redirection below it may
        // point at /dev/null or the proxy's terminal, so execve() failures are
        // reported through this saved descriptor. Nothing else is logged by
        // the child between the redirection and execve().
        // WARNING: never use spdlog (or any malloc/stdio-based logging) here:
        // this code runs between fork() and execve() and must remain
        // async-signal-safe. Raw write()/dprintf() to a descriptor only.
        int original_stderr = dup(STDERR_FILENO);
        if (original_stderr == -1) {
            perror("child: dup stderr failed");
            _exit(EXIT_FAILURE);
        }
        fcntl(original_stderr, F_SETFD, FD_CLOEXEC);

        // Redirect file descriptors according to the mode
        redirect_child_fds(mode, forward_output,
                           (mode == SpawnMode::MapSizePass) ? pipefd[1] : -1);

        // Put child in a new process group, making it the leader
        if (setpgid(0,0) == -1) {
            dprintf(original_stderr, "proxy: setpgid failed: %s\n", strerror(errno));
            _exit(127);
        }

        // Ptrace/Seccomp setup (child side)
        const bool use_ptrace = (cfg.port_detection.primary == "ptrace");
        const bool use_seccomp = (cfg.port_detection.primary == "seccomp");
        if (use_ptrace || use_seccomp) {
            ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);

            if (use_seccomp) {
                prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &seccomp_prog);
            }

            raise(SIGSTOP);
        }

        execve(cfg.target.binary.c_str(), prep.argv.data(), prep.envp.data());

        // execve() only returns on failure. Report through the saved original stderr.
        dprintf(original_stderr, "proxy: execve failed (%d) for %s: %s\n",
                errno, cfg.target.binary.c_str(), strerror(errno));
        close(original_stderr);
        _exit(127);
    }

    // Parent: we have successfully forked
    if (publish_pid) {
        *publish_pid = pid;
    }
    sigprocmask(SIG_SETMASK, &old_mask, nullptr);

    // Close the write end of the pipe in the parent (we only read from it)
    if (mode == SpawnMode::MapSizePass) {
        close(pipefd[1]);
    }

    return SpawnedTarget{
        .pid = pid,
        .map_size_fd = (mode == SpawnMode::MapSizePass) ? pipefd[0] : -1
    };
}

void handshake_tracer(pid_t pid, const Config& cfg) {
    const bool use_ptrace = (cfg.port_detection.primary == "ptrace");
    const bool use_seccomp = (cfg.port_detection.primary == "seccomp");
    if (!use_ptrace && !use_seccomp) {
        return;
    }

    int status;
    // Wait for SIGSTOP from child
    if (waitpid(pid, &status, 0) == -1) {
        // TODO(claude): handle error? In the original code, this was ignored.
        return;
    }
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
        long opts = 0;
        if (use_ptrace) {
            opts = PTRACE_O_TRACESYSGOOD;
        } else if (use_seccomp) {
            opts = PTRACE_O_TRACESECCOMP | PTRACE_O_TRACESYSGOOD;
        }
        ptrace(PTRACE_SETOPTIONS, pid, 0, opts);
        ptrace(PTRACE_CONT, pid, 0, 0);
    }
    // If we didn't get a SIGSTOP, something went wrong; we just continue and let
    // the child run (or die) without tracing. This matches the original behavior
    // where the parent would proceed anyway.
}

void collect_map_size(int pipe_read_fd) {
    char buffer[1024] = {0};
    ssize_t bytes_read = read(pipe_read_fd, buffer, sizeof(buffer) - 1);
    close(pipe_read_fd);
    PROXY_LOG_DEBUG("bytes read: {}", bytes_read);

    if (bytes_read > 0) {
        std::string output(buffer, bytes_read);
        std::istringstream iss(output);
        std::string line;
        if (std::getline(iss, line)) {
            size_t start = line.find_first_not_of(" \t\r\n");
            size_t end = line.find_last_not_of(" \t\r\n");
            if (start != std::string::npos) {
                std::string trimmed = line.substr(start, end - start + 1);
                bool is_digit = !trimmed.empty() && std::all_of(trimmed.begin(), trimmed.end(),
                    [](unsigned char c){ return std::isdigit(c); });

                if (is_digit) {
                    PROXY_LOG_INFO("map size: {}", trimmed);
                } else {
                    // TODO(claude): spec 6.2 requires this to be a hard error ("assuming the target lacks
                    //   proper AFL++ instrumentation" -> return an error). Here only a message is logged
                    //   and spawn_target() still returns a pid, so main.cpp continues as if all was well.
                    //   Also the spec says the integer must be on the first line with no extra text; the
                    //   code silently takes the first line and ignores everything after it (e.g. a target
                    //   that prints "MAP_SIZE: 65536" fails, but one that prints "65536\ngarbage" passes).
                    PROXY_LOG_ERROR("failed to parse map size from target output. Output: '{}'", trimmed);
                }
            }
        }
    } else {
        PROXY_LOG_ERROR("target produced no output for map size.");
    }
}

// PF_EXITING / PF_SIGNALED: task->flags bits visible as field 9 of
// /proc/<pid>/stat. PF_EXITING is set in exit_signals() for any exiting task;
// PF_SIGNALED is set in complete_signal/do_coredump path for a task killed by
// a signal. Both are set before do_exit() tears down the file descriptors, so
// they let us know the target is dying before it is waitable.
static constexpr unsigned long PF_EXITING_LOCAL  = 0x00000004UL;
static constexpr unsigned long PF_SIGNALISED_LOCAL = 0x00000400UL;

// Parse the `flags` field (whitespace field 9) out of a /proc stat buffer.
// Returns false if the buffer cannot be parsed. comm (field 2) may contain
// spaces and parentheses, so the field numbering restarts after the LAST ')'.
static bool parse_proc_flags(const char* buf, size_t len, unsigned long* out) {
    // Find the LAST ')' without relying on memrchr/_GNU_SOURCE: comm may
    // itself contain ')' characters, so field numbering restarts after it.
    size_t rparen = 0;
    bool found = false;
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == ')') { rparen = i; found = true; }
    }
    if (!found) return false;
    const char* p = buf + rparen + 1;
    // Fields after ')': 0=state 1=ppid 2=pgrp 3=session 4=tty_nr 5=tpgid 6=flags
    int idx = -1;
    while (true) {
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '\n') break;
        idx++;
        if (idx == 6) {
            unsigned long v = 0;
            while (*p >= '0' && *p <= '9') { v = v * 10UL + static_cast<unsigned long>(*p - '0'); p++; }
            *out = v;
            return true;
        }
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\0') p++;
    }
    return false;
}

// Read the flags field of a single /proc stat file (pid, or tid under task/).
static bool proc_flags_of(const char* path, unsigned long* out) {
    int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char buf[512];
    ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
    ::close(fd);
    if (n <= 0) return false;
    buf[n] = '\0';
    return parse_proc_flags(buf, static_cast<size_t>(n), out);
}

// True if the process (or any of its threads) carries dying flags. The leader
// check is the cheap fast path for single-threaded targets; the task/ scan
// covers a fatal signal delivered on a non-leader thread of a threaded target.
static bool pid_is_dying(pid_t pid) {
    char path[64];
    unsigned long flags = 0;

    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    if (proc_flags_of(path, &flags) &&
        (flags & (PF_EXITING_LOCAL | PF_SIGNALISED_LOCAL))) {
        return true;
    }

    snprintf(path, sizeof(path), "/proc/%d/task", pid);
    DIR* d = opendir(path);
    if (!d) return false;  // gone (already a zombie/reaped): caller's waitpid handles it
    struct dirent* e;
    bool dying = false;
    while ((e = readdir(d)) != nullptr) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        char tpath[96];
        snprintf(tpath, sizeof(tpath), "/proc/%d/task/%s/stat", pid, e->d_name);
        if (proc_flags_of(tpath, &flags) &&
            (flags & (PF_EXITING_LOCAL | PF_SIGNALISED_LOCAL))) {
            dying = true;
            break;
        }
    }
    closedir(d);
    return dying;
}

static TargetState classify(int status) {
    if (WIFSIGNALED(status)) return {TargetState::Kind::Crashed, status};
    if (WIFEXITED(status))   return {TargetState::Kind::Exited, status};
    return {TargetState::Kind::Alive, status};
}

int open_pidfd(pid_t pid) {
#ifdef __NR_pidfd_open
    return static_cast<int>(syscall(__NR_pidfd_open, pid, 0));
#else
    (void)pid;
    errno = ENOSYS;
    return -1;
#endif
}

TargetState check_target_state(pid_t pid, int pidfd, int grace_ms) {
    // 1. Fast reap: the target is already a zombie we can collect.
    int status = 0;
    pid_t r = waitpid(pid, &status, WNOHANG);
    if (r == pid) return classify(status);
    if (r == -1 && errno == ECHILD) return {TargetState::Kind::Unknown, 0};

    // 2. Not waitable yet: peek at the kernel's exit flags to detect a target
    //    that is mid-exit (fds already closed for a crashed peer, or wedged in
    //    a coredump) but not a zombie, which is the race WNOHANG misses.
    if (!pid_is_dying(pid)) return {TargetState::Kind::Alive, 0};

    // 3. Dying: wait for it to become a zombie, bounded so a hung core_pattern
    //    pipe cannot wedge the fuzzing loop. poll() returns the instant death
    //    materialises, so this is not a delay in the normal case.
    if (pidfd >= 0) {
        struct pollfd pfd;
        pfd.fd = pidfd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int pr;
        do {
            pr = poll(&pfd, 1, grace_ms);
        } while (pr == -1 && errno == EINTR);
    } else {
        utils::sleep_ms(grace_ms);  // fallback if no pidfd was available
    }

    // 4. Reap if the death landed; otherwise the target is wedged (still alive
    //    after grace) and will be re-checked on the next call.
    r = waitpid(pid, &status, WNOHANG);
    if (r == pid) return classify(status);
    return {TargetState::Kind::Alive, 0};
}

std::string TargetState::to_string() const {
    switch (kind) {
    case Kind::Alive:   return "alive";
    case Kind::Crashed: return "crashed (signal " + std::to_string(WTERMSIG(status)) + ")";
    case Kind::Exited:  return "exited (code " + std::to_string(WEXITSTATUS(status)) + ")";
    case Kind::Unknown: return "unknown (not our child / already reaped)";
    }
    return "unknown";
}

} // namespace process
