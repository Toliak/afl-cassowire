// src/process.cpp

#include "process.hpp"
#include "utils.hpp"

#include <iostream>
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

        // TODO(claude): std::stoi throws std::out_of_range (uncaught -> std::terminate) for an all-digit
        //   directory whose value exceeds INT_MAX; use std::from_chars and handle the error. The comment
        //   below mentions kernel threads but only pid<=1 is skipped (kernel threads have /proc/<pid>/comm).
        pid_t pid = std::stoi(entry->d_name);
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
            c_env_strings.push_back("__AFL_SHM_ID=" + std::string(afl_shm_id ? afl_shm_id : ""));
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

    // Log the execution plan (binary, args, env) - done in parent before fork
    dprintf(STDERR_FILENO, "Begin\n");
    dprintf(STDERR_FILENO, "execve binary=%s\n", cfg.target.binary.c_str());
    dprintf(STDERR_FILENO, "args:\n");
    for (const auto& arg : cfg.target.args) {
        dprintf(STDERR_FILENO, "  - %s\n", arg.c_str());
    }
    dprintf(STDERR_FILENO, "env:\n");
    for (const auto& env : c_env_strings) {
        const size_t separator = env.find('=');
        if (separator == std::string::npos) {
            dprintf(STDERR_FILENO, "  %s\n", env.c_str());
        } else {
            dprintf(STDERR_FILENO, "  %.*s:%s\n",
                static_cast<int>(separator), env.c_str(), env.c_str() + separator + 1);
        }
    }

    // Prepare pipe for map size pass if needed
    int pipefd[2] = {-1, -1};
    if (mode == SpawnMode::MapSizePass) {
        if (pipe(pipefd) < 0) {
            std::cerr << "proxy: failed to create pipe for map size extraction\n";
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
static void redirect_child_fds(SpawnMode mode, const TargetLog& log, int pipe_write_fd) {
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
    } else if (mode == SpawnMode::ProxyMode) {
        // Proxy mode: stdin -> /dev/null, stdout/stderr to log files
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            close(devnull);
        }
        if (!log.stdout_path.empty()) {
            int fd = open(log.stdout_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0) {
                dup2(fd, STDOUT_FILENO);
                close(fd);
            }
        }
        if (!log.stderr_path.empty()) {
            int fd = open(log.stderr_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0) {
                dup2(fd, STDERR_FILENO);
                close(fd);
            }
        }
    } else { // PlainTest
        // Test mode pass 2: stdin -> /dev/null, stdout/stderr inherit
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            close(devnull);
        }
    }
}

SpawnedTarget fork_target(const Config& cfg, const TargetPrepared& prep, SpawnMode mode,
                          volatile sig_atomic_t* publish_pid) {
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
            std::cerr << "proxy: failed to create pipe for map size extraction\n";
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
        std::cerr << "proxy: fork() failed\n";
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
        // point at /dev/null or a log file, so execve() failures are reported
        // through this saved descriptor. Nothing else is logged by the child
        // between the redirection and execve().
        int original_stderr = dup(STDERR_FILENO);
        if (original_stderr == -1) {
            perror("child: dup stderr failed");
            _exit(EXIT_FAILURE);
        }
        fcntl(original_stderr, F_SETFD, FD_CLOEXEC);

        // Redirect file descriptors according to the mode
        redirect_child_fds(mode, cfg.target.log, 
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
    std::cerr << "Bytes read: " << bytes_read << "\n";

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
                    std::cout << "Map size: " << trimmed << std::endl;
                } else {
                    // TODO(claude): spec 6.2 requires this to be a hard error ("assuming the target lacks
                    //   proper AFL++ instrumentation" -> return an error). Here only a message is printed
                    //   and spawn_target() still returns a pid, so main.cpp continues as if all was well.
                    //   Also the spec says the integer must be on the first line with no extra text; the
                    //   code silently takes the first line and ignores everything after it (e.g. a target
                    //   that prints "MAP_SIZE: 65536" fails, but one that prints "65536\ngarbage" passes).
                    std::cerr << "proxy: failed to parse map size from target output. Output: '" << trimmed << "'\n";
                }
            }
        }
    } else {
        std::cerr << "proxy: target produced no output for map size.\n";
    }
}

} // namespace process
