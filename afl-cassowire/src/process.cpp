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

pid_t spawn_target(const Config& cfg, const bool is_map_size_pass, const bool is_proxy_mode) {
    // ---------------------------------------------------------------------------
    // Prepare everything that can be prepared ONCE, before fork(): the tracer
    // flags, argv, the environment and the seccomp filter program. The child
    // section below then only has to redirect its file descriptors, arm
    // ptrace/seccomp and call execve() — no logging, no allocations and no
    // std::string/std::vector work between the redirection and execve().
    // ---------------------------------------------------------------------------

    const bool use_ptrace = (cfg.port_detection.primary == "ptrace");
    const bool use_seccomp = (cfg.port_detection.primary == "seccomp");

    // Prepare argv (the pointers refer to cfg.target.args, which outlives fork)
    std::vector<char*> c_args;
    for (const auto& arg : cfg.target.args) {
        c_args.push_back(const_cast<char*>(arg.c_str()));
    }
    c_args.push_back(nullptr);

    // Build environment array for execve
    std::vector<std::string> c_env_strings;

    if (cfg.target.env_preserve) {
        for (char** envp = ::environ; *envp != nullptr; ++envp) {
            c_env_strings.push_back(*envp);
        }
    } else {
        // TODO(claude): __AFL_CMPLOG_SHM_ID and AFL_DUMP_MAP_SIZE handling: the AFL++ CMPLOG shm id is NOT
        //   propagated to the target here, so `afl.enable_cmplog` (checked in main.cpp) has no effect - the
        //   instrumented target gets no cmplog map. Must be added when cfg.afl.enable_cmplog is set.
        //   Also AFL++ runs set many other vars (AFL_MAP_SIZE, LD_PRELOAD/__AFL_PRELOAD, AFL_* debug vars,
        //   ASAN_OPTIONS, ...); a whitelist of PATH + __AFL_SHM_ID is easy to get wrong.
        // TODO(claude): PROXY_AFL_FORCE_FINAL_LOC is documented in main.cpp as "consumed by the target's AFL++
        //   runtime to force __afl_final_loc", but it is never copied into the child environment here.
        const char* path = getenv("PATH");
        c_env_strings.push_back("PATH=" + std::string(path ? path : ""));
        const char* afl_shm_id = getenv("__AFL_SHM_ID");
        c_env_strings.push_back("__AFL_SHM_ID=" + std::string(afl_shm_id ? afl_shm_id : ""));
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

    if (is_map_size_pass) {
        set_env_var("AFL_DUMP_MAP_SIZE", "1");
    }

    // Convert to char** for execve (fork() duplicates the address space, so
    // these pointers stay valid in the child)
    std::vector<char*> c_env;
    c_env.reserve(c_env_strings.size());
    for (const auto& s : c_env_strings) {
        c_env.push_back(const_cast<char*>(s.c_str()));
    }
    c_env.push_back(nullptr);

    // Seccomp program that traces bind() so the parent can rewrite the port
    // TODO(claude): the spec requires the BPF filter to be ARCH-AWARE (it runs on a possibly different arch
    //   than the tracer via SECCOMP_RET_TRACE). This filter only checks the syscall number (__NR_bind from
    //   the *current* headers) and never loads/checks arch in seccomp_data -> a 32-bit/compat process can
    //   hit a different syscall with nr 49. Also it must load the args (or at least not assume the tracer
    //   reads them from registers) if the filter needs to distinguish, and it ignores the wide-argument
    //   (x32) bit in seccomp_data->arch.
    struct sock_filter seccomp_filter[] = {
        // Load syscall number
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        // Jump if equal to __NR_bind (49 on x86_64)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bind, 0, 1),
        // Return TRACE
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
        // Return ALLOW
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };

    struct sock_fprog seccomp_prog = {
        .len = (unsigned short)(sizeof(seccomp_filter) / sizeof(seccomp_filter[0])),
        .filter = seccomp_filter,
    };

    // Log the exact command the child is about to execute. This runs in the
    // parent, before fork(), so the child never logs between its stderr
    // redirection and the execve() call.
    // TODO(claude): DEBUG output on every spawn, always to the proxy's stderr (also in proxy mode under
    //   afl-fuzz) - dumps the full environment, which may contain secrets. Also the spec says Pass 1 must keep
    //   stderr clean; this runs in the parent so it is OK there, but gate it behind a verbose option.
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

    int pipefd[2] = {-1, -1};
    if (is_map_size_pass) {
        if (pipe(pipefd) < 0) {
            std::cerr << "proxy: failed to create pipe for map size extraction\n";
            return -1;
        }
    }

    pid_t pid = fork();
    if (pid < 0) {
        if (is_map_size_pass) {
            close(pipefd[0]);
            close(pipefd[1]);
        }
        std::cerr << "proxy: fork() failed\n";
        return -1;
    }

    if (pid == 0) {
        // TODO(claude): fork() + iostream comes with the usual caveats: the child must not allocate or lock
        //   anything before execve(). The code below honours that (dprintf/write only, no std::string in the
        //   child path) - keep it that way if this block is edited.
        // --- Child Process ---

        // Ask the Linux kernel to send SIGKILL to this child if the parent dies
        prctl(PR_SET_PDEATHSIG, SIGKILL); 
        
        // Safety check: Did the parent die right before we called prctl()?
        // TODO(claude): TOCTOU race: if the parent died between prctl() and this check, getppid() may
        //   already be 1 and we exit; but if the parent died before prctl(), PR_SET_PDEATHSIG is also
        //   cleared on setuid-like transitions in some cases. The check itself should compare against a
        //   stored parent pid captured before fork() to be race-free.
        if (getppid() == 1) { 
            _exit(0); // Parent already died and we got adopted by init, exit now
        }

        // Keep the original stderr around: after the redirection below it may
        // point at /dev/null or a log file, so execve() failures are reported
        // through this saved descriptor. Nothing else is logged by the child
        // between the redirection and execve().
        int original_stderr = dup(STDERR_FILENO);
        if (original_stderr == -1) {
            // If this fails, we can still use the raw STDERR_FILENO to complain
            perror("child: dup stderr failed");
            _exit(EXIT_FAILURE);
        }
        fcntl(original_stderr, F_SETFD, FD_CLOEXEC);

        if (is_map_size_pass) {
            close(pipefd[0]);
            dup2(pipefd[1], STDOUT_FILENO);
            close(pipefd[1]);
            
            int devnull = open("/dev/null", O_RDWR);
            if (devnull >= 0) {
                dup2(devnull, STDERR_FILENO);
                dup2(devnull, STDIN_FILENO);
                close(devnull);
            }
        } else if (is_proxy_mode) {
            // TODO(claude): the log fds are re-opened with O_TRUNC here even though main.cpp already created
            //   them; two sources of truth, and the child truncates again. More importantly the spec says
            //   the log files "must be created before process management" and "if the log file cannot be
            //   created, fail" - if this per-child open() fails (fd < 0) we silently keep the proxy's own
            //   stdout/stderr instead of failing.
            int devnull = open("/dev/null", O_RDONLY);
            if (devnull >= 0) {
                dup2(devnull, STDIN_FILENO);
                close(devnull);
            }
            if (!cfg.target.log.stdout_path.empty()) {
                int fd = open(cfg.target.log.stdout_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (fd >= 0) {
                    dup2(fd, STDOUT_FILENO);
                    close(fd);
                }
            }
            if (!cfg.target.log.stderr_path.empty()) {
                int fd = open(cfg.target.log.stderr_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (fd >= 0) {
                    dup2(fd, STDERR_FILENO);
                    close(fd);
                }
            }
        } else {
            // Pass 2: stdin -> /dev/null, stdout/stderr inherit
            int devnull = open("/dev/null", O_RDONLY);
            if (devnull >= 0) {
                dup2(devnull, STDIN_FILENO);
                close(devnull);
            }
        }
        // Put child in a new process group, making it the leader
        // TODO(claude): setpgid() is called here (after fd redirection, before PTRACE_TRACEME/execve) but the
        //   parent does NOT call setpgid(pid,pid); if the parent's timed_kill_pgid(-child) / kill_pgid() runs
        //   before the child reached this point, the signal goes to the wrong group (or fails). Also
        //   credentials/session handling (setsid) is not done, so Ctrl+C at the terminal may reach the child
        //   independently of the proxy.
        if (setpgid(0,0) == -1) {
            dprintf(original_stderr, "proxy: setpgid failed: %s\n", strerror(errno));
            _exit(127);
        }


        // Ptrace/Seccomp setup
        if (use_ptrace || use_seccomp) {
            // TODO(claude): the return value of ptrace(PTRACE_TRACEME) is ignored; if it fails the tracee
            //   continues untraced but the parent below still blocks in waitpid() forever. Check it and
            //   _exit on failure. Also PR_SET_SECCOMP's return value and the prctl(PR_SET_NO_NEW_PRIVS) result
            //   are ignored: if seccomp install fails the child runs with a filter that is not installed and
            //   the parent waits for a PTRACE_EVENT_SECCOMP that never comes.
            ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);

            if (use_seccomp) {
                prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &seccomp_prog);
            }

            raise(SIGSTOP);
        }

        execve(cfg.target.binary.c_str(), c_args.data(), c_env.data());

        // execve() only returns on failure. stderr may already have been
        // redirected above, so report through the saved original stderr.
        dprintf(original_stderr, "proxy: execve failed (%d) for %s: %s\n",
            errno, cfg.target.binary.c_str(), strerror(errno));
        close(original_stderr);
        _exit(127);
    }

    // --- Parent Process ---
    
    // TODO(claude): DEADLOCK in test mode Pass 1 when port_detection.primary is ptrace/seccomp: the child
    //   does raise(SIGSTOP) BEFORE execve(), but the parent reaches the blocking read() on the pipe below
    //   before the "wait for SIGSTOP / PTRACE_CONT" block further down. The child never execs, the pipe never
    //   gets data or EOF -> hang. The ptrace handshake must be done before reading the pipe. Moreover Pass 1
    //   does not need ptrace/seccomp at all (spec: only map size is captured) - skip it for is_map_size_pass.
    if (is_map_size_pass) {
        close(pipefd[1]);
        // TODO(claude): this read() is BLOCKING and happens only ONCE: if the target writes the integer in
        //   several write()s the rest is lost, and a target that writes nothing but stays alive makes the
        //   proxy block here forever (no timeout). Read until EOF with a poll() timeout. Also the Pass 1
        //   child is never reaped inside this function (main.cpp does waitpid(map_pid) afterwards - keep
        //   them in sync), and a blocking waitpid() there has no timeout either.
        char buffer[1024] = {0};
        ssize_t bytes_read = read(pipefd[0], buffer, sizeof(buffer) - 1);
        close(pipefd[0]);
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

    if (use_ptrace || use_seccomp) {
        int status;
        // Wait for SIGSTOP from child
        // TODO(claude): blocking waitpid() without a timeout - if PTRACE_TRACEME failed in the child (its
        //   return value is ignored) this blocks forever, and the proxy has no way to reap the child it just
        //   forked. Also the ptrace() calls below ignore their return values.
        waitpid(pid, &status, 0);
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) {
            // TODO(claude): the child is resumed with PTRACE_CONT even in `ptrace` mode, but syscall-stops
            //   (the ones trace_port() waits for) only happen after PTRACE_SYSCALL. This is why
            //   `primary: ptrace` never detects the bind: no stop is ever generated.
            long opts = 0;
            if (use_ptrace) {
                opts = PTRACE_O_TRACESYSGOOD;
            } else if (use_seccomp) {
                opts = PTRACE_O_TRACESECCOMP | PTRACE_O_TRACESYSGOOD;
            }
            ptrace(PTRACE_SETOPTIONS, pid, 0, opts);
            ptrace(PTRACE_CONT, pid, 0, 0);
        }
    }

    return pid;
}

} // namespace process