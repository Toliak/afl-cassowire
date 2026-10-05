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

        pid_t pid = std::stoi(entry->d_name);
        if (pid <= 1) continue; // Skip init and kernel threads

        std::string proc_path = std::string("/proc/") + entry->d_name;
        bool match = false;

        if (kp.type == "comm" || (kp.type == "regexp" && kp.target == "comm")) {
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
        // --- Child Process ---

        // Ask the Linux kernel to send SIGKILL to this child if the parent dies
        prctl(PR_SET_PDEATHSIG, SIGKILL); 
        
        // Safety check: Did the parent die right before we called prctl()?
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
        if (setpgid(0,0) == -1) {
            dprintf(original_stderr, "proxy: setpgid failed: %s\n", strerror(errno));
            _exit(127);
        }


        // Ptrace/Seccomp setup
        if (use_ptrace || use_seccomp) {
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
    
    if (is_map_size_pass) {
        close(pipefd[1]);

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
        waitpid(pid, &status, 0);
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
    }

    return pid;
}

} // namespace process