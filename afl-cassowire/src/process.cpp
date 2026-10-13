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
#include <unordered_set>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/socket.h>
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

// Seccomp BPF filter for user-notification port detection (kernel >= 5.0).
// bind() and listen() are reported to the proxy over a SECCOMP_RET_USER_NOTIF
// listener fd (SECCOMP_FILTER_FLAG_NEW_LISTENER); everything else is allowed.
// The filter is installed in the child between fork() and execve() and is
// inherited by every thread and forked descendant, so notifications arrive no
// matter which task of the target (or of a QEMU guest) issues bind()/listen().
// Arch-aware: a non-x86_64 audit arch means the syscall numbers below are
// meaningless for the filter, so such tasks are killed instead of silently
// bypassing detection.
static struct sock_filter bind_listen_notif_filter[] = {
    /* 0 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
    /* 1 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    /* 2 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    /* 3 */ BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    /* 4 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bind, 0, 1),
    /* 5 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
    /* 6 */ BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_listen, 0, 1),
    /* 7 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
    /* 8 */ BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};

static const struct sock_fprog seccomp_notif_prog = {
    .len = sizeof(bind_listen_notif_filter) / sizeof(bind_listen_notif_filter[0]),
    .filter = bind_listen_notif_filter,
};

// Send a descriptor over a connected UNIX socket (SCM_RIGHTS). Async-signal-safe
// in the sense required between fork() and execve(): fixed stack buffers only,
// no allocation, no stdio. Returns 0 on success, -1 with errno set.
static int send_fd(int sock, int fd) {
    char byte = '\0';
    struct iovec iov = {};
    iov.iov_base = &byte;
    iov.iov_len = sizeof(byte);

    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } control = {};

    struct msghdr msg = {};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.buf;
    msg.msg_controllen = sizeof(control.buf);

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));

    return sendmsg(sock, &msg, 0) < 0 ? -1 : 0;
}

// Receive a descriptor over a connected UNIX socket, or -1 with errno set
// (the child closing the peer before sending yields ECONNRESET).
static int recv_fd(int sock) {
    char byte = '\0';
    struct iovec iov = {};
    iov.iov_base = &byte;
    iov.iov_len = sizeof(byte);

    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } control = {};

    struct msghdr msg = {};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.buf;
    msg.msg_controllen = sizeof(control.buf);

    ssize_t n;
    do {
        n = recvmsg(sock, &msg, 0);
    } while (n < 0 && errno == EINTR);

    if (n <= 0) {
        if (n == 0) errno = ECONNRESET;
        return -1;
    }

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == nullptr || cmsg->cmsg_level != SOL_SOCKET ||
        cmsg->cmsg_type != SCM_RIGHTS || cmsg->cmsg_len != CMSG_LEN(sizeof(int))) {
        errno = EINVAL;
        return -1;
    }

    int fd = -1;
    memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
    return fd;
}

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

// Parse the ppid field (whitespace field 4) out of a /proc stat buffer:
// "pid (comm) state ppid ...". comm (field 2) may contain spaces and
// parentheses, so the field numbering restarts after the LAST ')' (same
// trick as parse_proc_flags below).
static bool parse_proc_ppid(const char* buf, size_t len, pid_t* out) {
    size_t rparen = 0;
    bool found = false;
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == ')') { rparen = i; found = true; }
    }
    if (!found) return false;
    const char* p = buf + rparen + 1;
    // Fields after ')': 0=state 1=ppid ...
    int idx = -1;
    while (true) {
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '\n') break;
        idx++;
        if (idx == 1) {
            long v = 0;
            bool neg = false;
            if (*p == '-') { neg = true; p++; }
            while (*p >= '0' && *p <= '9') { v = v * 10 + static_cast<long>(*p - '0'); p++; }
            *out = static_cast<pid_t>(neg ? -v : v);
            return true;
        }
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\0') p++;
    }
    return false;
}

// Children of one pid via /proc/<pid>/task/<tid>/children (one file per
// thread, because clone() makes a child a child of the *thread* that created
// it). Returns false when the files cannot be read at all (kernel built
// without CONFIG_PROC_CHILDREN, or an EPERM-protected task dir); the caller
// then falls back to children_via_ppid_scan().
static bool children_via_procfs(pid_t pid, std::vector<pid_t>& out) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task", pid);
    DIR* d = opendir(path);
    if (!d) return false;
    struct dirent* e;
    bool ok = true;
    while ((e = readdir(d)) != nullptr) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        char cpath[96];
        snprintf(cpath, sizeof(cpath), "/proc/%d/task/%s/children", pid, e->d_name);
        std::ifstream f(cpath);
        if (!f.is_open()) { ok = false; continue; }
        std::string line;
        if (std::getline(f, line)) {
            std::istringstream iss(line);
            pid_t child = 0;
            while (iss >> child) out.push_back(child);
        }
    }
    closedir(d);
    return ok;
}

// Fallback for kernels without CONFIG_PROC_CHILDREN (or an unreadable task
// dir): one /proc scan collecting pids whose stat ppid equals @p pid. This
// misses children created by a non-leader thread (their stat ppid is the
// thread's tgid, which equals the group leader's pid only for leader-created
// children) - hence it is a fallback only.
static void children_via_ppid_scan(pid_t pid, std::vector<pid_t>& out) {
    DIR* proc = opendir("/proc");
    if (!proc) return;
    struct dirent* e;
    while ((e = readdir(proc)) != nullptr) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        // std::stoi replaced by the exception-free utils::parse_u32_strict
        // (see cleanup_stale_processes above for the rationale).
        auto parsed_pid = utils::parse_u32_strict(e->d_name);
        if (!std::holds_alternative<std::uint32_t>(parsed_pid)) continue;
        pid_t cand = static_cast<pid_t>(std::get<std::uint32_t>(parsed_pid));
        if (cand == pid) continue;
        char spath[64];
        snprintf(spath, sizeof(spath), "/proc/%d/stat", cand);
        int fd = ::open(spath, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        char buf[512];
        ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
        ::close(fd);
        if (n <= 0) continue;
        buf[n] = '\0';
        pid_t ppid = -1;
        if (parse_proc_ppid(buf, static_cast<size_t>(n), &ppid) && ppid == pid) {
            out.push_back(cand);
        }
    }
    closedir(proc);
}

std::vector<pid_t> collect_pid_tree(pid_t root) {
    std::vector<pid_t> tree;
    tree.push_back(root);
    std::unordered_set<pid_t> seen{root};
    // BFS with an index loop: the vector grows while we iterate it.
    for (size_t i = 0; i < tree.size(); i++) {
        std::vector<pid_t> kids;
        if (!children_via_procfs(tree[i], kids)) {
            kids.clear();
            children_via_ppid_scan(tree[i], kids);
        }
        for (pid_t k : kids) {
            if (k > 0 && seen.insert(k).second) tree.push_back(k);
        }
    }
    return tree;
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
        // Inherit only the variables the target's AFL++ runtime needs.
        // PATH is always added; the rest are propagated when present.
        {
            const std::vector<std::string> conditional_vars = {
                "PATH", "__AFL_SHM_ID", "__AFL_CMPLOG_SHM_ID", "___AFL_EINS_ZWEI_POLIZEI___",
                "AFL_DEBUG", "AFL_DEBUG_CHILD", "AFL_NO_UI", "AFL_QEMU_COMPCOV_DEBUG",
                "AFL_QEMU_CMPLOG_DEBUG", "AFL_QEMU_MAP_SIZE",
            };
            for (const auto& var : conditional_vars) {
                const char* value = getenv(var.c_str());
                if (value != nullptr) {
                    c_env_strings.push_back(var + "=" + std::string(value));
                }
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

    // seccomp(user-notif) mode: a socketpair carries the notification fd from
    // the child (which installs the filter) back to us via SCM_RIGHTS before
    // execve(). MapSizePass performs no port detection, so it skips the setup.
    const bool use_notif = (cfg.port_detection.primary == "seccomp") &&
                           (mode != SpawnMode::MapSizePass);
    int sv[2] = {-1, -1};
    if (use_notif) {
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0) {
            PROXY_LOG_ERROR("socketpair for seccomp listener handoff failed: {}", strerror(errno));
            sigprocmask(SIG_SETMASK, &old_mask, nullptr);
            return SpawnedTarget{-1, -1};
        }
    }

    int pipefd[2] = {-1, -1};
    if (mode == SpawnMode::MapSizePass) {
        if (pipe(pipefd) < 0) {
            if (use_notif) {
                close(sv[0]);
                close(sv[1]);
            }
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
        if (use_notif) {
            close(sv[0]);
            close(sv[1]);
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

        // Seccomp user-notification setup (child side). Runs between fork()
        // and execve(): async-signal-safe calls only (prctl/syscall/sendmsg/
        // read/close), failures reported through the saved stderr fd.
        // The filter is installed with SECCOMP_FILTER_FLAG_NEW_LISTENER, which
        // returns the notification fd; it is handed to the parent via
        // SCM_RIGHTS and the child waits for a 1-byte ack (the in-flight fd
        // and the ack guarantee the parent holds the listener before the
        // target can reach any bind()/listen()). No ptrace is used.
        if (use_notif) {
            close(sv[0]);

            if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
                dprintf(original_stderr, "proxy: PR_SET_NO_NEW_PRIVS failed: %s\n", strerror(errno));
                _exit(126);
            }

            long listener = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                                    SECCOMP_FILTER_FLAG_NEW_LISTENER, &seccomp_notif_prog);
            if (listener < 0) {
                dprintf(original_stderr, "proxy: seccomp(SET_MODE_FILTER, NEW_LISTENER) failed: %s\n",
                        strerror(errno));
                _exit(126);
            }

            if (send_fd(sv[1], (int)listener) != 0) {
                dprintf(original_stderr, "proxy: sending seccomp listener fd failed: %s\n", strerror(errno));
                _exit(126);
            }

            char ack = '\0';
            ssize_t r;
            do {
                r = read(sv[1], &ack, 1);
            } while (r < 0 && errno == EINTR);
            if (r != 1) {
                dprintf(original_stderr, "proxy: waiting for listener ack failed: %s\n", strerror(errno));
                _exit(126);
            }

            close((int)listener); // the parent owns the SCM-received copy now
            close(sv[1]);
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

    int notif_fd = -1;
    if (use_notif) {
        close(sv[1]);
        // Blocks until the child sends the listener fd; the child cannot die
        // quietly first (it is blocked on the ack read, and PDEATHSIG covers
        // our own death), so a failure here means the bootstrap itself
        // failed: the child exits and recvmsg returns ECONNRESET.
        notif_fd = recv_fd(sv[0]);
        char ack = '\0';
        ssize_t w = write(sv[0], &ack, 1); // release the child even on failure
        (void)w;
        close(sv[0]);
        if (notif_fd < 0) {
            PROXY_LOG_ERROR("seccomp listener fd handoff failed: {}", strerror(errno));
            // The ack write above may have released a child that execve()d a
            // long-running target (handshake races are not: recv_fd only fails
            // with ECONNRESET/EINVAL). Kill unconditionally, then reap.
            kill(pid, SIGKILL);
            int st = 0;
            waitpid(pid, &st, 0);
            if (mode == SpawnMode::MapSizePass) {
                close(pipefd[0]);
            }
            return SpawnedTarget{-1, -1};
        }
        // Non-blocking for the life-of-target pump (network::pump_notif_listener).
        fcntl(notif_fd, F_SETFL, O_NONBLOCK);
    }

    return SpawnedTarget{
        .pid = pid,
        .map_size_fd = (mode == SpawnMode::MapSizePass) ? pipefd[0] : -1,
        .notif_fd = notif_fd
    };
}

TargetExit wait_target_exit(pid_t pid, uint64_t timeout_ms) {
    const uint64_t start = utils::get_time_ms();
    int status = 0;
    while (true) {
        pid_t res = waitpid(pid, &status, WNOHANG);
        if (res == pid) {
            return TargetExit{.exited = true, .status = status};
        }
        if (res == -1) {
            if (errno == EINTR) continue;
            return TargetExit{.exited = false, .status = 0};  // e.g. ECHILD
        }
        if (utils::get_time_ms() - start >= timeout_ms) {
            return TargetExit{.exited = false, .status = 0};
        }
        utils::sleep_ms(10);
    }
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
