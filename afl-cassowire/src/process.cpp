// src/process.cpp

#include "process.hpp"
#include "log.hpp"
#include "network.hpp"
#include "utils.hpp"

#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include <unordered_set>
#include <filesystem>
#include <climits>
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
#include <cstdio>
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
        // Exception-free parsing: an all-digit directory name that exceeds
        // uint32 would make std::stoi throw std::out_of_range uncaught.
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

// --- Port-conflict preflight ------------------------------------------------

static bool read_proc_ppid(pid_t pid, pid_t* out) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char buf[512];
    ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
    ::close(fd);
    if (n <= 0) return false;
    buf[n] = '\0';
    return parse_proc_ppid(buf, static_cast<size_t>(n), out);
}

static std::string proc_comm(pid_t pid) {
    std::ifstream file("/proc/" + std::to_string(pid) + "/comm");
    std::string comm;
    if (std::getline(file, comm)) return comm;
    return "?";
}

static std::string proc_cmdline(pid_t pid) {
    std::ifstream file("/proc/" + std::to_string(pid) + "/cmdline", std::ios::binary);
    std::string cmdline((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    std::replace(cmdline.begin(), cmdline.end(), '\0', ' ');
    if (!cmdline.empty() && cmdline.back() == ' ') cmdline.pop_back();
    return cmdline;
}

static std::string proc_exe(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    char buf[PATH_MAX];
    ssize_t n = readlink(path, buf, sizeof(buf) - 1);
    if (n <= 0) return {};
    std::string exe(buf, static_cast<size_t>(n));
    const std::string deleted = " (deleted)";
    if (exe.size() > deleted.size() &&
        exe.compare(exe.size() - deleted.size(), deleted.size(), deleted) == 0) {
        exe.resize(exe.size() - deleted.size());
    }
    return exe;
}

static bool is_self_or_ancestor(pid_t pid) {
    pid_t cur = getpid();
    while (cur > 1) {
        if (cur == pid) return true;
        pid_t ppid = -1;
        if (!read_proc_ppid(cur, &ppid) || ppid <= 0) break;
        cur = ppid;
    }
    return pid == getpid();
}

// True when @p pid has a live (non-zombie) parent. A process with a live
// parent belongs to a live tree (the cmplog target under its proxy and
// afl-fuzz included) and is never a cleanup candidate. Only a process whose
// parent is init, gone, or a zombie is considered orphaned/stale.
static bool has_live_parent(pid_t pid) {
    pid_t ppid = -1;
    if (!read_proc_ppid(pid, &ppid) || ppid <= 1) return false;

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/stat", ppid);
    int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    char buf[512];
    ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
    ::close(fd);
    if (n <= 0) return false;
    buf[n] = '\0';

    // Field 3 (state) is the first token after the last ')'.
    size_t rparen = 0;
    bool found = false;
    for (ssize_t i = 0; i < n; i++) {
        if (buf[i] == ')') { rparen = static_cast<size_t>(i); found = true; }
    }
    if (!found) return false;
    const char* p = buf + rparen + 1;
    while (*p == ' ' || *p == '\t') p++;
    return *p != 'Z' && *p != 'X' && *p != 'x' && *p != '\0';
}

static bool is_orphaned(pid_t pid) {
    return !has_live_parent(pid);
}

static bool process_matches_target(pid_t pid, const TargetConfig& target) {
    const std::string exe = proc_exe(pid);
    if (!exe.empty()) {
        std::error_code ec;
        std::filesystem::path want = std::filesystem::canonical(target.binary, ec);
        if (ec) {
            ec.clear();
            want = std::filesystem::absolute(target.binary, ec);
        }
        if (!ec && want.string() == exe) return true;
    }

    // argv[0] fallback for scripts / wrappers whose /proc/<pid>/exe is an
    // interpreter instead of the configured binary.
    std::ifstream file("/proc/" + std::to_string(pid) + "/cmdline", std::ios::binary);
    std::string cmdline((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    const size_t nul = cmdline.find('\0');
    const std::string argv0 = cmdline.substr(0, nul);
    if (!target.args.empty()) return argv0 == target.args[0];
    return argv0 == target.binary;
}

struct InodeHolders {
    std::vector<pid_t> pids;
    bool unreadable = false;
};

static InodeHolders find_inode_holders(const std::string& inode) {
    InodeHolders result;
    const std::string want = "socket:[" + inode + "]";

    DIR* proc = opendir("/proc");
    if (!proc) {
        result.unreadable = true;
        return result;
    }
    struct dirent* entry;
    while ((entry = readdir(proc)) != nullptr) {
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;
        auto parsed = utils::parse_u32_strict(entry->d_name);
        if (!std::holds_alternative<std::uint32_t>(parsed)) continue;
        const pid_t pid = static_cast<pid_t>(std::get<std::uint32_t>(parsed));
        if (pid <= 1) continue;

        const std::string fd_dir = "/proc/" + std::to_string(pid) + "/fd";
        DIR* fds = opendir(fd_dir.c_str());
        if (!fds) {
            if (errno == EACCES || errno == EPERM) result.unreadable = true;
            continue;
        }
        struct dirent* fd_entry;
        bool holds = false;
        while ((fd_entry = readdir(fds)) != nullptr) {
            if (fd_entry->d_name[0] < '0' || fd_entry->d_name[0] > '9') continue;
            const std::string link_path = fd_dir + "/" + fd_entry->d_name;
            char link[128];
            ssize_t n = readlink(link_path.c_str(), link, sizeof(link) - 1);
            if (n <= 0) continue;
            link[n] = '\0';
            if (want == link) {
                holds = true;
                break;
            }
        }
        closedir(fds);
        if (holds) result.pids.push_back(pid);
    }
    closedir(proc);
    std::sort(result.pids.begin(), result.pids.end());
    result.pids.erase(std::unique(result.pids.begin(), result.pids.end()), result.pids.end());
    return result;
}

static std::string describe_holder(pid_t pid) {
    pid_t ppid = -1;
    (void)read_proc_ppid(pid, &ppid);
    return "pid " + std::to_string(pid) + " (comm '" + proc_comm(pid) +
           "', ppid " + std::to_string(ppid) + ", argv '" + proc_cmdline(pid) + "')";
}

bool handle_port_conflict(const Config& cfg) {
    if (!cfg.cleanup.enabled) return true;

    const uint16_t port = static_cast<uint16_t>(cfg.network.port);
    const std::optional<std::string> inode = network::find_listen_inode_for_port(port);
    if (!inode) return true; // port is free

    const InodeHolders holders = find_inode_holders(*inode);
    if (holders.pids.empty()) {
        // The LISTEN entry exists but no holder was resolvable. Re-check: the
        // socket may have disappeared between the two scans, otherwise refuse
        // rather than start or kill blindly.
        if (!network::find_listen_inode_for_port(port)) return true;
        PROXY_LOG_ERROR("cleanup: port {} is listening (inode {}) but its holder could not be "
                        "resolved{}; refusing to start",
                        port, *inode, holders.unreadable ? " (unreadable /proc/<pid>/fd)" : "");
        return false;
    }

    std::vector<pid_t> orphans;
    for (pid_t pid : holders.pids) {
        if (is_self_or_ancestor(pid) || !is_orphaned(pid)) {
            PROXY_LOG_ERROR("cleanup: port {} is held by a live process {}; refusing to start "
                            "(only orphaned holders of this port are eligible)",
                            port, describe_holder(pid));
            return false;
        }
        orphans.push_back(pid);
    }

    if (cfg.cleanup.on_port_conflict == CleanupConfig::PortConflictPolicy::error) {
        for (pid_t pid : orphans) {
            PROXY_LOG_ERROR("cleanup: port {} is held by orphaned process {}; refusing to start "
                            "(cleanup.on_port_conflict=error)",
                            port, describe_holder(pid));
        }
        return false;
    }

    for (pid_t pid : orphans) {
        if (!process_matches_target(pid, cfg.target)) {
            PROXY_LOG_ERROR("cleanup: orphaned holder {} does not match target binary '{}'; "
                            "refusing to kill it",
                            describe_holder(pid), cfg.target.binary);
            return false;
        }
    }

    // SIGKILL the union of the holders' process trees. Targets stay in their
    // own process group and do not detach, so this covers their workers too.
    std::vector<pid_t> victims;
    std::unordered_set<pid_t> seen;
    for (pid_t pid : orphans) {
        for (pid_t victim : collect_pid_tree(pid)) {
            if (victim <= 1 || is_self_or_ancestor(victim)) continue;
            const pid_t pgid = getpgid(victim);
            if (pgid != -1 && pgid == getpgrp()) continue;
            if (seen.insert(victim).second) victims.push_back(victim);
        }
    }

    for (pid_t pid : victims) {
        if (kill(pid, SIGKILL) != 0 && errno != ESRCH) {
            PROXY_LOG_WARN("cleanup: SIGKILL of {} failed: {}", describe_holder(pid), strerror(errno));
        }
    }
    for (pid_t pid : victims) {
        PROXY_LOG_INFO("cleanup: SIGKILLed orphaned port holder {}", describe_holder(pid));
    }

    // SIGKILL delivery is asynchronous; give the kernel a bounded moment to
    // release the socket before declaring failure. This is not a term/kill
    // grace, just a confirmation wait.
    const uint64_t deadline = utils::get_time_ms() + 200;
    while (utils::get_time_ms() < deadline) {
        if (!network::find_listen_inode_for_port(port)) return true;
        utils::sleep_ms(10);
    }

    PROXY_LOG_ERROR("cleanup: port {} is still listening after SIGKILLing its orphaned holders",
                    port);
    return false;
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
                "AFL_DEBUG", "AFL_DEBUG_CHILD", "AFL_MAP_SIZE", "AFL_NO_UI",
                "AFL_QEMU_COMPCOV_DEBUG", "AFL_QEMU_CMPLOG_DEBUG", "AFL_QEMU_MAP_SIZE",
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

    // Open the configured stdin path (target.stdin_path) in the parent, before
    // fork(), so failures surface with normal logging instead of the pre-exec
    // dprintf path. The descriptor is handed to fork_target() via
    // TargetPrepared::stdin_fd and dup2()ed onto the child's fd 0 there.
    // MapSizePass deliberately skips this: opening the path would create a
    // fifo reader during test-mode Pass 1, which (a) unblocks an external
    // writer so its data lands in the fifo buffer that Pass 1 never reads -
    // and when Pass 1's fds close, buffered data may be discarded - and (b)
    // serves no purpose, since the map-size dump never touches stdin.
    // O_NONBLOCK keeps the open itself from parking on a fifo that has no
    // writer yet; the flag is cleared right away so the target's read()s
    // behave like regular blocking stdin. O_CLOEXEC is hygiene for the
    // parent's copy; the child's dup onto fd 0 clears it.
    int stdin_fd = -1;
    if (mode != SpawnMode::MapSizePass && cfg.target.stdin_path) {
        stdin_fd = open(cfg.target.stdin_path->c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (stdin_fd < 0) {
            PROXY_LOG_ERROR("failed to open target.stdin_path '{}': {}",
                            *cfg.target.stdin_path, strerror(errno));
            return std::nullopt;
        }
        const int flags = fcntl(stdin_fd, F_GETFL);
        if (flags >= 0) {
            (void)fcntl(stdin_fd, F_SETFL, flags & ~O_NONBLOCK);
        }
        PROXY_LOG_DEBUG("target stdin wired to {}", *cfg.target.stdin_path);
    }

    return TargetPrepared{
        .argv = std::move(c_args),
        .env_strings = std::move(c_env_strings),
        .envp = std::move(c_env),
        .stdin_fd = stdin_fd,
    };
}

// Helper to redirect file descriptors in the child according to the mode.
// stdin_fd is the prepared target.stdin_path descriptor (-1 when unset and
// for MapSizePass, which never opens it): ProxyMode/PlainTest dup2() it onto
// fd 0 (and close the original).
static void redirect_child_fds(SpawnMode mode, bool forward_output, int pipe_write_fd, int stdin_fd) {
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
        // ProxyMode and PlainTest: stdin comes from target.stdin_path when
        // prepared, else /dev/null; stdout/stderr either
        // forwarded to the proxy's descriptors (--child-output) or discarded.
        if (stdin_fd >= 0) {
            dup2(stdin_fd, STDIN_FILENO);
            close(stdin_fd);
        } else {
            int devnull = open("/dev/null", O_RDONLY);
            if (devnull >= 0) {
                dup2(devnull, STDIN_FILENO);
                close(devnull);
            }
        }
        if (!forward_output) {
            const int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDOUT_FILENO);
                dup2(devnull, STDERR_FILENO);
                close(devnull);
            }
        }
    }
}

SpawnedTarget fork_target(const Config& cfg, const TargetPrepared& prep, SpawnMode mode,
                          bool forward_output) {
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
            if (prep.stdin_fd >= 0) {
                close(prep.stdin_fd);
            }
            PROXY_LOG_ERROR("socketpair for seccomp listener handoff failed: {}", strerror(errno));
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
            if (prep.stdin_fd >= 0) {
                close(prep.stdin_fd);
            }
            PROXY_LOG_ERROR("failed to create pipe for map size extraction");
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
        if (prep.stdin_fd >= 0) {
            close(prep.stdin_fd);
        }
        PROXY_LOG_ERROR("fork() failed: {}", strerror(errno));
        return SpawnedTarget{-1, -1};
    }

    if (pid == 0) {
        // Child. The target inherits the proxy's signal mask unchanged; no
        // signals are blocked around fork(). If the proxy died between fork()
        // and the prctl below, the getppid() check catches the orphan.

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
                           (mode == SpawnMode::MapSizePass) ? pipefd[1] : -1,
                           prep.stdin_fd);

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

    // Close our copy of the stdin_path descriptor: the child owns the dup on
    // its fd 0 now (it is -1 for MapSizePass, which never opens the path).
    if (prep.stdin_fd >= 0) {
        close(prep.stdin_fd);
    }

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

std::optional<uint64_t> collect_map_size(int pipe_read_fd) {
    constexpr size_t kMaxMapSizeOutput = 4096;

    // Pass 1 has already exited, so every write is either buffered or the pipe
    // is at EOF. Non-blocking reads keep a descendant that inherited the write
    // end from hanging the proxy; EOF/EAGAIN ends the drain.
    const int flags = fcntl(pipe_read_fd, F_GETFL);
    if (flags >= 0) {
        fcntl(pipe_read_fd, F_SETFL, flags | O_NONBLOCK);
    }

    std::string output;
    char buffer[512];
    for (;;) {
        const ssize_t bytes_read = read(pipe_read_fd, buffer, sizeof(buffer));
        if (bytes_read > 0) {
            if (output.size() + static_cast<size_t>(bytes_read) > kMaxMapSizeOutput) {
                PROXY_LOG_ERROR("map size output exceeds {} bytes.", kMaxMapSizeOutput);
                close(pipe_read_fd);
                return std::nullopt;
            }
            output.append(buffer, static_cast<size_t>(bytes_read));
        } else if (bytes_read == 0) {
            break;
        } else if (errno == EINTR) {
            continue;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        } else {
            PROXY_LOG_ERROR("failed to read map size from target output: {}", strerror(errno));
            close(pipe_read_fd);
            return std::nullopt;
        }
    }
    close(pipe_read_fd);
    PROXY_LOG_DEBUG("bytes read: {}", output.size());

    // Strictly one integer: trim surrounding whitespace from the whole buffer
    // (not just the first line) and reject any other text, a prefix, or a
    // trailing line. The AFL++ runtime prints exactly "%u\n" and exits.
    const size_t start = output.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        PROXY_LOG_ERROR("target produced no output for map size.");
        return std::nullopt;
    }
    const size_t end = output.find_last_not_of(" \t\r\n");
    const std::string trimmed = output.substr(start, end - start + 1);

    auto parsed = utils::parse_u64_strict(trimmed);
    if (std::holds_alternative<utils::ParseError>(parsed)) {
        PROXY_LOG_ERROR("failed to parse map size from target output. Output: '{}'", trimmed);
        return std::nullopt;
    }

    const uint64_t map_size = std::get<uint64_t>(parsed);
    PROXY_LOG_INFO("map size: {}", map_size);
    return map_size;
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
