// src/network.cpp

#include "network.hpp"
#include "log.hpp"
#include "utils.hpp"
#include "process.hpp"

#include <chrono>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstring>
#include <cstdint>
#include <cerrno>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>

namespace network {

std::string DetectError::to_string() const {
    std::ostringstream ss;
    switch (kind) {
        case Kind::TimedOut:
            ss << "timed out waiting for the target to bind and listen on the port";
            break;
        case Kind::TargetDied:
            if (WIFEXITED(wait_status)) {
                ss << "target exited during startup (exit code " << WEXITSTATUS(wait_status) << ")";
            } else if (WIFSIGNALED(wait_status)) {
                ss << "target was killed by signal " << WTERMSIG(wait_status)
                   << " (" << strsignal(WTERMSIG(wait_status)) << ") during startup";
            } else {
                ss << "target died during startup (wait status " << wait_status << ")";
            }
            break;
        case Kind::WaitpidFailed:
            ss << "waitpid() failed: " << strerror(sys_errno);
            break;
        case Kind::UnknownMethod:
            ss << "unknown port detection method";
            break;
    }
    return ss.str();
}

std::string ConnectError::to_string() const {
    std::ostringstream ss;
    switch (kind) {
        case Kind::SocketCreate:  ss << "socket() failed: " << strerror(sys_errno); break;
        case Kind::FcntlSetup:    ss << "fcntl(F_GETFL) failed: " << strerror(sys_errno); break;
        case Kind::InvalidHost:   ss << "host is not a valid IPv4 dotted-quad address"; break;
        case Kind::ConnectFailed: ss << "connect() failed: " << strerror(sys_errno); break;
        case Kind::TimedOut:      ss << "connect timed out"; break;
        case Kind::PollFailed:    ss << "poll() failed: " << strerror(sys_errno); break;
        case Kind::SocketError:   ss << "connection failed: " << strerror(sys_errno); break;
    }
    return ss.str();
}

std::string SendError::to_string() const {
    std::ostringstream ss;
    switch (kind) {
        case Kind::TimedOut:   ss << "send timed out"; break;
        case Kind::SendFailed: ss << "send() failed: " << strerror(sys_errno); break;
        case Kind::PollFailed: ss << "poll() failed: " << strerror(sys_errno); break;
    }
    return ss.str();
}

std::string WaitError::to_string() const {
    std::ostringstream ss;
    switch (kind) {
        case Kind::TimedOut:   ss << "no response within timeout"; break;
        case Kind::PollFailed: ss << "poll() failed: " << strerror(sys_errno); break;
        case Kind::RecvFailed: ss << "recv() failed: " << strerror(sys_errno); break;
    }
    return ss.str();
}

struct InodeOwnershipResult {
    bool found = false;
    bool unreadable = false;
    int last_errno = 0;
    pid_t last_errno_pid = 0;
};

// True if "socket:[<inode>]" is held by @p target_pid or any process in its
// subtree (NGINX-style workers included). Returns detailed result including
// whether the inode was found, whether EACCES/EPERM was encountered (e.g. a
// setuid target that dropped privileges), and the last non-permission errno
// (e.g. ENOENT for dead process, EMFILE/ENFILE for resource exhaustion).
static InodeOwnershipResult check_inode_ownership(pid_t target_pid, const std::string& inode) {
    InodeOwnershipResult result;
    const std::string want = "socket:[" + inode + "]";
    std::vector<pid_t> tree = process::collect_pid_tree(target_pid);
    for (pid_t pid : tree) {
        char dir[64];
        snprintf(dir, sizeof(dir), "/proc/%d/fd", pid);
        DIR* d = opendir(dir);
        if (!d) {
            int err = errno;
            if (err == EACCES || err == EPERM) {
                result.unreadable = true;
            } else if (err != ENOENT) {
                // Track non-permission, non-ENOENT errors (ENOENT = process already dead)
                result.last_errno = err;
                result.last_errno_pid = pid;
            }
            continue;
        }
        struct dirent* e;
        while ((e = readdir(d)) != nullptr) {
            if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
            char path[96];
            snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
            char link[128];
            ssize_t n = readlink(path, link, sizeof(link) - 1);
            if (n <= 0) continue;
            link[n] = '\0';
            if (want == link) {
                closedir(d);
                result.found = true;
                return result;
            }
        }
        closedir(d);
    }
    return result;
}

// TODO(claude): RESOLVED (was: procfs detection could not notice that the target already died - it
//   polled the whole initial_ms even if the child exited - and could false-positive on a port held
//   by a stale/foreign process): the loop now polls waitpid(WNOHANG) every pass and reports
//   TargetDied (the zombie is reaped here, like the seccomp(user-notif) death path), and with
//   port_detection.verify_ownership (default true) the matched LISTEN line's socket inode
//   (10th token of the /proc/net/tcp{,6} entry) must be held via a socket:[<inode>] readlink in
//   /proc/<pid>/fd of the direct child or one of its descendants (process::collect_pid_tree). A
//   setuid-style target with an unreadable fd dir (EACCES/EPERM) is accepted unverified with a WARN.
//
// TODO(claude): the ownership check races with the target itself: a LISTEN entry whose fd was
//   already closed (socket half-torn-down) fails ownership for one poll pass and then disappears;
//   that is benign (we keep polling), but a rebinding target (SO_REUSEADDR close->bind) can pass
//   with the OLD inode on the very pass after its close - the next exchange would still work since
//   the port is then genuinely listening again.
static DetectResult check_procfs(pid_t target_pid, int target_port, uint64_t timeout_ms,
                                 bool verify_ownership) {
    uint64_t start = utils::get_time_ms();
    std::string stale_inode;   // last LISTEN inode that failed ownership verification
    bool warned_unreadable = false;
    while (utils::get_time_ms() - start < timeout_ms) {
        // Death check: the target is the proxy's direct child and nothing else
        // reaps it during detection (no tracing or handshakes are involved),
        // so a non-zero waitpid(WNOHANG) result is a real death event.
        int wait_status = 0;
        pid_t reaped = waitpid(target_pid, &wait_status, WNOHANG);
        if (reaped == target_pid) {
            return DetectError{DetectError::Kind::TargetDied, 0, wait_status};
        }
        if (reaped == -1) {
            if (errno == EINTR) continue;
            return DetectError{DetectError::Kind::WaitpidFailed, errno, 0};
        }

        // Find a LISTEN entry on the configured port and remember its socket
        // inode (10th token: sl local rem st tx:rx tr:tm retrnsmt uid timeout inode).
        std::string listen_inode;
        for (const char* path : {"/proc/net/tcp", "/proc/net/tcp6"}) {
            std::ifstream file(path);
            if (!file.is_open()) continue;

            std::string line;
            std::getline(file, line); // skip header
            while (std::getline(file, line)) {
                std::istringstream iss(line);
                std::string idx, local_addr, rem_addr, state;
                if (!(iss >> idx >> local_addr >> rem_addr >> state)) continue;
                if (state != "0A") continue; // TCP_LISTEN
                size_t colon = local_addr.find(':');
                if (colon == std::string::npos) continue;
                auto parsed = utils::parse_u16_strict(local_addr.substr(colon + 1), 16);
                if (!std::holds_alternative<std::uint16_t>(parsed) ||
                    std::get<std::uint16_t>(parsed) != target_port) {
                    continue;
                }
                std::string tok;
                for (int i = 0; i < 6; i++) {
                    if (!(iss >> tok)) { tok.clear(); break; }
                }
                if (!tok.empty()) {
                    listen_inode = tok;
                    break;
                }
            }
            if (!listen_inode.empty()) break;
        }
        if (listen_inode.empty()) {
            utils::sleep_ms(10);
            continue;
        }
        if (!verify_ownership) return std::monostate{};

        // Ownership verification: the inode must be held by the target or one of
        // its descendants (NGINX-style workers included).
        auto ownership = check_inode_ownership(target_pid, listen_inode);
        if (ownership.found) {
            PROXY_LOG_DEBUG("port {} listening via inode {} owned by target {} (procfs)",
                            target_port, listen_inode, static_cast<int>(target_pid));
            return std::monostate{};
        }
        if (ownership.unreadable) {
            // Cannot prove ownership (e.g. a setuid target that dropped
            // privileges): accept rather than wedge the proxy, but say so.
            if (!warned_unreadable) {
                PROXY_LOG_WARN("port {} is listening (inode {}) but the fd directory of target "
                               "{} or a descendant is unreadable (EACCES/EPERM, e.g. a setuid "
                               "target); accepting the port unverified",
                               target_port, listen_inode, static_cast<int>(target_pid));
                warned_unreadable = true;
            }
            return std::monostate{};
        }
        if (ownership.last_errno != 0) {
            if (!warned_unreadable) {
                PROXY_LOG_WARN("port {} is listening (inode {}) but fd directory access failed "
                               "for target {} or descendant {}: {}",
                               target_port, listen_inode, static_cast<int>(target_pid),
                               static_cast<int>(ownership.last_errno_pid),
                               strerror(ownership.last_errno));
                warned_unreadable = true;
            }
            return std::monostate{};
        }
        stale_inode = listen_inode;
        utils::sleep_ms(10);
    }
    if (!stale_inode.empty()) {
        PROXY_LOG_WARN("port {} is held by a listener whose socket inode {} is not owned by "
                       "target {} or any of its descendants (stale or foreign process?); "
                       "failing detection after {} ms via procfs",
                       target_port, stale_inode, static_cast<int>(target_pid), timeout_ms);
    } else {
        PROXY_LOG_WARN("port {} not seen listening after {} ms via procfs",
                       target_port, timeout_ms);
    }
    return DetectError{DetectError::Kind::TimedOut, 0, 0};
}

// --- seccomp(user-notif) port detection -------------------------------------

// Notification plumbing shared by the startup detector (notif_port) and the
// steady-state pump (pump_notif_listener). The target runs with a
// SECCOMP_RET_USER_NOTIF filter on bind()/listen() installed before its
// execve(); the listener fd (passed to us via SCM_RIGHTS in fork_target) is
// the single aggregation point for those syscalls from ANY thread or forked
// descendant of the target tree (including a QEMU guest's workers). No ptrace
// is involved anywhere.

namespace {

struct NotifBuffers {
    size_t req_size = 0;  // kernel-reported size of struct seccomp_notif; 0 => unusable
    struct seccomp_notif_resp cont = {};
    NotifBuffers() {
        struct seccomp_notif_sizes sizes = {};
        if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) == 0 &&
            sizes.seccomp_notif >= sizeof(struct seccomp_notif)) {
            req_size = sizes.seccomp_notif;
        }
        cont.val = 0;
        cont.error = 0;
        cont.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;  // run the syscall unmodified
    }
};

const NotifBuffers& notif_buffers() {
    static NotifBuffers nb;
    return nb;
}

// Answers a received notification with CONTINUE. False means the task is gone
// (ENOENT) or EINTR - both benign; the task simply resumes without us.
bool notif_send_continue(int fd, const struct seccomp_notif& n) {
    struct seccomp_notif_resp resp = notif_buffers().cont;
    resp.id = n.id;
    if (ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) == 0) return true;
    return errno == ENOENT || errno == EINTR;
}

// Extracts the port from the sockaddr of a notified bind(). The pointer lives
// in the target's address space (n.pid is the notifying thread's tid; the
// address space is shared), read without stopping the task: the notification
// itself keeps it suspended until we answer.
bool notif_bind_port(const struct seccomp_notif& n, int* port_out) {
    const __u64 addr_ptr = n.data.args[1];
    const __u64 addrlen_u = n.data.args[2];
    if (addr_ptr == 0 || addrlen_u < 2 || addrlen_u > sizeof(struct sockaddr_storage)) {
        return false;
    }
    const socklen_t addrlen = static_cast<socklen_t>(addrlen_u);
    struct sockaddr_storage addr = {};
    struct iovec local_iov = { &addr, sizeof(addr) };
    struct iovec remote_iov = { reinterpret_cast<void*>(addr_ptr), addrlen };
    if (process_vm_readv(static_cast<pid_t>(n.pid), &local_iov, 1, &remote_iov, 1, 0) !=
        static_cast<ssize_t>(addrlen)) {
        return false;
    }
    if (addr.ss_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
        *port_out = ntohs(reinterpret_cast<const struct sockaddr_in*>(&addr)->sin_port);
        return true;
    }
    if (addr.ss_family == AF_INET6 && addrlen >= sizeof(struct sockaddr_in6)) {
        *port_out = ntohs(reinterpret_cast<const struct sockaddr_in6*>(&addr)->sin6_port);
        return true;
    }
    return false;  // other families are not TCP servers we care about
}

// True while any /proc/net/tcp{,6} entry shows the port in TCP_LISTEN. Used to
// confirm readiness after the listen() notification: user notifications carry
// syscall ENTRY only, so unlike the old ptrace realization there is no exit
// value to prove bind()/listen() actually succeeded (EADDRINUSE etc. is only
// visible through the socket table).
bool procfs_port_listening(int target_port) {
    for (const char* path : {"/proc/net/tcp", "/proc/net/tcp6"}) {
        std::ifstream file(path);
        if (!file.is_open()) continue;
        std::string line;
        std::getline(file, line);  // skip header
        while (std::getline(file, line)) {
            std::istringstream iss(line);
            std::string idx, local_addr, rem_addr, state;
            if (!(iss >> idx >> local_addr >> rem_addr >> state)) continue;
            if (state != "0A") continue;  // TCP_LISTEN
            size_t colon = local_addr.find(':');
            if (colon == std::string::npos) continue;
            auto parsed = utils::parse_u16_strict(local_addr.substr(colon + 1), 16);
            if (std::holds_alternative<std::uint16_t>(parsed) &&
                std::get<std::uint16_t>(parsed) == target_port) {
                return true;
            }
        }
    }
    return false;
}

DetectResult notif_port(int notif_fd, pid_t target_pid, int target_port, uint64_t timeout_ms) {
    const NotifBuffers& nb = notif_buffers();
    if (notif_fd < 0 || nb.req_size == 0) {
        return DetectError{DetectError::Kind::UnknownMethod, 0, 0};
    }

    // fd -> port, recorded from bind() notifications (listen() carries no
    // address argument). A failed bind leaves a stale entry until the next
    // confirmation failure clears it; readiness is only ever declared after a
    // /proc confirmation, so this cannot false-positive.
    std::unordered_map<int, int> bound_ports;
    std::vector<unsigned char> buf(nb.req_size);
    const uint64_t start = utils::get_time_ms();
    int wait_status = 0;

    while (utils::get_time_ms() - start < timeout_ms) {
        // Death check (same contract as check_procfs): nothing else reaps the
        // child during detection.
        pid_t reaped = waitpid(target_pid, &wait_status, WNOHANG);
        if (reaped == target_pid) {
            return DetectError{DetectError::Kind::TargetDied, 0, wait_status};
        }
        if (reaped == -1 && errno != EINTR) {
            return DetectError{DetectError::Kind::WaitpidFailed, errno, 0};
        }

        int remaining = static_cast<int>(timeout_ms - (utils::get_time_ms() - start));
        if (remaining < 1) break;
        struct pollfd pfd = { notif_fd, POLLIN, 0 };
        int pr = poll(&pfd, 1, remaining);
        if (pr < 0) {
            if (errno == EINTR) continue;
            PROXY_LOG_WARN("notif poll() failed: {}", strerror(errno));
            utils::sleep_ms(10);
            continue;
        }
        if (pr == 0) continue;
        if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) {
            // No task references the listener anymore: the whole filtered tree
            // is gone; the death check above reaps and reports next pass.
            utils::sleep_ms(10);
            continue;
        }
        if (!(pfd.revents & POLLIN)) continue;

        std::memset(buf.data(), 0, buf.size());
        struct seccomp_notif* n = reinterpret_cast<struct seccomp_notif*>(buf.data());
        if (ioctl(notif_fd, SECCOMP_IOCTL_NOTIF_RECV, n) != 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ||
                errno == ENOENT || errno == ENOTCONN || errno == EIO) {
                utils::sleep_ms(1);  // spurious readiness or a dead notification
                continue;
            }
            PROXY_LOG_WARN("NOTIF_RECV failed: {}", strerror(errno));
            break;
        }

        const int fd = static_cast<int>(n->data.args[0]);
        bool listen_on_configured_fd = false;
        if (n->data.nr == __NR_bind) {
            int port = -1;
            if (notif_bind_port(*n, &port)) {
                if (port == 0) {
                    PROXY_LOG_WARN("target requested ephemeral port (0), skipping...");
                } else {
                    bound_ports[fd] = port;
                    PROXY_LOG_DEBUG("Detected bind on port {} (fd {}, tid {})",
                                    port, fd, static_cast<int>(n->pid));
                }
            } else {
                PROXY_LOG_DEBUG("bind notification on fd {} without a readable "
                                "IPv4/IPv6 sockaddr (tid {})", fd, static_cast<int>(n->pid));
            }
        } else if (n->data.nr == __NR_listen) {
            PROXY_LOG_DEBUG("Detected listen on fd {} (tid {})", fd, static_cast<int>(n->pid));
            auto it = bound_ports.find(fd);
            if (it != bound_ports.end() && it->second == target_port) {
                listen_on_configured_fd = true;
            }
        }

        // Always answer: the notified task sleeps in the kernel until we do.
        notif_send_continue(notif_fd, *n);

        if (listen_on_configured_fd) {
            // Confirm the (now resumed) bind()/listen() reached the socket
            // table: bounded scan, ~100 ms worst case.
            for (int i = 0; i < 20; i++) {
                if (procfs_port_listening(target_port)) {
                    PROXY_LOG_INFO("target is listening on port {} (via seccomp user-notification)",
                                   target_port);
                    return std::monostate{};
                }
                utils::sleep_ms(5);
                reaped = waitpid(target_pid, &wait_status, WNOHANG);
                if (reaped == target_pid) {
                    return DetectError{DetectError::Kind::TargetDied, 0, wait_status};
                }
            }
            PROXY_LOG_WARN("listen() on port {} was notified but not confirmed in /proc "
                           "(bind/listen may have failed, e.g. EADDRINUSE); continuing to wait",
                           target_port);
            bound_ports.erase(fd);  // let a re-bind of the same fd re-arm detection
        }
    }

    PROXY_LOG_WARN("configured port {} not bound+listened after {} ms via seccomp(user-notif)",
                   target_port, timeout_ms);
    return DetectError{DetectError::Kind::TimedOut, 0, 0};
}

}  // namespace

// Listener fd of the target's seccomp notification filter, kept for the whole
// target lifetime (the filter is installed before execve and is irremovable,
// so bind()/listen() keep notifying forever); -1 disables the pump.
static int g_notif_fd = -1;

void set_notif_listener(int fd) {
    g_notif_fd = fd;
}

void pump_notif_listener() {
    const int fd = g_notif_fd;
    if (fd < 0) return;
    const NotifBuffers& nb = notif_buffers();
    if (nb.req_size == 0) return;

    static std::vector<unsigned char> buf(nb.req_size);  // proxy is single-threaded
    while (true) {
        struct pollfd pfd = { fd, POLLIN, 0 };
        int pr = poll(&pfd, 1, 0);
        if (pr <= 0 || !(pfd.revents & POLLIN)) return;  // nothing queued / listener gone

        std::memset(buf.data(), 0, buf.size());
        struct seccomp_notif* n = reinterpret_cast<struct seccomp_notif*>(buf.data());
        if (ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, n) != 0) return;  // EAGAIN/ENOENT/...

        // Steady state: the port is already known, every bind()/listen() the
        // target (or a worker/thread under the inherited filter) issues is
        // simply released to run normally.
        const char* what = (n->data.nr == __NR_bind) ? "bind" :
                           (n->data.nr == __NR_listen) ? "listen" : "traced syscall";
        PROXY_LOG_DEBUG("notif pump: released {} from tid {}", what, static_cast<int>(n->pid));
        notif_send_continue(fd, *n);
    }
}

DetectResult wait_for_port(pid_t target_pid, const Config& cfg, int notif_fd) {
    PROXY_LOG_INFO("waiting for port {} via {} (initial_ms={})",
                   cfg.network.port, cfg.port_detection.primary, cfg.network.initial_ms);
    if (cfg.port_detection.primary == "procfs") {
        return check_procfs(target_pid, cfg.network.port, cfg.network.initial_ms,
                            cfg.port_detection.verify_ownership);
    } else if (cfg.port_detection.primary == "seccomp") {
        return notif_port(notif_fd, target_pid, cfg.network.port, cfg.network.initial_ms);
    }
    return DetectError{DetectError::Kind::UnknownMethod, 0, 0};
}

ConnectResult connect_target(const NetworkConfig& net_cfg) {
    // TODO(claude): (1) the socket is switched back to BLOCKING mode after connect, so send_all()'s timeout
    //   is not enforced: send() can block forever if the target stops reading (the EAGAIN/poll branch in
    //   send_all is dead code). Keep O_NONBLOCK or set SO_SNDTIMEO.
    //   (2) RESOLVED: thousands of iterations/s used to create thousands of TIME_WAIT sockets on the client
    //       side, eventually exhausting the ephemeral port range (connect fails with EADDRNOTAVAIL). Callers
    //       now arm SO_LINGER{1,0} via arm_rst_on_close() before dropping the socket, so close() sends RST
    //       and nothing sits in TIME_WAIT. Also no TCP_NODELAY / SOCK_CLOEXEC.
    //   (3) Only AF_INET + inet_pton is supported; host "localhost"/IPv6 (accepted by config.cpp) fails.
    //   (4) poll() returning -1/EINTR is treated as a connect failure.
    //   (5) The second fcntl() per successful connect (restore of blocking mode) is intentionally left
    //   unchecked, matching the original behavior.
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return ConnectError{ConnectError::Kind::SocketCreate, errno};

    utils::FdGuard guard{sock};

    int flags = fcntl(guard.get(), F_GETFL, 0);
    if (flags < 0) return ConnectError{ConnectError::Kind::FcntlSetup, errno};
    fcntl(guard.get(), F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(net_cfg.port);
    if (inet_pton(AF_INET, net_cfg.host.c_str(), &addr.sin_addr) <= 0) {
        return ConnectError{ConnectError::Kind::InvalidHost, 0};
    }

    int res = connect(guard.get(), (struct sockaddr*)&addr, sizeof(addr));
    if (res < 0 && errno != EINPROGRESS) {
        return ConnectError{ConnectError::Kind::ConnectFailed, errno};
    }

    if (res == 0) {
        fcntl(guard.get(), F_SETFL, flags);
        return guard;
    }

    struct pollfd pfd;
    pfd.fd = guard.get();
    pfd.events = POLLOUT;

    int poll_res = poll(&pfd, 1, net_cfg.timeout_ms);
    if (poll_res == 0) {
        return ConnectError{ConnectError::Kind::TimedOut, 0};
    }
    if (poll_res < 0) {
        return ConnectError{ConnectError::Kind::PollFailed, errno};
    }

    int err = 0;
    socklen_t len = sizeof(err);
    getsockopt(guard.get(), SOL_SOCKET, SO_ERROR, &err, &len);
    if (err != 0) {
        return ConnectError{ConnectError::Kind::SocketError, err};
    }

    fcntl(guard.get(), F_SETFL, flags);
    return guard;
}

// TODO(claude): `buf` may be nullptr/len 0 (placeholder AFL macros) - harmless here (the loop simply does
//   not run and the call reports success). The callers in main.cpp now check the returned SendResult.
// TODO(claude): with a blocking socket (the state connect_target() leaves it in) the EAGAIN/poll branch is
//   dead code and send() can block forever if the target stops reading - see the connect_target() TODO.
SendResult send_all(int sock, const uint8_t* buf, size_t len, int timeout_ms) {
    size_t sent = 0;
    uint64_t start = utils::get_time_ms();

    while (sent < len) {
        if (utils::get_time_ms() - start > (uint64_t)timeout_ms)
            return SendError{SendError::Kind::TimedOut, 0};

        ssize_t n = send(sock, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd;
                pfd.fd = sock;
                pfd.events = POLLOUT;
                int remaining = timeout_ms - (int)(utils::get_time_ms() - start);
                if (remaining <= 0) return SendError{SendError::Kind::TimedOut, 0};
                int poll_res = poll(&pfd, 1, remaining);
                if (poll_res < 0) {
                    if (errno == EINTR) continue;
                    return SendError{SendError::Kind::PollFailed, errno};
                }
                if (poll_res == 0) {
                    pump_notif_listener();
                    return SendError{SendError::Kind::TimedOut, 0};
                }
                continue;
            }
            return SendError{SendError::Kind::SendFailed, errno};
        }
        sent += n;
    }
    return std::monostate{};
}

// TODO(claude): reading "until EOF or timeout" against a keep-alive server (nginx) always burns the full
//   timeout_ms per iteration, capping throughput at 1000/timeout_ms exec/s (5/s with the default 200ms).
//   The other problems of the former bool API (contract mismatch, discarded data, debug spam, EINTR treated
//   as EOF) were addressed by the SendResult/WaitResult conversion.
WaitResult wait_response(int sock, int timeout_ms) {
    std::vector<uint8_t> data;
    uint8_t buf[4096];
    uint64_t start = utils::get_time_ms();

    while (true) {
        if (utils::get_time_ms() - start > (uint64_t)timeout_ms) {
            if (data.empty()) return WaitError{WaitError::Kind::TimedOut, 0};
            return data; // partial response received before the timeout
        }

        struct pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLIN;
        int remaining = timeout_ms - (int)(utils::get_time_ms() - start);
        if (remaining <= 0) {
            if (data.empty()) return WaitError{WaitError::Kind::TimedOut, 0};
            return data;
        }

        int poll_res = poll(&pfd, 1, remaining);
        if (poll_res < 0) {
            if (errno == EINTR) continue;
            return WaitError{WaitError::Kind::PollFailed, errno};
        }
        if (poll_res == 0) {
            // Release a pending seccomp notification: a target task blocked
            // waiting for our CONTINUE cannot service the connection, so poll
            // would just time out.
            pump_notif_listener();
            continue; // poll timeout; the loop top re-checks the overall deadline
        }

        ssize_t n = recv(sock, buf, sizeof(buf), 0);
        if (n > 0) {
            data.insert(data.end(), buf, buf + n);
            continue;
        }
        if (n == 0) break; // orderly EOF

        if (errno == EINTR) continue;
        return WaitError{WaitError::Kind::RecvFailed, errno};
    }

    return data;
}

std::string probe_outcome_to_string(ProbeOutcome outcome) {
    switch (outcome) {
        case ProbeOutcome::Serviced: return "Serviced";
        case ProbeOutcome::Refused: return "Refused";
        case ProbeOutcome::Timeout: return "Timeout";
        case ProbeOutcome::Failed: return "Failed";
    }
    return "Unknown";
}

ProbeResult probe_target(const NetworkConfig& net_cfg) {
    auto conn = connect_target(net_cfg);
    if (std::holds_alternative<ConnectError>(conn)) {
        const ConnectError& err = std::get<ConnectError>(conn);
        // ECONNREFUSED means no listening socket: the target process died, or
        // its listener is gone for other reasons (rate limit, one-shot server).
        // Everything else is a client-side failure (e.g. EADDRNOTAVAIL on
        // ephemeral port exhaustion, EMFILE on fd exhaustion); the errno is
        // propagated in the result so the caller can tell the two apart.
        // Classification is the caller's job (check_target_state()).
        if (err.kind == ConnectError::Kind::ConnectFailed && err.sys_errno == ECONNREFUSED) {
            return ProbeResult{ProbeOutcome::Refused, err};
        }
        return ProbeResult{ProbeOutcome::Failed, err};
    }
    utils::FdGuard sock = std::get<utils::FdGuard>(std::move(conn));

    // Provoke the target: a healthy keep-alive server (nginx) sends nothing on
    // an accepted-but-unserved connection, so without a stimulus the poll()
    // below would never see readability and the probe would always end in
    // Timeout. Half-closing (the same pattern exchange_once uses on the main
    // connection) delivers EOF; the target reacts by responding or closing,
    // which is exactly what poll() waits for. Errors are ignored: ENOTCONN
    // means the peer already reset (still a serviced connection), and anything
    // else surfaces at poll() time.
    (void)shutdown(sock.get(), SHUT_WR);
    // The probe socket is throwaway: abandon it with RST instead of FIN so it
    // never pins an ephemeral port in TIME_WAIT (see arm_rst_on_close).
    arm_rst_on_close(sock.get());

    // Wait until the target services the probe connection. connect() alone
    // proves nothing (the kernel backlog accepts it), but nothing makes an
    // established, unaccepted socket readable by itself: readability means the
    // target app sent data, closed (EOF), or died (RST). poll() reports
    // POLLERR/POLLHUP even when not requested, so EOF/RST are covered.
    // TODO(claude): residual gaps - deferred timers/async work after servicing,
    //   multi-acceptor/threaded targets, banner servers (see the header contract).
    uint64_t start = utils::get_time_ms();
    PROXY_LOG_TRACE("probe_target start={}", start);
    while (true) {
        int remaining = net_cfg.timeout_ms - (int)(utils::get_time_ms() - start);
        PROXY_LOG_TRACE("probe_target remaining={}", remaining);
        if (remaining <= 0) return ProbeResult{ProbeOutcome::Timeout, std::nullopt};

        struct pollfd pfd;
        pfd.fd = sock.get();
        pfd.events = POLLIN;
        pfd.revents = 0;
        int poll_res = poll(&pfd, 1, remaining);
        PROXY_LOG_TRACE("probe_target poll_res={}", poll_res);
        if (poll_res < 0) {
            if (errno == EINTR) continue;
            return ProbeResult{ProbeOutcome::Failed,
                               ConnectError{ConnectError::Kind::PollFailed, errno}};
        }
        if (poll_res == 0) {
            // Release a pending seccomp notification: a target task blocked
            // waiting for our CONTINUE cannot service the connection, so poll
            // would just time out.
            pump_notif_listener();
            continue; // poll timeout; the loop top re-checks the overall deadline
        }
        return ProbeResult{ProbeOutcome::Serviced, std::nullopt};
    }
}

void arm_rst_on_close(int sock) {
    struct linger lg;
    lg.l_onoff = 1;  // enable SO_LINGER
    lg.l_linger = 0; // zero grace: close() discards and sends RST
    // Best-effort: on failure the next close() keeps its normal FIN semantics.
    (void)setsockopt(sock, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
}

} // namespace network