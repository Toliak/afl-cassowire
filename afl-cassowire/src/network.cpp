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
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/uio.h>
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

// True if "socket:[<inode>]" is held by @p target_pid or any process in its
// subtree (NGINX-style workers included). Sets @p fd_dir_unreadable when a
// tree pid's /proc/<pid>/fd could not be opened for permission reasons
// (EACCES/EPERM, e.g. a setuid target that dropped privileges): ownership
// then cannot be proven, and the caller decides to accept or reject.
static bool inode_owned_by_tree(pid_t target_pid, const std::string& inode,
                                bool* fd_dir_unreadable) {
    const std::string want = "socket:[" + inode + "]";
    std::vector<pid_t> tree = process::collect_pid_tree(target_pid);
    for (pid_t pid : tree) {
        char dir[64];
        snprintf(dir, sizeof(dir), "/proc/%d/fd", pid);
        DIR* d = opendir(dir);
        if (!d) {
            if ((errno == EACCES || errno == EPERM) && fd_dir_unreadable) {
                *fd_dir_unreadable = true;
            }
            continue; // vanished pid or another error: skip it
        }
        struct dirent* e;
        while ((e = readdir(d)) != nullptr) {
            if (e->d_name[0] < '0' || e->d_name[0] > '9') continue; // skip "." and ".."
            char path[96];
            snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
            char link[128]; // "socket:[" + <=20 inode digits + "]" fits easily
            ssize_t n = readlink(path, link, sizeof(link) - 1);
            if (n <= 0) continue;
            link[n] = '\0';
            if (want == link) {
                closedir(d);
                return true;
            }
        }
        closedir(d);
    }
    return false;
}

// TODO(claude): RESOLVED (was: procfs detection could not notice that the target already died - it
//   polled the whole initial_ms even if the child exited - and could false-positive on a port held
//   by a stale/foreign process): the loop now polls waitpid(WNOHANG) every pass and reports
//   TargetDied (the zombie is reaped here, like trace_port's death path), and with
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
        // reaps it during detection (handshake_tracer() is a no-op in procfs
        // mode), so a non-zero waitpid(WNOHANG) result is a real death event.
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
        bool fd_dir_unreadable = false;
        if (inode_owned_by_tree(target_pid, listen_inode, &fd_dir_unreadable)) {
            PROXY_LOG_DEBUG("port {} listening via inode {} owned by target {} (procfs)",
                            target_port, listen_inode, static_cast<int>(target_pid));
            return std::monostate{};
        }
        if (fd_dir_unreadable) {
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

static DetectResult trace_port(pid_t pid, int target_port, uint64_t timeout_ms, bool use_seccomp,
                               bool* tracer_attached) {
    // fd -> port, committed only when a bind() syscall EXITS successfully (listen() carries no
    // address argument, so readiness can only be tied to the fd bound to the configured port).
    std::unordered_map<int, int> bound_ports;

    // bind()/listen() whose exit stop is still pending. In seccomp mode the exit is fetched by
    // resuming the trapped entry stop with PTRACE_SYSCALL exactly once.
    struct Pending {
        bool active = false;
        unsigned long long nr = 0;
        int fd = -1;
        int port = -1; // bind only: port read from the sockaddr at entry
    } pending;

    uint64_t start = utils::get_time_ms();
    int status;
    
    while (utils::get_time_ms() - start < timeout_ms) {
        // TODO(claude): BUG: blocking waitpid (no WNOHANG). The timeout is only evaluated between events, so
        //   if the target never produces a stop (e.g. never calls bind) initial_ms is NOT enforced and the
        //   proxy hangs here. Poll with WNOHANG + short sleep, or use a timer/signalfd.
        pid_t res = waitpid(pid, &status, __WALL);
        if (res == -1) {
            if (errno == EINTR) continue;
            return DetectError{DetectError::Kind::WaitpidFailed, errno, 0};
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            // TODO(claude): silent failure - the target died during startup but nothing says so (exit code /
            //   signal is lost, and it is already reaped here so main.cpp's later waitpid will not see it).
            //   The status is now captured in the returned DetectError before the reap below.
            return DetectError{DetectError::Kind::TargetDied, 0, status};
        }

        // TODO(claude): RESOLVED (was: confusing condition `WIFSTOPPED(res == pid ? status : 0)`) - the
        //   stop check now uses WIFSTOPPED(status) directly; res is always pid here (waitpid(pid, ...)).
        if (WIFSTOPPED(status)) { // waitpid returns pid on success
            int sig = WSTOPSIG(status);
            int event = (status >> 16);

            // Syscall stops only: with TRACESYSGOOD they report SIGTRAP|0x80; a seccomp stop
            // reports SIGTRAP with PTRACE_EVENT_SECCOMP in the event field.
            const bool syscall_stop = sig == (SIGTRAP | 0x80) || event == PTRACE_EVENT_SECCOMP;

            if (syscall_stop) {
                struct user_regs_struct regs;
                // TODO(claude): x86_64-only, like the rest of this function: a syscall-entry
                //   stop always reports rax == -ENOSYS (an exit stop carries the return value
                //   in rax instead). The old `in_syscall` toggle misclassified stops here: once
                //   the exec stop is resumed with PTRACE_SYSCALL, the next stop is execve's
                //   *exit*, which flips the parity, so bind() was only ever evaluated at exit
                //   stops where rsi/rdx no longer hold the sockaddr/length arguments.
                if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == 0) {
                    const bool entry = use_seccomp
                        ? (event == PTRACE_EVENT_SECCOMP)
                        : ((long)regs.rax == -ENOSYS);
            
                    if (entry && regs.orig_rax == __NR_bind) {
                        uintptr_t addr_ptr = regs.rsi;
                        socklen_t addrlen = regs.rdx;
                        
                        // TODO(claude): `addrlen > 0` is too weak: reading ss_family needs >= 2 bytes,
                        //   sin_port >= 4 (AF_INET) / sin6_port >= 4 (AF_INET6); with a shorter addrlen the
                        //   fields below are read from uninitialised stack memory. Also `addr` is not
                        //   zero-initialised. Also regs.rsi/rdx are x86_64-only (fine per spec, but no
                        //   #if defined(__x86_64__) guard / static check).
                        if (addrlen > 0 && addrlen <= sizeof(struct sockaddr_storage)) {
                            struct sockaddr_storage addr;
                            struct iovec local_iov = { &addr, sizeof(addr) };
                            struct iovec remote_iov = { (void*)addr_ptr, addrlen };
                            
                            if (process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0) == (ssize_t)addrlen) {
                                int port = 0;
                                // TODO(claude): spec 5.2 says the intercepted bind() must be VERIFIED to be the
                                //   right one; only the port is compared here - address/interface (INADDR_ANY
                                //   vs a specific IP) and the socklen are ignored. Also IPv6-in-IPv4
                                //   (V4MAPPED) binds are not handled.
                                if (addr.ss_family == AF_INET) {
                                    struct sockaddr_in* in = (struct sockaddr_in*)&addr;
                                    port = ntohs(in->sin_port);
                                } else if (addr.ss_family == AF_INET6) {
                                    struct sockaddr_in6* in6 = (struct sockaddr_in6*)&addr;
                                    port = ntohs(in6->sin6_port);
                                }

                                PROXY_LOG_DEBUG("Detected bind on port {}", port);
                                if (port == 0) {
                                    PROXY_LOG_WARN("target requested ephemeral port (0), skipping...");
                                }
                                pending = {true, __NR_bind, static_cast<int>(regs.rdi), port};
                            }
                        }
                    } else if (entry && regs.orig_rax == __NR_listen) {
                        pending = {true, __NR_listen, static_cast<int>(regs.rdi), -1};
                    } else if (!entry && pending.active && regs.orig_rax == pending.nr) {
                        // Exit stop of a pending bind()/listen(): the return value decides.
                        pending.active = false;
                        const long retval = static_cast<long>(regs.rax);

                        if (pending.nr == __NR_bind) {
                            if (retval == 0) {
                                bound_ports[pending.fd] = pending.port;
                            } else if (pending.port == target_port) {
                                PROXY_LOG_WARN("bind on port {} failed ({}), continuing to wait",
                                               pending.port, strerror(static_cast<int>(-retval)));
                            }
                        } else if (pending.nr == __NR_listen && retval == 0) {
                            auto it = bound_ports.find(pending.fd);
                            if (it != bound_ports.end() && it->second == target_port) {
                                PROXY_LOG_INFO("target is listening on port {}", target_port);
                                // TODO(claude): (1) RESOLVED (was: readiness was declared at bind() ENTRY,
                                //   before bind() succeeded and before listen() ran, so the first
                                //   connect_target() could hit ECONNREFUSED, and a failed (EADDRINUSE)
                                //   bind still counted as ready): readiness is now the successful
                                //   listen() EXIT on the fd bound to the configured port.
                                //   (2) In seccomp mode the BPF filter (trapping bind+listen) stays
                                //   installed (it cannot be removed), so the tracer STAYS ATTACHED and
                                //   resumes every seccomp stop with PTRACE_CONT ("transparent tracer",
                                //   see process::set_transparent_tracer / pump_transparent_tracer) -
                                //   otherwise SECCOMP_RET_TRACE with no tracer fails the syscall with
                                //   ENOSYS. Children of the target inherit the filter UNTRACED, so
                                //   their bind()/listen() still fail with ENOSYS (documented
                                //   limitation). Also ptrace() return value is unchecked.
                                if (use_seccomp) {
                                    // The tracee is in a ptrace-stop right now; PTRACE_CONT (not
                                    // DETACH) is the resume, and it lets listen() complete normally.
                                    ptrace(PTRACE_CONT, pid, 0, 0);
                                    if (tracer_attached) *tracer_attached = true;
                                    PROXY_LOG_INFO("tracer stays attached (transparent mode)");
                                } else {
                                    ptrace(PTRACE_DETACH, pid, 0, 0);
                                }
                                return std::monostate{};
                            }
                        }
                    }
                }
            }
            
            // TODO(claude): RESOLVED (was CRITICAL BUG for `primary: ptrace`): syscall-stops are only
            //   produced if the tracee is resumed with PTRACE_SYSCALL (spec 5.2 says so); the old
            //   unconditional PTRACE_CONT meant no bind() was ever seen and the loop hung in waitpid.
            //   Seccomp mode keeps PTRACE_CONT, except after a trapped bind()/listen() entry whose
            //   exit stop is fetched with a one-shot PTRACE_SYSCALL resume (pending.active).
            //   Still open: group-stop / SIGSTOP signal-delivery-stops are re-injected with `sig` which can leave
            //   the tracee stopped; and the tracer sees only `pid` (no PTRACE_O_TRACEFORK), so forked
            //   children are not traced (fine for the master, but should be documented).
            const auto resume = (!use_seccomp || pending.active) ? PTRACE_SYSCALL : PTRACE_CONT;
            if (sig != SIGTRAP && sig != (SIGTRAP | 0x80) && event == 0) {
                ptrace(resume, pid, 0, sig);
            } else {
                ptrace(resume, pid, 0, 0);
            }
        }
    }
    
    // TODO(claude): after a timeout the tracee is usually RUNNING (not in ptrace-stop), so PTRACE_DETACH
    //   fails with ESRCH and the child stays traced; the error is ignored. Also the timeout is only reached
    //   if waitpid above returned, see the blocking-waitpid TODO.
    // Timeout reached, detach before returning false
    PROXY_LOG_WARN("configured port {} not bound+listened after {} ms via {}; detaching tracer",
                   target_port, timeout_ms, use_seccomp ? "seccomp" : "ptrace");
    ptrace(PTRACE_DETACH, pid, 0, 0);
    return DetectError{DetectError::Kind::TimedOut, 0, 0};
}

DetectResult wait_for_port(pid_t target_pid, const Config& cfg, bool* tracer_attached) {
    if (tracer_attached) *tracer_attached = false;
    PROXY_LOG_INFO("waiting for port {} via {} (initial_ms={})",
                   cfg.network.port, cfg.port_detection.primary, cfg.network.initial_ms);
    if (cfg.port_detection.primary == "procfs") {
        return check_procfs(target_pid, cfg.network.port, cfg.network.initial_ms,
                            cfg.port_detection.verify_ownership);
    } else if (cfg.port_detection.primary == "ptrace") {
        return trace_port(target_pid, cfg.network.port, cfg.network.initial_ms, false, tracer_attached);
    } else if (cfg.port_detection.primary == "seccomp") {
        return trace_port(target_pid, cfg.network.port, cfg.network.initial_ms, true, tracer_attached);
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
                    process::pump_transparent_tracer();
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
            // Release a pending ptrace stop (transparent tracer): a stopped target
            // cannot service the connection, so poll would just time out.
            process::pump_transparent_tracer();
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
            // Release a pending ptrace stop (transparent tracer): a stopped target
            // cannot service the connection, so poll would just time out.
            process::pump_transparent_tracer();
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