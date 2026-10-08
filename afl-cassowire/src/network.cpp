// src/network.cpp

#include "network.hpp"
#include "log.hpp"
#include "utils.hpp"

#include <chrono>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>
#include <cerrno>
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
            ss << "timed out waiting for the target to bind the port";
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

// TODO(claude): procfs detection is global (spec accepts that) but it also cannot notice that the target
//   already died: it polls the whole initial_ms even if the child exited. Consider a waitpid(WNOHANG) check
//   on the target pid inside the loop (needs target_pid passed in). It can also false-positive on a port that
//   is held by a stale/other process.
static DetectResult check_procfs(int target_port, uint64_t timeout_ms) {
    uint64_t start = utils::get_time_ms();
    while (utils::get_time_ms() - start < timeout_ms) {
        bool found = false;
        for (const char* path : {"/proc/net/tcp", "/proc/net/tcp6"}) {
            std::ifstream file(path);
            if (!file.is_open()) continue;
            
            std::string line;
            std::getline(file, line); // skip header
            while (std::getline(file, line)) {
                std::istringstream iss(line);
                std::string idx, local_addr, rem_addr, state;
                if (iss >> idx >> local_addr >> rem_addr >> state) {
                    if (state == "0A") { // TCP_LISTEN
                        size_t colon = local_addr.find(':');
                        if (colon != std::string::npos) {
                            std::string port_hex = local_addr.substr(colon + 1);
                            auto parsed = utils::parse_u16_strict(port_hex, 16);
                            if (std::holds_alternative<std::uint16_t>(parsed) &&
                                std::get<std::uint16_t>(parsed) == target_port) {
                                found = true;
                                break;
                            }
                        }
                    }
                }
            }
            if (found) break;
        }
        if (found) return std::monostate{};
        utils::sleep_ms(10);
    }
    return DetectError{DetectError::Kind::TimedOut, 0, 0};
}

static DetectResult trace_port(pid_t pid, int target_port, uint64_t timeout_ms, bool use_seccomp) {
    uint64_t start = utils::get_time_ms();
    int status;
    bool in_syscall = false;
    
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
        
        // TODO(claude): confusing condition `WIFSTOPPED(res == pid ? status : 0)`; res is always pid here
        //   (waitpid(pid, ...)). Just use WIFSTOPPED(status).
        if (WIFSTOPPED(res == pid ? status : 0)) { // waitpid returns pid on success
            int sig = WSTOPSIG(status);
            int event = (status >> 16);
            
            bool check_bind = false;
            
            if (use_seccomp) {
                if (event == PTRACE_EVENT_SECCOMP) {
                    check_bind = true;
                }
            } else {
                if (sig == (SIGTRAP | 0x80)) {
                    if (!in_syscall) {
                        check_bind = true;
                    }
                    in_syscall = !in_syscall;
                }
            }
            
            if (check_bind) {
                struct user_regs_struct regs;
                if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == 0) {
                    if (regs.orig_rax == __NR_bind) {
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
                                
                                if (port == 0) {
                                    PROXY_LOG_WARN("target requested ephemeral port (0), skipping...");
                                } else if (port == target_port) {
                                    // TODO(claude): two problems. (1) We are at bind() ENTRY: the target is
                                    //   declared "ready" before bind() succeeded and before listen() ran, so
                                    //   the first connect_target() can get ECONNREFUSED (race). Bind may
                                    //   even fail (EADDRINUSE). Consider also confirming via procfs/retrying
                                    //   connect within initial_ms.
                                    //   (2) In seccomp mode the BPF filter stays installed after DETACH (it
                                    //   cannot be removed) and is inherited by forked workers. With
                                    //   SECCOMP_RET_TRACE and NO tracer the kernel fails the syscall with
                                    //   ENOSYS, so any later bind() in the target (or its children, e.g.
                                    //   nginx workers/reload) will break. Also ptrace() return value is
                                    //   unchecked.
                                    ptrace(PTRACE_DETACH, pid, 0, 0);
                                    return std::monostate{};
                                }
                            }
                        }
                    }
                }
            }
            
            // TODO(claude): CRITICAL BUG for `primary: ptrace`: syscall-stops are only produced if the
            //   tracee is resumed with PTRACE_SYSCALL (spec 5.2 says so). Here (and in process.cpp after
            //   PTRACE_SETOPTIONS) PTRACE_CONT is always used, so in ptrace mode no bind() is ever seen and
            //   the loop just hangs in waitpid. Use PTRACE_SYSCALL when !use_seccomp.
            //   Also: group-stop / SIGSTOP signal-delivery-stops are re-injected with `sig` which can leave
            //   the tracee stopped; and the tracer sees only `pid` (no PTRACE_O_TRACEFORK), so forked
            //   children are not traced (fine for the master, but should be documented).
            if (sig != SIGTRAP && sig != (SIGTRAP | 0x80) && event == 0) {
                ptrace(PTRACE_CONT, pid, 0, sig);
            } else {
                ptrace(PTRACE_CONT, pid, 0, 0);
            }
        }
    }
    
    // TODO(claude): after a timeout the tracee is usually RUNNING (not in ptrace-stop), so PTRACE_DETACH
    //   fails with ESRCH and the child stays traced; the error is ignored. Also the timeout is only reached
    //   if waitpid above returned, see the blocking-waitpid TODO.
    // Timeout reached, detach before returning false
    ptrace(PTRACE_DETACH, pid, 0, 0);
    return DetectError{DetectError::Kind::TimedOut, 0, 0};
}

DetectResult wait_for_port(pid_t target_pid, const Config& cfg) {
    if (cfg.port_detection.primary == "procfs") {
        return check_procfs(cfg.network.port, cfg.network.initial_ms);
    } else if (cfg.port_detection.primary == "ptrace") {
        return trace_port(target_pid, cfg.network.port, cfg.network.initial_ms, false);
    } else if (cfg.port_detection.primary == "seccomp") {
        return trace_port(target_pid, cfg.network.port, cfg.network.initial_ms, true);
    }
    return DetectError{DetectError::Kind::UnknownMethod, 0, 0};
}

ConnectResult connect_target(const NetworkConfig& net_cfg) {
    // TODO(claude): (1) the socket is switched back to BLOCKING mode after connect, so send_all()'s timeout
    //   is not enforced: send() can block forever if the target stops reading (the EAGAIN/poll branch in
    //   send_all is dead code). Keep O_NONBLOCK or set SO_SNDTIMEO.
    //   (2) Thousands of iterations/s create thousands of TIME_WAIT sockets on the client side; consider
    //   SO_LINGER{1,0} (RST on close) to avoid ephemeral-port exhaustion. Also no TCP_NODELAY / SOCK_CLOEXEC.
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

    struct sockaddr_in addr;  // TODO(claude): not zero-initialised (sin_zero garbage); use `= {}`.
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
                if (poll_res == 0) return SendError{SendError::Kind::TimedOut, 0};
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
        if (poll_res == 0) continue; // poll timeout; the loop top re-checks the overall deadline

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

} // namespace network