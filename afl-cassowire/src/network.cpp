// src/network.cpp

#include "network.hpp"
#include "utils.hpp"

#include <chrono>
#include <iostream>
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

// TODO(claude): procfs detection is global (spec accepts that) but it also cannot notice that the target
//   already died: it polls the whole initial_ms even if the child exited. Consider a waitpid(WNOHANG) check
//   on the target pid inside the loop (needs target_pid passed in). It can also false-positive on a port that
//   is held by a stale/other process.
static bool check_procfs(int target_port, uint64_t timeout_ms) {
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
                            try {
                                int port = std::stoi(port_hex, nullptr, 16);
                                if (port == target_port) {
                                    found = true;
                                    break;
                                }
                            } catch (...) {
                                // Ignore parsing errors
                            }
                        }
                    }
                }
            }
            if (found) break;
        }
        if (found) return true;
        utils::sleep_ms(10);
    }
    return false;
}

static bool trace_port(pid_t pid, int target_port, uint64_t timeout_ms, bool use_seccomp) {
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
            return false;
        }
        
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            // TODO(claude): silent failure - the target died during startup but nothing says so (exit code /
            //   signal is lost, and it is already reaped here so main.cpp's later waitpid will not see it).
            return false;
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
                                    std::cerr << "proxy: target requested ephemeral port (0), skipping...\n";
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
                                    return true;
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
    return false;
}

bool wait_for_port(pid_t target_pid, const Config& cfg) {
    if (cfg.port_detection.primary == "procfs") {
        return check_procfs(cfg.network.port, cfg.network.initial_ms);
    } else if (cfg.port_detection.primary == "ptrace") {
        return trace_port(target_pid, cfg.network.port, cfg.network.initial_ms, false);
    } else if (cfg.port_detection.primary == "seccomp") {
        return trace_port(target_pid, cfg.network.port, cfg.network.initial_ms, true);
    }
    return false;
}

int connect_target(const NetworkConfig& net_cfg) {
    // TODO(claude): (1) the socket is switched back to BLOCKING mode after connect, so send_all()'s timeout
    //   is not enforced: send() can block forever if the target stops reading (the EAGAIN/poll branch in
    //   send_all is dead code). Keep O_NONBLOCK or set SO_SNDTIMEO.
    //   (2) Thousands of iterations/s create thousands of TIME_WAIT sockets on the client side; consider
    //   SO_LINGER{1,0} (RST on close) to avoid ephemeral-port exhaustion. Also no TCP_NODELAY / SOCK_CLOEXEC.
    //   (3) Only AF_INET + inet_pton is supported; host "localhost"/IPv6 (accepted by config.cpp) fails.
    //   (4) poll() returning -1/EINTR is treated as a connect failure.
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr;  // TODO(claude): not zero-initialised (sin_zero garbage); use `= {}`.
    addr.sin_family = AF_INET;
    addr.sin_port = htons(net_cfg.port);
    if (inet_pton(AF_INET, net_cfg.host.c_str(), &addr.sin_addr) <= 0) {
        close(sock);
        return -1;
    }

    int res = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (res < 0 && errno != EINPROGRESS) {
        close(sock);
        return -1;
    }

    if (res == 0) {
        fcntl(sock, F_SETFL, flags);
        return sock;
    }

    struct pollfd pfd;
    pfd.fd = sock;
    pfd.events = POLLOUT;
    
    int poll_res = poll(&pfd, 1, net_cfg.timeout_ms);
    if (poll_res <= 0) {
        close(sock);
        return -1;
    }

    int err = 0;
    socklen_t len = sizeof(err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
    if (err != 0) {
        close(sock);
        return -1;
    }

    fcntl(sock, F_SETFL, flags);
    return sock;
}

bool send_all(int sock, const uint8_t* buf, size_t len, int timeout_ms) {
    // TODO(claude): `buf` may be nullptr/len 0 (placeholder AFL macros) - harmless here, but the callers in
    //   main.cpp ignore the return value, so a failed/partial send (target died) is silently dropped.
    size_t sent = 0;
    uint64_t start = utils::get_time_ms();
    
    while (sent < len) {
        if (utils::get_time_ms() - start > (uint64_t)timeout_ms) return false;
        
        ssize_t n = send(sock, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd;
                pfd.fd = sock;
                pfd.events = POLLOUT;
                int remaining = timeout_ms - (int)(utils::get_time_ms() - start);
                if (remaining <= 0) return false;
                if (poll(&pfd, 1, remaining) <= 0) return false;
                continue;
            }
            return false;
        }
        sent += n;
    }
    return true;
}

// TODO(claude): multiple problems in wait_response():
//   - Return value contradicts network.hpp: poll timeout / poll error / recv error all `break` and return
//     true; only the `remaining <= 0` paths return false. Callers cannot distinguish timeout vs EOF.
//   - Debug output on EVERY poll (std::cerr << system_clock::now()) and "buf len" on stdout in the fuzz hot
//     loop: heavy slowdown, and printing std::chrono::system_clock::time_point needs a very recent C++20
//     stdlib. Remove, or guard behind a verbose flag.
//   - Spec 6.2 requires the response to be printed in test mode, but the write() is commented out, so the
//     response is never shown; data should be returned to the caller.
//   - Reading "until EOF or timeout" against a keep-alive server (nginx) always burns the full timeout_ms
//     per iteration, capping throughput at 1000/timeout_ms exec/s (5/s with the default 200ms).
//   - recv() n < 0 with EINTR is treated as end of stream.
bool wait_response(int sock, int timeout_ms) {
    uint8_t buf[4096];
    uint64_t start = utils::get_time_ms();
    
    while (true) {
        if (utils::get_time_ms() - start > (uint64_t)timeout_ms) break;
        
        struct pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLIN;
        int remaining = timeout_ms - (int)(utils::get_time_ms() - start);
        if (remaining <= 0) return false;
        
        int poll_res = poll(&pfd, 1, remaining);
        std::cerr <<  std::chrono::system_clock::now() << " poll_res " << poll_res << "\n";
        if (poll_res <= 0) break;

        ssize_t n = recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) break;

        // Print response to console as per spec for test mode
        // write(STDOUT_FILENO, buf, n);
        std::cout << "buf len = " << n << "\n";
    }

    return true;
}

} // namespace network