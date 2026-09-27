// src/network.cpp

#include "network.hpp"
#include "utils.hpp"

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
        pid_t res = waitpid(pid, &status, __WALL);
        if (res == -1) {
            if (errno == EINTR) continue;
            return false;
        }
        
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            return false;
        }
        
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
                        
                        if (addrlen > 0 && addrlen <= sizeof(struct sockaddr_storage)) {
                            struct sockaddr_storage addr;
                            struct iovec local_iov = { &addr, sizeof(addr) };
                            struct iovec remote_iov = { (void*)addr_ptr, addrlen };
                            
                            if (process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0) == (ssize_t)addrlen) {
                                int port = 0;
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
                                    ptrace(PTRACE_DETACH, pid, 0, 0);
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
            
            if (sig != SIGTRAP && sig != (SIGTRAP | 0x80) && event == 0) {
                ptrace(PTRACE_CONT, pid, 0, sig);
            } else {
                ptrace(PTRACE_CONT, pid, 0, 0);
            }
        }
    }
    
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
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr;
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

void wait_response(int sock, int timeout_ms) {
    uint8_t buf[4096];
    uint64_t start = utils::get_time_ms();
    
    while (true) {
        if (utils::get_time_ms() - start > (uint64_t)timeout_ms) break;
        
        struct pollfd pfd;
        pfd.fd = sock;
        pfd.events = POLLIN;
        int remaining = timeout_ms - (int)(utils::get_time_ms() - start);
        if (remaining <= 0) break;
        
        int poll_res = poll(&pfd, 1, remaining);
        if (poll_res <= 0) break;
        
        ssize_t n = recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) break;
        
        // Print response to console as per spec for test mode
        write(STDOUT_FILENO, buf, n);
    }
}

} // namespace network