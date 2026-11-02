// src/net.cpp

#include "net.hpp"

#include "common.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace testtarget {

namespace {

constexpr int kListenBacklog = 16;
constexpr int kRecvTimeoutMs = 500;

} // namespace

void bind_socket(int fd, const std::string& host, uint16_t port, const char* label) {
    const int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        fatal("invalid bind address '" + host + "'");
    }
    if (bind(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) < 0) {
        fatal(std::string(label) + " bind(" + host + ":" + std::to_string(port) + "): " +
              std::strerror(errno));
    }
}

int make_bound_socket(const std::string& host, uint16_t port, const char* label) {
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        fatal(std::string(label) + " socket: " + std::strerror(errno));
    }
    bind_socket(fd, host, port, label);
    return fd;
}

void listen_on(int fd, const char* label) {
    if (listen(fd, kListenBacklog) < 0) {
        fatal(std::string(label) + " listen: " + std::strerror(errno));
    }
}

int make_listener(const std::string& host, uint16_t port, const char* label) {
    const int fd = make_bound_socket(host, port, label);
    listen_on(fd, label);
    return fd;
}

void set_recv_timeout(int fd) {
    timeval tv{};
    tv.tv_sec = kRecvTimeoutMs / 1000;
    tv.tv_usec = (kRecvTimeoutMs % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

bool send_all(int fd, const std::string& data) {
    size_t offset = 0;
    while (offset < data.size()) {
        const ssize_t sent = send(fd, data.data() + offset, data.size() - offset, MSG_NOSIGNAL);
        if (sent > 0) {
            offset += static_cast<size_t>(sent);
        } else if (sent < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

} // namespace testtarget
