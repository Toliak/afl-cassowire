// src/common.cpp

#include "common.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <poll.h>
#include <unistd.h>

namespace testtarget {

volatile sig_atomic_t g_stop = 0;

void request_stop(int) {
    g_stop = 1;
}

namespace {

// Optional request log (--log-requests): one "<n> <bytes>" line per received
// message, appended and flushed immediately so e2e tests can inspect how many
// messages the proxy actually delivered on the connection.
std::FILE* g_request_log = nullptr;

} // namespace

[[noreturn]] void fatal(const std::string& message) {
    std::fprintf(stderr, "test-target: %s\n", message.c_str());
    std::exit(1);
}

void sleep_ms(long ms) {
    while (ms > 0 && !g_stop) {
        timespec request{};
        request.tv_sec = ms / 1000;
        request.tv_nsec = (ms % 1000) * 1000000L;
        timespec remain{};
        if (nanosleep(&request, &remain) == 0) {
            break;
        }
        if (errno != EINTR || g_stop) {
            break;
        }
        ms = remain.tv_sec * 1000 + remain.tv_nsec / 1000000;
    }
}

void open_request_log(const std::string& path) {
    g_request_log = std::fopen(path.c_str(), "a");
    if (g_request_log == nullptr) {
        fatal("--log-requests: cannot open '" + path + "': " + std::strerror(errno));
    }
}

void log_request(size_t index, size_t bytes) {
    if (g_request_log == nullptr) {
        return;
    }
    std::fprintf(g_request_log, "%zu %zu\n", index, bytes);
    std::fflush(g_request_log);
}

std::string trim_end(std::string text) {
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) {
        text.pop_back();
    }
    return text;
}

void consume_stdin_marker(const std::string& expected) {
    constexpr int kStdinWaitMs = 10000;
    std::string line;
    char buffer[1];
    while (line.size() < kMaxRequestBytes) {
        pollfd pfd{STDIN_FILENO, POLLIN, 0};
        const int ready = poll(&pfd, 1, kStdinWaitMs);
        if (ready <= 0) {
            fatal("stdin marker: no data on stdin within " + std::to_string(kStdinWaitMs) + " ms");
        }
        const ssize_t received = read(STDIN_FILENO, buffer, 1);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            fatal(std::string("stdin marker read: ") + std::strerror(errno));
        }
        if (received == 0 || buffer[0] == '\n') {
            break;
        }
        line.push_back(buffer[0]);
    }
    if (line != expected) {
        fatal("stdin marker mismatch: expected '" + expected + "', got '" + line + "'");
    }
}

} // namespace testtarget
