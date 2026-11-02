// src/main.cpp

#include "common.hpp"
#include "handler.hpp"
#include "net.hpp"
#include "options.hpp"

#include <cerrno>
#include <csignal>
#include <cstring>
#include <string>
#include <vector>

#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

// --fork-bind-collision: bind the main port, then fork a child that closes
// the inherited listener fd, reuses the number for a socket bound to a
// different port, and only then let the parent listen(). This reproduces the
// cross-process fd-number collision that seccomp port detection must survive:
// with a bare fd-keyed map the child's bind overwrites the parent's entry and
// detection misses the configured port. The pipe orders the child's bind()
// (and its notification) strictly before the parent's listen().
void fork_bind_collision(const testtarget::Options& opts, int main_fd) {
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        testtarget::fatal(std::string("fork-bind-collision pipe: ") + std::strerror(errno));
    }
    const pid_t pid = fork();
    if (pid < 0) {
        testtarget::fatal(std::string("fork-bind-collision fork: ") + std::strerror(errno));
    }
    if (pid == 0) {
        close(pipefd[0]);
        close(main_fd);
        const int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            _exit(1);
        }
        if (fd != main_fd) {
            if (dup2(fd, main_fd) < 0) {
                _exit(1);
            }
            close(fd);
        }
        testtarget::bind_socket(main_fd, opts.host, static_cast<uint16_t>(opts.port + 1),
                                "collision");
        const char ok = 1;
        (void)write(pipefd[1], &ok, 1);
        _exit(0);
    }
    close(pipefd[1]);
    char ok = 0;
    ssize_t r;
    do {
        r = read(pipefd[0], &ok, 1);
    } while (r < 0 && errno == EINTR);
    close(pipefd[0]);
    if (r != 1 || ok != 1) {
        testtarget::fatal("fork-bind-collision child failed to bind the reused fd");
    }
}

} // namespace

int main(int argc, char* argv[]) {
    const testtarget::Options opts = testtarget::parse_options(argc, argv);

    if (!opts.stdin_marker.empty()) {
        testtarget::consume_stdin_marker(opts.stdin_marker);
    }

    signal(SIGPIPE, SIG_IGN);
    if (opts.ignore_sigterm) {
        signal(SIGTERM, SIG_IGN);
    } else {
        struct sigaction action{};
        action.sa_handler = testtarget::request_stop;
        sigemptyset(&action.sa_mask);
        action.sa_flags = 0;  // no SA_RESTART: interrupt accept/recv
        sigaction(SIGTERM, &action, nullptr);
    }

    if (opts.startup_delay_ms > 0) {
        testtarget::sleep_ms(opts.startup_delay_ms);
    }
    if (testtarget::g_stop) {
        return 0;
    }

    if (!opts.request_log.empty()) {
        testtarget::open_request_log(opts.request_log);
    }

    std::vector<int> listeners;
    if (opts.bind_ephemeral_first) {
        listeners.push_back(testtarget::make_listener(opts.host, 0, "ephemeral"));
    }
    if (opts.bind_extra_port) {
        listeners.push_back(testtarget::make_listener(opts.host, static_cast<uint16_t>(opts.port + 1), "extra"));
    }
    const int main_fd = opts.fork_bind_collision
                            ? testtarget::make_bound_socket(opts.host, opts.port, "main")
                            : testtarget::make_listener(opts.host, opts.port, "main");
    if (opts.fork_bind_collision) {
        fork_bind_collision(opts, main_fd);
        testtarget::listen_on(main_fd, "main");
    }
    listeners.push_back(main_fd);
    if (opts.bind_extra_after) {
        listeners.push_back(testtarget::make_listener(opts.host, static_cast<uint16_t>(opts.port + 1), "extra-after"));
    }

    int lingering_fd = -1;
    while (!testtarget::g_stop) {
        const int conn = accept(main_fd, nullptr, nullptr);
        if (conn < 0) {
            if (errno == EINTR) {
                if (testtarget::g_stop) {
                    break;
                }
                continue;
            }
            testtarget::fatal(std::string("accept: ") + std::strerror(errno));
        }
        if (lingering_fd >= 0) {
            close(lingering_fd);
            lingering_fd = -1;
        }
        testtarget::handle_connection(conn, opts);
        if (opts.keep_alive) {
            lingering_fd = conn;
        } else {
            shutdown(conn, SHUT_WR);
            char drain[512];
            while (recv(conn, drain, sizeof(drain), 0) > 0) {
            }
            close(conn);
        }
    }
    return 0;
}
