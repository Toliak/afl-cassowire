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
    const int main_fd = testtarget::make_listener(opts.host, opts.port, "main");
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
