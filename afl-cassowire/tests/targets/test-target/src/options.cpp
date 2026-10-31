// src/options.cpp

#include "options.hpp"

#include "common.hpp"

#include <argparse/argparse.hpp>

#include <cstdio>
#include <cstdlib>
#include <string>

namespace testtarget {

Options parse_options(int argc, char* argv[]) {
    argparse::ArgumentParser program("test-target", "1.0");
    program.add_description("AFL++ test target: raw TCP calculator or minimal HTTP server.");

    program.add_argument("mode")
        .help("server mode: calc (default), http or cache (stateful HTTP-like server)")
        .default_value(std::string("calc"));

    program.add_argument("--host")
        .help("bind address")
        .default_value(std::string("127.0.0.1"));

    program.add_argument("--port")
        .help("bind port")
        .default_value(8080)
        .scan<'i', int>();

    program.add_argument("--startup-delay-ms")
        .help("sleep before binding any socket (slow start)")
        .default_value(0)
        .scan<'i', int>();

    program.add_argument("--bind-ephemeral-first")
        .help("bind an ephemeral (port 0) socket before the configured port")
        .default_value(false)
        .implicit_value(true);

    program.add_argument("--bind-extra-port")
        .help("bind port+1 before the configured port")
        .default_value(false)
        .implicit_value(true);

    program.add_argument("--bind-extra-after")
        .help("bind port+1 after the configured port (startup notifications "
              "queued behind the detected one, as e.g. nginx's TLS/QUIC "
              "listeners land after its main HTTP port)")
        .default_value(false)
        .implicit_value(true);

    program.add_argument("--ignore-sigterm")
        .help("ignore SIGTERM so cleanup must escalate to SIGKILL")
        .default_value(false)
        .implicit_value(true);

    program.add_argument("--keep-alive")
        .help("keep the connection open after responding (forces a recv timeout)")
        .default_value(false)
        .implicit_value(true);

    program.add_argument("--with-crash")
        .help("inject crash")
        .default_value(false)
        .implicit_value(true);

    program.add_argument("--multi-request")
        .help("keep handling framed requests on the same connection until EOF: "
              "calc frames on '\\n', http on CRLFCRLF; one response per request "
              "(exercises afl-cassowire sequence mode)")
        .default_value(false)
        .implicit_value(true);

    program.add_argument("--log-requests")
        .help("append one '<n> <bytes>' line per received message to this file "
              "(lets e2e tests verify how many messages arrived)")
        .default_value(std::string(""));

    program.add_argument("--stdin-marker")
        .help("read one newline-terminated line from stdin before binding and "
              "require it to equal this string (exercises fd-0 wiring, e.g. a "
              "fifo passed by afl-cassowire's target.stdin_path)")
        .default_value(std::string(""));

    try {
        program.parse_args(argc, argv);
    } catch (const std::exception& err) {
        std::fprintf(stderr, "test-target: %s\n%s", err.what(), program.help().str().c_str());
        std::exit(2);
    }

    Options opts;
    opts.mode = program.get<std::string>("mode");
    if (opts.mode != "calc" && opts.mode != "http" && opts.mode != "cache") {
        fatal("invalid mode '" + opts.mode + "': expected 'calc', 'http' or 'cache'");
    }
    opts.host = program.get<std::string>("--host");

    const int port = program.get<int>("--port");
    if (port < 1 || port > 65535) {
        fatal("invalid --port " + std::to_string(port) + ": expected 1-65535");
    }
    opts.port = static_cast<uint16_t>(port);

    opts.startup_delay_ms = program.get<int>("--startup-delay-ms");
    if (opts.startup_delay_ms < 0) {
        fatal("invalid --startup-delay-ms: expected >= 0");
    }
    opts.bind_ephemeral_first = program.get<bool>("--bind-ephemeral-first");
    opts.bind_extra_port = program.get<bool>("--bind-extra-port");
    opts.bind_extra_after = program.get<bool>("--bind-extra-after");
    if ((opts.bind_extra_port || opts.bind_extra_after) && opts.port == 65535) {
        fatal("--bind-extra-port/--bind-extra-after require --port < 65535");
    }
    opts.ignore_sigterm = program.get<bool>("--ignore-sigterm");
    opts.keep_alive = program.get<bool>("--keep-alive");
    opts.with_crash = program.get<bool>("--with-crash");
    opts.multi_request = program.get<bool>("--multi-request");
    opts.request_log = program.get<std::string>("--log-requests");
    opts.stdin_marker = program.get<std::string>("--stdin-marker");
    return opts;
}

} // namespace testtarget
