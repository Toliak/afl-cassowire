// http_bench.cpp
//
// Build:
//   g++ -O2 -std=c++17 -Wall -Wextra -o http_bench http_bench.cpp
//
// Example:
//   ./http_bench --host 192.168.1.10 --port 8080 --cpu 2

#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <sched.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>

namespace {

volatile std::sig_atomic_t stop = 0;

void signal_handler(int)
{
    stop = 1;
}

struct Args {
    std::string host;
    std::string port;
    int cpu = 0;
};

void usage(const char* program)
{
    std::cerr
        << "Usage: " << program
        << " --host <ip> --port <port> [--cpu <cpu_id>]\n";
}

bool parse_args(int argc, char** argv, Args& args)
{
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--host") {
            if (++i >= argc)
                return false;
            args.host = argv[i];
        } else if (arg == "--port") {
            if (++i >= argc)
                return false;
            args.port = argv[i];
        } else if (arg == "--cpu") {
            if (++i >= argc)
                return false;

            char* end = nullptr;
            long cpu = std::strtol(argv[i], &end, 10);

            if (*argv[i] == '\0' || *end != '\0' || cpu < 0) {
                std::cerr << "Invalid CPU id: " << argv[i] << '\n';
                return false;
            }

            args.cpu = static_cast<int>(cpu);
        } else if (arg == "--help" || arg == "-h") {
            usage(argv[0]);
            std::exit(0);
        } else {
            std::cerr << "Unknown argument: " << arg << '\n';
            return false;
        }
    }

    if (args.host.empty() || args.port.empty())
        return false;

    return true;
}

bool pin_to_cpu(int cpu)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);

    if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0) {
        std::cerr << "sched_setaffinity(" << cpu << "): "
                  << std::strerror(errno) << '\n';
        return false;
    }

    return true;
}

int connect_to_server(const std::string& host, const std::string& port)
{
    struct addrinfo hints {};
    struct addrinfo* result = nullptr;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(host.c_str(), port.c_str(), &hints, &result);
    if (rc != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(rc) << '\n';
        return -1;
    }

    int fd = -1;

    for (struct addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1)
            continue;

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;

        close(fd);
        fd = -1;
    }

    freeaddrinfo(result);
    return fd;
}

bool send_all(int fd, const char* data, size_t length)
{
    size_t sent = 0;

    while (sent < length && !stop) {
        ssize_t n = send(fd, data + sent, length - sent, 0);

        if (n > 0) {
            sent += static_cast<size_t>(n);
            continue;
        }

        if (n < 0 && errno == EINTR)
            continue;

        return false;
    }

    return sent == length;
}

// Read and discard the entire HTTP response.
//
// This relies on the server providing either:
//   - Content-Length
//   - chunked transfer encoding
//   - connection close
//
// For a normal HTTP/1.1 response, Content-Length is the common case.
bool read_and_discard(int fd)
{
    char buffer[64 * 1024];

    while (!stop) {
        ssize_t n = recv(fd, buffer, sizeof(buffer), 0);

        if (n > 0)
            continue;

        if (n == 0)
            return true;

        if (errno == EINTR)
            continue;

        return false;
    }

    return false;
}

bool do_request(const Args& args, long long& request_us)
{
    static constexpr char request[] =
        "GET / HTTP/1.1\r\n"
        "Host: benchmark\r\n"
        "Connection: close\r\n"
        "\r\n";

    auto start = std::chrono::steady_clock::now();

    int fd = connect_to_server(args.host, args.port);
    if (fd < 0)
        return false;

    bool ok = send_all(fd, request, sizeof(request) - 1);

    if (ok)
        ok = read_and_discard(fd);

    close(fd);

    auto end = std::chrono::steady_clock::now();

    request_us =
        std::chrono::duration_cast<std::chrono::microseconds>(
            end - start
        ).count();

    return ok;
}

} // namespace

int main(int argc, char** argv)
{
    Args args;

    if (!parse_args(argc, argv, args)) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (!pin_to_cpu(args.cpu))
        return EXIT_FAILURE;

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    using clock = std::chrono::steady_clock;

    auto interval_start = clock::now();
    uint64_t requests = 0;
    long long last_request_us = 0;

    while (!stop) {
        long long request_us = 0;

        if (do_request(args, request_us)) {
            ++requests;
            last_request_us = request_us;
        }

        auto now = clock::now();
        auto elapsed =
            std::chrono::duration_cast<std::chrono::seconds>(
                now - interval_start
            );

        if (elapsed.count() >= 10) {
            double seconds =
                std::chrono::duration<double>(now - interval_start).count();

            double requests_per_second =
                static_cast<double>(requests) / seconds;

            std::cout
                << "Speed (requests/s): " << requests_per_second
                << "  Request time (usec): " << last_request_us
                << '\n';

            std::cout.flush();

            interval_start = now;
            requests = 0;
        }
    }

    std::cout << "Stopped.\n";
    return EXIT_SUCCESS;
}