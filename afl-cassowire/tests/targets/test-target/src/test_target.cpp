#include <argparse/argparse.hpp>

#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cstdint>
#include <string>
#include <vector>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace {

constexpr size_t kMaxRequestBytes = 64 * 1024;
constexpr int kListenBacklog = 16;
constexpr int kRecvTimeoutMs = 500;
constexpr long kMaxSlowMs = 60000;

struct Options {
    std::string mode;
    std::string host;
    uint16_t port = 0;
    int startup_delay_ms = 0;
    bool bind_ephemeral_first = false;
    bool bind_extra_port = false;
    bool ignore_sigterm = false;
    bool keep_alive = false;
    bool with_crash = false;
};

[[noreturn]] void fatal(const std::string& message) {
    std::fprintf(stderr, "test-target: %s\n", message.c_str());
    std::exit(1);
}

void sleep_ms(long ms) {
    while (ms > 0) {
        timespec request{};
        request.tv_sec = ms / 1000;
        request.tv_nsec = (ms % 1000) * 1000000L;
        timespec remain{};
        if (nanosleep(&request, &remain) == 0) {
            break;
        }
        if (errno != EINTR) {
            break;
        }
        ms = remain.tv_sec * 1000 + remain.tv_nsec / 1000000;
    }
}

Options parse_options(int argc, char* argv[]) {
    argparse::ArgumentParser program("test-target", "1.0");
    program.add_description("AFL++ test target: raw TCP calculator or minimal HTTP server.");

    program.add_argument("mode")
        .help("server mode: calc (default) or http")
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

    try {
        program.parse_args(argc, argv);
    } catch (const std::exception& err) {
        std::fprintf(stderr, "test-target: %s\n%s", err.what(), program.help().str().c_str());
        std::exit(2);
    }

    Options opts;
    opts.mode = program.get<std::string>("mode");
    if (opts.mode != "calc" && opts.mode != "http") {
        fatal("invalid mode '" + opts.mode + "': expected 'calc' or 'http'");
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
    if (opts.bind_extra_port && opts.port == 65535) {
        fatal("--bind-extra-port requires --port < 65535");
    }
    opts.bind_ephemeral_first = program.get<bool>("--bind-ephemeral-first");
    opts.bind_extra_port = program.get<bool>("--bind-extra-port");
    opts.ignore_sigterm = program.get<bool>("--ignore-sigterm");
    opts.keep_alive = program.get<bool>("--keep-alive");
    opts.with_crash = program.get<bool>("--with-crash");
    return opts;
}

int make_listener(const std::string& host, uint16_t port, const char* label) {
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        fatal(std::string(label) + " socket: " + std::strerror(errno));
    }
    const int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        close(fd);
        fatal("invalid bind address '" + host + "'");
    }
    if (bind(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) < 0) {
        const std::string reason = std::strerror(errno);
        close(fd);
        fatal(std::string(label) + " bind(" + host + ":" + std::to_string(port) + "): " + reason);
    }
    if (listen(fd, kListenBacklog) < 0) {
        const std::string reason = std::strerror(errno);
        close(fd);
        fatal(std::string(label) + " listen: " + reason);
    }
    return fd;
}

void set_recv_timeout(int fd) {
    timeval tv{};
    tv.tv_sec = kRecvTimeoutMs / 1000;
    tv.tv_usec = (kRecvTimeoutMs % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

bool request_complete(const std::string& data, bool stop_at_newline) {
    if (stop_at_newline) {
        return data.find('\n') != std::string::npos;
    }
    return data.find("\r\n\r\n") != std::string::npos;
}

std::string read_request(int fd, bool stop_at_newline) {
    std::string data;
    char buffer[4096];
    for (;;) {
        const ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
        if (received > 0) {
            data.append(buffer, static_cast<size_t>(received));
            if (request_complete(data, stop_at_newline) || data.size() >= kMaxRequestBytes) {
                break;
            }
        } else if (received == 0) {
            break;
        } else if (errno != EINTR) {
            break;
        }
    }
    return data;
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

std::string trim_end(std::string text) {
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) {
        text.pop_back();
    }
    return text;
}

unsigned long long parse_number(const std::string& text, size_t& index, bool& ok) {
    const size_t start = index;
    unsigned long long value = 0;
    while (index < text.size() && text[index] >= '0' && text[index] <= '9') {
        value = value * 10ULL + static_cast<unsigned long long>(text[index] - '0');
        ++index;
    }
    ok = index > start;
    return value;
}

volatile int *ptr;

std::string calc_response(const std::string& line, const bool with_crash) {
    size_t index = 0;
    auto skip_spaces = [&index, &line] {
        while (index < line.size() && (line[index] == ' ' || line[index] == '\t')) {
            ++index;
        }
    };
    skip_spaces();
    bool ok = false;
    const unsigned long long lhs = parse_number(line, index, ok);
    if (!ok) {
        return "ERR\n";
    }
    skip_spaces();
    if (index >= line.size()) {
        return "ERR\n";
    }
    const char op = line[index++];
    if (op != '+' && op != '-' && op != '*' && op != '/') {
        return "ERR\n";
    }
    skip_spaces();
    const unsigned long long rhs = parse_number(line, index, ok);
    if (!ok) {
        return "ERR\n";
    }
    skip_spaces();
    if (index != line.size()) {
        return "ERR\n";
    }
    if (op == '/' && rhs == 0) {
        return "ERR\n";
    }
    unsigned long long result = 0;
    switch (op) {
        case '+': result = lhs + rhs; break;
        case '-': result = lhs - rhs; break;
        case '*': result = lhs * rhs; break;
        default: result = lhs / rhs; break;
    }
    // <BEGIN> Simulated crash (random numbers + operator)
    if (with_crash && lhs == 115 && 115 > rhs && rhs > 100 && op == '*' ) {
        ptr = 0x0uL;  // Point to nothing
        *ptr = 42;        // CRASH: Trying to write to address 0
    }
    // <END> Simulated crash
    return std::to_string(result) + "\n";
}

const char* http_bad_request() {
    return "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
}

std::string http_response(const std::string& raw) {
    size_t line_end = raw.find('\n');
    if (line_end == std::string::npos) {
        line_end = raw.size();
    }
    std::string first = raw.substr(0, line_end);
    while (!first.empty() && (first.back() == '\r' || first.back() == ' ')) {
        first.pop_back();
    }

    const size_t method_end = first.find(' ');
    if (method_end == std::string::npos) {
        return http_bad_request();
    }
    const std::string method = first.substr(0, method_end);
    const std::string rest = first.substr(method_end + 1);
    const size_t path_end = rest.find(' ');
    const std::string path = path_end == std::string::npos ? rest : rest.substr(0, path_end);
    if (path.empty()) {
        return http_bad_request();
    }

    const char* status = "200 OK";
    const char* body = "OK";
    if (method != "GET") {
        status = "405 Method Not Allowed";
        body = "";
    } else if (path != "/") {
        status = "404 Not Found";
        body = "";
    }
    return std::string("HTTP/1.1 ") + status + "\r\nContent-Length: " +
        std::to_string(std::strlen(body)) + "\r\nConnection: close\r\n\r\n" + body;
}

bool parse_slow_ms(const std::string& line, long& out_ms) {
    size_t index = 5;
    unsigned long long value = 0;
    bool any = false;
    while (index < line.size() && line[index] >= '0' && line[index] <= '9') {
        if (value <= static_cast<unsigned long long>(kMaxSlowMs)) {
            value = value * 10ULL + static_cast<unsigned long long>(line[index] - '0');
        }
        ++index;
        any = true;
    }
    if (!any || index != line.size()) {
        return false;
    }
    out_ms = value > static_cast<unsigned long long>(kMaxSlowMs) ? kMaxSlowMs
                                                                 : static_cast<long>(value);
    return true;
}

void handle_connection(int fd, const Options& opts) {
    set_recv_timeout(fd);
    const std::string data = read_request(fd, opts.mode == "calc");
    const std::string line = trim_end(data);
    if (line.empty()) {
        return;
    }
    if (line == "CRASH") {
        abort();
    }
    if (line == "HANG") {
        pause();
    }
    if (line.rfind("SLOW ", 0) == 0) {
        long ms = 0;
        if (parse_slow_ms(line, ms)) {
            sleep_ms(ms);
            if (opts.mode == "calc") {
                send_all(fd, "OK\n");
            } else {
                send_all(fd, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");
            }
            return;
        }
    }
    if (opts.mode == "calc") {
        send_all(fd, calc_response(line, opts.with_crash));
    } else {
        send_all(fd, http_response(data));
    }
}

} // namespace

int main(int argc, char* argv[]) {
    const Options opts = parse_options(argc, argv);

    signal(SIGPIPE, SIG_IGN);
    if (opts.ignore_sigterm) {
        signal(SIGTERM, SIG_IGN);
    }

    if (opts.startup_delay_ms > 0) {
        sleep_ms(opts.startup_delay_ms);
    }

    std::vector<int> listeners;
    if (opts.bind_ephemeral_first) {
        listeners.push_back(make_listener(opts.host, 0, "ephemeral"));
    }
    if (opts.bind_extra_port) {
        listeners.push_back(make_listener(opts.host, static_cast<uint16_t>(opts.port + 1), "extra"));
    }
    const int main_fd = make_listener(opts.host, opts.port, "main");
    listeners.push_back(main_fd);

    int lingering_fd = -1;
    for (;;) {
        const int conn = accept(main_fd, nullptr, nullptr);
        if (conn < 0) {
            if (errno == EINTR) {
                continue;
            }
            fatal(std::string("accept: ") + std::strerror(errno));
        }
        if (lingering_fd >= 0) {
            close(lingering_fd);
            lingering_fd = -1;
        }
        handle_connection(conn, opts);
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
}
