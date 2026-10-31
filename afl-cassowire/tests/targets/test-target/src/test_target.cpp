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
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace {

constexpr size_t kMaxRequestBytes = 64 * 1024;
constexpr int kListenBacklog = 16;
constexpr int kRecvTimeoutMs = 500;
constexpr long kMaxSlowMs = 60000;

volatile sig_atomic_t g_stop = 0;

void request_stop(int) {
    g_stop = 1;
}

struct Options {
    std::string mode;
    std::string host;
    uint16_t port = 0;
    int startup_delay_ms = 0;
    bool bind_ephemeral_first = false;
    bool bind_extra_port = false;
    bool bind_extra_after = false;
    bool ignore_sigterm = false;
    bool keep_alive = false;
    bool with_crash = false;
    bool multi_request = false;
    std::string stdin_marker;   // empty: never touch stdin
    std::string request_log;    // empty: do not log received messages
};

// Optional request log (--log-requests): one "<n> <bytes>" line per received
// message, appended and flushed immediately so e2e tests can inspect how many
// messages the proxy actually delivered on the connection.
std::FILE* g_request_log = nullptr;

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

// Buffered framed-request reader: returns exactly one message per call and
// keeps any extra bytes (pipelined requests) for the next call. Used by
// --multi-request so a single recv that spans several messages is not lost.
class RequestReader {
public:
    RequestReader(int fd, bool stop_at_newline) : fd_(fd), stop_at_newline_(stop_at_newline) {}

    // Reads the next framed request into @p out. Returns false when the
    // connection is done (EOF/timeout/error) and no partial data is left.
    bool next(std::string& out) {
        out.clear();
        while (!g_stop) {
            const size_t frame = frame_end();
            if (frame != std::string::npos) {
                out = buffer_.substr(0, frame);
                buffer_.erase(0, frame);
                return true;
            }
            if (buffer_.size() >= kMaxRequestBytes) {
                // Unframed flood: hand the buffered bytes over as one message.
                out.swap(buffer_);
                return true;
            }
            char chunk[4096];
            const ssize_t received = recv(fd_, chunk, sizeof(chunk), 0);
            if (received > 0) {
                buffer_.append(chunk, static_cast<size_t>(received));
                continue;
            }
            if (received == 0) break;  // EOF
            if (errno == EINTR) continue;
            break;  // timeout (EAGAIN) or error: return whatever is buffered
        }
        if (buffer_.empty()) {
            return false;
        }
        out.swap(buffer_);
        return true;
    }

private:
    // Position just past the next frame terminator, or npos if not yet seen.
    size_t frame_end() const {
        if (stop_at_newline_) {
            const size_t pos = buffer_.find('\n');
            return pos == std::string::npos ? std::string::npos : pos + 1;
        }
        const size_t pos = buffer_.find("\r\n\r\n");
        return pos == std::string::npos ? std::string::npos : pos + 4;
    }

    int fd_;
    bool stop_at_newline_;
    std::string buffer_;
};

void log_request(size_t index, size_t bytes) {
    if (g_request_log == nullptr) {
        return;
    }
    std::fprintf(g_request_log, "%zu %zu\n", index, bytes);
    std::fflush(g_request_log);
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

// ---------------------------------------------------------------------------
// cache mode: a deliberately stateful HTTP-like server.
// The same request takes different paths depending on the server state (cold
// fill, warm hit, LRU eviction, periodic revalidation, admin unlock), which is
// exactly the coverage instability that AFL++ calibration marks as variable.
// All state transitions are deterministic given the request history, so the
// mode provides ground truth for instability-aware fuzzing experiments.
// ---------------------------------------------------------------------------

constexpr size_t kCacheCapacity = 4;

struct CacheEntry {
    std::string key;
    std::string body;
    uint64_t uses = 0;
    uint64_t stamp = 0;
    bool compressed = false;
};

std::vector<CacheEntry> g_cache;
uint64_t g_clock = 0;
uint64_t g_requests = 0;
uint64_t g_fills = 0;

__attribute__((noinline)) std::string cache_compress_body(const std::string& key) {
    std::string out;
    for (const unsigned char c : key) {
        if (c >= 'a' && c <= 'z') {
            out.push_back(static_cast<char>(c - 32));
        } else if (c >= '0' && c <= '9') {
            out.push_back('#');
        } else if (c == '/') {
            out.push_back('|');
        } else {
            out.push_back(static_cast<char>(c));
        }
    }
    return out;
}

__attribute__((noinline)) std::string cache_fill_body(const std::string& key, bool& compressed) {
    std::string body = "fill:";
    // Hit-count instability: the loop trip count depends on server history.
    const uint64_t rounds = (g_fills % 4) + 1;
    for (uint64_t i = 0; i < rounds; ++i) {
        body += std::to_string((g_fills + i) % 10);
        body += '.';
    }
    body += key;
    if (key.size() > 6 && key.find("/zip") != std::string::npos) {
        compressed = true;
        body = cache_compress_body(key);
    }
    return body;
}

__attribute__((noinline)) void cache_insert(const std::string& key, const std::string& body,
                                            bool compressed) {
    if (g_cache.size() >= kCacheCapacity) {
        size_t victim = 0;
        for (size_t i = 1; i < g_cache.size(); ++i) {
            if (g_cache[i].stamp < g_cache[victim].stamp) {
                victim = i;
            }
        }
        g_cache.erase(g_cache.begin() + static_cast<long>(victim));
    }
    CacheEntry entry;
    entry.key = key;
    entry.body = body;
    entry.compressed = compressed;
    entry.stamp = ++g_clock;
    g_cache.push_back(entry);
    ++g_fills;
}

__attribute__((noinline)) std::string cache_serve_hit(CacheEntry& entry) {
    ++entry.uses;
    entry.stamp = ++g_clock;
    std::string body = entry.body;
    if (entry.uses % 3 == 0) {
        body += "|revalidated";
        if (entry.compressed) {
            body += "|z";
        }
    }
    if (entry.uses % 5 == 0) {
        body += "|stale-check";
    }
    return body;
}

__attribute__((noinline)) std::string cache_admin(uint64_t fills) {
    std::string body = "admin:";
    if (fills >= 8) {
        body += "many";
    } else if (fills >= 4) {
        body += "some";
    } else {
        body += "few";
    }
    for (const auto& entry : g_cache) {
        body += "|" + std::to_string(entry.uses);
    }
    return body;
}

std::string cache_response(const std::string& raw) {
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
    if (method != "GET") {
        return "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    }

    ++g_requests;
    std::string body;
    std::string cache_status = "MISS";
    if (path == "/admin") {
        if (g_fills >= 3) {
            body = cache_admin(g_fills);
            cache_status = "ADMIN";
        } else {
            body = "forbidden";
            cache_status = "ADMIN-COLD";
        }
    } else {
        CacheEntry* found = nullptr;
        for (auto& entry : g_cache) {
            if (entry.key == path) {
                found = &entry;
                break;
            }
        }
        if (found != nullptr) {
            cache_status = "HIT";
            body = cache_serve_hit(*found);
        } else {
            bool compressed = false;
            body = cache_fill_body(path, compressed);
            cache_insert(path, body, compressed);
        }
    }

    return std::string("HTTP/1.1 200 OK\r\nContent-Length: ") +
        std::to_string(body.size()) + "\r\nX-Cache: " + cache_status +
        "\r\nConnection: close\r\n\r\n" + body;
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

void handle_message(int fd, const Options& opts, const std::string& data) {
    const std::string line = trim_end(data);
    if (line.empty()) {
        return;
    }
    // The CRASH/HANG/SLOW hooks exercise the proxy's fault handling. They are
    // disabled in cache mode, which is a coverage/instability experiment target
    // where slow or crashing inputs would only add measurement noise.
    if (opts.mode != "cache") {
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
    }
    if (opts.mode == "calc") {
        send_all(fd, calc_response(line, opts.with_crash));
    } else if (opts.mode == "cache") {
        send_all(fd, cache_response(data));
    } else {
        send_all(fd, http_response(data));
    }
}

void handle_connection(int fd, const Options& opts) {
    set_recv_timeout(fd);
    RequestReader reader(fd, opts.mode == "calc");
    std::string data;
    size_t index = 0;
    while (reader.next(data)) {
        ++index;
        log_request(index, data.size());
        handle_message(fd, opts, data);
        if (!opts.multi_request) {
            break;
        }
    }
}

// Reads one newline-terminated line from fd 0 (bounded, with a poll timeout)
// and requires it to equal @p expected. Used to prove that a specific file -
// typically a fifo wired by afl-cassowire's target.stdin_path - really is our
// stdin: a missing, late, or different first line aborts the target.
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

} // namespace

int main(int argc, char* argv[]) {
    const Options opts = parse_options(argc, argv);

    if (!opts.stdin_marker.empty()) {
        consume_stdin_marker(opts.stdin_marker);
    }

    signal(SIGPIPE, SIG_IGN);
    if (opts.ignore_sigterm) {
        signal(SIGTERM, SIG_IGN);
    } else {
        struct sigaction action{};
        action.sa_handler = request_stop;
        sigemptyset(&action.sa_mask);
        action.sa_flags = 0;  // no SA_RESTART: interrupt accept/recv
        sigaction(SIGTERM, &action, nullptr);
    }

    if (opts.startup_delay_ms > 0) {
        sleep_ms(opts.startup_delay_ms);
    }
    if (g_stop) {
        return 0;
    }

    if (!opts.request_log.empty()) {
        g_request_log = std::fopen(opts.request_log.c_str(), "a");
        if (g_request_log == nullptr) {
            fatal("--log-requests: cannot open '" + opts.request_log + "': " +
                  std::strerror(errno));
        }
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
    if (opts.bind_extra_after) {
        listeners.push_back(make_listener(opts.host, static_cast<uint16_t>(opts.port + 1), "extra-after"));
    }

    int lingering_fd = -1;
    while (!g_stop) {
        const int conn = accept(main_fd, nullptr, nullptr);
        if (conn < 0) {
            if (errno == EINTR) {
                if (g_stop) {
                    break;
                }
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
    return 0;
}
