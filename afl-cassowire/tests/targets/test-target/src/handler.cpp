// src/handler.cpp

#include "handler.hpp"

#include "calc_mode.hpp"
#include "cache_mode.hpp"
#include "common.hpp"
#include "http_mode.hpp"
#include "net.hpp"

#include <cstdlib>
#include <string>
#include <unistd.h>

namespace testtarget {

namespace {

constexpr long kMaxSlowMs = 60000;

// CmpLog canary (--cmplog-canary): one comparison per accepted connection,
// including the request-less connections afl-cassowire's post-response health
// probe opens (received bytes == 0). Real servers compare protocol tokens on
// every connection, so this mirrors a realistic probe-side comparison; the
// e2e coverage-window test uses it to check that probe-time comparisons are
// discarded. The volatile load keeps the compare instrumetable (never folded
// by the compiler) and the value is unreachable for a real request length.
[[gnu::noinline]] void cmplog_canary(size_t received_bytes) {
    volatile unsigned long long expected = 0x2a2a2a2a2a2a2a2aULL;
    if (received_bytes == expected) {
        abort();
    }
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

} // namespace

void handle_message(int fd, const Options& opts, const std::string& data) {
    const std::string line = trim_end(data);
    if (line.empty()) {
        return;
    }
    // The CRASH/HANG/SLOW hooks exercise the proxy's fault handling. They are
    // disabled in cache mode; its opt-in lottery crash is drawn on cache hits.
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
        send_all(fd, cache_response(data, opts.with_crash));
    } else {
        send_all(fd, http_response(data));
    }
}

void handle_connection(int fd, const Options& opts) {
    set_recv_timeout(fd);
    RequestReader reader(fd, opts.mode == "calc");
    std::string data;
    size_t index = 0;
    size_t received_bytes = 0;
    while (reader.next(data)) {
        ++index;
        received_bytes += data.size();
        log_request(index, data.size());
        handle_message(fd, opts, data);
        if (!opts.multi_request) {
            break;
        }
    }
    if (opts.cmplog_canary) {
        cmplog_canary(received_bytes);
    }
}

} // namespace testtarget
