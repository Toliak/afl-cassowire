// src/cache_mode.cpp

#include "cache_mode.hpp"

#include "http_mode.hpp"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace testtarget {

namespace {

// ---------------------------------------------------------------------------
// cache mode: a deliberately stateful HTTP-like server.
// The same request takes different paths depending on the server state (cold
// fill, warm hit, LRU eviction, periodic revalidation, admin unlock), which is
// exactly the coverage instability that AFL++ calibration marks as variable.
// All state transitions are deterministic given the request history, so the
// mode provides ground truth for instability-aware fuzzing experiments.
// ---------------------------------------------------------------------------

constexpr size_t kCacheCapacity = 4;
constexpr char kPrngPrefix[] = "/prng/";
constexpr size_t kPrngPrefixLen = sizeof(kPrngPrefix) - 1;
constexpr size_t kPrngTokenOffset = kPrngPrefixLen;
constexpr size_t kPrngTokenBytes = 8;
constexpr size_t kPrngSeedOffset = kPrngTokenOffset + kPrngTokenBytes + 1;
constexpr uint64_t kPrngGateToken = 0x3372317735356143ULL;
constexpr char kLotteryPrefix[] = "/lottery/";

struct CacheEntry {
    std::string key;
    std::string body;
    uint64_t uses = 0;
    uint64_t stamp = 0;
    bool compressed = false;
    bool lottery = false;
    uint64_t lottery_state = 0;
};

std::vector<CacheEntry> g_cache;
uint64_t g_clock = 0;
uint64_t g_requests = 0;
uint64_t g_fills = 0;

__attribute__((noinline)) uint64_t splitmix64(uint64_t& state) {
    state += 0x9E3779B97F4A7C15ULL;
    uint64_t value = state;
    value = (value ^ (value >> 30)) * 0xBF58476D1CE4E5B9ULL;
    value = (value ^ (value >> 27)) * 0x94D049BB133111EBULL;
    return value ^ (value >> 31);
}

__attribute__((noinline)) uint64_t cache_hash_seed(const std::string& seed) {
    uint64_t hash = 1469598103934665603ULL;
    for (const unsigned char byte : seed) {
        hash ^= byte;
        hash *= 1099511628211ULL;
    }
    return hash;
}

__attribute__((noinline)) bool cache_is_prng_path(const std::string& path) {
    return path.rfind(kPrngPrefix, 0) == 0;
}

__attribute__((noinline)) bool cache_prng_gate(const std::string& path, std::string& seed) {
    if (path.size() < kPrngSeedOffset || path[kPrngSeedOffset - 1] != '/') {
        return false;
    }
    uint64_t token = 0;
    std::memcpy(&token, path.data() + kPrngTokenOffset, kPrngTokenBytes);
    seed = path.substr(kPrngSeedOffset);
    return token == kPrngGateToken;
}

__attribute__((noinline)) std::string cache_prng_bucket0(uint64_t value) {
    return "prng:0:" + std::to_string(value % 97);
}

__attribute__((noinline)) std::string cache_prng_bucket1(uint64_t value) {
    return "prng:1:" + std::to_string(value % 89);
}

__attribute__((noinline)) std::string cache_prng_bucket2(uint64_t value) {
    return "prng:2:" + std::to_string(value % 83);
}

__attribute__((noinline)) std::string cache_prng_body(const std::string& seed) {
    uint64_t state = cache_hash_seed(seed);
    const uint64_t value = splitmix64(state);
    switch (value % 3) {
        case 0: return cache_prng_bucket0(value);
        case 1: return cache_prng_bucket1(value);
        default: return cache_prng_bucket2(value);
    }
}

__attribute__((noinline)) std::string cache_prng_reply(const std::string& seed) {
    const std::string body = cache_prng_body(seed);
    return std::string("HTTP/1.1 200 OK\r\nContent-Length: ") +
        std::to_string(body.size()) + "\r\nX-Cache: PRNG\r\nConnection: close\r\n\r\n" + body;
}

__attribute__((noinline)) std::string cache_gate_locked_reply() {
    const std::string body = "gate-locked";
    return std::string("HTTP/1.1 200 OK\r\nContent-Length: ") +
        std::to_string(body.size()) + "\r\nX-Cache: GATE\r\nConnection: close\r\n\r\n" + body;
}

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
                                            bool compressed, bool lottery, uint64_t lottery_state) {
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
    entry.lottery = lottery;
    entry.lottery_state = lottery_state;
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

__attribute__((noinline)) std::string cache_lottery_hit(CacheEntry& entry, bool with_crash) {
    ++entry.uses;
    entry.stamp = ++g_clock;
    const uint64_t value = splitmix64(entry.lottery_state);
    if ((value & 1ULL) == 0) {
        return "lottery:safe";
    }
    if (with_crash) {
        abort();
    }
    return "lottery:bang";
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

} // namespace

std::string cache_response(const std::string& raw, bool with_crash) {
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

    if (cache_is_prng_path(path)) {
        std::string seed;
        if (cache_prng_gate(path, seed)) {
            return cache_prng_reply(seed);
        }
        return cache_gate_locked_reply();
    }

    const bool lottery = path.rfind(kLotteryPrefix, 0) == 0;
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
            if (lottery && found->lottery) {
                cache_status = "LOTTERY-HIT";
                body = cache_lottery_hit(*found, with_crash);
            } else {
                cache_status = "HIT";
                body = cache_serve_hit(*found);
            }
        } else {
            bool compressed = false;
            body = cache_fill_body(path, compressed);
            cache_insert(path, body, compressed, lottery,
                         lottery ? cache_hash_seed(path) : 0);
            if (lottery) {
                cache_status = "LOTTERY-MISS";
            }
        }
    }

    return std::string("HTTP/1.1 200 OK\r\nContent-Length: ") +
        std::to_string(body.size()) + "\r\nX-Cache: " + cache_status +
        "\r\nConnection: close\r\n\r\n" + body;
}

} // namespace testtarget
