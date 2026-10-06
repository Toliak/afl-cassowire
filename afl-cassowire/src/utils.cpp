// src/utils.cpp

#include "utils.hpp"
#include <ctime>
#include <csignal>
#include <cstdlib>
#include <unistd.h>
#include <errno.h>

namespace utils {

uint64_t get_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)(ts.tv_sec) * 1000ULL + (uint64_t)(ts.tv_nsec) / 1000000ULL;
}

void sleep_ms(int ms) {
    if (ms <= 0) return;
    struct timespec req;
    req.tv_sec = ms / 1000;
    req.tv_nsec = (ms % 1000) * 1000000L;
    
    // Handle potential interruptions by nanosleep
    while (nanosleep(&req, &req) == -1 && errno == EINTR) {
        // Continue sleeping the remaining time
    }
}

// TODO(claude): crash_proxy() is never used: main.cpp calls raise(SIGSEGV) directly (and then falls through
//   if the signal is blocked/ignored). Use this helper there. Also `_exit(139)` below is unreachable after abort().
[[noreturn]] void crash_proxy() {
    raise(SIGSEGV);
    // Fallback in case SIGSEGV is somehow blocked, ignored, or caught
    abort();
    _exit(139); // 139 is the standard exit code for segmentation fault
}

} // namespace utils