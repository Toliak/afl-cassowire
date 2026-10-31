// src/common.hpp

#pragma once

#include <csignal>
#include <cstddef>
#include <string>

namespace testtarget {

/// Largest single message ever accepted (request frames and the stdin marker
/// read); unframed floods above this are handed over as one message.
constexpr size_t kMaxRequestBytes = 64 * 1024;

/// Set by the SIGTERM handler; every poll/sleep/accept loop checks it so
/// shutdown never depends on SA_RESTART.
extern volatile sig_atomic_t g_stop;

/// SIGTERM handler: sets g_stop.
void request_stop(int);

/// Prints "test-target: <message>" to stderr and exits with status 1.
[[noreturn]] void fatal(const std::string& message);

/// Interruptible nanosleep loop: returns early once g_stop is set.
void sleep_ms(long ms);

/// Opens the --log-requests file for appending; fatal() on failure.
void open_request_log(const std::string& path);

/// Appends one "<n> <bytes>" line per received message (no-op when the log
/// is not open), flushed immediately so e2e tests can inspect how many
/// messages the proxy actually delivered on the connection.
void log_request(size_t index, size_t bytes);

/// Strips trailing '\n' and '\r' characters.
std::string trim_end(std::string text);

/// Reads one newline-terminated line from fd 0 (bounded, with a poll timeout)
/// and requires it to equal @p expected. Used to prove that a specific file -
/// typically a fifo wired by afl-cassowire's target.stdin_path - really is our
/// stdin: a missing, late, or different first line aborts the target.
void consume_stdin_marker(const std::string& expected);

} // namespace testtarget
