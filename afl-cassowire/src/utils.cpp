// src/utils.cpp

#include "utils.hpp"
#include <ctime>
#include <csignal>
#include <cstdlib>
#include <unistd.h>
#include <errno.h>
#include <charconv>
#include <cerrno>
#include <fcntl.h>
#include <sys/types.h>

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



namespace {

template <typename T>
std::variant<T, ParseError> parse_uint_impl(std::string_view s, int base) {
    T value = 0;
    const char* const end = s.data() + s.size();
    auto [ptr, ec] = std::from_chars(s.data(), end, value, base);

    if (ec != std::errc{})  return ParseError{ec};
    if (ptr != end)         return ParseError{CustomParseError::TrailingCharacters};
    return value;
}

} // namespace

[[nodiscard]] ParseResult parse_u64_strict(std::string_view s, int base) {
    return parse_uint_impl<std::uint64_t>(s, base);
}

[[nodiscard]] U8ParseResult parse_u8_strict(std::string_view s, int base) {
    return parse_uint_impl<std::uint8_t>(s, base);
}

[[nodiscard]] U16ParseResult parse_u16_strict(std::string_view s, int base) {
    return parse_uint_impl<std::uint16_t>(s, base);
}

[[nodiscard]] U32ParseResult parse_u32_strict(std::string_view s, int base) {
    return parse_uint_impl<std::uint32_t>(s, base);
}


ReadResult read_fd(int fd, size_t max_bytes) {
    std::vector<uint8_t> buffer;
    uint8_t chunk[4096];

    for (;;) {
        ssize_t n = ::read(fd, chunk, sizeof(chunk));
        if (n > 0) {
            if (buffer.size() + static_cast<size_t>(n) > max_bytes)
                return std::make_error_code(std::errc::file_too_large);
            buffer.insert(buffer.end(), chunk, chunk + n);
        } else if (n == 0) {
            break;
        } else {
            if (errno == EINTR) continue;
            return std::error_code(errno, std::system_category());
        }
    }
    return buffer;
}

ReadResult read_file(std::string_view path, size_t max_bytes) {
    if (path.find('\0') != std::string_view::npos)
        return std::make_error_code(std::errc::invalid_argument);

    int fd = ::open(std::string(path).c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return std::error_code(errno, std::system_category());

    FdGuard guard{fd};
    return read_fd(fd, max_bytes);
}

ReadResult read_stdin(size_t max_bytes) {
    return read_fd(STDIN_FILENO, max_bytes);
}

ReadResult read_input_file(std::string_view path, size_t max_bytes) {
    return (path == "-") ? read_stdin(max_bytes) : read_file(path, max_bytes);
}

} // namespace utils