// src/net.hpp

#pragma once

#include "common.hpp"

#include <cerrno>
#include <cstdint>
#include <string>
#include <sys/socket.h>

namespace testtarget {

/**
 * @brief Creates a listening TCP socket bound to @p host:@p port.
 *
 * SO_REUSEADDR is set; any failure is fatal(), labeled with @p label.
 */
int make_listener(const std::string& host, uint16_t port, const char* label);

/**
 * @brief Arms the fixed recv timeout on an accepted connection fd.
 */
void set_recv_timeout(int fd);

/**
 * @brief Sends the whole buffer; returns false on error (EINTR is retried).
 */
bool send_all(int fd, const std::string& data);

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

} // namespace testtarget
