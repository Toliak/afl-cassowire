// src/network.hpp

#pragma once

#include "config.hpp"
#include "utils.hpp"
#include <sys/types.h>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace network {

    /**
     * @brief Reason why wait_for_port() did not observe the configured port.
     */
    struct DetectError {
        enum class Kind {
            TimedOut,      ///< initial_ms elapsed without seeing the configured port bound
            TargetDied,    ///< target exited or was signalled during startup (wait_status holds the waitpid status)
            WaitpidFailed, ///< waitpid() failed (sys_errno holds errno)
            UnknownMethod, ///< port_detection.primary is not a known method
        };

        Kind kind;
        int sys_errno;    ///< errno for WaitpidFailed, 0 otherwise
        int wait_status;  ///< raw waitpid status for TargetDied, 0 otherwise

        /// @brief Human-readable description (decodes exit codes / signals).
        std::string to_string() const;
    };

    /**
     * @brief Result of wait_for_port(): success (monostate) or a DetectError.
     */
    using DetectResult = std::variant<std::monostate, DetectError>;

    /**
     * @brief Waits for the target process to bind to the configured port.
     * Uses the method specified in port_detection.primary (procfs, ptrace, seccomp).
     *
     * @param target_pid The PID of the target process.
     * @param cfg The global configuration.
     * @return DetectResult Success if the port was successfully detected within
     *         initial_ms, otherwise a DetectError explaining what happened.
     */
    [[nodiscard]] DetectResult wait_for_port(pid_t target_pid, const Config& cfg);

    /**
     * @brief Reason why connect_target() could not establish a connection.
     */
    struct ConnectError {
        enum class Kind {
            SocketCreate,   ///< socket() syscall failed (sys_errno holds errno)
            FcntlSetup,     ///< fcntl(F_GETFL) failed while enabling non-blocking mode (sys_errno holds errno)
            InvalidHost,    ///< inet_pton() rejected the host (not an IPv4 dotted-quad address)
            ConnectFailed,  ///< connect() failed immediately (sys_errno holds errno)
            TimedOut,       ///< poll() timed out waiting for the connection to complete
            PollFailed,     ///< poll() returned an error (sys_errno holds errno)
            SocketError,    ///< SO_ERROR was non-zero after poll (sys_errno holds the socket error)
        };

        Kind kind;
        int sys_errno;  ///< errno at the failure point, 0 if not applicable

        /// @brief Human-readable description (strerror-based where applicable).
        std::string to_string() const;
    };

    /**
     * @brief Result of connect_target(): the connected socket wrapped in an
     *        owning utils::FdGuard on success, or a ConnectError otherwise.
     *        The descriptor is closed when the guard is destroyed or reset.
     */
    using ConnectResult = std::variant<utils::FdGuard, ConnectError>;

    /**
     * @brief Connects to the target application via TCP.
     *
     * @param net_cfg The network configuration.
     * @return ConnectResult The connected socket (switched back to blocking
     *         mode) owned by a utils::FdGuard, or a ConnectError describing
     *         the failure.
     */
    [[nodiscard]] ConnectResult connect_target(const NetworkConfig& net_cfg);

    /**
     * @brief Reason why send_all() did not transmit the whole buffer.
     */
    struct SendError {
        enum class Kind {
            TimedOut,   ///< timeout_ms elapsed before the whole buffer was written
            SendFailed, ///< send() failed (sys_errno holds errno)
            PollFailed, ///< poll() failed while waiting for writability (sys_errno holds errno)
        };

        Kind kind;
        int sys_errno;  ///< errno at the failure point, 0 if not applicable

        /// @brief Human-readable description (strerror-based where applicable).
        std::string to_string() const;
    };

    /**
     * @brief Result of send_all(): success (monostate) or a SendError.
     */
    using SendResult = std::variant<std::monostate, SendError>;

    /**
     * @brief Sends the entire buffer to the socket, handling partial sends and timeouts.
     *
     * @param sock The socket file descriptor.
     * @param buf The data to send.
     * @param len The length of the data.
     * @param timeout_ms The timeout in milliseconds.
     * @return SendResult Success if all data was sent, otherwise a SendError
     *         describing the failure or timeout.
     */
    [[nodiscard]] SendResult send_all(int sock, const uint8_t* buf, size_t len, int timeout_ms);

    /**
     * @brief Reason why wait_response() stopped reading without any data.
     */
    struct WaitError {
        enum class Kind {
            TimedOut,   ///< timeout_ms elapsed without receiving any data
            PollFailed, ///< poll() failed (sys_errno holds errno)
            RecvFailed, ///< recv() failed (sys_errno holds errno)
        };

        Kind kind;
        int sys_errno;  ///< errno at the failure point, 0 if not applicable

        /// @brief Human-readable description (strerror-based where applicable).
        std::string to_string() const;
    };

    /**
     * @brief Result of wait_response(): the bytes received until EOF or timeout
     *        (possibly a partial response), or a WaitError.
     */
    using WaitResult = std::variant<std::vector<uint8_t>, WaitError>;

    /**
     * @brief Reads from the socket until EOF or timeout.
     *
     * Returns the accumulated bytes when the peer closes the connection, or
     * when a timeout fires after at least some data was received (a partial
     * response is still data). A timeout with no data at all, a poll() failure
     * or a recv() failure is a WaitError. EINTR on poll()/recv() is retried.
     *
     * @param sock The socket file descriptor.
     * @param timeout_ms The timeout in milliseconds.
     * @return WaitResult The received bytes, or a WaitError describing the failure.
     */
    [[nodiscard]] WaitResult wait_response(int sock, int timeout_ms);

} // namespace network