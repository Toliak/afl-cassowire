// src/network.hpp

#pragma once

#include "config.hpp"
#include "utils.hpp"
#include <sys/types.h>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace network {

    /**
     * @brief Reason why wait_for_port() did not observe the configured port.
     */
    struct DetectError {
        enum class Kind {
            TimedOut,      ///< initial_ms elapsed without seeing the configured port bound and listened (procfs with verify_ownership: the port listened but was held by a non-target process)
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
     * @brief Waits for the target process to bind and listen on the configured port.
     * Uses the method specified in port_detection.primary (procfs, ptrace, seccomp).
     * The ptrace/seccomp methods declare readiness on a successful listen() exit on
     * the fd bound to the configured port (fd tracked from bind stops). In seccomp
     * mode the tracer does NOT detach on success (the seccomp filter is
     * unremovable): it stays attached and resumes every seccomp stop with
     * PTRACE_CONT so later bind()/listen() in the target execute normally
     * ("transparent tracer"; enable the pump with process::set_transparent_tracer()).
     *
     * The procfs method polls /proc/net/tcp{,6} for a LISTEN entry on the
     * configured port and additionally (port_detection.verify_ownership, default
     * true) requires the entry's socket inode to be held via a socket:[<inode>]
     * readlink in /proc/<pid>/fd of @p target_pid or one of its descendants
     * (process::collect_pid_tree), so a stale or foreign listener cannot
     * false-positive. A setuid-style target with an unreadable fd dir
     * (EACCES/EPERM) is accepted unverified with a WARN. Every poll pass also
     * checks waitpid(WNOHANG), so a target that dies during startup reports
     * TargetDied instead of a silent initial_ms stall (the zombie is reaped
     * here, like the ptrace/seccomp death path).
     *
     * @param target_pid The PID of the target process.
     * @param cfg The global configuration.
     * @param tracer_attached Optional out-param; set to true when the tracer was
     *        left attached to the target after successful detection (seccomp mode
     *        only). The caller should then enable process::set_transparent_tracer().
     * @return DetectResult Success if the port was successfully detected within
     *         initial_ms, otherwise a DetectError explaining what happened.
     */
    [[nodiscard]] DetectResult wait_for_port(pid_t target_pid, const Config& cfg,
                                             bool* tracer_attached = nullptr);

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

    /**
     * @brief Outcome of probe_target().
     */
    enum class ProbeOutcome {
        Serviced, ///< the target touched the probe connection (data, EOF, or RST)
        Refused,  ///< connect() got ECONNREFUSED: no listening socket on the target
        Timeout,  ///< the target did not service the probe connection within timeout_ms
        Failed,   ///< connect() or poll() failed for another reason (non-fatal)
    };

    /**
     * @brief probe_target() result: the outcome plus the underlying
     *        ConnectError (kind + errno) for Refused/Failed, so the caller
     *        can tell a gone listener (ECONNREFUSED) apart from client-side
     *        failures (e.g. EADDRNOTAVAIL on ephemeral port exhaustion,
     *        EMFILE on fd exhaustion). Empty for Serviced/Timeout.
     */
    struct ProbeResult {
        ProbeOutcome outcome;
        std::optional<ConnectError> error; ///< populated for Refused and Failed
    };

    /**
     * @brief Post-response quiescence probe: checks that the target has finished
     *        handling the previous request.
     *
     * Opens a throwaway TCP connection to the target, half-closes it (EOF to
     * the target) and waits until the target actually services it (the socket
     * becomes readable due to data, EOF, or RST). The half-close is required:
     * a bare connect() proves nothing by itself (the kernel completes the
     * handshake from the listen backlog without waking the application), and a
     * healthy keep-alive server that merely accepted the connection sends
     * nothing back, which would make every probe end in Timeout:
     *
     * - Serial (blocking-accept) servers cannot service the probe before the
     *   previous connection is completely handled, so Serviced means the
     *   previous request was fully processed (post-response cleanup included).
     * - Event-loop servers get at least one more loop pass after closing the
     *   main connection.
     * - If the target dies before servicing the probe, the kernel RSTs the
     *   established probe connection, which also reports as Serviced; the
     *   caller is expected to classify the death with
     *   process::check_target_state() afterwards (this function never decides
     *   by itself).
     *
     * Known gaps (TODO(claude)): deferred work that runs only after the probe
     * is serviced (timers, async logging) is not covered; on multi-acceptor /
     * threaded targets the probe may be serviced while main-connection cleanup
     * still runs elsewhere; banner-sending servers report Serviced as soon as
     * they send their greeting, before reading EOF.
     *
     * @param net_cfg The network configuration (host, port, timeout_ms).
     * @return ProbeResult Serviced, Refused, Timeout, or Failed with the
     *         underlying connect error (see ProbeResult). All outcomes are
     *         non-fatal; interpretation is up to the caller.
     */
    [[nodiscard]] ProbeResult probe_target(const NetworkConfig& net_cfg);

    /**
     * @brief Convert a ProbeOutcome to its string representation.
     */
    [[nodiscard]] std::string probe_outcome_to_string(ProbeOutcome outcome);

    /**
     * @brief Arms "RST on close" for a client socket (SO_LINGER with a zero
     *        timeout): close() then sends RST instead of FIN, so the local
     *        endpoint never enters TIME_WAIT and no ephemeral port is pinned
     *        for ~2 minutes. Only safe once the caller is done with the
     *        socket (all wanted data already read): the RST discards anything
     *        still unread or in flight. Best-effort: a failure is ignored and
     *        the next close() keeps its normal FIN semantics.
     *
     * @param sock The socket file descriptor.
     */
    void arm_rst_on_close(int sock);

} // namespace network