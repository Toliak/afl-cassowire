// src/network.hpp

#pragma once

#include "config.hpp"
#include <sys/types.h>
#include <cstdint>

namespace network {

    /**
     * @brief Waits for the target process to bind to the configured port.
     * Uses the method specified in port_detection.primary (procfs, ptrace, seccomp).
     * 
     * @param target_pid The PID of the target process.
     * @param cfg The global configuration.
     * @return true if the port was successfully detected within initial_ms, false otherwise.
     */
    bool wait_for_port(pid_t target_pid, const Config& cfg);

    /**
     * @brief Connects to the target application via TCP.
     * 
     * @param net_cfg The network configuration.
     * @return int The socket file descriptor, or -1 on failure/timeout.
     */
    int connect_target(const NetworkConfig& net_cfg);

    /**
     * @brief Sends the entire buffer to the socket, handling partial sends and timeouts.
     * 
     * @param sock The socket file descriptor.
     * @param buf The data to send.
     * @param len The length of the data.
     * @param timeout_ms The timeout in milliseconds.
     * @return true if all data was sent successfully, false on error/timeout.
     */
    bool send_all(int sock, const uint8_t* buf, size_t len, int timeout_ms);

    /**
     * @brief Reads from the socket until EOF or timeout.
     *
     * @param sock The socket file descriptor.
     * @param timeout_ms The timeout in milliseconds.
     * @return true if data was received or connection closed without timeout, false on timeout.
     */
    // TODO(claude): the documented contract ("false on timeout") is not what network.cpp does: a poll()
    //   timeout/error returns true, only the "remaining <= 0" path returns false. Also the response data is
    //   neither returned nor printed (spec 6.2 wants the response printed in test mode) - consider returning
    //   the bytes / status instead of a bool.
    bool wait_response(int sock, int timeout_ms);

} // namespace network