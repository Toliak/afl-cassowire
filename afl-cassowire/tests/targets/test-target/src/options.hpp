// src/options.hpp

#pragma once

#include <cstdint>
#include <string>

namespace testtarget {

/// Command-line configuration (see parse_options()).
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

/// Parses and validates the command line (argparse); exit(2) on argument
/// errors, fatal() on semantic ones (invalid mode/port/delay/flags).
Options parse_options(int argc, char* argv[]);

} // namespace testtarget
