#pragma once

#include <sys/types.h>

namespace target {

/// Result of spawning the traced program.
struct spawned {
    pid_t pid = -1;   ///< PID of the child that will exec the target.
    int listener_fd = -1; ///< Seccomp notification descriptor owned by us.
};

/// Forks, installs the seccomp notification filter in the child, hands the
/// listening descriptor back over a UNIX socket, and execs `argv` (a
/// NULL-terminated vector whose argv[0] is looked up on PATH).
///
/// `argv` must outlive the call but is only read before exec. On any failure
/// returns {-1, -1} and leaves no child behind.
spawned spawn(char* const argv[]);

} // namespace target
