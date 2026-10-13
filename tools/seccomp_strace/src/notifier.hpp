#pragma once

#include <sys/types.h>

namespace notifier {

/// How the first-spawned child (the traced program) terminated.
struct outcome {
    bool signaled = false; ///< true when killed by a signal.
    int code = 0;          ///< exit status, or signal number when signaled.
    bool reaped = false;   ///< false if we never saw it exit.
};

/// Runs the notification loop until every descendant that inherited the filter
/// has exited (the listener reports EOF) and all children are reaped.
///
/// `listener_fd` is the seccomp notification descriptor; `init_pid` is the
/// child that exec'd the traced program. The supervisor is marked as a child
/// subreaper so orphaned descendants reparent to us and can be reaped.
///
/// Every intercepted call is continued with SECCOMP_USER_NOTIF_FLAG_CONTINUE,
/// so no return value is observable. Returns the init child's outcome.
outcome run(int listener_fd, pid_t init_pid);

} // namespace notifier
