#pragma once

namespace seccomp_filter {

/// Builds a BPF program that returns SECCOMP_RET_USER_NOTIF for every system
/// call in trace::traced() and SECCOMP_RET_ALLOW for everything else, then
/// installs it on the calling thread with SECCOMP_FILTER_FLAG_NEW_LISTENER.
///
/// Sets PR_SET_NO_NEW_PRIVS first. Must be called after fork() and before
/// execve() in the child: the filter is inherited by every descendant and
/// preserved across execve(), so the whole process tree stays notifiable on
/// the returned descriptor.
///
/// Returns the listening descriptor on success, or -1 with errno set. The
/// descriptor has close-on-exec set by the kernel; callers must keep it open
/// to keep receiving notifications.
int install_with_listener();

} // namespace seccomp_filter
