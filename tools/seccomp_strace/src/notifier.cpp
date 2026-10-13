#include "notifier.hpp"

#include "trace.hpp"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <linux/seccomp.h>
#include <poll.h>
#include <set>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace {

/// Queued notifications for TIDs we have not printed yet, so that a freshly
/// created child's first line is preceded by a synthetic "<new ...>" marker.
void note_new_tid(std::set<std::uint32_t>& seen, std::uint32_t tid)
{
    if (!seen.insert(tid).second)
        return;

    // The very first TID is the program we were asked to run; every later one
    // appeared because the target called fork/clone/vfork.
    if (seen.size() == 1)
        return;

    std::cout << "[pid " << tid << "] <new thread/process>\n";
    std::cout.flush();
}

void log_call(const trace::syscall_entry* entry, const struct seccomp_notif& req)
{
    const char* name = entry ? entry->name : "unknown";

    std::cout << "[pid " << req.pid << "] " << name << '('
              << trace::format_args(req.data.args) << ") = <cont>\n";
    std::cout.flush();
}

/// Sends a CONTINUE response for `req`. Returns false once the notification is
/// stale (the target exited or a signal handler interrupted it), which is
/// normal and must not be treated as an error.
bool continue_syscall(int listener_fd, const struct seccomp_notif& req,
                      const struct seccomp_notif_resp& resp_template)
{
    struct seccomp_notif_resp resp = resp_template;
    resp.id = req.id;

    if (ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) == 0)
        return true;

    if (errno == ENOENT || errno == EINTR)
        return false;

    std::cerr << "strace_seccomp: SECCOMP_IOCTL_NOTIF_SEND: "
              << std::strerror(errno) << '\n';
    return false;
}

} // namespace

namespace notifier {

outcome run(int listener_fd, pid_t init_pid)
{
    // Orphans reparent to us on death, so we can reap them and so the listener
    // fd stays referenced until the last filtered task is gone.
    prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);

    // Query structure sizes rather than assuming this kernel's ABI.
    struct seccomp_notif_sizes sizes {};
    if (syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) != 0) {
        std::cerr << "strace_seccomp: SECCOMP_GET_NOTIF_SIZES: "
                  << std::strerror(errno) << '\n';
        return {};
    }

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, nullptr);

    int sigfd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
    if (sigfd < 0) {
        std::cerr << "strace_seccomp: signalfd: " << std::strerror(errno) << '\n';
        return {};
    }

    std::vector<unsigned char> req_buf(sizes.seccomp_notif);
    struct seccomp_notif_resp resp_template {};
    resp_template.val = 0;
    resp_template.error = 0;
    resp_template.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;

    std::set<std::uint32_t> seen;
    outcome result {};
    bool child_alive = true;
    bool listener_open = true;

    while (child_alive || listener_open) {
        struct pollfd fds[2];
        fds[0].fd = listener_fd;
        fds[0].events = POLLIN;
        fds[0].revents = 0;
        fds[1].fd = sigfd;
        fds[1].events = POLLIN;
        fds[1].revents = 0;

        int n = poll(fds, 2, -1);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            std::cerr << "strace_seccomp: poll: " << std::strerror(errno) << '\n';
            break;
        }

        if (fds[1].revents & POLLIN) {
            struct signalfd_siginfo si {};
            while (read(sigfd, &si, sizeof(si)) == static_cast<ssize_t>(sizeof(si))) {
                // Reap everything currently available, recording the init
                // child's fate. Other descendants are followed via the filter.
                for (;;) {
                    int status = 0;
                    pid_t p = waitpid(-1, &status, WNOHANG);
                    if (p <= 0)
                        break;

                    if (p == init_pid) {
                        result.reaped = true;
                        if (WIFSIGNALED(status)) {
                            result.signaled = true;
                            result.code = WTERMSIG(status);
                        } else {
                            result.code = WEXITSTATUS(status);
                        }
                        child_alive = false;
                    }
                }
            }
        }

        if (fds[0].revents & (POLLIN | POLLHUP)) {
            // poll() told us at least one notification is ready. Drain the
            // first one, then only keep going while more are already queued
            // (checked with a zero-timeout poll) so we never block past a
            // pending SIGCHLD.
            bool more = true;
            while (more) {
                std::memset(req_buf.data(), 0, req_buf.size());
                struct seccomp_notif* req =
                    reinterpret_cast<struct seccomp_notif*>(req_buf.data());

                if (ioctl(listener_fd, SECCOMP_IOCTL_NOTIF_RECV, req) != 0) {
                    if (errno == ENOENT)
                        break; // stale: the target thread is gone
                    if (errno == EINTR)
                        break; // let the outer poll() re-evaluate

                    std::cerr << "strace_seccomp: SECCOMP_IOCTL_NOTIF_RECV: "
                              << std::strerror(errno) << '\n';
                    break;
                }

                note_new_tid(seen, req->pid);

                const trace::syscall_entry* entry = nullptr;
                for (const trace::syscall_entry& e : trace::traced()) {
                    if (e.nr == req->data.nr) {
                        entry = &e;
                        break;
                    }
                }

                log_call(entry, *req);
                continue_syscall(listener_fd, *req, resp_template);

                struct pollfd again {};
                again.fd = listener_fd;
                again.events = POLLIN;
                more = poll(&again, 1, 0) > 0 && (again.revents & POLLIN) != 0;
            }
        }

        if (fds[0].revents & POLLHUP) {
            // No task references the listener any more: the tree is gone.
            listener_open = false;
        }
    }

    close(sigfd);
    return result;
}

} // namespace notifier
