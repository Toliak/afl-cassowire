// strace_seccomp — a miniature strace built on SECCOMP_RET_USER_NOTIF.
//
// The supervisor spawns a program, arms a seccomp filter (inherited by every
// descendant and preserved across execve) that bounces a fixed set of syscalls
// to user space, prints each call, and always replies with CONTINUE so the
// kernel runs it. Because continuation returns control to the kernel, the
// result of the call is not observable here: this is an entry/argument tracer.
//
// Usage:
//   strace_seccomp [--] PROGRAM [ARGS...]
//
// Example:
//   ./strace_seccomp -- nginx -c /etc/nginx/nginx.conf

#include "notifier.hpp"
#include "target.hpp"

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

pid_t g_child_pgid = -1;

void forward_signal(int sig)
{
    if (g_child_pgid > 0)
        kill(-g_child_pgid, sig);
}

void usage(const char* program)
{
    std::cerr << "Usage: " << program
              << " [--] PROGRAM [ARGS...]\n"
                 "\n"
                 "Traces bind, listen, epoll, poll, select and fork/clone/vfork\n"
                 "via SECCOMP_RET_USER_NOTIF (entry + raw args, no return\n"
                 "values).\n";
}

} // namespace

int main(int argc, char** argv)
{
    int first = 1;

    // An explicit "--" separates our (currently empty) options from the
    // command line of the traced program. Without it everything is the program.
    if (first < argc && std::strcmp(argv[first], "--") == 0)
        ++first;
    else if (first < argc && argv[first][0] == '-' && argv[first][1] != '\0') {
        std::string arg = argv[first];
        if (arg == "-h" || arg == "--help") {
            usage(argv[0]);
            return EXIT_SUCCESS;
        }
        std::cerr << "strace_seccomp: unknown option: " << arg << '\n';
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (first >= argc) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    std::vector<char*> child_argv;
    for (int i = first; i < argc; ++i)
        child_argv.push_back(argv[i]);
    child_argv.push_back(nullptr);

    target::spawned t = target::spawn(child_argv.data());
    if (t.pid < 0) {
        std::cerr << "strace_seccomp: failed to start target: "
                  << std::strerror(errno) << '\n';
        return EXIT_FAILURE;
    }

    g_child_pgid = t.pid; // setpgid(0,0) made the child's pgid equal its pid

    struct sigaction sa {};
    sa.sa_handler = forward_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    notifier::outcome o = notifier::run(t.listener_fd, t.pid);

    close(t.listener_fd);

    if (!o.reaped)
        return EXIT_FAILURE;

    if (o.signaled) {
        // Mirror the shell convention: die with the same signal.
        std::signal(o.code, SIG_DFL);
        raise(o.code);
        return EXIT_FAILURE;
    }

    return o.code;
}
