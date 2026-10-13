#include "target.hpp"

#include "seccomp_filter.hpp"

#include <cerrno>
#include <cstddef>
#include <cstring>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

/// Sends `fd` over the connected UNIX socket `sock`. Returns 0 or -1/errno.
int send_fd(int sock, int fd)
{
    char byte = '\0';
    struct iovec iov {};
    iov.iov_base = &byte;
    iov.iov_len = sizeof(byte);

    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } control {};

    struct msghdr msg {};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.buf;
    msg.msg_controllen = sizeof(control.buf);

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));

    return static_cast<int>(sendmsg(sock, &msg, 0)) < 0 ? -1 : 0;
}

/// Receives a descriptor over `sock`, or -1/errno.
int recv_fd(int sock)
{
    char byte = '\0';
    struct iovec iov {};
    iov.iov_base = &byte;
    iov.iov_len = sizeof(byte);

    union {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } control {};

    struct msghdr msg {};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.buf;
    msg.msg_controllen = sizeof(control.buf);

    ssize_t n;
    do {
        n = recvmsg(sock, &msg, 0);
    } while (n < 0 && errno == EINTR);

    if (n <= 0)
        return -1;

    struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg == nullptr || cmsg->cmsg_level != SOL_SOCKET
        || cmsg->cmsg_type != SCM_RIGHTS
        || cmsg->cmsg_len != CMSG_LEN(sizeof(int))) {
        errno = EINVAL;
        return -1;
    }

    int fd = -1;
    std::memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
    return fd;
}

} // namespace

namespace target {

spawned spawn(char* const argv[])
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) != 0)
        return {};

    const pid_t parent_pid = getpid();

    pid_t pid = fork();
    if (pid < 0) {
        close(sv[0]);
        close(sv[1]);
        return {};
    }

    if (pid == 0) {
        // Child: own process group so the supervisor can forward Ctrl-C to the
        // whole traced tree. arm the filter, hand the listener to the
        // supervisor, then exec the real program. None of these bootstrap
        // syscalls are traced, so we cannot deadlock waiting for a supervisor
        // that does not exist yet.
        if (setpgid(0, 0) != 0 && errno != EACCES)
            _exit(126);

        // Die with the supervisor: if we are killed (even with SIGKILL) while
        // the target is still alive, the kernel delivers SIGKILL to it so no
        // orphaned listener survives. Re-check the parent afterwards to close
        // the race where it died between fork() and this call.
        prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
        if (getppid() != parent_pid)
            _exit(126);

        close(sv[0]);

        int listener = seccomp_filter::install_with_listener();
        if (listener < 0)
            _exit(126);

        if (send_fd(sv[1], listener) != 0)
            _exit(126);

        char ack;
        while (read(sv[1], &ack, 1) < 0 && errno == EINTR) {
        }

        close(sv[1]);
        close(listener);

        execvp(argv[0], argv);
        _exit(127); // exec failed (e.g. ENOENT)
    }

    // Parent: wait for the child to pass us the listener, then release it.
    close(sv[1]);

    int listener = recv_fd(sv[0]);
    if (listener < 0) {
        close(sv[0]);
        waitpid(pid, nullptr, 0);
        return {};
    }

    char ack = '\0';
    ssize_t unused = write(sv[0], &ack, sizeof(ack));
    (void)unused;
    close(sv[0]);

    return {pid, listener};
}

} // namespace target
