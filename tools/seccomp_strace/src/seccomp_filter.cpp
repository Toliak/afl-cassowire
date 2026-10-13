#include "seccomp_filter.hpp"

#include "trace.hpp"

#include <cerrno>
#include <cstddef>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

namespace {

int seccomp_syscall(unsigned int operation, unsigned int flags, void* args)
{
    return static_cast<int>(syscall(SYS_seccomp, operation, flags, args));
}

} // namespace

namespace seccomp_filter {

int install_with_listener()
{
    std::vector<struct sock_filter> prog;

    // x86-64 ABI guard: anything not x86-64 is killed rather than silently
    // untraced. This mirrors the kernel's own example boilerplate.
    prog.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                            offsetof(struct seccomp_data, arch)));
    prog.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0));
    prog.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    prog.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                            offsetof(struct seccomp_data, nr)));

    // For each traced number: if nr == N jump over the notification return
    // (kFalseOffset = 0, kTrueOffset = 1), then notify. Everything else falls
    // through to the trailing ALLOW.
    for (const trace::syscall_entry& e : trace::traced()) {
        prog.push_back(
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<__u32>(e.nr), 0, 1));
        prog.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF));
    }

    prog.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    struct sock_fprog fprog {};
    fprog.len = static_cast<unsigned short>(prog.size());
    fprog.filter = prog.data();

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return -1;

    return seccomp_syscall(SECCOMP_SET_MODE_FILTER,
                           SECCOMP_FILTER_FLAG_NEW_LISTENER, &fprog);
}

} // namespace seccomp_filter
