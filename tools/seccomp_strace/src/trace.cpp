#include "trace.hpp"

#include <cstddef>
#include <sstream>
#include <sys/syscall.h>

namespace {

// Keep this list in the same order as the request: sockets, epoll, poll,
// select, fork-and-alternatives. Numbers come from the kernel headers so the
// tool stays honest about what it matches.
const std::vector<trace::syscall_entry> kTraced = {
    // sockets
    {__NR_bind, "bind"},
    {__NR_listen, "listen"},

    // epoll
    {__NR_epoll_create, "epoll_create"},
    {__NR_epoll_create1, "epoll_create1"},
    {__NR_epoll_ctl, "epoll_ctl"},
    {__NR_epoll_wait, "epoll_wait"},
    {__NR_epoll_pwait, "epoll_pwait"},
#ifdef __NR_epoll_pwait2
    {__NR_epoll_pwait2, "epoll_pwait2"},
#endif

    // poll
    {__NR_poll, "poll"},
    {__NR_ppoll, "ppoll"},

    // select
    {__NR_select, "select"},
    {__NR_pselect6, "pselect6"},

    // fork and its alternatives
    {__NR_clone, "clone"},
#ifdef __NR_clone3
    {__NR_clone3, "clone3"},
#endif
    {__NR_fork, "fork"},
    {__NR_vfork, "vfork"},
};

} // namespace

namespace trace {

const std::vector<syscall_entry>& traced()
{
    return kTraced;
}

const char* name_of(long nr)
{
    for (const syscall_entry& e : kTraced) {
        if (e.nr == nr)
            return e.name;
    }

    return "unknown";
}

std::string format_args(const unsigned long long (&args)[6])
{
    std::ostringstream out;
    out << std::hex << std::showbase;

    for (std::size_t i = 0; i < 6; ++i) {
        if (i != 0)
            out << ", ";
        out << args[i];
    }

    return out.str();
}

} // namespace trace
