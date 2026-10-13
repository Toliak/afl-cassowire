#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace trace {

/// One intercepted system call: the number we match in the BPF filter and the
/// name we print.
struct syscall_entry {
    long nr;
    const char* name;
};

/// The exact set of system calls this tool intercepts. This is the single
/// source of truth shared by the BPF filter builder and the pretty-printer.
const std::vector<syscall_entry>& traced();

/// Name for a system call number, or "unknown" when the number is not part of
/// the traced set.
const char* name_of(long nr);

/// Formats the six raw register arguments as space-free hex, e.g.
/// "0x3, 0x7ffd0000, 0x10, 0x0, 0x0, 0x0". No target memory is read.
/// The element type matches `struct seccomp_data::args` (kernel `__u64`).
std::string format_args(const unsigned long long (&args)[6]);

} // namespace trace
