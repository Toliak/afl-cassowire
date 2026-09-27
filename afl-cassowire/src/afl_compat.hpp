// src/afl_compat.hpp

#ifndef AFL_COMPAT_HPP
#define AFL_COMPAT_HPP

#ifndef __AFL_LOOP
#error "AFL++ persistent mode macros not found. Compile with afl-clang-fast/afl-clang-lto."
#endif

#endif // AFL_COMPAT_HPP