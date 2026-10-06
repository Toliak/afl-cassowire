#ifndef AFL_COMPAT_H
#define AFL_COMPAT_H

// TODO(claude): Spec violation. The spec (sec. 2 and 7) requires `afl_compat.hpp` (not `.h`) that FAILS
//   compilation with `#ifndef __AFL_LOOP / #error ...` when AFL++ macros are missing. This header does the
//   opposite: it silently defines no-op placeholders, so a build with plain g++/clang++ succeeds.
//   Worse, the fake `__AFL_LOOP(count)` is `(0)`, so the fuzz loop never runs and the proxy "works" but
//   fuzzes nothing; and `__AFL_FUZZ_TESTCASE_BUF` is NULL with LEN 0. Replace with the #error guard.
// SOLUTION: we do not produce error here. we check the compiler in the meson-side
/* Placeholder definitions for AFL++ identifiers when not compiled with AFL++ */
#ifndef __AFL_INIT
#define __AFL_INIT() do { } while(0)
#endif

#ifndef __AFL_LOOP
#define __AFL_LOOP(count) (0)
#endif

#ifndef __AFL_FUZZ_TESTCASE_LEN
#define __AFL_FUZZ_TESTCASE_LEN (0)
#endif

#ifndef __AFL_FUZZ_TESTCASE_BUF
#define __AFL_FUZZ_TESTCASE_BUF (NULL)
#endif

#ifndef __AFL_FUZZ_INIT
#define __AFL_FUZZ_INIT() 
#endif

#endif /* AFL_COMPAT_H */