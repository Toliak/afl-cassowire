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

/* Selective coverage control. afl-cc injects the real macros via -D (see
   instrumentation/README.instrument_list.md sec. 2); these are the no-ops for
   builds without AFL++'s toolchain. __AFL_COVERAGE and __AFL_COVERAGE_START_OFF
   expand to file-scope definitions in AFL++ builds and may be used once, at
   file scope; the rest are function calls usable anywhere. */
#ifndef __AFL_COVERAGE
#define __AFL_COVERAGE()
#endif

#ifndef __AFL_COVERAGE_START_OFF
#define __AFL_COVERAGE_START_OFF()
#endif

#ifndef __AFL_COVERAGE_ON
#define __AFL_COVERAGE_ON()
#endif

#ifndef __AFL_COVERAGE_OFF
#define __AFL_COVERAGE_OFF()
#endif

#ifndef __AFL_COVERAGE_DISCARD
#define __AFL_COVERAGE_DISCARD()
#endif

#ifndef __AFL_COVERAGE_SKIP
#define __AFL_COVERAGE_SKIP()
#endif

#endif /* AFL_COMPAT_H */