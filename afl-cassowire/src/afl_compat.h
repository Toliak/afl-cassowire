#ifndef AFL_COMPAT_H
#define AFL_COMPAT_H

// The "must be built with an AFL++ compiler" check lives in meson.build (a
// __AFL_LOOP / __AFL_INIT compiler probe), not here: this header defines no-op
// placeholders so that tooling (IDEs, clangd) can parse the sources.
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
   builds without AFL++'s toolchain. __AFL_COVERAGE expands to a file-scope
   definition in AFL++ builds and may be used once, at file scope; DISCARD is
   a function call usable anywhere. */
#ifndef __AFL_COVERAGE
#define __AFL_COVERAGE()
#endif

#ifndef __AFL_COVERAGE_DISCARD
#define __AFL_COVERAGE_DISCARD()
#endif

#endif /* AFL_COMPAT_H */
