#ifndef AFL_COMPAT_H
#define AFL_COMPAT_H

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