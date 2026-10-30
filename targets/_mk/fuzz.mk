__MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

FUZZ_SHARED_DIR := $(__MAKEFILE_DIR)/../_fuzz

AFL_FUZZ_ENV := AFL_ALLOW_CORES=1

CASSOWIRE_LOG_ARGS ?= --log-level error

# FUZZ_DEBUG=1 enables AFL++ debug output and verbose afl-cassowire logs.
ifeq ($(FUZZ_DEBUG),1)
    AFL_FUZZ_ENV += AFL_DEBUG=1 AFL_DEBUG_CHILD=1 AFL_NO_UI=1
    CASSOWIRE_LOG_ARGS := --log-level debug --child-output
endif
