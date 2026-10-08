__MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

FUZZ_SHARED_DIR := $(__MAKEFILE_DIR)/../_fuzz

AFL_FUZZ_ENV := AFL_ALLOW_CORES=1

# If FUZZ_DEBUG = 1, then set AFL_FUZZ_ENV with debug flags
ifdef FUZZ_DEBUG
    ifeq ($(FUZZ_DEBUG),1)
        AFL_FUZZ_ENV += AFL_DEBUG=1 AFL_DEBUG_CHILD=1 AFL_NO_UI=1
    endif
endif
