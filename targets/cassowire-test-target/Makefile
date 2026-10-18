include ../_mk/git.mk
# include ../_mk/aflpp.mk
include ../_mk/fuzz.mk

BUILD_DIR := ./src/build

build:
	mkdir -p $(BUILD_DIR)/afl-clang-fast++
	cp ../../afl-cassowire/tests/targets/test-target/build/afl-clang-fast++/test-target $(BUILD_DIR)/afl-clang-fast++/./
	mkdir -p $(BUILD_DIR)/afl-clang-lto++
	cp ../../afl-cassowire/tests/targets/test-target/build/afl-clang-lto++/test-target $(BUILD_DIR)/afl-clang-lto++/./
	
# ------------------------------

AFL_FUZZ_TIMEOUT ?= 1500
CASSOWIRE_CONFIG ?= http.cassowire.yaml

CASSOWIRE_LOG_ARGS := --log-level error

ifdef FUZZ_DEBUG
	CASSOWIRE_LOG_ARGS := --log-level debug --child-output
endif

fuzz:
	mkdir -p ./out ./in
	cp -f $(FUZZ_SHARED_DIR)/in_calc/* ./in/.
ifdef FUZZ_DEBUG
	@echo "AFL++ debug mode"
endif
	export AFL_CASSOWIRE_FORCE_FINAL_LOC=70000 && \
		$(AFL_FUZZ_ENV) afl-fuzz -b 3 -i ./in -o ./out -x $(FUZZ_SHARED_DIR)/dict/http.dict -t $(AFL_FUZZ_TIMEOUT) -c 0 -- \
 		"$$(which afl-cassowire)" $(CASSOWIRE_LOG_ARGS) --config $(CASSOWIRE_CONFIG) proxy

.PHONY: fuzz
