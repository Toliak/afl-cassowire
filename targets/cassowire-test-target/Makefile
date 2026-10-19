include ../_mk/env.mk
include ../_mk/git.mk
include ../_mk/fuzzers/aflpp.mk

# Deterministic test target: no compile, just copies the prebuilt instrumented
# test-target binaries built by afl-cassowire's own build.
TARGET_NAME := cassowire-test-target

build:
	mkdir -p ./src/build/afl-clang-fast++
	cp $(REPO_ROOT)/afl-cassowire/tests/targets/test-target/build/afl-clang-fast++/test-target \
		./src/build/afl-clang-fast++/
	mkdir -p ./src/build/afl-clang-lto++
	cp $(REPO_ROOT)/afl-cassowire/tests/targets/test-target/build/afl-clang-lto++/test-target \
		./src/build/afl-clang-lto++/

prepare-data:
	$(ORC) $(TARGET_NAME) prepare-data

prepare-seeds:
	$(ORC) $(TARGET_NAME) prepare-seeds --fuzzer $(FUZZER)

FUZZER ?= aflpp
CASSOWIRE_CONFIG ?= http.cassowire.yaml
AFL_FUZZ_TIMEOUT ?= 1500
AFL_FUZZ_CPU ?= 0

fuzz: fuzz-aflpp

fuzz-aflpp:
	mkdir -p ./out ./in
	PATH="$(AFLPP_BIN_DIR):$$PATH" \
	AFL_CASSOWIRE_FORCE_FINAL_LOC=70000 AFL_ALLOW_CORES=1 \
		afl-fuzz -b $(AFL_FUZZ_CPU) -i ./in -o ./out \
			-x $(REPO_ROOT)/targets/_fuzz/dict/http.dict -t $(AFL_FUZZ_TIMEOUT) -c 0 -- \
			$(AFLPP_CASSOWIRE) --log-level error --config $(CASSOWIRE_CONFIG) proxy

cov: replay-cov collect-cov

replay-cov:
	$(ORC) $(TARGET_NAME) replay-cov

collect-cov:
	$(ORC) $(TARGET_NAME) collect-cov

crashes:
	$(ORC) $(TARGET_NAME) collect-crashes

.PHONY: build prepare-data prepare-seeds fuzz fuzz-aflpp cov replay-cov collect-cov crashes
