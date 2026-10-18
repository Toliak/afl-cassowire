include ../_mk/container.mk
include ../_mk/git.mk
include ../_mk/fuzzers/aflpp.mk

# Deterministic test target: no compile, just copies the prebuilt instrumented
# test-target binaries built by afl-cassowire's own build.
TARGET_NAME := cassowire-test-target
CTR_W       := $(CONTAINER_WORKDIR)/targets/$(TARGET_NAME)

build:
	$(PODMAN_RUN) -w $(CTR_W) $(TOOLCHAIN_IMAGE) bash -lc '\
		mkdir -p ./src/build/afl-clang-fast++ && \
		cp ../../afl-cassowire/tests/targets/test-target/build/afl-clang-fast++/test-target ./src/build/afl-clang-fast++/ && \
		mkdir -p ./src/build/afl-clang-lto++ && \
		cp ../../afl-cassowire/tests/targets/test-target/build/afl-clang-lto++/test-target ./src/build/afl-clang-lto++/'

prepare-data:
	$(ORC) $(TARGET_NAME) prepare-data

prepare-seeds:
	$(ORC) $(TARGET_NAME) prepare-seeds --fuzzer $(FUZZER)

FUZZER ?= aflpp
CASSOWIRE_CONFIG ?= http.cassowire.yaml
AFL_FUZZ_TIMEOUT ?= 1500

fuzz: fuzz-aflpp

fuzz-aflpp:
	$(PODMAN_RUN_TTY) -w $(CTR_W) -e AFL_CASSOWIRE_FORCE_FINAL_LOC=70000 -e AFL_ALLOW_CORES=1 \
		$(TOOLCHAIN_IMAGE) bash -lc '\
		mkdir -p ./out ./in && \
		export PATH="$(AFLPP_BIN_DIR):$$PATH" && \
		afl-fuzz -b 3 -i ./in -o ./out -x $(CONTAINER_WORKDIR)/targets/_fuzz/dict/http.dict -t $(AFL_FUZZ_TIMEOUT) -c 0 -- \
			$(AFLPP_CASSOWIRE) --log-level error --config $(CASSOWIRE_CONFIG) proxy'

cov:
	$(ORC) $(TARGET_NAME) collect-cov

crashes:
	$(ORC) $(TARGET_NAME) collect-crashes

.PHONY: build prepare-data prepare-seeds fuzz fuzz-aflpp cov crashes