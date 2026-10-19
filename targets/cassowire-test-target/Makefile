include ../_mk/env.mk
include ../_mk/git.mk
include ../_mk/fuzzers/aflpp.mk

TARGET_NAME := cassowire-test-target

# Canonical source for the deterministic test target. Builds are out-of-tree
# under this target so afl-cassowire's own source tree keeps only its own build.
TEST_TARGET_SRC   := $(REPO_ROOT)/afl-cassowire/tests/targets/test-target
TEST_TARGET_BUILD := $(TARGET_DIR)/src/build

# ---------------------------------------------------------------------------
# build variants (run inside the toolchain/dev container)
# ---------------------------------------------------------------------------

ALL_BUILD_SUBTARGETS := build_clang++ \
	build_afl-clang-lto++ build_afl-clang-lto++_cmplog \
	build_afl-clang-fast++ build_afl-clang-fast++_cmplog \
	build_gcov

$(ALL_BUILD_SUBTARGETS): AFL_LLVM_CMPLOG := 0
$(ALL_BUILD_SUBTARGETS): FZ_BIN_DIR :=
$(ALL_BUILD_SUBTARGETS): MESON_ARGS :=

build_clang++:                 CXX := clang++
build_afl-clang-lto++:         CXX := afl-clang-lto++
build_afl-clang-lto++_cmplog:  CXX := afl-clang-lto++
build_afl-clang-fast++:        CXX := afl-clang-fast++
build_afl-clang-fast++_cmplog: CXX := afl-clang-fast++
build_gcov:                    CXX := clang++

build_afl-clang-lto++:         FZ_BIN_DIR := $(AFLPP_BIN_DIR)
build_afl-clang-lto++_cmplog:  FZ_BIN_DIR := $(AFLPP_BIN_DIR)
build_afl-clang-fast++:        FZ_BIN_DIR := $(AFLPP_BIN_DIR)
build_afl-clang-fast++_cmplog: FZ_BIN_DIR := $(AFLPP_BIN_DIR)

build_afl-clang-lto++_cmplog:  AFL_LLVM_CMPLOG := 1
build_afl-clang-fast++_cmplog: AFL_LLVM_CMPLOG := 1

# meson's built-in coverage support; no changes to the upstream meson.build.
build_gcov: MESON_ARGS := -Db_coverage=true

# argparse lives in a gitignored meson subproject; pre-fetch it like the
# test-target's own Makefile does.
prepare:
	cd "$(TEST_TARGET_SRC)" && meson subprojects download

build: prepare $(ALL_BUILD_SUBTARGETS)

$(ALL_BUILD_SUBTARGETS): build_%:
	export PATH="$(if $(FZ_BIN_DIR),$(FZ_BIN_DIR):,)$$PATH"; \
	export AFL_LLVM_CMPLOG="$(AFL_LLVM_CMPLOG)"; \
	rm -rf "$(TEST_TARGET_BUILD)/$*" && \
	mkdir -p "$(TEST_TARGET_BUILD)" && \
	CXX="$(CXX)" meson setup "$(TEST_TARGET_BUILD)/$*" "$(TEST_TARGET_SRC)" $(MESON_ARGS) && \
	meson compile -C "$(TEST_TARGET_BUILD)/$*"

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

.PHONY: prepare build prepare-data prepare-seeds fuzz fuzz-aflpp cov replay-cov collect-cov crashes $(ALL_BUILD_SUBTARGETS)
