include ../_mk/env.mk
include ../_mk/git.mk
include ../_mk/fuzzers/aflpp.mk
include ../_mk/fuzz.mk

TARGET_NAME := cassowire-test-target

# Canonical source for the deterministic test target. Builds are out-of-tree
# under this target so afl-cassowire's own source tree keeps only its own build.
TEST_TARGET_SRC   := $(REPO_ROOT)/afl-cassowire/tests/targets/test-target
TEST_TARGET_BUILD := $(TARGET_DIR)/src/build

# ---------------------------------------------------------------------------
# profile selection (keep in sync with PROFILES in orchestrator.py)
# ---------------------------------------------------------------------------

DEFAULT_PROFILE := http
PROFILES := http calc

# Coverage/triage goals without an explicit profile aggregate every profile;
# seed/fuzz goals default to the target's primary profile.
ifeq ($(filter cov replay-cov collect-cov crashes,$(MAKECMDGOALS)),)
PROFILE ?= $(DEFAULT_PROFILE)
endif
ifneq ($(filter-out $(PROFILES),$(PROFILE)),)
$(error invalid PROFILE '$(PROFILE)'; valid: $(PROFILES) or empty for all profiles)
endif

PROFILE_ARG  = $(if $(PROFILE),--profile $(PROFILE))
FUZZ_PROFILE = $(or $(PROFILE),$(DEFAULT_PROFILE))

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
	$(ORC) $(TARGET_NAME) prepare-seeds --fuzzer $(FUZZER) $(PROFILE_ARG) --out $(AFL_IN_DIR)

FUZZER ?= aflpp
CASSOWIRE_CONFIG ?= $(FUZZ_PROFILE).cassowire.yaml
AFL_FUZZ_TIMEOUT ?= 1500
AFL_FUZZ_CPU ?= 0
AFL_IN_DIR ?= in/$(FUZZ_PROFILE)
AFL_OUT_DIR ?= out/$(FUZZ_PROFILE)
AFL_FUZZ_DICT ?= $(REPO_ROOT)/targets/_fuzz/dict/$(FUZZ_PROFILE).dict
COVERAGE_OUT ?= $(if $(PROFILE),cov/$(PROFILE),cov)

fuzz: fuzz-aflpp

fuzz-aflpp:
	mkdir -p "$(AFL_IN_DIR)" "$(AFL_OUT_DIR)"
	PATH="$(AFLPP_BIN_DIR):$$PATH" \
	AFL_CASSOWIRE_FORCE_FINAL_LOC=70000 $(AFL_FUZZ_ENV) \
		afl-fuzz -b $(AFL_FUZZ_CPU) -i "$(AFL_IN_DIR)" -o "$(AFL_OUT_DIR)" \
			-x $(AFL_FUZZ_DICT) -t $(AFL_FUZZ_TIMEOUT) -c 0 -- \
			$(AFLPP_CASSOWIRE) $(CASSOWIRE_LOG_ARGS) --config $(CASSOWIRE_CONFIG) proxy

cov: replay-cov collect-cov

replay-cov:
	$(ORC) $(TARGET_NAME) replay-cov $(PROFILE_ARG)

collect-cov:
	$(ORC) $(TARGET_NAME) collect-cov --out $(COVERAGE_OUT)

crashes:
	$(ORC) $(TARGET_NAME) collect-crashes $(PROFILE_ARG)

.PHONY: prepare build prepare-data prepare-seeds fuzz fuzz-aflpp cov replay-cov collect-cov crashes $(ALL_BUILD_SUBTARGETS)
