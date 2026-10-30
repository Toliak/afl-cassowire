include ../_mk/env.mk
include ../_mk/git.mk
include ../_mk/fuzzers/aflpp.mk
include ../_mk/fuzzers/aflnet.mk
include ../_mk/fuzz.mk

TARGET_NAME := h2o

H2O_URL    := https://github.com/h2o/h2o
H2O_COMMIT := 534c5fd9f10d185bd9b87ac75ec05dcc0722369e

# ---------------------------------------------------------------------------
# source
# ---------------------------------------------------------------------------

src:
	$(GIT_CLONE_CMD) $(H2O_URL) $@
	cd "$@" && { git checkout $(H2O_COMMIT) || \
		{ git fetch --depth 1 origin $(H2O_COMMIT) && git checkout $(H2O_COMMIT); }; }
	cd "$@" && git submodule update --init --recursive

# ---------------------------------------------------------------------------
# build variants (run inside the toolchain/dev container)
# ---------------------------------------------------------------------------

ALL_BUILD_SUBTARGETS := build_clang \
	build_afl-clang-lto build_afl-clang-lto_cmplog \
	build_afl-clang-fast build_afl-clang-fast_cmplog \
	build_aflnet build_gcov

$(ALL_BUILD_SUBTARGETS): AFL_LLVM_CMPLOG := 0
$(ALL_BUILD_SUBTARGETS): CC_ADD_FLAGS :=
$(ALL_BUILD_SUBTARGETS): LD_ADD_FLAGS :=
$(ALL_BUILD_SUBTARGETS): FZ_BIN_DIR :=

build_clang:                 CC := clang
build_afl-clang-lto:         CC := afl-clang-lto
build_afl-clang-lto_cmplog:  CC := afl-clang-lto
build_afl-clang-fast:        CC := afl-clang-fast
build_afl-clang-fast_cmplog: CC := afl-clang-fast
build_aflnet:                CC := $(AFLNET_DIR)/afl-gcc
build_gcov:                  CC := clang

build_clang:                 CXX := clang++
build_afl-clang-lto:         CXX := afl-clang-lto++
build_afl-clang-lto_cmplog:  CXX := afl-clang-lto++
build_afl-clang-fast:        CXX := afl-clang-fast++
build_afl-clang-fast_cmplog: CXX := afl-clang-fast++
build_aflnet:                CXX := $(AFLNET_DIR)/afl-g++
build_gcov:                  CXX := clang++

build_afl-clang-lto:         FZ_BIN_DIR := $(AFLPP_BIN_DIR)
build_afl-clang-lto_cmplog:  FZ_BIN_DIR := $(AFLPP_BIN_DIR)
build_afl-clang-fast:        FZ_BIN_DIR := $(AFLPP_BIN_DIR)
build_afl-clang-fast_cmplog: FZ_BIN_DIR := $(AFLPP_BIN_DIR)

build_afl-clang-lto_cmplog:  AFL_LLVM_CMPLOG := 1
build_afl-clang-fast_cmplog: AFL_LLVM_CMPLOG := 1

build_gcov: CC_ADD_FLAGS := --coverage
build_gcov: LD_ADD_FLAGS := --coverage

build: $(ALL_BUILD_SUBTARGETS)

$(ALL_BUILD_SUBTARGETS): build_%:
	export PATH="$(if $(FZ_BIN_DIR),$(FZ_BIN_DIR):,)$$PATH"; \
	export AFL_LLVM_CMPLOG="$(AFL_LLVM_CMPLOG)"; \
	rm -rf "src/build/$*" && \
	cmake -S src -B "src/build/$*" -G Ninja \
		-DCMAKE_BUILD_TYPE=Release \
		-DCMAKE_C_COMPILER="$(CC)" \
		-DCMAKE_CXX_COMPILER="$(CXX)" \
		-DCMAKE_C_FLAGS="$(CC_ADD_FLAGS)" \
		-DCMAKE_EXE_LINKER_FLAGS="$(LD_ADD_FLAGS)" \
		-DWITH_MRUBY=OFF \
		-DBUILD_FUZZER=OFF && \
	cmake --build "src/build/$*" --target h2o -j$(NUM_CORES)

# ---------------------------------------------------------------------------
# data / seeds / fuzz / coverage / crashes (delegated to the orc helper)
# ---------------------------------------------------------------------------

prepare-data:
	$(ORC) $(TARGET_NAME) prepare-data

prepare-seeds:
	$(ORC) $(TARGET_NAME) prepare-seeds --fuzzer $(FUZZER)

CASSOWIRE_CONFIG ?= data/cassowire.yaml
FUZZER           ?= aflpp
AFL_FUZZ_CPU     ?= 0

fuzz: fuzz-$(FUZZER)

fuzz-aflpp:
	mkdir -p ./out ./in
	PATH="$(AFLPP_BIN_DIR):$$PATH" \
	AFL_CASSOWIRE_FORCE_FINAL_LOC=262144 $(AFL_FUZZ_ENV) \
		afl-fuzz -b $(AFL_FUZZ_CPU) -i ./in -o ./out \
			-x $(REPO_ROOT)/targets/_fuzz/dict/http.dict -t 1500 -c 0 -- \
			$(AFLPP_CASSOWIRE) $(CASSOWIRE_LOG_ARGS) --config $(CASSOWIRE_CONFIG) proxy

fuzz-qemu:
	mkdir -p ./out ./in
	PATH="$(AFLPP_BIN_DIR):$$PATH" \
	AFL_CASSOWIRE_FORCE_FINAL_LOC=262144 $(AFL_FUZZ_ENV) \
		afl-fuzz -b $(AFL_FUZZ_CPU) -i ./in -o ./out -t 2000 -c 0 -- \
			$(AFLPP_CASSOWIRE) $(CASSOWIRE_LOG_ARGS) --config data/cassowire.qemu.yaml proxy

fuzz-aflnet:
	mkdir -p ./out ./in
	PATH="$(AFLNET_BIN_DIR):$$PATH" \
		afl-fuzz -d -i ./in -o ./out -N tcp://127.0.0.1/8070 -P HTTP -D 10000 -q 3 -s 3 -E -K -R -- \
			./src/build/aflnet/h2o -c ./data/h2o.conf

cov: replay-cov collect-cov

replay-cov:
	$(ORC) $(TARGET_NAME) replay-cov

collect-cov:
	$(ORC) $(TARGET_NAME) collect-cov

crashes:
	$(ORC) $(TARGET_NAME) collect-crashes

.PHONY: src build prepare-data prepare-seeds fuzz fuzz-aflpp fuzz-qemu fuzz-aflnet \
	cov replay-cov collect-cov crashes $(ALL_BUILD_SUBTARGETS)
