include ../_mk/env.mk
include ../_mk/git.mk
include ../_mk/fuzzers/aflpp.mk
include ../_mk/fuzzers/aflnet.mk

TARGET_NAME := haproxy

HAPROXY_URL    := https://github.com/haproxy/haproxy
HAPROXY_BRANCH := v3.4.0

# ---------------------------------------------------------------------------
# source
# ---------------------------------------------------------------------------

src:
	$(GIT_CLONE_CMD) $(HAPROXY_URL) --branch "$(HAPROXY_BRANCH)" $@

# ---------------------------------------------------------------------------
# build variants (run inside the toolchain/dev container)
# ---------------------------------------------------------------------------

HAPROXY_BUILD_FLAGS := TARGET=linux-glibc \
	USE_OPENSSL=1 USE_PCRE2=1 USE_ZLIB=1 USE_THREAD=1 USE_MINIDEBUG=0

ALL_BUILD_SUBTARGETS := build_clang \
	build_afl-clang-lto build_afl-clang-lto_cmplog \
	build_afl-clang-fast build_afl-clang-fast_cmplog \
	build_aflnet build_gcov

$(ALL_BUILD_SUBTARGETS): AFL_LLVM_CMPLOG := 0
$(ALL_BUILD_SUBTARGETS): CC_ADD_FLAGS :=
$(ALL_BUILD_SUBTARGETS): LD_ADD_FLAGS :=
$(ALL_BUILD_SUBTARGETS): FZ_BIN_DIR :=
$(ALL_BUILD_SUBTARGETS): AFL_PATH :=

build_clang:                 CC := clang
build_afl-clang-lto:         CC := afl-clang-lto
build_afl-clang-lto_cmplog:  CC := afl-clang-lto
build_afl-clang-fast:        CC := afl-clang-fast
build_afl-clang-fast_cmplog: CC := afl-clang-fast
build_aflnet:                CC := $(AFLNET_BIN_DIR)/afl-gcc
build_gcov:                  CC := gcc

build_afl-clang-lto:         FZ_BIN_DIR := $(AFLPP_BIN_DIR)
build_afl-clang-lto_cmplog:  FZ_BIN_DIR := $(AFLPP_BIN_DIR)
build_afl-clang-fast:        FZ_BIN_DIR := $(AFLPP_BIN_DIR)
build_afl-clang-fast_cmplog: FZ_BIN_DIR := $(AFLPP_BIN_DIR)
build_aflnet:                AFL_PATH := $(AFLNET_BIN_DIR)

build_afl-clang-lto_cmplog:  AFL_LLVM_CMPLOG := 1
build_afl-clang-fast_cmplog: AFL_LLVM_CMPLOG := 1

build_gcov: CC_ADD_FLAGS := -fprofile-arcs -ftest-coverage
build_gcov: LD_ADD_FLAGS := -fprofile-arcs -ftest-coverage

build: $(ALL_BUILD_SUBTARGETS)

$(ALL_BUILD_SUBTARGETS): build_%:
	export PATH="$(if $(FZ_BIN_DIR),$(FZ_BIN_DIR):,)$$PATH"; \
	unset AFL_PATH; \
	$(if $(AFL_PATH),export AFL_PATH="$(AFL_PATH)";) \
	export AFL_LLVM_CMPLOG="$(AFL_LLVM_CMPLOG)"; \
	make -C src clean && \
	make -C src -j$(NUM_CORES) $(HAPROXY_BUILD_FLAGS) \
		CC="$(CC)" CFLAGS="$(CC_ADD_FLAGS)" LDFLAGS="$(LD_ADD_FLAGS)" && \
	mkdir -p "src/build/$*" && \
	cp src/haproxy "src/build/$*/haproxy"

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
	AFL_CASSOWIRE_FORCE_FINAL_LOC=262144 AFL_ALLOW_CORES=1 \
		afl-fuzz -b $(AFL_FUZZ_CPU) -i ./in -o ./out \
			-x $(TARGETS_DIR)/_fuzz/dict/http.dict -t 1500 -c 0 -- \
			$(AFLPP_CASSOWIRE) --log-level error --config $(CASSOWIRE_CONFIG) proxy

fuzz-qemu:
	mkdir -p ./out ./in
	PATH="$(AFLPP_BIN_DIR):$$PATH" \
	AFL_CASSOWIRE_FORCE_FINAL_LOC=262144 AFL_ALLOW_CORES=1 \
		afl-fuzz -b $(AFL_FUZZ_CPU) -i ./in -o ./out \
			-x $(TARGETS_DIR)/_fuzz/dict/http.dict -t 2000 -c 0 -- \
			$(AFLPP_CASSOWIRE) --log-level error --config data/cassowire.qemu.yaml proxy

fuzz-aflnet:
	mkdir -p ./out ./in
	PATH="$(AFLNET_BIN_DIR):$$PATH" \
		afl-fuzz -d -i ./in -o ./out -N tcp://127.0.0.1/8080 -P HTTP -D 10000 -q 3 -s 3 -E -K -R -- \
			./src/build/aflnet/haproxy -db -f data/haproxy.cfg

cov: replay-cov collect-cov

replay-cov:
	$(ORC) $(TARGET_NAME) replay-cov

collect-cov:
	$(ORC) $(TARGET_NAME) collect-cov

crashes:
	$(ORC) $(TARGET_NAME) collect-crashes

.PHONY: src build prepare-data prepare-seeds fuzz fuzz-aflpp fuzz-qemu fuzz-aflnet \
	cov replay-cov collect-cov crashes $(ALL_BUILD_SUBTARGETS)
