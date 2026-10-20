include ../../mk/env.mk
include ../../mk/git.mk

GIT_URL := https://github.com/bajinsheng/SGFuzz
GIT_COMMIT := 35f1ffc9482d524b03e54c7a48f4a742ba9fc9a3

SGFUZZ_DIR             := $(patsubst %/,%,$(CURDIR))
REPO_ROOT              := $(abspath $(SGFUZZ_DIR)/../..)
SGFUZZ_SRC_DIR         := $(SGFUZZ_DIR)/src
SGFUZZ_LIB             := $(SGFUZZ_SRC_DIR)/libsfuzzer.a
SGFUZZ_CC              ?= clang
SGFUZZ_CXX             ?= clang++
# robin_hood.h uses std::numeric_limits without including <limits>; newer
# libstdc++ no longer provides it transitively.
SGFUZZ_CXXFLAGS        ?= -g -fPIC -O2 -std=c++11 -include limits

HONGGFUZZ_DIR          := $(REPO_ROOT)/other_fuzzers/honggfuzz
HONGGFUZZ_SRC_DIR      := $(HONGGFUZZ_DIR)/src
SGFUZZ_HFND_BUILD_DIR  := $(SGFUZZ_DIR)/build/hfnd
SGFUZZ_HFCOMMON_LIB    := $(SGFUZZ_HFND_BUILD_DIR)/libhfcommon/libhfcommon.a
SGFUZZ_HFNETDRIVER_LIB := $(SGFUZZ_HFND_BUILD_DIR)/libhfnetdriver/libhfnetdriver.a
SGFUZZ_HFND_CFLAGS     := -O2 -g -DHFND_RECVTIME=1 \
	-fsanitize=fuzzer-no-link -fsanitize=address

src/.cloned:
	$(call GIT_SRC_COMMIT_TARGET_CMD,$(GIT_URL),$(GIT_COMMIT))

src: src/.cloned

# Build the SGFuzz libFuzzer driver in src/ (upstream build.sh hardcodes clang++
# and does not accept CXXFLAGS, so use the same recipe with an overridable CXX).
libsfuzzer: src/.cloned
	cd "$(SGFUZZ_SRC_DIR)" && \
	rm -f Fuzzer*.o libsfuzzer.a && \
	for f in *.cpp; do \
		$(SGFUZZ_CXX) $(SGFUZZ_CXXFLAGS) -c "$$f" || exit 1; \
	done && \
	ar rcs libsfuzzer.a Fuzzer*.o && \
	rm -f Fuzzer*.o

# libhfnetdriver needs libhfcommon. Build both out-of-tree so the honggfuzz
# checkout stays pristine. CFLAGS is passed via the environment, not on the
# command line, so honggfuzz's own COMMON_CFLAGS/ARCH_CFLAGS are still appended.
netdriver: src/.cloned "$(HONGGFUZZ_SRC_DIR)/.cloned"
	CFLAGS="$(SGFUZZ_HFND_CFLAGS)" \
		$(MAKE) -C "$(HONGGFUZZ_SRC_DIR)" \
			BUILD_DIR="$(SGFUZZ_HFND_BUILD_DIR)" \
			CC="$(SGFUZZ_CC)" \
			"$(SGFUZZ_HFCOMMON_LIB)" "$(SGFUZZ_HFNETDRIVER_LIB)"

"$(HONGGFUZZ_SRC_DIR)/.cloned":
	$(MAKE) -C "$(HONGGFUZZ_DIR)" src

build: libsfuzzer netdriver

clean:
	rm -f "$(SGFUZZ_SRC_DIR)"/Fuzzer*.o "$(SGFUZZ_LIB)"
	rm -rf "$(SGFUZZ_HFND_BUILD_DIR)"

.PHONY: src libsfuzzer netdriver build clean
