include ../../mk/env.mk
include ../../mk/git.mk

GIT_URL := https://github.com/google/honggfuzz
GIT_COMMIT := 940b958dfeb6f9131fd846cae31fcc0fe996ae98

HFUZZ_DISTRIB ?= $(CURDIR)/src/distrib

MAKE_ARGS := -j$(NUM_CORES)
MAKE_ARGS_ADD :=

help:
	@echo "src     -- git clone the honggfuzz repo"
	@echo "build   -- build honggfuzz and the hfuzz-cc compiler wrappers"
	@echo "install -- stage honggfuzz and the clang-based wrappers in src/distrib/bin"
	@echo "clean   -- remove build artifacts"

src/.cloned:
	$(call GIT_SRC_COMMIT_TARGET_CMD,$(GIT_URL),$(GIT_COMMIT))

src: src/.cloned

build: src
	$(MAKE) -C src $(MAKE_ARGS) $(MAKE_ARGS_ADD)

install: build
	install -d "$(HFUZZ_DISTRIB)/bin"
	install -m 755 src/honggfuzz "$(HFUZZ_DISTRIB)/bin/"
	install -m 755 src/hfuzz_cc/hfuzz-cc "$(HFUZZ_DISTRIB)/bin/"
	install -m 755 src/hfuzz_cc/hfuzz-clang "$(HFUZZ_DISTRIB)/bin/"
	install -m 755 src/hfuzz_cc/hfuzz-clang++ "$(HFUZZ_DISTRIB)/bin/"

clean:
	$(MAKE) -C src clean

.PHONY: help src build install clean