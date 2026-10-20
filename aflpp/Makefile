include ../mk/env.mk
include ../mk/git.mk

GIT_URL := https://github.com/aflplusplus/aflplusplus
GIT_TAG := v5.03c

MAKE_ARGS := -j$(NUM_CORES)
MAKE_ARGS_ADD :=

help:
	@echo "prepare -- git clone the AFL++ repo"

src/.cloned:
	$(call GIT_SRC_TAG_TARGET_CMD,$(GIT_URL),$(GIT_TAG))

src/.submodules: src/.cloned
	$(call GIT_SUBMODULES_TARGET_CMD,qemu_mode/qemuafl qemu_bridge/qemu-libafl-bridge)

src: src/.submodules

src/.patched: src/.submodules
	cd "./src" && \
		for F in "../patch"/*.patch; do \
			patch -p1 -i "$$F" || exit 1; \
		done
	touch ./src/.patched

patch: src/.patched

build: src/.patched
	cd "./src" && \
		make $(MAKE_ARGS) $(MAKE_ARGS_ADD) \
			distrib \
			PERFORMANCE=1 \
			NO_PYTHON=0 \
			NO_NYX=1 \
			NO_CORESIGHT=1 \
			NO_FRIDA=1 \
			NO_UNICORN=1

install:
	cd "./src" && \
		make $(MAKE_ARGS) $(MAKE_ARGS_ADD) \
			PREFIX=distrib install

.PHONY: help src patch build install
