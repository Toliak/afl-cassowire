AFLPP_URL := https://github.com/aflplusplus/aflplusplus
AFLPP_TAG := v5.02c

AFLPP_MAKE_ARGS := -j$(nproc)
AFLPP_MAKE_ARGS_ADD :=

GIT_ARGS := --progress --depth 1

help:
	@echo "prepare -- git clone the AFL++ repo"

src/.cloned:
	git clone $(AFLPP_URL) $(GIT_ARGS) --branch=$(AFLPP_TAG) ./src
	touch $@

src: src/.cloned

prepare: src/.cloned

PATCH_TARGETS := src/.patched

src/.patched: src/.cloned
	cd "./src" && \
		for F in "../patch"/*.patch; do \
			patch -p1 -i "$$F" || exit 1; \
		done
	touch ./src/.patched

patch: src/.patched

src/.submodules: src/.cloned
	git -C ./src submodule update --init $(GIT_ARGS) qemu_mode/qemuafl qemu_bridge/qemu-libafl-bridge
	touch $@

submodules: src/.submodules

build: $(PATCH_TARGETS) src/.submodules
	cd "./src" && \
		make $(AFLPP_MAKE_ARGS) $(AFLPP_MAKE_ARGS_ADD) \
			distrib \
			PERFORMANCE=1 \
			NO_PYTHON=0 \
			NO_NYX=1 \
			NO_CORESIGHT=1 \
			NO_FRIDA=1 \
			NO_UNICORN=1

install:
	cd "./src" && \
		make $(AFLPP_MAKE_ARGS) $(AFLPP_MAKE_ARGS_ADD) \
			PREFIX=distrib install

.PHONY: help prepare patch submodules build install
