include ../mk/env.mk
include ../mk/git.mk

GIT_URL := https://github.com/aflplusplus/aflplusplus
GIT_TAG := v5.03c

MAKE_ARGS := -j$(NUM_CORES)
MAKE_ARGS_ADD :=

# Guest architectures to build QEMU support for. The native architecture is
# reused from the regular `make distrib` build; non-native ones are built with
# CPU_TARGET=<arch> and installed as arch-suffixed binaries.
QEMU_ARCHS ?= x86_64 aarch64
QEMU_HOST_ARCH := $(shell uname -m)
QEMU_ARCH_STAGE := src/.qemu

help:
	@echo "prepare -- git clone the AFL++ repo"
	@echo "QEMU_ARCHS -- guest arches for QEMU support (default: x86_64 aarch64)"

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

build-qemu: build
	$(MAKE) qemu-archs

# Stage arch-suffixed QEMU binaries. `make distrib` already built QEMU for the
# native architecture, so reuse it; other architectures are built in the same
# tree with CPU_TARGET=<arch>. The trap restores the native binaries afterwards
# so `make install` still installs the default afl-qemu-trace/afl-qemu-bridge.
qemu-archs:
	@set -e; \
	native="$(QEMU_ARCH_STAGE)/native"; \
	rm -rf "$$native"; \
	mkdir -p "$$native"; \
	cp -f src/afl-qemu-trace src/afl-qemu-bridge "$$native/"; \
	trap 'cp -f "$$native"/afl-qemu-trace "$$native"/afl-qemu-bridge src/ 2>/dev/null || true' EXIT; \
	for arch in $(QEMU_ARCHS); do \
		out="$(QEMU_ARCH_STAGE)/$$arch"; \
		if [ -x "$$out/afl-qemu-trace" ] && [ -x "$$out/afl-qemu-bridge" ] && \
		   [ "$$out/.built" -nt "src/.patched" ] && \
		   [ "$$out/.built" -nt "Makefile" ] && \
		   [ "$$out/.built" -nt "src/qemu_mode/QEMUAFL_VERSION" ] && \
		   [ "$$out/.built" -nt "src/qemu_bridge/QEMU_BRIDGE_VERSION" ]; then \
			echo "[*] Reusing staged QEMU $$arch binaries"; \
			continue; \
		fi; \
		echo "[*] Staging QEMU $$arch guest support"; \
		rm -rf "$$out"; \
		mkdir -p "$$out"; \
		if [ "$$arch" = "$(QEMU_HOST_ARCH)" ]; then \
			cp -f "$$native/afl-qemu-trace" "$$native/afl-qemu-bridge" "$$out/"; \
		else \
			( cd src/qemu_mode && unset CFLAGS && CPU_TARGET="$$arch" ./build_qemu_support.sh ); \
			( cd src/qemu_bridge && unset CFLAGS && CPU_TARGET="$$arch" ./build_qemu_bridge_support.sh ); \
			cp -f src/afl-qemu-trace src/afl-qemu-bridge "$$out/"; \
		fi; \
		touch "$$out/.built"; \
	done

install: build-qemu
	cd "./src" && \
		make $(MAKE_ARGS) $(MAKE_ARGS_ADD) \
			PREFIX=distrib install
	@set -e; \
	mkdir -p src/distrib/bin; \
	for arch in $(QEMU_ARCHS); do \
		install -m 755 "$(QEMU_ARCH_STAGE)/$$arch/afl-qemu-trace" \
			"src/distrib/bin/afl-qemu-trace-$$arch"; \
		install -m 755 "$(QEMU_ARCH_STAGE)/$$arch/afl-qemu-bridge" \
			"src/distrib/bin/afl-qemu-bridge-$$arch"; \
	done

.PHONY: help src prepare patch submodules build build-qemu install qemu-archs
