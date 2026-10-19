include ../_mk/container.mk
include ../_mk/git.mk
include ../_mk/fuzzers/aflpp.mk

TARGET_NAME := tiny-nginx
CTR_W       := $(CONTAINER_WORKDIR)/targets/$(TARGET_NAME)

TINY_NGINX_URL    := https://github.com/gd-arnold/tiny-nginx
TINY_NGINX_COMMIT := 0a4900630457ede33abdb836f54a4d2aee6a6c3b

# ---------------------------------------------------------------------------
# source + patches
# ---------------------------------------------------------------------------

src:
	$(GIT_CLONE_CMD) $(TINY_NGINX_URL) $@
	cd "$@" && git checkout $(TINY_NGINX_COMMIT)

prepare: src
	@cd src && \
		for F in ../patch/*.patch; do \
			if [ -f "$$F" ]; then \
				echo "Applying $$F"; \
				patch -p1 -i "../patch/$$F" || { echo "Patch $$F failed"; exit 1; }; \
			fi; \
		done

# ---------------------------------------------------------------------------
# build variants (run inside the toolchain container)
# ---------------------------------------------------------------------------

ALL_BUILD_SUBTARGETS := build_clang \
	build_afl-clang-lto build_afl-clang-lto_cmplog \
	build_afl-clang-fast build_afl-clang-fast_cmplog \
	build_gcov

$(ALL_BUILD_SUBTARGETS): AFL_LLVM_CMPLOG := 0
$(ALL_BUILD_SUBTARGETS): FZ_BIN_DIR :=

build_clang:                 CC := clang
build_afl-clang-lto:         CC := afl-clang-lto
build_afl-clang-lto_cmplog:  CC := afl-clang-lto
build_afl-clang-fast:        CC := afl-clang-fast
build_afl-clang-fast_cmplog: CC := afl-clang-fast
build_gcov:                  CC := gcc --coverage

build_afl-clang-lto:         FZ_BIN_DIR := $(AFLPP_BIN_DIR)
build_afl-clang-lto_cmplog:  FZ_BIN_DIR := $(AFLPP_BIN_DIR)
build_afl-clang-fast:        FZ_BIN_DIR := $(AFLPP_BIN_DIR)
build_afl-clang-fast_cmplog: FZ_BIN_DIR := $(AFLPP_BIN_DIR)

build_afl-clang-lto_cmplog:  AFL_LLVM_CMPLOG := 1
build_afl-clang-fast_cmplog: AFL_LLVM_CMPLOG := 1

build: $(ALL_BUILD_SUBTARGETS)

$(ALL_BUILD_SUBTARGETS): build_%:
	$(PODMAN_RUN) -w $(CTR_W) $(TOOLCHAIN_IMAGE) bash -lc '\
		export PATH="$(if $(FZ_BIN_DIR),$(FZ_BIN_DIR):,)$$PATH" && \
		export AFL_LLVM_CMPLOG="$(AFL_LLVM_CMPLOG)" && \
		make -C src clean && \
		make -C src CC="$(CC)" BUILD_DIR="build/$*"'

# ---------------------------------------------------------------------------
# data / seeds / fuzz / coverage / crashes
# ---------------------------------------------------------------------------

prepare-data:
	$(ORC) $(TARGET_NAME) prepare-data

prepare-seeds:
	$(ORC) $(TARGET_NAME) prepare-seeds --fuzzer $(FUZZER)

FUZZER ?= aflpp

fuzz: fuzz-aflpp

fuzz-aflpp:
	$(PODMAN_RUN_TTY) -w $(CTR_W) -e AFL_CASSOWIRE_FORCE_FINAL_LOC=4096 -e AFL_ALLOW_CORES=1 \
		$(TOOLCHAIN_IMAGE) bash -lc '\
		mkdir -p ./out ./in && \
		export PATH="$(AFLPP_BIN_DIR):$$PATH" && \
		afl-fuzz -b 5 -i ./in -o ./out -t 1500 -c 0 -- \
			$(AFLPP_CASSOWIRE) --log-level error --config data/cassowire.yaml proxy'

fuzz-qemu:
	$(PODMAN_RUN_TTY) -w $(CTR_W) -e AFL_CASSOWIRE_FORCE_FINAL_LOC=65536 -e AFL_ALLOW_CORES=1 \
		$(TOOLCHAIN_IMAGE) bash -lc '\
		mkdir -p ./out ./in && \
		export PATH="$(AFLPP_BIN_DIR):$$PATH" && \
		afl-fuzz -b 5 -i ./in -o ./out -t 2000 -c 0 -- \
			$(AFLPP_CASSOWIRE) --log-level error --config data/cassowire.qemu.yaml proxy'

cov:
	$(ORC) $(TARGET_NAME) collect-cov

crashes:
	$(ORC) $(TARGET_NAME) collect-crashes

.PHONY: src prepare build prepare-data prepare-seeds fuzz fuzz-aflpp fuzz-qemu cov crashes $(ALL_BUILD_SUBTARGETS)