include ../_mk/git.mk
include ../_mk/aflpp.mk
include ../_mk/fuzz.mk

TINY_NGINX_URL := https://github.com/gd-arnold/tiny-nginx
TINY_NGINX_COMMIT := 0a4900630457ede33abdb836f54a4d2aee6a6c3b

BUILD_MAKE_ARGS := -j$(nproc)

src:
	$(GIT_CLONE_CMD) $(TINY_NGINX_URL) $@
	cd "$@" && git checkout $(TINY_NGINX_COMMIT)

# Optional patches
prepare: src
	@cd src && \
		for F in ../patch/*.patch; do \
			if [ -f "$$F" ]; then \
				echo "Applying $$F"; \
				patch -p1 -i "../patch/$$F" || { echo "Patch $$F failed"; exit 1; }; \
			fi; \
		done

ALL_BUILD_SUBTARGETS :=	build_clang \
						build_afl-clang-lto \
						build_afl-clang-lto_cmplog \
						build_afl-clang-fast \
						build_afl-clang-fast_cmplog

$(ALL_BUILD_SUBTARGETS): AFL_LLVM_CMPLOG=0

build_clang: CC=clang
build_afl-clang-lto \
	build_afl-clang-lto_cmplog: CC=afl-clang-lto
build_afl-clang-lto_cmplog: AFL_LLVM_CMPLOG=1
build_afl-clang-fast \
	build_afl-clang-fast_cmplog: CC=afl-clang-fast
build_afl-clang-fast_cmplog: AFL_LLVM_CMPLOG=1

$(ALL_BUILD_SUBTARGETS): build_%:
	export PATH="$(AFLPP_BIN_DIR):$$PATH" && \
		export AFL_LLVM_CMPLOG="$(AFL_LLVM_CMPLOG)" && \
		make -C src clean && \
		make $(BUILD_MAKE_ARGS) -C src CC="$(CC)" BUILD_DIR="build/$*"

build: $(ALL_BUILD_SUBTARGETS)

fuzz:
	mkdir -p ./out ./in
	cp -f $(FUZZ_SHARED_DIR)/in_http/* ./in/.
ifdef FUZZ_DEBUG
	@echo "AFL++ debug mode"
endif
#  -x $(FUZZ_SHARED_DIR)/dict/http.dict
	AFL_CASSOWIRE_FORCE_FINAL_LOC=4096 $(AFL_FUZZ_ENV) afl-fuzz  -b 5 -i ./in -o ./out -t 1500 -c 0 -- \
 		"$$(which afl-cassowire)" --log-level trace --child-output --config cassowire.yaml proxy
# 		"$$(which afl-cassowire)" --log-level error --config cassowire.yaml proxy

# Binary-only QEMU mode: afl-cassowire forks+execs afl-qemu-bridge, which runs the
# uninstrumented guest (src/build/clang/tinynginx, see `make build_clang`).
# Invariant: AFL_CASSOWIRE_FORCE_FINAL_LOC >= AFL_QEMU_MAP_SIZE (cassowire.qemu.yaml).
# -c 0: cmplog runs in-emulator (target_cmplog = same bridge + guest on port 8081);
# the proxy forwards ___AFL_EINS_ZWEI_POLIZEI___ to the bridge.
fuzz-qemu:
	mkdir -p ./out ./in
	cp -f $(FUZZ_SHARED_DIR)/in_http/* ./in/.
ifdef FUZZ_DEBUG
	@echo "AFL++ debug mode"
endif
	AFL_CASSOWIRE_FORCE_FINAL_LOC=65536 $(AFL_FUZZ_ENV) afl-fuzz -b 2 -i ./in -o ./out -t 2000 -c 0 -- \
 		"$$(which afl-cassowire)" --log-level trace --child-output --config cassowire.qemu.yaml proxy
#  		"$$(which afl-cassowire)" --log-level error --config cassowire.qemu.yaml proxy

# fuzz-qemu-test:
# 	mkdir -p ./out ./in
# 	cp -f $(FUZZ_SHARED_DIR)/in_http/* ./in/.
# ifdef FUZZ_DEBUG
# 	@echo "AFL++ debug mode"
# endif
# 	$(AFL_FUZZ_ENV) afl-fuzz -b 5 -i ./in -o ./out -t 2000 -- \
# 		/opt/workdir/aflpp/src/distrib/bin/afl-qemu-bridge /opt/workdir/targets/nginx/src/install/clang/usr/bin/nginx -t -c @@


.PHONY: build prepare fuzz fuzz-qemu
