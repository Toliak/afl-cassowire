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
						build_afl-clang-fast

$(ALL_BUILD_SUBTARGETS): build_%:
	export PATH="$(AFLPP_BIN_DIR):$$PATH" && \
		make -C src clean && \
		make $(BUILD_MAKE_ARGS) -C src CC="$*" BUILD_DIR="build/$*"

build: $(ALL_BUILD_SUBTARGETS)

fuzz:
	mkdir -p ./out ./in
	cp -f $(FUZZ_SHARED_DIR)/in_http/* ./in/.
ifdef FUZZ_DEBUG
	@echo "AFL++ debug mode"
endif
	$(AFL_FUZZ_ENV) afl-fuzz -i ./in -o ./out -x $(FUZZ_SHARED_DIR)/dict/http.dict -t 1500 -- \
 		afl-cassowire --log-level trace --child-output --config cassowire.yaml proxy
# 		afl-cassowire --log-level error --config cassowire.yaml proxy

.PHONY: build prepare