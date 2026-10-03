include ../_shared/git.mk
include ../_shared/aflpp.mk

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

.PHONY: build prepare