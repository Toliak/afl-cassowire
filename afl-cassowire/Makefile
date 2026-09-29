MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

AFLPP_DISTRIB_DIR := $(MAKEFILE_DIR)/../aflpp/src/distrib

prepare:
	cd $(MAKEFILE_DIR) && \
		meson subprojects download

prepare2:
	cd $(MAKEFILE_DIR) && \
		CC="$(AFLPP_DISTRIB_DIR)/bin/afl-clang-fast" CXX="$(AFLPP_DISTRIB_DIR)/bin/afl-clang-fast++" meson setup build

build:
	cd $(MAKEFILE_DIR) && \
		export PATH="$(AFLPP_DISTRIB_DIR)/bin:$$PATH"
		export AFL_PROXY_LLVM_ONLY_FSRV=1 && \
		meson compile -C build

clean:
	cd $(MAKEFILE_DIR) && \
		rm -rf build

.PHONY: prepare prepare2 build