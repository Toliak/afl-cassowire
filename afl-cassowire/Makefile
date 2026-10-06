AFLPP_DISTRIB_DIR := $(shell realpath "$$PWD/../aflpp/src/distrib")

.DEFAULT_GOAL := build

prepare:
	meson subprojects download

prepare2:
	CXX="$(AFLPP_DISTRIB_DIR)/bin/afl-clang-fast++" meson setup build

build:
	export AFL_PROXY_LLVM_ONLY_FSRV=1 && \
	meson compile -C build

clean:
	rm -rf build

.PHONY: prepare prepare2 build clean
