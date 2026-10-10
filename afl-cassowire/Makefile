AFLPP_DISTRIB_DIR := $(shell realpath "$$PWD/../aflpp/src/distrib")

.DEFAULT_GOAL := build

prepare:
	meson subprojects download

prepare2:
	CXX="$(AFLPP_DISTRIB_DIR)/bin/afl-clang-fast++" meson setup build

build:
	export AFL_CASSOWIRE_LLVM_ONLY_FSRV=1 && \
	meson compile -C build

clean:
	rm -rf build

e2e-test-simple:
	AFL_CASSOWIRE_FORCE_FINAL_LOC=2048 make -C "$$PWD/../targets/tiny-nginx" fuzz FUZZ_DEBUG=1 2>&1 | head -n100

.PHONY: prepare prepare2 build clean
