AFLPP_DISTRIB_DIR := $(shell realpath "$$PWD/../aflpp/src/distrib")

# STATIC=0 builds the default dynamically linked binary; STATIC=1 links
# afl-cassowire and its dependencies statically.
STATIC ?= 0
ifeq ($(strip $(STATIC)),1)
  BUILD_DIR := build-static
  MESON_STATIC := true
else
  BUILD_DIR := build
  MESON_STATIC := false
endif

.DEFAULT_GOAL := build

prepare:
	meson subprojects download

prepare2:
	CXX="$(AFLPP_DISTRIB_DIR)/bin/afl-clang-fast++" \
		meson setup "$(BUILD_DIR)" -Dstatic_link=$(MESON_STATIC)

build:
	export AFL_CASSOWIRE_LLVM_ONLY_FSRV=1 && \
	meson compile -C "$(BUILD_DIR)"

clean:
	rm -rf build build-static

e2e-test-simple:
	AFL_CASSOWIRE_FORCE_FINAL_LOC=2048 make -C "$$PWD/../targets/tiny-nginx" fuzz FUZZ_DEBUG=1 2>&1 | head -n100

.PHONY: prepare prepare2 build clean
