AFLPP_DISTRIB_DIR := $(shell realpath "$(CURDIR)/../../../../aflpp/src/distrib")

.DEFAULT_GOAL := build

prepare:
	meson subprojects download

ALL_BUILD_SUBTARGETS :=	build_clang++ \
						build_afl-clang-lto++ \
						build_afl-clang-lto++_cmplog \
						build_afl-clang-fast++ \
						build_afl-clang-fast++_cmplog

build_clang++: CXX=clang++
build_afl-clang-lto++ \
	build_afl-clang-lto++_cmplog: CXX=afl-clang-lto++
build_afl-clang-lto++_cmplog: AFL_LLVM_CMPLOG=1
build_afl-clang-fast++ \
	build_afl-clang-fast++_cmplog: CXX=afl-clang-fast++
build_afl-clang-fast++_cmplog: AFL_LLVM_CMPLOG=1

$(ALL_BUILD_SUBTARGETS): build_%:
	export PATH="$(AFLPP_BIN_DIR):$$PATH" && \
		export AFL_LLVM_CMPLOG="$(AFL_LLVM_CMPLOG)" && \
		rm -rf "./build/$*"
		mkdir -p "./build/$*"
		CXX="$(CXX)" meson setup "./build/$*"
		meson compile -C "./build/$*"

build: $(ALL_BUILD_SUBTARGETS)

clean:
	rm -rf ./build

.PHONY: prepare build clean $(ALL_BUILD_SUBTARGETS)
