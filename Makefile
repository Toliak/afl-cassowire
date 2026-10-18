# Top-level interface. Generic: knows nothing about individual targets, fuzzers
# or the orc helper — it forwards to the per-target Makefile (the interface).
#
#   make toolchain                                   # build the toolchain image
#   make aflpp | aflnet                              # build a fuzzer toolchain
#   make TARGET=nginx VARIANT=afl-clang-fast build    # build one variant
#   make TARGET=nginx build                          # build all variants
#   make TARGET=nginx prepare-data                    # render data_template -> data/
#   make TARGET=nginx FUZZER=aflpp prepare-seeds      # prepare in/ corpus
#   make TARGET=nginx FUZZER=aflpp fuzz               # fuzz (network-isolated)
#   make TARGET=nginx cov                             # lcov coverage
#   make TARGET=nginx crashes                         # collect crashes
#
# FUZZER : aflpp | aflnet (default aflpp, set in the per-target Makefile)
# VARIANT: build variant name (build_<VARIANT>), only meaningful for `build`

TOOLCHAIN_IMAGE ?= localhost/afl-cassowire-toolchain:latest

.PHONY: help toolchain aflpp aflnet build prepare-data prepare-seeds fuzz cov crashes

help:
	@printf '%s\n' \
		'Goals: toolchain aflpp aflnet build prepare-data prepare-seeds fuzz cov crashes' \
		'Required: TARGET=<name> (except toolchain/aflpp/aflnet)' \
		'Optional: FUZZER=aflpp|aflnet  VARIANT=<build-variant>' \
		'' \
		'Examples:' \
		'  make TARGET=nginx VARIANT=afl-clang-fast build' \
		'  make TARGET=nginx prepare-data' \
		'  make TARGET=nginx FUZZER=aflpp prepare-seeds' \
		'  make TARGET=nginx FUZZER=aflpp fuzz' \
		'  make TARGET=nginx FUZZER=aflnet fuzz' \
		'  make TARGET=nginx cov'

toolchain:
	podman build -t $(TOOLCHAIN_IMAGE) -f container/toolchain.Containerfile container/

# Build the fuzzer toolchains (like targets), inside the toolchain container.
aflpp:
	podman run --rm --userns=keep-id -v $(CURDIR):/work:Z -w /work/aflpp \
		$(TOOLCHAIN_IMAGE) make prepare patch submodules build install

aflnet:
	podman run --rm --userns=keep-id -v $(CURDIR):/work:Z -w /work/other/aflnet \
		$(TOOLCHAIN_IMAGE) make

# Generic passthrough to the per-target Makefile (the interface).
build:
	make -C targets/$(TARGET) build$(if $(VARIANT),_$(VARIANT),)

prepare-data prepare-seeds fuzz cov crashes:
	make -C targets/$(TARGET) $@