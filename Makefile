# Top-level interface and the only container-aware makefile.
#
# On the host (default, RUN_IN_CONTAINER=1) every goal runs inside the toolchain
# image, with the whole repo mounted at $(CONTAINER_WORKDIR):
#
#   make TARGET=nginx VARIANT=afl-clang-fast build
#   make TARGET=nginx FUZZER=aflpp fuzz
#
# Inside the dev container use RUN_IN_CONTAINER=0 to run the per-target
# Makefiles directly (no nested podman):
#
#   RUN_IN_CONTAINER=0 make TARGET=nginx build
#   cd targets/nginx && make build
#
# Converted per-target Makefiles (nginx, tiny-nginx, haproxy, h2o, cassowire-test-target) are
# plain make: they never invoke podman themselves. Unconverted targets still use
# their own container recipes and are forwarded unchanged on the host.
#
# FUZZER : aflpp | aflnet (default aflpp, set in the per-target Makefile)
# VARIANT: build variant name (build_<VARIANT>), only meaningful for `build`

REPO_ROOT := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

TOOLCHAIN_IMAGE  ?= localhost/afl-cassowire-toolchain:latest
CONTAINER_WORKDIR ?= /opt/workdir
RUN_IN_CONTAINER ?= 1
PODMAN           ?= podman
WITH_QEMU        ?= 1

# Targets whose Makefiles are container-local (no podman).
CONTAINER_TARGETS := nginx tiny-nginx haproxy h2o cassowire-test-target

PODMAN_RUN     = $(PODMAN) run --rm --userns=keep-id \
	-v "$(REPO_ROOT):$(CONTAINER_WORKDIR):Z"
PODMAN_RUN_TTY = $(PODMAN_RUN) -it

TARGET_IS_CONVERTED := $(filter $(TARGET),$(CONTAINER_TARGETS))

ifeq ($(TARGET_IS_CONVERTED),)
  # Legacy target: keep the previous host passthrough.
  TARGET_RUN     = $(MAKE) -C targets/$(TARGET)
  TARGET_RUN_TTY = $(TARGET_RUN)
  TARGET_MAKE_ENV =
else ifeq ($(RUN_IN_CONTAINER),1)
  TARGET_RUN     = $(PODMAN_RUN) -w $(CONTAINER_WORKDIR) \
	$(TOOLCHAIN_IMAGE) make -C targets/$(TARGET)
  TARGET_RUN_TTY = $(PODMAN_RUN_TTY) -w $(CONTAINER_WORKDIR) \
	$(TOOLCHAIN_IMAGE) make -C targets/$(TARGET)
  TARGET_MAKE_ENV = ORC_PYTHON=python3
else
  TARGET_RUN     = $(MAKE) -C targets/$(TARGET)
  TARGET_RUN_TTY = $(TARGET_RUN)
  TARGET_MAKE_ENV = ORC_PYTHON=$(if $(wildcard $(REPO_ROOT)/.venv/bin/python),$(REPO_ROOT)/.venv/bin/python,python3)
endif

ifeq ($(RUN_IN_CONTAINER),1)
  SHELL_CMD = $(PODMAN_RUN_TTY) -w $(CONTAINER_WORKDIR) $(TOOLCHAIN_IMAGE)
  RUN_CMD   = $(PODMAN_RUN) -w $(CONTAINER_WORKDIR) $(TOOLCHAIN_IMAGE) bash -lc
else
  SHELL_CMD = cd "$(REPO_ROOT)" && bash
  RUN_CMD   = cd "$(REPO_ROOT)" && bash -lc
endif

PASSTHROUGH_VARS := \
	$(if $(PROFILE),PROFILE=$(PROFILE)) \
	$(if $(FUZZER),FUZZER=$(FUZZER)) \
	$(if $(VARIANT),VARIANT=$(VARIANT)) \
	$(if $(CASSOWIRE_CONFIG),CASSOWIRE_CONFIG=$(CASSOWIRE_CONFIG)) \
	$(if $(AFL_FUZZ_TIMEOUT),AFL_FUZZ_TIMEOUT=$(AFL_FUZZ_TIMEOUT)) \
	$(if $(AFL_FUZZ_CPU),AFL_FUZZ_CPU=$(AFL_FUZZ_CPU)) \
	$(if $(COVERAGE_OUT),COVERAGE_OUT=$(COVERAGE_OUT)) \
	$(if $(FUZZ_DEBUG),FUZZ_DEBUG=$(FUZZ_DEBUG))

.PHONY: help check-target toolchain aflpp aflnet afl-cassowire shell run \
	build prepare-data prepare-seeds fuzz fuzz-qemu cov replay-cov collect-cov crashes

help:
	@printf '%s\n' \
		'Goals: toolchain aflpp aflnet afl-cassowire shell run' \
		'       build prepare-data prepare-seeds fuzz fuzz-qemu cov replay-cov collect-cov crashes' \
		'Required: TARGET=<name> (except toolchain/aflpp/aflnet/afl-cassowire/shell/run)' \
		'Optional: PROFILE=<mode>  FUZZER=aflpp|aflnet  VARIANT=<build-variant>' \
		'          AFL_FUZZ_CPU=<n> (afl-fuzz -b, default 0)' \
		'          WITH_QEMU=0|1 (aflpp QEMU support, default 1)' \
		'          RUN_IN_CONTAINER=1|0 (default 1; 0 runs targets directly)' \
		'' \
		'Examples (host):' \
		'  make aflpp WITH_QEMU=0' \
		'  make afl-cassowire' \
		'  make TARGET=nginx VARIANT=afl-clang-fast build' \
		'  make TARGET=nginx prepare-data' \
		'  make TARGET=nginx FUZZER=aflpp prepare-seeds' \
		'  make TARGET=nginx FUZZER=aflpp fuzz' \
		'  make TARGET=nginx FUZZER=aflnet fuzz' \
		'  make TARGET=cassowire-test-target PROFILE=calc FUZZER=aflpp fuzz' \
		'  make TARGET=cassowire-test-target PROFILE=calc cov' \
		'  make TARGET=nginx replay-cov' \
		'  make TARGET=nginx collect-cov' \
		'  make TARGET=nginx cov' \
		'  make shell' \
		'  make run CMD="make -C targets/nginx build"' \
		'' \
		'Inside the dev container:' \
		'  RUN_IN_CONTAINER=0 make TARGET=nginx build'

check-target:
	@test -n "$(TARGET)" || { \
		echo "error: TARGET is required (e.g. make TARGET=nginx build)" >&2; \
		exit 1; \
	}

toolchain:
	$(PODMAN) build -t $(TOOLCHAIN_IMAGE) \
		-f container/toolchain.Containerfile container/

# Build the fuzzer toolchains (like targets), inside the toolchain container.
aflpp:
	$(PODMAN_RUN) -w $(CONTAINER_WORKDIR)/aflpp \
		$(TOOLCHAIN_IMAGE) make prepare patch submodules build install \
			WITH_QEMU=$(WITH_QEMU)

aflnet:
	$(PODMAN_RUN) -w $(CONTAINER_WORKDIR)/other/aflnet \
		$(TOOLCHAIN_IMAGE) make

# Build the persistent proxy. Assumes `make toolchain` and `make aflpp` ran.
afl-cassowire:
	$(PODMAN_RUN) -w $(CONTAINER_WORKDIR)/afl-cassowire \
		$(TOOLCHAIN_IMAGE) bash -lc \
		'make prepare && { [ -f build/build.ninja ] || make prepare2; } && make build'

shell:
	$(SHELL_CMD)

run:
	@test -n "$(CMD)" || { \
		echo "error: CMD is required (e.g. make run CMD=\"make -C targets/nginx build\")" >&2; \
		exit 1; \
	}
	$(RUN_CMD) '$(CMD)'

# Generic passthrough to the per-target Makefile (the interface).
build: check-target
	$(TARGET_RUN) build$(if $(VARIANT),_$(VARIANT)) \
		$(TARGET_MAKE_ENV) $(PASSTHROUGH_VARS)

prepare-data prepare-seeds cov replay-cov collect-cov crashes: check-target
	$(TARGET_RUN) $@ $(TARGET_MAKE_ENV) $(PASSTHROUGH_VARS)

fuzz: check-target
	$(TARGET_RUN_TTY) fuzz $(TARGET_MAKE_ENV) $(PASSTHROUGH_VARS)

fuzz-qemu: check-target
	$(TARGET_RUN_TTY) fuzz-qemu $(TARGET_MAKE_ENV) $(PASSTHROUGH_VARS)
