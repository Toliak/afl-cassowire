# Plain, container-local environment for per-target Makefiles.
#
# Include this from a target Makefile:
#
#   include ../_mk/env.mk
#
# There is deliberately no podman here: these recipes run inside the toolchain
# container (via the root Makefile) or directly inside the dev container. Paths
# are derived from this file's location, so the same recipes work in both when
# the repo is mounted at the same path.

__ENV_MK_DIR := $(strip $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
REPO_ROOT    := $(realpath $(__ENV_MK_DIR)/../..)
TARGETS_DIR  := $(REPO_ROOT)/targets
TARGET_DIR    = $(TARGETS_DIR)/$(TARGET_NAME)

NUM_CORES    := $(shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)

# The orc helper renders container-absolute paths into generated configs.
ORC_WORKDIR ?= $(REPO_ROOT)
ORC_PYTHON  ?= $(if $(wildcard $(REPO_ROOT)/.venv/bin/python),$(REPO_ROOT)/.venv/bin/python,python3)

ORC = ORC_WORKDIR=$(ORC_WORKDIR) PYTHONPATH=$(REPO_ROOT)/targets/_orc/src \
	$(ORC_PYTHON) -m orc
