# Shared podman wrapper for running targets' build/fuzz/assist steps in the
# toolchain container. Include this from a per-target Makefile to get PODMAN_RUN,
# PODMAN_RUN_TTY and ORC.
#
# Rootless podman provides user-mode networking by default, so each `podman run`
# fuzz step is network-isolated (no explicit --network needed).

__MAKEFILE_DIR := $(strip $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
_ORC_ROOT      := $(realpath $(__MAKEFILE_DIR)/..)
_REPO_ROOT     := $(realpath $(_ORC_ROOT)/..)

TOOLCHAIN_IMAGE   ?= localhost/afl-cassowire-toolchain:latest
CONTAINER_WORKDIR ?= /work

# Base non-interactive run.
PODMAN_RUN = podman run --rm --userns=keep-id \
	-v "$(_REPO_ROOT):$(CONTAINER_WORKDIR):Z"

# Interactive run (afl-fuzz UI / stdin corpus -i-).
PODMAN_RUN_TTY = $(PODMAN_RUN) -it

# Run the Python helper inside the container (never on the host).
ORC = $(PODMAN_RUN) \
	-w $(CONTAINER_WORKDIR)/targets/_orc \
	-e ORC_WORKDIR=$(CONTAINER_WORKDIR) \
	-e PYTHONPATH=$(CONTAINER_WORKDIR)/targets/_orc/src \
	$(TOOLCHAIN_IMAGE) python3 -m orc