MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

include $(MAKEFILE_DIR).env.mk

# Check .env
REQUIRED_VARS := BASE_IMAGE USER_NAME USER_PASS SSH_ADDR PROJECT_NAME
$(foreach var,$(REQUIRED_VARS),$(if $(value $(var)),,$(error $(var) is not set. Please set it in .env or export it)))

# For docker/podman build
BUILD_ARGS := \
	--build-arg BASE_IMAGE="$(BASE_IMAGE)" \
	--build-arg USER_NAME="$(USER_NAME)" \
	--build-arg USER_PASS="$(USER_PASS)" \
	--build-arg USER_UID="1000" \
	--build-arg USER_GID="1000" \
	--build-arg SSH_PUB_KEY="$(SSH_PUB_KEY)" \
	--build-arg MCE_VERSION="$(MCE_VERSION)" \
	--build-arg VSCODE_VERSION="$(VSCODE_VERSION)"

PODMAN_BIN := podman
PODMAN_JOBS := $(shell nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)
PODMAN_ENV :=

IMAGE_NAME := $(PROJECT_NAME)_dev
CONTAINER_NAME := $(PROJECT_NAME)_dev-run

SHARED_RUN_OPTS := 		--rm \
						-it \
						--security-opt label=disable \
						--device /dev/fuse \
						-e TERM=xterm-256color \
						-p "$(SSH_ADDR):22" \
						-v "$$PWD/../..:/opt/workdir" \
						-v "$$HOME/.local/share/containers/storage:/var/lib/shared:ro" \
						--name "$(CONTAINER_NAME)"

SHARED_BUILD_OPTS :=    $(BUILD_ARGS) \
						-t "$(IMAGE_NAME)" \
						-f ./Containerfile

PODMAN_RUN_MAP :=   --uidmap 1000:0:1 \
					--uidmap 0:1:1000 \
					--uidmap 100000:1001:$(shell expr 65536 - 1000 - 2 - 1) \
					--uidmap 65534:65534:2

.PHONY: podman-up podman-stop podman-build

# ----------------------------------------

all: podman-up

# Or
# @test -f .env || (echo "ERROR: $@ file is missing. Manual configuration required" && exit 1)

# ----------------------------------------

podman-up: podman-build
	@echo "Run (podman) dev container with:"
	@echo "  SSH_ADDR: $(SSH_ADDR)"

	$(PODMAN_ENV) "$(PODMAN_BIN)" \
				run \
				$(SHARED_RUN_OPTS) \
				$(PODMAN_RUN_MAP)\
				"$(IMAGE_NAME)"

podman-stop:
	@echo "Stop (podman) dev container"
	$(PODMAN_ENV) "$(PODMAN_BIN)" \
				stop \
				$(CONTAINER_NAME)

podman-build:
	@echo "Building (podman) with:"
	@echo "  BASE_IMAGE: $(BASE_IMAGE)"
	@echo "  USER_NAME:   $(USER_NAME)"

	$(PODMAN_ENV) "$(PODMAN_BIN)" \
				build . \
				--jobs="$(PODMAN_JOBS)" \
				$(SHARED_BUILD_OPTS)
