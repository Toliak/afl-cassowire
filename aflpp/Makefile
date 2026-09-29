MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

AFLPP_URL := https://github.com/aflplusplus/aflplusplus
AFLPP_TAG := v5.02c

AFLPP_MAKE_ARGS := -j$(nproc)
AFLPP_MAKE_ARGS_ADD := 

GIT_ARGS := --progress --depth 1

help:
	@echo "prepare -- git clone the AFL++ repo"

$(MAKEFILE_DIR)/src:
	git clone $(AFLPP_URL) $(GIT_ARGS) --branch=$(AFLPP_TAG) $(MAKEFILE_DIR)/src

prepare: $(MAKEFILE_DIR)/src

$(MAKEFILE_DIR)/src/.patched: prepare
	cd "$(MAKEFILE_DIR)/src" && \
		for F in "$(MAKEFILE_DIR)/patch"/*.patch; do \
			patch -p1 -i "$$F" || exit 1; \
		done
	touch $(MAKEFILE_DIR)/src/.patched

patch: $(MAKEFILE_DIR)/src/.patched

build: patch
	cd "$(MAKEFILE_DIR)/src" && \
		make $(AFLPP_MAKE_ARGS) $(AFLPP_MAKE_ARGS_ADD) \
			PERFORMANCE=1 \
			NO_PYTHON=0 \
			NO_NYX=1 \
			NO_CORESIGHT=1 \
			NO_QEMU=1 \
			NO_FRIDA=1 \
			NO_UNICORN=1

install:
	cd "$(MAKEFILE_DIR)/src" && \
		make $(AFLPP_MAKE_ARGS) $(AFLPP_MAKE_ARGS_ADD) \
			PREFIX=distrib install

.PHONY: help patch prepare build install
