MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

AFLPP_URL := https://github.com/aflplusplus/aflplusplus
AFLPP_TAG := v5.02c

GIT_ARGS := --progress --depth 1

help:
	@echo "$(MAKEFILE_DIR)/src -- git clone the AFL++ repo"

$(MAKEFILE_DIR)/src:
	git clone $(AFLPP_URL) $(GIT_ARGS) --branch=$(AFLPP_TAG) $(MAKEFILE_DIR)/src

patch:
	@echo TODO
	exit 1

.PHONY: help patch
