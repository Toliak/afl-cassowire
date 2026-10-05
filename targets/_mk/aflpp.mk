__MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

AFLPP_DISTRIB_DIR := $(realpath "$(__MAKEFILE_DIR)/../../aflpp/src/distrib")
AFLPP_BIN_DIR := $(AFLPP_DISTRIB_DIR)/bin