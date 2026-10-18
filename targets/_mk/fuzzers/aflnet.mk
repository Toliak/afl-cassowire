# Fuzzer: AFLNet (vendor fork of AFL 2.52b for stateful network fuzzing).
#
# Built in-place: binaries land in other/aflnet/ (the source root).
# Paths are CONTAINER paths; include AFTER ../container.mk.

AFLNET_DIR     := $(CONTAINER_WORKDIR)/other/aflnet
AFLNET_BIN_DIR := $(AFLNET_DIR)
AFLNET_CC      := afl-clang
AFLNET_CXX     := afl-clang++