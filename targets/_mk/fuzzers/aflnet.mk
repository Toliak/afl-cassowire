# Fuzzer: AFLNet (vendor fork of AFL 2.52b for stateful network fuzzing).
#
# Built in-place: binaries land in other/aflnet/ (the source root).
# Paths resolve from the repo root (see ../env.mk).
#
# Include AFTER ../env.mk (which defines REPO_ROOT).

AFLNET_DIR     := $(REPO_ROOT)/other/aflnet
AFLNET_BIN_DIR := $(AFLNET_DIR)
AFLNET_CC      := afl-clang
AFLNET_CXX     := afl-clang++
