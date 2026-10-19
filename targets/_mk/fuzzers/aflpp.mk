# Fuzzer: our patched AFL++.
#
# Paths resolve from the repo root (see ../env.mk); the repo is mounted at the
# same path inside the toolchain and dev containers. Built AFL++ binaries land in
# aflpp/src/distrib/bin.
#
# Include AFTER ../env.mk (which defines REPO_ROOT).

AFLPP_DIR      := $(REPO_ROOT)/aflpp
AFLPP_SRC_DIR  := $(AFLPP_DIR)/src
AFLPP_BIN_DIR  := $(AFLPP_SRC_DIR)/distrib/bin
AFLPP_CC       := afl-clang-fast
AFLPP_CXX      := afl-clang-fast++

# afl-cassowire proxy binary (built separately, see afl-cassowire/).
AFLPP_CASSOWIRE := $(REPO_ROOT)/afl-cassowire/build/afl-cassowire
