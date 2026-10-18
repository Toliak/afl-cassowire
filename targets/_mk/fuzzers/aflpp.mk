# Fuzzer: our patched AFL++.
#
# Paths are CONTAINER paths (the repo is mounted at $(CONTAINER_WORKDIR)); the
# already-built AFL++ binaries land in aflpp/src/distrib/bin.
#
# Include AFTER ../container.mk (which defines CONTAINER_WORKDIR).

AFLPP_DIR      := $(CONTAINER_WORKDIR)/aflpp
AFLPP_SRC_DIR  := $(AFLPP_DIR)/src
AFLPP_BIN_DIR  := $(AFLPP_SRC_DIR)/distrib/bin
AFLPP_CC       := afl-clang-fast
AFLPP_CXX      := afl-clang-fast++

# afl-cassowire proxy binary (built separately, see afl-cassowire/).
AFLPP_CASSOWIRE := $(CONTAINER_WORKDIR)/afl-cassowire/build/afl-cassowire