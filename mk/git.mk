GIT_ARGS := --progress --depth 1
GIT_ARGS_ADD := 
GIT := git
GIT_CLONE_CMD = $(GIT) clone $(GIT_ARGS) $(GIT_ARGS_ADD)

# Use only inside the `src/.cloned` target
define GIT_SRC_TAG_TARGET_CMD
git clone $(1) $(GIT_ARGS) --branch=$(2) ./src && \
	touch ./src/.cloned
endef

# Use only inside the `src/.cloned` target
define GIT_SRC_COMMIT_TARGET_CMD
$(GIT_CLONE_CMD) $(1) ./src && \
	cd ./src && \
	{ git checkout $(2) || { git fetch --depth 1 origin $(2) && git checkout $(2); }; } && \
	touch .cloned
endef

# Use only inside the `src/.submodules` target.
# Shallow top-level submodules only: QEMU's own configure fetches the nested
# modules it needs. Do not use `--recursive --depth 1` here: nested pins are
# non-tip commits (on GitLab) that a depth-1 clone cannot always check out.
define GIT_SUBMODULES_TARGET_CMD
cd ./src && \
	git submodule update --progress --init --depth 1 $(1) && \
	touch .submodules
endef
