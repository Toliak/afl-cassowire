# Clone/submodule depth. Shallow by default; set GIT_DEPTH= (or GIT_DEPTH=0)
# to fetch full histories. Only affects new clones.
GIT_DEPTH ?= 1
GIT_DEPTH_ARGS := $(if $(filter-out 0,$(strip $(GIT_DEPTH))),--depth $(strip $(GIT_DEPTH)))
GIT_ARGS := --progress $(GIT_DEPTH_ARGS)
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
	{ git checkout $(2) || { git fetch $(GIT_DEPTH_ARGS) origin $(2) && git checkout $(2); }; } && \
	touch .cloned
endef

# Use only inside the `src/.submodules` target.
# Top-level submodules only: QEMU's own configure fetches the nested modules it
# needs. Do not use `--recursive` here: nested pins are non-tip commits (on
# GitLab) that a depth-1 clone cannot always check out.
define GIT_SUBMODULES_TARGET_CMD
cd ./src && \
	git submodule update --progress --init $(GIT_DEPTH_ARGS) $(1) && \
	touch .submodules
endef
