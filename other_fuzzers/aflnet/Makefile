include ../../mk/env.mk
include ../../mk/git.mk

GIT_URL := https://github.com/aflnet/aflnet
GIT_COMMIT := 96032f86d0005dfeeb41ea7b31103f1d1ff8f168

src/.cloned:
	$(call GIT_SRC_COMMIT_TARGET_CMD,$(GIT_URL),$(GIT_COMMIT))

src: src/.cloned
.PHONY: src