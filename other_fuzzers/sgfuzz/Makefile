include ../../mk/env.mk
include ../../mk/git.mk

GIT_URL := https://github.com/bajinsheng/SGFuzz
GIT_COMMIT := 35f1ffc9482d524b03e54c7a48f4a742ba9fc9a3

src/.cloned:
	$(call GIT_SRC_COMMIT_TARGET_CMD,$(GIT_URL),$(GIT_COMMIT))

src: src/.cloned
.PHONY: src