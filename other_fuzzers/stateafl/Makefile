include ../../mk/env.mk
include ../../mk/git.mk

GIT_URL := https://github.com/stateafl/stateafl
GIT_COMMIT := d923e22f7b2688db45b08f3fa3a29a566e7ff3a4

src/.cloned:
	$(call GIT_SRC_COMMIT_TARGET_CMD,$(GIT_URL),$(GIT_COMMIT))

src: src/.cloned
.PHONY: src