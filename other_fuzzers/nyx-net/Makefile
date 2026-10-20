include ../../mk/env.mk
include ../../mk/git.mk

GIT_URL := https://github.com/RUB-SysSec/nyx-net
GIT_COMMIT := 354920e8ca381b01b626bad7a42e5974d809117e

src/.cloned:
	$(call GIT_SRC_COMMIT_TARGET_CMD,$(GIT_URL),$(GIT_COMMIT))

src: src/.cloned
.PHONY: src