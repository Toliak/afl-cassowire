include ../_shared/git.mk

TINY_NGINX_URL := https://github.com/gd-arnold/tiny-nginx
TINY_NGINX_COMMIT := 0a4900630457ede33abdb836f54a4d2aee6a6c3b

src:
	$(GIT_CLONE_CMD) $(TINY_NGINX_URL) $@
	cd "$@" && git checkout $(TINY_NGINX_COMMIT)

build:

.PHONY: build