GIT_ARGS := --progress --depth 1
GIT_ARGS_ADD := 
GIT := git
GIT_CLONE_CMD = $(GIT) clone $(GIT_ARGS) $(GIT_ARGS_ADD)

help:
	@echo "TODO"


targets/tiny-nginx:

NGINX_URL := https://github.com/nginx/nginx
NGINX_TAG := release-1.31.4

targets/nginx:
	$(GIT_CLONE_CMD) --branch=$(NGINX_TAG) $(NGINX_URL) $@

HAPROXY_URL := https://github.com/haproxy/haproxy
HAPROXY_TAG := v3.4.0

targets/haproxy:
	$(GIT_CLONE_CMD) --branch=$(HAPROXY_TAG) $(HAPROXY_URL) $@

ALL_TARGETS := targets/tiny-nginx targets/nginx targets/haproxy

clone: $(ALL_TARGETS)

.PHONY: help clone
