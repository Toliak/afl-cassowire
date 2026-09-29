MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

GIT_ARGS := --progress --depth 1

TINY_NGINX_URL := https://github.com/gd-arnold/tiny-nginx

NGINX_URL := https://github.com/nginx/nginx
NGINX_TAG := release-1.31.4

HAPROXY_URL := https://github.com/haproxy/haproxy
HAPROXY_TAG := v3.4.0

help:
	@echo "clone -- clone all the target repositories"
	@echo "  tiny-nginx -- clone tiny-nginx"
	@echo "  nginx -- clone nginx"
	@echo "  haproxy -- clone haproxy"

tiny-nginx:
	git clone $(GIT_ARGS) $(TINY_NGINX_URL)

nginx:
	git clone $(GIT_ARGS) --branch=$(NGINX_TAG) $(NGINX_URL)

haproxy:
	git clone $(GIT_ARGS) --branch=$(HAPROXY_TAG) $(HAPROXY_URL)

clone: tiny-nginx nginx haproxy

.PHONY: help clone
