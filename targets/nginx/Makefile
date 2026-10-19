include ../_mk/env.mk
include ../_mk/git.mk
include ../_mk/fuzzers/aflpp.mk
include ../_mk/fuzzers/aflnet.mk

TARGET_NAME := nginx

NGINX_URL    := https://github.com/nginx/nginx
NGINX_BRANCH := release-1.31.4

# ---------------------------------------------------------------------------
# profile selection (keep in sync with PROFILES in orchestrator.py)
# ---------------------------------------------------------------------------

DEFAULT_PROFILE := http
PROFILES := http

# Coverage/triage goals without an explicit profile aggregate every profile;
# seed/fuzz goals default to the target's primary profile.
ifeq ($(filter cov replay-cov collect-cov crashes,$(MAKECMDGOALS)),)
PROFILE ?= $(DEFAULT_PROFILE)
endif
ifneq ($(filter-out $(PROFILES),$(PROFILE)),)
$(error invalid PROFILE '$(PROFILE)'; valid: $(PROFILES) or empty for all profiles)
endif

PROFILE_ARG  = $(if $(PROFILE),--profile $(PROFILE))
FUZZ_PROFILE = $(or $(PROFILE),$(DEFAULT_PROFILE))

# ---------------------------------------------------------------------------
# source
# ---------------------------------------------------------------------------

src:
	$(GIT_CLONE_CMD) $(NGINX_URL) --branch "$(NGINX_BRANCH)" $@

# ---------------------------------------------------------------------------
# build variants (run inside the toolchain/dev container)
# ---------------------------------------------------------------------------

ALL_BUILD_SUBTARGETS := build_clang \
	build_afl-clang-lto build_afl-clang-lto_cmplog \
	build_afl-clang-fast build_afl-clang-fast_cmplog \
	build_aflnet build_gcov

$(ALL_BUILD_SUBTARGETS): AFL_LLVM_CMPLOG := 0
$(ALL_BUILD_SUBTARGETS): CC_ADD_FLAGS :=
$(ALL_BUILD_SUBTARGETS): LD_ADD_FLAGS :=
$(ALL_BUILD_SUBTARGETS): FZ_BIN_DIR :=

build_clang:                 CC := clang
build_afl-clang-lto:         CC := afl-clang-lto
build_afl-clang-lto_cmplog:  CC := afl-clang-lto
build_afl-clang-fast:        CC := afl-clang-fast
build_afl-clang-fast_cmplog: CC := afl-clang-fast
build_aflnet:                CC := afl-clang
build_gcov:                  CC := gcc

build_afl-clang-lto:         FZ_BIN_DIR := $(AFLPP_BIN_DIR)
build_afl-clang-lto_cmplog:  FZ_BIN_DIR := $(AFLPP_BIN_DIR)
build_afl-clang-fast:        FZ_BIN_DIR := $(AFLPP_BIN_DIR)
build_afl-clang-fast_cmplog: FZ_BIN_DIR := $(AFLPP_BIN_DIR)
build_aflnet:                FZ_BIN_DIR := $(AFLNET_BIN_DIR)

build_afl-clang-lto_cmplog:  AFL_LLVM_CMPLOG := 1
build_afl-clang-fast_cmplog: AFL_LLVM_CMPLOG := 1

build_gcov: CC_ADD_FLAGS := -fprofile-arcs -ftest-coverage
build_gcov: LD_ADD_FLAGS := -fprofile-arcs -ftest-coverage

build: $(ALL_BUILD_SUBTARGETS)

$(ALL_BUILD_SUBTARGETS): build_%:
	export PATH="$(if $(FZ_BIN_DIR),$(FZ_BIN_DIR):,)$$PATH"; \
		export AFL_LLVM_CMPLOG="$(AFL_LLVM_CMPLOG)"; \
		cd ./src && \
		{ make clean || true; } && \
		./auto/configure \
			--prefix=/etc/nginx \
			--conf-path=/etc/nginx/nginx.conf \
			--sbin-path=/usr/bin/nginx \
			--modules-path=/usr/lib/nginx/modules \
			--pid-path=/run/nginx.pid \
			--lock-path=/run/lock/nginx.lock \
			--user=http \
			--group=http \
			--http-log-path=/var/log/nginx/access.log \
			--error-log-path=stderr \
			--http-client-body-temp-path=/var/lib/nginx/client-body \
			--http-proxy-temp-path=/var/lib/nginx/proxy \
			--http-fastcgi-temp-path=/var/lib/nginx/fastcgi \
			--http-scgi-temp-path=/var/lib/nginx/scgi \
			--http-uwsgi-temp-path=/var/lib/nginx/uwsgi \
			--with-cc="$(CC)" \
			--with-cc-opt="$(CC_ADD_FLAGS)" \
			--with-ld-opt="$(LD_ADD_FLAGS)" \
			--with-compat \
			--with-debug \
			--with-file-aio \
			--with-http_addition_module \
			--with-http_auth_request_module \
			--with-http_dav_module \
			--with-http_degradation_module \
			--with-http_flv_module \
			--with-http_gunzip_module \
			--with-http_gzip_static_module \
			--with-http_mp4_module \
			--with-http_perl_module=dynamic \
			--with-http_random_index_module \
			--with-http_realip_module \
			--with-http_secure_link_module \
			--with-http_slice_module \
			--with-http_ssl_module \
			--with-http_stub_status_module \
			--with-http_sub_module \
			--with-http_v2_module \
			--with-http_v3_module \
			--with-mail=dynamic \
			--with-mail_ssl_module \
			--with-pcre-jit \
			--with-stream=dynamic \
			--with-stream_ssl_module \
			--with-stream_ssl_preread_module \
			--with-threads \
		&& \
		mkdir -p "./install/$*" && \
		make -j$(NUM_CORES) && \
		make DESTDIR="./install/$*" install

# ---------------------------------------------------------------------------
# data / seeds / fuzz / coverage / crashes (delegated to the orc helper)
# ---------------------------------------------------------------------------

prepare-data:
	$(ORC) $(TARGET_NAME) prepare-data
	mkdir -p ./data/dav
	ffmpeg -nostdin -loglevel error -y \
		-f lavfi -i smptebars=duration=2:size=320x240:rate=15 \
		-pix_fmt yuv420p -c:v libx264 ./data/www/test.mp4
	ffmpeg -nostdin -loglevel error -y \
		-f lavfi -i smptebars=duration=2:size=320x240:rate=15 \
		-pix_fmt yuv420p -c:v libx264 -f flv ./data/www/test.flv

prepare-seeds:
	$(ORC) $(TARGET_NAME) prepare-seeds --fuzzer $(FUZZER) $(PROFILE_ARG) --out $(AFL_IN_DIR)

CASSOWIRE_CONFIG ?= data/cassowire.yaml
FUZZER           ?= aflpp
AFL_FUZZ_CPU     ?= 0
AFL_IN_DIR       ?= in/$(FUZZ_PROFILE)
AFL_OUT_DIR      ?= out/$(FUZZ_PROFILE)
AFL_FUZZ_DICT    ?= $(REPO_ROOT)/targets/_fuzz/dict/$(FUZZ_PROFILE).dict
COVERAGE_OUT     ?= $(if $(PROFILE),cov/$(PROFILE),cov)

fuzz: fuzz-$(FUZZER)

fuzz-aflpp:
	mkdir -p "$(AFL_IN_DIR)" "$(AFL_OUT_DIR)"
	PATH="$(AFLPP_BIN_DIR):$$PATH" \
	AFL_CASSOWIRE_FORCE_FINAL_LOC=70000 AFL_ALLOW_CORES=1 \
		afl-fuzz -b $(AFL_FUZZ_CPU) -i "$(AFL_IN_DIR)" -o "$(AFL_OUT_DIR)" \
			-x $(AFL_FUZZ_DICT) -t 1500 -c 0 -- \
			$(AFLPP_CASSOWIRE) --log-level error --config $(CASSOWIRE_CONFIG) proxy

fuzz-aflnet:
	mkdir -p "$(AFL_IN_DIR)" "$(AFL_OUT_DIR)"
	PATH="$(AFLNET_BIN_DIR):$$PATH" \
		afl-fuzz -d -i "$(AFL_IN_DIR)" -o "$(AFL_OUT_DIR)" -N tcp://127.0.0.1/8080 -P HTTP -D 10000 -q 3 -s 3 -E -K -R -- \
			./src/install/aflnet/usr/bin/nginx

cov: replay-cov collect-cov

replay-cov:
	$(ORC) $(TARGET_NAME) replay-cov $(PROFILE_ARG)

collect-cov:
	$(ORC) $(TARGET_NAME) collect-cov --out $(COVERAGE_OUT)

crashes:
	$(ORC) $(TARGET_NAME) collect-crashes $(PROFILE_ARG)

.PHONY: src build prepare-data prepare-seeds fuzz fuzz-aflpp fuzz-aflnet cov replay-cov collect-cov crashes $(ALL_BUILD_SUBTARGETS)
