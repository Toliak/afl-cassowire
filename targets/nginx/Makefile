include ../_mk/container.mk
include ../_mk/git.mk
include ../_mk/fuzzers/aflpp.mk
include ../_mk/fuzzers/aflnet.mk

TARGET_NAME := nginx
CTR_W       := $(CONTAINER_WORKDIR)/targets/$(TARGET_NAME)

NGINX_URL    := https://github.com/nginx/nginx
NGINX_BRANCH := release-1.31.4

# ---------------------------------------------------------------------------
# source
# ---------------------------------------------------------------------------

src:
	$(GIT_CLONE_CMD) $(NGINX_URL) --branch "$(NGINX_BRANCH)" $@

# ---------------------------------------------------------------------------
# build variants (run inside the toolchain container)
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
	$(PODMAN_RUN) -w $(CTR_W) $(TOOLCHAIN_IMAGE) bash -lc '\
		export PATH="$(if $(FZ_BIN_DIR),$(FZ_BIN_DIR):,)$$PATH" && \
		export AFL_LLVM_CMPLOG="$(AFL_LLVM_CMPLOG)" && \
		cd ./src && \
		make clean || true && \
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
		make -j$$(nproc) && \
		make DESTDIR="./install/$*" install'

# ---------------------------------------------------------------------------
# data / seeds / fuzz / coverage / crashes (delegated to the orc helper)
# ---------------------------------------------------------------------------

prepare-data:
	$(ORC) $(TARGET_NAME) prepare-data
	mkdir -p ./data/dav
	$(PODMAN_RUN) -w $(CTR_W) $(TOOLCHAIN_IMAGE) bash -lc '\
		ffmpeg -nostdin -loglevel error -y \
			-f lavfi -i smptebars=duration=2:size=320x240:rate=15 \
			-pix_fmt yuv420p -c:v libx264 ./data/www/test.mp4 && \
		ffmpeg -nostdin -loglevel error -y \
			-f lavfi -i smptebars=duration=2:size=320x240:rate=15 \
			-pix_fmt yuv420p -c:v libx264 -f flv ./data/www/test.flv'

prepare-seeds:
	$(ORC) $(TARGET_NAME) prepare-seeds --fuzzer $(FUZZER)

CASSOWIRE_CONFIG ?= cassowire.yaml
FUZZER           ?= aflpp

fuzz: fuzz-$(FUZZER)

fuzz-aflpp:
	$(PODMAN_RUN_TTY) -w $(CTR_W) -e AFL_CASSOWIRE_FORCE_FINAL_LOC=70000 -e AFL_ALLOW_CORES=1 \
		$(TOOLCHAIN_IMAGE) bash -lc '\
		mkdir -p ./out ./in && \
		export PATH="$(AFLPP_BIN_DIR):$$PATH" && \
		afl-fuzz -b 4 -i ./in -o ./out -x $(CONTAINER_WORKDIR)/targets/_fuzz/dict/http.dict -t 1500 -c 0 -- \
			$(AFLPP_CASSOWIRE) --log-level error --config $(CASSOWIRE_CONFIG) proxy'

fuzz-aflnet:
	$(PODMAN_RUN_TTY) -w $(CTR_W) \
		$(TOOLCHAIN_IMAGE) bash -lc '\
		mkdir -p ./out ./in && \
		export PATH="$(AFLNET_BIN_DIR):$$PATH" && \
		afl-fuzz -d -i ./in -o ./out -N tcp://127.0.0.1/8080 -P HTTP -D 10000 -q 3 -s 3 -E -K -R -- \
			./src/install/aflnet/usr/bin/nginx'

cov:
	$(ORC) $(TARGET_NAME) collect-cov

crashes:
	$(ORC) $(TARGET_NAME) collect-crashes

.PHONY: src build prepare-data prepare-seeds fuzz fuzz-aflpp fuzz-aflnet cov crashes $(ALL_BUILD_SUBTARGETS)