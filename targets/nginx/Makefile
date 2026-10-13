include ../_mk/git.mk
include ../_mk/aflpp.mk
include ../_mk/fuzz.mk

NGINX_URL := https://github.com/nginx/nginx
NGINX_BRANCH := release-1.31.4

BUILD_MAKE_ARGS := -j$(nproc)

src:
	$(GIT_CLONE_CMD) $(NGINX_URL) --branch "$(NGINX_BRANCH)" $@

ALL_BUILD_SUBTARGETS :=	build_clang \
						build_afl-clang-lto \
						build_afl-clang-lto_cmplog \
						build_afl-clang-fast \
						build_afl-clang-fast_cmplog

build_clang: CC=clang
build_afl-clang-lto \
	build_afl-clang-lto_cmplog: CC=afl-clang-lto
build_afl-clang-lto_cmplog: AFL_LLVM_CMPLOG=1
build_afl-clang-fast \
	build_afl-clang-fast_cmplog: CC=afl-clang-fast
build_afl-clang-fast_cmplog: AFL_LLVM_CMPLOG=1

$(ALL_BUILD_SUBTARGETS): build_%:
	export PATH="$(AFLPP_BIN_DIR):$$PATH" && \
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
		make -j$(nproc) && \
		make DESTDIR="./install/$*" install

build: $(ALL_BUILD_SUBTARGETS)

# Ports for the generated configs. cmplog variants use 9xxx ports so the
# main and cmplog nginx instances can run side by side.
# Expand config templates. Supported placeholders:
#   @PORT_MAIN@ @PORT_BACKEND@ @PORT_BACKEND2@ @PORT_BACKEND3@ @TARGET_DIR@
SED_EXPAND       = -e 's/@PORT_MAIN@/$(1)/g' \
                   -e 's/@PORT_BACKEND@/$(2)/g' \
                   -e 's/@PORT_BACKEND2@/$(3)/g' \
                   -e 's/@PORT_BACKEND3@/$(4)/g' \
                   -e 's|@TARGET_DIR@|$(CURDIR)|g'

# Small synthetic test videos, generated instead of being committed.
FFMPEG_SRC       := -f lavfi -i smptebars=duration=2:size=320x240:rate=15
FFMPEG_ENC       := -pix_fmt yuv420p -c:v libx264
FFMPEG_COMMON    := -nostdin -loglevel error -y

# Expand data_template/ into ./data: payload files are copied as-is, the two
# config templates produce the four nginx configs (normal + cmplog), and the
# test videos are rendered with ffmpeg. Safe to re-run (wipes ./data).
data:
	rm -rf ./data && cp -r ./data_template ./data && mkdir -p ./data/dav
	sed $(call SED_EXPAND,8080,8090,8091,8092) ./data_template/nginx.conf     > ./data/nginx.conf
	sed $(call SED_EXPAND,8080,8090,8091,8092) ./data_template/nginx.new.conf > ./data/nginx.new.conf
	sed $(call SED_EXPAND,9080,9090,9091,9092) ./data_template/nginx.conf     > ./data/nginx.cmplog.conf
	sed $(call SED_EXPAND,9080,9090,9091,9092) ./data_template/nginx.new.conf > ./data/nginx.new.cmplog.conf
	ffmpeg $(FFMPEG_SRC) $(FFMPEG_ENC) $(FFMPEG_COMMON)             ./data/www/test.mp4
	ffmpeg $(FFMPEG_SRC) $(FFMPEG_ENC) -f flv $(FFMPEG_COMMON)      ./data/www/test.flv

fuzz: data

fuzz:
	mkdir -p ./out ./in
	cp -f $(FUZZ_SHARED_DIR)/in_http/* ./in/.
ifdef FUZZ_DEBUG
	@echo "AFL++ debug mode"
endif
	export AFL_CASSOWIRE_FORCE_FINAL_LOC=70000 && \
		$(AFL_FUZZ_ENV) afl-fuzz -b 4 -i- -o ./out -x $(FUZZ_SHARED_DIR)/dict/http.dict -t 1500 -c 0 -- \
 		"$$(which afl-cassowire)" --log-level error --config cassowire.yaml proxy
# 		"$$(which afl-cassowire)" --log-level debug --child-output --config cassowire.yaml proxy

.PHONY: build data fuzz