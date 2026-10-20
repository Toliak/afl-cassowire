include ../../mk/env.mk

LLVM_VERSION := 15.0.7
SRC_DIR      := src/llvm-$(LLVM_VERSION)

TARBALL_LLVM              := llvm-$(LLVM_VERSION).src.tar.xz
TARBALL_CLANG             := clang-$(LLVM_VERSION).src.tar.xz
TARBALL_CLANG_TOOLS_EXTRA := clang-tools-extra-$(LLVM_VERSION).src.tar.xz
TARBALL_COMPILER_RT       := compiler-rt-$(LLVM_VERSION).src.tar.xz
TARBALL_CMAKE             := cmake-$(LLVM_VERSION).src.tar.xz

URL_LLVM              := https://github.com/llvm/llvm-project/releases/download/llvmorg-$(LLVM_VERSION)/$(TARBALL_LLVM)
URL_CLANG             := https://github.com/llvm/llvm-project/releases/download/llvmorg-$(LLVM_VERSION)/$(TARBALL_CLANG)
URL_CLANG_TOOLS_EXTRA := https://github.com/llvm/llvm-project/releases/download/llvmorg-$(LLVM_VERSION)/$(TARBALL_CLANG_TOOLS_EXTRA)
URL_COMPILER_RT       := https://github.com/llvm/llvm-project/releases/download/llvmorg-$(LLVM_VERSION)/$(TARBALL_COMPILER_RT)
URL_CMAKE             := https://github.com/llvm/llvm-project/releases/download/llvmorg-$(LLVM_VERSION)/$(TARBALL_CMAKE)

SHA256_LLVM              := 4ad8b2cc8003c86d0078d15d987d84e3a739f24aae9033865c027abae93ee7a4
SHA256_CLANG             := a6b673ef15377fb46062d164e8ddc4d05c348ff8968f015f7f4af03f51000067
SHA256_CLANG_TOOLS_EXTRA := 809a2ef46d46be3b83ca389356404ac041fa6d8f5496cb02ec35d252afb64fd1
SHA256_COMPILER_RT       := 353832c66cce60931ea0413b3c071faad59eefa70d02c97daa8978b15e4b25b7
SHA256_CMAKE             := 8986f29b634fdaa9862eedda78513969fe9788301c9f2d938f4c10a3e7a3e7ea

TARBALLS := dl/$(TARBALL_LLVM) \
	dl/$(TARBALL_CLANG) \
	dl/$(TARBALL_CLANG_TOOLS_EXTRA) \
	dl/$(TARBALL_COMPILER_RT) \
	dl/$(TARBALL_CMAKE)

# DOWNLOAD_TARGET(name, filename, url, sha256)
define DOWNLOAD_TARGET
download_$(1): dl/$(2)

dl/$(2):
	@mkdir -p dl
	@rm -f $$@.part
	@wget -q -O $$@.part $(3)
	@printf '%s  %s\n' '$(4)' '$$@.part' | sha256sum -c -
	@mv $$@.part $$@
endef

$(eval $(call DOWNLOAD_TARGET,llvm,$(TARBALL_LLVM),$(URL_LLVM),$(SHA256_LLVM)))
$(eval $(call DOWNLOAD_TARGET,clang,$(TARBALL_CLANG),$(URL_CLANG),$(SHA256_CLANG)))
$(eval $(call DOWNLOAD_TARGET,clang-tools-extra,$(TARBALL_CLANG_TOOLS_EXTRA),$(URL_CLANG_TOOLS_EXTRA),$(SHA256_CLANG_TOOLS_EXTRA)))
$(eval $(call DOWNLOAD_TARGET,compiler-rt,$(TARBALL_COMPILER_RT),$(URL_COMPILER_RT),$(SHA256_COMPILER_RT)))
$(eval $(call DOWNLOAD_TARGET,cmake,$(TARBALL_CMAKE),$(URL_CMAKE),$(SHA256_CMAKE)))

DOWNLOAD_TARGETS := $(addprefix download_,llvm clang clang-tools-extra compiler-rt cmake)

BUILD_DIR    := src/build
INSTALL_DIR  ?= src/dist
BUILD_TYPE   ?= Release
LLVM_TARGETS ?= X86
JOBS         ?= $(NUM_CORES)
LINK_JOBS    ?= 1

# clang, clang-tools-extra and compiler-rt are discovered from the legacy
# in-tree layout prepared above (tools/clang, tools/clang/tools/extra,
# projects/compiler-rt). LLVM_ENABLE_PROJECTS is intentionally left unset: it
# requires side-by-side source directories (../clang, ../compiler-rt).
CMAKE_ARGS := \
	-G Ninja \
	-DCMAKE_BUILD_TYPE=$(BUILD_TYPE) \
	-DCMAKE_INSTALL_PREFIX=$(abspath $(INSTALL_DIR)) \
	-DCMAKE_C_COMPILER=clang \
	-DCMAKE_CXX_COMPILER=clang++ \
	-DLLVM_TARGETS_TO_BUILD=$(LLVM_TARGETS) \
	-DLLVM_BUILD_LLVM_DYLIB=ON \
	-DLLVM_LINK_LLVM_DYLIB=ON \
	-DLLVM_INCLUDE_TESTS=OFF \
	-DLLVM_INCLUDE_EXAMPLES=OFF \
	-DLLVM_INCLUDE_BENCHMARKS=OFF \
	-DLLVM_INCLUDE_DOCS=OFF \
	-DLLVM_ENABLE_ASSERTIONS=OFF \
	-DLLVM_PARALLEL_LINK_JOBS=$(LINK_JOBS) \
	-DCMAKE_EXE_LINKER_FLAGS="-Wl,--undefined-version" \
	-DCMAKE_SHARED_LINKER_FLAGS="-Wl,--undefined-version" \
	-DCMAKE_MODULE_LINKER_FLAGS="-Wl,--undefined-version" \
	-DLLVM_USE_LINKER=lld

PKG_NAME       ?= llvm-15
PKG_VERSION    ?= $(LLVM_VERSION)-1
PKG_ARCH       ?= $(shell dpkg --print-architecture)
PKG_PREFIX     ?= /usr/lib/llvm-15
PKG_DIR        ?= pkg
PKG_ROOT       := $(PKG_DIR)/root
DEB_FILE       := $(PKG_DIR)/$(PKG_NAME)_$(PKG_VERSION)_$(PKG_ARCH).deb
DEB_MAINTAINER ?= toliak <toliakpurple@gmail.com>
DEB_DEPENDS    ?= libc6 (>= 2.34), libgcc-s1, libstdc++6, liblzma5, libtinfo6, libxml2, zlib1g, libzstd1

help:
	@echo "download    -- download and verify the LLVM $(LLVM_VERSION) tarballs into dl/"
	@echo "verify      -- re-check SHA-256 of the tarballs already present in dl/"
	@echo "prepare     -- download, extract and lay out the LLVM $(LLVM_VERSION) source tree"
	@echo "configure   -- configure the LLVM build in $(BUILD_DIR)"
	@echo "build       -- compile LLVM, clang, clang-tools-extra and compiler-rt"
	@echo "install     -- install into $(INSTALL_DIR)"
	@echo "deb         -- build $(DEB_FILE) from a staged $(PKG_PREFIX) install"
	@echo "clean       -- remove the extracted source tree (src/)"
	@echo "clean-build -- remove build artifacts and stale in-source CMake files"
	@echo "clean-pkg   -- remove packaging staging and the generated .deb (pkg/)"
	@echo "distclean   -- clean, and remove downloaded tarballs (dl/)"

download: $(DOWNLOAD_TARGETS)

verify:
	@printf '%s  %s\n' \
		'$(SHA256_LLVM)' 'dl/$(TARBALL_LLVM)' \
		'$(SHA256_CLANG)' 'dl/$(TARBALL_CLANG)' \
		'$(SHA256_CLANG_TOOLS_EXTRA)' 'dl/$(TARBALL_CLANG_TOOLS_EXTRA)' \
		'$(SHA256_COMPILER_RT)' 'dl/$(TARBALL_COMPILER_RT)' \
		'$(SHA256_CMAKE)' 'dl/$(TARBALL_CMAKE)' | sha256sum -c -

prepare: src/.prepared

src: prepare

src/.prepared: $(TARBALLS)
	@rm -rf src
	@mkdir -p src
	@tar -xf dl/$(TARBALL_LLVM) -C src
	@mv src/llvm-$(LLVM_VERSION).src $(SRC_DIR)
	@tar -xf dl/$(TARBALL_CLANG) -C $(SRC_DIR)/tools
	@mv $(SRC_DIR)/tools/clang-$(LLVM_VERSION).src $(SRC_DIR)/tools/clang
	@tar -xf dl/$(TARBALL_CLANG_TOOLS_EXTRA) -C $(SRC_DIR)/tools/clang/tools
	@mv $(SRC_DIR)/tools/clang/tools/clang-tools-extra-$(LLVM_VERSION).src \
		$(SRC_DIR)/tools/clang/tools/extra
	@tar -xf dl/$(TARBALL_COMPILER_RT) -C $(SRC_DIR)/projects
	@mv $(SRC_DIR)/projects/compiler-rt-$(LLVM_VERSION).src \
		$(SRC_DIR)/projects/compiler-rt
	@rm -rf dl/cmake-$(LLVM_VERSION).src
	@tar -xf dl/$(TARBALL_CMAKE) -C dl
	@cp dl/cmake-$(LLVM_VERSION).src/Modules/* $(SRC_DIR)/cmake/modules/
	@rm -rf dl/cmake-$(LLVM_VERSION).src
	@touch $@

configure: src/.prepared
	cmake -S $(SRC_DIR) -B $(BUILD_DIR) $(CMAKE_ARGS)

build: configure
	cmake --build $(BUILD_DIR) -j$(JOBS)

install: build
	cmake --install $(BUILD_DIR)

deb: $(DEB_FILE)

$(DEB_FILE): build
	@rm -rf "$(PKG_ROOT)"
	@mkdir -p "$(PKG_ROOT)/DEBIAN" "$(PKG_ROOT)/usr/bin"
	@DESTDIR="$(abspath $(PKG_ROOT))" cmake --install "$(BUILD_DIR)" --prefix "$(PKG_PREFIX)"
	@for f in "$(PKG_ROOT)$(PKG_PREFIX)/bin/"*; do \
		name=$$(basename "$$f"); \
		case "$$name" in \
			*-15) ;; \
			*) ln -sfn "../lib/llvm-15/bin/$$name" "$(PKG_ROOT)/usr/bin/$$name-15" ;; \
		esac; \
	done
	@install -D -m 0644 "$(SRC_DIR)/LICENSE.TXT" \
		"$(PKG_ROOT)/usr/share/doc/$(PKG_NAME)/copyright"
	@sed -i 's|^set(LLVM_DEFAULT_EXTERNAL_LIT .*|set(LLVM_DEFAULT_EXTERNAL_LIT "")|' \
		"$(PKG_ROOT)$(PKG_PREFIX)/lib/cmake/llvm/LLVMConfig.cmake"
	@{ \
		echo "Package: $(PKG_NAME)"; \
		echo "Version: $(PKG_VERSION)"; \
		echo "Architecture: $(PKG_ARCH)"; \
		echo "Maintainer: $(DEB_MAINTAINER)"; \
		echo "Installed-Size: $$(du -sk "$(PKG_ROOT)/usr" | cut -f1)"; \
		echo "Depends: $(DEB_DEPENDS)"; \
		echo "Section: devel"; \
		echo "Priority: optional"; \
		echo "Homepage: https://llvm.org/"; \
		echo "Description: LLVM $(LLVM_VERSION) toolchain with Clang and compiler-rt"; \
		echo " Self-built LLVM $(LLVM_VERSION), Clang, clang-tools-extra and compiler-rt."; \
		echo " Installed under $(PKG_PREFIX) with versioned symlinks in /usr/bin."; \
	} > "$(PKG_ROOT)/DEBIAN/control"
	@( cd "$(PKG_ROOT)" && find usr -type f -print0 | xargs -0 md5sum > DEBIAN/md5sums )
	@chmod 0644 "$(PKG_ROOT)/DEBIAN/control" "$(PKG_ROOT)/DEBIAN/md5sums"
	@dpkg-deb --root-owner-group --build "$(PKG_ROOT)" "$(DEB_FILE)"
	@dpkg-deb --info "$(DEB_FILE)"

clean-build:
	rm -rf $(BUILD_DIR) \
		$(SRC_DIR)/build $(SRC_DIR)/CMakeCache.txt $(SRC_DIR)/CMakeFiles

clean:
	rm -rf src

clean-pkg:
	rm -rf $(PKG_DIR)

distclean: clean clean-pkg
	rm -rf dl

.PHONY: help download verify prepare src configure build install deb clean clean-build \
	clean-pkg distclean $(DOWNLOAD_TARGETS)

