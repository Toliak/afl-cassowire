# Toolchain container: build + fuzz environment for all targets.
#
# Built once (`podman build`); every target build/fuzz/assist step then runs via
# `podman run` against this image (incremental builds live on the host volume,
# mounted at /opt/workdir).

ARG BASE_IMAGE="debian:trixie-20260610"
FROM ${BASE_IMAGE} AS target

ENV DEBIAN_FRONTEND=noninteractive

# Enable apt-get cache, see https://stackoverflow.com/a/79936062/14142236
RUN [ -f "/etc/apt/apt.conf.d/docker-clean" ] && \
    mv /etc/apt/apt.conf.d/docker-clean /etc/apt/apt.conf.d/docker-clean.disabled || \
    true

RUN --mount=type=cache,sharing=locked,target=/var/cache/apt \
    --mount=type=cache,sharing=locked,target=/var/lib/apt \
\
    apt-get update -y --allow-releaseinfo-change && \
    apt-get install -y --no-install-recommends \
        # build system
        make cmake meson ninja-build git patch autoconf automake libtool pkg-config \
        # compilers / LLVM
        lld gcc g++ build-essential flex bison \
        # LLVM 
        clang-22 clang-tools-22 libclang-rt-22-dev llvm-22-dev \
#        clang-19 clang-tools-19 libclang-rt-19-dev llvm-19-dev \
#        clang-17 clang-tools-17 libclang-rt-17-dev llvm-17-dev \
        # AFL++ / QEMU deps
        libglib2.0-dev libpixman-1-dev qemu-user qemu-user-static \
        # honggfuzz deps
        binutils-dev libunwind-dev libblocksruntime-dev \
        # AFLNet deps
        libpcap-dev libcap-dev graphviz-dev \
        # NGINX / HAProxy deps
        libpcre2-dev zlib1g-dev libssl-dev libxml2-dev libxslt-dev \
        libgd-dev libperl-dev \
        # coverage + python
        lcov python3 python3-pip python3-venv python3-dev \
        # languages
        golang rustc cargo \
        # utils
        curl ca-certificates bash jq procps psmisc xxd netcat-openbsd \
        iproute2 net-tools tree wget ffmpeg tcpdump

# Python deps for the orc helper (also declared in the root uv workspace).
RUN pip3 install --break-system-packages jinja2 pyyaml

# LLVM 15 is the last release with the old pass manager; AFLNet's llvm_mode and
# Nyx's packer need clang-15/llvm-config-15, which Debian trixie no longer ships.
# The deb is built on the host by `make -C container/clang deb`.
# RUN --mount=type=cache,sharing=locked,target=/var/cache/apt \
#    --mount=type=bind,source=clang/pkg/llvm-15_15.0.7-1_amd64.deb,target=/tmp/llvm-15.deb \
#    apt-get install -y --no-install-recommends /tmp/llvm-15.deb

# The repo is mounted at /opt/workdir; orc package lives under targets/_orc/src.
ENV PYTHONPATH=/opt/workdir/targets/_orc/src
ENV ORC_WORKDIR=/opt/workdir

WORKDIR /opt/workdir

# Command runner by default: `podman run <image> <cmd>` executes <cmd>;
# `podman run -it <image>` drops into bash.
CMD ["bash"]
