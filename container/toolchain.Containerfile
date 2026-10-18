# Toolchain container: build + fuzz environment for all targets.
#
# Built once (`podman build`); every target build/fuzz/assist step then runs via
# `podman run` against this image (incremental builds live on the host volume,
# mounted at /work).

ARG BASE_IMAGE="debian:trixie-20260610"
FROM ${BASE_IMAGE} AS target

ENV DEBIAN_FRONTEND=noninteractive

# Enable apt-get cache, see https://stackoverflow.com/a/79936062/14142236
RUN [ -f "/etc/apt/apt.conf.d/docker-clean" ] && \
    mv /etc/apt/apt.conf.d/docker-clean /etc/apt/apt.conf.d/docker-clean.disabled || \
    true

RUN --mount=type=cache,sharing=locked,target=/var/cache/apt \
\
    apt-get update -y --allow-releaseinfo-change && \
    apt-get install -y --no-install-recommends \
        # build system
        make cmake meson ninja-build git patch autoconf automake libtool pkg-config \
        # compilers / LLVM
        clang lld llvm-dev gcc g++ build-essential flex bison \
        # AFL++ / QEMU deps
        libglib2.0-dev libpixman-1-dev qemu-user qemu-user-static \
        # AFLNet deps
        libpcap-dev libcap-dev graphviz-dev \
        # NGINX / HAProxy deps
        libpcre2-dev libpcre3-dev zlib1g-dev libssl-dev libxml2-dev libxslt-dev \
        libgd-dev libperl-dev \
        # coverage + python
        lcov python3 python3-pip python3-venv python3-dev \
        # languages
        golang \
        # utils
        curl ca-certificates bash jq procps psmisc xxd netcat-openbsd \
        iproute2 net-tools tree wget ffmpeg tcpdump

# Python deps for the orc helper (also declared in the root uv workspace).
RUN pip3 install --break-system-packages jinja2 pyyaml

# The repo is mounted at /work; orc package lives under targets/_orc/src.
ENV PYTHONPATH=/work/targets/_orc/src
ENV ORC_WORKDIR=/work

WORKDIR /work
ENTRYPOINT ["bash"]