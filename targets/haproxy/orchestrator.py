"""Declarative metadata for the haproxy target.

Consumed by the `orc` helper (targets/_orc) and hand-written fuzz/build recipes
in the Makefile. Nothing here executes anything.
"""

TARGET_NAME = "haproxy"

# Build variants (must match the `build_*` Makefile targets).
BUILD_VARIANTS = [
    "clang",
    "afl-clang-lto",
    "afl-clang-lto_cmplog",
    "afl-clang-fast",
    "afl-clang-fast_cmplog",
    "aflnet",
    "gcov",
]

# Seed sources per fuzzer. Paths are resolved relative to targets/, the target
# dir, then the repo root (see orc.common.resolve_source_path).
SEED_SOURCES = {
    "aflpp": ["_fuzz/in_http"],
    "aflnet": ["_fuzz/in_http"],
}

# Reference documentation of the fuzz command per fuzzer. The executable form
# lives in the Makefile (`fuzz-aflpp`, `fuzz-aflnet`, `fuzz-qemu`); keep them in
# sync.
FUZZ_VARIANTS = {
    "aflpp": {
        "config": "data/cassowire.yaml",  # override with CASSOWIRE_CONFIG=<file>
        "afl_args": ["-b", "0", "-t", "1500", "-c", "0", "-x", "_fuzz/dict/http.dict"],
        "force_final_loc": 262144,  # AFL_CASSOWIRE_FORCE_FINAL_LOC
    },
    "aflpp-qemu": {
        "config": "data/cassowire.qemu.yaml",
        "afl_args": ["-b", "0", "-t", "2000", "-c", "0", "-x", "_fuzz/dict/http.dict"],
        "force_final_loc": 262144,
    },
    "aflnet": {
        "protocol": "HTTP",
        "netinfo": "tcp://127.0.0.1/8080",
        "afl_args": ["-d", "-D", "10000", "-q", "3", "-s", "3", "-E", "-K", "-R"],
    },
}

# data_template/ -> data/ rendering. Each .j2 template renders to one or more
# outputs; extra keys become Jinja2 variables. `target_dir`/`workdir` are
# injected automatically by the helper.
RENDER = {
    "haproxy.cfg.j2": [
        {
            "output": "haproxy.cfg",
            "port_main": 8080,
            "port_backend": 8090,
            "port_tls": 8443,
            "port_h2": 8444,
        },
        {
            "output": "haproxy.cmplog.cfg",
            "port_main": 9080,
            "port_backend": 9090,
            "port_tls": 9443,
            "port_h2": 9444,
        },
    ],
}

# lcov coverage on the gcov build variant.
COVERAGE = {
    "build_variant": "gcov",
    "gcov_dir": "src/src",  # objects (and .gcno/.gcda) live next to the sources
    "binary": "src/build/gcov/haproxy",
    "args": ["-db", "-f", "{target_dir}/data/haproxy.cfg"],
    "host": "127.0.0.1",
    "port": 8080,
    "timeout_ms": 200,
    "startup_ms": 3000,
    # Standalone HAProxy has no SIGTERM handler, so a plain SIGTERM skips the
    # gcov atexit flush. SIGUSR1 triggers its graceful soft stop.
    "stop_signal": "SIGUSR1",
    # lcov 2.x flags HAProxy's function-level counters as inconsistent.
    "ignore_errors": ["inconsistent", "corrupt"],
    "payload_suffix": "\r\n\r\n",
    "corpus": ["in", "out/*/queue"],
}
