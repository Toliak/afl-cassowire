"""Declarative metadata for the nginx target.

Consumed by the `orc` helper (targets/_orc) and hand-written fuzz/build recipes
in the Makefile. Nothing here executes anything.
"""

TARGET_NAME = "nginx"

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
# lives in the Makefile (`fuzz-aflpp`, `fuzz-aflnet`); keep them in sync.
FUZZ_VARIANTS = {
    "aflpp": {
        "config": "data/cassowire.yaml",  # override with CASSOWIRE_CONFIG=<file>
        "afl_args": ["-b", "4", "-t", "1500", "-c", "0", "-x", "_fuzz/dict/http.dict"],
        "force_final_loc": 70000,  # AFL_CASSOWIRE_FORCE_FINAL_LOC
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
    "nginx.new.conf.j2": [
        {
            "output": "nginx.new.conf",
            "port_main": 8080,
            "port_backend": 8090,
            "port_backend2": 8091,
            "port_backend3": 8092,
        },
        {
            "output": "nginx.new.cmplog.conf",
            "port_main": 9080,
            "port_backend": 9090,
            "port_backend2": 9091,
            "port_backend3": 9092,
        },
    ],
}

# lcov coverage on the gcov build variant.
COVERAGE = {
    "build_variant": "gcov",
    "binary": "src/install/gcov/usr/bin/nginx",
    "corpus": ["data/seeds", "out/default/queue"],
}