"""Declarative metadata for the h2o target.

Consumed by the `orc` helper (targets/_orc) and hand-written fuzz/build recipes
in the Makefile. Nothing here executes anything.
"""

TARGET_NAME = "h2o"

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
    "aflnet": {
        "protocol": "HTTP",
        "netinfo": "tcp://127.0.0.1/8070",
        "afl_args": ["-d", "-D", "10000", "-q", "3", "-s", "3", "-E", "-K", "-R"],
    },
    "aflpp-qemu": {
        "config": "data/cassowire.qemu.yaml",
        "afl_args": ["-b", "0", "-t", "2000", "-c", "0"],
        "force_final_loc": 262144,
    },
}

# data_template/ -> data/ rendering. Each .j2 template renders to one or more
# outputs; extra keys become Jinja2 variables. `target_dir`/`workdir` are
# injected automatically by the helper.
RENDER = {
    "h2o.conf.j2": [
        {
            "output": "h2o.conf",
            "port_main": 8070,
            "port_backend": 8071,
        },
        {
            "output": "h2o.cmplog.conf",
            "port_main": 9070,
            "port_backend": 9071,
        },
    ],
}

# lcov coverage on the gcov build variant.
COVERAGE = {
    "build_variant": "gcov",
    "gcov_dir": "src/build/gcov",  # .gcno/.gcda live next to the CMake objects
    "gcov_tool": "llvm-cov gcov",  # build_gcov uses clang --coverage
    "binary": "src/build/gcov/h2o",
    "args": ["-c", "{target_dir}/data/h2o.conf"],
    "host": "127.0.0.1",
    "port": 8070,
    "timeout_ms": 200,
    "startup_ms": 5000,
    "payload_suffix": "\r\n\r\n",
    "corpus": ["in", "out/*/queue"],
    # CMake's unity-ish build and the bundled deps leave a few functions whose
    # line records lcov considers inconsistent; keep the report generation
    # useful instead of aborting on them.
    "ignore_errors": ["inconsistent", "corrupt"],
}
