"""Declarative metadata for the deterministic test target (afl-cassowire's own).

The Makefile builds the canonical `afl-cassowire/tests/targets/test-target`
source out-of-tree under `src/build/<variant>`; the build leaves the upstream
source tree untouched.
"""

TARGET_NAME = "cassowire-test-target"

BUILD_VARIANTS = [
    "clang++",
    "afl-clang-lto++",
    "afl-clang-lto++_cmplog",
    "afl-clang-fast++",
    "afl-clang-fast++_cmplog",
    "gcov",
]

SEED_SOURCES = {
    "aflpp": ["_fuzz/in_calc", "_fuzz/in_http"],
}

FUZZ_VARIANTS = {
    "aflpp": {
        "config": "http.cassowire.yaml",  # or calc.cassowire.yaml
        "afl_args": ["-b", "3", "-t", "1500", "-c", "0", "-x", "_fuzz/dict/http.dict"],
        "force_final_loc": 70000,
    },
}

# No data_template/ -> no RENDER.

COVERAGE = {
    "build_variant": "gcov",
    "gcov_dir": "src/build/gcov",
    "gcov_tool": "llvm-cov gcov",  # build_gcov uses clang++ --coverage
    "binary": "src/build/gcov/test-target",
    # clang gcov branch data is inconsistent for libstdc++ headers.
    "include": ["*/test_target.cpp"],
    "ignore_errors": ["inconsistent"],
    "args": ["http", "--port", "8050", "--startup-delay-ms", "100"],
    "host": "127.0.0.1",
    "port": 8050,
    "timeout_ms": 200,
    "startup_ms": 5000,
    "payload_suffix": "\r\n\r\n",
    "corpus": ["in", "out/*/queue"],
}
