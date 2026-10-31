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

DEFAULT_PROFILE = "http"

# A profile selects the target mode plus its seed corpus and coverage framing.
# The Makefile mirrors this mapping for config/dictionary selection.
PROFILES = {
    "http": {
        "seeds": {"aflpp": ["_fuzz/in_http"]},
        "coverage": {
            "args": ["http", "--port", "8050", "--startup-delay-ms", "100"],
            "payload_suffix": "\r\n\r\n",
            "corpus": ["in/http", "out/http/*/queue"],
        },
    },
    "calc": {
        "seeds": {"aflpp": ["_fuzz/in_calc"]},
        "coverage": {
            "args": ["calc", "--port", "8050"],
            "payload_suffix": "\n",
            "corpus": ["in/calc", "out/calc/*/queue"],
        },
    },
    # Stateful cache server: identical requests take different paths depending
    # on the cache/history, which is the instability under study. The profile
    # also carries a CmpLog-gated PRNG region and an opt-in lottery crash that
    # only fires on a warm hit.
    "cache": {
        "seeds": {"aflpp": ["_fuzz/in_cache"]},
        "coverage": {
            "args": ["cache", "--port", "8050", "--startup-delay-ms", "100"],
            "payload_suffix": "\r\n\r\n",
            "corpus": ["in/cache", "out/cache/*/queue"],
        },
    },
}

# No data_template/ -> no RENDER.

# Shared coverage defaults; per-profile entries override args/framing/corpus.
COVERAGE = {
    "build_variant": "gcov",
    "gcov_dir": "src/build/gcov",
    "gcov_tool": "llvm-cov gcov",  # build_gcov uses clang++ --coverage
    "binary": "src/build/gcov/test-target",
    # clang gcov branch data is inconsistent for libstdc++ headers.
    "include": ["*/test_target.cpp"],
    "ignore_errors": ["inconsistent", "category"],
    "host": "127.0.0.1",
    "port": 8050,
    "timeout_ms": 200,
    "startup_ms": 5000,
}
