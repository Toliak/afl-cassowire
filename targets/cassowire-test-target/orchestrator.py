"""Declarative metadata for the deterministic test target (afl-cassowire's own).

This target does not compile: it copies the prebuilt instrumented `test-target`
binaries built by afl-cassowire's own build (see its Makefile).
"""

from typing import List


TARGET_NAME = "cassowire-test-target"

BUILD_VARIANTS: List[] = []  # copy target; see Makefile `build`

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
    "binary": "src/build/gcov/test-target",
    "corpus": ["data/seeds", "out/default/queue"],
}