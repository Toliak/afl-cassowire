"""Declarative metadata for the tiny-nginx target."""

TARGET_NAME = "tiny-nginx"

BUILD_VARIANTS = [
    "clang",
    "afl-clang-lto",
    "afl-clang-lto_cmplog",
    "afl-clang-fast",
    "afl-clang-fast_cmplog",
]

SEED_SOURCES = {
    "aflpp": ["_fuzz/in_http"],
}

# Config variants are selected with CASSOWIRE_CONFIG=cassowire.yaml (normal) or
# cassowire.qemu.yaml (binary-only QEMU). force_final_loc differs per variant.
FUZZ_VARIANTS = {
    "aflpp": {
        "config": "cassowire.yaml",  # normal: port 8060
        "afl_args": ["-b", "5", "-t", "1500", "-c", "0"],
        "force_final_loc": 4096,
    },
    "aflpp-qemu": {
        "config": "cassowire.qemu.yaml",
        "afl_args": ["-b", "5", "-t", "2000", "-c", "0"],
        "force_final_loc": 65536,
    },
}

# No data_template/ (static cassowire.yaml at the target root) -> no RENDER.

COVERAGE = {
    "build_variant": "gcov",
    "binary": "src/build/gcov/tinynginx",
    "corpus": ["data/seeds", "out/default/queue"],
}