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

# Config variants are selected with CASSOWIRE_CONFIG=data/cassowire.yaml (normal)
# or data/cassowire.qemu.yaml (binary-only QEMU). force_final_loc differs per variant.
FUZZ_VARIANTS = {
    "aflpp": {
        "config": "data/cassowire.yaml",  # normal: port 8060
        "afl_args": ["-b", "5", "-t", "1500", "-c", "0"],
        "force_final_loc": 4096,
    },
    "aflpp-qemu": {
        "config": "data/cassowire.qemu.yaml",
        "afl_args": ["-b", "5", "-t", "2000", "-c", "0"],
        "force_final_loc": 65536,
    },
}

# Configs are rendered from data_template/*.j2 -> data/ (no RENDER needed).

COVERAGE = {
    "build_variant": "gcov",
    "binary": "src/build/gcov/tinynginx",
    "corpus": ["data/seeds", "out/default/queue"],
}