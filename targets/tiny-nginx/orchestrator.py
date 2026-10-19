"""Declarative metadata for the tiny-nginx target."""

TARGET_NAME = "tiny-nginx"

BUILD_VARIANTS = [
    "clang",
    "afl-clang-lto",
    "afl-clang-lto_cmplog",
    "afl-clang-fast",
    "afl-clang-fast_cmplog",
]

DEFAULT_PROFILE = "http"

# tiny-nginx exposes one plain-HTTP mode. QEMU is selected with the fuzzer
# commands (`fuzz-qemu`), not with PROFILE.
PROFILES = {
    "http": {
        "seeds": {"aflpp": ["_fuzz/in_http"]},
        "coverage": {
            "args": ["-p", "8060"],
            "payload_suffix": "\r\n\r\n",
            "corpus": ["in/http", "out/http/*/queue"],
        },
    },
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
    "gcov_dir": "src/src",  # .gcno/.gcda are emitted next to the objects
    "gcov_tool": "llvm-cov gcov",  # build_gcov uses clang --coverage
    "binary": "src/build/gcov/tinynginx",
    "env": {"WORKERS": "1"},
    "host": "127.0.0.1",
    "port": 8060,
    "timeout_ms": 200,
    "startup_ms": 5000,
}