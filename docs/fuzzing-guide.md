# Fuzzing Guide

The workspace builds and fuzzes network targets (nginx, tiny-nginx, ...) through
a Debian-based **toolchain container**. The host `Makefile` is a generic
passthrough to each target's `Makefile` (the interface), which in turn uses the
Python helper `targets/_orc` for data rendering, seeds, coverage and crash triage.

## Prerequisites

- podman (rootless)
- Python 3.10+ and the root uv workspace (`.venv` provides `jinja2`/`pyyaml`; the
  toolchain container installs them too)

## 1. Build the toolchain image (once)

```sh
make toolchain
# or: podman build -t localhost/afl-cassowire-toolchain:latest -f container/toolchain.Containerfile container/
```

## 2. Build the fuzzer toolchains (once each)

```sh
make aflpp          # our patched AFL++ (aflpp/src/distrib)
make aflnet         # vendor AFLNet (other/aflnet)
make afl-cassowire  # the persistent proxy (afl-cassowire/build)
```

All are built like targets, inside the toolchain container; artifacts persist on
the host volume.

## 3. Build a target

```sh
make TARGET=nginx VARIANT=afl-clang-fast build     # one variant
make TARGET=nginx build                            # all variants (incl. aflnet, gcov)
```

Variants follow the `build_<variant>` targets in each target's `Makefile`
(`clang`, `afl-clang-fast`, `afl-clang-fast_cmplog`, `afl-clang-lto`, `aflnet`,
`gcov`, ...).

## 4. Prepare data and seeds

```sh
make TARGET=nginx prepare-data                 # render data_template/*.j2 -> data/ (+ cassowire.yaml)
make TARGET=nginx FUZZER=aflpp prepare-seeds   # merge SEED_SOURCES into in/
make TARGET=nginx FUZZER=aflnet prepare-seeds  # request-sequence seeds for AFLNet
```

`prepare-data` renders every `*.j2` in `data_template/` (multi-output via the
target's `RENDER` map) and any root-level `*.j2` (e.g. `cassowire.yaml.j2`).

## 5. Fuzz

```sh
make TARGET=nginx FUZZER=aflpp fuzz    # afl-fuzz + afl-cassowire (persistent proxy)
make TARGET=nginx FUZZER=aflnet fuzz   # AFLNet -P HTTP stateful fuzzing
make TARGET=tiny-nginx fuzz            # normal
make TARGET=tiny-nginx fuzz-qemu       # binary-only QEMU mode
```

Each fuzz run is a separate `podman run`; rootless podman provides user-mode
networking by default, so every instance is network-isolated (no port collisions,
no host exposure). Run multiple campaigns simply by launching more `make ... fuzz`
processes.

## 6. Coverage

```sh
make TARGET=nginx cov
```

Collects gcov coverage (`lcov --capture` + `genhtml`) from the target's `gcov`
build variant into `targets/nginx/cov/html/index.html`.

## 7. Crash triage

```sh
make TARGET=nginx crashes
```

Copies every `out/**/crashes/id:*` into `targets/nginx/crashes/` (as
`<campaign>__<name>`) and writes `summary.json`.

## Layout

```
targets/
├── _mk/            shared makefiles (container.mk, fuzzers/{aflpp,aflnet}.mk, git.mk)
├── _orc/           Python helper (prepare-data / prepare-seeds / collect-cov / collect-crashes)
├── _fuzz/          shared seed corpora + dictionaries
└── <target>/
    ├── data_template/   Jinja2 templates + static assets (rendered -> data/)
    ├── orchestrator.py  declarative per-target metadata
    ├── src/            (gitignored) cloned source + build artifacts
    ├── data/           (gitignored) rendered configs/assets
    ├── in/  out/       (gitignored) seeds / AFL output
    └── Makefile        the interface: build_{variant}, prepare-data, fuzz-<fuzzer>, cov, crashes
```

Fuzzers live at `aflpp/` (ours) and `other/` (vendors, e.g. `aflnet`); each is
built like a target via `make -C` inside the toolchain container.