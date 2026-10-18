# AGENTS.md

Workspace for fuzzing network targets with **afl-cassowire** (our C++ persistent
proxy for `afl-fuzz`) and other fuzzers (`aflpp`, vendor `aflnet`, ...).

## Layout

- `afl-cassowire/` — the proxy. See [`./afl-cassowire/AGENTS.md`](./afl-cassowire/AGENTS.md).
- `aflpp/` — our patched AFL++ (`src/` cloned source + built `src/distrib`).
- `other/` — vendor fuzzers (`aflnet`, `honggfuzz`, `afl-proxy`, ...).
- `targets/` — fuzz targets (nginx, tiny-nginx, cassowire-test-target, ...).
- `container/` — toolchain image (`toolchain.Containerfile`).
- `tools/` — extra C++ tools (`seccomp_strace`, `http_throughput`).

## Target workflow

Everything runs inside the toolchain container. The host `Makefile` is a generic
passthrough to each target's `Makefile` (the interface):

```sh
make toolchain                                 # build the toolchain image (once)
make aflpp                                     # build our AFL++ (once)
make TARGET=nginx VARIANT=afl-clang-fast build # build one variant
make TARGET=nginx prepare-data                 # render data_template/*.j2 -> data/
make TARGET=nginx FUZZER=aflpp prepare-seeds   # merge seeds into in/
make TARGET=nginx FUZZER=aflpp fuzz            # fuzz (aflpp + afl-cassowire)
make TARGET=nginx FUZZER=aflnet fuzz           # fuzz (AFLNet, stateful HTTP)
make TARGET=nginx cov                          # lcov coverage
make TARGET=nginx crashes                      # collect crashes
```

## Conventions

- **Build + fuzz live in Makefiles** (`build_<variant>`, `fuzz-<fuzzer>`).
- **Data/seeds/coverage/crash-triage live in the Python helper** `targets/_orc`
  (`python -m orc <target> prepare-data|prepare-seeds|collect-cov|collect-crashes`),
  driven per-target by a declarative `targets/<target>/orchestrator.py`.
- Fuzzer toolchains are built like targets, in `aflpp/` and `other/<fuzzer>/`.
- Generated configs: `data_template/*.j2` → `data/`, root `*.j2` → target root
  (e.g. `cassowire.yaml.j2` → `cassowire.yaml`).

Full workflow: [`docs/fuzzing-guide.md`](./docs/fuzzing-guide.md).