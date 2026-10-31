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
make TARGET=nginx PROFILE=http-seq FUZZER=aflpp prepare-seeds  # multi-request sessions
```

`prepare-data` renders every `*.j2` in `data_template/` (multi-output via the
target's `RENDER` map) and any root-level `*.j2` (e.g. `cassowire.yaml.j2`).

## 5. Fuzz

```sh
make TARGET=nginx FUZZER=aflpp fuzz    # afl-fuzz + afl-cassowire (persistent proxy)
make TARGET=nginx FUZZER=aflnet fuzz   # AFLNet -P HTTP stateful fuzzing
make TARGET=tiny-nginx fuzz            # normal
make TARGET=tiny-nginx fuzz-qemu       # binary-only QEMU mode
make TARGET=nginx FUZZER=aflpp FUZZ_DEBUG=1 fuzz  # AFL++ debug output + proxy debug logs
```

`FUZZ_DEBUG=1` sets `AFL_DEBUG=1 AFL_DEBUG_CHILD=1 AFL_NO_UI=1` for `afl-fuzz`
and runs `afl-cassowire` with `--log-level debug --child-output`. Without it the
proxy stays at `--log-level error`.

Each fuzz run is a separate `podman run`; rootless podman provides user-mode
networking by default, so every instance is network-isolated (no port collisions,
no host exposure). Run multiple campaigns simply by launching more `make ... fuzz`
processes.

### Sequence (AFLNet-style) fuzzing

`PROFILE=http-seq` drives afl-cassowire's sequence mode: each seed is a session
of several CRLFCRLF-terminated requests, and the proxy sends them one at a time
on a single connection, reading after each send (AFLNet's execution model). AFL++
still mutates the session byte-wise.

```sh
make TARGET=nginx PROFILE=http-seq prepare-data
make TARGET=nginx PROFILE=http-seq FUZZER=aflpp prepare-seeds
make TARGET=nginx PROFILE=http-seq FUZZER=aflpp fuzz
```

The generated config is `data/cassowire.seq.yaml`; the knobs live in its
`sequence:` section:

- `delimiter` (required when enabled) — message separator, plain string or
  `!!binary` bytes; scanned left to right.
- `keep_delimiter` — keep the separator at the end of each sent message
  (`true`) or strip it and re-add via `message_suffix`.
- `response_poll_us` — per-message idle window in **microseconds**; the main
  speed/fidelity knob (`0` = one non-blocking drain; >=1000 approximates
  AFLNet's default but costs ~1 ms per message).
- `initial_poll_us` — optional banner drain before the first message.
- `final_poll_us` — drain after `shutdown(SHUT_WR)`.
- `max_messages` — per-iteration cap; truncation logs a WARN.

`payload.prefix/suffix` cannot be combined with sequence mode; use
`sequence.message_prefix/message_suffix` instead. Because mutation is still
byte-level, keep the dictionary (`_fuzz/dict/http-seq.dict`) close at hand and
prefer `response_poll_us` low for throughput.

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

### Probabilistic cache crashes

`cassowire-test-target`'s cache profile has an opt-in lottery crash
(`--with-crash`, enabled by `cache.cassowire.yaml`). Its request is safe on the
cold MISS that populates the cache entry and draws again on every warm HIT, so
one collected AFL artifact reproduces with retries:

1. Start a fresh cache target with `--with-crash`.
2. Send the collected request once to prime its cache entry.
3. Send the same request again over new connections to the same live target,
   up to the retry budget (the draw is roughly 50/50 per warm hit).
4. After any crash or target restart, start a fresh target and prime again.

If the budget is exhausted without a crash, classify the finding as
`unreproduced/flaky` rather than as a false positive. `make ... crashes` only
collects artifacts and does not perform this replay, so probabilistic findings
need manual (or future tooling-assisted) prime-and-retry reproduction.

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