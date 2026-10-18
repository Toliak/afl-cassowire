# Targets

Fuzzing targets for afl-cassowire.

Each target directory follows the same shape:

```
<target>/
├── data_template/   Jinja2 templates + static assets (rendered -> data/)
├── orchestrator.py  declarative per-target metadata (build variants, seeds, fuzz, coverage)
├── src/             (gitignored) cloned source + build artifacts
├── data/            (gitignored) rendered configs/assets
├── in/ out/         (gitignored) seeds / AFL output
└── Makefile         the interface: build_{variant}, prepare-data, fuzz-<fuzzer>, cov, crashes
```

Driven from the repo root:

```sh
make TARGET=nginx VARIANT=afl-clang-fast build
make TARGET=nginx prepare-data
make TARGET=nginx FUZZER=aflpp prepare-seeds
make TARGET=nginx FUZZER=aflpp fuzz
make TARGET=nginx cov
```

Shared make logic lives in `_mk/`; the Python helper lives in `_orc/`; shared
seed corpora/dictionaries live in `_fuzz/`.

See `docs/fuzzing-guide.md` for the full workflow.