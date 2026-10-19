# Targets

Fuzzing targets for afl-cassowire.

Each target directory follows the same shape:

```
<target>/
├── data_template/   Jinja2 templates + static assets (rendered -> data/)
├── orchestrator.py  declarative per-target metadata (build variants, profiles/seeds/coverage)
├── src/             (gitignored) cloned source + build artifacts
├── data/            (gitignored) rendered configs/assets
├── in/ out/         (gitignored) seeds / AFL output (or in|out/<profile>/)
└── Makefile         the interface: build_{variant}, prepare-data, fuzz-<fuzzer>, cov, crashes
```

Driven from the repo root:

```sh
make TARGET=nginx VARIANT=afl-clang-fast build
make TARGET=nginx prepare-data
make TARGET=nginx FUZZER=aflpp prepare-seeds
make TARGET=nginx FUZZER=aflpp fuzz
make TARGET=nginx replay-cov    # replay in/ + out/*/queue into the gcov build
make TARGET=nginx collect-cov   # lcov/genhtml from existing .gcda
make TARGET=nginx cov           # replay-cov + collect-cov

# Targets with modes select one with PROFILE:
make TARGET=cassowire-test-target PROFILE=calc FUZZER=aflpp prepare-seeds
make TARGET=cassowire-test-target PROFILE=calc FUZZER=aflpp fuzz
make TARGET=cassowire-test-target PROFILE=calc cov   # cov/calc
make TARGET=cassowire-test-target cov                # all profiles -> cov/
```

`nginx` and `tiny-nginx` define a single `http` profile; their seeds and
campaigns live in `in/http/` and `out/http/`. `PROFILE` defaults to `http`, so
commands without it keep working.

The root `Makefile` is the container boundary. Converted targets (`nginx`,
`tiny-nginx`, `haproxy`, `h2o`, `cassowire-test-target`) include `_mk/env.mk` and are plain make —
they never invoke podman. Inside the dev container run them either through the
root with `RUN_IN_CONTAINER=0`, or directly:

```sh
RUN_IN_CONTAINER=0 make TARGET=nginx build
cd targets/nginx && make build
```

Shared make logic lives in `_mk/` (`env.mk` for plain targets, `container.mk`
only for not-yet-converted legacy targets); the Python helper lives in `_orc/`;
shared seed corpora/dictionaries live in `_fuzz/`.

See `docs/fuzzing-guide.md` for the full workflow.