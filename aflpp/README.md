# aflpp

Build wrapper around [AFL++](https://github.com/aflplusplus/aflplusplus) (`v5.02c`), patched to
support the **afl-cassowire** project (a proxy/fork-server bridge for fuzzing network services).

## Patches

`make patch` clones AFL++ into `src/` and applies every `*.patch` in `patch/` with `patch -p1`
(see the `Makefile`). Files ending in `.patch.disabled` are ignored.

| Patch | Purpose |
| --- | --- |
| `force_loc.patch` | Required for the `afl-cassowire` binary. Adds `AFL_CASSOWIRE_LLVM_ONLY_FSRV` to disable LLVM PC-guard coverage writes (removing coverage noise) while preserving fork-server/persistence mode, and `AFL_CASSOWIRE_FORCE_FINAL_LOC` to force the `afl_area_map` size via `__afl_final_loc` so the map can be passed through to the target unchanged. |
| `qemu_bridge_cmplog_log.patch` | Adds opt-in debug logging to the QEMU bridge cmplog implementation. Setting `AFL_QEMU_CMPLOG_DEBUG` prints cmplog map attach info, RTN enablement, and the first INS/RTN comparison operands per map slot. |
| `debug.patch.disabled` | Disabled. Instruments `updateCoverageBitmap` to `fprintf` every PC-guard index to stderr; very noisy, kept for reference only. |

New env vars introduced by the patches:

- `AFL_CASSOWIRE_LLVM_ONLY_FSRV` — skip LLVM coverage instrumentation (fork-server only).
- `AFL_CASSOWIRE_FORCE_FINAL_LOC` — override the coverage map size (`__afl_final_loc`).
- `AFL_QEMU_CMPLOG_DEBUG` — enable QEMU bridge cmplog debug output.

## Usage

```
make prepare    # git clone AFL++ v5.02c into src/
make patch      # apply patches from patch/
make submodules # init qemu_mode/qemuafl and qemu_bridge/qemu-libafl-bridge
make build      # build the distrib/ bundle
make install    # install into src/distrib
```

Requires `nproc`, `git`, `patch`, and a working C/C++ toolchain.
