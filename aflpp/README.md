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
make prepare    # git clone AFL++ v5.03c into src/
make patch      # apply patches from patch/
make submodules # init qemu_mode/qemuafl and qemu_bridge/qemu-libafl-bridge
make build      # build the distrib/ bundle
make build-qemu # build + stage the QEMU guest architectures
make install    # install into src/distrib (depends on build-qemu when WITH_QEMU=1)
```

Requires `nproc`, `git`, `patch`, and a working C/C++ toolchain.

QEMU support is optional. Set `WITH_QEMU=0` to skip the QEMU submodules,
`afl-qemu-trace`/`afl-qemu-bridge`, and guest-architecture staging:

```
make build WITH_QEMU=0
make install WITH_QEMU=0   # host tools only; no QEMU binaries installed
```

With `WITH_QEMU=0`, `install` depends on `build` instead of `build-qemu`, and
`build` passes `NO_QEMU=1` to AFL++'s `distrib` target.

## QEMU guest architectures

`QEMU_ARCHS` selects which guest architectures get QEMU support (default
`x86_64 aarch64`; values are QEMU `CPU_TARGET` names). AFL++ itself is always
built for the host; each entry is built with `CPU_TARGET=<arch>` and installed
as an arch-suffixed binary next to the native one:

```
src/distrib/bin/afl-qemu-trace              # native (x86_64 here)
src/distrib/bin/afl-qemu-bridge
src/distrib/bin/afl-qemu-trace-x86_64
src/distrib/bin/afl-qemu-bridge-x86_64
src/distrib/bin/afl-qemu-trace-aarch64
src/distrib/bin/afl-qemu-bridge-aarch64
```

The native entry is reused, not rebuilt. Non-native builds do not need a
cross-compiler: QEMU is compiled by the host compiler and only the *guest*
architecture differs. Building ARM64 guest binaries still needs an
`aarch64-linux-gnu` toolchain/sysroot.

```
make build-qemu QEMU_ARCHS="aarch64"       # ARM64 guests only
make build-qemu QEMU_ARCHS="x86_64 aarch64"
make build-qemu QEMU_ARCHS=               # native only
```

`afl-fuzz -Q` only auto-discovers the unsuffixed native binaries. To use an
arch-suffixed emulator, pass it explicitly with `AFL_QEMU_CUSTOM_BIN` (for
example `AFL_QEMU_CUSTOM_BIN=1 afl-fuzz -Q ... -- ./afl-qemu-trace-aarch64 --
./guest`), or point `afl-cassowire`'s `target.binary` at it. Dynamic guests need
`QEMU_LD_PREFIX=/path/to/arm64/sysroot`.

Note: `afl-qemu-bridge` persistent mode is currently x86/x86_64 only; aarch64
guests run in fork mode. `afl-qemu-trace` (qemuafl) supports aarch64 persistent
mode.
