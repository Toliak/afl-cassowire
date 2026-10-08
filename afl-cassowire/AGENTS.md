# AGENTS.md

## What this is
`afl-cassowire` — a C++20 persistent-mode proxy for `afl-fuzz`. It spawns a slow-starting
network target (e.g. NGINX), waits until the target binds its port, then loops
connect → send fuzz buffer → recv → health-check inside `__AFL_LOOP`.

`DEV_SPECIFICATION.md` is the source of truth for behavior. Where code and spec disagree,
the spec wins (but see "Known deviations" below before "fixing" anything).

## Build
Must be compiled with the AFL++ toolchain — plain g++/clang++ is rejected by a compile
check in `meson.build` (`__AFL_LOOP` / `__AFL_INIT` probe).

```sh
make prepare    # meson subprojects download (yaml-cpp, argparse wraps)
make prepare2   # meson setup build with CXX=<aflpp>/src/distrib/bin/afl-clang-fast++
make build      # meson compile -C build (sets AFL_PROXY_LLVM_ONLY_FSRV=1)
```

`AFLPP_DISTRIB_DIR` defaults to `../aflpp/src/distrib`; override if AFL++ lives elsewhere.

## Testing policy (strict)
No test suite and no linter exist — verify changes by building. Do NOT improvise
verification steps that are not explicitly described in this file or in an explicit
user instruction. Specifically:
- Do not invent, write, or run tests, linters, static analyzers, sanitizers, or
  coverage tools that were not asked for.
- Do not create ad-hoc scripts or harnesses to "verify" behavior.
- Do not run the proxy against live targets (e.g. NGINX) or fuzz it unless the user
  explicitly requests it.
- Do not guess test commands (`make test`, `ctest`, etc. do not exist here).
The only default verification is the documented build sequence above.

## Running
```sh
./build/afl-cassowire [-c config.yaml] [proxy]        # default mode, needs __AFL_SHM_ID
./build/afl-cassowire [-c config.yaml] test --input f # or '-' for stdin
```
`proxy` also requires `PROXY_AFL_FORCE_FINAL_LOC=<uint64>` in the environment.
Config reference: `default.yaml` (copy to `config.yaml`).

## Layout & conventions
- `src/main.cpp` — CLI (argparse), mode routing, signal handlers, AFL loop.
- `src/config.{hpp,cpp}` — structs + `load_config()` returning
  `std::variant<Config, ConfigError>`; **no exceptions**, strict type/range validation
  with a structured `ConfigError` (path/message/expected/actual).
- `src/log.{hpp,cpp}` — namespace `log`: spdlog setup (single-threaded stdout logger,
  flush on warn+), `PROXY_LOG_*` macros gated by `SPDLOG_ACTIVE_LEVEL`
  (`-Dstrip_low_logs=true` compiles trace/debug out), `parse_level()`, `escape_bytes()`.
- `src/process.{hpp,cpp}` — namespace `process`: stale-process cleanup, `prepare_target()` →
  `fork_target()` → `handshake_tracer()` split (prepare env/argv before `fork()`, no heap
  allocs between `fork()` and `execve()`), ptrace/seccomp arming, stdio/pipe redirection.
- `src/network.{hpp,cpp}` — namespace `network`: port detection (`procfs` | `ptrace` |
  `seccomp`, all in `wait_for_port()`) plus TCP client (`connect_target`, `send_all`,
  `wait_response`).
- `src/utils.{hpp,cpp}` — namespace `utils`: time, sleep, `crash_proxy()`.
- Header guards are `#pragma once`; Doxygen-style comments on public functions;
  4-space indent, no tabs.

## Important details
- Port detection must confirm the *configured* port, not just any `bind()`; a bound port
  of 0 (ephemeral) logs a warning and is skipped. `bind` is syscall 49 on x86_64; read the
  `sockaddr` via `PTRACE_GETREGS` + `process_vm_readv()` (not `PTRACE_PEEKDATA`).
- Stdio redirection differs per mode: stdin always → `/dev/null`; the target's
  stdout/stderr go to `/dev/null` by default and are forwarded to the proxy's fds with
  `--child-output` (both proxy and test pass 2). MapSizePass always pipes stdout (map
  size protocol) and sends stderr to `/dev/null`; the flag does not affect it.
- Logging is spdlog → stdout (logger `proxy`, `flush_on(warn)` so messages survive the
  proxy's own `raise(SIGSEGV)`), runtime level via `--log-level`. Never log via spdlog
  between `fork()` and `execve()` — the pre-exec child reports failures with raw
  `dprintf()` to a saved, CLOEXEC stderr fd (async-signal-safety).
- Target crash detection: `waitpid(WNOHANG)` + `WIFSIGNALED` → proxy raises `SIGSEGV` so
  AFL registers the finding. Target is cleaned up SIGTERM → wait `cleanup.force_kill_ms`
  → SIGKILL, on the whole process group.
- Payload sent over TCP is `payload.prefix + fuzz input + payload.suffix`
  (`PayloadConfig::wrap()`); values may be `!!binary`.

## Known deviations from the spec
- `src/afl_compat.h` (not `.hpp`) defines *no-op* AFL++ macros instead of `#error`-ing;
  the "must use an AFL++ compiler" enforcement was moved to the `meson.build` compiler
  probe. Don't add an `#error` guard to the header.
- Extra config keys not in the spec: `target.env`, `target.env_preserve`, `payload.*`,
  and the required `PROXY_AFL_FORCE_FINAL_LOC` env var.
- Logging/target-stdio behavior intentionally diverges from the spec (spec is deprecated
  on these points): proxy logs go through spdlog to stdout with `--log-level` (not
  `std::cout`/`std::cerr`); the spec's `target.log.*` config keys were removed — target
  output defaults to `/dev/null` and is only forwarded with `--child-output` (spec said
  test pass 2 always inherits); the test-mode response is logged as escaped text at info
  level (spec said raw bytes on stdout). DEV_SPECIFICATION.md is NOT updated — trust
  this file for logging/stdio behavior.

## Review markers
Existing review notes are tagged `TODO(claude): ...` (≈40 across `src/`). Preserve the
tag when touching those lines; don't silently drop them.
