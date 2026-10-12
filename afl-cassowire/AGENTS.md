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
make build      # meson compile -C build (sets AFL_CASSOWIRE_LLVM_ONLY_FSRV=1)
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
`proxy` also requires `AFL_CASSOWIRE_FORCE_FINAL_LOC=<uint64>` in the environment.
Global options (`-c/--config`, `--log-level`, `--child-output`, `--data-dir`) must
precede the subcommand. `--data-dir` selects where termination dumps are written
(default `afl-cassowire-data`, created recursively if missing).
Config reference: `default.yaml` (copy to `config.yaml`).

## Layout & conventions
- `src/main.cpp` — CLI (argparse), mode routing, signal handlers, AFL loop.
- `src/config.{hpp,cpp}` — structs + `load_config()` returning
  `std::variant<Config, ConfigError>`; **no exceptions**, strict type/range validation
  with a structured `ConfigError` (path/message/expected/actual).
- `src/log.{hpp,cpp}` — namespace `log`: spdlog setup (single-threaded stdout logger,
  flush on warn+), `PROXY_LOG_*` macros gated by `SPDLOG_ACTIVE_LEVEL`
  (`-Dstrip_low_logs=true` compiles trace/debug out), `parse_level()`, `escape_bytes()`,
  and a warn-level ringbuffer sink (capacity 16) exposing `recent_lines()` for
  termination dumps.
- `src/process.{hpp,cpp}` — namespace `process`: stale-process cleanup, `prepare_target()` →
  `fork_target()` → `handshake_tracer()` split (prepare env/argv before `fork()`, no heap
  allocs between `fork()` and `execve()`), ptrace/seccomp arming, stdio/pipe redirection.
- `src/network.{hpp,cpp}` — namespace `network`: port detection (`procfs` | `ptrace` |
  `seccomp`, all in `wait_for_port()`) plus TCP client (`connect_target`, `send_all`,
  `wait_response`).
- `src/utils.{hpp,cpp}` — namespace `utils`: time, sleep, `crash_proxy()`/`abort_proxy()`
  (shared `terminate_proxy()` implementation) and their termination dumps.
- Header guards are `#pragma once`; Doxygen-style comments on public functions;
  4-space indent, no tabs.

## Important details
- Port detection must confirm the *configured* port, not just any `bind()`; a bound port
  of 0 (ephemeral) logs a warning and is skipped. Readiness is a successful `listen()` EXIT
  on the fd bound to the configured port (fd→port tracked from bind stops; `listen` is
  syscall 50 on x86_64). `bind` is syscall 49 on x86_64; read the
  `sockaddr` via `PTRACE_GETREGS` + `process_vm_readv()` (not `PTRACE_PEEKDATA`).
  In seccomp mode the tracer stays attached after detection and is pumped via
  `process::pump_transparent_tracer()` from `exchange_once` and the network poll loops
  (worst-case stall for the target = one poll leg); ptrace options include
  `PTRACE_O_EXITKILL`, and `timed_kill_pgid` resumes traced targets so SIGTERM stays
  deliverable.
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
- Targets are spawned with `PR_SET_PDEATHSIG(SIGKILL)` plus a `getppid()` race check in
  the pre-exec child (`fork_target()`, src/process.cpp:390-397), so the kernel kills the
  target whenever the proxy dies — `abort_proxy`, `crash_proxy`, or AFL killing the
  proxy — in all modes (proxy/test) and all spawn modes, even in procfs port-detection
  mode. This complements `PTRACE_O_EXITKILL` (ptrace/seccomp only): orphaned reuseport
  listeners are impossible. Delivery is immediate SIGKILL with no `force_kill_ms` grace —
  by design, since the proxy is already dead when it fires. It relies on the proxy
  staying single-threaded (PDEATHSIG watches the forking thread).
- `crash_proxy(message, payload)`/`abort_proxy(message, payload)` share `terminate_proxy()`
  and, before raising `SIGSEGV`/`SIGABRT`, write a termination pair into `--data-dir`
  (default `afl-cassowire-data`, created recursively): `{timestamp}-{tag}.msg` (reason)
  and `{timestamp}-{tag}.data` (the full payload built for the iteration: prefix + input
  + suffix), sharing one `YYYYmmdd-HHMMSS-mmm` stem. `-tag` is the instance kind set in
  `main()` (`normal` | `cmplog` | `test`, via `utils::set_instance_tag()`), so dumps from
  concurrently running instances stay attributable; the `.msg` content and the
  termination log line embed it as `{kind}[{tag}]: {reason}`. The `.msg` additionally
  embeds the last ≤16 warn/error lines (oldest first, console-style timestamps) captured
  by the logger's ring sink (`log::recent_lines()`); capture is independent of
  `--log-level` (logger level is floored at warn, the console sink applies the runtime
  level), so quiet runs still produce rich dumps. Dumps are best-effort and never fatal.
- Payload sent over TCP is `payload.prefix + fuzz input + payload.suffix`
  (`PayloadConfig::wrap()`); values may be `!!binary`.
- Observability (hang triage): the proxy loop emits an INFO heartbeat every ~5 s
  (iteration count + max connect/send/wait/probe stage times + slow-iteration
  count, flushed) and a WARN whenever a stage reaches `network.timeout_ms`
  (send not drained; response kept open / a `Content-Length` larger than the
  body sent; slow probe). `wait_for_port()` logs an INFO start line and a WARN
  on timeout; procfs cannot detect a dead target. Repeated connect/send/wait
  errors are rate-limited (first 3, then one per 5 s with a suppressed count).
  Run with `--log-level warn` (or `info`) to see these; `error` hides all but
  the first few failures. Per-iteration detail stays at TRACE/DEBUG.
- Probe failures are two-strike, never instantly fatal: `probe_target()` returns
  a `ProbeResult` carrying the underlying `ConnectError` (kind + errno). On a
  failed probe the proxy first classifies via `check_target_state()` — a dead
  target ends in `crash_proxy` (SIGSEGV) / `abort_proxy` (SIGABRT) as usual; a
  live target gets one probe retry (WARN includes the errno and a hint on
  `EADDRNOTAVAIL`/`EMFILE`-style resource exhaustion), and only a second
  consecutive failure aborts the proxy for the AFL respawn.
- Iteration/probe sockets are armed with `SO_LINGER{1,0}`
  (`network::arm_rst_on_close()`) once their data is fully read, so `close()`
  sends RST: nothing sits in TIME_WAIT and the proxy's ephemeral port range
  cannot be exhausted by fast fuzzing.
- `port_detection.defork` (requires `primary: seccomp`): the target runs with a
  `bind_defork_filter` BPF (`src/process.cpp`) instead of the plain bind filter.
  It cancels every non-thread fork in-kernel: `fork`/`vfork`/`clone` without
  `CLONE_THREAD` -> `SECCOMP_RET_ERRNO|0` (kernel returns 0, syscall never runs,
  so the caller continues in the child path and no second process exists);
  `clone` with `CLONE_THREAD` (pthreads) -> ALLOW; `bind`/`listen` -> TRACE as
  usual.
  De-forking needs NO tracer interaction (no PTRACE_O_TRACEFORK, no
  create-then-kill) and stays installed for the target's whole life (seccomp
  filters are irremovable). `clone3` is intentionally not
  trapped (its flags live in a userspace struct cBPF cannot dereference; glibc
  x86_64 pthread_create uses `clone`). The defork filter is arch-aware
  (non-x86_64 seccomp arch -> `SECCOMP_RET_KILL_PROCESS`); the plain bind filter
  remains arch-unaware (TODO in source).

## Known deviations from the spec
- `src/afl_compat.h` (not `.hpp`) defines *no-op* AFL++ macros instead of `#error`-ing;
  the "must use an AFL++ compiler" enforcement was moved to the `meson.build` compiler
  probe. Don't add an `#error` guard to the header.
- Extra config keys not in the spec: `target.env`, `target.env_preserve`, `payload.*`,
  `target_cmplog.*`, `network_cmplog.*`, `port_detection.defork`, and the required
  `AFL_CASSOWIRE_FORCE_FINAL_LOC` env var. `target_cmplog`/`network_cmplog` are standalone
  (no key falls back to `target`/`network`) and required when `afl.enable_cmplog: true`;
  in cmplog mode both replace their normal counterparts in `run_proxy_mode()` before
  spawn, so port detection, connect, timeouts, and probe all use the cmplog values.
- Port detection (`ptrace`/`seccomp`) deviates from spec §4/5.2: the seccomp BPF filter
  traps `bind` AND `listen`, and readiness is declared on the successful `listen()` exit
  (fd tracked from bind stops), not at `bind()` entry as the spec says. After detection
  the tracer stays attached as a *transparent tracer* (every seccomp stop is resumed with
  PTRACE_CONT so later bind()/listen() work despite the unremovable filter); the target's
  forked children inherit the filter UNTRACED — their bind()/listen() still fail with
  ENOSYS (accepted limitation). `PTRACE_O_EXITKILL` is set so a proxy death kills the
  traced target instead of leaving a filter-lame process holding the port.
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
