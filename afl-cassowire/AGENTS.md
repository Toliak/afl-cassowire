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
Config reference: `default.yaml` (copy to `config.yaml`). Root `__`-prefixed keys
are ignored helper-anchor fields (see Important details).

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
  `fork_target()` split (prepare env/argv before `fork()`, no heap
  allocs between `fork()` and `execve()`), seccomp user-notif filter install +
  listener-fd handoff (`SpawnedTarget::notif_fd`) in the pre-exec child, stdio/pipe redirection.
- `src/network.{hpp,cpp}` — namespace `network`: port detection (`procfs` |
  `seccomp`, both in `wait_for_port()`), the steady-state notification pump
  (`set_notif_listener`/`pump_notif_listener`) plus TCP client (`connect_target`, `send_all`,
  `wait_response`).
- `src/utils.{hpp,cpp}` — namespace `utils`: time, sleep, `crash_proxy()`/`abort_proxy()`
  (shared `terminate_proxy()` implementation) and their termination dumps.
- Header guards are `#pragma once`; Doxygen-style comments on public functions;
  4-space indent, no tabs.

## Important details
- Port detection must confirm the *configured* port, not just any `bind()`; a bound port
  of 0 (ephemeral) logs a warning and is skipped. Seccomp mode is
  `SECCOMP_RET_USER_NOTIF`-based (kernel >= 5.0; **no ptrace anywhere**): the
  pre-exec child installs a bind/listen filter (`SECCOMP_SET_MODE_FILTER` +
  `SECCOMP_FILTER_FLAG_NEW_LISTENER`; x86_64 arch guard, foreign arch ->
  `KILL_PROCESS`), hands the listener fd back over a private socketpair via
  `SCM_RIGHTS`, and blocks on a 1-byte ack so the proxy is guaranteed to hold
  the fd before the target can reach any `bind()`. Threads and forked children
  inherit the filter automatically and notify the same fd — multi-process and
  multi-threaded targets (and QEMU guests: guest `bind`/`listen` translate to
  real host syscalls with faithful fd/sockaddr values) are fully covered.
  Readiness = a `listen` notification on an fd recorded from a `bind`
  notification for the configured port (`sockaddr` read with
  `process_vm_readv` on the notifying tid), plus a bounded (~100 ms)
  `/proc/net/tcp{,6}` LISTEN confirmation — notifications carry syscall ENTRY
  only, so there is no exit value and e.g. EADDRINUSE is invisible otherwise.
  Every notification must be answered (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`):
  the filter is irremovable, so `network::pump_notif_listener()` (non-blocking
  drain; registered after detection via `network::set_notif_listener()`) runs
  from `exchange_once` and the network poll loops for the target's whole life
  (worst-case stall for the target = one poll leg). Both detection methods and
  the procfs path poll `waitpid(WNOHANG)` and report `TargetDied`.
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
  the pre-exec child (`fork_target()`), so the kernel kills the target whenever the
  proxy dies — `abort_proxy`, `crash_proxy`, or AFL killing the
  proxy — in all modes (proxy/test) and all spawn modes, even in procfs port-detection
  mode. Delivery is immediate SIGKILL with no `force_kill_ms` grace —
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
   level), so quiet runs still produce rich dumps. The `.msg` also embeds the
   current 1-based `__AFL_LOOP` iteration as an `iteration: N` line (set once per
   loop pass via `utils::set_current_iteration()` in `run_proxy_mode()`; `0` =
   termination outside the loop or test mode). Dumps are best-effort and never fatal.
- Payload sent over TCP is `payload.prefix + fuzz input + payload.suffix`
  (`PayloadConfig::wrap()`); values may be `!!binary`.
- Startup-coverage fix (stability): `main.cpp` has a file-scope `__AFL_COVERAGE()` +
  `__AFL_COVERAGE_START_OFF()` (afl-cc `-D` macros; no-op placeholders in `afl_compat.h`),
  and `run_proxy_mode()` emits `__AFL_COVERAGE_DISCARD()` (gated by `afl.cov_discard_init`,
  default true) + unconditional `__AFL_COVERAGE_ON()` right before the first `__AFL_LOOP()`
  pass — the proxy and the instrumented target share one coverage map, so the discard
  zeroes the startup feedback (NGINX init included; `__afl_coverage_discard()` also zeroes
  the cmplog map) that would otherwise be attributed to the first testcase. The ON is
  mandatory: with START_OFF the runtime never auto-re-enables; it only works before the
  loop because `__afl_persistent_loop()` clears `__afl_selective_coverage_temp` on the
  second pass. (`__AFL_COVERAGE_OFF()` around in-loop work cannot work as a probe-noise
  filter: the macros only pivot the *proxy's* map pointer — the target is a separate
  process writing the same map — and the runtime accepts `ON()` only until the second
  `__AFL_LOOP()` pass.)
- Root config keys starting with `__` (e.g. `__helpers: &anchor`) are ignored by
  `load_config()` and exempted in `config.schema.json` (root `patternProperties
  "^__"`): a reserved namespace for YAML anchor/merge (`<<`) helper fragments.
  The exemption is root-only — `__`-prefixed keys inside any section are still
  rejected as unknown keys. Fixtures: `test/schema_validate/cases/*helper*.yaml`.
- Observability (hang triage): the proxy loop emits an INFO heartbeat every ~5 s
  (iteration count + max connect/send/wait/probe stage times + slow-iteration
  count, flushed) and a WARN whenever a stage reaches `network.timeout_ms`
  (send not drained; response kept open / a `Content-Length` larger than the
  body sent; slow probe). `wait_for_port()` logs an INFO start line and a WARN
  on timeout; both detection methods notice a dead target (waitpid(WNOHANG)
  every pass), and procfs additionally flags a foreign port holder (ownership
  check, see below). Repeated connect/send/wait
  errors are rate-limited (first 3, then one per 5 s with a suppressed count).
  `port_detection.verify_ownership` (procfs only, default `true`) additionally
  requires the matched LISTEN socket inode to be held by the target's process
  tree (`process::collect_pid_tree()`); an unreadable `/proc/<pid>/fd` (setuid
  targets) is accepted with a WARN, and the key is ignored for seccomp
  (ownership is verified by construction there).
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
- `port_detection.defork` and the ptrace-based port-detection modes were REMOVED.
  Seccomp detection is now `SECCOMP_RET_USER_NOTIF`-based, which handles
  multi-process and multi-threaded targets correctly (all inherited-filter
  tasks notify the same fd), so the old fork-cancelling workaround is no
  longer needed for detection. If de-forking is ever wanted again, the clean
  route is NOTIF on `fork`/`vfork`/`clone` with `SECCOMP_USER_NOTIF` responses
  faking a return value of 0 — not a BPF `ERRNO|0` hack.

## Known deviations from the spec
- `src/afl_compat.h` (not `.hpp`) defines *no-op* AFL++ macros instead of `#error`-ing;
  the "must use an AFL++ compiler" enforcement was moved to the `meson.build` compiler
  probe. Don't add an `#error` guard to the header.
- Extra config keys not in the spec: `target.env`, `target.env_preserve`, `payload.*`,
  `afl.cov_discard_init`,
  `target_cmplog.*`, `network_cmplog.*`, and the required
  `AFL_CASSOWIRE_FORCE_FINAL_LOC` env var. `target_cmplog`/`network_cmplog` are standalone
  (no key falls back to `target`/`network`) and required when `afl.enable_cmplog: true`;
  in cmplog mode both replace their normal counterparts in `run_proxy_mode()` before
  spawn, so port detection, connect, timeouts, and probe all use the cmplog values.
- Port detection deviates from spec §4/5.2: there is **no ptrace at all** — the `ptrace`
  primary and the TRACEME/`SECCOMP_RET_TRACE` realization of `seccomp` were removed in
  favor of `SECCOMP_RET_USER_NOTIF` (listener fd handed over `SCM_RIGHTS` pre-exec,
  polled by the proxy; readiness = `listen` notification for the configured port's fd
  + bounded `/proc/net/tcp` confirmation, since notifications carry no syscall exit
  value — the spec wanted readiness at `bind()` ENTRY; both are deviations). The
  inherited filter notifies for every thread and forked child, so the old
  "children fail bind/listen with ENOSYS" limitation is gone; QEMU-mode targets
  work with `seccomp` now (procfs remains the default there). `PDEATHSIG` (see above)
  replaced `PTRACE_O_EXITKILL` as the proxy-death backstop.
- Logging/target-stdio behavior intentionally diverges from the spec (spec is deprecated
  on these points): proxy logs go through spdlog to stdout with `--log-level` (not
  `std::cout`/`std::cerr`); the spec's `target.log.*` config keys were removed — target
  output defaults to `/dev/null` and is only forwarded with `--child-output` (spec said
  test pass 2 always inherits); the test-mode response is logged as escaped text at info
  level (spec said raw bytes on stdout). DEV_SPECIFICATION.md is NOT updated — trust
  this file for logging/stdio behavior.
- Both `afl-qemu-bridge` and `afl-qemu-trace` are supported as QEMU backends for
  binary-only fuzzing. See `default.qemu.yaml` for configuration examples and instructions
  on switching between them.

## Review markers
Existing review notes are tagged `TODO(claude): ...` (≈40 across `src/`). Preserve the
tag when touching those lines; don't silently drop them.
