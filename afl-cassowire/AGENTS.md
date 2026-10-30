# AGENTS.md

## What this is
`afl-cassowire` — a C++20 persistent-mode proxy for `afl-fuzz`. It spawns a slow-starting
network target (e.g. NGINX), waits until the target binds its port, then loops
connect → send fuzz buffer → recv → health-check inside `__AFL_LOOP`.

`DEV_SPECIFICATION.md` is the original design spec and is **deprecated** (it carries a
banner and is no longer maintained). The source of truth is the code plus this file,
`README.md`, `default.yaml` and `schema/config.schema.json`. See "Design notes and extras"
below before "fixing" anything that looks odd.

## Build
Must be compiled with the AFL++ toolchain — plain g++/clang++ is rejected by a compile
check in `meson.build` (`__AFL_LOOP` / `__AFL_INIT` probe).

```sh
make prepare    # meson subprojects download (yaml-cpp, argparse wraps)
make prepare2   # meson setup build with CXX=<aflpp>/src/distrib/bin/afl-clang-fast++
make build      # meson compile -C build (sets AFL_CASSOWIRE_LLVM_ONLY_FSRV=1)
```

The default build is dynamically linked. Pass `STATIC=1` to `prepare2`/`build`
for a fully static build (Meson `-Dstatic_link=true`); it uses `build-static/`.

`AFLPP_DISTRIB_DIR` defaults to `../aflpp/src/distrib`; override if AFL++ lives elsewhere.

## Testing policy (strict)
There is no C++ unit-test suite and no C++ linter — verify code changes by building.
End-to-end tests live in `tests/e2e` (a self-contained uv project):
- `schema_validate/` — parametrized config JSON-Schema fixtures (`cases.py` +
  `blocks.py`, engine in `validate.py`).
- `test_mode/` — `afl-cassowire test` mode against the prebuilt instrumented
  `tests/targets/test-target` (dump-map pass + single-iteration pass, payload
  wrapping, stdin input, procfs/seccomp port detection). It expects the binaries
  to be already built — `build/afl-cassowire` and the target's
  `build/afl-clang-fast++/test-target` (override with `AFL_CASSOWIRE_BIN` /
  `CASSOWIRE_TEST_TARGET_BIN`); it never builds them and fails when missing.
- `proxy_mode/` — `afl-cassowire proxy` mode driven by an AFL++ "emulator"
  (`proxy_mode/emul.py`, a stdlib-only fake afl-fuzz: SysV shmem for the
  coverage / fuzz-testcase / cmplog maps plus the AFL++ FS_NEW forkserver
  protocol on fds 198/199). Runs the persistent `__AFL_LOOP` against the
  prebuilt instrumented test-target in calc/http mode (normal + cmplog,
  procfs + one seccomp config) and asserts the coverage and cmplog maps differ
  between target modes and between corpora. Same prebuilt-binary contract as
  `test_mode` plus the cmplog target variant `build/afl-clang-fast++_cmplog/`
  (override with `AFL_CASSOWIRE_BIN`, `CASSOWIRE_TEST_TARGET_BIN`,
  `CASSOWIRE_TEST_TARGET_CMPLOG_BIN`); fails when binaries are missing, skips
  cmplog cases when `kernel.shmmax` < ~144 MiB (sizeof of the cmplog map).

Run them with (from the repository root):
```sh
make -C tests/e2e prepare-dev   # uv sync
make -C tests/e2e tests         # uv run pytest (all suites)
make -C tests/e2e lint          # ruff
make -C tests/e2e typecheck     # mypy --strict
```
Do NOT improvise verification steps beyond the ones above. Specifically:
- Do not invent, write, or run C++ tests, linters, static analyzers, sanitizers, or
  coverage tools that were not asked for.
- Do not create ad-hoc scripts or harnesses to "verify" behavior.
- Do not run the proxy against live targets (e.g. NGINX) or fuzz it unless the user
  explicitly requests it.
- Do not guess test commands (`make test`, `ctest`, etc. do not exist here).
For C++ changes the only default verification is the documented build sequence above.

## Running
```sh
./build/afl-cassowire [-c config.yaml] [proxy]        # default mode, needs __AFL_SHM_ID
./build/afl-cassowire [-c config.yaml] test --input f # or '-' for stdin
```
`proxy` also requires `AFL_CASSOWIRE_FORCE_FINAL_LOC=<uint64>` in the environment.
Global options (`-c/--config`, `--log-level`, `--child-output`, `--data-dir`) must
precede the subcommand. `--data-dir` selects where termination dumps are written
(default `afl-cassowire-data`, created recursively if missing).
argv/yaml split: **argv** carries logging (`--log-level`), environmental,
fuzzing-unrelated settings (`-c/--config`, `--data-dir`, `--child-output`), and
mode-specific extras (`test --input`; `proxy` takes none of its own). Everything
that affects the fuzzing process itself — target, network, AFL loop, port
detection, payload wrapping, dump *content* such as `afl.msg_log_level` — lives in
config.yaml.
Config reference: `default.yaml` (copy to `config.yaml`). Root `__`-prefixed keys
are ignored helper-anchor fields (see Important details).

## Layout & conventions
- `src/main.cpp` — CLI (argparse), mode routing, signal handlers, AFL loop.
- `src/config.{hpp,cpp}` — structs + `load_config()` returning
  `std::variant<Config, ConfigError>`; **no exceptions**, strict type/range validation
  with a structured `ConfigError` (path/message/expected/actual).
  `config.cpp` **cannot include `log.hpp`** — yaml-cpp pulls in `<cmath>`, whose `::log`
  collides with the `casslog` namespace in either include order (level-name validation for
  `afl.msg_log_level` therefore lives in `main()`).
- `src/log.{hpp,cpp}` — namespace `casslog`: spdlog setup (single-threaded stdout logger,
  flush on warn+), `PROXY_LOG_*` macros gated by `SPDLOG_ACTIVE_LEVEL`
  (`-Dstrip_low_logs=true` compiles trace/debug out), `parse_level()`, `escape_bytes()`,
  and a warn-level ringbuffer sink (capacity 16) exposing `recent_lines()` for
  termination dumps.
- `src/process.{hpp,cpp}` — namespace `process`: optional pre-spawn port-conflict
  check/cleanup (`handle_port_conflict()`), `prepare_target()` →
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
- Stdio redirection differs per mode: stdin comes from `target.stdin_path` when
  set (opened read-only in `prepare_target()` with `O_NONBLOCK|O_CLOEXEC`, the
  nonblocking flag cleared again so the target's reads block like regular
  stdin, then `dup2`ed onto the child's fd 0 by `fork_target()`; the proxy
  never reads or writes it — the surrounding setup creates and feeds the file,
  typically a fifo), else `/dev/null`; the target's
  stdout/stderr go to `/dev/null` by default and are forwarded to the proxy's fds with
  `--child-output` (both proxy and test pass 2). MapSizePass always pipes stdout (map
  size protocol) and sends stderr to `/dev/null`; the flag does not affect it, and it
  ignores `stdin_path` entirely (never opens it: a Pass 1 reader would unblock an
  external fifo writer whose buffered data no pass reads, and the map-size dump never
  touches stdin).
- Logging is spdlog → stdout (logger `proxy`, `flush_on(warn)` so messages survive the
  proxy's own `raise(SIGSEGV)`), runtime level via `--log-level`. Never log via spdlog
  between `fork()` and `execve()` — the pre-exec child reports failures with raw
  `dprintf()` to a saved, CLOEXEC stderr fd (async-signal-safety).
- Target crash detection: `waitpid(WNOHANG)` + `WIFSIGNALED` → proxy raises `SIGSEGV` so
  AFL registers the finding. Target teardown is a plain SIGKILL to the whole process
  group plus a bounded (~200 ms) reap of the group leader (`kill_and_reap_pgid()` in
  `main.cpp`), in all modes and on every exit path — the shared coverage map is
  shm-backed and written on every edge hit, so a SIGKILL'd target loses nothing AFL
  reads. `cleanup` is not involved in this teardown; it is only a pre-spawn
  port-conflict check (see below).
- Optional pre-spawn port cleanup (`cleanup.enabled`, default `false`): resolves
  the LISTEN socket inode for the configured port and its holders. A holder with a
  live parent is never touched (the cmplog target, another campaign, a service);
  the proxy refuses to start instead. `on_port_conflict: error` (default) reports an
  orphaned holder; `kill_orphan` SIGKILLs only orphaned holders whose exe/argv[0]
  matches the resolved target (normal vs cmplog) plus their process trees, with no
  SIGTERM grace. Runs only in proxy mode after AFL env validation and before
  `__AFL_INIT()`; test mode never scans `/proc` or kills anything.
- Targets are spawned with `PR_SET_PDEATHSIG(SIGKILL)` plus a `getppid()` race check in
  the pre-exec child (`fork_target()`), so the kernel kills the target whenever the
  proxy dies — `abort_proxy`, `crash_proxy`, or AFL killing the
  proxy — in all modes (proxy/test) and all spawn modes, even in procfs port-detection
  mode. Delivery is immediate SIGKILL — by design, since the proxy is already
  dead when it fires. It relies on the proxy staying single-threaded
  (PDEATHSIG watches the forking thread).
- `crash_proxy(message, payload)`/`abort_proxy(message, payload)` share `terminate_proxy()`
  and, before raising `SIGSEGV`/`SIGABRT`, write a termination pair into `--data-dir`
  (default `afl-cassowire-data`, created recursively): `{timestamp}-{tag}.msg` (reason)
  and `{timestamp}-{tag}.data` (the full payload built for the iteration: prefix + input
  + suffix), sharing one `YYYYmmdd-HHMMSS-mmm` stem. `-tag` is the instance kind set in
  `main()` (`normal` | `cmplog` | `test`, via `utils::set_instance_tag()`), so dumps from
  concurrently running instances stay attributable; the `.msg` content and the
  termination log line embed it as `{kind}[{tag}]: {reason}`. The `.msg` additionally
   embeds the last ≤16 warn/error lines (oldest first, console-style timestamps) captured
   by the logger's ring sink (`casslog::recent_lines()`, level = `afl.msg_log_level`,
   default `warn`); capture is independent of
   `--log-level` (logger level is floored at warn, the console sink applies the runtime
    level), so quiet runs still produce rich dumps. The `.msg` also embeds the
   current 1-based `__AFL_LOOP` iteration as an `iteration: N` line (set once per
   loop pass via `utils::set_current_iteration()` in `run_proxy_mode()`; `0` =
   termination outside the loop or test mode). Dumps are best-effort and never fatal.
   With `afl.dump_history > 0` the dump also writes the retained previous-iteration
   payloads as `{stem}.-1.data`, `{stem}.-2.data`, ... (see "Crash detection gaps").
- Payload sent over TCP is `payload.prefix + fuzz input + payload.suffix`
  (`PayloadConfig::wrap()`); values may be `!!binary`.
- Startup-coverage fix (stability): `main.cpp` has a file-scope `__AFL_COVERAGE()`
  (afl-cc `-D` macro; no-op placeholder in `afl_compat.h`). afl-cassowire is built with
  the patched `afl-clang-fast++` (`patch/force_loc.patch`), which skips PC-guard edge
  emission for this binary, so the proxy writes no coverage and `__AFL_COVERAGE_ON()` /
  `__AFL_COVERAGE_OFF()` have no effect (they are not used). `run_proxy_mode()` emits
  `__AFL_COVERAGE_DISCARD()` right before the first `__AFL_LOOP()` pass, gated by
  `afl.cov_discard_init` (default true). DISCARD `memset`s the shared map
  (`__afl_coverage_discard()` zeroes `__afl_area_ptr_backup`, plus the cmplog map), so
  startup feedback from the proxy and the instrumented target (NGINX init included) is
  not attributed to the first testcase. With `cov_discard_init: false` nothing clears it.
- Root config keys starting with `__` (e.g. `__helpers: &anchor`) are ignored by
  `load_config()` and exempted in `config.schema.json` (root `patternProperties
  "^__"`): a reserved namespace for YAML anchor/merge (`<<`) helper fragments.
  The exemption is root-only — `__`-prefixed keys inside any section are still
  rejected as unknown keys. Fixtures: the `valid_helper_anchors`,
  `invalid_single_underscore_key` and `invalid_nested_helper_key` cases in
  `tests/e2e/schema_validate/cases.py`.
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
  consecutive failure aborts the proxy for the AFL respawn. A failed
  `exchange_once()` connect rides the same path: after the immediate health
  classification a live target falls through to the probe (instead of
  returning), so a persistently unreachable listener exhausts
  `network.probe_attempts` there and aborts for the AFL respawn;
  `network.probe: false` is the explicit opt-out (retry with rate-limited
  logs, visible via the heartbeat).
- Iteration/probe sockets are armed with `SO_LINGER{1,0}`
  (`network::arm_rst_on_close()`) once their data is fully read, so `close()`
  sends RST: nothing sits in TIME_WAIT and the proxy's ephemeral port range
  cannot be exhausted by fast fuzzing.
- `port_detection.defork` and the ptrace-based port-detection modes were REMOVED
  (the schema cases `invalid_defork_key_removed` and `invalid_primary_ptrace` in
   `tests/e2e/schema_validate/cases.py` assert that both are rejected).
  Seccomp detection is now `SECCOMP_RET_USER_NOTIF`-based, which handles
  multi-process and multi-threaded targets correctly (all inherited-filter
  tasks notify the same fd).

## Crash detection gaps and termination-dump history
- The proxy's crash detection is synchronous: each iteration runs the quiescence
  probe and a race-free `check_target_state()` (reads `PF_EXITING`/`PF_SIGNALED`,
  blocks on the pidfd). A crash that happens *after* that check returns `Alive` —
  deferred/async work (timers, atexit, a worker thread, a QEMU child) — is detected
  only on the next iteration, so it is attributed to the next input and the saved
  `.data` payload may be the wrong one. This is inherent: a top-of-iteration check
  would only move the window, not close it; a full fix needs idle detection (e.g. a
  procfs syscall whitelist). The proxy mitigates it with `afl.dump_history` (default
  `1`): the last N completed payloads (prefix + input + suffix) are retained and
  written with every termination dump as `{stem}.-1.data` (most recent previous
  iteration), `{stem}.-2.data`, ... so the likely culprit survives alongside the
  current input. `0` disables the history (only `{stem}.data` is written).
- Crashes in worker children of the target (nginx workers, QEMU child processes) are
  not detected directly: only the direct child pid is watched
  (`process::check_target_state`). A dead worker stops servicing, so it surfaces as
  a probe/connect timeout → `abort_proxy` → AFL respawn, not as a crash finding. The
  dump history keeps the recent requests for triage.

## Design notes and extras
- `src/afl_compat.h` (not `.hpp`) defines *no-op* AFL++ macros instead of `#error`-ing;
  the "must use an AFL++ compiler" enforcement lives in the `meson.build` compiler
  probe. Don't add an `#error` guard to the header.
- Config keys added after the original design: `target.env`, `target.env_preserve`, `target.stdin_path`, `payload.*`,
  `afl.cov_discard_init`, `afl.dump_history`, `afl.msg_log_level`,
  `target_cmplog.*`, `network_cmplog.*`, and the required
  `AFL_CASSOWIRE_FORCE_FINAL_LOC` env var. `target_cmplog`/`network_cmplog` are standalone
  (no key falls back to `target`/`network`) and required when `afl.enable_cmplog: true`;
  in cmplog mode both replace their normal counterparts in `run_proxy_mode()` before
  spawn, so port detection, connect, timeouts, and probe all use the cmplog values.
- Port detection uses **no ptrace at all**: it is `SECCOMP_RET_USER_NOTIF`-based
  (listener fd handed over `SCM_RIGHTS` pre-exec, polled by the proxy; readiness =
  `listen` notification for the configured port's fd + bounded `/proc/net/tcp`
  confirmation, since notifications carry no syscall exit value). The
  inherited filter notifies for every thread and forked child; QEMU-mode targets
  work with `seccomp` (procfs remains the default there). `PDEATHSIG` (see above)
  is the proxy-death backstop for the target.
- Logging/target-stdio: proxy logs go through spdlog to stdout with `--log-level` (not
  `std::cout`/`std::cerr`); there are no `target.log.*` config keys — target
  output defaults to `/dev/null` and is only forwarded with `--child-output`; the
  test-mode response is logged as escaped text at info level.
- Both `afl-qemu-bridge` and `afl-qemu-trace` are supported as QEMU backends for
  binary-only fuzzing. See `default.qemu.yaml` for configuration examples and instructions
  on switching between them.

## Known limitations
- `network::wait_response()` reads until the peer closes the connection (EOF) or
  `network.timeout_ms` expires. A keep-alive server (nginx) that ignores the
  half-close (`shutdown(SHUT_WR)` in `exchange_once`) may keep the connection open
  after sending a complete response; the read then burns up to the full
  `timeout_ms` per iteration, capping throughput at roughly `1000/timeout_ms`
  exec/s per proxy (5/s at the default 200 ms; 10/s at 100 ms). The bytes already
  received are still returned as a partial response, so this shows up as slowness
  plus the "response took >= timeout_ms" WARN rather than an error. Mitigate by
  disabling/limiting target keep-alive (e.g. `Connection: close`) or keeping
  `timeout_ms` short; protocol-aware response framing (HTTP Content-Length /
  chunked) would be the proper fix. `probe_target()` uses the same half-close
  pattern for its throwaway connection.

## Review markers
Existing review notes are tagged `TODO(claude): ...` (see `grep -rn "TODO(claude)" src/`).
They mark real, still-open issues; resolved notes are deleted rather than kept as
"RESOLVED". Preserve the tag when touching those lines; don't silently drop open ones.
