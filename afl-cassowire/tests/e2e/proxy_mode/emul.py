#!/usr/bin/env python3
"""AFL++ emulator: a minimal afl-fuzz stand-in for afl-cassowire proxy-mode e2e tests.

Provides the afl-fuzz side of the AFL++ runtime interface so the real proxy
binary can run under `__AFL_INIT` / `__AFL_LOOP` without a live afl-fuzz:

- SysV shared memory for the coverage map (`__AFL_SHM_ID`), the shared-memory
  testcase buffer (`__AFL_SHM_FUZZ_ID`, layout `u32 len + bytes`) and, in
  cmplog mode, the compare-log map (`__AFL_CMPLOG_SHM_ID`,
  `sizeof(struct cmp_map)`).
- The AFL++ "FS_NEW" forkserver protocol on fds 198/199 over a socketpair
  (hello -> ~hello -> options [+ params] -> welcome, then one 4-byte poke /
  pid / wait-status round trip per persistent iteration).
- The environment the proxy requires (`__AFL_PERSISTENT`,
  `AFL_CASSOWIRE_FORCE_FINAL_LOC`, ...), with inherited `AFL_*`/`__AFL_*`
  variables stripped.

After the loop the emulator dumps the final coverage and cmplog maps plus a
`summary.json` into `--out-dir`; the e2e tests compare those maps across
target modes and corpora.

Protocol reference: aflpp src/instrumentation/afl-compiler-rt.o.c
(`__afl_map_shm`, `__afl_start_forkserver`, `__afl_persistent_loop`) and
src/src/afl-forkserver.c. Constants must match the aflpp tree this repo's
toolchain is built from.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import hashlib
import json
import os
import signal
import socket
import struct
import sys
import time
import zlib
from pathlib import Path
from typing import Any

# --- AFL++ constants (include/config.h, include/types.h) ---
FORKSRV_FD = 198
FS_VERSION_BASE = 0x41464C00
FS_NEW_VERSION_MIN = 1
FS_NEW_VERSION_MAX = 1
FS_NEW_OPT_MAPSIZE = 0x00000001
FS_NEW_OPT_SHDMEM_FUZZ = 0x00000002
FS_NEW_OPT_FUTEX = 0x00000004
FS_NEW_OPT_ALLOCSIZE_DERIVE = 0x00000008
FS_NEW_OPT_BUG_MAP = 0x00000010
FS_NEW_OPT_AUTODICT = 0x00000800
FS_OPT_IJON = 0x04000000
FS_OPT_C11 = 0x20000000
FS_NEW_OPT_NAMES = {
    FS_NEW_OPT_MAPSIZE: "MAPSIZE",
    FS_NEW_OPT_SHDMEM_FUZZ: "SHDMEM_FUZZ",
    FS_NEW_OPT_FUTEX: "FUTEX",
    FS_NEW_OPT_ALLOCSIZE_DERIVE: "ALLOCSIZE_DERIVE",
    FS_NEW_OPT_BUG_MAP: "BUG_MAP",
    FS_NEW_OPT_AUTODICT: "AUTODICT",
    FS_OPT_IJON: "IJON",
    FS_OPT_C11: "C11",
}

# sizeof(struct cmp_map) (include/cmplog.h): packed 2-byte cmp_header per slot
# plus log[CMP_MAP_W][CMP_MAP_H] of 72-byte packed cmp_operands.
CMP_MAP_W = 65536
CMP_MAP_H = 32
CMP_OPERANDS_SIZE = 72
CMP_MAP_SIZE = CMP_MAP_W * 2 + CMP_MAP_W * CMP_MAP_H * CMP_OPERANDS_SIZE

# Coverage map: must hold the forced final loc (+1) of every writer and the
# MAP_INITIAL_SIZE (2 MiB) default the runtime memsets when unforced.
DEFAULT_COV_SHM_SIZE = 2 << 20
DEFAULT_FUZZ_SHM_SIZE = 1 << 20
DEFAULT_FORCE_FINAL_LOC = 70000
DEFAULT_HANDSHAKE_TIMEOUT_S = 60.0
DEFAULT_POKE_TIMEOUT_S = 30.0
DEFAULT_PROXY_WAIT_TIMEOUT_S = 30.0

_ENV_KEEP = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TERM")


class EmulError(Exception):
    pass


# --- SysV shared memory (the distrib afl-compiler-rt is built without USEMMAP) ---
_libc = ctypes.CDLL(None, use_errno=True)
_shmget = _libc.shmget
_shmget.argtypes = [ctypes.c_int, ctypes.c_size_t, ctypes.c_int]
_shmget.restype = ctypes.c_int
_shmat = _libc.shmat
_shmat.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
_shmat.restype = ctypes.c_void_p
_shmdt = _libc.shmdt
_shmdt.argtypes = [ctypes.c_void_p]
_shmdt.restype = ctypes.c_int
_shmctl = _libc.shmctl
_shmctl.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
_shmctl.restype = ctypes.c_int

_IPC_PRIVATE = 0
_IPC_CREAT = 0o1000
_IPC_RMID = 0
_SHMAT_FAIL = ctypes.c_void_p(-1).value
assert _SHMAT_FAIL is not None


class SysvShm:
    """A SysV shared memory segment, marked for removal immediately at attach."""

    def __init__(self, size: int) -> None:
        shmid = int(_shmget(_IPC_PRIVATE, size, _IPC_CREAT | 0o600))
        if shmid < 0:
            raise EmulError(f"shmget(IPC_PRIVATE, {size}) failed: errno={ctypes.get_errno()}")
        addr = _shmat(shmid, None, 0)
        ctypes.get_errno()
        if addr is None or addr == _SHMAT_FAIL:
            int(_shmctl(shmid, _IPC_RMID, None))
            raise EmulError(f"shmat({shmid}, size={size}) failed")
        self.id = shmid
        self.size = size
        self.addr = int(addr)
        # Remove-on-close: the segment dies once every attachment is gone.
        int(_shmctl(shmid, _IPC_RMID, None))

    def write(self, data: bytes, offset: int = 0) -> None:
        if offset + len(data) > self.size:
            raise EmulError(f"shm write of {len(data)} bytes at {offset} overflows {self.size}-byte segment")
        ctypes.memmove(self.addr + offset, data, len(data))

    def read(self) -> bytes:
        return ctypes.string_at(self.addr, self.size)

    def close(self) -> None:
        if self.addr:
            int(_shmdt(ctypes.c_void_p(self.addr)))
            self.addr = 0


# --- forkserver protocol helpers ---
def _recv_u32(sock: socket.socket, what: str, timeout_s: float) -> int:
    sock.settimeout(timeout_s)
    buf = b""
    while len(buf) < 4:
        try:
            chunk = sock.recv(4 - len(buf))
        except TimeoutError as exc:
            raise EmulError(f"timeout waiting for {what} from proxy (see proxy.log)") from exc
        if not chunk:
            raise EmulError(f"EOF while waiting for {what} from proxy (proxy died? see proxy.log)")
        buf += chunk
    return int(struct.unpack("=I", buf)[0])


def _send_u32(sock: socket.socket, value: int, what: str) -> None:
    try:
        sock.sendall(struct.pack("=I", value & 0xFFFFFFFF))
    except OSError as exc:
        raise EmulError(f"failed to send {what} to proxy: {exc}") from exc


def do_handshake(sock: socket.socket, timeout_s: float) -> dict[str, Any]:
    hello = _recv_u32(sock, "forkserver hello", timeout_s)
    if not FS_VERSION_BASE <= hello <= FS_VERSION_BASE + 0xFF:
        raise EmulError(f"unexpected forkserver hello 0x{hello:08x} (expected 0x41464c00..0x41464cff)")
    version = hello - FS_VERSION_BASE
    if not FS_NEW_VERSION_MIN <= version <= FS_NEW_VERSION_MAX:
        raise EmulError(f"unsupported forkserver protocol version {version}")
    _send_u32(sock, hello ^ 0xFFFFFFFF, "handshake reply")

    opts = _recv_u32(sock, "forkserver options", timeout_s)
    map_size: int | None = None
    if opts & FS_NEW_OPT_MAPSIZE:
        map_size = _recv_u32(sock, "map size parameter", timeout_s)
    if opts & FS_NEW_OPT_AUTODICT:
        dict_len = _recv_u32(sock, "autodict length", timeout_s)
        raise EmulError(f"unexpected AUTODICT option (length {dict_len}) - not supported by the emulator")
    if not opts & FS_NEW_OPT_SHDMEM_FUZZ:
        raise EmulError("proxy did not request SHDMEM_FUZZ - check __AFL_SHM_FUZZ_ID in the emulator env")
    if opts & FS_NEW_OPT_FUTEX:
        raise EmulError("unexpected FUTEX option - emulator expects fd-based persistent sync")

    welcome = _recv_u32(sock, "forkserver welcome", timeout_s)
    if welcome != hello:
        raise EmulError(f"forkserver welcome 0x{welcome:08x} != hello 0x{hello:08x}")
    return {
        "hello": f"0x{hello:08x}",
        "version": version,
        "opts": f"0x{opts:08x}",
        "opts_names": [name for bit, name in FS_NEW_OPT_NAMES.items() if opts & bit],
        "map_size": map_size,
    }


def drive_iterations(
    sock: socket.socket,
    fuzz_shm: SysvShm,
    inputs: list[bytes],
    iterations: int,
    poke_timeout_s: float,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for i in range(1, iterations + 1):
        data = inputs[(i - 1) % len(inputs)]
        fuzz_shm.write(struct.pack("=I", len(data)) + data)
        _send_u32(sock, 0, f"poke {i}")
        pid = _recv_u32(sock, f"child pid (poke {i})", poke_timeout_s)
        status = _recv_u32(sock, f"wait status (poke {i})", poke_timeout_s)
        event = _classify_wait(i, pid, status)
        events.append(event)
        if event["kind"] == "signaled":
            break
    return events


def _classify_wait(iteration: int, pid: int, raw: int) -> dict[str, Any]:
    event: dict[str, Any] = {
        "iteration": iteration,
        "pid": pid,
        "kind": "other",
        "raw_status": raw,
        "signal": None,
        "exit_code": None,
    }
    if os.WIFSIGNALED(raw):
        event["kind"] = "signaled"
        event["signal"] = signal.Signals(os.WTERMSIG(raw)).name
    elif os.WIFEXITED(raw):
        event["kind"] = "exited"
        event["exit_code"] = os.WEXITSTATUS(raw)
    elif os.WIFSTOPPED(raw):
        event["kind"] = "stopped"
        event["signal"] = signal.Signals(os.WSTOPSIG(raw)).name
    return event


def _exit_fields(raw: int) -> dict[str, Any]:
    if os.WIFSIGNALED(raw):
        return {"code": None, "signal": signal.Signals(os.WTERMSIG(raw)).name}
    if os.WIFEXITED(raw):
        return {"code": os.WEXITSTATUS(raw), "signal": None}
    return {"code": None, "signal": None}


# --- proxy process management ---
def build_env(args: argparse.Namespace, cov_id: int, fuzz_id: int, cmplog_id: int | None) -> dict[str, str]:
    env = {key: os.environ[key] for key in _ENV_KEEP if key in os.environ}
    env["__AFL_SHM_ID"] = str(cov_id)
    env["__AFL_SHM_FUZZ_ID"] = str(fuzz_id)
    env["__AFL_PERSISTENT"] = "1"
    env["AFL_CASSOWIRE_FORCE_FINAL_LOC"] = str(args.force_final_loc)
    # Like real afl-fuzz: the runtime's __afl_map_shm() demands AFL_MAP_SIZE
    # (>= MAP_SIZE) whenever __afl_final_loc exceeds the default map size.
    env["AFL_MAP_SIZE"] = str(args.cov_shm_size)
    env["AFL_NO_IJON"] = "1"
    env["AFL_NO_C11"] = "1"
    if cmplog_id is not None:
        env["__AFL_CMPLOG_SHM_ID"] = str(cmplog_id)
    for item in args.env:
        key, sep, value = item.partition("=")
        if not sep or not key:
            raise EmulError(f"bad --env {item!r} (expected KEY=VALUE)")
        env[key] = value
    return env


def _child_exec_proxy(
    proxy_argv: list[str],
    out_dir: Path,
    env: dict[str, str],
    parent_sock: socket.socket,
    child_sock: socket.socket,
    log_path: Path,
) -> None:
    """Runs in the forked child; replaces itself with the proxy and never returns."""
    try:
        # One full-duplex socket end for both forkserver fds: the child reads
        # pokes on 198 and writes hello/pid/status on 199.
        os.dup2(child_sock.fileno(), FORKSRV_FD)
        os.dup2(child_sock.fileno(), FORKSRV_FD + 1)
        child_sock.close()
        parent_sock.close()
        os.chdir(out_dir)
        fd = os.open(str(log_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.dup2(fd, 1)
        os.dup2(fd, 2)
        if fd > 2:
            os.close(fd)
        os.execve(proxy_argv[0], proxy_argv, env)
    except OSError:
        pass
    os._exit(127)


def wait_proxy(proxy_pid: int, timeout_s: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while True:
        waited, status = os.waitpid(proxy_pid, os.WNOHANG)
        if waited == proxy_pid:
            return {"killed": False, **_exit_fields(status)}
        if time.monotonic() > deadline:
            _kill(proxy_pid)
            _, status = os.waitpid(proxy_pid, 0)
            return {"killed": True, **_exit_fields(status)}
        time.sleep(0.05)


def _kill(pid: int) -> None:
    if pid <= 0:
        return
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.kill(pid, signal.SIGKILL)


# --- inputs, outputs ---
def collect_inputs(paths: list[str], fuzz_shm_size: int) -> list[bytes]:
    files: list[Path] = []
    for item in paths:
        path = Path(item)
        if path.is_dir():
            files.extend(sorted(entry for entry in path.iterdir() if entry.is_file()))
        else:
            files.append(path)
    if not files:
        raise EmulError("no corpus inputs found")
    inputs: list[bytes] = []
    for path in files:
        data = path.read_bytes()
        if not data:
            raise EmulError(f"empty corpus input: {path}")
        if len(data) > fuzz_shm_size - 4:
            raise EmulError(f"corpus input too large for the fuzz shm: {path} ({len(data)} bytes)")
        inputs.append(data)
    return inputs


def _describe_map(name: str, data: bytes) -> dict[str, Any]:
    return {
        "file": name,
        "bytes": len(data),
        "nonzero": len(data) - data.count(0),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


# --- the run itself ---
def run_proxy(args: argparse.Namespace, out_dir: Path, inputs: list[bytes]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "ok": False,
        "error": None,
        "proxy": str(args.proxy),
        "config": str(args.config),
        "mode": args.mode,
        "iterations_requested": args.iterations,
        "inputs": [Path(p).name for p in args.input],
        "handshake": None,
        "events": [],
        "iterations_completed": 0,
        "proxy_exit": None,
        "cov": None,
        "cmplog": None,
    }
    cov: SysvShm | None = None
    fuzz: SysvShm | None = None
    cmp_shm: SysvShm | None = None
    proxy_pid = 0
    last_child_pid = 0
    sock: socket.socket | None = None
    try:
        cov = SysvShm(args.cov_shm_size)
        fuzz = SysvShm(args.fuzz_shm_size)
        if args.mode == "cmplog":
            cmp_shm = SysvShm(CMP_MAP_SIZE)
        parent_sock, child_sock = socket.socketpair()
        try:
            env = build_env(args, cov.id, fuzz.id, cmp_shm.id if cmp_shm is not None else None)
            proxy_argv = [str(args.proxy), *args.proxy_arg, "-c", str(args.config), "proxy"]
            proxy_pid = os.fork()
            if proxy_pid == 0:
                log_path = out_dir / "proxy.log"
                _child_exec_proxy(proxy_argv, out_dir, env, parent_sock, child_sock, log_path)
        finally:
            child_sock.close()
        sock = parent_sock

        summary["handshake"] = do_handshake(parent_sock, args.handshake_timeout)
        events = drive_iterations(parent_sock, fuzz, inputs, args.iterations, args.poke_timeout)
        summary["events"] = events
        summary["iterations_completed"] = len(events)
        if events:
            last_child_pid = int(events[-1]["pid"] or 0)
        parent_sock.close()
        sock = None

        summary["proxy_exit"] = wait_proxy(proxy_pid, args.proxy_wait_timeout)
        cov_data = cov.read()
        (out_dir / "cov.bin").write_bytes(cov_data)
        summary["cov"] = _describe_map("cov.bin", cov_data)
        if cmp_shm is not None:
            cmp_data = cmp_shm.read()
            (out_dir / "cmp.bin.zlib").write_bytes(zlib.compress(cmp_data, 1))
            summary["cmplog"] = _describe_map("cmp.bin.zlib", cmp_data)

        last = events[-1] if events else None
        ok = (
            len(events) == args.iterations
            and last is not None
            and last["kind"] == "exited"
            and last["exit_code"] == 0
            and all(event["kind"] == "stopped" for event in events[:-1])
        )
        summary["ok"] = ok
        if not ok:
            summary["error"] = "proxy run finished uncleanly (see events and proxy.log)"
    except EmulError as exc:
        summary["error"] = str(exc)
    finally:
        if sock is not None:
            sock.close()
        if proxy_pid > 0 and summary["proxy_exit"] is None:
            # Kill the persistent child first: it is the target's parent, so
            # PDEATHSIG takes the target down with it.
            _kill(last_child_pid)
            _kill(proxy_pid)
            try:
                _, status = os.waitpid(proxy_pid, 0)
                summary["proxy_exit"] = {"killed": True, **_exit_fields(status)}
            except ChildProcessError:
                pass
        for shm in (cov, fuzz, cmp_shm):
            if shm is not None:
                shm.close()
    return summary


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AFL++ emulator for afl-cassowire proxy-mode e2e tests")
    parser.add_argument("--proxy", required=True, help="path to the afl-cassowire binary")
    parser.add_argument("--config", required=True, help="proxy config.yaml")
    parser.add_argument("--mode", choices=("normal", "cmplog"), default="normal")
    parser.add_argument("--iterations", type=int, required=True, help="__AFL_LOOP iterations (match afl.loop_count)")
    parser.add_argument("--input", action="append", required=True, help="corpus file/dir, cycled per iteration")
    parser.add_argument("--out-dir", required=True, help="directory for summary.json, cov.bin, cmp.bin.zlib, proxy.log")
    parser.add_argument("--env", action="append", default=[], help="KEY=VALUE added to the proxy environment")
    parser.add_argument("--proxy-arg", action="append", default=[], help="extra argv for the proxy (before -c)")
    parser.add_argument("--cov-shm-size", type=int, default=DEFAULT_COV_SHM_SIZE)
    parser.add_argument("--fuzz-shm-size", type=int, default=DEFAULT_FUZZ_SHM_SIZE)
    parser.add_argument("--force-final-loc", type=int, default=DEFAULT_FORCE_FINAL_LOC)
    parser.add_argument("--handshake-timeout", type=float, default=DEFAULT_HANDSHAKE_TIMEOUT_S)
    parser.add_argument("--poke-timeout", type=float, default=DEFAULT_POKE_TIMEOUT_S)
    parser.add_argument("--proxy-wait-timeout", type=float, default=DEFAULT_PROXY_WAIT_TIMEOUT_S)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(130))
    # Resolve before the forked child chdir()s into the out dir.
    args.proxy = str(Path(args.proxy).resolve())
    args.config = str(Path(args.config).resolve())
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        inputs = collect_inputs(args.input, args.fuzz_shm_size)
        summary = run_proxy(args, out_dir, inputs)
    except EmulError as exc:
        summary = {"ok": False, "error": str(exc)}
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    status = "ok" if summary.get("ok") else f"FAILED: {summary.get('error')}"
    print(f"emul: {status} ({summary.get('iterations_completed', 0)}/{args.iterations} iterations)")
    return 0 if summary.get("ok") else 3


if __name__ == "__main__":
    sys.exit(main())
