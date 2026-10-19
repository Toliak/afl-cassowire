"""Replay a target corpus against its gcov-instrumented binary.

The replay writes coverage counters (``.gcda``) into the instrumented build
tree; ``collect-cov`` then turns those counters into an lcov/genhtml report.
"""

from __future__ import annotations

import contextlib
import os
import signal
import socket
import subprocess
import time
from pathlib import Path

from .common import TargetError, load_target_module, target_dir

DEFAULT_HOST = "127.0.0.1"
DEFAULT_STARTUP_MS = 5000
DEFAULT_TIMEOUT_MS = 200


def _as_bytes(value: object, key: str) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode()
    raise TargetError(f"COVERAGE[{key!r}] must be a string or bytes")


def _target_path(target: Path, value: object) -> Path:
    path = Path(str(value))
    return path if path.is_absolute() else target / path


def _resolve_gcov_dir(target: Path, cov: dict[str, object]) -> Path:
    raw = cov.get("gcov_dir")
    if raw:
        gcov_dir = _target_path(target, raw)
        if not gcov_dir.is_dir():
            raise TargetError(f"gcov dir not found: {gcov_dir}")
        return gcov_dir
    raise TargetError("COVERAGE must define 'gcov_dir' for replay-cov")


def _has_glob(spec: str) -> bool:
    return any(ch in spec for ch in "*?[")


def _expand_corpus(target: Path, specs: object) -> list[Path]:
    if isinstance(specs, str):
        specs = [specs]
    if not isinstance(specs, (list, tuple)):
        raise TargetError("COVERAGE['corpus'] must be a list")

    files: list[Path] = []
    seen: set[Path] = set()
    for spec in specs:
        raw = str(spec)
        matches = sorted(target.glob(raw)) if _has_glob(raw) else [_target_path(target, raw)]
        for match in matches:
            candidates = (
                sorted(p for p in match.iterdir() if p.is_file()) if match.is_dir() else [match]
            )
            for candidate in candidates:
                if not candidate.is_file():
                    continue
                resolved = candidate.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                files.append(candidate)
    if not files:
        raise TargetError(f"no corpus files matched {specs!r}")
    return files


def _argv(cov: dict[str, object], target: Path) -> list[str]:
    raw_binary = cov.get("binary")
    if not raw_binary:
        raise TargetError("COVERAGE must define 'binary' for replay-cov")
    binary = str(raw_binary).replace("{target_dir}", target.as_posix())
    argv = [binary]

    raw_args = cov.get("args", [])
    if not isinstance(raw_args, (list, tuple)):
        raise TargetError("COVERAGE['args'] must be a list")
    for arg in raw_args:
        argv.append(str(arg).replace("{target_dir}", target.as_posix()))
    return argv


def _spawn(cov: dict[str, object], target: Path, log: Path) -> subprocess.Popen[bytes]:
    argv = _argv(cov, target)
    binary = _target_path(target, argv[0])
    if not binary.is_file():
        raise TargetError(f"gcov binary not found: {binary}")
    argv[0] = binary.as_posix()

    env = os.environ.copy()
    raw_env = cov.get("env", {})
    if not isinstance(raw_env, dict):
        raise TargetError("COVERAGE['env'] must be a dict")
    for key, value in raw_env.items():
        env[str(key)] = str(value).replace("{target_dir}", target.as_posix())

    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("ab") as out:
        return subprocess.Popen(
            argv,
            cwd=target,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )


def _wait_for_port(host: str, port: int, proc: subprocess.Popen[bytes], timeout_ms: int, log: Path) -> None:
    deadline = time.monotonic() + timeout_ms / 1000.0
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise TargetError(
                f"target exited with status {proc.returncode} before binding {host}:{port}; see {log}"
            )
        try:
            with socket.create_connection((host, port), timeout=0.1):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(0.02)
    raise TargetError(f"target did not bind {host}:{port} within {timeout_ms} ms ({last_error}); see {log}")


def _exchange(host: str, port: int, payload: bytes, timeout_ms: int) -> int:
    timeout = timeout_ms / 1000.0
    received = 0
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(payload)
        with contextlib.suppress(OSError):
            sock.shutdown(socket.SHUT_WR)
        while True:
            try:
                chunk = sock.recv(65536)
            except TimeoutError:
                break
            except OSError:
                break
            if not chunk:
                break
            received += len(chunk)
    return received


def _stop(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=2)


def replay_cov(name: str) -> dict[str, object]:
    """Replay the target corpus into the gcov build's ``.gcda`` counters."""
    mod = load_target_module(name)
    cov = getattr(mod, "COVERAGE", None)
    if not isinstance(cov, dict):
        raise TargetError(f"{name}: COVERAGE must be a dict")

    target = target_dir(name)
    gcov_dir = _resolve_gcov_dir(target, cov)
    corpus = _expand_corpus(target, cov.get("corpus", []))
    host = str(cov.get("host", DEFAULT_HOST))
    port = int(cov.get("port", 0))
    if not 1 <= port <= 65535:
        raise TargetError(f"COVERAGE['port'] must be 1-65535, got {port}")
    startup_ms = int(cov.get("startup_ms", DEFAULT_STARTUP_MS))
    timeout_ms = int(cov.get("timeout_ms", DEFAULT_TIMEOUT_MS))
    prefix = _as_bytes(cov.get("payload_prefix"), "payload_prefix")
    suffix = _as_bytes(cov.get("payload_suffix"), "payload_suffix")

    removed = 0
    for stale in gcov_dir.rglob("*.gcda"):
        stale.unlink()
        removed += 1

    log = target / "cov" / "replay-target.log"
    if log.exists():
        log.unlink()

    proc = _spawn(cov, target, log)
    restarts = 0
    errors: list[str] = []
    bytes_received = 0
    try:
        _wait_for_port(host, port, proc, startup_ms, log)
        for path in corpus:
            if proc.poll() is not None:
                restarts += 1
                proc = _spawn(cov, target, log)
                _wait_for_port(host, port, proc, startup_ms, log)
            payload = prefix + path.read_bytes() + suffix
            try:
                bytes_received += _exchange(host, port, payload, timeout_ms)
            except OSError as exc:
                errors.append(f"{path.name}: {exc}")
    finally:
        _stop(proc)

    return {
        "target": name,
        "gcov_dir": gcov_dir.as_posix(),
        "corpus": len(corpus),
        "gcda_removed": removed,
        "restarts": restarts,
        "bytes_received": bytes_received,
        "errors": errors,
        "target_log": log.as_posix(),
    }
