"""Test harness for the afl-cassowire proxy-mode e2e tests (AFL++ emulator).

Runs the real proxy under emul.py, a stdlib-only fake afl-fuzz: it creates the
SysV shared memory segments of the AFL++ runtime (coverage map, shared-memory
testcase buffer, cmplog map) and speaks the AFL++ FS_NEW forkserver protocol on
fds 198/199, so the proxy executes its persistent __AFL_LOOP against the
prebuilt instrumented test-target. Nothing is built here: a missing binary
fails the test.

Paths can be overridden with the AFL_CASSOWIRE_BIN, CASSOWIRE_TEST_TARGET_BIN
and CASSOWIRE_TEST_TARGET_CMPLOG_BIN environment variables.
"""

import json
import os
import platform
import socket
import subprocess
import sys
import threading
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml
from emul import CMP_MAP_SIZE

REPO_ROOT = Path(__file__).resolve().parents[3]
EMUL_PATH = Path(__file__).resolve().parent / "emul.py"

RUN_TIMEOUT_SECONDS = 300
NETWORK_TIMEOUT_MS = 500
INITIAL_MS = 1000
LOOP_COUNT = 20

NORMAL_VARIANT = "afl-clang-fast++"
CMPLOG_VARIANT = "afl-clang-fast++_cmplog"


def cassowire_bin() -> Path:
    """Path to the prebuilt afl-cassowire proxy binary."""
    override = os.environ.get("AFL_CASSOWIRE_BIN")
    path = Path(override) if override else REPO_ROOT / "build" / "afl-cassowire"
    if not path.is_file():
        pytest.fail(
            f"afl-cassowire binary not found at {path} "
            "(build it first: make prepare && make prepare2 && make build, "
            "or point AFL_CASSOWIRE_BIN at an existing binary)"
        )
    return path


def test_target_bin(variant: str = NORMAL_VARIANT) -> Path:
    """Path to the prebuilt instrumented test-target (AFL++ runtime required)."""
    override_var = "CASSOWIRE_TEST_TARGET_BIN" if variant == NORMAL_VARIANT else "CASSOWIRE_TEST_TARGET_CMPLOG_BIN"
    override = os.environ.get(override_var)
    path = (
        Path(override)
        if override
        else REPO_ROOT / "tests" / "targets" / "test-target" / "build" / variant / "test-target"
    )
    if not path.is_file():
        pytest.fail(
            f"instrumented test-target not found at {path} "
            "(build it first with the AFL++ toolchain, e.g. "
            "make -C tests/targets/test-target prepare build_afl-clang-fast++, "
            f"or point {override_var} at an existing binary)"
        )
    return path


def corpus_dir(name: str) -> Path:
    """Directory of static corpus files (cycled one per __AFL_LOOP iteration)."""
    return Path(__file__).resolve().parent / "inputs" / name


def free_port() -> int:
    """Grab a free TCP port on 127.0.0.1 and release it for the target."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def write_config(
    tmp_path: Path,
    *,
    mode: str,
    port: int,
    cmplog: bool = False,
    primary: str = "procfs",
    loop_count: int = LOOP_COUNT,
    payload: dict[str, str | bytes] | None = None,
    sequence: dict[str, Any] | None = None,
    stdin_path: str | None = None,
    target_extra_args: list[str] | None = None,
) -> Path:
    """Write a proxy-mode config for the test-target (calc or http mode).

    target.args is the full argv (binary first, like execve) and must pin the
    same port the proxy watches. In cmplog mode both cmplog sections are
    emitted; the proxy switches to them because the emulator exports
    __AFL_CMPLOG_SHM_ID. Like in production, the target is NOT given
    AFL_CASSOWIRE_FORCE_FINAL_LOC (env_preserve: afl_only does not forward
    it), so only the proxy's map size is forced.
    """
    normal_binary = str(test_target_bin(NORMAL_VARIANT))
    network: dict[str, Any] = {
        "host": "127.0.0.1",
        "port": port,
        "timeout_ms": NETWORK_TIMEOUT_MS,
        "initial_ms": INITIAL_MS,
        "probe": True,
    }
    target_section: dict[str, Any] = {
        "binary": normal_binary,
        "args": [normal_binary, mode, "--port", str(port)] + (target_extra_args or []),
    }
    if stdin_path is not None:
        target_section["stdin_path"] = stdin_path
    config: dict[str, Any] = {
        "target": target_section,
        "network": network,
        "afl": {"loop_count": loop_count, "enable_cmplog": cmplog},
        "port_detection": {"primary": primary},
        "cleanup": {"enabled": False},
    }
    if payload is not None:
        config["payload"] = payload
    if sequence is not None:
        config["sequence"] = sequence
    if cmplog:
        cmplog_binary = str(test_target_bin(CMPLOG_VARIANT))
        config["target_cmplog"] = {
            "binary": cmplog_binary,
            "args": [cmplog_binary, mode, "--port", str(port)],
        }
        config["network_cmplog"] = dict(network)
    path = tmp_path / "cassowire.yaml"
    path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    return path


def wire_stdin_fifo(fifo: Path, payload: bytes) -> threading.Thread:
    """Write payload into a fifo as soon as a reader appears (the proxy's open).

    open('wb') blocks until the proxy's read end exists, so the thread must be
    started before the proxy runs. Daemonized: when a run fails before the
    proxy ever opens the fifo, the blocked open must not wedge pytest.
    """

    def run() -> None:
        with open(fifo, "wb") as writer:
            writer.write(payload)
            writer.flush()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


@dataclass(frozen=True)
class ProxyRun:
    """Result of one emulator-driven proxy run (summary + dump directory)."""

    out_dir: Path
    summary: dict[str, Any]

    @property
    def proxy_log(self) -> str:
        return (self.out_dir / "proxy.log").read_text(errors="replace")

    def cov_bytes(self) -> bytes:
        return (self.out_dir / "cov.bin").read_bytes()

    def cmp_bytes(self) -> bytes:
        return zlib.decompress((self.out_dir / "cmp.bin.zlib").read_bytes())


def run_proxy_mode(out_dir: Path, config_path: Path, corpus: str, *,
                   cmplog: bool = False, iterations: int = LOOP_COUNT) -> ProxyRun:
    """Drive one emulator run; raises AssertionError when the emulator itself crashes.

    `iterations` must match the config's afl.loop_count. Tests that expect the
    proxy to terminate early (e.g. a target crash) use 1.
    """
    command = [
        sys.executable,
        str(EMUL_PATH),
        "--proxy",
        str(cassowire_bin()),
        "--config",
        str(config_path),
        "--mode",
        "cmplog" if cmplog else "normal",
        "--iterations",
        str(iterations),
        "--out-dir",
        str(out_dir),
        "--input",
        str(corpus_dir(corpus)),
    ]
    proc = subprocess.run(command, capture_output=True, text=True, timeout=RUN_TIMEOUT_SECONDS, check=False)
    summary_path = out_dir / "summary.json"
    if not summary_path.is_file():
        raise AssertionError(
            f"emul.py produced no summary.json (exit {proc.returncode})\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    summary: dict[str, Any] = json.loads(summary_path.read_text())
    summary["emul_exit_code"] = proc.returncode
    summary["emul_stdout"] = proc.stdout
    return ProxyRun(out_dir=out_dir, summary=summary)


def seccomp_supported() -> bool:
    """SECCOMP_RET_USER_NOTIF port detection needs kernel >= 5.0."""
    release = platform.release()
    try:
        major = int(release.split(".")[0])
    except ValueError:
        return False
    return major >= 5


def skip_unless_shm_available(need: int = CMP_MAP_SIZE) -> None:
    """The cmplog map is a single SysV segment of sizeof(struct cmp_map) bytes."""
    try:
        shmmax = int(Path("/proc/sys/kernel/shmmax").read_text())
    except OSError:
        return
    if shmmax < need:
        pytest.skip(f"kernel.shmmax={shmmax} is below the {need} bytes needed for the cmplog map")
