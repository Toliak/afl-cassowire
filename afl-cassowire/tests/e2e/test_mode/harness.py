"""Test harness for the afl-cassowire `test`-mode e2e tests.

Runs the real binaries: `build/afl-cassowire test --input ...` against the
prebuilt instrumented test-target (`tests/targets/test-target`, built with
afl-clang-fast++ - the dump-map pass needs the AFL++ runtime). Nothing is
built here: a missing binary fails the test.

Paths can be overridden with the AFL_CASSOWIRE_BIN and CASSOWIRE_TEST_TARGET_BIN
environment variables.
"""

import os
import platform
import re
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]

RUN_TIMEOUT_SECONDS = 60
NETWORK_TIMEOUT_MS = 2000


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


def test_target_bin() -> Path:
    """Path to the prebuilt instrumented test-target (AFL++ runtime required)."""
    override = os.environ.get("CASSOWIRE_TEST_TARGET_BIN")
    path = (
        Path(override)
        if override
        else REPO_ROOT / "tests" / "targets" / "test-target" / "build" / "afl-clang-fast++" / "test-target"
    )
    if not path.is_file():
        pytest.fail(
            f"instrumented test-target not found at {path} "
            "(build it first with the AFL++ toolchain, e.g. "
            "make -C tests/targets/test-target prepare build_afl-clang-fast++, "
            "or point CASSOWIRE_TEST_TARGET_BIN at an existing binary)"
        )
    return path


def free_port() -> int:
    """Grab a free TCP port on 127.0.0.1 and release it for the target."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        port = int(sock.getsockname()[1])
    return port


def write_config(
    tmp_path: Path,
    *,
    target_args: list[str],
    port: int,
    payload: dict[str, str] | None = None,
    primary: str = "procfs",
) -> Path:
    """Write a config for the test-target; target_args is the full argv (binary first)."""
    config: dict[str, Any] = {
        "target": {"binary": target_args[0], "args": target_args},
        "network": {
            "host": "127.0.0.1",
            "port": port,
            "timeout_ms": NETWORK_TIMEOUT_MS,
            "initial_ms": NETWORK_TIMEOUT_MS,
        },
        "port_detection": {"primary": primary},
        "cleanup": {"enabled": False},
    }
    if payload is not None:
        config["payload"] = payload
    path = tmp_path / "cassowire.yaml"
    path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    return path


@dataclass(frozen=True)
class RunResult:
    """Outcome of one afl-cassowire invocation with captured output."""

    returncode: int
    stdout: str
    stderr: str

    def detail(self) -> str:
        return f"returncode={self.returncode}\n--- stdout ---\n{self.stdout}\n--- stderr ---\n{self.stderr}"


def run_cassowire(config_path: Path, *args: str, stdin: bytes | None = None) -> RunResult:
    """Run `afl-cassowire -c <config> <args...>`; global options precede the subcommand."""
    proc = subprocess.run(
        [str(cassowire_bin()), "-c", str(config_path), *args],
        input=stdin,
        capture_output=True,
        timeout=RUN_TIMEOUT_SECONDS,
    )
    return RunResult(
        returncode=proc.returncode,
        stdout=proc.stdout.decode(errors="replace"),
        stderr=proc.stderr.decode(errors="replace"),
    )


def log_lines(stdout: str, level: str) -> list[str]:
    """Proxy log lines of one level ([timestamp] [level] message pattern)."""
    return [line for line in stdout.splitlines() if f"[{level}]" in line]


def error_lines(stdout: str) -> list[str]:
    """[error]/[critical] lines; the happy path must not produce any."""
    return log_lines(stdout, "error") + log_lines(stdout, "critical")


def map_sizes(stdout: str) -> list[int]:
    """Map sizes reported by the dump-map pass ("map size: <n>" INFO lines)."""
    return [int(match) for match in re.findall(r"\[info\] map size: (\d+)", stdout)]


def escaped(data: bytes) -> str:
    """Escape bytes the way casslog::escape_bytes() renders them in the Response line."""
    return "".join(chr(byte) if 0x20 <= byte < 0x7F else f"\\x{byte:02x}" for byte in data)


def target_map_size(target: Path) -> int:
    """Map size the target's AFL++ runtime dumps for AFL_DUMP_MAP_SIZE=1.

    The runtime prints "<n>\\n" to stdout and exits (255) before main(), so the
    run is safe: no server is started.
    """
    proc = subprocess.run(
        [str(target), "calc"],
        env={**os.environ, "AFL_DUMP_MAP_SIZE": "1"},
        capture_output=True,
        timeout=RUN_TIMEOUT_SECONDS,
    )
    assert proc.returncode == 255, (
        f"expected the AFL_DUMP_MAP_SIZE run of {target} to exit 255, got {proc.returncode}: "
        f"{proc.stdout!r} / {proc.stderr!r}"
    )
    return int(proc.stdout.strip())


def seccomp_supported() -> bool:
    """SECCOMP_RET_USER_NOTIF port detection needs kernel >= 5.0."""
    release = platform.release()
    try:
        major = int(release.split(".")[0])
    except ValueError:
        return False
    return major >= 5
