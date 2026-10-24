"""E2E: afl-cassowire proxy mode driven by an AFL++ emulator (a fake afl-fuzz).

The emulator (emul.py) provides the forkserver and shared-memory sides of
afl-fuzz, so the real proxy binary runs its persistent __AFL_LOOP against the
prebuilt instrumented test-target: coverage lands in the shared map written by
the target, and in cmplog mode the cmplog-instrumented target writes compare
records into the cmplog map. The tests assert that the calc and http target
modes produce different coverage and cmplog feedback, and that the feedback
tracks the fuzzed input.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
from emul import CMP_MAP_H, CMP_MAP_SIZE, CMP_MAP_W, CMP_OPERANDS_SIZE
from runner import (
    ProxyRun,
    free_port,
    run_proxy_mode,
    seccomp_supported,
    skip_unless_shm_available,
    wire_stdin_fifo,
    write_config,
)

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="proxy-mode e2e requires Linux (SysV shmem, forkserver fds)"),
]

LOOP_COUNT = 20


def _assert_clean_run(run: ProxyRun, iterations: int = LOOP_COUNT) -> None:
    summary = run.summary
    context = f"events={summary['events']}\nproxy.log tail:\n{run.proxy_log[-2000:]}"
    assert summary["error"] is None, f"emulator error: {summary['error']}\n{context}"
    assert summary["emul_exit_code"] == 0, f"emulator exited non-zero\n{context}"
    assert summary["iterations_completed"] == iterations, f"expected {iterations} iterations\n{context}"
    events = summary["events"]
    assert len(events) == iterations
    for event in events[:-1]:
        assert event["kind"] == "stopped", f"iteration {event['iteration']} did not stop cleanly: {event}"
    last = events[-1]
    assert last["kind"] == "exited", f"__AFL_LOOP did not exhaust on the last poke: {last}"
    assert last["exit_code"] == 0, f"proxy loop exited with {last['exit_code']}\n{context}"
    assert summary["handshake"]["map_size"] is not None
    assert "SHDMEM_FUZZ" in summary["handshake"]["opts_names"]
    # Offset 0 is the proxy's own marker byte (__afl_area_ptr[0] = 1); every
    # other non-zero byte must come from the instrumented target.
    assert summary["cov"]["nonzero"] > 1, f"coverage map is empty beyond the marker byte\n{context}"


def _assert_cmplog_written(run: ProxyRun) -> None:
    assert run.summary["cmplog"] is not None
    assert run.summary["cmplog"]["nonzero"] > 0, "cmplog map is empty\n" + run.proxy_log[-2000:]


def _has_bits_only_in(a: bytes, b: bytes) -> bool:
    """True if any byte is non-zero in `a` where `b` is zero (marker byte 0 excluded)."""
    a_int = int.from_bytes(a[1:], "big")
    mask = (1 << 8 * (len(b) - 1)) - 1
    mask ^= int.from_bytes(b[1:], "big")
    return (a_int & mask) != 0


def test_coverage_differs_calc_vs_http(proxy_runner: Callable[..., ProxyRun]) -> None:
    calc = proxy_runner("calc", "calc/set1")
    http = proxy_runner("http", "http/set1")
    _assert_clean_run(calc)
    _assert_clean_run(http)

    a, b = calc.cov_bytes(), http.cov_bytes()
    assert len(a) == len(b) != 0
    assert a[1:] != b[1:], "calc and http produced identical coverage"
    assert _has_bits_only_in(a, b), "http coverage fully covers the calc edges"
    assert _has_bits_only_in(b, a), "calc coverage fully covers the http edges"


def test_cmplog_differs_calc_vs_http(proxy_runner: Callable[..., ProxyRun]) -> None:
    skip_unless_shm_available()
    calc = proxy_runner("calc", "calc/set1", cmplog=True)
    http = proxy_runner("http", "http/set1", cmplog=True)
    _assert_clean_run(calc)
    _assert_clean_run(http)
    _assert_cmplog_written(calc)
    _assert_cmplog_written(http)

    a, b = calc.cmp_bytes(), http.cmp_bytes()
    assert len(a) == len(b) != 0
    assert a != b, "calc and http produced identical cmplog feedback"


def test_coverage_tracks_input(proxy_runner: Callable[..., ProxyRun]) -> None:
    mul_add = proxy_runner("calc", "calc/set1")
    div = proxy_runner("calc", "calc/set2")
    _assert_clean_run(mul_add)
    _assert_clean_run(div)
    assert mul_add.cov_bytes()[1:] != div.cov_bytes()[1:], "coverage did not change with the corpus"


def test_cmplog_tracks_input(proxy_runner: Callable[..., ProxyRun]) -> None:
    skip_unless_shm_available()
    mul_add = proxy_runner("calc", "calc/set1", cmplog=True)
    div = proxy_runner("calc", "calc/set2", cmplog=True)
    _assert_clean_run(mul_add)
    _assert_clean_run(div)
    _assert_cmplog_written(mul_add)
    _assert_cmplog_written(div)
    assert mul_add.cmp_bytes() != div.cmp_bytes(), "cmplog feedback did not change with the corpus"


def test_seccomp_port_detection(proxy_runner: Callable[..., ProxyRun]) -> None:
    if not seccomp_supported():
        pytest.skip("SECCOMP_RET_USER_NOTIF port detection needs kernel >= 5.0")
    run = proxy_runner("calc", "calc/set1", primary="seccomp")
    _assert_clean_run(run)


def test_stdin_path_fifo_wiring(tmp_path: Path) -> None:
    # target.stdin_path wires a fifo to the target's fd 0 for the whole
    # persistent run: the --stdin-marker canary must arrive there (any
    # mismatch aborts the target before it binds, which fails the run).
    marker = "cassowire-stdin-e2e"
    fifo = tmp_path / "stdin.fifo"
    os.mkfifo(fifo)
    wire_stdin_fifo(fifo, (marker + "\n").encode())
    config = write_config(
        tmp_path,
        mode="calc",
        port=free_port(),
        stdin_path=str(fifo),
        target_extra_args=["--stdin-marker", marker],
    )
    run = run_proxy_mode(tmp_path / "run", config, "calc/set1")
    _assert_clean_run(run)


def test_cmplog_map_size_matches_runtime() -> None:
    # The cmplog segment must be exactly sizeof(struct cmp_map); a smaller one
    # would let the target's cmplog instrumentation run off the mapping.
    assert CMP_MAP_SIZE == CMP_MAP_W * 2 + CMP_MAP_W * CMP_MAP_H * CMP_OPERANDS_SIZE
    assert CMP_MAP_SIZE == 151_126_016
