"""E2E: afl-cassowire proxy mode driven by an AFL++ emulator (a fake afl-fuzz).

The emulator (emul.py) provides the forkserver and shared-memory sides of
afl-fuzz, so the real proxy binary runs its persistent __AFL_LOOP against the
prebuilt instrumented test-target: coverage lands in the shared map written by
the target, and in cmplog mode the cmplog-instrumented target writes compare
records into the cmplog map. The tests assert that the calc, http and cache target
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
    corpus_dir,
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


# --- post-exchange coverage window (afl.cov_discard_probe) ------------------
#
# The window snapshots the map(s) right after the input exchange and restores
# them after the post-response probe, so probe-only feedback never reaches
# afl-fuzz. The probe still perturbs the target's __afl_prev_loc (the target is
# a long-lived process), so edge *counts* and even a few indices of the next
# exchange can differ between runs; the assertions therefore work on the
# presence of edges (counts are monotonic, u8 wrap notwithstanding) and on the
# cmp_map `hits` counters, which only grow.


def _window_run(
    tmp_path: Path,
    *,
    probe: bool,
    discard: bool,
    cmplog: bool = False,
    iterations: int = LOOP_COUNT,
    target_extra_args: list[str] | None = None,
    discard_cmplog: bool = True,
) -> ProxyRun:
    tmp_path.mkdir(parents=True, exist_ok=True)
    config = write_config(
        tmp_path,
        mode="calc",
        port=free_port(),
        loop_count=iterations,
        cmplog=cmplog,
        probe=probe,
        cov_discard_probe=discard,
        cov_discard_probe_cmplog=discard_cmplog,
        target_extra_args=target_extra_args,
    )
    return run_proxy_mode(tmp_path / "run", config, "calc/set1", cmplog=cmplog, iterations=iterations)


def _presence(raw: bytes) -> set[int]:
    """Indices with a non-zero map byte (an edge was hit at least once)."""
    return {index for index, value in enumerate(raw) if value}


def _cmp_hits(raw: bytes) -> list[int]:
    """The 6-bit `hits` field of every cmp_map header (u16, little endian)."""
    return [int.from_bytes(raw[2 * key:2 * key + 2], "little") & 0x3F for key in range(CMP_MAP_W)]


def test_probe_coverage_window_removes_probe_edges(tmp_path: Path) -> None:
    window = _window_run(tmp_path / "window", probe=True, discard=True)
    unwindowed = _window_run(tmp_path / "unwindowed", probe=True, discard=False)
    _assert_clean_run(window)
    _assert_clean_run(unwindowed)
    window_edges = _presence(window.cov_bytes())
    unwindowed_edges = _presence(unwindowed.cov_bytes())
    extra = sorted(window_edges - unwindowed_edges)
    assert not extra, f"afl.cov_discard_probe produced edges absent without the window: {extra[:10]}"
    probe_only = sorted(unwindowed_edges - window_edges)
    assert probe_only, "the probe contributed no unique edge; nothing was discarded"


def test_probe_cmplog_window_removes_probe_comparisons(tmp_path: Path) -> None:
    skip_unless_shm_available()
    # The target's own request path does not compare anything on an empty
    # request, so --cmplog-canary adds one comparison per accepted connection:
    # the exchange connections and the request-less health probes both run it.
    # CmpLog keys are PC hashes (ASLR differs between runs), so compare the
    # aggregate hits, which is layout independent: the window removes the
    # probe's extra hits.
    iterations = 4
    extra = ["--cmplog-canary"]
    window = _window_run(
        tmp_path / "window", probe=True, discard=True, cmplog=True,
        iterations=iterations, target_extra_args=extra,
    )
    unwindowed = _window_run(
        tmp_path / "unwindowed", probe=True, discard=True, cmplog=True,
        iterations=iterations, target_extra_args=extra, discard_cmplog=False,
    )
    _assert_clean_run(window, iterations=iterations)
    _assert_clean_run(unwindowed, iterations=iterations)
    _assert_cmplog_written(window)
    window_hits = sum(_cmp_hits(window.cmp_bytes()))
    unwindowed_hits = sum(_cmp_hits(unwindowed.cmp_bytes()))
    assert window_hits < unwindowed_hits, (
        f"afl.cov_discard_probe_cmplog kept the probe's comparison: "
        f"window hits {window_hits}, unwindowed {unwindowed_hits}"
    )


def test_cache_prng_gate_coverage(proxy_runner: Callable[..., ProxyRun]) -> None:
    near = proxy_runner("cache", "cache_prng/near")
    solved = proxy_runner("cache", "cache_prng/solved")
    _assert_clean_run(near)
    _assert_clean_run(solved)

    near_cov, solved_cov = near.cov_bytes(), solved.cov_bytes()
    assert near_cov[1:] != solved_cov[1:], "solving the gate did not change coverage"
    assert _has_bits_only_in(solved_cov, near_cov), "no coverage is unique to the gated PRNG region"
    assert _has_bits_only_in(near_cov, solved_cov), "no coverage is unique to the locked gate path"


def test_cache_prng_gate_cmplog_feedback(proxy_runner: Callable[..., ProxyRun]) -> None:
    skip_unless_shm_available()
    near = proxy_runner("cache", "cache_prng/near", cmplog=True)
    solved = proxy_runner("cache", "cache_prng/solved", cmplog=True)
    _assert_clean_run(near)
    _assert_clean_run(solved)
    _assert_cmplog_written(near)
    _assert_cmplog_written(solved)
    assert near.cmp_bytes() != solved.cmp_bytes(), "solving the gate did not change cmplog feedback"


def _lottery_run(
    tmp_path: Path,
    *,
    with_crash: bool,
    iterations: int,
) -> tuple[ProxyRun, Path]:
    """Run one cache lottery campaign; returns (run, request-log path)."""
    port = free_port()
    request_log = tmp_path / "requests.log"
    target_args = ["--log-requests", str(request_log)]
    if with_crash:
        target_args = ["--with-crash", *target_args]
    config = write_config(
        tmp_path,
        mode="cache",
        port=port,
        loop_count=iterations,
        target_extra_args=target_args,
    )
    run = run_proxy_mode(tmp_path / "run", config, "cache_lottery/repeat", iterations=iterations)
    return run, request_log


def test_cache_lottery_cold_miss_is_safe(tmp_path: Path) -> None:
    run, request_log = _lottery_run(tmp_path, with_crash=True, iterations=1)
    _assert_clean_run(run, iterations=1)
    assert [index for index, _ in _request_log_lines(request_log)] == [1]


def test_cache_lottery_crashes_on_warm_hit(tmp_path: Path) -> None:
    run, request_log = _lottery_run(tmp_path, with_crash=True, iterations=2)
    events = run.summary["events"]
    assert [event["kind"] for event in events] == ["stopped", "signaled"], run.summary
    assert events[-1]["signal"] == "SIGSEGV", run.summary
    lines = _request_log_lines(request_log)
    assert [index for index, _ in lines] == [1, 1]
    payload = corpus_dir("cache_lottery/repeat/01-lottery.txt").read_bytes()
    assert {size for _, size in lines} == {len(payload)}
    dumps = sorted((run.out_dir / "afl-cassowire-data").glob("*.data"))
    assert len(dumps) == 2, "expected the current payload plus one history payload"
    assert payload in [path.read_bytes() for path in dumps]


def test_cache_lottery_without_crash_stays_safe(tmp_path: Path) -> None:
    run, request_log = _lottery_run(tmp_path, with_crash=False, iterations=4)
    _assert_clean_run(run, iterations=4)
    assert [index for index, _ in _request_log_lines(request_log)] == [1] * 4


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
    # headers (u16) + log[CMP_MAP_W][CMP_MAP_H] of packed cmp_operands +
    # site_ids (u32) + attributes (u16) per slot (include/cmplog.h).
    assert CMP_MAP_SIZE == (
        CMP_MAP_W * 2
        + CMP_MAP_W * CMP_MAP_H * CMP_OPERANDS_SIZE
        + CMP_MAP_W * 4
        + CMP_MAP_W * 2
    )
    assert CMP_MAP_SIZE == 151_519_232


# --- AFLNet-style sequence mode -------------------------------------------


def _sequence_run(
    tmp_path: Path,
    *,
    mode: str,
    corpus: str,
    delimiter: str | bytes,
    keep_delimiter: bool = True,
    max_messages: int = 64,
    response_poll_us: int = 0,
    message_suffix: str | bytes | None = None,
    iterations: int = LOOP_COUNT,
) -> tuple[ProxyRun, Path]:
    """Run one sequence-mode proxy campaign; returns (run, request-log path)."""
    port = free_port()
    request_log = tmp_path / "requests.log"
    sequence: dict[str, object] = {
        "enabled": True,
        "delimiter": delimiter,
        "keep_delimiter": keep_delimiter,
        "response_poll_us": response_poll_us,
        "initial_poll_us": 0,
        "final_poll_us": 0,
        "max_messages": max_messages,
    }
    if message_suffix is not None:
        sequence["message_suffix"] = message_suffix
    config = write_config(
        tmp_path,
        mode=mode,
        port=port,
        loop_count=iterations,
        sequence=sequence,
        target_extra_args=["--multi-request", "--log-requests", str(request_log)],
    )
    run = run_proxy_mode(tmp_path / "run", config, corpus, iterations=iterations)
    return run, request_log


def _request_log_lines(path: Path) -> list[tuple[int, int]]:
    """(per-connection message index, byte size) pairs written by --log-requests."""
    if not path.is_file():
        return []
    lines = []
    for line in path.read_text().splitlines():
        index, size = line.split()
        lines.append((int(index), int(size)))
    return lines


def test_sequence_calc_delivers_each_message(tmp_path: Path) -> None:
    # calc frames on '\n': each testcase holds 2 or 3 complete messages, so the
    # target must see every one of them (not just the first frame of a burst).
    run, request_log = _sequence_run(
        tmp_path, mode="calc", corpus="calc_seq/set1", delimiter=b"\n"
    )
    _assert_clean_run(run)
    lines = _request_log_lines(request_log)
    # 20 iterations alternate between the 2-message and the 3-message file.
    assert len(lines) == 10 * 2 + 10 * 3
    assert sum(1 for index, _ in lines if index == 1) == LOOP_COUNT
    assert all(size == len(b"2 + 2\n") for _, size in lines)


def test_sequence_strip_delimiter(tmp_path: Path) -> None:
    # keep_delimiter: false strips the framing bytes. Without re-adding them the
    # target cannot frame per message, so the whole session arrives as one
    # message (the proxy half-closes and the target returns its buffered bytes).
    run, request_log = _sequence_run(
        tmp_path,
        mode="calc",
        corpus="calc_seq/set1",
        delimiter=b"\n",
        keep_delimiter=False,
    )
    _assert_clean_run(run)
    lines = _request_log_lines(request_log)
    assert len(lines) == LOOP_COUNT  # one message per connection
    assert all(index == 1 for index, _ in lines)
    # "\n"-joined messages without the separators: "2 + 23 * 3" / "1 + 14 - 22 * 3".
    assert {size for _, size in lines} == {len(b"2 + 23 * 3"), len(b"1 + 14 - 22 * 3")}


def test_sequence_message_suffix_restores_framing(tmp_path: Path) -> None:
    # Stripping the delimiter is useful together with message_suffix: here the
    # '\n' is re-added to every message, so the target sees 2/3 framed requests.
    run, request_log = _sequence_run(
        tmp_path,
        mode="calc",
        corpus="calc_seq/set1",
        delimiter=b"\n",
        keep_delimiter=False,
        message_suffix=b"\n",
    )
    _assert_clean_run(run)
    lines = _request_log_lines(request_log)
    assert len(lines) == 10 * 2 + 10 * 3
    assert all(size == len(b"2 + 2\n") for _, size in lines)


def test_sequence_http_crlfcrlf(tmp_path: Path) -> None:
    # HTTP requests are framed by CRLFCRLF; both requests of each testcase must
    # reach the server on the same connection (pipelined, as AFLNet does).
    run, request_log = _sequence_run(
        tmp_path,
        mode="http",
        corpus="http_seq/set1",
        delimiter=b"\r\n\r\n",
        iterations=4,
    )
    _assert_clean_run(run, iterations=4)
    lines = _request_log_lines(request_log)
    assert len(lines) == 4 * 2
    assert [index for index, _ in lines] == [1, 2] * 4


def test_sequence_max_messages_truncates(tmp_path: Path) -> None:
    run, request_log = _sequence_run(
        tmp_path,
        mode="calc",
        corpus="calc_seq/three",
        delimiter=b"\n",
        max_messages=2,
        iterations=5,
    )
    _assert_clean_run(run, iterations=5)
    lines = _request_log_lines(request_log)
    assert len(lines) == 5 * 2  # the third message was dropped
    assert "sequence truncated to sequence.max_messages=2" in run.proxy_log


def test_sequence_crash_dump_has_full_session(tmp_path: Path) -> None:
    # "CRASH" is the second message: the target aborts while it is handled, the
    # proxy must die with SIGSEGV (AFL crash) and dump the whole session so the
    # finding is replayable.
    run, _ = _sequence_run(
        tmp_path,
        mode="calc",
        corpus="calc_seq/crash",
        delimiter=b"\n",
        iterations=1,
    )
    # The AFL runtime reports the persistent child's death as signaled; the
    # forkserver parent then exits non-zero, so proxy_exit itself is not the
    # crash. The emulator records the iteration event.
    events = run.summary["events"]
    assert events and events[0]["kind"] == "signaled", run.summary
    assert events[0]["signal"] == "SIGSEGV", run.summary
    dumps = sorted((run.out_dir / "afl-cassowire-data").glob("*.data"))
    assert dumps, "no termination dump written"
    assert b"2 + 2\nCRASH\n" in [path.read_bytes() for path in dumps]
