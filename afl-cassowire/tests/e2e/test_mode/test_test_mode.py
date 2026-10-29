"""E2E tests for afl-cassowire `test` mode against the prebuilt test-target.

Every `test --input <file>` run executes both passes:
  - Pass 1 (dump map): the proxy spawns the target with AFL_DUMP_MAP_SIZE=1;
    the target's AFL++ runtime prints its coverage-map size and exits. The
    proxy must parse it ("map size: <n>") and complete the pass.
  - Pass 2 (single iteration): one connect -> send (prefix + input + suffix)
    -> half-close -> read-response cycle; the response is logged escaped.

The test-target must be already built with the AFL++ toolchain (see
harness.cassowire_bin / harness.test_target_bin for the exact paths); missing
binaries fail instead of being built.
"""

import os
import sys
from pathlib import Path

import harness
import pytest

CALC_INPUT = b"2 + 2\n"
CALC_RESPONSE = b"4\n"


def run_calc_case(tmp_path: Path, primary: str = "procfs") -> harness.RunResult:
    """One calc-mode run: input "2 + 2" -> response "4"."""
    target = harness.test_target_bin()
    port = harness.free_port()
    config = harness.write_config(
        tmp_path,
        target_args=[str(target), "calc", "--port", str(port)],
        port=port,
        primary=primary,
    )
    input_file = tmp_path / "input.bin"
    input_file.write_bytes(CALC_INPUT)
    return harness.run_cassowire(config, "test", "--input", str(input_file))


def assert_dump_map_pass(res: harness.RunResult, target: Path) -> None:
    """Pass 1 must report exactly the map size the target's runtime dumps."""
    assert res.returncode == 0, res.detail()
    assert "Pass 1 (Map Size) completed." in res.stdout, res.detail()
    expected = harness.target_map_size(target)
    assert harness.map_sizes(res.stdout) == [expected], res.detail()


def assert_single_iteration_pass(res: harness.RunResult, response: bytes) -> None:
    """Pass 2 must complete without errors and log the escaped response."""
    assert res.returncode == 0, res.detail()
    assert harness.error_lines(res.stdout) == [], res.detail()
    assert "Pass 2 (Single Iteration) completed successfully." in res.stdout, res.detail()
    assert f"Response: '{harness.escaped(response)}'" in res.stdout, res.detail()


@pytest.mark.parametrize("primary", ["procfs", "seccomp"])
def test_dump_map_and_single_iteration_calc(tmp_path: Path, primary: str) -> None:
    if primary == "seccomp" and not harness.seccomp_supported():
        pytest.skip("SECCOMP_RET_USER_NOTIF port detection needs kernel >= 5.0")
    res = run_calc_case(tmp_path, primary)
    assert_dump_map_pass(res, harness.test_target_bin())
    assert_single_iteration_pass(res, CALC_RESPONSE)


@pytest.mark.parametrize("primary", ["procfs", "seccomp"])
def test_single_iteration_extra_bind_after_main(tmp_path: Path, primary: str) -> None:
    """Startup binds queued behind the configured port must not stall the
    first request: --bind-extra-after binds port+1 after the detected port, so
    its bind()/listen() notifications arrive while the proxy is already in its
    exchange/poll loop (the seccomp user-notif case that made nginx's TLS/QUIC
    listeners suspend the event loop). Multiplexing the seccomp notification fd
    alongside the data socket in poll() releases them immediately.
    """
    if primary == "seccomp" and not harness.seccomp_supported():
        pytest.skip("SECCOMP_RET_USER_NOTIF port detection needs kernel >= 5.0")
    target = harness.test_target_bin()
    port = harness.free_port()
    config = harness.write_config(
        tmp_path,
        target_args=[str(target), "calc", "--port", str(port), "--bind-extra-after"],
        port=port,
        primary=primary,
    )
    input_file = tmp_path / "input.bin"
    input_file.write_bytes(CALC_INPUT)
    res = harness.run_cassowire(config, "--log-level", "debug", "test", "--input", str(input_file))
    assert_dump_map_pass(res, target)
    assert_single_iteration_pass(res, CALC_RESPONSE)
    if primary == "seccomp":
        # The multiplexed poll + pump must have released the queued extra bind().
        assert "notif pump: released bind" in res.stdout, res.detail()


@pytest.mark.parametrize(
    "output",
    [b"MAP_SIZE: 65536\n", b"65536\ngarbage\n", b""],
    ids=["prefixed", "trailing_garbage", "no_output"],
)
def test_dump_map_rejects_malformed_output(tmp_path: Path, output: bytes) -> None:
    """Pass 1 is a hard gate: malformed or missing map-size output stops test mode."""
    code = (
        "import sys\n"
        f"sys.stdout.buffer.write({output!r})\n"
        "sys.stdout.buffer.flush()\n"
        "raise SystemExit(255)\n"
    )
    config = harness.write_config(
        tmp_path,
        target_args=[sys.executable, "-c", code],
        port=harness.free_port(),
    )
    input_file = tmp_path / "input.bin"
    input_file.write_bytes(b"x")
    res = harness.run_cassowire(config, "test", "--input", str(input_file))

    assert res.returncode != 0, res.detail()
    assert harness.error_lines(res.stdout), res.detail()
    assert "Pass 1 (Map Size) completed." not in res.stdout, res.detail()
    assert "Pass 2" not in res.stdout, res.detail()


def test_single_iteration_payload_wrapping(tmp_path: Path) -> None:
    # prefix "1" + input "+" + suffix "1" reaches the calc as "1+1" -> "2".
    target = harness.test_target_bin()
    port = harness.free_port()
    config = harness.write_config(
        tmp_path,
        target_args=[str(target), "calc", "--port", str(port)],
        port=port,
        payload={"prefix": "1", "suffix": "1"},
    )
    input_file = tmp_path / "input.bin"
    input_file.write_bytes(b"+")
    res = harness.run_cassowire(config, "test", "--input", str(input_file))
    assert_single_iteration_pass(res, b"2\n")


def test_single_iteration_stdin(tmp_path: Path) -> None:
    # "--input -" reads the testcase from stdin: "2 * 3" -> "6".
    target = harness.test_target_bin()
    port = harness.free_port()
    config = harness.write_config(
        tmp_path,
        target_args=[str(target), "calc", "--port", str(port)],
        port=port,
    )
    res = harness.run_cassowire(config, "test", "--input", "-", stdin=b"2 * 3\n")
    assert_single_iteration_pass(res, b"6\n")


def test_single_iteration_http(tmp_path: Path) -> None:
    # http mode: the payload lands in the header section of a GET / request.
    target = harness.test_target_bin()
    port = harness.free_port()
    config = harness.write_config(
        tmp_path,
        target_args=[str(target), "http", "--port", str(port)],
        port=port,
        payload={"prefix": "GET / HTTP/1.1\r\nHost: localhost\r\n", "suffix": "\r\n\r\n"},
    )
    input_file = tmp_path / "input.bin"
    input_file.write_bytes(b"X-Case: e2e\r\n")
    res = harness.run_cassowire(config, "test", "--input", str(input_file))
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
    assert_single_iteration_pass(res, response)


STDIN_MARKER = "cassowire-stdin-e2e"


def _start_stdin_fifo(tmp_path: Path, payload: bytes) -> Path:
    """Create the fifo and start the writer thread for the stdin_path cases."""
    fifo = tmp_path / "stdin.fifo"
    os.mkfifo(fifo)
    harness.wire_stdin_fifo(fifo, payload)
    return fifo


def test_stdin_path_fifo_wiring(tmp_path: Path) -> None:
    # target.stdin_path wires the fifo to the target's fd 0: the --stdin-marker
    # canary must arrive there (any mismatch aborts the target) and the calc
    # serving continues normally.
    target = harness.test_target_bin()
    port = harness.free_port()
    fifo = _start_stdin_fifo(tmp_path, (STDIN_MARKER + "\n").encode())
    config = harness.write_config(
        tmp_path,
        target_args=[str(target), "calc", "--port", str(port), "--stdin-marker", STDIN_MARKER],
        port=port,
        stdin_path=str(fifo),
    )
    input_file = tmp_path / "input.bin"
    input_file.write_bytes(CALC_INPUT)
    res = harness.run_cassowire(config, "test", "--input", str(input_file))
    assert_dump_map_pass(res, target)
    assert_single_iteration_pass(res, CALC_RESPONSE)


def test_stdin_path_fifo_marker_mismatch_fails(tmp_path: Path) -> None:
    # The canary proves the wiring is real: when the fifo carries a different
    # line than --stdin-marker expects, the target aborts before binding and
    # the run must fail instead of silently ignoring fd 0.
    target = harness.test_target_bin()
    port = harness.free_port()
    fifo = _start_stdin_fifo(tmp_path, b"something-else\n")
    config = harness.write_config(
        tmp_path,
        target_args=[str(target), "calc", "--port", str(port), "--stdin-marker", STDIN_MARKER],
        port=port,
        stdin_path=str(fifo),
    )
    input_file = tmp_path / "input.bin"
    input_file.write_bytes(CALC_INPUT)
    res = harness.run_cassowire(config, "test", "--input", str(input_file))
    assert res.returncode != 0, res.detail()
    assert "Pass 2 (Single Iteration) completed successfully." not in res.stdout, res.detail()


def test_stdin_path_missing_file_fails(tmp_path: Path) -> None:
    # An unopenable stdin_path aborts at the Pass 2 prepare step (the
    # map-size pass never opens the path) with a clear error.
    target = harness.test_target_bin()
    port = harness.free_port()
    config = harness.write_config(
        tmp_path,
        target_args=[str(target), "calc", "--port", str(port)],
        port=port,
        stdin_path=str(tmp_path / "does-not-exist.fifo"),
    )
    input_file = tmp_path / "input.bin"
    input_file.write_bytes(CALC_INPUT)
    res = harness.run_cassowire(config, "test", "--input", str(input_file))
    assert res.returncode != 0, res.detail()
    assert "failed to open target.stdin_path" in res.stdout, res.detail()
    assert "Pass 2 (Single Iteration) completed successfully." not in res.stdout, res.detail()
