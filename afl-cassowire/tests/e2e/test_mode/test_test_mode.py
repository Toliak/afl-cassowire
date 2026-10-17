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
