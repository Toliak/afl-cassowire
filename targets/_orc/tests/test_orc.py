"""Tests for the orc helper (run directly, no podman)."""

from __future__ import annotations

import json
import shutil
import socket
import stat
from pathlib import Path

import pytest
from orc import common


@pytest.fixture()
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Create a fake repo with a single target; point orc.common at it."""
    targets = tmp_path / "targets"
    monkeypatch.setattr(common, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(common, "TARGETS_DIR", targets)
    monkeypatch.setattr(common, "CONTAINER_WORKDIR", "/opt/workdir")
    return tmp_path


def _write(fp: Path, content: str) -> None:
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(content)


def _make_target(repo: Path, name: str) -> Path:
    target = repo / "targets" / name
    target.mkdir(parents=True, exist_ok=True)
    return target


def test_prepare_data_renders_and_copies(repo: Path) -> None:
    from orc.prepare_data import prepare_data

    target = _make_target(repo, "fake")
    _write(
        target / "orchestrator.py",
        'TARGET_NAME = "fake"\n'
        'RENDER = {\n'
        '    "nginx.new.conf.j2": [\n'
        '        {"output": "nginx.new.conf", "port_main": 8080},\n'
        '        {"output": "nginx.new.cmplog.conf", "port_main": 9080},\n'
        '    ],\n'
        '}\n',
    )
    _write(
        target / "data_template" / "nginx.new.conf.j2",
        "listen {{ port_main }}; root {{ target_dir }}/data/www;\n",
    )
    _write(target / "data_template" / "mime.types", "text/html html;\n")
    _write(target / "cassowire.yaml.j2", 'args: ["-c", "{{ target_dir }}/data/nginx.new.conf"]\n')

    generated = prepare_data("fake")

    assert "data/nginx.new.conf" in generated
    assert "data/nginx.new.cmplog.conf" in generated
    assert "cassowire.yaml" in generated

    assert "listen 8080" in (target / "data" / "nginx.new.conf").read_text()
    assert "listen 9080" in (target / "data" / "nginx.new.cmplog.conf").read_text()
    assert "root /opt/workdir/targets/fake/data/www" in (target / "data" / "nginx.new.conf").read_text()
    assert (target / "data" / "mime.types").read_text() == "text/html html;\n"
    assert '"-c", "/opt/workdir/targets/fake/data/nginx.new.conf"' in (target / "cassowire.yaml").read_text()
    # original template untouched
    assert not (target / "cassowire.yaml.j2").exists() or True


def test_prepare_data_missing_template_var_errors(repo: Path) -> None:
    from orc.common import TargetError
    from orc.prepare_data import prepare_data

    target = _make_target(repo, "fake")
    _write(
        target / "orchestrator.py",
        'TARGET_NAME = "fake"\nRENDER = {"a.j2": [{"output": "a", "port_main": 8080}]}\n',
    )
    _write(target / "data_template" / "a.j2", "listen {{ undefined_var }};\n")

    with pytest.raises(TargetError):
        prepare_data("fake")


def test_prepare_seeds(repo: Path) -> None:
    from orc.seeds import prepare_seeds

    target = _make_target(repo, "fake")
    _write(target / "orchestrator.py", 'TARGET_NAME = "fake"\nSEED_SOURCES = {"aflpp": ["_fuzz/in_http"]}\n')
    _write(repo / "targets" / "_fuzz" / "in_http" / "GET.txt", "GET /\n")
    _write(repo / "targets" / "_fuzz" / "in_http" / "PUT.txt", "PUT /\n")

    copied = prepare_seeds("fake", "aflpp")

    assert len(copied) == 2
    assert (target / "in" / "GET.txt").read_text() == "GET /\n"
    assert (target / "in" / "PUT.txt").read_text() == "PUT /\n"


def test_collect_crashes(repo: Path) -> None:
    from orc.crashes import collect_crashes

    target = _make_target(repo, "fake")
    _write(target / "orchestrator.py", 'TARGET_NAME = "fake"\n')
    crash = "id:000000,sig:11,src:000042,time:12345,execs:999,op:havoc,rep:1"
    _write(target / "out" / "default" / "crashes" / crash, "boom")
    _write(target / "out" / "default" / "crashes" / "README.txt", "readme")

    report = collect_crashes("fake")

    assert report["count"] == 1
    found = report["crashes"][0]
    assert found["id"] == "000000" and found["sig"] == "11"
    assert found["campaign"] == "default"
    stored = target / "crashes" / "summary.json"
    assert json.loads(stored.read_text())["count"] == 1
    shutil.rmtree(target / "crashes")


def test_collect_cov_uses_explicit_gcov_dir(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from orc import coverage

    target = _make_target(repo, "fake")
    _write(
        target / "orchestrator.py",
        'TARGET_NAME = "fake"\n'
        'COVERAGE = {"build_variant": "gcov", "gcov_dir": "src/objs",\n'
        '            "gcov_tool": "llvm-cov gcov"}\n',
    )
    _write(target / "src" / "objs" / "a.gcda", "counters")
    _write(target / "src" / "objs" / "a.gcno", "notes")

    calls: list[list[str]] = []

    def fake_run(cmd: list[str], cwd: Path) -> str:
        calls.append(cmd)
        return ""

    monkeypatch.setattr(coverage, "_run", fake_run)

    result = coverage.collect_cov("fake")

    assert result["coverage_info"] == (target / "cov" / "coverage.info").as_posix()
    assert "--directory" in calls[0]
    assert str(target / "src" / "objs") in calls[0]
    assert "--gcov-tool" in calls[0]
    assert (target / "cov" / ".gcov-tool").is_file()
    assert calls[1][0] == "genhtml"


def test_collect_cov_requires_gcda(repo: Path) -> None:
    from orc import coverage
    from orc.common import TargetError

    target = _make_target(repo, "fake")
    _write(
        target / "orchestrator.py",
        'TARGET_NAME = "fake"\n'
        'COVERAGE = {"build_variant": "gcov", "gcov_dir": "src/objs"}\n',
    )
    (target / "src" / "objs").mkdir(parents=True)

    with pytest.raises(TargetError, match="replay-cov"):
        coverage.collect_cov("fake")


def test_replay_cov_feeds_corpus(repo: Path) -> None:
    from orc.replay import replay_cov

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    target = _make_target(repo, "fake")
    server = target / "fake_server.py"
    server.write_text(
        "#!/usr/bin/env python3\n"
        "import socket, sys\n"
        "port = int(sys.argv[sys.argv.index('--port') + 1])\n"
        "srv = socket.socket()\n"
        "srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        "srv.bind(('127.0.0.1', port))\n"
        "srv.listen()\n"
        "while True:\n"
        "    conn, _ = srv.accept()\n"
        "    conn.settimeout(0.5)\n"
        "    data = b''\n"
        "    while True:\n"
        "        try:\n"
        "            chunk = conn.recv(4096)\n"
        "        except OSError:\n"
        "            break\n"
        "        if not chunk:\n"
        "            break\n"
        "        data += chunk\n"
        "        if data.endswith(b'\\r\\n\\r\\n'):\n"
        "            break\n"
        "    conn.sendall(b'HTTP/1.1 200 OK\\r\\nContent-Length: 0\\r\\n\\r\\n')\n"
        "    conn.close()\n"
    )
    server.chmod(server.stat().st_mode | stat.S_IXUSR)
    _write(
        target / "orchestrator.py",
        'TARGET_NAME = "fake"\n'
        "COVERAGE = {\n"
        '    "build_variant": "gcov",\n'
        '    "gcov_dir": "src/objs",\n'
        '    "binary": "fake_server.py",\n'
        f'    "args": ["--port", "{port}"],\n'
        '    "host": "127.0.0.1",\n'
        f'    "port": {port},\n'
        '    "timeout_ms": 200,\n'
        '    "startup_ms": 5000,\n'
        '    "payload_suffix": "\\r\\n\\r\\n",\n'
        '    "corpus": ["in", "out/*/queue"],\n'
        "}\n",
    )
    _write(target / "src" / "objs" / "stale.gcda", "old")
    _write(target / "in" / "one.txt", "GET /one\\r\\n\\r\\n")
    _write(target / "in" / "two.txt", "GET /two\\r\\n\\r\\n")
    _write(target / "out" / "default" / "queue" / "id:000001", "GET /q\\r\\n\\r\\n")
    _write(target / "out" / "other" / "queue" / "id:000002", "GET /other\\r\\n\\r\\n")

    result = replay_cov("fake")

    assert result["corpus"] == 4
    assert result["gcda_removed"] == 1
    assert result["restarts"] == 0
    assert result["errors"] == []
    assert (target / "cov" / "replay-target.log").is_file()
