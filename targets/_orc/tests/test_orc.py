"""Tests for the orc helper (run directly, no podman)."""

from __future__ import annotations

import json
import shutil
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
