"""Shared helpers for the ``orc`` target-assist CLI."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from types import ModuleType

# Package layout: targets/_orc/src/orc/<this file>
#   parents[0] = orc
#   parents[1] = src
#   parents[2] = _orc
#   parents[3] = targets
#   parents[4] = repo root
_ORC_DIR = Path(__file__).resolve().parents[2]
TARGETS_DIR = _ORC_DIR.parent
REPO_ROOT = TARGETS_DIR.parent

# Absolute path the repo is mounted at inside the container.
# Used only when materializing container-absolute paths into generated configs.
CONTAINER_WORKDIR = os.environ.get("ORC_WORKDIR", "/opt/workdir")


class TargetError(Exception):
    """Raised when a target (or its orchestrator.py) is missing/malformed."""


def target_dir(name: str) -> Path:
    d = TARGETS_DIR / name
    if not d.is_dir():
        raise TargetError(f"target not found: {name!r} (looked in {d})")
    return d


def container_target_dir(name: str) -> str:
    return f"{CONTAINER_WORKDIR}/targets/{name}"


def load_target_module(name: str) -> ModuleType:
    py = target_dir(name) / "orchestrator.py"
    if not py.is_file():
        raise TargetError(f"target {name!r} has no orchestrator.py ({py})")
    spec = importlib.util.spec_from_file_location(f"target_{name}_orchestrator", py)
    if spec is None or spec.loader is None:
        raise TargetError(f"cannot load {py}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def resolve_source_path(target_name: str, source: str) -> Path:
    """Resolve a seed/template source spec to a concrete path.

    Looked up in order: relative to ``targets/``, relative to the target dir,
    relative to the repo root. Falls back to the targets-relative path even if
    it does not exist so callers can produce a useful error.
    """
    spec = source if isinstance(source, Path) else Path(source)
    candidates = [TARGETS_DIR / spec, target_dir(target_name) / spec, REPO_ROOT / spec]
    for c in candidates:
        if c.exists():
            return c
    return candidates[0]