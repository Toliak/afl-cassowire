"""Seed-corpus preparation (``in/``) from per-fuzzer source specs."""

from __future__ import annotations

import shutil
from pathlib import Path

from .common import TargetError, load_target_module, resolve_source_path, target_dir


def _expand(source: Path) -> list[Path]:
    if source.is_dir():
        return sorted(p for p in source.iterdir() if p.is_file())
    if source.is_file():
        return [source]
    # glob support
    globbed = sorted(source.parent.glob(source.name))
    return [p for p in globbed if p.is_file()]


def prepare_seeds(name: str, fuzzer: str, out_rel: str = "in") -> list[str]:
    """Merge ``SEED_SOURCES[fuzzer]`` into ``<target>/<out_rel>/`` (dedup by name)."""
    mod = load_target_module(name)
    seed_sources = getattr(mod, "SEED_SOURCES", None)
    if not isinstance(seed_sources, dict):
        raise TargetError(f"{name}: SEED_SOURCES must be a dict keyed by fuzzer")
    if fuzzer not in seed_sources:
        raise TargetError(f"{name}: no SEED_SOURCES for fuzzer {fuzzer!r}")

    sources = seed_sources[fuzzer]
    target = target_dir(name)
    out_dir = target / out_rel
    out_dir.mkdir(parents=True, exist_ok=True)

    copied: list[str] = []
    seen: set[str] = set()
    for spec in sources:
        src = resolve_source_path(name, spec)
        files = _expand(src)
        if not files:
            raise TargetError(f"{name}: seed source {spec!r} resolved to nothing ({src})")
        for f in files:
            if f.name in seen:
                continue
            seen.add(f.name)
            shutil.copy2(f, out_dir / f.name)
            copied.append((out_dir / f.name).as_posix())
    return copied