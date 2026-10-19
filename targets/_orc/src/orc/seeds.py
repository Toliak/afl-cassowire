"""Seed-corpus preparation (``in/``) from per-fuzzer source specs."""

from __future__ import annotations

import shutil
from pathlib import Path
from types import ModuleType

from .common import TargetError, load_target_module, resolve_source_path, target_dir


def _expand(source: Path) -> list[Path]:
    if source.is_dir():
        return sorted(p for p in source.iterdir() if p.is_file())
    if source.is_file():
        return [source]
    # glob support
    globbed = sorted(source.parent.glob(source.name))
    return [p for p in globbed if p.is_file()]


def _resolve_sources(
    name: str, mod: ModuleType, fuzzer: str, profile: str | None
) -> tuple[str | None, object]:
    """Resolve seed sources for a profile, or legacy ``SEED_SOURCES``.

    Returns the concrete profile name (``None`` for legacy targets) and the
    per-fuzzer source spec.
    """
    profiles = getattr(mod, "PROFILES", None)
    if profiles is None:
        if profile:
            raise TargetError(f"{name}: target has no PROFILES; cannot select {profile!r}")
        seed_sources = getattr(mod, "SEED_SOURCES", None)
        if not isinstance(seed_sources, dict):
            raise TargetError(f"{name}: SEED_SOURCES must be a dict keyed by fuzzer")
        if fuzzer not in seed_sources:
            raise TargetError(f"{name}: no SEED_SOURCES for fuzzer {fuzzer!r}")
        return None, seed_sources[fuzzer]

    if not isinstance(profiles, dict) or not profiles:
        raise TargetError(f"{name}: PROFILES must be a non-empty dict")
    if not profile:
        profile = getattr(mod, "DEFAULT_PROFILE", None)
    if not profile:
        available = ", ".join(sorted(profiles))
        raise TargetError(f"{name}: --profile is required (available: {available})")
    if profile not in profiles:
        available = ", ".join(sorted(profiles))
        raise TargetError(f"{name}: unknown profile {profile!r} (available: {available})")

    entry = profiles[profile]
    if not isinstance(entry, dict):
        raise TargetError(f"{name}: PROFILES[{profile!r}] must be a dict")
    seeds = entry.get("seeds")
    if not isinstance(seeds, dict):
        raise TargetError(f"{name}: PROFILES[{profile!r}]['seeds'] must be a dict")
    if fuzzer not in seeds:
        raise TargetError(f"{name}: profile {profile!r} has no seeds for fuzzer {fuzzer!r}")
    return str(profile), seeds[fuzzer]


def prepare_seeds(
    name: str, fuzzer: str, out_rel: str | None = None, profile: str | None = None
) -> list[str]:
    """Merge seeds into ``<target>/<out_rel>/`` (dedup by name).

    Profiled targets read ``PROFILES[profile]['seeds'][fuzzer]`` and default to
    ``in/<profile>/`` when *out_rel* is omitted. Legacy targets keep using
    ``SEED_SOURCES[fuzzer]`` and the existing ``in/`` destination.
    """
    mod = load_target_module(name)
    profile, sources = _resolve_sources(name, mod, fuzzer, profile)
    if out_rel is None:
        out_rel = f"in/{profile}" if profile else "in"
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