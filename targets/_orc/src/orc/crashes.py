"""Post-run crash triage: collect AFL and libFuzzer artifacts into ``<target>/crashes/``."""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from .common import TargetError, load_target_module, target_dir

_LIBFUZZER_ARTIFACTS = ("crash-*", "timeout-*", "oom-*", "leak-*", "slow-unit-*")


def _parse_afl_name(name: str) -> dict[str, str]:
    meta: dict[str, str] = {}
    for part in name.split(","):
        if ":" in part:
            k, _, v = part.partition(":")
            meta[k] = v
    return meta


def _parse_libfuzzer_name(name: str) -> dict[str, str]:
    kind, sep, sha1 = name.partition("-")
    meta = {"kind": kind}
    if sep and sha1:
        meta["sha1"] = sha1
    return meta


def _iter_artifacts(root: Path) -> list[Path]:
    seen: set[Path] = set()
    found: list[Path] = []
    for pattern in ("id:*", *_LIBFUZZER_ARTIFACTS):
        for path in sorted(root.rglob(pattern)):
            if path.is_file() and path not in seen:
                seen.add(path)
                found.append(path)
    return found


def collect_crashes(name: str, profile: str | None = None) -> dict[str, object]:
    """Scan crash dirs and copy them into ``<target>/crashes/``.

    Without *profile*, every ``<target>/out/**/crashes/id:*`` (AFL) and
    ``crash-*``/``timeout-*``/``oom-*``/``leak-*``/``slow-unit-*`` (libFuzzer,
    e.g. SGFuzz ``out/sgfuzz``) is collected. With one, only the matching
    ``<target>/out/<profile>/`` subtree is scanned.

    Each crash is copied as ``<campaign-path>__<original-name>`` where the
    campaign path joins the output directories below ``out/`` (for example
    ``default`` or ``sgfuzz``). A ``summary.json`` is written alongside
    describing every finding.
    """
    mod = load_target_module(name)
    profiles = getattr(mod, "PROFILES", None)
    if profile:
        if not isinstance(profiles, dict) or not profiles:
            raise TargetError(f"{name}: target has no PROFILES; cannot select {profile!r}")
        if profile not in profiles:
            available = ", ".join(sorted(profiles))
            raise TargetError(f"{name}: unknown profile {profile!r} (available: {available})")

    target = target_dir(name)
    out_root = target / "out"
    scan_root = out_root / profile if profile else out_root
    dst_root = target / "crashes"
    dst_root.mkdir(parents=True, exist_ok=True)

    findings: list[dict[str, str]] = []
    if scan_root.is_dir():
        for crash in _iter_artifacts(scan_root):
            rel_parts = crash.relative_to(out_root).parent.parts
            is_afl = crash.name.startswith("id:")
            if is_afl:
                if not rel_parts or rel_parts[-1] != "crashes":
                    continue
                campaign_parts = rel_parts[:-1]
            else:
                campaign_parts = rel_parts
            if not campaign_parts:
                continue
            campaign = "/".join(campaign_parts)
            meta = _parse_afl_name(crash.name) if is_afl else _parse_libfuzzer_name(crash.name)
            dst_name = "__".join(campaign_parts) + f"__{crash.name}"
            dst = dst_root / dst_name
            shutil.copy2(crash, dst)
            findings.append(
                {
                    "campaign": campaign,
                    "source": crash.as_posix(),
                    "dest": dst.as_posix(),
                    **meta,
                }
            )

    summary = dst_root / "summary.json"
    report = {
        "target": name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(findings),
        "crashes": findings,
    }
    summary.write_text(json.dumps(report, indent=2, sort_keys=True))
    return report
