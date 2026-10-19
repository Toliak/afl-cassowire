"""Post-run crash triage: collect AFL crash files into ``<target>/crashes/``."""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone

from .common import TargetError, load_target_module, target_dir


def _parse_afl_name(name: str) -> dict[str, str]:
    meta: dict[str, str] = {}
    for part in name.split(","):
        if ":" in part:
            k, _, v = part.partition(":")
            meta[k] = v
    return meta


def collect_crashes(name: str, profile: str | None = None) -> dict[str, object]:
    """Scan crash dirs and copy them into ``<target>/crashes/``.

    Without *profile*, every ``<target>/out/**/crashes/id:*`` is collected.
    With one, only ``<target>/out/<profile>/**/crashes/id:*`` is scanned.

    Each crash is copied as ``<campaign-path>__<original-name>`` where the
    campaign path joins the AFL output directories below ``out/`` (for example
    ``default`` or ``calc__default``). A ``summary.json`` is written alongside
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
        for crash in sorted(scan_root.rglob("id:*")):
            rel_parts = crash.relative_to(out_root).parent.parts
            if not rel_parts or rel_parts[-1] != "crashes":
                continue
            campaign_parts = rel_parts[:-1]
            if not campaign_parts:
                continue
            campaign = "/".join(campaign_parts)
            meta = _parse_afl_name(crash.name)
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