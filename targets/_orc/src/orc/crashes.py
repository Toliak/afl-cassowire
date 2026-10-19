"""Post-run crash triage: collect AFL crash files into ``<target>/crashes/``."""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from .common import load_target_module, target_dir


def _parse_afl_name(name: str) -> dict[str, str]:
    meta: dict[str, str] = {}
    for part in name.split(","):
        if ":" in part:
            k, _, v = part.partition(":")
            meta[k] = v
    return meta


def collect_crashes(name: str) -> dict[str, object]:
    """Scan ``<target>/out/**/crashes/id:*`` and copy into ``<target>/crashes/``.

    Each crash is copied as ``<campaign>__<original-name>`` where *campaign* is
    the AFL output-directory name (e.g. ``default``, ``default-qemu-cmplog``).
    A ``summary.json`` is written alongside describing every finding.
    """
    target = target_dir(name)
    out_root = target / "out"
    dst_root = target / "crashes"
    dst_root.mkdir(parents=True, exist_ok=True)

    findings: list[dict[str, str]] = []
    if out_root.is_dir():
        for crash in sorted(out_root.rglob("id:*")):
            parts = crash.parts
            crash_idx = next((i for i, p in enumerate(parts) if p.startswith("crashes")), None)
            if crash_idx is None or crash_idx == 0:
                continue
            campaign = parts[crash_idx - 1]
            meta = _parse_afl_name(crash.name)
            dst_name = f"{campaign}__{crash.name}"
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