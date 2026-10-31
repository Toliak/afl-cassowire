"""gcov/lcov coverage collection on a target's gcov build variant."""

from __future__ import annotations

import shlex
import subprocess
from pathlib import Path

from .common import TargetError, load_target_module, target_dir


def _run(cmd: list[str], cwd: Path) -> str:
    proc = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    if proc.returncode != 0:
        raise TargetError(f"command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr}")
    return proc.stdout


def _gcov_tool(cov: dict[str, object], out_dir: Path) -> str | None:
    """Return an executable path for lcov, wrapping multi-word tools.

    lcov's ``--gcov-tool`` accepts a single executable, so ``llvm-cov gcov``
    (needed for clang's gcov format) is materialized as a small wrapper.
    """
    raw = cov.get("gcov_tool")
    if not raw:
        return None
    parts = shlex.split(str(raw))
    if len(parts) == 1:
        return parts[0]
    wrapper = out_dir / ".gcov-tool"
    wrapper.write_text("#!/bin/sh\nexec " + shlex.join(parts) + ' "$@"\n')
    wrapper.chmod(0o755)
    return wrapper.as_posix()


def _resolve_build_dir(target: Path, cov: dict[str, object]) -> Path:
    raw = cov.get("gcov_dir")
    if raw:
        candidate = Path(str(raw))
        if not candidate.is_absolute():
            candidate = target / candidate
        if candidate.is_dir():
            return candidate
        raise TargetError(f"gcov dir not found: {candidate}")

    # Legacy fallback for targets without an explicit gcov_dir.
    variant = str(cov.get("build_variant", "gcov"))
    candidate = target / "src" / "install" / variant
    if candidate.is_dir():
        return candidate
    candidate = target / "src" / "build" / variant
    if candidate.is_dir():
        return candidate
    raise TargetError(f"gcov build dir not found for variant {variant!r}")


def collect_cov(name: str, out_rel: str = "cov") -> dict[str, object]:
    """Capture existing gcov counters and emit an HTML report.

    This is the collection half: it expects ``.gcda`` files already present in
    ``COVERAGE['gcov_dir']`` (normally produced by ``replay-cov``). Produces
    ``<target>/<out_rel>/coverage.info`` and ``<target>/<out_rel>/html/index.html``.
    """
    mod = load_target_module(name)
    cov = getattr(mod, "COVERAGE", None)
    if not isinstance(cov, dict):
        raise TargetError(f"{name}: COVERAGE must be a dict")

    target = target_dir(name)
    build_dir = _resolve_build_dir(target, cov)
    gcda = list(build_dir.rglob("*.gcda"))
    if not gcda:
        raise TargetError(
            f"no .gcda files under {build_dir}; run `orc {name} replay-cov` first"
        )
    out_dir = target / out_rel
    out_dir.mkdir(parents=True, exist_ok=True)

    info = out_dir / "coverage.info"
    html = out_dir / "html"

    capture = [
        "lcov",
        "--capture",
        "--directory",
        str(build_dir),
        "--output-file",
        str(info),
        "--rc",
        "branch_coverage=1",
    ]
    include = cov.get("include", [])
    if isinstance(include, str):
        include = [include]
    if not isinstance(include, (list, tuple)):
        raise TargetError("COVERAGE['include'] must be a string or a list")
    for pattern in include:
        capture.extend(["--include", str(pattern)])
    ignore_errors = cov.get("ignore_errors", [])
    if isinstance(ignore_errors, str):
        ignore_errors = [ignore_errors]
    if not isinstance(ignore_errors, (list, tuple)):
        raise TargetError("COVERAGE['ignore_errors'] must be a string or a list")
    if ignore_errors:
        capture.extend(["--ignore-errors", ",".join(str(e) for e in ignore_errors)])
    gcov_tool = _gcov_tool(cov, out_dir)
    if gcov_tool:
        capture.extend(["--gcov-tool", gcov_tool])
    _run(capture, target)
    html_cmd = [
        "genhtml",
        str(info),
        "--output-directory",
        str(html),
        "--branch-coverage",
        "--legend",
        "--title",
        f"{name} coverage",
    ]
    if ignore_errors:
        html_cmd.extend(["--ignore-errors", ",".join(str(e) for e in ignore_errors)])
    _run(html_cmd, target)

    return {
        "target": name,
        "build_variant": cov.get("build_variant", "gcov"),
        "coverage_info": info.as_posix(),
        "html_report": (html / "index.html").as_posix(),
    }
