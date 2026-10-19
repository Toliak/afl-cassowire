"""Jinja2 rendering of target data and root config templates."""

from __future__ import annotations

import shutil
from pathlib import Path

from jinja2 import BaseLoader, Environment, FileSystemLoader, StrictUndefined

from .common import CONTAINER_WORKDIR, TargetError, container_target_dir, load_target_module, target_dir


def _base_context(name: str) -> dict[str, object]:
    return {
        "target_name": name,
        "target_dir": container_target_dir(name),
        "workdir": CONTAINER_WORKDIR,
    }


def _iter_files(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    return sorted(p for p in root.rglob("*") if p.is_file())


def _render_template(env: Environment, template: str, ctx: dict[str, object], name: str) -> str:
    try:
        return env.get_template(template).render(**ctx)
    except Exception as exc:  # noqa: BLE001 - surface template errors with context
        raise TargetError(f"{name}: rendering {template!r} failed: {exc}") from exc


def _write(dst: Path, text: str, seen: set[str], name: str) -> None:
    if dst.as_posix() in seen:
        raise TargetError(f"{name}: duplicate data output {dst.as_posix()!r}")
    seen.add(dst.as_posix())
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(text)


def prepare_data(name: str) -> list[str]:
    """Render ``data_template/`` into ``data/`` and root ``*.j2`` into the target root.

    - ``data_template/*.j2`` → ``data/`` (multi-output via ``RENDER``; otherwise
      the ``.j2`` suffix is stripped for the destination).
    - ''data_template/`` non-``.j2`` files copied verbatim (structure preserved).
    - any ``*.j2`` at the *target root* (e.g. ``cassowire.yaml.j2``) → the target
      root with the ``.j2`` suffix stripped, using the base context (``target_dir``,
      ``workdir``, ``target_name``).

    Returns the list of generated destination paths (relative to the target dir).
    """
    mod = load_target_module(name)
    target = target_dir(name)
    src_dir = target / "data_template"
    dst_dir = target / "data"

    render = getattr(mod, "RENDER", None) or {}
    if not isinstance(render, dict):
        raise TargetError(f"{name}: RENDER must be a dict, got {type(render).__name__}")

    env = Environment(
        loader=FileSystemLoader(str(src_dir)),
        undefined=StrictUndefined,
        keep_trailing_newline=True,
    )

    if dst_dir.exists():
        shutil.rmtree(dst_dir)
    dst_dir.mkdir(parents=True, exist_ok=True)

    generated: list[str] = []
    seen: set[str] = set()

    # 1) static files in data_template/ (non-.j2), preserving structure.
    for f in _iter_files(src_dir):
        rel = f.relative_to(src_dir).as_posix()
        if rel.endswith(".j2"):
            continue
        out = dst_dir / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, out)

    # 2) render data_template/*.j2 per RENDER, then any remaining .j2.
    explicit = set(render.keys())
    for template, specs in render.items():
        for raw in specs:
            spec = dict(raw)
            output = spec.pop("output", "")
            if not output:
                raise TargetError(f"{name}: RENDER[{template!r}] missing 'output'")
            ctx = _base_context(name)
            ctx.update(spec)
            text = _render_template(env, template, ctx, name)
            out = dst_dir / output
            _write(out, text, seen, name)
            generated.append(out.relative_to(target).as_posix())

    for f in _iter_files(src_dir):
        rel = f.relative_to(src_dir).as_posix()
        if not rel.endswith(".j2") or rel in explicit:
            continue
        output = rel[: -len(".j2")]
        text = _render_template(env, rel, _base_context(name), name)
        out = dst_dir / output
        _write(out, text, seen, name)
        generated.append(out.relative_to(target).as_posix())

    # 3) render root-level *.j2 templates (cassowire.yaml.j2 etc.) in place.
    root_env = Environment(loader=BaseLoader(), undefined=StrictUndefined, keep_trailing_newline=True)
    for f in sorted(target.glob("*.j2")):
        try:
            tpl = root_env.from_string(f.read_text())
            text = tpl.render(**_base_context(name))
        except Exception as exc:  # noqa: BLE001
            raise TargetError(f"{name}: rendering {f.name} failed: {exc}") from exc
        out = f.with_suffix("")
        _write(out, text, seen, name)
        generated.append(out.relative_to(target).as_posix())

    return generated