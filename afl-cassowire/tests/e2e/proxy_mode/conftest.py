"""Pytest fixtures for the proxy-mode e2e suite."""

from __future__ import annotations

from collections.abc import Callable

import pytest
import runner
from runner import ProxyRun


@pytest.fixture(scope="module")
def proxy_runner(tmp_path_factory: pytest.TempPathFactory) -> Callable[..., ProxyRun]:
    """Run the emulator + proxy, cached per (cmplog, mode, corpus, primary) within a module."""

    cache: dict[tuple[bool, str, str, str], ProxyRun] = {}
    root = tmp_path_factory.mktemp("proxy-mode")

    def run(mode: str, corpus: str, *, cmplog: bool = False, primary: str = "procfs") -> ProxyRun:
        key = (cmplog, mode, corpus, primary)
        if key not in cache:
            variant = "cmplog" if cmplog else "normal"
            slug = f"run{len(cache):02d}-{variant}-{mode}-{corpus.replace('/', '-')}-{primary}"
            case_dir = root / slug
            case_dir.mkdir(parents=True)
            config = runner.write_config(
                case_dir,
                mode=mode,
                port=runner.free_port(),
                cmplog=cmplog,
                primary=primary,
            )
            cache[key] = runner.run_proxy_mode(case_dir / "run", config, corpus, cmplog=cmplog)
        return cache[key]

    return run
