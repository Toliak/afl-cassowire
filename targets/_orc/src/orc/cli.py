"""argparse CLI: ``python -m orc <target> <command> [options]``."""

from __future__ import annotations

import argparse
import json
import sys

from . import common
from .common import TargetError


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="orc",
        description="Target-assist CLI (runs inside the container or dev container).",
    )
    parser.add_argument("target", help="target name under targets/ (e.g. nginx)")
    parser.add_argument(
        "--repo-root",
        default=None,
        help="override repo root (default: derived from the orc package location)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("prepare-data", help="render data_template/*.j2 -> data/")
    p_seeds = sub.add_parser("prepare-seeds", help="merge seed sources into in/")
    p_seeds.add_argument("--fuzzer", default="aflpp", help="fuzzer key in SEED_SOURCES")
    p_seeds.add_argument(
        "--profile",
        default=None,
        help="profile name for targets that define PROFILES (default: DEFAULT_PROFILE)",
    )
    p_seeds.add_argument(
        "--out",
        default=None,
        help="destination dir relative to target (default: in/<profile> or in)",
    )
    p_cov = sub.add_parser("collect-cov", help="lcov capture + genhtml from existing .gcda")
    p_cov.add_argument("--out", default="cov", help="output dir relative to target")
    p_replay = sub.add_parser("replay-cov", help="replay corpus against the gcov build")
    p_replay.add_argument(
        "--profile",
        default=None,
        help="profile to replay (default: all profiles; legacy targets: default)",
    )
    p_crashes = sub.add_parser("collect-crashes", help="collect AFL crash files into crashes/")
    p_crashes.add_argument(
        "--profile",
        default=None,
        help="restrict triage to out/<profile> (default: all profiles)",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.repo_root:
        common.REPO_ROOT = __import__("pathlib").Path(args.repo_root).resolve()
        common.TARGETS_DIR = common.REPO_ROOT / "targets"

    try:
        target = args.target
        if args.command == "prepare-data":
            from .prepare_data import prepare_data

            result = prepare_data(target)
            print(f"prepare-data[{target}]: {len(result)} file(s) rendered")
            for r in result:
                print(f"  {r}")

        elif args.command == "prepare-seeds":
            from .seeds import prepare_seeds

            result = prepare_seeds(target, args.fuzzer, args.out, args.profile)
            print(f"prepare-seeds[{target}/{args.fuzzer}]: {len(result)} seed(s)")
            for r in result:
                print(f"  {r}")

        elif args.command == "collect-cov":
            from .coverage import collect_cov

            result = collect_cov(target, args.out)
            print(json.dumps(result, indent=2))

        elif args.command == "replay-cov":
            from .replay import replay_cov

            result = replay_cov(target, args.profile)
            print(json.dumps(result, indent=2))

        elif args.command == "collect-crashes":
            from .crashes import collect_crashes

            result = collect_crashes(target, args.profile)
            print(json.dumps(result, indent=2))

        else:  # pragma: no cover - argparse enforces this
            parser.error(f"unknown command: {args.command}")
        return 0

    except TargetError as exc:
        print(f"orc: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
