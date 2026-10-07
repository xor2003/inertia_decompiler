#!/usr/bin/env python3
"""Collect MonkeyType traces from curated pytest targets.

Layer: Tooling/gates.
Responsibility: owns pytest-driven MonkeyType trace collection.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from inertia.cli.monkeytype_tools import DEFAULT_MONKEYTYPE_TEST_TARGETS, ensure_monkeytype_dirs  # noqa: E402


def _python() -> str:
    venv_py = REPO_ROOT / ".venv" / "bin" / "python"
    if venv_py.exists():
        return str(venv_py)
    return sys.executable


def _run_target(pytest_target: str, extra_pytest_args: list[str]) -> int:
    cmd = [
        _python(),
        "-m",
        "monkeytype",
        "-c",
        "monkeytype_config:CONFIG",
        "run",
        "-m",
        "pytest",
        "-q",
        pytest_target,
        *extra_pytest_args,
    ]
    print(" ".join(cmd))
    proc = subprocess.run(cmd, cwd=REPO_ROOT, check=False)
    return int(proc.returncode)


def main(argv: list[str] | None = None) -> int:
    """Collect MonkeyType traces from configured pytest targets."""

    parser = argparse.ArgumentParser(description="Collect MonkeyType traces by running pytest targets.")
    parser.add_argument(
        "--target",
        action="append",
        default=[],
        help="Pytest target path; can be provided multiple times. Defaults to curated target list.",
    )
    parser.add_argument(
        "--keep-going",
        action="store_true",
        help="Continue tracing remaining targets even if one fails.",
    )
    parser.add_argument(
        "pytest_args",
        nargs="*",
        help="Extra arguments passed through to pytest.",
    )
    args = parser.parse_args(argv)

    ensure_monkeytype_dirs()
    targets = tuple(args.target) if args.target else DEFAULT_MONKEYTYPE_TEST_TARGETS
    failed: list[str] = []
    for target in targets:
        rc = _run_target(target, args.pytest_args)
        if rc != 0:
            failed.append(target)
            if not args.keep_going:
                break
    if failed:
        print("failed targets:")
        for target in failed:
            print(f"  {target}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
