#!/usr/bin/env python3
"""Run MonkeyType tracing commands for the docs/types ratchet.

Layer: Tooling/gates.
Responsibility: collect optional MonkeyType traces that inform, but do not replace, typed contracts.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from inertia.cli.monkeytype_tools import (  # noqa: E402
    DEFAULT_MONKEYTYPE_TEST_TARGETS,
    MONKEYTYPE_DB_PATH,
    ensure_monkeytype_dirs,
)

PYTHON = REPO_ROOT / ".venv" / "bin" / "python"


def _python() -> str:
    return str(PYTHON if PYTHON.exists() else Path(sys.executable))


def main(argv: list[str] | None = None) -> int:
    """Run selected pytest targets under MonkeyType tracing."""
    parser = argparse.ArgumentParser(description="Run pytest targets under MonkeyType tracing.")
    parser.add_argument(
        "--reset-db", action="store_true", help="Remove the existing MonkeyType sqlite DB before tracing."
    )
    parser.add_argument(
        "--pytest-target",
        action="append",
        default=[],
        help="Pytest target to trace. Can be repeated. Defaults to the phase-7 fast targets.",
    )
    parser.add_argument("--pytest-arg", action="append", default=[], help="Extra raw pytest args.")
    args = parser.parse_args(argv)

    ensure_monkeytype_dirs()
    if args.reset_db and MONKEYTYPE_DB_PATH.exists():
        MONKEYTYPE_DB_PATH.unlink()

    targets = tuple(args.pytest_target) if args.pytest_target else DEFAULT_MONKEYTYPE_TEST_TARGETS
    command = [
        _python(),
        "-m",
        "monkeytype",
        "-c",
        "monkeytype_config:CONFIG",
        "run",
        "-m",
        "pytest",
        "-q",
        *targets,
        *args.pytest_arg,
    ]
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=REPO_ROOT, check=True)
    print(f"db: {MONKEYTYPE_DB_PATH}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
