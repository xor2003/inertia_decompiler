#!/usr/bin/env python3
"""Export MonkeyType stubs for selected traced project modules.

Layer: Tooling/gates.
Responsibility: owns exporting traced MonkeyType stubs.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from inertia.cli.monkeytype_tools import (  # noqa: E402
    DEFAULT_STUB_MODULE_PREFIXES,
    MONKEYTYPE_DB_PATH,
    ensure_monkeytype_dirs,
    parse_list_modules_output,
    stub_path_for_module,
)

PYTHON: Path = REPO_ROOT / ".venv" / "bin" / "python"


def _python() -> str:
    return str(PYTHON if PYTHON.exists() else Path(sys.executable))


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [_python(), "-m", "monkeytype", "-c", "monkeytype_config:CONFIG", *args],
        cwd=REPO_ROOT,
        check=False,
        text=True,
        capture_output=True,
    )


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export MonkeyType stubs into .cache/monkeytype/stubs.")
    parser.add_argument(
        "--module-prefix",
        action="append",
        default=[],
        help="Module prefix to export. Can be repeated. Defaults to the repo prefixes.",
    )
    return parser.parse_args(argv)


def _resolve_modules(prefixes: tuple[str, ...]) -> tuple[str, ...]:
    listed = _run("list-modules")
    if listed.returncode:
        raise SystemExit(listed.stderr.strip() or listed.stdout.strip() or "monkeytype list-modules failed")
    return parse_list_modules_output(listed.stdout, prefixes=prefixes)


def _export_stub(module_name: str) -> str | None:
    completed = _run("stub", module_name)
    if completed.returncode:
        return f"{module_name}: {completed.stderr.strip() or completed.stdout.strip()}"
    stub = completed.stdout
    if not stub.strip():
        return None
    stub_path = stub_path_for_module(module_name)
    stub_path.parent.mkdir(parents=True, exist_ok=True)
    stub_path.write_text(stub, encoding="utf-8")
    print(stub_path.relative_to(REPO_ROOT))
    return None


def _write_failures(failures: list[str]) -> None:
    failures_path = REPO_ROOT / ".cache" / "monkeytype" / "stub_failures.txt"
    failures_path.write_text("\n\n".join(failures) + "\n", encoding="utf-8")
    print(".cache/monkeytype/stub_failures.txt")


def main(argv: list[str] | None = None) -> int:
    """Export MonkeyType stubs for modules selected by prefix."""

    args = _parse_args(argv)

    ensure_monkeytype_dirs()
    if not MONKEYTYPE_DB_PATH.exists():
        raise SystemExit(f"MonkeyType DB not found: {MONKEYTYPE_DB_PATH}")

    prefixes = tuple(args.module_prefix) if args.module_prefix else DEFAULT_STUB_MODULE_PREFIXES
    modules = _resolve_modules(prefixes)
    failures: list[str] = []
    for module_name in modules:
        failure = _export_stub(module_name)
        if failure is not None:
            failures.append(failure)
    if failures:
        _write_failures(failures)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
