#!/usr/bin/env python3
"""Apply MonkeyType inferred annotations to selected project modules.

Layer: Tooling/gates.
Responsibility: owns applying traced annotations to selected modules.
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
    MONKEYTYPE_CACHE_DIR,
    MONKEYTYPE_DB_PATH,
    parse_list_modules_output,
)


def _python() -> str:
    venv_py = REPO_ROOT / ".venv" / "bin" / "python"
    if venv_py.exists():
        return str(venv_py)
    return sys.executable


def _run_monkeytype(args: list[str]) -> subprocess.CompletedProcess[str]:
    cmd = [_python(), "-m", "monkeytype", "-c", "monkeytype_config:CONFIG", *args]
    return subprocess.run(cmd, cwd=REPO_ROOT, check=False, text=True, capture_output=True)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Apply MonkeyType inferred annotations to traced project modules.")
    parser.add_argument(
        "--module-prefix",
        action="append",
        default=[],
        help="Module prefix to include. Defaults to project prefixes.",
    )
    parser.add_argument(
        "--ignore-existing-annotations",
        action="store_true",
        help="Pass --ignore-existing-annotations to monkeytype apply.",
    )
    parser.add_argument(
        "--per-module-timeout",
        type=int,
        default=120,
        help="Timeout in seconds for each monkeytype apply call.",
    )
    return parser.parse_args(argv)


def _resolve_modules(prefixes: tuple[str, ...]) -> tuple[str, ...]:
    listed = _run_monkeytype(["list-modules"])
    if listed.returncode != 0:
        raise SystemExit(listed.stderr.strip() or listed.stdout.strip() or "monkeytype list-modules failed")
    return parse_list_modules_output(listed.stdout, prefixes=prefixes)


def _apply_module_annotations(
    module_name: str, *, ignore_existing_annotations: bool, per_module_timeout: int
) -> str | None:
    apply_args = ["apply", module_name]
    if ignore_existing_annotations:
        apply_args.append("--ignore-existing-annotations")
    try:
        done = subprocess.run(
            [_python(), "-m", "monkeytype", "-c", "monkeytype_config:CONFIG", *apply_args],
            cwd=REPO_ROOT,
            check=False,
            text=True,
            capture_output=True,
            timeout=max(5, per_module_timeout),
        )
    except subprocess.TimeoutExpired:
        return f"{module_name}: timed out after {per_module_timeout}s"
    if done.returncode != 0:
        return f"{module_name}: {done.stderr.strip() or done.stdout.strip()}"
    print("  applied", flush=True)
    return None


def _write_failures(failed: list[str]) -> None:
    failures_path = MONKEYTYPE_CACHE_DIR / "apply_failures.txt"
    failures_path.parent.mkdir(parents=True, exist_ok=True)
    failures_path.write_text("\n".join(failed) + "\n", encoding="utf-8")
    print(f"wrote {failures_path}")
    print("failed modules:")
    for line in failed:
        print(f"  {line}")


def main(argv: list[str] | None = None) -> int:
    """Apply MonkeyType annotations to modules selected by prefix."""

    args = _parse_args(argv)

    if not MONKEYTYPE_DB_PATH.exists():
        raise SystemExit(f"MonkeyType DB not found: {MONKEYTYPE_DB_PATH}")

    prefixes = tuple(args.module_prefix) if args.module_prefix else DEFAULT_STUB_MODULE_PREFIXES
    modules = _resolve_modules(prefixes)
    if not modules:
        print("No modules matched prefixes.")
        return 0

    failed: list[str] = []
    for idx, module_name in enumerate(modules, 1):
        print(f"[{idx}/{len(modules)}] {module_name}", flush=True)
        failure = _apply_module_annotations(
            module_name,
            ignore_existing_annotations=args.ignore_existing_annotations,
            per_module_timeout=args.per_module_timeout,
        )
        if failure is not None:
            failed.append(failure)
    if failed:
        _write_failures(failed)
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
