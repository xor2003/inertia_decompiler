#!/usr/bin/env python3
"""Exhaustively verify defined borrowed 80286 and 80386 real-mode cases.

Layer: Tooling/gates.
Responsibility: run deterministic, resumable, bounded-parallel corpus sweeps and
write compact evidence without treating undefined outcomes as passes.
"""

from __future__ import annotations

import argparse
import contextlib
import fnmatch
import io
import json
import os
import sys
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from inertia.frontend.x86_16.borrow_verification import BorrowCaseDisposition, classify_borrow_case  # noqa: E402
from inertia.frontend.x86_16.verification_80286 import _make_project as _make_project_80286  # noqa: E402
from inertia.frontend.x86_16.verification_80286 import (  # noqa: E402
    load_moo_cases,
    opcode_name_for_path,
    verify_case,
)
from inertia.frontend.x86_16.verification_80386 import _make_project as _make_project_80386  # noqa: E402
from inertia.frontend.x86_16.verification_80386 import (  # noqa: E402
    verify_straightline_case_80386,
)

CORPUS_ROOTS = {
    "80286": REPO_ROOT / "borrow" / "80286" / "v1_real_mode",
    "80386": REPO_ROOT / "borrow" / "80386" / "v1_ex_real_mode",
}
MAX_FAILURE_EVIDENCE = 20
AUDIT_SCHEMA_VERSION = 2


def _verify_file(task: tuple[str, str, int | None, str]) -> dict[str, Any]:
    """Verify one opcode file and return compact deterministic accounting."""
    cpu, raw_path, limit, raw_resume_dir = task
    path = Path(raw_path)
    resume_path = Path(raw_resume_dir) / f"{cpu}-{opcode_name_for_path(path)}.json"
    source_mtime_ns = path.stat().st_mtime_ns
    if resume_path.exists():
        cached = json.loads(resume_path.read_text(encoding="utf-8"))
        if (
            cached.get("schema_version") == AUDIT_SCHEMA_VERSION
            and cached.get("source_mtime_ns") == source_mtime_ns
            and cached.get("limit_per_file") == limit
        ):
            return cached
    with contextlib.redirect_stdout(io.StringIO()):
        _cpu_name, cases = load_moo_cases(path)
    if limit is not None:
        cases = cases[:limit]
    opcode = opcode_name_for_path(path)
    counts = {disposition.value: 0 for disposition in BorrowCaseDisposition}
    passed = 0
    failed = 0
    failures: list[dict[str, Any]] = []
    project = _make_project_80286() if cpu == "80286" else _make_project_80386()
    for case in cases:
        classification = classify_borrow_case(cpu, opcode, case)
        counts[classification.disposition.value] += 1
        if classification.disposition is not BorrowCaseDisposition.HARDWARE_REQUIRED:
            continue
        result = (
            verify_case(case, opcode=opcode, project=project)
            if cpu == "80286"
            else verify_straightline_case_80386(case, opcode=opcode, project=project)
        )
        if result.passed:
            passed += 1
            continue
        failed += 1
        if len(failures) < MAX_FAILURE_EVIDENCE:
            failures.append(asdict(result))
    accounted = sum(counts.values())
    if accounted != len(cases) or passed + failed != counts[BorrowCaseDisposition.HARDWARE_REQUIRED.value]:
        raise RuntimeError(f"incomplete accounting for {cpu} {opcode}")
    result = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "source_mtime_ns": source_mtime_ns,
        "limit_per_file": limit,
        "cpu": cpu,
        "opcode": opcode,
        "path": str(path),
        "total": len(cases),
        **counts,
        "passed": passed,
        "failed": failed,
        "failures": failures,
    }
    resume_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = resume_path.with_suffix(".tmp")
    temporary_path.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary_path, resume_path)
    return result


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpu", choices=("80286", "80386", "all"), default="all")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--limit-per-file", type=int)
    parser.add_argument(
        "--opcode",
        action="append",
        dest="opcode_patterns",
        help="verify only opcode names matching this shell-style pattern; repeatable",
    )
    parser.add_argument("--output", type=Path, default=REPO_ROOT / ".cache" / "borrow-real-mode-verification.json")
    parser.add_argument(
        "--resume-dir",
        type=Path,
        default=REPO_ROOT / ".cache" / "borrow-real-mode-verification-files",
    )
    return parser.parse_args()


def main() -> int:
    """Run selected corpora and write one deterministic aggregate report."""
    args = _parse_args()
    cpus = ("80286", "80386") if args.cpu == "all" else (args.cpu,)
    tasks = []
    for cpu in cpus:
        for path in sorted(CORPUS_ROOTS[cpu].glob("*.MOO.gz")):
            opcode = opcode_name_for_path(path)
            if args.opcode_patterns and not any(fnmatch.fnmatchcase(opcode, pattern.upper()) for pattern in args.opcode_patterns):
                continue
            tasks.append((cpu, str(path), args.limit_per_file, str(args.resume_dir)))
    workers = max(1, min(args.workers, os.cpu_count() or 1))
    with ProcessPoolExecutor(max_workers=workers) as executor:
        files = list(executor.map(_verify_file, tasks, chunksize=1))
    files.sort(key=lambda item: (str(item["cpu"]), str(item["opcode"])))
    summary: dict[str, Any] = {
        "suite": "borrow_real_mode_defined_cases",
        "workers": workers,
        "files": files,
        "total_files": len(files),
    }
    for field in (
        "total",
        "pyvex_proven",
        "hardware_required",
        "undefined_excluded",
        "out_of_scope_excluded",
        "oracle_defect_excluded",
        "passed",
        "failed",
    ):
        summary[field] = sum(int(item[field]) for item in files)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in summary.items() if key != "files"}, sort_keys=True))
    return int(summary["failed"] != 0)


if __name__ == "__main__":
    raise SystemExit(main())
