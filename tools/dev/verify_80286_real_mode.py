#!/usr/bin/env python3
"""Compatibility helpers for 80286 real-mode verifier tests.

Layer: Tooling/gates.
Responsibility: expose the canonical 80286 verifier helper surface for tests and scripts.

This module mirrors the small utility surface that older verifier tests and
scripts expect while reusing the canonical implementation in
``inertia.frontend.x86_16.verification_80286``.
"""

from __future__ import annotations

from pathlib import Path

from inertia.frontend.x86_16.coverage_manifest import COMPARE_VERIFIED_MOO_OPCODES
from inertia.frontend.x86_16.verification_80286 import (
    REPO_ROOT,
    load_moo_cases,
    summarize_results,
    summary_to_json,
    verify_case,
    verify_moo_file,
)


def _normalize_opcode(path: Path) -> str:
    name = path.name
    if name.endswith(".MOO.gz"):
        return name[:-7].upper()
    if name.endswith(".MOO"):
        return name[:-4].upper()
    return path.stem.upper()


def _exclude_compare_covered(files: list[Path]) -> tuple[list[Path], list[Path]]:
    kept: list[Path] = []
    skipped: list[Path] = []
    compare_verified = {opcode.upper() for opcode in COMPARE_VERIFIED_MOO_OPCODES}
    for path in files:
        if _normalize_opcode(path) in compare_verified:
            skipped.append(path)
        else:
            kept.append(path)
    return kept, skipped


def _sample_compare_covered(files: list[Path], *, day_of_month: int = 1) -> tuple[list[Path], list[Path], list[Path]]:
    kept, skipped = _exclude_compare_covered(files)
    if not kept:
        return kept, [], skipped

    ordered = list(kept)
    ordered.sort(key=_normalize_opcode)
    sample_count = max(1, len(ordered) // 2)
    start = ((day_of_month - 1) % len(ordered))
    sampled = [ordered[(start + offset) % len(ordered)] for offset in range(sample_count)]
    return ordered, sampled, skipped


def _load_passed_cache(path: Path) -> set[str]:
    if not path.exists():
        return set()

    lines = (line.strip() for line in path.read_text(encoding="utf-8").splitlines())
    return {line.upper() for line in lines if line}


def _exclude_cached_passes(files: list[Path], passed_cache: set[str]) -> tuple[list[Path], list[Path]]:
    normalized = {opcode.upper() for opcode in passed_cache}
    kept: list[Path] = []
    skipped: list[Path] = []
    for path in files:
        if _normalize_opcode(path) in normalized:
            skipped.append(path)
        else:
            kept.append(path)
    return kept, skipped


def _update_passed_cache(path: Path, file_summaries: list[dict[str, object]]) -> set[str]:
    existing = _load_passed_cache(path)
    for item in file_summaries:
        if not isinstance(item, dict):
            continue
        opcode = item.get("opcode")
        failed = item.get("failed")
        if not isinstance(opcode, str) or not isinstance(failed, int) or failed != 0:
            continue
        existing.add(opcode.upper())

    ordered = []
    for opcode in sorted(existing):
        ordered.append(opcode)  # noqa: PERF402
    path.write_text("\n".join(ordered), encoding="utf-8")
    return existing


__all__ = [
    "REPO_ROOT",
    "_exclude_cached_passes",
    "_exclude_compare_covered",
    "_load_passed_cache",
    "_sample_compare_covered",
    "_update_passed_cache",
    "load_moo_cases",
    "summarize_results",
    "summary_to_json",
    "verify_case",
    "verify_moo_file",
]


if __name__ == "__main__":
    raise SystemExit(0)
