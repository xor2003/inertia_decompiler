"""Recover exact failed-case selections from completed coverage reports.

Layer: Test infrastructure.
Responsibility: reject stale or ambiguous report identities before rerunning.
"""

from __future__ import annotations

import json
from pathlib import Path

from scripts.compiler_coverage_manifest import CoverageCase, CoverageManifest
from scripts.compiler_coverage_result import CoverageOutcome


def _completed_rows(path: Path, digest: str) -> list[object]:
    """Validate manifest identity and completeness before interpreting case rows."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or type(payload.get("schema")) is not int or payload["schema"] != 1:
        raise ValueError("Rerun report: unsupported schema")
    if payload.get("manifest_sha256") != digest:
        raise ValueError("Rerun report: manifest identity changed or is missing")
    rows = payload.get("cases")
    if not isinstance(rows, list) or not rows:
        raise ValueError("Rerun report: cases must be a nonempty list")
    for field in ("selected", "completed"):
        if type(payload.get(field)) is not int or payload[field] != len(rows):
            raise ValueError("Rerun report: incomplete case inventory")
    return rows


def failed_cases(path: Path, manifest: CoverageManifest, digest: str) -> tuple[CoverageCase, ...]:
    """Select nonpassing rows only when the report matches the current manifest."""
    rows = _completed_rows(path, digest)
    known = {case.identifier: case for case in manifest.cases}
    seen: set[str] = set()
    failed: list[CoverageCase] = []
    for row in rows:
        candidate, outcome = _case_row(row, known)
        if candidate.identifier in seen:
            raise ValueError("Rerun report: duplicate case")
        seen.add(candidate.identifier)
        if outcome is not CoverageOutcome.PASSED:
            failed.append(candidate)
    if not failed:
        raise ValueError("Rerun report: no failed cases")
    return tuple(failed)


def _case_row(row: object, known: dict[str, CoverageCase]) -> tuple[CoverageCase, CoverageOutcome]:
    """Validate one case identity and outcome without trusting aggregate booleans."""
    if not isinstance(row, dict) or not isinstance(row.get("case"), str):
        raise ValueError("Rerun report: invalid case row")
    candidate = known.get(row["case"])
    if candidate is None:
        raise ValueError("Rerun report: unknown case")
    if row.get("construct") != candidate.construct or row.get("obligations") != list(candidate.obligations):
        raise ValueError("Rerun report: changed case definition")
    value = row.get("outcome")
    if not isinstance(value, str):
        raise ValueError("Rerun report: invalid outcome")
    return candidate, CoverageOutcome(value)
