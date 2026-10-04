"""Layer: validation proof accounting.

Responsibility: publish PASS only from complete, identified backend evidence;
keep relocation-dependent equality distinct from unconditional equivalence.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Any


class Status(StrEnum):
    """Public function verdict; CONDITIONAL does not satisfy a proof obligation."""

    PASSED = 'passed'
    FAILED = 'failed'
    REFUSED = 'refused'
    CONDITIONAL = 'conditional'


class Reason(StrEnum):
    """Typed reasons why backend evidence cannot establish an unconditional proof."""

    INVALID_REPORT = 'invalid_backend_report'
    INCONSISTENT_SUMMARY = 'inconsistent_backend_summary'
    ABORTED = 'backend_aborted'
    UNEXPECTED_RESULT = 'unexpected_backend_result'
    MISSING_RESULT = 'missing_backend_result'
    DUPLICATE_RESULT = 'duplicate_backend_result'
    UNKNOWN_STATUS = 'unknown_backend_status'
    IDENTITY_MISMATCH = 'backend_identity_mismatch'
    RELOCATION_ASSUMPTIONS = 'relocation_assumptions'


BACKEND_STATUSES: frozenset[Status] = frozenset((Status.PASSED, Status.FAILED, Status.REFUSED))
REPORT_SCHEMA: str = 'msc8.z3cmp32.v2'


def refusal(name: str, function_id: str, reason: Reason) -> dict[str, Any]:
    """Keep the original obligation visible when proof evidence is unusable."""
    return {'function': {'id': function_id, 'name': name}, 'status': Status.REFUSED, 'reason': reason}


def _report_problem(report: dict[str, Any], rows: list[dict[str, Any]]) -> Reason | None:
    """Cross-check backend counters against records, rejecting aborted comparisons."""
    summary = report.get('summary')
    if not isinstance(summary, dict):
        return Reason.INVALID_REPORT
    if report.get('aborted') or summary.get('aborted'):
        return Reason.ABORTED
    counts = Counter(row.get('status') for row in rows)
    if any(status not in BACKEND_STATUSES for status in counts):
        return Reason.UNKNOWN_STATUS
    expected = {'total': len(rows), **{status.value: counts[status] for status in BACKEND_STATUSES}}
    for field, value in expected.items():
        if type(summary.get(field)) is not int or summary[field] != value:
            return Reason.INCONSISTENT_SUMMARY
    return None


def _identified_rows(report: dict[str, Any]) -> tuple[list[dict[str, Any]], Reason | None]:
    """Validate the dynamic JSON boundary before typed verdict accounting."""
    rows = report.get('results')
    if not isinstance(rows, list):
        return [], Reason.INVALID_REPORT
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('function'), dict):
            return [], Reason.INVALID_REPORT
        if not isinstance(row.get('status'), str) or not isinstance(row['function'].get('name'), str):
            return [], Reason.INVALID_REPORT
    return rows, _report_problem(report, rows)


def checked_results(expected: Mapping[str, str], report: dict[str, Any], *,
                    relocation: Mapping[int, int] | None = None) -> list[dict[str, Any]]:
    """Require one identified verdict per obligation and label relocation assumptions."""
    rows, problem = _identified_rows(report)
    if problem is None and any(row['function']['name'] not in expected for row in rows):
        problem = Reason.UNEXPECTED_RESULT
    if problem is not None:
        return [refusal(name, identity, problem) for name, identity in expected.items()]
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(row['function']['name'], []).append(row)
    return [_checked_obligation(name, identity, grouped.get(name, []), relocation)
            for name, identity in expected.items()]


def _checked_obligation(name: str, identity: str, rows: list[dict[str, Any]],
                        relocation: Mapping[int, int] | None) -> dict[str, Any]:
    """Reject missing/duplicate identities and retain the raw solver verdict."""
    if not rows:
        return refusal(name, identity, Reason.MISSING_RESULT)
    if len(rows) != 1:
        return refusal(name, identity, Reason.DUPLICATE_RESULT)
    row = rows[0]
    if row['function'].get('id') != identity:
        return refusal(name, identity, Reason.IDENTITY_MISMATCH)
    result = dict(row)
    result['status'] = Status(row['status'])
    if result['status'] == Status.PASSED and relocation:
        result.update(status=Status.CONDITIONAL, reason=Reason.RELOCATION_ASSUMPTIONS,
                      backend_status=Status.PASSED, backend_reason=row.get('reason'),
                      assumptions={'constant_relocation_count': len(relocation),
                                   'scope': 'equality of rewritten SSA; original memory/alias relation unproved'})
    return result


def summarize(results: Sequence[dict[str, Any]]) -> dict[str, int]:
    """Count every public verdict; reject internal unknown states rather than hide them."""
    counts = Counter(Status(row['status']) for row in results)
    return {'total': len(results), **{status.value: counts[status] for status in Status}}


def aggregate(results: Sequence[dict[str, Any]]) -> Status:
    """All blocks must pass; any missing proof keeps the whole CFG unproved."""
    statuses = {Status(row['status']) for row in results}
    if Status.FAILED in statuses:
        return Status.FAILED
    if not statuses or Status.REFUSED in statuses:
        return Status.REFUSED
    if Status.CONDITIONAL in statuses:
        return Status.CONDITIONAL
    return Status.PASSED


def exit_code(summary: Mapping[str, int]) -> int:
    """Return 0 only for consistent nonempty all-PASS counts; conditional is 2."""
    counts = {status: summary.get(status.value, 0) for status in Status}
    total = summary.get('total', 0)
    if any(type(value) is not int or value < 0 for value in (*counts.values(), total)):
        return 2
    if counts[Status.FAILED]:
        return 1
    if total <= 0 or sum(counts.values()) != total:
        return 2
    return 0 if counts[Status.PASSED] == total else 2
