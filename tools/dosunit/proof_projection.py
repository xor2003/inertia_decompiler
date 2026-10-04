"""Checked compatibility boundary for comparator proof reports.

Layer: dosunit proof accounting.
Responsibility: project identified legacy backend records into contract-bound
obligations without promoting missing, malformed or conditional evidence.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from typing import Any

from tools.dosunit.proof_contracts import (
    ContractIdentity,
    FactCounters,
    Obligation,
    ObligationEvidence,
    ObligationId,
    ObligationReport,
    ProofStatus,
    evaluate_obligations,
    proof_status_from_legacy,
)


def _report_rows(report: Mapping[str, object]) -> tuple[list[dict[str, Any]], bool]:
    """Validate dynamic JSON rows and cross-check all backend summary counts."""
    rows, summary = report.get('results'), report.get('summary')
    if not isinstance(rows, list) or not isinstance(summary, dict):
        return [], False
    if not all(isinstance(row, dict) for row in rows):
        return [], False
    statuses = Counter(str(row.get('status')) for row in rows)
    valid = not report.get('aborted') and not summary.get('aborted')
    expected = {'total': len(rows), **{status: statuses[status] for status in ('passed', 'failed', 'refused', 'conditional')}}
    for field, count in expected.items():
        # Legacy raw dosunit summaries lack a conditional counter; zero is safe.
        value = summary.get(field, 0)
        valid = valid and type(value) is int and value == count
    if set(statuses) - {'passed', 'failed', 'refused', 'conditional'}:
        valid = False
    return rows, valid


def project_backend_report(
    contract: ContractIdentity, required_names: tuple[str, ...], report: Mapping[str, object],
) -> ObligationReport:
    """Evaluate exactly the requested identities against a checked backend report.

    This checks evidence accounting, not correctness of the lifter or backend.
    Callers bind the model and proof scope into the contract identity.
    """
    required = tuple(Obligation(ObligationId('function', name)) for name in required_names)
    rows, valid = _report_rows(report)
    evidence: list[ObligationEvidence] = []
    for index, row in enumerate(rows):
        function = row.get('function')
        name = function.get('name') if isinstance(function, dict) else None
        name = name if isinstance(name, str) and name else f'<invalid-row:{index}>'
        status = proof_status_from_legacy(row.get('status')) if valid else None
        status = status if status is not None else ProofStatus.UNKNOWN
        raw_assumptions = row.get('assumptions') or row.get('paired_call_assumptions')
        assumptions = ('backend_assumptions',) if raw_assumptions else ()
        evidence.append(ObligationEvidence(
            id=ObligationId('function', name), contract=contract, status=status,
            method='legacy_backend', reason=str(row.get('reason') or ''), assumptions=assumptions,
            counters=FactCounters(1, 1, 1, 1, int(status is not ProofStatus.PROVED)),
        ))
    return evaluate_obligations(contract, required, tuple(evidence))
