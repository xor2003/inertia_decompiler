"""Deterministic publication of typed semantic and execution evidence.

Layer: dosunit proof reporting.
Responsibility: retain provenance, methods, dependency identities, assumptions
and obligation counters at the JSON boundary.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from tools.dosunit.model import canonical_json_bytes
from tools.dosunit.proof_contracts import (
    REPORT_SCHEMA,
    FactCounters,
    ObligationReport,
    ProofStatus,
)


def _counters_document(counters: FactCounters) -> dict[str, int]:
    """Serialize the closed fact-pipeline counters."""
    return {
        "raw_fact_count": counters.raw_fact_count,
        "normalized_fact_count": counters.normalized_fact_count,
        "classified_fact_count": counters.classified_fact_count,
        "materialized_count": counters.materialized_count,
        "failure_count": counters.failure_count,
    }


def report_to_document(report: ObligationReport) -> dict[str, Any]:
    """Serialize a report deterministically for JSON boundaries and caches."""
    counts = Counter(verdict.status for verdict in report.verdicts)
    discharged = counts[ProofStatus.PROVED]
    conditional = counts[ProofStatus.CONDITIONAL]
    failed = counts[ProofStatus.COUNTEREXAMPLE]
    return {
        "schema": REPORT_SCHEMA,
        "status": report.status.value,
        "problem": report.problem.value if report.problem is not None else None,
        "contract": {**report.contract.to_document(), "key": report.contract.key()},
        "counters": _counters_document(report.counters),
        "obligations": {
            "required": len(report.verdicts),
            "attempted": sum(verdict.attempted for verdict in report.verdicts),
            "discharged": discharged,
            "conditional": conditional,
            "failed": failed,
            "unresolved": len(report.verdicts) - discharged - conditional - failed,
        },
        "verdicts": [
            {
                "id": {"kind": verdict.id.kind, "key": verdict.id.key},
                "status": verdict.status.value,
                "reason": verdict.reason.value,
                "detail": verdict.detail,
                "method": verdict.method,
                "attempted": verdict.attempted,
                "evidence_contract_key": verdict.evidence_contract_key,
                "dependencies": [{"kind": dep.kind, "key": dep.key} for dep in verdict.dependencies],
                "assumptions": list(verdict.assumptions),
                "counters": _counters_document(verdict.counters),
            }
            for verdict in report.verdicts
        ],
        "unexpected_evidence": [{"kind": ob_id.kind, "key": ob_id.key} for ob_id in report.unexpected_evidence],
        "executions": [
            {"id": {"kind": item.id.kind, "key": item.id.key}, "status": item.status.value, "detail": item.detail}
            for item in report.executions
        ],
    }


def report_json_bytes(report: ObligationReport) -> bytes:
    """Return the canonical deterministic JSON encoding of a report."""
    serialized: bytes = canonical_json_bytes(report_to_document(report))
    return serialized

