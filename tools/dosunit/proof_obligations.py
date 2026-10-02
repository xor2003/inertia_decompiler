"""Conservative evaluation of contract-bound semantic proof obligations.

Layer: dosunit proof accounting.
Responsibility: enforce evidence closure and dependency validity without
allowing missing facts, assumptions or cyclic dependencies to establish proof.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

from tools.dosunit.proof_contracts import (
    ContractIdentity,
    ExecutionEvidence,
    FactCounters,
    Obligation,
    ObligationEvidence,
    ObligationId,
    ObligationReport,
    ObligationVerdict,
    ProofReason,
    ProofStatus,
)

_PROVABLE = (ProofStatus.PROVED, ProofStatus.CONDITIONAL)
_STATUS_RANK = {ProofStatus.PROVED: 0, ProofStatus.CONDITIONAL: 1, ProofStatus.UNKNOWN: 2}

@dataclass(frozen=True)
class _BaseVerdict:
    """One obligation's verdict before dependency constraints are applied."""

    status: ProofStatus
    reason: ProofReason
    detail: str
    method: str
    counters: FactCounters


def evaluate_obligations(
    contract: ContractIdentity,
    required: Sequence[Obligation],
    evidence: Sequence[ObligationEvidence],
    *,
    executions: Sequence[ExecutionEvidence] = (),
) -> ObligationReport:
    """Evaluate required obligations against evidence; never promote incomplete proof.

    Rejects empty obligation sets, unexpected or duplicated rows, stale or
    narrowed contract identities, assumption-laden evidence, open fact
    pipelines and any dependency that is missing, unproved or cyclic.
    """
    required_ids = Counter(obligation.id for obligation in required)
    if not required_ids:
        stray = tuple(sorted({row.id for row in evidence}))
        return _report(contract, ProofReason.EMPTY_OBLIGATIONS, (), stray, executions)
    evidence_index: dict[ObligationId, list[ObligationEvidence]] = {}
    unexpected: set[ObligationId] = set()
    for row in evidence:
        if row.id in required_ids:
            evidence_index.setdefault(row.id, []).append(row)
        else:
            unexpected.add(row.id)
    problem = ProofReason.UNEXPECTED_EVIDENCE if unexpected else None
    if problem is None and any(count != 1 for count in required_ids.values()):
        problem = ProofReason.DUPLICATE_OBLIGATION
    if problem is not None:
        verdicts = tuple(
            ObligationVerdict(id=ob_id, status=ProofStatus.UNKNOWN, reason=problem) for ob_id in sorted(required_ids)
        )
        return _report(contract, problem, verdicts, tuple(sorted(unexpected)), executions)
    base: dict[ObligationId, _BaseVerdict] = {}
    deps: dict[ObligationId, tuple[ObligationId, ...]] = {}
    for obligation in required:
        rows = evidence_index.get(obligation.id, [])
        base[obligation.id] = _base_verdict(contract, rows)
        declared = set(obligation.dependencies)
        if len(rows) == 1 and rows[0].contract == contract:
            declared.update(rows[0].dependencies)
        deps[obligation.id] = tuple(sorted(declared))
    resolved = _resolve_dependencies(set(required_ids), base, deps)
    verdicts = tuple(
        ObligationVerdict(
            id=ob_id,
            status=resolved[ob_id][0],
            reason=resolved[ob_id][1],
            detail=base[ob_id].detail,
            method=base[ob_id].method,
            counters=base[ob_id].counters,
            dependencies=deps[ob_id],
            assumptions=evidence_index[ob_id][0].assumptions if len(evidence_index.get(ob_id, ())) == 1 else (),
            evidence_contract_key=evidence_index[ob_id][0].contract.key() if len(evidence_index.get(ob_id, ())) == 1 else "",
            attempted=bool(evidence_index.get(ob_id)),
        )
        for ob_id in sorted(required_ids)
    )
    return ObligationReport(
        contract=contract,
        status=_aggregate_status(verdicts),
        verdicts=verdicts,
        counters=_sum_counters(verdict.counters for verdict in verdicts),
        executions=tuple(executions),
    )


def _report(
    contract: ContractIdentity,
    problem: ProofReason,
    verdicts: tuple[ObligationVerdict, ...],
    unexpected: tuple[ObligationId, ...],
    executions: Sequence[ExecutionEvidence],
) -> ObligationReport:
    """Build a refused report for a report-level integrity problem."""
    return ObligationReport(
        contract=contract,
        status=ProofStatus.UNKNOWN,
        verdicts=verdicts,
        counters=_sum_counters(verdict.counters for verdict in verdicts),
        problem=problem,
        unexpected_evidence=unexpected,
        executions=tuple(executions),
    )


def _sum_counters(counters: Iterable[FactCounters]) -> FactCounters:
    """Aggregate closed fact counters across all evaluated verdicts."""
    totals = FactCounters()
    for item in counters:
        totals = FactCounters(
            raw_fact_count=totals.raw_fact_count + item.raw_fact_count,
            normalized_fact_count=totals.normalized_fact_count + item.normalized_fact_count,
            classified_fact_count=totals.classified_fact_count + item.classified_fact_count,
            materialized_count=totals.materialized_count + item.materialized_count,
            failure_count=totals.failure_count + item.failure_count,
        )
    return totals


def _base_verdict(contract: ContractIdentity, rows: list[ObligationEvidence]) -> _BaseVerdict:
    """Evaluate one obligation's own evidence before dependency constraints."""
    if not rows:
        return _BaseVerdict(ProofStatus.UNKNOWN, ProofReason.MISSING_EVIDENCE, "", "", FactCounters())
    if len(rows) != 1:
        return _BaseVerdict(ProofStatus.UNKNOWN, ProofReason.DUPLICATE_EVIDENCE, "", "", FactCounters())
    ev = rows[0]
    if ev.contract != contract:
        return _BaseVerdict(ProofStatus.UNKNOWN, ProofReason.CONTRACT_MISMATCH, ev.reason, ev.method, ev.counters)
    if not ev.counters.closed():
        return _BaseVerdict(ProofStatus.UNKNOWN, ProofReason.UNMATERIALIZED_FACTS, ev.reason, ev.method, ev.counters)
    if ev.status is ProofStatus.PROVED and ev.counters.failure_count:
        return _BaseVerdict(ProofStatus.UNKNOWN, ProofReason.FAILED_FACTS, ev.reason, ev.method, ev.counters)
    if ev.status in _PROVABLE:
        if ev.assumptions:
            return _BaseVerdict(
                ProofStatus.CONDITIONAL, ProofReason.UNPROVED_ASSUMPTIONS, ev.reason, ev.method, ev.counters
            )
        reason = ProofReason.DISCHARGED if ev.status is ProofStatus.PROVED else ProofReason.BACKEND_VERDICT
        return _BaseVerdict(ev.status, reason, ev.reason, ev.method, ev.counters)
    return _BaseVerdict(ev.status, ProofReason.BACKEND_VERDICT, ev.reason, ev.method, ev.counters)


def _dependency_limit(
    ob_id: ObligationId,
    required: set[ObligationId],
    status: Mapping[ObligationId, ProofStatus],
    deps: Mapping[ObligationId, tuple[ObligationId, ...]],
) -> tuple[ProofStatus, ProofReason]:
    """Return the strictest status an obligation's dependencies permit."""
    limit = (ProofStatus.PROVED, ProofReason.DISCHARGED)
    for dep in deps[ob_id]:
        if dep not in required:
            return ProofStatus.UNKNOWN, ProofReason.DEPENDENCY_MISSING
        dep_status = status[dep]
        if dep_status is ProofStatus.PROVED:
            continue
        if dep_status is ProofStatus.CONDITIONAL:
            limit = (ProofStatus.CONDITIONAL, ProofReason.DEPENDENCY_CONDITIONAL)
            continue
        return ProofStatus.UNKNOWN, ProofReason.DEPENDENCY_UNPROVED
    return limit


def _cyclic_obligations(
    required: set[ObligationId],
    deps: Mapping[ObligationId, tuple[ObligationId, ...]],
) -> set[ObligationId]:
    """Find obligations that transitively depend on themselves; cycles cannot bootstrap."""
    reachable = {ob: {dep for dep in deps[ob] if dep in required} for ob in required}
    changed = True
    while changed:
        changed = False
        for ob in sorted(required):
            expanded = set(reachable[ob])
            for dep in reachable[ob]:
                expanded.update(reachable[dep])
            if expanded != reachable[ob]:
                reachable[ob] = expanded
                changed = True
    return {ob for ob in required if ob in reachable[ob]}


def _resolve_dependencies(
    required: set[ObligationId],
    base: Mapping[ObligationId, _BaseVerdict],
    deps: Mapping[ObligationId, tuple[ObligationId, ...]],
) -> dict[ObligationId, tuple[ProofStatus, ProofReason]]:
    """Apply dependency caps until verdicts settle; verdicts only move downward."""
    status = {ob: base[ob].status for ob in required}
    reason = {ob: base[ob].reason for ob in required}
    for ob in _cyclic_obligations(required, deps):
        if status[ob] in _PROVABLE:
            status[ob], reason[ob] = ProofStatus.UNKNOWN, ProofReason.DEPENDENCY_CYCLE
    changed = True
    while changed:
        changed = False
        for ob in sorted(required):
            if status[ob] not in _PROVABLE:
                continue
            limit = _dependency_limit(ob, required, status, deps)
            if _STATUS_RANK[limit[0]] > _STATUS_RANK[status[ob]]:
                status[ob], reason[ob] = limit
                changed = True
    return {ob: (status[ob], reason[ob]) for ob in required}


def _aggregate_status(verdicts: tuple[ObligationVerdict, ...]) -> ProofStatus:
    """Aggregate conservatively: any counterexample dominates; mixed gaps are UNKNOWN."""
    statuses = {verdict.status for verdict in verdicts}
    if ProofStatus.COUNTEREXAMPLE in statuses:
        return ProofStatus.COUNTEREXAMPLE
    if statuses == {ProofStatus.PROVED}:
        return ProofStatus.PROVED
    if statuses <= {ProofStatus.PROVED, ProofStatus.CONDITIONAL}:
        return ProofStatus.CONDITIONAL
    if statuses == {ProofStatus.UNSUPPORTED}:
        return ProofStatus.UNSUPPORTED
    if statuses == {ProofStatus.UNMAPPED}:
        return ProofStatus.UNMAPPED
    return ProofStatus.UNKNOWN

