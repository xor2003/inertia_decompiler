"""Typed flat32 cutpoint-attempt evidence with complete refusal accounting.

Layer: dosunit relational proof reporting.
Responsibility: retain each untrusted state relation, solver rows and fact
counts without promoting cutpoint countermodels to whole-function inequality.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from tools.dosunit.compare.memory_invariant_obligations import MemoryInvariantProof
from tools.dosunit.contracts.cutpoint_state_relations import CutpointRelation
from tools.dosunit.contracts.memory_state_invariants import MemoryInvariant
from tools.dosunit.contracts.proof_contracts import FactCounters, ProofStatus, proof_status_from_legacy


@dataclass(frozen=True, slots=True)
class Flat32RelationAttempt:
    """One checked proposal with raw solver rows and complete fact accounting."""

    relation: CutpointRelation
    status: ProofStatus
    block_compare: dict[str, Any]
    block_verdicts: tuple[dict[str, Any], ...]
    counters: FactCounters
    invariant: MemoryInvariant | None = None
    invariant_proofs: tuple[MemoryInvariantProof, ...] = ()


def attempt_record(
    relation: CutpointRelation, status: object, compared: dict[str, Any],
    rows: list[dict[str, Any]], count: int,
    invariant: MemoryInvariant | None = None,
    invariant_proofs: tuple[MemoryInvariantProof, ...] = (),
) -> dict[str, Any]:
    """Serialize one admitted attempt without dropping its failed countermodels."""
    admitted = proof_status_from_legacy(status) or ProofStatus.UNKNOWN
    failures = sum(proof_status_from_legacy(row.get("status")) is not ProofStatus.PROVED for row in rows)
    failures += sum(proof.status is not ProofStatus.PROVED for proof in invariant_proofs)
    count += len(invariant_proofs)
    counters = FactCounters(count, count, count, count, max(int(admitted is not ProofStatus.PROVED), failures))
    return asdict(Flat32RelationAttempt(relation, admitted, compared, tuple(rows), counters,
                                        invariant, invariant_proofs))
