"""Bounded real16 memory correspondence and invariant proposal scheduling.

Layer: dosunit relational proof orchestration.
Responsibility: retain every attempted coordinate/fixed-point relation and stop
only on a fully discharged attempt. Synthesis ordering influences effort alone;
the complete transition consumer owns acceptance and the shared deadline.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from tools.dosunit.compare.memory_invariant_priority import prioritize_invariants
from tools.dosunit.compare.memory_invariant_proposals import (
    MemoryInvariantProposalReason,
    propose_entry_invariants,
)
from tools.dosunit.compare.memory_relation_proposals import MemoryProposalReason, propose_entry_memory_relations
from tools.dosunit.contracts.cutpoint_state_relations import CutpointStateRelation
from tools.dosunit.contracts.memory_state_invariants import MemoryInvariant
from tools.dosunit.contracts.proof_contracts import ProofStatus
from tools.dosunit.contracts.register_state_relations import MachineState

if TYPE_CHECKING:
    from tools.dosunit.compare.real16_region_proof import RegionRelationAttempt

type CompareMemoryAttempt = Callable[[CutpointStateRelation, MemoryInvariant | None], RegionRelationAttempt]


@dataclass(frozen=True, slots=True)
class MemoryRetryResult:
    """Retain synthesis outcomes independently of the selected proof attempt."""

    memory_reason: MemoryProposalReason | None
    invariant_reason: MemoryInvariantProposalReason | None


def try_entry_memory_relations(
    original: MachineState, rebuilt: MachineState,
    attempts: list[RegionRelationAttempt], compare: CompareMemoryAttempt,
) -> MemoryRetryResult:
    """Discharge memory coordinates and saved-byte invariants through one owner."""
    memory_reason = None
    invariant_reason = None
    invariants = propose_entry_invariants(original)
    candidates: list[tuple[CutpointStateRelation, int]] = []
    for proposed in propose_entry_memory_relations(original, rebuilt):
        memory_reason = proposed.reason
        if proposed.relation is None or proposed.relation.is_identity:
            continue
        relation = CutpointStateRelation(proposed.relation)
        attempt = compare(relation, None)
        attempts.append(attempt)
        if attempt.status is ProofStatus.PROVED:
            return MemoryRetryResult(memory_reason, invariant_reason)
        candidates.append((relation, sum(row.status is ProofStatus.PROVED for row in attempt.transitions)))
    # Existing discharged transitions rank proposals without granting facts.
    # Check every pure coordinate relation before spending invariant budgets.
    for relation, _ in sorted(candidates, key=lambda candidate: -candidate[1]):
        for invariant in prioritize_invariants(invariants, relation.memory):
            invariant_reason = invariant.reason
            if invariant.invariant is None:
                continue
            attempt = compare(relation, invariant.invariant)
            attempts.append(attempt)
            if attempt.status is ProofStatus.PROVED:
                return MemoryRetryResult(memory_reason, invariant_reason)
    return MemoryRetryResult(memory_reason, invariant_reason)
