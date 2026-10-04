"""Bounded automatic flat32 invariant discovery with retained failed attempts.

Layer: dosunit flat32 relational proof orchestration.
Responsibility: derive candidates from binary entry SSA and send each through
the complete comparison path. Explicit candidates stop further discovery, so
there is at most one retry level; every retry uses the same total deadline.
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

from tools.dosunit.memory_invariant_priority import prioritize_invariants
from tools.dosunit.memory_invariant_proposals import propose_entry_invariants
from tools.dosunit.memory_state_invariants import MemoryInvariant
from tools.dosunit.memory_state_relations import MemoryPermutation
from tools.dosunit.proof_contracts import ProofStatus, proof_status_from_legacy
from tools.dosunit.register_state_relations import MachineState

type CompareInvariant = Callable[[MemoryInvariant, int], dict[str, Any]]


class InvariantSearchReason(StrEnum):
    """Typed completion or refusal reason for bounded candidate discovery."""

    PROVED = "memory_invariant_search_proved"
    EXHAUSTED = "memory_invariant_candidates_unproved"
    DEADLINE = "memory_invariant_search_deadline_exceeded"


@dataclass(frozen=True, slots=True)
class InvariantSearchRecord:
    """Discovery effort and completeness, independent of individual proof facts."""

    reason: InvariantSearchReason
    proposed_count: int
    attempted_count: int
    complete: bool


def retry_entry_invariants(
    initial: dict[str, Any], original: MachineState | None, memory: MemoryPermutation,
    *, explicit: MemoryInvariant | None, deadline: float, compare: CompareInvariant,
) -> dict[str, Any]:
    """Retain every completed attempt and select only a fully proved retry.

    Result dictionaries cross the legacy artifact-driver/report boundary; its
    statuses are normalized through the shared typed parser. Internal proposal
    and invariant contracts use their explicit owned fields. No timeout or
    failed initialization can become a pass by applying a projection alone.
    """
    if explicit is not None or original is None:
        return initial
    if proof_status_from_legacy(initial["status"]) is ProofStatus.PROVED:
        return initial
    attempts = list(initial["relation_attempts"])
    selected = initial
    proposals = prioritize_invariants(propose_entry_invariants(original), memory)
    proposed_count = sum(proposal.invariant is not None for proposal in proposals)
    attempted_count = 0
    for proposal in proposals:
        if proposal.invariant is None:
            continue
        remaining = int((deadline - time.monotonic()) * 1000)
        if remaining <= 0:
            selected["invariant_search"] = asdict(InvariantSearchRecord(
                InvariantSearchReason.DEADLINE, proposed_count, attempted_count, False,
            ))
            selected["relation_attempts"] = list(attempts)
            return selected
        result = compare(proposal.invariant, remaining)
        attempted_count += 1
        attempts.extend(result.get("relation_attempts", []))
        result["relation_attempts"] = list(attempts)
        result["invariant_proposal_reason"] = proposal.reason
        selected = result
        if proof_status_from_legacy(result["status"]) is ProofStatus.PROVED:
            result["invariant_search"] = asdict(InvariantSearchRecord(
                InvariantSearchReason.PROVED, proposed_count, attempted_count, True,
            ))
            return result
    selected["invariant_search"] = asdict(InvariantSearchRecord(
        InvariantSearchReason.EXHAUSTED, proposed_count, attempted_count, True,
    ))
    return selected
