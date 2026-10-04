"""Deterministic effort ordering for untrusted memory invariant proposals.

Layer: dosunit relational proposal scheduling.
Responsibility: prioritize complete byte groups at changed coordinates without
granting truth, excluding states or dropping candidates. Both architectures
consume this ordering; only their complete proof obligations admit invariants.
"""
from __future__ import annotations

from tools.dosunit.memory_invariant_proposals import MemoryInvariantProposal
from tools.dosunit.memory_state_relations import MemoryPermutation
from tools.dosunit.model import canonical_json_bytes


def _priority(proposal: MemoryInvariantProposal, changed: set[bytes]) -> tuple[int, int, int]:
    """Rank a complete moved-byte group before partial or unrelated facts."""
    if proposal.invariant is None:
        return (1, 0, 0)
    facts = proposal.invariant.facts
    overlap = sum(canonical_json_bytes(fact.address) in changed for fact in facts)
    return (-int(overlap == len(facts)), -overlap, len(facts))


def prioritize_invariants(
    proposals: tuple[MemoryInvariantProposal, ...], memory: MemoryPermutation,
) -> tuple[MemoryInvariantProposal, ...]:
    """Return every proposal once, with deterministic stable ordering of ties."""
    changed = {canonical_json_bytes(address) for swap in memory.swaps for address in (swap.left, swap.right)}
    return tuple(sorted(proposals, key=lambda proposal: _priority(proposal, changed)))
