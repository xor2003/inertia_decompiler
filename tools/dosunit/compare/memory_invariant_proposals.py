"""Finite entry-store proposals for saved-byte/live-scalar invariants.

Layer: dosunit relational invariant synthesis.
Responsibility: rebase exact typed entry-store effects into invertible post-entry
scalar coordinates. Every proposal needs independent entry, preservation and
final observation proofs; neither matching syntax nor synthesis grants a fact.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any, Final

from tools.dosunit.compare.memory_relation_proposals import (
    MemorySynthesisRefusal,
    _anchor,
    _inverse_inputs,
    _store_bytes,
)
from tools.dosunit.contracts.memory_state_invariants import (
    MemoryByteFact,
    MemoryInvariant,
    MemoryInvariantRefusal,
    _template_bindings,
)
from tools.dosunit.contracts.model import canonical_json_bytes
from tools.dosunit.contracts.register_affine_relations import _linear_effect
from tools.dosunit.contracts.register_state_relations import MachineState, RegisterRelationRefusal

MAX_ENTRY_STORES: Final[int] = 64
MAX_PROPOSALS: Final[int] = 64
MAX_PROPOSED_BYTES: Final[int] = 64


class MemoryInvariantProposalReason(StrEnum):
    """Typed synthesis results, independent of induction proof status."""

    PROPOSED = "entry_scalar_byte_invariant_proposed"
    STORES = "memory_invariant_entry_store_chain_missing"
    UNBOUND = "memory_invariant_cutpoint_inverse_missing"
    SCALAR = "memory_invariant_scalar_template_unproved"
    LIMIT = "memory_invariant_synthesis_limit"


class InvariantSynthesisRefusal(Exception):
    """Retain an explicit bounded invariant-synthesis non-result."""

    def __init__(self, reason: MemoryInvariantProposalReason) -> None:
        """Publish the typed missing synthesis obligation."""
        self.reason = reason
        super().__init__(reason.value)


@dataclass(frozen=True, slots=True)
class MemoryInvariantProposal:
    """A bounded untrusted fixed-point proposal or an explicit non-result."""

    reason: MemoryInvariantProposalReason
    invariant: MemoryInvariant | None


def _entry_stores(state: MachineState) -> tuple[tuple[str, dict[str, Any], dict[str, Any]], ...] | None:
    """Read oldest-to-newest stores without interpreting rendered code or labels."""
    memory = state.get("memory")
    stores: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
    for _ in range(MAX_ENTRY_STORES + 1):
        if memory is None:
            return None
        op = memory.get("op")
        if op == "mem_input":
            return tuple(reversed(stores))
        args = memory.get("args")
        if op not in {"storele", "storebe"} or not isinstance(args, list) or len(args) != 3:
            return None
        if not all(isinstance(arg, dict) for arg in args):
            return None
        stores.append((op, args[1], args[2]))
        memory = args[0]
    raise InvariantSynthesisRefusal(MemoryInvariantProposalReason.LIMIT)


def _anchors(state: MachineState) -> tuple[str | None, ...]:
    """Enumerate binary-derived invertible cross-register anchors deterministically."""
    names: list[str | None] = [None]
    for name, term in sorted(state.items()):
        width = term.get("width")
        if type(width) is not int:
            continue
        effect = _linear_effect(term, width)
        base = effect.base
        if base is not None and base.get("op") == "input" and base.get("name") != name and effect.multiplier % 2:
            names.append(name)
    return tuple(names)


def _store_fact_group(
    store: tuple[str, dict[str, Any], dict[str, Any]], inverse: MachineState,
) -> MemoryInvariant | None:
    """Rebase every byte of one exact store, refusing incomplete inverse bindings."""
    facts: list[MemoryByteFact] = []
    for address, value in _store_bytes(*store):
        anchored_address, anchored_value = _anchor(address, inverse), _anchor(value, inverse)
        if anchored_address is None or anchored_value is None:
            return None
        facts.append(MemoryByteFact(anchored_address, anchored_value))
    return MemoryInvariant(tuple(facts))


def _append_unique(
    proposals: list[MemoryInvariantProposal], seen: set[bytes], invariant: MemoryInvariant,
) -> bool:
    """Keep finite deterministic proposals and expose saturation to the caller."""
    key = canonical_json_bytes(asdict(invariant))
    if key in seen:
        return True
    if len(proposals) >= MAX_PROPOSALS:
        return False
    seen.add(key)
    proposals.append(MemoryInvariantProposal(MemoryInvariantProposalReason.PROPOSED, invariant))
    return True


def _anchor_proposals(
    stores: tuple[tuple[str, dict[str, Any], dict[str, Any]], ...], inverse: MachineState,
    proposals: list[MemoryInvariantProposal], seen: set[bytes],
) -> MemoryInvariantProposalReason:
    """Propose individual typed store groups plus their ordered combined image."""
    combined: list[MemoryByteFact] = []
    scalar_groups: dict[tuple[tuple[str, int], ...], list[MemoryByteFact]] = {}
    reason = MemoryInvariantProposalReason.UNBOUND
    for store in stores:
        try:
            invariant = _store_fact_group(store, inverse)
        except (MemoryInvariantRefusal, MemorySynthesisRefusal, RegisterRelationRefusal):
            reason = MemoryInvariantProposalReason.SCALAR
            continue
        if invariant is None:
            continue
        if not _append_unique(proposals, seen, invariant):
            return MemoryInvariantProposalReason.LIMIT
        combined.extend(invariant.facts)
        for fact in invariant.facts:
            sources = tuple(sorted(_template_bindings(fact.value, 8).items()))
            scalar_groups.setdefault(sources, []).append(fact)
        if len(combined) > MAX_PROPOSED_BYTES:
            return MemoryInvariantProposalReason.LIMIT
    # Frontends may lower one register store into individual byte stores.
    # Group their common scalar sources without assuming the facts are true.
    for facts in scalar_groups.values():
        if not _append_unique(proposals, seen, MemoryInvariant(tuple(facts))):
            return MemoryInvariantProposalReason.LIMIT
    if combined and not _append_unique(proposals, seen, MemoryInvariant(tuple(combined))):
        return MemoryInvariantProposalReason.LIMIT
    return reason


def propose_entry_invariants(state: MachineState) -> tuple[MemoryInvariantProposal, ...]:
    """Derive bounded invariant candidates solely from typed binary entry effects.

    Individual stores avoid requiring every saved value to remain live forever.
    The combined projection preserves ordered alias semantics. Unmatched or
    memory-dependent stores do not become facts; the consumer must prove every
    retained candidate's reachable-state initiation and continuation closure.
    """
    proposals: list[MemoryInvariantProposal] = []
    seen: set[bytes] = set()
    try:
        stores = _entry_stores(state)
        if not stores:
            return (MemoryInvariantProposal(MemoryInvariantProposalReason.STORES, None),)
        reason = MemoryInvariantProposalReason.UNBOUND
        for anchor in _anchors(state):
            reason = _anchor_proposals(stores, _inverse_inputs(state, anchor), proposals, seen)
            if reason is MemoryInvariantProposalReason.LIMIT:
                break
    except (MemorySynthesisRefusal, RegisterRelationRefusal, InvariantSynthesisRefusal):
        return (MemoryInvariantProposal(MemoryInvariantProposalReason.LIMIT, None),)
    if not proposals or reason is MemoryInvariantProposalReason.LIMIT:
        proposals.append(MemoryInvariantProposal(reason, None))
    return tuple(proposals)
