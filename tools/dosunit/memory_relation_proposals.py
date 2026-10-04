"""Binary entry-store proposals for invertible cutpoint memory relations.

Layer: dosunit relational state synthesis.
Responsibility: derive finite byte permutations from typed entry SSA effects.
Matching selects a proposal only; complete initiation, preservation and exit
proofs remain mandatory. No stack bytes or alias cases are excluded.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

from tools.dosunit.memory_state_relations import MemoryByteSwap, MemoryPermutation
from tools.dosunit.model import canonical_json_bytes
from tools.dosunit.real16_call_contracts import substitute_state_term
from tools.dosunit.register_affine_relations import _linear_effect
from tools.dosunit.register_state_relations import MachineState, RegisterRelationRefusal

MAX_STORES: int = 64
MAX_DEPTH: int = 64
MAX_BYTE_FACTS: int = 64
MAX_STORE_WIDTH: int = 64


class MemoryProposalReason(StrEnum):
    """Exact synthesis result retained independently of solver acceptance."""

    PROPOSED = 'entry_byte_permutation_proposed'
    STORES = 'entry_memory_store_chain_missing'
    AMBIGUOUS = 'entry_memory_value_correspondence_ambiguous'
    DOMAIN = 'entry_memory_address_domains_differ'
    ANCHOR = 'entry_memory_anchor_not_invertible'
    LIMIT = 'memory_relation_synthesis_limit'
    WIDTH = 'entry_memory_term_width_unsupported'


class MemorySynthesisRefusal(Exception):
    """Retain one typed unsupported synthesis boundary."""

    def __init__(self, reason: MemoryProposalReason) -> None:
        """Publish the specific bounded synthesis obligation."""
        self.reason = reason
        super().__init__(reason.value)


@dataclass(frozen=True, slots=True)
class MemoryProposal:
    """One untrusted finite byte relation or explicit synthesis non-result."""

    reason: MemoryProposalReason
    relation: MemoryPermutation | None


def _constant(value: int, width: int) -> dict[str, Any]:
    """Construct an exact modular bitvector literal."""
    return {'op': 'const', 'width': width, 'value': hex(value % (1 << width))}


def _canonical(term: dict[str, Any], depth: int = 0) -> dict[str, Any]:
    """Normalize linear proposal syntax without changing expression semantics."""
    if depth >= MAX_DEPTH:
        raise MemorySynthesisRefusal(MemoryProposalReason.LIMIT)
    normalized = dict(term)
    args = term.get('args')
    if isinstance(args, list):
        normalized['args'] = [_canonical(arg, depth + 1) for arg in args]
    width = normalized.get('width')
    if type(width) is not int:
        return normalized
    effect = _linear_effect(normalized, width)
    if effect.base is None:
        return _constant(effect.offset, width)
    if canonical_json_bytes(effect.base) == canonical_json_bytes(normalized):
        return normalized
    base: dict[str, Any] = effect.base
    if effect.multiplier != 1:
        base = {'op': 'mul', 'width': width, 'args': [base, _constant(effect.multiplier, width)]}
    if effect.offset:
        base = {'op': 'add', 'width': width, 'args': [base, _constant(effect.offset, width)]}
    return base


def _store_bytes(
    operation: str, address: dict[str, Any], value: dict[str, Any],
) -> tuple[tuple[dict[str, Any], dict[str, Any]], ...]:
    """Project one typed wide SSA store into its exact ordered byte effects."""
    width = value.get('width')
    if type(width) is not int or width <= 0 or width > MAX_STORE_WIDTH or width % 8:
        raise MemorySynthesisRefusal(MemoryProposalReason.WIDTH)
    count = width // 8
    projected = []
    for index in range(count):
        location = address if index == 0 else {'op': 'add', 'width': 32,
                                               'args': [address, _constant(index, 32)]}
        shift = index * 8 if operation == 'storele' else (count - index - 1) * 8
        byte = value
        if shift:
            byte = {'op': 'lshr', 'width': width, 'args': [value, _constant(shift, 8)]}
        if width != 8:
            byte = {'op': 'trunc', 'width': 8, 'args': [byte]}
        projected.append((_canonical(location), _canonical(byte)))
    return tuple(projected)


def _stores(state: MachineState) -> dict[bytes, tuple[dict[str, Any], bytes]] | None:
    """Retain last byte stores at structurally normalized complete addresses."""
    memory = state.get('memory')
    if memory is None:
        return None
    result: dict[bytes, tuple[dict[str, Any], bytes]] = {}
    for index in range(MAX_STORES + 1):
        if memory.get('op') == 'mem_input':
            return result
        if index == MAX_STORES:
            raise MemorySynthesisRefusal(MemoryProposalReason.LIMIT)
        args = memory.get('args')
        if memory.get('op') not in {'storele', 'storebe'} or not isinstance(args, list) or len(args) != 3:
            return None
        if not all(isinstance(arg, dict) for arg in args):
            return None
        for address, byte in _store_bytes(memory['op'], args[1], args[2]):
            result.setdefault(canonical_json_bytes(address), (address, canonical_json_bytes(byte)))
        if len(result) > MAX_BYTE_FACTS:
            raise MemorySynthesisRefusal(MemoryProposalReason.LIMIT)
        memory = args[0]
    return None


def _inverse_inputs(state: MachineState, anchor_register: str | None) -> MachineState:
    """Express entry scalar inputs in unchanged or invertible post-entry registers."""
    inverse: MachineState = {}
    names = sorted(state)
    if anchor_register is not None and anchor_register in names:
        names.remove(anchor_register)
        names.append(anchor_register)
    for name in names:
        term = state[name]
        width = term.get('width')
        if type(width) is not int:
            continue
        effect = _linear_effect(term, width)
        base = effect.base
        if base is None or base.get('op') != 'input' or effect.multiplier % 2 != 1:
            continue
        original_name = base.get('name')
        if not isinstance(original_name, str) or (original_name != name and name != anchor_register):
            continue
        multiplier = pow(effect.multiplier, -1, 1 << width)
        value: dict[str, Any] = {'op': 'input', 'name': name, 'width': width}
        if effect.offset:
            value = {'op': 'sub', 'width': width, 'args': [value, _constant(effect.offset, width)]}
        if multiplier != 1:
            value = {'op': 'mul', 'width': width, 'args': [value, _constant(multiplier, width)]}
        inverse[original_name] = value
    return inverse


def _anchor(address: dict[str, Any], inverse: MachineState) -> dict[str, Any] | None:
    """Refuse an address whose entry inputs lack a cutpoint inverse."""
    pending = [address]
    while pending:
        node = pending.pop()
        if node.get('op') == 'input' and node.get('name') not in inverse:
            return None
        args = node.get('args')
        if isinstance(args, list):
            pending.extend(args)
    return _canonical(substitute_state_term(address, inverse))


def _cycle_swaps(
    mapping: dict[bytes, bytes], anchors: dict[bytes, dict[str, Any] | None],
) -> tuple[MemoryByteSwap, ...]:
    """Factor a finite bijection into elementary address transpositions."""
    swaps: list[MemoryByteSwap] = []
    unseen = set(mapping)
    while unseen:
        first = min(unseen)
        unseen.remove(first)
        current = mapping[first]
        while current != first:
            unseen.remove(current)
            a, b = anchors[first], anchors[current]
            assert a is not None and b is not None
            # Reverse cycle swaps implement candidate[k] = oracle[map[k]].
            swaps.insert(0, MemoryByteSwap(a, b))
            current = mapping[current]
    return tuple(swaps)


def propose_memory_permutation(
    oracle: MachineState, candidate: MachineState, *, anchor_register: str | None = None,
) -> MemoryProposal:
    """Match changed entry-store values and derive an untrusted byte permutation.

    Cancel structurally unchanged stores before value matching. Duplicate moved
    values, unequal address domains and noninvertible anchors refuse synthesis.
    Full-array proofs must still reject aliases, unmodeled writes or bad exits.
    """
    try:
        left, right = _stores(oracle), _stores(candidate)
        if left is None or right is None:
            return MemoryProposal(MemoryProposalReason.STORES, None)
        if left.keys() != right.keys():
            return MemoryProposal(MemoryProposalReason.DOMAIN, None)
        changed = {key for key in left if left[key][1] != right[key][1]}
        mapping: dict[bytes, bytes] = {}
        for key in sorted(changed):
            matches = [other for other in changed if left[other][1] == right[key][1]]
            if len(matches) != 1:
                return MemoryProposal(MemoryProposalReason.AMBIGUOUS, None)
            mapping[key] = matches[0]
        if set(mapping.values()) != changed:
            return MemoryProposal(MemoryProposalReason.AMBIGUOUS, None)
        inverse = _inverse_inputs(oracle, anchor_register)
        anchors = {key: _anchor(left[key][0], inverse) for key in changed}
        if any(value is None for value in anchors.values()):
            return MemoryProposal(MemoryProposalReason.ANCHOR, None)
        return MemoryProposal(MemoryProposalReason.PROPOSED, MemoryPermutation(_cycle_swaps(mapping, anchors)))
    except MemorySynthesisRefusal as error:
        return MemoryProposal(error.reason, None)
    except RegisterRelationRefusal:
        return MemoryProposal(MemoryProposalReason.LIMIT, None)


def propose_entry_memory_relations(oracle: MachineState, candidate: MachineState) -> tuple[MemoryProposal, ...]:
    """Retain finite proposals using every invertible cross-register entry anchor.

    A stack/frame anchor is chosen from SSA effects rather than register names.
    Different inverse coordinates may work at different cutpoints; the complete
    transition proof selects a relation, never synthesis ordering alone.
    """
    proposals = [propose_memory_permutation(oracle, candidate)]
    seen = {canonical_json_bytes(asdict(proposals[0]))}
    for name, term in sorted(oracle.items()):
        width = term.get('width')
        if type(width) is not int:
            continue
        effect = _linear_effect(term, width)
        base = effect.base
        if base is None or base.get('op') != 'input' or base.get('name') == name:
            continue
        proposed = propose_memory_permutation(oracle, candidate, anchor_register=name)
        key = canonical_json_bytes(asdict(proposed))
        if key not in seen:
            seen.add(key)
            proposals.append(proposed)
    return tuple(proposals)
