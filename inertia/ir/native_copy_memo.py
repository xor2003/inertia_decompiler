"""Seed a deepcopy memo with detached typed IR nodes for native surface copies.

Layer: IR.
Responsibility: prebuild detached clones of every exact owned IR node
reachable from a native surface's blocks so a native-surface deepcopy
resolves them through a seeded memo instead of paying generic frozen
dataclass reconstruction. Foreign, subclassed, and malformed payloads
stay absent from seeding so ordinary deepcopy rebuilds them through the
same memo, preserving cross-field DAG sharing.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from typing import cast

from .call_stack_coordinates import IRCallStackCoordinates8616
from .core import (
    AddressStatus,
    IRActiveUnary8616,
    IRAddress,
    IRBinaryValue,
    IRBlock,
    IRCallOutputProvenance8616,
    IRCallOutputShape8616,
    IRCallStackEffect8616,
    IRCondition,
    IRInstr,
    IRRefusal,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from .dead_temporary_normalization import DeadTemporaryDecision8616, DeadTemporaryDecisionKind8616
from .instruction_origin import IRInstructionOrigin8616

__all__ = ["native_copy_memo_producers_8616", "seed_native_copy_memo_8616", "seed_native_decisions_8616"]

_EXACT_INT_TYPES_8616: tuple[type, ...] = (int, bool)

# Exact immutable scalars generic deepcopy also returns unchanged; sharing
# them between source and clone cannot leak mutation either direction.
_SHARED_SCALAR_TYPES_8616: frozenset[type] = frozenset({
    type(None), bool, int, float, complex, bytes, str,
    MemSpace, AddressStatus, SegmentOrigin, IRCallOutputShape8616,
})

_MISSING_8616: object = object()


def seed_native_decisions_8616(
    decisions: tuple[DeadTemporaryDecision8616, ...], memo: dict[int, object],
) -> None:
    """Detach exact scalar decisions in the shared surface-copy memo.

    Foreign records and malformed payloads retain ordinary deepcopy. Existing
    entries must survive so repeated decisions and cross-field aliases keep
    one detached identity, including nodes already reached through IR fields.
    """
    if type(decisions) is not tuple:
        return
    for decision in decisions:
        if (type(decision) is DeadTemporaryDecision8616
                and type(decision.instruction_index) is int
                and type(decision.kind) is DeadTemporaryDecisionKind8616
                and id(decision) not in memo):
            memo[id(decision)] = DeadTemporaryDecision8616(decision.instruction_index, decision.kind)


def seed_native_copy_memo_8616(blocks: tuple[IRBlock, ...]) -> dict[int, object]:
    """Prebuild detached clones of every owned node reachable from ``blocks``.

    The returned mapping is a ready ``copy.deepcopy`` memo: copying a native
    surface with it resolves each seeded node to its already-detached clone
    instead of paying generic frozen-dataclass reconstruction, while the
    same memo keeps cross-field DAG sharing identical to an unseeded
    deepcopy. Each typed clone is registered before its fields are filled,
    so cyclic payloads terminate and resolve to the in-progress clone —
    exactly what generic deepcopy's memo produces. Foreign block entries
    are ignored; subclasses and malformed payloads encountered below a
    valid node fall back to ``deepcopy`` against this memo, so they retain
    ordinary reconstruction and sharing semantics.
    """
    memo: dict[int, object] = {}
    if type(blocks) is not tuple:
        return memo
    for block in blocks:
        if type(block) is IRBlock:
            _detach_native_node_8616(block, memo)
    return memo


def _detach_native_field_8616(value: object, memo: dict[int, object]) -> object:
    """Detach one field payload, sharing only exact immutable scalars."""
    value_type = type(value)
    if value_type in _SHARED_SCALAR_TYPES_8616:
        return value
    if value_type is tuple:
        return _detach_native_tuple_8616(cast(tuple[object, ...], value), memo)
    return _detach_native_node_8616(value, memo)


def _detach_native_tuple_8616(
    items: tuple[object, ...], memo: dict[int, object],
) -> tuple[object, ...]:
    """Preserve tuple aliases, including tuples completed by recursive copying."""
    identity = id(items)
    existing = memo.get(identity, _MISSING_8616)
    if existing is not _MISSING_8616:
        return cast(tuple[object, ...], existing)
    detached = [_detach_native_field_8616(item, memo) for item in items]
    # A mutable child may recursively copy this tuple before returning.
    # Reuse that completed tuple so the child's back-reference stays exact.
    existing = memo.get(identity, _MISSING_8616)
    if existing is not _MISSING_8616:
        return cast(tuple[object, ...], existing)
    if all(new is old for new, old in zip(detached, items, strict=True)):
        return items
    result = tuple(detached)
    memo[identity] = result
    return result


def _detach_native_node_8616(node: object, memo: dict[int, object]) -> object:
    """Detach one node, dispatching exact owned types to typed clones.

    A memo hit returns the registered clone, which may be an unfilled shell
    mid-cycle; it is completed before the seeding pass returns. Unknown
    types, subclasses and foreign payloads keep ordinary deepcopy
    reconstruction against the same memo.
    """
    existing = memo.get(id(node), _MISSING_8616)
    if existing is not _MISSING_8616:
        return existing
    detacher = _TYPED_NODE_DETACHERS_8616.get(type(node))
    if detacher is None:
        return deepcopy(node, memo)
    return detacher(node, memo)


def _detach_native_value_8616(value: IRValue, memo: dict[int, object]) -> IRValue:
    """Detach one exact ``IRValue``: direct leaf build or shell then fields."""
    if _is_seedable_native_leaf_8616(value):
        clone = _detach_native_leaf_8616(value)
        memo[id(value)] = clone
        return clone
    clone = IRValue.__new__(IRValue)
    memo[id(value)] = clone
    object.__setattr__(clone, "space", _detach_native_field_8616(value.space, memo))
    object.__setattr__(clone, "name", _detach_native_field_8616(value.name, memo))
    object.__setattr__(clone, "offset", _detach_native_field_8616(value.offset, memo))
    object.__setattr__(clone, "const", _detach_native_field_8616(value.const, memo))
    object.__setattr__(clone, "size", _detach_native_field_8616(value.size, memo))
    object.__setattr__(clone, "version", _detach_native_field_8616(value.version, memo))
    object.__setattr__(clone, "expr", _detach_native_field_8616(value.expr, memo))
    object.__setattr__(clone, "index", _detach_native_field_8616(value.index, memo))
    object.__setattr__(clone, "index_shift", _detach_native_field_8616(value.index_shift, memo))
    object.__setattr__(
        clone, "memory_access_size",
        _detach_native_field_8616(value.memory_access_size, memo),
    )
    object.__setattr__(
        clone, "memory_access_insn",
        _detach_native_field_8616(value.memory_access_insn, memo),
    )
    object.__setattr__(
        clone, "source_tmp", _detach_native_field_8616(value.source_tmp, memo),
    )
    object.__setattr__(
        clone, "call_output", _detach_native_field_8616(value.call_output, memo),
    )
    object.__setattr__(
        clone, "active_unary", _detach_native_field_8616(value.active_unary, memo),
    )
    return clone


def _detach_native_instr_8616(instr: IRInstr, memo: dict[int, object]) -> IRInstr:
    """Detach one exact ``IRInstr`` shell-first so cyclic args terminate."""
    clone = IRInstr.__new__(IRInstr)
    memo[id(instr)] = clone
    object.__setattr__(clone, "op", _detach_native_field_8616(instr.op, memo))
    object.__setattr__(clone, "dst", _detach_native_field_8616(instr.dst, memo))
    object.__setattr__(clone, "args", _detach_native_field_8616(instr.args, memo))
    object.__setattr__(clone, "size", _detach_native_field_8616(instr.size, memo))
    object.__setattr__(clone, "addr", _detach_native_field_8616(instr.addr, memo))
    object.__setattr__(
        clone, "call_stack_effect",
        _detach_native_field_8616(instr.call_stack_effect, memo),
    )
    object.__setattr__(
        clone, "origin", _detach_native_field_8616(instr.origin, memo),
    )
    return clone


def _detach_native_address_8616(
    address: IRAddress, memo: dict[int, object],
) -> IRAddress:
    """Detach one exact ``IRAddress`` shell-first for shared base values."""
    clone = IRAddress.__new__(IRAddress)
    memo[id(address)] = clone
    object.__setattr__(clone, "space", _detach_native_field_8616(address.space, memo))
    object.__setattr__(clone, "base", _detach_native_field_8616(address.base, memo))
    object.__setattr__(
        clone, "offset", _detach_native_field_8616(address.offset, memo),
    )
    object.__setattr__(clone, "size", _detach_native_field_8616(address.size, memo))
    object.__setattr__(
        clone, "status", _detach_native_field_8616(address.status, memo),
    )
    object.__setattr__(
        clone, "segment_origin",
        _detach_native_field_8616(address.segment_origin, memo),
    )
    object.__setattr__(clone, "expr", _detach_native_field_8616(address.expr, memo))
    object.__setattr__(
        clone, "version", _detach_native_field_8616(address.version, memo),
    )
    object.__setattr__(
        clone, "base_values", _detach_native_field_8616(address.base_values, memo),
    )
    return clone


def _detach_native_condition_8616(
    condition: IRCondition, memo: dict[int, object],
) -> IRCondition:
    """Detach one exact ``IRCondition`` shell-first for cyclic args."""
    clone = IRCondition.__new__(IRCondition)
    memo[id(condition)] = clone
    object.__setattr__(clone, "op", _detach_native_field_8616(condition.op, memo))
    object.__setattr__(
        clone, "args", _detach_native_field_8616(condition.args, memo),
    )
    object.__setattr__(
        clone, "expr", _detach_native_field_8616(condition.expr, memo),
    )
    object.__setattr__(
        clone, "width_bits", _detach_native_field_8616(condition.width_bits, memo),
    )
    return clone


def _detach_native_binary_8616(
    value: IRBinaryValue, memo: dict[int, object],
) -> IRBinaryValue:
    """Detach one exact ``IRBinaryValue`` shell-first for shared operands."""
    clone = IRBinaryValue.__new__(IRBinaryValue)
    memo[id(value)] = clone
    object.__setattr__(clone, "op", _detach_native_field_8616(value.op, memo))
    object.__setattr__(clone, "lhs", _detach_native_field_8616(value.lhs, memo))
    object.__setattr__(clone, "rhs", _detach_native_field_8616(value.rhs, memo))
    object.__setattr__(clone, "size", _detach_native_field_8616(value.size, memo))
    return clone


def _detach_native_call_stack_8616(
    effect: IRCallStackEffect8616, memo: dict[int, object],
) -> IRCallStackEffect8616:
    """Detach effect data while retaining immutable external proof scopes.

    The source/callee certificates point at the original analysis project and
    authenticate themselves there. They are scope references, not copied IR
    data: copying the project would change their meaning. Coordinate and range
    data still detach normally through the shared memo.
    """
    clone = IRCallStackEffect8616.__new__(IRCallStackEffect8616)
    memo[id(effect)] = clone
    object.__setattr__(
        clone, "net_stack_delta",
        _detach_native_field_8616(effect.net_stack_delta, memo),
    )
    object.__setattr__(
        clone, "preserved_ranges",
        _detach_native_field_8616(effect.preserved_ranges, memo),
    )
    object.__setattr__(
        clone, "escaped_ranges",
        _detach_native_field_8616(effect.escaped_ranges, memo),
    )
    object.__setattr__(
        clone, "complete", _detach_native_field_8616(effect.complete, memo),
    )
    object.__setattr__(
        clone, "bp_preserved",
        _detach_native_field_8616(effect.bp_preserved, memo),
    )
    coordinates = effect.stack_coordinates
    if type(coordinates) is IRCallStackCoordinates8616:
        for authority in (coordinates.source, coordinates.callee_sp_proof):
            if authority is not None:
                memo.setdefault(id(authority), authority)
    object.__setattr__(
        clone, "stack_coordinates", _detach_native_field_8616(coordinates, memo),
    )
    scoped = effect.scoped_coordinates
    if scoped is not None:
        # The scoped carrier retains live domain/project authority objects;
        # sharing the immutable carrier preserves their identities verbatim.
        memo.setdefault(id(scoped), scoped)
    object.__setattr__(
        clone, "scoped_coordinates", _detach_native_field_8616(scoped, memo),
    )
    return clone


def _detach_native_active_unary_8616(
    active: IRActiveUnary8616, memo: dict[int, object],
) -> IRActiveUnary8616:
    """Detach one exact active unary with its operand value."""
    clone = IRActiveUnary8616.__new__(IRActiveUnary8616)
    memo[id(active)] = clone
    object.__setattr__(clone, "op", _detach_native_field_8616(active.op, memo))
    object.__setattr__(
        clone, "operand", _detach_native_field_8616(active.operand, memo),
    )
    object.__setattr__(
        clone, "result_bits", _detach_native_field_8616(active.result_bits, memo),
    )
    return clone


def _detach_native_refusal_8616(
    refusal: IRRefusal, memo: dict[int, object],
) -> IRRefusal:
    """Detach one exact ``IRRefusal``; shell-first keeps parity with cycles."""
    clone = IRRefusal.__new__(IRRefusal)
    memo[id(refusal)] = clone
    object.__setattr__(
        clone, "kind", _detach_native_field_8616(refusal.kind, memo),
    )
    object.__setattr__(
        clone, "detail", _detach_native_field_8616(refusal.detail, memo),
    )
    object.__setattr__(
        clone, "block_addr", _detach_native_field_8616(refusal.block_addr, memo),
    )
    return clone


def _detach_native_call_output_8616(
    provenance: IRCallOutputProvenance8616, memo: dict[int, object],
) -> IRCallOutputProvenance8616:
    """Detach one exact call-output provenance record."""
    clone = IRCallOutputProvenance8616.__new__(IRCallOutputProvenance8616)
    memo[id(provenance)] = clone
    object.__setattr__(
        clone, "callsite_addr",
        _detach_native_field_8616(provenance.callsite_addr, memo),
    )
    object.__setattr__(
        clone, "target_addr",
        _detach_native_field_8616(provenance.target_addr, memo),
    )
    object.__setattr__(
        clone, "shape", _detach_native_field_8616(provenance.shape, memo),
    )
    return clone


def _detach_native_origin_8616(
    origin: IRInstructionOrigin8616, memo: dict[int, object],
) -> IRInstructionOrigin8616:
    """Detach one exact instruction origin; shell-first for cycle parity."""
    clone = IRInstructionOrigin8616.__new__(IRInstructionOrigin8616)
    memo[id(origin)] = clone
    object.__setattr__(
        clone, "block_addr", _detach_native_field_8616(origin.block_addr, memo),
    )
    object.__setattr__(
        clone, "statement_index",
        _detach_native_field_8616(origin.statement_index, memo),
    )
    object.__setattr__(
        clone, "address_tmp",
        _detach_native_field_8616(origin.address_tmp, memo),
    )
    object.__setattr__(
        clone, "is_block_next",
        _detach_native_field_8616(origin.is_block_next, memo),
    )
    object.__setattr__(
        clone, "block_next_tmp",
        _detach_native_field_8616(origin.block_next_tmp, memo),
    )
    object.__setattr__(
        clone, "is_instruction_mark",
        _detach_native_field_8616(origin.is_instruction_mark, memo),
    )
    return clone


def _detach_native_block_8616(block: IRBlock, memo: dict[int, object]) -> IRBlock:
    """Detach one exact ``IRBlock`` shell-first for cyclic instructions."""
    clone = IRBlock.__new__(IRBlock)
    memo[id(block)] = clone
    object.__setattr__(clone, "addr", _detach_native_field_8616(block.addr, memo))
    object.__setattr__(
        clone, "instrs", _detach_native_field_8616(block.instrs, memo),
    )
    object.__setattr__(
        clone, "refusals", _detach_native_field_8616(block.refusals, memo),
    )
    object.__setattr__(
        clone, "successor_addrs",
        _detach_native_field_8616(block.successor_addrs, memo),
    )
    return clone


# Exact owned node type -> detached typed reconstruction. Ordered so the
# hottest native-surface classes resolve first on display only; dict lookup
# makes runtime dispatch order-independent.
_TYPED_NODE_DETACHERS_8616: dict[type, Callable[..., object]] = {
    IRValue: _detach_native_value_8616,
    IRInstr: _detach_native_instr_8616,
    IRAddress: _detach_native_address_8616,
    IRCondition: _detach_native_condition_8616,
    IRBinaryValue: _detach_native_binary_8616,
    IRCallStackEffect8616: _detach_native_call_stack_8616,
    IRActiveUnary8616: _detach_native_active_unary_8616,
    IRRefusal: _detach_native_refusal_8616,
    IRCallOutputProvenance8616: _detach_native_call_output_8616,
    IRInstructionOrigin8616: _detach_native_origin_8616,
    IRBlock: _detach_native_block_8616,
}


def _is_seedable_native_leaf_8616(value: IRValue) -> bool:
    """Return whether ``value`` is an exact leaf safe to rebuild directly.

    Nested provenance (``index``, ``call_output``, ``active_unary``) or any
    non-exact scalar payload disqualifies the node so the shell-first path
    keeps full fidelity for unknown shapes.
    """
    return (
        type(value) is IRValue
        and value.index is None
        and value.call_output is None
        and value.active_unary is None
        and _seedable_native_scalar_fields_8616(value)
    )


def _seedable_native_scalar_fields_8616(value: IRValue) -> bool:
    """Return whether every scalar field is an exact immutable builtin."""
    return (
        type(value.space) is MemSpace
        and _exact_optional_str_8616(value.name)
        and type(value.offset) in _EXACT_INT_TYPES_8616
        and _exact_optional_int_8616(value.const)
        and type(value.size) in _EXACT_INT_TYPES_8616
        and _exact_optional_int_8616(value.version)
        and type(value.index_shift) in _EXACT_INT_TYPES_8616
        and _exact_optional_int_8616(value.memory_access_size)
        and _exact_optional_int_8616(value.memory_access_insn)
        and _exact_optional_int_8616(value.source_tmp)
        and (value.expr is None or _exact_str_tuple_8616(value.expr))
    )


def _exact_optional_int_8616(value: object) -> bool:
    """Return whether ``value`` is absent or an exact immutable int."""
    return value is None or type(value) in _EXACT_INT_TYPES_8616


def _exact_optional_str_8616(value: object) -> bool:
    """Return whether ``value`` is absent or an exact string."""
    return value is None or type(value) is str


def _exact_str_tuple_8616(value: tuple[object, ...]) -> bool:
    """Return whether ``value`` is an exact tuple of exact strings."""
    return type(value) is tuple and all(type(item) is str for item in value)


def _detach_native_leaf_8616(value: IRValue) -> IRValue:
    """Rebuild one detached leaf preserving every field, ``compare=False`` too.

    All surviving fields are exact immutables, so sharing them with the source
    cannot leak mutation; only the node identity changes.
    """
    return IRValue(
        space=value.space,
        name=value.name,
        offset=value.offset,
        const=value.const,
        size=value.size,
        version=value.version,
        expr=value.expr,
        index=value.index,
        index_shift=value.index_shift,
        memory_access_size=value.memory_access_size,
        memory_access_insn=value.memory_access_insn,
        source_tmp=value.source_tmp,
        call_output=value.call_output,
        active_unary=value.active_unary,
    )


def native_copy_memo_producers_8616() -> tuple[object, ...]:
    """Bind copier helpers to the native import's existing source identity."""
    return (
        seed_native_decisions_8616,
        seed_native_copy_memo_8616, _detach_native_field_8616,
        _detach_native_tuple_8616, _detach_native_node_8616,
        _detach_native_value_8616, _detach_native_instr_8616,
        _detach_native_address_8616, _detach_native_condition_8616,
        _detach_native_binary_8616, _detach_native_call_stack_8616,
        _detach_native_active_unary_8616, _detach_native_refusal_8616,
        _detach_native_call_output_8616, _detach_native_origin_8616,
        _detach_native_block_8616, _is_seedable_native_leaf_8616,
        _seedable_native_scalar_fields_8616, _exact_optional_int_8616,
        _exact_optional_str_8616, _exact_str_tuple_8616, _detach_native_leaf_8616,
        _EXACT_INT_TYPES_8616, _SHARED_SCALAR_TYPES_8616,
        _TYPED_NODE_DETACHERS_8616,
        IRCallStackEffect8616.current_net_stack_delta,
        IRCallStackCoordinates8616.to_dict,
        IRCallStackCoordinates8616.has_proven_sp_delta,
        IRCallStackCoordinates8616.closed,
        IRCallStackCoordinates8616.callee_return_sp_delta,
        IRCallStackCoordinates8616._slot_values,
        IRCallStackCoordinates8616._layout_valid,
    )
