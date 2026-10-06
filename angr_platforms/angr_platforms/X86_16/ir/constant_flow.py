"""Exact local constant values and proven bit lanes for typed instruction consumers.

Layer: IR.
Responsibility: preserve constants, proven bit lanes, and immutable temporary
identities within one basic block. Unknown operations stay unknown; calls
invalidate register knowledge. This proves values only, never memory aliases
or C replacements.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

import operator
from collections.abc import Callable
from dataclasses import dataclass, field, replace

from ..semantics.register_value_preservation import (
    register_value_family_8616,
    register_value_projection_8616,
)
from .core import IRActiveUnary8616, IRInstr, IRValue, MemSpace
from .scalar_value_projection import (
    ScalarBinaryKind8616,
    ScalarProjectionKind8616,
    scalar_binary_operation_8616,
    scalar_produced_decoration_8616,
    scalar_read_projection_8616,
)

_BINARY: dict[ScalarBinaryKind8616, Callable[[int, int], int]] = {
    ScalarBinaryKind8616.ADD: operator.add,
    ScalarBinaryKind8616.SUB: operator.sub,
    ScalarBinaryKind8616.AND: operator.and_,
    ScalarBinaryKind8616.OR: operator.or_,
    ScalarBinaryKind8616.XOR: operator.xor,
    ScalarBinaryKind8616.SHL: operator.lshift,
    ScalarBinaryKind8616.SHR: operator.rshift,
}

_ACTIVE_UNARY_DEPTH_LIMIT_8616 = 8
_UNARY_COMPLEMENT_OPS_8616: dict[str, int] = {
    f"Iop_Not{bits}": bits for bits in (8, 16, 32, 64)
}


@dataclass(frozen=True, slots=True)
class _Value:
    """One immutable width-bounded definition with proven bit lanes.

    ``known`` marks the bits whose contents are proven in ``value``; the
    invariant ``value & ~known == 0`` keeps unproven bits free of contents.
    A value with every bit known is an exact constant. ``produced`` records
    the descriptive ``expr`` decoration the producing expression earned, so a
    later temporary read that re-presents exactly that decoration is
    distinguished from an unearned conversion claim.
    """

    identity: int
    bits: int
    known: int
    value: int
    produced: tuple[str, ...] = ()

    @property
    def constant(self) -> int | None:
        """Return the complete integer only when every bit is proven."""
        return self.value if self.known == (1 << self.bits) - 1 else None


def _storage_parent_8616(name: str) -> str:
    """Return the family member whose architectural view covers all others."""
    family: frozenset[str] = register_value_family_8616(name)
    for candidate in sorted(family):
        if all(
            register_value_projection_8616(candidate, member) is not None
            for member in family
        ):
            return candidate
    return name


def _boolean_lanes_8616(
    name: ScalarBinaryKind8616, bits: int, left: _Value, right: _Value,
) -> tuple[int, int]:
    """Return proven (known, value) lanes for one And/Or/Xor operation.

    A result bit is proven only when the Boolean rule determines it from
    proven input bits: And is zero when either side is proven zero, Or is
    one when either side is proven one, Xor needs both sides proven.
    """
    full = (1 << bits) - 1
    if name is ScalarBinaryKind8616.AND:
        known = (left.known & ~left.value) | (right.known & ~right.value) | (left.value & right.value)
        value = left.value & right.value
    elif name is ScalarBinaryKind8616.OR:
        known = ((left.known & ~left.value) & (right.known & ~right.value)) | left.value | right.value
        value = left.value | right.value
    else:
        known = left.known & right.known
        value = left.value ^ right.value
    return known & full, value & full


def _shift_lanes_8616(
    name: ScalarBinaryKind8616, bits: int, operand: _Value, count: int,
) -> tuple[int, int]:
    """Return proven (known, value) lanes for a logical shift by ``count``.

    ``count`` must already be a proven in-range constant; the vacated bits
    are proven zero. Out-of-range or unknown counts refuse before this.
    """
    full = (1 << bits) - 1
    if name is ScalarBinaryKind8616.SHL:
        known = ((operand.known << count) | ((1 << count) - 1)) & full
        value = (operand.value << count) & full
    else:
        known = (operand.known >> count) | (full ^ ((1 << (bits - count)) - 1))
        value = operand.value >> count
    return known & full, value & full


def _produced_8616(instruction: IRInstr) -> tuple[str, ...]:
    """Retain the importer's exact producing decoration for later TMP reads.

    Delegates to the scalar-projection adapter, which owns the single
    producing-decoration truth; labels validate re-decoration, never compute
    a value.
    """
    return scalar_produced_decoration_8616(instruction)


def _convert_lanes_8616(value: _Value, source: int, target: int, signed: bool) -> tuple[int, int]:
    """Return proven (known, value) lanes through one integer conversion.

    Truncation keeps only the target's low bits. Unsigned extension proves
    the new high bits zero. Signed extension proves the high bits only when
    the source sign bit is proven; an unknown sign leaves them unknown.
    """
    low_mask = (1 << source) - 1
    full_target = (1 << target) - 1
    known = value.known & low_mask
    lanes = value.value & low_mask
    if target < source:
        return known & full_target, lanes & full_target
    high = full_target & ~low_mask
    if signed:
        sign_bit = 1 << (source - 1)
        if not known & sign_bit:
            return known, lanes
        return known | high, lanes | (high if lanes & sign_bit else 0)
    return known | high, lanes


@dataclass(slots=True)
class IRConstantFlow8616:
    """Consume instructions in order; create a fresh instance per IR block."""

    _registers: dict[str, _Value] = field(default_factory=dict)
    _views: dict[str, tuple[int, _Value]] = field(default_factory=dict)
    _temporaries: dict[int, _Value] = field(default_factory=dict)
    _identity: int = 0

    def _new(self, bits: int, constant: int | None = None) -> _Value:
        """Allocate an immutable width-normalized definition."""
        self._identity += 1
        if constant is None:
            return _Value(self._identity, bits, 0, 0)
        return _Value(self._identity, bits, (1 << bits) - 1, constant & ((1 << bits) - 1))

    def _new_lanes(self, bits: int, known: int, value: int) -> _Value:
        """Allocate a partial definition; unproven bits carry no contents."""
        self._identity += 1
        known &= (1 << bits) - 1
        return _Value(self._identity, bits, known, value & known)

    def _register(self, name: str) -> _Value | None:
        """Read an exact register view from the authoritative storage layout."""
        name = name.lower()
        if register_value_projection_8616(name, name) is None:
            return None
        parent = _storage_parent_8616(name)
        lane = register_value_projection_8616(parent, name)
        if lane is None:
            return None
        entry = self._registers.get(parent)
        if entry is None:
            parent_view = register_value_projection_8616(parent, parent)
            if parent_view is None:
                return None
            entry = self._new(parent_view[1])
            self._registers[parent] = entry
        cached = self._views.get(name)
        if cached is not None and cached[0] == entry.identity:
            return cached[1]
        shift, bits = lane
        known = (entry.known >> shift) & ((1 << bits) - 1)
        view = self._new_lanes(bits, known, entry.value >> shift)
        self._views[name] = (entry.identity, view)
        return view

    def _read(self, value: object, _depth: int = 0) -> _Value | None:
        """Prefer the original temporary definition over its register label.

        A ``source_tmp``-pinned read names an already-computed captured
        definition, so its ``offset`` is provenance inside that captured
        result rather than arithmetic to re-apply; an unpinned nonzero
        ``offset`` would require re-reading current storage plus arithmetic
        this owner does not replay, and refuses. A value carrying
        ``active_unary`` is the pending operation's result: only the typed
        operation evidence describes it, never the projected storage fields.
        """
        if not isinstance(value, IRValue) or value.index is not None or value.call_output is not None:
            return None
        if value.size not in {1, 2, 4, 8}:
            return None
        if value.active_unary is not None:
            if value.source_tmp is not None:
                return None
            return self._read_active_unary_8616(value, _depth)
        if value.source_tmp is not None:
            result = self._temporaries.get(value.source_tmp)
        elif value.offset:
            return None
        elif value.space is MemSpace.CONST and value.const is not None:
            result = self._new(value.size * 8, value.const)
        elif value.space is MemSpace.REG and value.name is not None:
            result = self._register(value.name)
        else:
            return None
        if result is None:
            return None
        return self._project(value, result)

    def _read_active_unary_8616(self, value: IRValue, depth: int) -> _Value | None:
        """Evaluate one pending active unary against captured operand evidence.

        The operand may be a pinned temporary (already computed — never
        replayed), a plain register or constant, or itself an active unary,
        so recursion proceeds through ``_read`` with a hard depth bound. The
        scalar-projection adapter authenticates ``Iop_{src}{U,S}to{dst}``
        conversions against the operand's retained width and the declared
        result width; ``Iop_Not{bits}`` complements proven lanes. Width
        contradictions, decoration mismatches and unsupported operations
        refuse rather than guessing from the projected REG/CONST fields.
        """
        unary = value.active_unary
        if unary is None or depth >= _ACTIVE_UNARY_DEPTH_LIMIT_8616:
            return None
        if value.expr is not None and value.expr != (unary.op,):
            return None
        if not 0 < unary.result_bits <= value.size * 8:
            return None
        operand = self._read(unary.operand, depth + 1)
        if operand is None:
            return None
        result = self._apply_active_unary_8616(unary, operand)
        if result is None:
            return None
        if result.bits == value.size * 8:
            return result
        return self._new_lanes(value.size * 8, result.known, result.value)

    def _apply_active_unary_8616(self, unary: IRActiveUnary8616, operand: _Value) -> _Value | None:
        """Apply one authenticated unary operation to retained operand lanes."""
        decision = scalar_read_projection_8616(
            read_expr=(unary.op,),
            read_bits=unary.result_bits,
            produced=(),
            produced_bits=operand.bits,
        )
        if decision is not None and decision.kind is ScalarProjectionKind8616.CONVERSION:
            known, lanes = _convert_lanes_8616(
                operand, decision.source_bits, decision.target_bits, decision.signed,
            )
            return self._new_lanes(decision.target_bits, known, lanes)
        bits = _UNARY_COMPLEMENT_OPS_8616.get(unary.op)
        if bits is None or bits != unary.result_bits or operand.bits != bits:
            return None
        return self._new_lanes(bits, operand.known, ~operand.value)

    def _project(self, value: IRValue, result: _Value) -> _Value | None:
        """Apply one explicit conversion or match earned re-decoration.

        An undecorated read claims no conversion and passes through at the
        retained width. The importer copies a producing expression's ``expr``
        onto later reads of the same temporary, so a decoration equal to
        ``result.produced`` is the re-decoration of this very definition and
        also passes through. Any other decoration must be exactly one
        conversion whose declared source width equals the retained
        definition's width — that conversion is consumed and transported.
        A conversion matching only the target width is unearned, and
        unsupported or multiple labels refuse. The final width check never
        manufactures an implicit widening or truncation.
        """
        decision = scalar_read_projection_8616(
            read_expr=value.expr,
            read_bits=value.size * 8,
            produced=result.produced,
            produced_bits=result.bits,
        )
        if decision is None:
            return None
        if decision.kind is ScalarProjectionKind8616.CONVERSION:
            known, lanes = _convert_lanes_8616(
                result, decision.source_bits, decision.target_bits, decision.signed,
            )
            return self._new_lanes(decision.target_bits, known, lanes)
        return result

    def constant(self, value: object) -> int | None:
        """Read a proven value at the current program point; never guess zero."""
        result = self._read(value)
        return None if result is None else result.constant

    def _result(self, instruction: IRInstr) -> _Value | None:
        """Evaluate only explicitly supported pure bitvector operations."""
        arguments = instruction.args
        if instruction.op == "MOV" and len(arguments) == 1:
            return self._read(arguments[0])
        operation = scalar_binary_operation_8616(instruction.op)
        if operation is None or len(arguments) != 2:
            return None
        left, right = (self._read(argument) for argument in arguments)
        if left is None or right is None:
            return None
        name, bits = operation.kind, operation.bits
        shifts = {ScalarBinaryKind8616.SHR, ScalarBinaryKind8616.SHL}
        if left.bits != bits or (name not in shifts and right.bits != bits):
            return None
        if name in {ScalarBinaryKind8616.SUB, ScalarBinaryKind8616.XOR} and left.identity == right.identity:
            return self._new(bits, 0)
        if name in {ScalarBinaryKind8616.AND, ScalarBinaryKind8616.OR, ScalarBinaryKind8616.XOR}:
            known, lanes = _boolean_lanes_8616(name, bits, left, right)
            return self._new_lanes(bits, known, lanes)
        if name in shifts:
            count = right.constant
            if count is None or count >= bits:
                return None
            known, lanes = _shift_lanes_8616(name, bits, left, count)
            return self._new_lanes(bits, known, lanes)
        if left.constant is None or right.constant is None:
            return None
        return self._new(bits, _BINARY[name](left.constant, right.constant))

    def _merge_register_8616(self, instruction: IRInstr, destination: IRValue) -> None:
        """Merge proven bits into the storage parent; never invent other bits.

        A destination width that disagrees with the authoritative register
        view — including sizes outside the supported set — is malformed: it
        cannot justify preserving sibling lanes, so the entire storage family
        is invalidated. A name without an authoritative view, or a storage
        parent whose own layout is unknown, refuses rather than allocating an
        assumed-width storage object.
        """
        if destination.name is None:
            return
        name = destination.name.lower()
        view = register_value_projection_8616(name, name)
        parent = _storage_parent_8616(name)
        parent_view = register_value_projection_8616(parent, parent)
        lane = register_value_projection_8616(parent, name)
        if view is None or parent_view is None or lane is None:
            self._registers.pop(parent, None)
            self._views.pop(name, None)
            return
        if lane[1] != view[1] or destination.size * 8 != view[1]:
            self._registers[parent] = self._new(parent_view[1])
            return
        result = self._result(instruction)
        shift, bits = lane
        if result is None or result.bits != bits:
            result = self._new(bits)
        entry = self._registers.get(parent)
        if entry is None or entry.bits != parent_view[1]:
            entry = self._new(parent_view[1])
        lane_mask = ((1 << bits) - 1) << shift
        known = (entry.known & ~lane_mask) | ((result.known << shift) & lane_mask)
        value = (entry.value & ~lane_mask) | ((result.value << shift) & lane_mask)
        self._registers[parent] = self._new_lanes(parent_view[1], known, value)

    def observe(self, instruction: IRInstr) -> None:
        """Publish each definition after reading operands from the old state.

        ``CALL`` carries its target in ``dst``; it is not an output
        definition, so only register and view knowledge is invalidated while
        pre-call immutable temporary definitions stay untouched.
        """
        if instruction.op == "CALL":
            self._registers.clear()
            self._views.clear()
            return
        destination = instruction.dst
        if not isinstance(destination, IRValue):
            return
        if destination.space is MemSpace.REG and destination.name is not None:
            self._merge_register_8616(instruction, destination)
            return
        if destination.space is not MemSpace.TMP or destination.source_tmp is None:
            return
        if destination.size not in {1, 2, 4, 8}:
            self._temporaries.pop(destination.source_tmp, None)
            return
        result = self._result(instruction)
        if result is None or result.bits != destination.size * 8:
            result = self._new(destination.size * 8)
        self._temporaries[destination.source_tmp] = replace(
            result, produced=_produced_8616(instruction)
        )
