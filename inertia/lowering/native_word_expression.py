"""Prove bounded unsigned C projections of one authenticated word value.

Layer: Types/Lowering.
Responsibility: check current typed C evaluation and exact leaf identity;
storage, captured-memory versions, dominance and freshness belong to callers.
No loads are introduced, and no source identity is inferred from coordinates.
Consumes alias, widening, and typed facts
Do not recover semantics from COD, source, assembly, or rendered C text
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import cast

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CTypeCast, CVariable
from angr.sim_type import SimTypeChar, SimTypeInt, SimTypeNum, SimTypeShort

from .semantic_cast import CSemanticCast8616, declared_variable_type_8616

_WORD_BITS = 16
_NODE_LIMIT = 32
_DEPTH_LIMIT = 16
_ONE = 16
_INTEGER_TYPES = (SimTypeChar, SimTypeInt, SimTypeNum, SimTypeShort)
type _Lanes = tuple[frozenset[int], ...]


class NativeWordExpressionStatus8616(Enum):
    """Whether defined current C evaluation is exactly the supplied word."""

    PROVEN = "proven"
    MISMATCH = "mismatch"
    REFUSED = "refused"


class NativeWordExpressionFailure8616(Enum):
    """Typed exclusions from the bounded, defined unsigned fragment."""

    LIMIT = "limit"
    TYPE = "type"
    LEAF = "leaf"
    OPERATION = "operation"
    SHIFT = "shift"
    UNBOUNDED = "unbounded"


@dataclass(frozen=True, slots=True)
class NativeWordExpressionProof8616:
    """Value-only proof; it never grants memory or source freshness authority."""

    status: NativeWordExpressionStatus8616
    failure: NativeWordExpressionFailure8616 | None = None


@dataclass(frozen=True, slots=True)
class _WordTerm8616:
    """Symbolic low word plus its current integer width and range proof."""

    lanes: _Lanes
    width: int
    bounded: bool = True


def _unsigned_width_8616(type_: object) -> int | None:
    """Accept only explicit nonvolatile unsigned byte/word integer types."""
    if not isinstance(type_, _INTEGER_TYPES) or type(type_) not in _INTEGER_TYPES or type_.signed is not False:
        return None
    if type_.qualifier is not None:
        return None
    try:
        width = type_.size
    except ValueError:
        return None
    return width if width in {8, 16} else None


@dataclass(slots=True)
class _WordEvaluation8616:
    """One bounded evaluation over an exact caller-authenticated leaf."""

    leaf: CVariable
    remaining: int = _NODE_LIMIT

    def evaluate(self, node: object, depth: int = 0) -> _WordTerm8616 | NativeWordExpressionFailure8616:
        """Evaluate pure bit operations only after their C definedness checks."""
        self.remaining -= 1
        if self.remaining < 0 or depth >= _DEPTH_LIMIT:
            return NativeWordExpressionFailure8616.LIMIT
        if type(node) is CVariable:
            variable = cast(CVariable, node)
            identity = variable.unified_variable or variable.variable
            expected = self.leaf.unified_variable or self.leaf.variable
            if identity is not expected or variable.vvar_id != self.leaf.vvar_id:
                return NativeWordExpressionFailure8616.LEAF
            if _unsigned_width_8616(declared_variable_type_8616(variable)) != _WORD_BITS:
                return NativeWordExpressionFailure8616.TYPE
            return _WordTerm8616(tuple(frozenset({bit}) for bit in range(_WORD_BITS)), _WORD_BITS)
        if type(node) is CConstant:
            constant = cast(CConstant, node)
            width = _unsigned_width_8616(constant.type)
            if width is None or type(constant.value) is not int or not 0 <= constant.value < 1 << width or constant.reference_values:
                return NativeWordExpressionFailure8616.TYPE
            lanes = tuple(frozenset({_ONE}) if constant.value & (1 << bit) else frozenset() for bit in range(_WORD_BITS))
            return _WordTerm8616(lanes, width)
        if isinstance(node, CTypeCast):
            return self.conversion(node, depth)
        if type(node) is CBinaryOp:
            return self.binary(cast(CBinaryOp, node), depth)
        return NativeWordExpressionFailure8616.OPERATION

    def conversion(self, node: CTypeCast, depth: int) -> _WordTerm8616 | NativeWordExpressionFailure8616:
        """Retain only visible machine casts with coherent source metadata."""
        width = _unsigned_width_8616(node.dst_type)
        if type(node) is not CSemanticCast8616 or width is None:
            return NativeWordExpressionFailure8616.TYPE
        source = self.evaluate(node.expr, depth + 1)
        if isinstance(source, NativeWordExpressionFailure8616):
            return source
        if _unsigned_width_8616(node.src_type) != source.width:
            return NativeWordExpressionFailure8616.TYPE
        lanes = source.lanes[:width] + (frozenset(),) * (_WORD_BITS - width)
        return _WordTerm8616(lanes, width)

    def binary(self, node: CBinaryOp, depth: int) -> _WordTerm8616 | NativeWordExpressionFailure8616:
        """Preserve unsigned shifts under DOS int16 and host int32 promotion."""
        left = self.evaluate(node.lhs, depth + 1)
        if isinstance(left, NativeWordExpressionFailure8616):
            return left
        if not left.bounded:
            return NativeWordExpressionFailure8616.UNBOUNDED
        if node.op == "Or":
            right = self.evaluate(node.rhs, depth + 1)
            if isinstance(right, NativeWordExpressionFailure8616):
                return right
            if not right.bounded:
                return NativeWordExpressionFailure8616.UNBOUNDED
            lanes = tuple(a | b for a, b in zip(left.lanes, right.lanes, strict=True))
            return _WordTerm8616(lanes, max(left.width, right.width))
        if node.op not in {"Shl", "Shr"}:
            return NativeWordExpressionFailure8616.OPERATION
        return self.shift(node, left, depth)

    def shift(self, node: CBinaryOp, left: _WordTerm8616, depth: int) -> _WordTerm8616 | NativeWordExpressionFailure8616:
        """Check literal shift bounds and both target promotion domains."""
        count = node.rhs
        self.remaining -= 1
        if self.remaining < 0 or depth + 1 >= _DEPTH_LIMIT:
            return NativeWordExpressionFailure8616.LIMIT
        if type(count) is not CConstant or type(count.value) is not int or not 0 <= count.value < _WORD_BITS:
            return NativeWordExpressionFailure8616.SHIFT
        if count.reference_values or type(count.type) not in _INTEGER_TYPES:
            return NativeWordExpressionFailure8616.TYPE
        amount = count.value
        if node.op == "Shr":
            return _WordTerm8616(left.lanes[amount:] + (frozenset(),) * amount, left.width)
        # u8 promotes to signed DOS int16. Only an explicit u16 operand
        # keeps a nonliteral left shift unsigned there; host int32 also
        # remains defined since 65535 << 15 is below INT32_MAX.
        if left.width != _WORD_BITS:
            return NativeWordExpressionFailure8616.SHIFT
        lanes: _Lanes = (frozenset(),) * amount + left.lanes[:_WORD_BITS - amount]
        bounded = not amount or not any(left.lanes[_WORD_BITS - amount:])
        return _WordTerm8616(lanes, _WORD_BITS, bounded)


def validate_native_word_expression_8616(expression: object, leaf: CVariable) -> NativeWordExpressionProof8616:
    """Prove current pure C computes exactly one caller-authenticated u16 leaf.

    Callers must separately authenticate storage/memory versions, definition
    dominance, source bytes and the current C-to-native SSA correspondence.
    No coordinate, register spelling or compiler identity supplies that proof.
    """
    if type(leaf) is not CVariable or _unsigned_width_8616(declared_variable_type_8616(leaf)) != _WORD_BITS:
        return NativeWordExpressionProof8616(NativeWordExpressionStatus8616.REFUSED, NativeWordExpressionFailure8616.TYPE)
    result = _WordEvaluation8616(leaf).evaluate(expression)
    if isinstance(result, NativeWordExpressionFailure8616):
        return NativeWordExpressionProof8616(NativeWordExpressionStatus8616.REFUSED, result)
    if not result.bounded:
        return NativeWordExpressionProof8616(NativeWordExpressionStatus8616.REFUSED, NativeWordExpressionFailure8616.UNBOUNDED)
    identity = tuple(frozenset({bit}) for bit in range(_WORD_BITS))
    status = NativeWordExpressionStatus8616.PROVEN if result.lanes == identity else NativeWordExpressionStatus8616.MISMATCH
    return NativeWordExpressionProof8616(status)
