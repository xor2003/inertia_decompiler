"""Check selector C expressions for defined, repeatable word evaluation.

Layer: Types/Lowering.
Responsibility: classify structured selector expressions without segment or
pointer authority. Refuse volatile reads, unbounded shifts and integer overflow
under both DOS int16 and host int32 promotions. Literal metadata is not a C
unsigned suffix; left-shift literals require a signed-int16-safe numeric bound.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""
from __future__ import annotations

from collections.abc import Iterable
from enum import IntEnum
from typing import TypeGuard

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimType, SimTypeChar, SimTypeInt

_WORD_MODULUS_8616 = 1 << 16
_SELECTOR_DEPTH_BUDGET_8616 = 128
# A literal shift count below the narrowest promoted operand width (DOS
# int16) is defined on every supported target regardless of operand width.
_SHIFT_COUNT_LIMIT_8616 = 16
_DOS_SIGNED_WORD_MAX_8616 = (1 << 15) - 1

# Bitwise ops whose result stays inside the proven guest u16 domain when both
# operands do, and whose C evaluation is always defined.
_BITWISE_OPS_8616 = frozenset({"And", "Or", "Xor"})
# Arithmetic that is defined only when both operands are already proven
# unsigned-word valued; the result is defined but not u16-bounded, so it is
# admissible only beneath an explicit (uintN_t) view. ``Mul`` is excluded:
# 0xFFFF * 0xFFFF overflows the signed ``int`` result of host int32
# promotion even though DOS int16 promotes the operands to ``unsigned int``.
_WORD_ARITHMETIC_OPS_8616 = frozenset({"Add", "Sub"})
_SHIFT_OPS_8616 = frozenset({"Shl", "Shr"})
# Unary integer ops with no side effects and no trap for any integer
# operand; the result domain is not provably u16 across int16/int32
# promotion targets. ``Neg`` is handled separately: it stays defined only
# on an unsigned-word operand since a signed one hits the int16 -32768
# singularity on the DOS target.
_UNARY_PURE_OPS_8616 = frozenset({"BitwiseNeg", "Not"})


class NearReturnSelectorEvidence8616(IntEnum):
    """Ordered evidence grade for one selector subtree.

    ``REJECT`` is outside the proven side-effect-free, defined fragment.
    ``DEFINED`` is pure, nonvolatile integer C with no proven u16 value
    bound. ``WORD`` is ``DEFINED`` plus a proof the value lies inside
    ``[0, 65535]``, which is what a 16-bit segment selector requires.
    """

    REJECT = 0
    DEFINED = 1
    WORD = 2



def _unsigned_int_bits_8616(type_: object, bits: int) -> bool:
    """Return whether ``type_`` is an unsigned integer of exact bit width."""
    if not isinstance(type_, SimTypeInt):
        return False
    try:
        size = type_.size
    except (AttributeError, TypeError, ValueError):
        return False
    return type_.signed is False and type(size) is int and size == bits


def _unsigned_word_type_8616(type_: object) -> bool:
    """Return whether ``type_`` is an unsigned integer of at most 16 bits."""
    if not isinstance(type_, (SimTypeInt, SimTypeChar)):
        return False
    try:
        size = type_.size
    except (AttributeError, TypeError, ValueError):
        return False
    return type_.signed is False and type(size) is int and size <= 16


def _volatile_type_8616(type_: object) -> bool:
    """Return whether a generic angr SimType carries a volatile qualifier.

    ``SimType.qualifier`` is a free-form third-party attribute (a string or
    an arbitrary iterable); a non-``None`` qualifier that cannot be inspected
    is treated as volatile so an unknown shape fails closed.
    """
    if not isinstance(type_, SimType):
        return False
    qualifier = type_.qualifier
    if qualifier is None:
        return False
    if isinstance(qualifier, str):
        return "volatile" in qualifier
    if isinstance(qualifier, Iterable):
        return any(str(item) == "volatile" for item in qualifier)
    return True


def _shift_count_proven_8616(node: object) -> TypeGuard[structured_c.CConstant]:
    """Prove a shift count is an integer literal inside ``[0, 16)``.

    Only constants carry the bound; masked or variable counts are refused
    rather than inferred.
    """
    return (
        isinstance(node, structured_c.CConstant)
        and type(node.value) is int
        and 0 <= node.value < _SHIFT_COUNT_LIMIT_8616
    )


def _constant_evidence_8616(node: structured_c.CConstant) -> NearReturnSelectorEvidence8616:
    """Grade one integer literal: word-valued only when unsigned-typed."""
    constant_type = node.type
    if (
        type(node.value) is not int
        or not isinstance(constant_type, (SimTypeInt, SimTypeChar))
        or _volatile_type_8616(constant_type)
        or bool(node.reference_values)
    ):
        return NearReturnSelectorEvidence8616.REJECT
    if not constant_type.signed and 0 <= node.value < _WORD_MODULUS_8616:
        return NearReturnSelectorEvidence8616.WORD
    return NearReturnSelectorEvidence8616.DEFINED


def _variable_evidence_8616(node: structured_c.CVariable) -> NearReturnSelectorEvidence8616:
    """Grade one variable leaf: a pure read only when nonvolatile integer."""
    variable_type = node.variable_type
    if (
        not isinstance(variable_type, (SimTypeInt, SimTypeChar))
        or _volatile_type_8616(variable_type)
    ):
        return NearReturnSelectorEvidence8616.REJECT
    return (
        NearReturnSelectorEvidence8616.WORD
        if _unsigned_word_type_8616(variable_type)
        else NearReturnSelectorEvidence8616.DEFINED
    )


def _cast_evidence_8616(node: structured_c.CTypeCast, remaining: int) -> NearReturnSelectorEvidence8616:
    """Grade one cast: integer-to-integer casts are defined; u8/u16 are word."""
    dst_type = node.dst_type
    if (
        not isinstance(dst_type, (SimTypeInt, SimTypeChar))
        or _volatile_type_8616(dst_type)
        or _selector_evidence_8616(node.expr, remaining - 1)
        is NearReturnSelectorEvidence8616.REJECT
    ):
        return NearReturnSelectorEvidence8616.REJECT
    return (
        NearReturnSelectorEvidence8616.WORD
        if _unsigned_word_type_8616(dst_type)
        else NearReturnSelectorEvidence8616.DEFINED
    )


def _binary_evidence_8616(node: structured_c.CBinaryOp, remaining: int) -> NearReturnSelectorEvidence8616:
    """Grade one binary op under the defined-arithmetic contract."""
    lhs = _selector_evidence_8616(node.lhs, remaining - 1)
    rhs = _selector_evidence_8616(node.rhs, remaining - 1)
    if node.op in _BITWISE_OPS_8616:
        if min(lhs, rhs) < NearReturnSelectorEvidence8616.DEFINED:
            return NearReturnSelectorEvidence8616.REJECT
        return min(lhs, rhs)
    if node.op in _WORD_ARITHMETIC_OPS_8616:
        # C signed-16 overflow is UB on the DOS int16 target; only provably
        # unsigned-word operands keep the arithmetic defined.
        return (
            NearReturnSelectorEvidence8616.DEFINED
            if lhs is NearReturnSelectorEvidence8616.WORD and rhs is NearReturnSelectorEvidence8616.WORD
            else NearReturnSelectorEvidence8616.REJECT
        )
    if node.op in _SHIFT_OPS_8616:
        return _shift_evidence_8616(node.op, node.lhs, lhs, node.rhs)
    return NearReturnSelectorEvidence8616.REJECT


def _unsigned_int16_declared_8616(node: object) -> bool:
    """Return whether ``node`` carries an exact ``uint16_t`` declared type.

    Only leaf and cast nodes expose an inspectable declared type; any
    composite shape fails closed. On the DOS int16 target an operand
    narrower than 16 bits promotes to signed ``int`` where a left shift
    can overflow, so a merely word-valued operand is not enough — its
    promoted type must stay unsigned 16-bit.
    """
    if isinstance(node, structured_c.CConstant):
        declared = node.type
    elif isinstance(node, structured_c.CVariable):
        declared = node.variable_type
    elif isinstance(node, structured_c.CTypeCast):
        declared = node.dst_type
    else:
        return False
    return _unsigned_int_bits_8616(declared, 16) and not _volatile_type_8616(declared)


def _shift_evidence_8616(
    op: str,
    lhs_node: object,
    lhs: NearReturnSelectorEvidence8616,
    count_node: object,
) -> NearReturnSelectorEvidence8616:
    """Grade one shift whose count must be a proven literal bound."""
    if not _shift_count_proven_8616(count_node):
        return NearReturnSelectorEvidence8616.REJECT
    if op == "Shl":
        if isinstance(lhs_node, structured_c.CConstant):
            # AST metadata does not force a literal U suffix or unsigned cast.
            # Require a bound safe even if the renderer emits signed int16.
            value, count = lhs_node.value, count_node.value
            bounded_literal = type(value) is int and type(count) is int and 0 <= value <= (_DOS_SIGNED_WORD_MAX_8616 >> count)
            return NearReturnSelectorEvidence8616.DEFINED if bounded_literal else NearReturnSelectorEvidence8616.REJECT
        # Shl leaves the u16 domain, and a left operand narrower than 16
        # bits promotes to signed ``int`` on DOS where the shift can
        # overflow; only an exact uint16-typed word operand stays unsigned
        # under both int16 and int32 promotion.
        return (
            NearReturnSelectorEvidence8616.DEFINED
            if lhs is NearReturnSelectorEvidence8616.WORD
            and _unsigned_int16_declared_8616(lhs_node)
            else NearReturnSelectorEvidence8616.REJECT
        )
    # Shr of a word stays a word; a merely defined left operand stays defined.
    return lhs


def _selector_evidence_8616(node: object, remaining: int) -> NearReturnSelectorEvidence8616:
    """Classify one selector subtree's purity and unsigned-word domain.

    The walk is depth-bounded and never mutates the tree. Arithmetic is
    admitted only between provably unsigned-word operands because signed-16
    overflow is undefined on the DOS target even beneath a ``(uint16_t)``
    cast; volatile-qualified leaves are refused outright since the helper
    macro may re-evaluate its arguments.
    """
    if remaining <= 0:
        return NearReturnSelectorEvidence8616.REJECT
    if isinstance(node, structured_c.CConstant):
        return _constant_evidence_8616(node)
    if isinstance(node, structured_c.CVariable):
        return _variable_evidence_8616(node)
    if isinstance(node, structured_c.CTypeCast):
        return _cast_evidence_8616(node, remaining)
    if isinstance(node, structured_c.CUnaryOp):
        operand = _selector_evidence_8616(node.operand, remaining - 1)
        if node.op == "Neg":
            # ``-v`` stays defined in every promotion regime only when ``v``
            # is provably unsigned-word typed; a signed operand can reach
            # the int16 singularity at -32768 on the DOS target.
            return (
                NearReturnSelectorEvidence8616.DEFINED
                if operand is NearReturnSelectorEvidence8616.WORD
                else NearReturnSelectorEvidence8616.REJECT
            )
        if node.op not in _UNARY_PURE_OPS_8616:
            return NearReturnSelectorEvidence8616.REJECT
        return min(operand, NearReturnSelectorEvidence8616.DEFINED)
    if isinstance(node, structured_c.CBinaryOp):
        return _binary_evidence_8616(node, remaining)
    return NearReturnSelectorEvidence8616.REJECT

def classify_near_return_selector_8616(node: object) -> NearReturnSelectorEvidence8616:
    """Classify one bounded selector subtree without granting segment identity."""
    return _selector_evidence_8616(node, _SELECTOR_DEPTH_BUDGET_8616)
