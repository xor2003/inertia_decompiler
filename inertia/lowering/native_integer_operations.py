"""Preserve explicit AIL arithmetic types at native C construction.

Layer: Types/Lowering.
Responsibility: consume proven scalar operation widths and signedness before
native C type inference can replace them with DOS int-sized operand types.
Consumes alias, widening, and typed facts at the native codegen boundary.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CExpression
from angr.sim_type import SimTypeNum

from .semantic_cast import CSemanticCast8616

_DWORD_BITS = 32
_WORD_BITS = 16


def lower_native_integer_operation_8616(expression: BinaryOp, native: CExpression) -> CExpression | None:
    """Keep word/dword shifts and dword division at their proven native widths.

    Shifts operate on unsigned bitvectors even when a sign-extended value feeds
    them. Division instead consumes the signedness explicitly supplied by AIL.
    Variable shifts are refused until their valid-count contract is available.
    """
    non_scalar = expression.floating_point or expression.vector_count is not None or expression.vector_size is not None
    if non_scalar or not isinstance(native, CBinaryOp):
        return None
    if expression.bits == _WORD_BITS:
        return _lower_native_word_shift_8616(expression, native)
    if expression.bits != _DWORD_BITS:
        return None
    left, right = expression.operands
    if left.bits != _DWORD_BITS:
        return None
    if expression.op == "Shl":
        if not isinstance(right, Const) or not isinstance(right.value, int) or not 0 <= right.value < _DWORD_BITS:
            return None
        signed = False
        rhs = native.rhs
    elif expression.op in {"Div", "Mod"} and right.bits == _DWORD_BITS:
        signed = expression.signed
        rhs = CSemanticCast8616(None, SimTypeNum(_DWORD_BITS, signed), native.rhs, codegen=native.codegen)
    else:
        return None
    lhs = CSemanticCast8616(None, SimTypeNum(_DWORD_BITS, signed), native.lhs, codegen=native.codegen)
    return CBinaryOp(expression.op, lhs, rhs, codegen=native.codegen, tags=native.tags)


def _lower_native_word_shift_8616(expression: BinaryOp, native: CBinaryOp) -> CExpression | None:
    """Widen byte-derived operands before DOS promotion, then restore the word.

    Unsigned word operands stay unsigned on a 16-bit C implementation. On a
    32-bit host their largest supported intermediate, 65535 << 15, remains
    within signed int32; the final conversion preserves native truncation.
    No memory reads, argument identities, or nonliteral counts are inferred.
    """
    left, right = expression.operands
    if expression.op != "Shl" or native.op != expression.op or left.bits != _WORD_BITS:
        return None
    if not isinstance(right, Const) or not isinstance(right.value, int) or not 0 <= right.value < _WORD_BITS:
        return None
    type_ = SimTypeNum(_WORD_BITS, False)
    lhs = CSemanticCast8616(None, type_, native.lhs, codegen=native.codegen)
    shifted = CBinaryOp("Shl", lhs, native.rhs, codegen=native.codegen, tags=native.tags)
    return CSemanticCast8616(None, type_, shifted, codegen=native.codegen, tags=native.tags)
