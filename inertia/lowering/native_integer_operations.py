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


def lower_native_integer_operation_8616(expression: BinaryOp, native: CExpression) -> CExpression | None:
    """Keep dword shifts and division typed without guessing operand semantics.

    Shifts operate on unsigned bitvectors even when a sign-extended value feeds
    them. Division instead consumes the signedness explicitly supplied by AIL.
    Variable shifts are refused until their valid-count contract is available.
    """
    non_scalar = expression.floating_point or expression.vector_count is not None or expression.vector_size is not None
    if non_scalar or expression.bits != _DWORD_BITS or not isinstance(native, CBinaryOp):
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
