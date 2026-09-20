"""Compose structured expressions from already-proven binary IR values.

Layer: Structuring.
Responsibility: map supported typed binary operators to C AST using the
caller's operand projection. Never infer operands, widths, or storage identity.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Callable

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CExpression

from ..ir.core import IRBinaryValue, IRValue
from ..lowering.condition_value_casts import materialize_signed_condition_value_8616


def materialize_binary_ir_value_8616(
    value: IRBinaryValue,
    codegen: object,
    lower_operand: Callable[[IRValue | IRBinaryValue], object | None],
) -> CExpression | None:
    """Compose supported operands without manufacturing missing value evidence."""
    signed_value = materialize_signed_condition_value_8616(value, codegen, lower_operand)
    if signed_value is not None:
        return signed_value
    operator = {"add": "Add", "and": "And", "or": "Or", "shr": "Shr",
                "sub": "Sub", "xor": "Xor"}.get(value.op)
    if operator is None:
        return None
    lhs, rhs = lower_operand(value.lhs), lower_operand(value.rhs)
    if not isinstance(lhs, CExpression) or not isinstance(rhs, CExpression):
        return None
    return CBinaryOp(operator, lhs, rhs, codegen=codegen)
