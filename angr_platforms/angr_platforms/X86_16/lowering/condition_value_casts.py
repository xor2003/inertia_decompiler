"""Materialize exact signed conversions already proven by typed IR.

Layer: Types/Lowering.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Responsibility: express proven conversion widths as C casts without changing
the source access, its storage identity or evaluation count.
"""

from __future__ import annotations

from collections.abc import Callable

from angr.analyses.decompiler.structured_codegen.c import CExpression

from ..ir.condition_value_extensions import signed_extension_source_8616
from ..ir.core import IRBinaryValue, IRValue
from .condition_stack_operands import _condition_integer_type
from .semantic_cast import CSemanticCast8616


def materialize_signed_condition_value_8616(
    value: IRBinaryValue,
    codegen: object,
    lower_operand: Callable[[IRValue | IRBinaryValue], object | None],
) -> CExpression | None:
    """Consume the exact IR extension proof, otherwise retain arithmetic.

    Both casts are needed: the first supplies the signed source view, and the
    second records the destination width for outer unsigned/value consumers.
    The original source is projected once, at its unchanged access width.
    """
    source = signed_extension_source_8616(value)
    if source is None:
        return None
    expression = lower_operand(source)
    if not isinstance(expression, CExpression):
        return None
    source_type = _condition_integer_type(codegen, source.size, signed=True)
    destination_type = _condition_integer_type(codegen, value.size, signed=True)
    signed_source = CSemanticCast8616(expression.type, source_type, expression, codegen=codegen)
    return CSemanticCast8616(source_type, destination_type, signed_source, codegen=codegen)
