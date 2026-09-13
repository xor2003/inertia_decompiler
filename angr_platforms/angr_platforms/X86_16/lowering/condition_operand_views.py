"""Preserve comparison width and signedness independently of storage types.

Layer: Types/Lowering.
Responsibility: consume proven ConditionIR ordering as required scalar views.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Do not change storage identity or infer a global declaration from one comparison.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimType, SimTypeChar, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeNum, SimTypeShort

from ..ir.condition_ir import ConditionIR
from .semantic_cast import CSemanticCast8616, is_identity_semantic_variable_cast_8616

_INTEGER_TYPES = (SimTypeChar, SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeNum)
_WIDTH_TYPES = {8: SimTypeChar, 16: SimTypeShort, 32: SimTypeLong}
_DWORD_BITS = 32


def _unsigned_mask_fits(expression: c.CExpression, width: int) -> bool:
    """A nonnegative bit mask proves a bounded unsigned integer result."""
    if not isinstance(expression, c.CBinaryOp) or expression.op != "And":
        return False
    return any(
        isinstance(operand, c.CConstant)
        and isinstance(operand.value, int)
        and 0 <= operand.value < (1 << width)
        for operand in (expression.lhs, expression.rhs)
    )


def _operand_view(expression: c.CExpression, target: SimType, width: int, signed: bool) -> c.CExpression | None:
    """Convert one integer operand without changing its shared declaration."""
    if not signed and _unsigned_mask_fits(expression, width):
        return expression
    source = expression.type
    if not isinstance(source, _INTEGER_TYPES):
        return None
    if isinstance(expression, c.CConstant) and isinstance(expression.value, int):
        value = expression.value & ((1 << width) - 1)
        if signed and value & (1 << (width - 1)):
            value -= 1 << width
        return c.CConstant(value, target, codegen=expression.codegen, tags=expression.tags)
    if isinstance(expression, CSemanticCast8616) and expression.dst_type == target:
        return expression
    conversion = CSemanticCast8616(source, target, expression, codegen=expression.codegen)
    if is_identity_semantic_variable_cast_8616(conversion):
        return expression
    return conversion


def materialize_condition_operand_views_8616(
    expression: c.CExpression, condition: ConditionIR,
) -> c.CExpression | None:
    """Apply exact signed/unsigned ordering views, refusing unsupported operands."""
    if not condition.is_signed and not condition.is_unsigned:
        return expression
    if not isinstance(expression, c.CBinaryOp):
        return None
    type_class = _WIDTH_TYPES.get(condition.width_bits)
    if type_class is None:
        return None
    target = type_class(signed=condition.is_signed).with_arch(expression.codegen.project.arch)
    if condition.width_bits == _DWORD_BITS:
        # C long is 64-bit on common portable-flat hosts, unlike the DOS ABI.
        label = "int32_t" if condition.is_signed else "uint32_t"
        target = SimTypeNum(_DWORD_BITS, signed=condition.is_signed, label=label)
    lhs = _operand_view(expression.lhs, target, condition.width_bits, condition.is_signed)
    rhs = _operand_view(expression.rhs, target, condition.width_bits, condition.is_signed)
    if lhs is None or rhs is None:
        return None
    # Mutate only after both views are proven, so refusal leaves the tree intact.
    expression.lhs, expression.rhs = lhs, rhs
    return expression
