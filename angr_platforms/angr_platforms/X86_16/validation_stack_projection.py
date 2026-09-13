"""Consume exact stack projection facts during final validation.

Layer: Tail validation.
Responsibility: validate the typed stack-owner/view contract published by
Types/Lowering and expose only contained BP-relative views to validation
consumers. This module does not infer projections from rendered expressions.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable

from .lowering.condition_stack_projection_contracts import (
    ConditionStackProjectionFact8616,
    condition_stack_projection_fact_8616,
)
from .lowering.stack_variable_coordinates import machine_bp_offset_for_stack_variable_8616

_BITS_PER_BYTE = 8


def validated_stack_projection_fact_8616(
    expression: object,
) -> ConditionStackProjectionFact8616 | None:
    """Return one internally consistent BP-relative projection fact."""
    if not isinstance(expression, structured_c.CExpression):
        return None
    fact = condition_stack_projection_fact_8616(expression)
    if fact is None:
        return None
    if (
        fact.base != "bp"
        or fact.owner_size <= 0
        or fact.view_size <= 0
        or fact.view_offset < fact.owner_offset
        or fact.view_offset + fact.view_size > fact.owner_offset + fact.owner_size
    ):
        return None
    return fact


def proven_stack_projection_fingerprint_8616(expression: object) -> str | None:
    """Identify a contained word only when its AST implements the typed view."""
    fact = validated_stack_projection_fact_8616(expression)
    if fact is None or not isinstance(expression, structured_c.CBinaryOp):
        return None
    mask = expression.rhs
    expected_mask = (1 << (fact.view_size * _BITS_PER_BYTE)) - 1
    if expression.op != "And" or not isinstance(mask, structured_c.CConstant) or mask.value != expected_mask:
        return None
    owner = expression.lhs
    shift_bits = (fact.view_offset - fact.owner_offset) * _BITS_PER_BYTE
    if shift_bits:
        if not isinstance(owner, structured_c.CBinaryOp) or owner.op != "Shr":
            return None
        shift = owner.rhs
        if not isinstance(shift, structured_c.CConstant) or shift.value != shift_bits:
            return None
        owner = owner.lhs
    if not isinstance(owner, structured_c.CVariable) or not isinstance(owner.variable, SimStackVariable):
        return None
    variable = owner.variable
    if variable.base != "bp" or variable.size != fact.owner_size:
        return None
    if machine_bp_offset_for_stack_variable_8616(owner.codegen, variable) != fact.owner_offset:
        return None
    # A stale narrowed C type could discard the high word before the shift.
    if owner.variable_type is None or owner.variable_type.size != fact.owner_size * _BITS_PER_BYTE:
        return None
    return f"stack_slot:SS:BP{fact.view_offset:+#x}:size{fact.view_size}"


__all__ = ["proven_stack_projection_fingerprint_8616", "validated_stack_projection_fact_8616"]
