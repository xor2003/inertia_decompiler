"""Resolve stored call-return operands for structured early exits.

Layer: Structuring.
Responsibility: lower one classified call-return condition to its active C stack object.
Consumes typed Lowering evidence and structured condition shape.
Do not recover call, alias, type, or return semantics from rendered text.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from typing import cast

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CVariable,
)
from angr.sim_variable import SimStackVariable

from inertia.ir.core import IRValue
from inertia.lowering.call_return_stack_conditions import (
    StoredCallReturnConditionEvidence8616,
    StoredCallReturnConditionKind8616,
)
from inertia.lowering.stack_variable_coordinates import (
    stack_cvar_for_machine_bp_range_8616,
)

from .condition_lowering import lower_ir_value_to_c_expr_8616


def _canonical_stack_offset_8616(offset: int) -> int:
    """Normalize one 16-bit BP displacement to its signed identity."""
    normalized = offset & 0xFFFF
    return normalized - 0x10000 if normalized >= 0x8000 else normalized


def _matches_stored_return_cvar_8616(
    operand: object,
    evidence: StoredCallReturnConditionEvidence8616,
) -> bool:
    """Match one active C stack object to the exact Lowering-owned store."""
    if not isinstance(operand, CVariable) or not isinstance(operand.variable, SimStackVariable):
        return False
    variable = operand.variable
    store = evidence.stack_store
    return (
        variable.base == "bp"
        and isinstance(variable.offset, int)
        and _canonical_stack_offset_8616(variable.offset)
        == _canonical_stack_offset_8616(store.dst_offset)
        and int(variable.size) == store.width
    )


def stored_return_operand_8616(
    condition: object,
    evidence: StoredCallReturnConditionEvidence8616,
    project: object,
    codegen: object,
) -> CVariable | None:
    """Return the exact active stack object from the inverted typed guard."""
    expected_op = "CmpNE" if evidence.kind is StoredCallReturnConditionKind8616.ZERO else "CmpEQ"
    if not isinstance(condition, CBinaryOp) or condition.op != expected_op:
        return None
    operands = (condition.lhs, condition.rhs)
    constants = tuple(
        operand for operand in operands if isinstance(operand, CConstant) and operand.value == 0
    )
    if len(constants) != 1:
        return None
    direct = tuple(
        operand
        for operand in operands
        if _matches_stored_return_cvar_8616(operand, evidence)
    )
    if len(direct) == 1:
        return cast(CVariable, direct[0])
    projected = stack_cvar_for_machine_bp_range_8616(
        codegen,
        evidence.stack_store.dst_offset,
        evidence.stack_store.width,
    )
    if isinstance(projected, CVariable):
        return projected
    lowered = tuple(
        lower_ir_value_to_c_expr_8616(value, project, codegen)
        for value in (evidence.condition.lhs, evidence.condition.rhs)
        if isinstance(value, IRValue)
    )
    matches = tuple(
        value for value in lowered if _matches_stored_return_cvar_8616(value, evidence)
    )
    return cast(CVariable, matches[0]) if len(matches) == 1 else None
