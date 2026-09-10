"""Classify runtime-GP projections of CALL stack execution carriers.

Layer: Types/Lowering.
Responsibility: recognize only the owned 16-bit SP subview write emitted when
GP-state lowering projects a machine CALL decrement into the 32-bit ESP lane.
Consumes alias, widening, and typed facts; it does not create those facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Typed runtime-GP ownership and exact frame width are required; this module does
not discover calls or remove statements.
Only an owned SP view or an existing stack object's address is a passive base.
Unknown arithmetic, calls and memory reads must survive rather than be discarded
with the consumed CALL carrier.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CUnaryOp,
    CVariable,
)
from angr.sim_variable import SimStackVariable

from .gp_register_state import runtime_gp_expression_view_8616

__all__ = ["is_runtime_sp_call_decrement_8616"]


def _masked_operand_8616(expression: object, mask: int) -> object | None:
    """Return the value under one exact generated runtime-lane mask."""
    if not (
        isinstance(expression, CBinaryOp)
        and expression.op == "And"
        and isinstance(expression.rhs, CConstant)
        and expression.rhs.value == mask
    ):
        return None
    operand: object = expression.lhs
    return operand


def is_runtime_sp_call_decrement_8616(
    assignment: CAssignment,
    return_frame_width: int,
) -> bool:
    """Recognize this owner's 16-bit ESP write for one CALL decrement."""
    lhs_view = runtime_gp_expression_view_8616(assignment.lhs)
    rhs = assignment.rhs
    if not (
        lhs_view is not None
        and lhs_view.parent_name == "esp"
        and lhs_view.width == 4
        and isinstance(rhs, CBinaryOp)
        and rhs.op == "Or"
    ):
        return False
    preserved = _masked_operand_8616(rhs.lhs, 0xFFFF0000)
    inserted = _masked_operand_8616(rhs.rhs, 0xFFFF)
    preserved_view = runtime_gp_expression_view_8616(preserved)
    return bool(
        preserved_view is not None
        and preserved_view.parent_name == "esp"
        and preserved_view.width == 4
        and isinstance(inserted, CBinaryOp)
        and inserted.op == "Sub"
        and _passive_stack_base_8616(inserted.lhs)
        and isinstance(inserted.rhs, CConstant)
        and inserted.rhs.value == return_frame_width
    )


def _passive_stack_base_8616(expression: object) -> bool:
    """Require a bounded stack base with no nested evaluation effects."""
    view = runtime_gp_expression_view_8616(expression)
    if view is not None:
        return view.parent_name == "esp" and view.bit_shift == 0 and view.width in {2, 4}
    return bool(
        isinstance(expression, CUnaryOp)
        and expression.op == "Reference"
        and isinstance(expression.operand, CVariable)
        and isinstance(expression.operand.variable, SimStackVariable)
    )
