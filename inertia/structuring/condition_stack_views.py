"""Materialize typed condition views over proven stack declarations.

Layer: Structuring.
Responsibility: map structured C stack snapshots onto the machine-BP identity
owned by Types/Lowering before a proven condition is rendered.
Do not infer stack coordinates, signedness, or condition semantics here.

Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence. Do not perform alias-state ownership, widening,
type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable

from inertia.lowering.condition_stack_operands import (
    materialize_typed_condition_stack_operand_8616,
)
from inertia.lowering.stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
)


def materialize_condition_stack_declaration_view_8616(
    codegen: object,
    declaration: structured_c.CVariable,
    *,
    signed: bool,
) -> structured_c.CExpression | None:
    """Return a typed view without confusing entry-SP and machine-BP offsets."""
    variable = declaration.variable
    if not isinstance(variable, SimStackVariable) or not isinstance(variable.size, int):
        return None
    stack_offset = (
        machine_bp_offset_for_stack_variable_8616(codegen, variable)
        if variable.base == "bp"
        else variable.offset
    )
    if not isinstance(stack_offset, int):
        return None
    return materialize_typed_condition_stack_operand_8616(
        codegen,
        base=variable.base,
        offset=stack_offset,
        size=max(variable.size, 1),
        name=declaration.name,
        signed=signed,
        prefer_signed_local_storage=signed,
        tags=dict(declaration.tags),
        preferred=declaration,
    )


__all__ = ["materialize_condition_stack_declaration_view_8616"]
