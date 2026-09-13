"""Publish coordinate and declaration views of a proven call-addressed object.

Layer: Types/Lowering.
Responsibility: preserve exact machine-BP object coordinates when their angr
carrier uses entry-SP offsets and a narrower or coarser physical allocation.
Synchronize exact declaration entries with the already-proven object type.
Consumes alias, widening, and typed facts from call-output object recovery.
Do not recover semantics from COD, source, assembly, or rendered C text.
This records storage identity, not evidence that a callee initialized memory.
"""

from __future__ import annotations

from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_type import SimType
from angr.sim_variable import SimStackVariable, SimVariable

from ..pipeline.errors import PipelineHardError
from .stack_variable_coordinates import (
    StackCoordinateProducer8616,
    StackVariableCoordinateProjection8616,
    bind_stack_variable_coordinate_cvar_8616,
    record_stack_variable_coordinate_alias_8616,
    record_stack_variable_coordinate_projection_8616,
    stack_variable_coordinate_registry_8616,
)


class _DeclarationFunction8616(Protocol):
    """Angr declaration-cache boundary for already-proven object types."""

    unified_local_vars: dict[SimVariable, set[tuple[CVariable, SimType]]]


class _DeclarationCodegen8616(Protocol):
    """Codegen boundary exposing the function's declaration cache."""

    cfunc: _DeclarationFunction8616


def synchronize_call_output_object_declaration_8616(
    codegen: object, base: CVariable, type_: SimType,
) -> bool:
    """Update only exact object entries, preserving unrelated declaration facts."""
    try:
        declarations = cast(_DeclarationCodegen8616, codegen).cfunc.unified_local_vars
    except AttributeError:
        return False
    changed = False
    found = False
    for variable, entries in tuple(declarations.items()):
        rebound: set[tuple[CVariable, SimType]] = set()
        for cvar, previous_type in entries:
            if cvar.variable is base.variable:
                found = True
                rebound.add((cvar, type_))
            else:
                rebound.add((cvar, previous_type))
        if rebound != entries:
            declarations[variable] = rebound
            changed = True
    if not found:
        key = base.unified_variable if base.unified_variable is not None else base.variable
        declarations.setdefault(key, set()).add((base, type_))
        changed = True
    return changed


def publish_call_output_object_projection_8616(
    codegen: object,
    base: CVariable,
    *,
    bp_offset: int,
    byte_size: int,
) -> StackVariableCoordinateProjection8616:
    """Bind the exact call-source address and closed extent before field emission."""
    variable = base.variable
    if not isinstance(variable, SimStackVariable) or not isinstance(variable.offset, int) or byte_size <= 0:
        raise PipelineHardError("call-output object requires a concrete stack carrier and positive extent",
                                layer="types_lowering:call_output_object_projection")
    registry = stack_variable_coordinate_registry_8616(codegen)
    previous = registry.for_variable(variable)
    if previous is not None and previous.bp_offset != bp_offset:
        raise PipelineHardError("call-output object conflicts with its registered machine-BP coordinate",
                                layer="types_lowering:call_output_object_projection")
    canonical = registry.for_bp_range(bp_offset, byte_size)
    if canonical is None:
        return record_stack_variable_coordinate_projection_8616(
            codegen, variable=variable, cvar=base, bp_offset=bp_offset,
            entry_sp_offset=variable.offset, size=byte_size,
            producer=StackCoordinateProducer8616.CALL_OUTPUT_OBJECT,
        )
    record_stack_variable_coordinate_alias_8616(
        codegen, bp_offset=bp_offset, size=byte_size, variable=variable,
    )
    rebound = bind_stack_variable_coordinate_cvar_8616(
        codegen, bp_offset=bp_offset, size=byte_size, cvar=base,
        producer=StackCoordinateProducer8616.CALL_OUTPUT_OBJECT,
    )
    if rebound is None:
        raise PipelineHardError("call-output object lost its canonical projection during binding",
                                layer="types_lowering:call_output_object_projection")
    return rebound
