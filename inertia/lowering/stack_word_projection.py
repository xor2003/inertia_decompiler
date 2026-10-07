"""Recognize Alias-owned word values rebuilt from byte stack projections.

Layer: Types/Lowering.
Responsibility: map a side-effect-free low/high byte recomposition to the
canonical word CVariable recorded by stack coordinate Lowering. Storage
ownership comes only from that Alias-derived registry; this module does not
infer stack identity from names, rendered C, assembly text, or addresses.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable

from .stack_variable_coordinates import (
    StackVariableCoordinateProjection8616,
    stack_variable_coordinate_registry_8616,
)
from .stack_word_recomposition import recognize_stack_word_recomposition_8616


def stack_word_projection_owner_8616(
    codegen: object,
    node: object,
) -> structured_c.CVariable | None:
    """Return the exact Alias-owned word represented by two byte projections."""
    recomposition = recognize_stack_word_recomposition_8616(node)
    if recomposition is None or not isinstance(
        recomposition.low,
        structured_c.CVariable,
    ) or not isinstance(recomposition.high, structured_c.CVariable):
        return None
    registry = stack_variable_coordinate_registry_8616(codegen)
    low_variable = recomposition.low.variable
    high_variable = recomposition.high.variable
    if not isinstance(low_variable, SimStackVariable) or not isinstance(
        high_variable,
        SimStackVariable,
    ):
        return None
    if not isinstance(low_variable.offset, int) or not isinstance(
        high_variable.offset,
        int,
    ):
        return None
    projection = registry.containing_entry_sp_range(low_variable.offset, 1)
    if (
        projection is not None
        and _word_pair_shape_8616(projection, low_variable, high_variable)
        and isinstance(projection.cvar, structured_c.CVariable)
    ):
        return projection.cvar
    return None


def _word_pair_shape_8616(
    projection: StackVariableCoordinateProjection8616,
    low_variable: SimStackVariable,
    high_variable: SimStackVariable,
) -> bool:
    """Return whether one projection covers the proven byte pair exactly."""
    return (
        projection.size == 2
        and low_variable.offset == projection.entry_sp_offset
        and high_variable.offset == projection.entry_sp_offset + 1
        and high_variable.size == 1
    )


__all__ = ["stack_word_projection_owner_8616"]
