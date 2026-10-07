"""Project machine-BP ranges into angr entry-SP coordinates.

Layer: Types/Lowering.
Responsibility: consume the authoritative stack-variable registry or proven
frame coordinate to translate one exact machine-BP storage range. This module
does not infer frame shape from C, assembly text, names, or offsets alone.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from angr.sim_variable import SimStackVariable

from .stack_storage_evidence import proven_bp_entry_sp_delta_8616
from .stack_variable_coordinates import stack_variable_coordinate_registry_8616


def entry_sp_offset_for_machine_bp_range_8616(
    codegen: object,
    bp_offset: int,
    size: int,
) -> int | None:
    """Use an exact binding or typed frame proof, never extrapolate local views."""
    registry = stack_variable_coordinate_registry_8616(codegen)
    projection = registry.for_bp_range(
        bp_offset,
        size,
    )
    if projection is not None:
        entry_sp_offset = projection.entry_sp_offset
        return entry_sp_offset if isinstance(entry_sp_offset, int) else None
    # A per-object view is not a function-wide frame relation. In particular,
    # native saved-frame views can coexist with machine-BP local projections.
    delta = proven_bp_entry_sp_delta_8616(codegen)
    return bp_offset + delta if isinstance(delta, int) else None


def machine_bp_owner_for_entry_sp_view_8616(
    codegen: object,
    variable: SimStackVariable,
    owner_ranges: frozenset[tuple[int, int]],
) -> int | None:
    """Resolve an angr entry-SP view inside one unique proven BP owner range."""
    projection = stack_variable_coordinate_registry_8616(codegen).for_variable(
        variable
    )
    if projection is not None:
        return projection.bp_offset
    if (
        variable.base != "bp"
        or not isinstance(variable.offset, int)
        or not isinstance(variable.size, int)
        or variable.size <= 0
    ):
        return None
    delta = proven_bp_entry_sp_delta_8616(codegen)
    if not isinstance(delta, int):
        return None
    projected_offset = variable.offset - delta
    matches = tuple(
        bp_offset
        for bp_offset, size in owner_ranges
        if size > 0
        and bp_offset <= projected_offset
        and bp_offset + size >= projected_offset + variable.size
    )
    return matches[0] if len(matches) == 1 else None


__all__ = [
    "entry_sp_offset_for_machine_bp_range_8616",
    "machine_bp_owner_for_entry_sp_view_8616",
]
