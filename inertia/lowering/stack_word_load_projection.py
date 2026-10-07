"""Resolve Alias-proven stack word loads to canonical C variables.

Layer: Types/Lowering.
Responsibility: join an exact Alias ``SS:BP`` range with the proven frame
coordinate and angr's entry-SP argument view, then materialize one canonical
word CVariable. This module does not infer storage from rendered C syntax.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable
from inertia.ir.analysis.stack_frame_ir import FrameAccessArtifact, FrameCoordinateStatus8616

from inertia.alias.stack_memory_ssa_contracts import StackMemorySSAAliasArtifact8616
from inertia.ir.core import MemSpace
from inertia.ir.logical_memory_contracts import IRMemoryAccessKind8616

from .stack_lowering_from_facts import materialize_stack_cvar_at_offset_from_facts_8616
from .stack_variable_coordinates import stack_variable_coordinate_registry_8616


class StackWordLoadProjectionStatus8616(StrEnum):
    """Typed outcome of resolving one Alias-proven stack word range."""

    EXISTING = "existing"
    MATERIALIZED = "materialized"
    FRAME_UNPROVEN = "frame_unproven"
    VARIABLE_MISMATCH = "variable_mismatch"
    MATERIALIZATION_FAILED = "materialization_failed"
    PROJECTION_MISMATCH = "projection_mismatch"


@dataclass(frozen=True, slots=True)
class StackWordLoadProjectionResult8616:
    """Canonical word CVariable or an exact typed refusal."""

    status: StackWordLoadProjectionStatus8616
    cvar: structured_c.CVariable | None = None
    detail: str = ""

    @property
    def resolved(self) -> bool:
        """Return whether an existing or newly materialized owner was proven."""
        return self.cvar is not None and self.status in {
            StackWordLoadProjectionStatus8616.EXISTING,
            StackWordLoadProjectionStatus8616.MATERIALIZED,
        }


class _CodegenBoundary8616(Protocol):
    """Dynamic angr codegen boundary carrying the typed frame artifact."""

    _inertia_vex_ir_frame: object


def _exact_projection_cvar_8616(
    codegen: object,
    variable: SimStackVariable,
    bp_offset: int,
    size: int,
) -> structured_c.CVariable | None:
    """Return the C owner only when every stored coordinate agrees."""
    projection = stack_variable_coordinate_registry_8616(codegen).for_variable(variable)
    if (
        projection is not None
        and projection.bp_offset == bp_offset
        and projection.entry_sp_offset == variable.offset
        and projection.size == size
        and isinstance(projection.cvar, structured_c.CVariable)
    ):
        return projection.cvar
    return None


def resolve_stack_word_load_projection_8616(
    codegen: object,
    variable: SimStackVariable,
    *,
    bp_offset: int,
    size: int,
) -> StackWordLoadProjectionResult8616:
    """Resolve a word load through exact Alias and frame coordinates only."""
    existing = _exact_projection_cvar_8616(codegen, variable, bp_offset, size)
    if existing is not None:
        return StackWordLoadProjectionResult8616(
            StackWordLoadProjectionStatus8616.EXISTING,
            existing,
        )

    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        frame = boundary._inertia_vex_ir_frame
    except AttributeError:
        frame = None
    if (
        not isinstance(frame, FrameAccessArtifact)
        or not frame.bp_coordinate.complete
        or frame.bp_coordinate.status is not FrameCoordinateStatus8616.PROVEN
        or not isinstance(frame.bp_coordinate.bp_entry_sp_delta, int)
    ):
        return StackWordLoadProjectionResult8616(
            StackWordLoadProjectionStatus8616.FRAME_UNPROVEN,
            detail="exact BP-to-entry-SP frame coordinate is unavailable",
        )

    entry_sp_offset = bp_offset + frame.bp_coordinate.bp_entry_sp_delta
    if variable.base != "bp" or variable.offset != entry_sp_offset:
        return StackWordLoadProjectionResult8616(
            StackWordLoadProjectionStatus8616.VARIABLE_MISMATCH,
            detail=(
                f"expected entry-SP offset {entry_sp_offset!r}, "
                f"found {(variable.base, variable.offset)!r}"
            ),
        )

    materialized = materialize_stack_cvar_at_offset_from_facts_8616(
        codegen,
        entry_sp_offset,
        size,
        machine_bp_offset=bp_offset,
        preferred_name=variable.name,
    )
    if not isinstance(materialized, structured_c.CVariable):
        return StackWordLoadProjectionResult8616(
            StackWordLoadProjectionStatus8616.MATERIALIZATION_FAILED,
            detail="canonical stack CVariable materialization failed",
        )
    result = _exact_projection_cvar_8616(
        codegen,
        materialized.variable,
        bp_offset,
        size,
    )
    if result is None:
        return StackWordLoadProjectionResult8616(
            StackWordLoadProjectionStatus8616.PROJECTION_MISMATCH,
            detail="materialized CVariable did not publish the exact coordinate",
        )
    return StackWordLoadProjectionResult8616(
        StackWordLoadProjectionStatus8616.MATERIALIZED,
        result,
    )


def resolve_logical_stack_word_owner_8616(
    codegen: object,
    source_alias: StackMemorySSAAliasArtifact8616,
    low: structured_c.CVariable,
    high: object,
) -> StackWordLoadProjectionResult8616:
    """Resolve an instructionless same-owner word from exact logical Alias IR."""
    variable = low.variable
    if (
        not isinstance(high, structured_c.CVariable)
        or high is not low
        or not isinstance(variable, SimStackVariable)
        or high.variable is not variable
    ):
        return StackWordLoadProjectionResult8616(
            StackWordLoadProjectionStatus8616.VARIABLE_MISMATCH,
            detail="byte views are not the same canonical stack CVariable",
        )
    projection = stack_variable_coordinate_registry_8616(codegen).for_variable(variable)
    if (
        projection is None
        or projection.size != 2
        or projection.cvar is not low
        or variable.size != 2
    ):
        return StackWordLoadProjectionResult8616(
            StackWordLoadProjectionStatus8616.PROJECTION_MISMATCH,
            detail="same-owner byte views lack one exact two-byte stack projection",
        )
    matches = tuple(
        identity
        for identity in source_alias.logical_storage_identities
        if identity.source.kind is IRMemoryAccessKind8616.READ
        and identity.address.space is MemSpace.SS
        and identity.address.base == ("bp",)
        and identity.address.offset == projection.bp_offset
        and identity.address.size == projection.size
    )
    if not source_alias.logical_storage_complete or len(matches) != 1:
        return StackWordLoadProjectionResult8616(
            StackWordLoadProjectionStatus8616.PROJECTION_MISMATCH,
            detail=(
                "logical Alias storage is incomplete"
                if not source_alias.logical_storage_complete
                else f"expected one logical word read, found {len(matches)}"
            ),
        )
    return StackWordLoadProjectionResult8616(
        StackWordLoadProjectionStatus8616.EXISTING,
        low,
    )


__all__ = [
    "StackWordLoadProjectionResult8616",
    "StackWordLoadProjectionStatus8616",
    "resolve_logical_stack_word_owner_8616",
    "resolve_stack_word_load_projection_8616",
]
