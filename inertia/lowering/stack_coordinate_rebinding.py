# cython: language_level=3, infer_types=True
"""Rebind and scope stack-coordinate projections across Lowering replays.

Layer: Types/Lowering.
Responsibility: reconcile the machine-BP/entry-SP registry with live angr
``CVariable`` objects after validation rollback deep-copies the C AST, and
refresh only the coordinate ranges owned by a partial Lowering producer.
Consumes only typed coordinate projections and structured AST identity. It
does not infer new stack storage or inspect rendered text.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616

from .stack_variable_coordinates import (
    StackCoordinateProducer8616,
    StackVariableCoordinateProjection8616,
    record_stack_variable_coordinate_alias_8616,
    record_stack_variable_coordinate_projection_8616,
    reset_stack_variable_coordinate_registry_8616,
    stack_variable_coordinate_registry_8616,
)
import dataclasses
import operator
import builtins


class StackCoordinateRebindRefusal8616(StrEnum):
    """Reason one live AST projection could not be selected safely."""

    AMBIGUOUS_NAME = "ambiguous_name"


@dataclasses.dataclass(frozen=True, )
class StackCoordinateRebindReport8616:
    """Closed evidence loop for one restored coordinate registry."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    refusals: tuple[StackCoordinateRebindRefusal8616, ...] = ()

    @property
    def failure_count(self) -> cython.longlong:
        """Return classified projections that were not rebound."""
        return self.classified_fact_count - self.materialized_count


def _projection_idents_8616(
    projection: StackVariableCoordinateProjection8616,
) -> frozenset[int | str]:
    """Return durable non-empty angr identifiers from one projection."""
    return frozenset(
        variable.ident
        for variable in iter((projection.variable, ) + tuple(projection.equivalent_variables))
        if isinstance(variable.ident, (int, str)) and variable.ident != ""
    )


def _numeric_projection_candidates_8616(
    projection: StackVariableCoordinateProjection8616,
    cvars: object,
) -> tuple[structured_c.CVariable, ...]:
    """Return full entry-SP views or exact recorded narrow-backing clones."""
    return tuple(
        cvar
        for cvar in iter(cvars)
        if isinstance(cvar.variable, SimStackVariable)
        and (
            (
                operator.eq(cvar.variable.offset, projection.entry_sp_offset)
                and operator.eq(cvar.variable.size, projection.size)
            )
            or _matches_recorded_backing_view_8616(projection, cvar.variable)
        )
    )


def _matches_recorded_backing_view_8616(
    projection: StackVariableCoordinateProjection8616,
    variable: SimStackVariable,
) -> cython.bint:
    """Match a clone to one explicit backing view without inventing coordinates."""
    return any(
        isinstance(recorded.ident, (int, str))
        and recorded.ident != ""
        and operator.eq(variable.ident, recorded.ident)
        and operator.eq(variable.base, recorded.base)
        and operator.eq(variable.offset, recorded.offset)
        and operator.eq(variable.size, recorded.size)
        for recorded in iter((projection.variable, ) + tuple(projection.equivalent_variables))
    )


def _live_projection_cvars_8616(
    projection: StackVariableCoordinateProjection8616,
    cvars: object,
) -> object:
    """Select exact restored identities, falling back to one unique name."""
    candidates = _numeric_projection_candidates_8616(projection, cvars)
    idents = _projection_idents_8616(projection)
    identified = tuple(
        cvar
        for cvar in iter(candidates)
        if isinstance(cvar.variable, SimStackVariable)
        and cvar.variable.ident in idents
    )
    if identified:
        return identified
    if not projection.display_name:
        return ()
    named = tuple(
        cvar
        for cvar in iter(candidates)
        if isinstance(cvar.variable, SimStackVariable)
        and operator.eq(cvar.variable.name, projection.display_name)
    )
    named_variable_ids = {id(cvar.variable) for cvar in iter(named)}
    return named if len(named_variable_ids) == 1 else ()


@cython.ccall
def _retain_projection_8616(
    codegen: object,
    projection: StackVariableCoordinateProjection8616,
) -> None:
    """Retain an unused projection when no live AST identity is present."""
    variable: object
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=projection.variable,
        cvar=projection.cvar,
        bp_offset=projection.bp_offset,
        entry_sp_offset=projection.entry_sp_offset,
        size=projection.size,
        display_name=projection.display_name,
        producer=projection.producer,
    )
    for variable in projection.equivalent_variables:
        record_stack_variable_coordinate_alias_8616(
            codegen,
            bp_offset=projection.bp_offset,
            size=projection.size,
            variable=variable,
        )


def reset_local_stack_coordinate_projections_8616(
    codegen: object, *, replaced_bp_ranges: object,
) -> None:
    """Drop local projections while preserving nonlocal coordinate owners.

    Stack-memory SSA materializes only negative-BP local ranges. Its replay
    must not erase unrelated locals, positive-BP arguments or call-output
    objects. Ranges are machine-BP identities, never raw variable offsets.
    """
    projection: object
    registry = stack_variable_coordinate_registry_8616(codegen)
    retained = tuple(
        projection for projection in iter(registry.projections)
        if projection.bp_offset >= 0 or projection.producer is not StackCoordinateProducer8616.STACK_STORAGE
        or (projection.bp_offset, projection.size) not in replaced_bp_ranges
    )
    reset_stack_variable_coordinate_registry_8616(codegen)
    for projection in retained:
        _retain_projection_8616(codegen, projection)


def rebind_restored_stack_coordinate_registry_8616(
    codegen: object,
    root: object,
) -> StackCoordinateRebindReport8616:
    """Rebind registry entries to exact C variables in restored AST roots."""
    cvar: object
    projection: object
    registry = stack_variable_coordinate_registry_8616(codegen)
    roots = tuple(root) if isinstance(root, (list, tuple)) else (root,)
    seen: set[cython.longlong] = set()
    cvars = tuple(
        node
        for candidate in iter(roots)
        for node in builtins.iter(_iter_c_nodes_deep_8616(candidate, seen))
        if isinstance(node, structured_c.CVariable)
    )
    normalized = 0
    classified = 0
    materialized = 0
    refusals: list[StackCoordinateRebindRefusal8616] = []
    reset_stack_variable_coordinate_registry_8616(codegen)
    for projection in registry.projections:
        numeric_candidates = _numeric_projection_candidates_8616(projection, cvars)
        if numeric_candidates:
            normalized += 1
        live_cvars = _live_projection_cvars_8616(projection, cvars)
        if not live_cvars:
            if numeric_candidates and not _projection_idents_8616(projection):
                classified += 1
                refusals.append(StackCoordinateRebindRefusal8616.AMBIGUOUS_NAME)
            _retain_projection_8616(codegen, projection)
            continue
        classified += 1
        selected = live_cvars[0]
        variable = selected.variable
        if not isinstance(variable, SimStackVariable):
            _retain_projection_8616(codegen, projection)
            continue
        record_stack_variable_coordinate_projection_8616(
            codegen,
            variable=variable,
            cvar=selected,
            bp_offset=projection.bp_offset,
            entry_sp_offset=projection.entry_sp_offset,
            size=projection.size,
            display_name=projection.display_name or variable.name,
            producer=projection.producer,
        )
        for cvar in live_cvars[1:]:
            alias = cvar.variable
            if isinstance(alias, SimStackVariable) and alias is not variable:
                record_stack_variable_coordinate_alias_8616(
                    codegen,
                    bp_offset=projection.bp_offset,
                    size=projection.size,
                    variable=alias,
                )
        materialized += 1
    return StackCoordinateRebindReport8616(
        raw_fact_count=len(registry.projections),
        normalized_fact_count=normalized,
        classified_fact_count=classified,
        materialized_count=materialized,
        refusals=tuple(refusals),
    )


__all__ = [
    "StackCoordinateRebindRefusal8616",
    "StackCoordinateRebindReport8616",
    "rebind_restored_stack_coordinate_registry_8616",
    "reset_local_stack_coordinate_projections_8616",
]
