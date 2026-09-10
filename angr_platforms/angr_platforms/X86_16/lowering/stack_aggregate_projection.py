"""Layer: Types/Lowering.

Responsibility: preserve a proven aggregate's canonical coordinate during replay.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Candidates must already be proven views of the same machine-BP object.
"""

from __future__ import annotations

from collections.abc import MutableMapping
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_type import SimTypeFixedSizeArray
from angr.sim_variable import SimStackVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616, _replace_c_children_8616
from .stack_variable_coordinates import (
    bind_stack_variable_coordinate_cvar_8616,
    record_stack_variable_coordinate_alias_8616,
    record_stack_variable_coordinate_projection_8616,
    stack_variable_coordinate_registry_8616,
)


def select_stack_aggregate_projection_8616(
    codegen: object,
    candidates: list[CVariable],
    tracked: CVariable | None,
    *,
    bp_offset: int,
    entry_sp_offset: int | None,
    size: int,
) -> CVariable:
    """Select a current proven view without erasing a canonical projection.

    Multiple entry-SP views share the caller-proven machine-BP identity; their
    multiplicity must not force a fallback to a raw-BP coordinate spelling.
    """
    if not candidates:
        raise ValueError("aggregate selection requires a current proven candidate")
    projection = stack_variable_coordinate_registry_8616(codegen).for_bp_range(bp_offset, size)
    canonical: CVariable | None = next(
        (candidate for candidate in candidates if projection is not None and candidate is projection.cvar),
        None,
    )
    entry_views: tuple[CVariable, ...] = tuple(
        candidate for candidate in candidates
        if isinstance(candidate.variable, SimStackVariable)
        and candidate.variable.offset == entry_sp_offset
    )
    selected: CVariable = canonical or (entry_views[0] if entry_views else tracked) or candidates[0]
    variable = selected.variable
    if not isinstance(variable, SimStackVariable) or entry_sp_offset is None:
        return selected
    if projection is not None and projection.entry_sp_offset == entry_sp_offset:
        record_stack_variable_coordinate_alias_8616(
            codegen, bp_offset=bp_offset, size=size, variable=variable,
        )
        bind_stack_variable_coordinate_cvar_8616(
            codegen, bp_offset=bp_offset, size=size, cvar=selected,
            display_name=variable.name,
        )
    else:
        record_stack_variable_coordinate_projection_8616(
            codegen, variable=variable, cvar=selected, bp_offset=bp_offset,
            entry_sp_offset=entry_sp_offset, size=size, display_name=variable.name,
        )
    return selected


@dataclass(frozen=True, slots=True)
class StackAggregateViewRebindReport8616:
    """Closed evidence counters for canonical aggregate AST references."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int = 0


class _AggregateFunctionBoundary8616(Protocol):
    """Third-party AST and declaration inventories sharing aggregate views."""

    addr: int
    statements: object
    variables_in_use: MutableMapping[object, object]
    unified_local_vars: MutableMapping[object, object]


class _AggregateViewBoundary8616(Protocol):
    """Codegen boundary publishing owned aggregate rebinding evidence."""

    cfunc: _AggregateFunctionBoundary8616
    _inertia_stack_aggregate_view_rebind_8616: StackAggregateViewRebindReport8616


def restore_live_stack_aggregate_declaration_8616(
    codegen: object,
    tracked: object,
    *,
    bp_offset: int,
    entry_sp_offset: int | None,
    size: int,
) -> bool:
    """Restore a live aggregate's declaration or lost coordinate projection.

    A copied private cache alone is insufficient. Require the exact tracked
    variable object in the current AST or exact tracked declaration, its
    function region and proven aggregate width, and the current producer's
    entry-SP coordinate. A narrower angr backing allocation is permitted only
    with the exact already-materialized array type. No name or offset-based
    variable join is performed.
    """
    if not isinstance(tracked, CVariable) or not isinstance(tracked.variable, SimStackVariable):
        return False
    boundary = cast(_AggregateViewBoundary8616, codegen)
    variable = tracked.variable
    array_type = tracked.variable_type
    width_matches = variable.size == size or (
        isinstance(variable.size, int) and 0 < variable.size < size
        and isinstance(array_type, SimTypeFixedSizeArray) and array_type.size == size * 8
    )
    try:
        function = boundary.cfunc
        root = function.statements
    except AttributeError:
        return False
    if (
        entry_sp_offset is None or variable.base != "bp" or variable.offset != entry_sp_offset
        or not width_matches or variable.region != function.addr
    ):
        return False
    declared = any(value is tracked for value in function.variables_in_use.values())
    existing = stack_variable_coordinate_registry_8616(codegen).for_variable(variable)
    if declared and existing is not None and (
        existing.bp_offset == bp_offset and existing.entry_sp_offset == entry_sp_offset and existing.size == size
    ):
        return False
    live = tracked if declared else next((
        node for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CVariable) and node.variable is variable
    ), None)
    if live is None:
        return False
    select_stack_aggregate_projection_8616(
        codegen, [live], live, bp_offset=bp_offset, size=size, entry_sp_offset=entry_sp_offset,
    )
    function.variables_in_use[variable] = live
    return True


def rebind_stack_aggregate_views_8616(
    codegen: object,
    candidates: list[CVariable],
    canonical: CVariable,
) -> StackAggregateViewRebindReport8616:
    """Unify caller-proven aggregate views without reinterpreting other storage.

    The caller must already establish one frame partition and apply its array
    type to every candidate. Preserve reference-site tags while replacing the
    variable identity, then retire only those consumed alias declarations.
    """
    boundary = cast(_AggregateViewBoundary8616, codegen)
    aliases = {
        id(candidate.variable): candidate.variable
        for candidate in candidates
        if candidate.variable is not canonical.variable
    }
    replaced: set[int] = set()
    consumed: set[int] = set()

    def transform(node: object) -> object:
        """Replace only exact variable identities proven by aggregate recovery."""
        if not isinstance(node, CVariable) or id(node.variable) not in aliases:
            return node
        replaced.add(id(node))
        consumed.add(id(node.variable))
        return CVariable(
            canonical.variable,
            unified_variable=canonical.unified_variable,
            variable_type=canonical.variable_type,
            vvar_id=canonical.vvar_id,
            tags=node.tags,
            codegen=codegen,
        )

    try:
        root = boundary.cfunc.statements
    except AttributeError:
        root = None
    if root is not None:
        _replace_c_children_8616(root, transform)
    for variable_id in consumed:
        variable = aliases[variable_id]
        boundary.cfunc.variables_in_use.pop(variable, None)
        boundary.cfunc.unified_local_vars.pop(variable, None)
    count = len(replaced)
    report = StackAggregateViewRebindReport8616(count, count, count, count)
    boundary._inertia_stack_aggregate_view_rebind_8616 = report
    return report
