"""Replay proven call-output stack-object types after AST regeneration.

Layer: Types/Lowering.
Responsibility: rebind persisted call-output object facts to the exact current
call argument and restore its struct type after call arguments are rebuilt.
Consumes alias, widening, and typed facts; it does not create those facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CVariable, CVariableField
from angr.sim_type import SimStruct
from angr.sim_variable import SimStackVariable

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.pipeline.errors import PipelineHardError

from .call_output_stack_objects import (
    CallOutputStackObjectFact8616,
    CallOutputStackObjectStats8616,
    _aggregate_boundaries_8616,
    _call_addressed_bases_8616,
    _CallOutputCodegen8616,
    _prepare_object_type_8616,
    _struct_type_for_fact_8616,
)

__all__ = ["reapply_call_output_stack_object_types_8616"]


class _CallOutputReplayCodegen8616(_CallOutputCodegen8616, Protocol):
    """Owned replay metadata published on the dynamic angr codegen object."""

    _inertia_call_output_stack_object_type_replay_stats_8616: CallOutputStackObjectStats8616


def _all_field_projections_present_8616(
    codegen: _CallOutputReplayCodegen8616,
    fact: CallOutputStackObjectFact8616,
    base_variable: SimStackVariable,
) -> bool:
    """Prove that every persisted field still exists on the rebound base."""
    expected = {(field.relative_offset, field.name) for field in fact.fields}
    observed: set[tuple[int, str]] = set()
    for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements):
        if not isinstance(node, CVariableField) or node.var_is_ptr:
            continue
        base = node.variable
        if not isinstance(base, CVariable) or base.variable is not base_variable:
            continue
        field_offset = node.field.offset
        field_name = node.field.field
        if isinstance(field_offset, int) and isinstance(field_name, str):
            observed.add((field_offset, field_name))
    return bool(expected) and expected <= observed


def reapply_call_output_stack_object_types_8616(codegen: object) -> bool:
    """Restore exact persisted call-output object types after regeneration."""
    boundary = cast(_CallOutputReplayCodegen8616, codegen)
    try:
        facts = boundary._inertia_call_output_stack_object_facts_8616
        call_bases = _call_addressed_bases_8616(boundary)
        aggregate_boundaries = _aggregate_boundaries_8616(
            boundary,
            boundary.cfunc.statements,
        )
    except AttributeError:
        return False

    normalized = 0
    materialized = 0
    changed = False
    rebound_facts: list[CallOutputStackObjectFact8616] = []
    for fact in facts:
        matching = tuple(
            base
            for base in call_bases
            if base.callsite_addr == fact.callsite_addr
            and base.base_offset == fact.base_offset
            and base.base_cvar is not None
        )
        if len(matching) != 1:
            rebound_facts.append(fact)
            continue
        current_base = matching[0].base_cvar
        if current_base is None:
            rebound_facts.append(fact)
            continue
        current_variable = current_base.variable
        if not isinstance(current_variable, SimStackVariable):
            rebound_facts.append(fact)
            continue
        rebound = CallOutputStackObjectFact8616(
            callsite_addr=fact.callsite_addr,
            base_offset=fact.base_offset,
            boundary_offset=fact.boundary_offset,
            base_variable=current_variable,
            base_cvar=current_base,
            fields=fact.fields,
        )
        has_inner_boundary = any(
            fact.base_offset < boundary_offset < fact.boundary_offset
            for boundary_offset in aggregate_boundaries
        )
        if has_inner_boundary or not _all_field_projections_present_8616(
            boundary,
            rebound,
            current_variable,
        ):
            rebound_facts.append(fact)
            continue
        normalized += 1
        struct_type = _struct_type_for_fact_8616(rebound)
        was_materialized = (
            isinstance(current_base.variable_type, SimStruct)
            and current_base.variable_type.name == struct_type.name
        )
        declarations_changed = _prepare_object_type_8616(boundary, rebound, struct_type)
        if isinstance(current_base.variable_type, SimStruct):
            materialized += 1
            changed = changed or not was_materialized or declarations_changed
        rebound_facts.append(rebound)

    stats = CallOutputStackObjectStats8616(
        raw_fact_count=len(facts),
        normalized_fact_count=normalized,
        classified_fact_count=normalized,
        materialized_count=materialized,
        failure_count=max(len(facts) - normalized, 0)
        + max(normalized - materialized, 0),
    )
    boundary._inertia_call_output_stack_object_type_replay_stats_8616 = stats
    boundary._inertia_call_output_stack_object_facts_8616 = tuple(rebound_facts)
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError(
            "classified call-output stack-object types were not replayed",
            layer="types_lowering:call_output_stack_object_replay",
        )
    return changed
