# cython: language_level=3, infer_types=True
"""Lower binary-proven fixed stack probes into recovered BP-local frame objects.

Layer: Types/Lowering.
Responsibility: remove an unused compiler stack-probe call statement only when
typed callsite evidence proves a fixed allocation covered by recovered BP locals.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Forbidden: helper-name matching, source/COD evidence, rendered-C matching, or
removing dynamic probes and used helper return values.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.sim_variable import SimStackVariable

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.pipeline.errors import PipelineHardError
from inertia.semantics.callsite_summary import CallsiteSummary8616
import dataclasses
import operator
import builtins

__all__ = [
    "FixedStackProbeFrameLoweringStats8616",
    "lower_fixed_stack_probe_frames_8616",
]


@dataclasses.dataclass(frozen=True, )
class FixedStackProbeFrameLoweringStats8616:
    """Closed evidence census for fixed stack-probe frame lowering."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong
    refused_fact_count: cython.longlong
    recovered_frame_extent: cython.longlong

    @property
    def changed(self) -> cython.bint:
        """Return whether at least one compiler probe statement was removed."""
        return self.materialized_count > 0


@dataclasses.dataclass(frozen=True, )
class _FixedStackProbeSurface8616:
    """One request-local census of the structured surfaces used by this owner."""

    frame_extent: cython.longlong
    containers: object
    live_call_ids: object
    statement_occurrences: object


@cython.ccall
def _dynamic_codegen_attr_8616(obj: object, name: object, default: object = None) -> Any:  # noqa: ANN401
    """Read optional metadata across the dynamic third-party angr codegen boundary."""
    return getattr(obj, name, default)


@cython.ccall
def _structured_root_8616(codegen: object) -> object | None:
    """Return the live structured C root across supported angr codegen shapes."""
    cfunc: object
    statements: object
    cfunc = _dynamic_codegen_attr_8616(codegen, "cfunc", None)
    if cfunc is None:
        return None
    statements = _dynamic_codegen_attr_8616(cfunc, "statements", None)
    if statements is not None:
        return cast(object, statements)
    return cast(object, _dynamic_codegen_attr_8616(cfunc, "body", None))


@cython.ccall
def _collect_fixed_stack_probe_surface_8616(
    root: object,
) -> _FixedStackProbeSurface8616:
    """Collect every read-only AST projection needed by fixed-probe lowering."""
    call: object
    node: object
    statement: object
    extent = 0
    containers: list[CStatements] = []
    live_call_ids: set[cython.longlong] = set()
    statement_occurrences: dict[cython.longlong, cython.longlong] = {}
    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, CVariable):
            variable = node.variable
            offset = variable.offset if isinstance(variable, SimStackVariable) else None
            if isinstance(offset, int) and offset < 0:
                extent = max(extent, -offset)
        if isinstance(node, CFunctionCall):
            live_call_ids.add(id(node))
        if not isinstance(node, CStatements):
            continue
        containers.append(node)
        for statement in tuple(node.statements or ()):
            call = _probe_call_statement_8616(statement)
            if call is None:
                continue
            call_id = id(call)
            statement_occurrences[call_id] = statement_occurrences.get(call_id, 0) + 1
    return _FixedStackProbeSurface8616(
        frame_extent=extent,
        containers=tuple(containers),
        live_call_ids=frozenset(live_call_ids),
        statement_occurrences=tuple(sorted(tuple(statement_occurrences.items()))),
    )


@cython.ccall
def _probe_call_statement_8616(statement: object) -> CFunctionCall | None:
    """Return a direct call statement without interpreting its rendered name."""
    if isinstance(statement, CExpressionStatement):
        expression = statement.expr
        return expression if isinstance(expression, CFunctionCall) else None
    if isinstance(statement, CAssignment):
        return statement.rhs if isinstance(statement.rhs, CFunctionCall) else None
    return None


@cython.ccall
def _probe_summary_map_8616(codegen: object) -> dict[cython.longlong, CallsiteSummary8616]:
    """Return only stack-probe callsite summaries published on the codegen."""
    summary_map_raw = _dynamic_codegen_attr_8616(codegen, "_inertia_callsite_summaries", None)
    if not isinstance(summary_map_raw, dict):
        return {}
    return {
        node_id: summary
        for node_id, summary in builtins.iter(summary_map_raw.items())
        if isinstance(node_id, int)
        and isinstance(summary, CallsiteSummary8616)
        and summary.stack_probe_helper
    }


@cython.ccall
def _classified_probe_ids_8616(
    probe_summaries: object,
    statement_occurrences: object,
    frame_extent: cython.longlong,
) -> object:
    """Classify probe calls proven fixed, unused, and covered by BP locals."""
    node_id: object
    summary: object
    classified_ids: set[cython.longlong] = set()
    for node_id, summary in probe_summaries.items():
        allocation_size = summary.stack_probe_allocation_size
        if statement_occurrences.get(node_id) != 1:
            continue
        if summary.arg_count != 0 or summary.stack_cleanup not in {None, 0}:
            continue
        if summary.return_used is not False:
            continue
        if not isinstance(allocation_size, int) or allocation_size <= 0:
            continue
        if frame_extent < allocation_size:
            continue
        classified_ids.add(node_id)
    return classified_ids


@cython.ccall
def _remove_classified_probes_8616(
    containers: object,
    classified_ids: object,
) -> object:
    """Remove each classified arg-less probe statement from its container."""
    call: object
    container: object
    statement: object
    removed_ids: set[cython.longlong] = set()
    for container in containers:
        statements = list(container.statements or ())
        retained: list[object] = []
        for statement in statements:
            call = _probe_call_statement_8616(statement)
            if call is not None and id(call) in classified_ids:
                if tuple(call.args or ()):
                    retained.append(statement)
                    continue
                removed_ids.add(id(call))
                continue
            retained.append(statement)
        if operator.ne(len(retained), len(statements)):
            cast(Any, container).statements = retained
    return removed_ids


def lower_fixed_stack_probe_frames_8616(codegen: object) -> FixedStackProbeFrameLoweringStats8616:
    """Remove only fixed, unused probe calls represented by recovered BP locals."""
    root: object
    root = _structured_root_8616(codegen)
    probe_summaries = _probe_summary_map_8616(codegen)
    raw_fact_count = len(probe_summaries)
    if raw_fact_count == 0:
        stats = FixedStackProbeFrameLoweringStats8616(0, 0, 0, 0, 0, 0, 0)
        cast(Any, codegen)._inertia_fixed_stack_probe_frame_lowering_stats_8616 = stats
        return stats
    surface = (
        _collect_fixed_stack_probe_surface_8616(root)
        if root is not None
        else _FixedStackProbeSurface8616(0, (), frozenset(), ())
    )
    frame_extent = surface.frame_extent
    statement_occurrences = dict(surface.statement_occurrences)

    normalized_fact_count = sum(
        node_id in surface.live_call_ids for node_id in iter(probe_summaries)
    )
    classified_ids = _classified_probe_ids_8616(
        probe_summaries, statement_occurrences, frame_extent
    )
    removed_ids = _remove_classified_probes_8616(surface.containers, classified_ids)

    materialized_count = len(classified_ids & removed_ids)
    failure_count = len(classified_ids - removed_ids)
    stats = FixedStackProbeFrameLoweringStats8616(
        raw_fact_count=raw_fact_count,
        normalized_fact_count=normalized_fact_count,
        classified_fact_count=len(classified_ids),
        materialized_count=materialized_count,
        failure_count=failure_count,
        refused_fact_count=raw_fact_count - len(classified_ids),
        recovered_frame_extent=frame_extent,
    )
    cast(Any, codegen)._inertia_fixed_stack_probe_frame_lowering_stats_8616 = stats
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError("fixed stack-probe facts were classified but not materialized")
    return stats
