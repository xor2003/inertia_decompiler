# cython: language_level=3, infer_types=True
"""Materialize call arguments that vary across several CFG predecessors.

Layer: Structuring.
Responsibility: Consume complete Alias-owned predecessor PUSH traces and typed
ConditionIR/CFG topology to build path-selected C call arguments. Common
arguments remain owned by earlier Lowering; only exact varying immediate lanes
are replaced. This module never decodes assembly or inspects rendered C.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall

from inertia.alias.callsite_stack_merge import (
    CallsitePredecessorStackMerge8616,
    CallsiteSource8616,
)
from inertia.lowering.c_ast_utils import _same_c_expression_8616
from inertia.semantics.callsite_summary import CallsiteSummary8616

from .call_argument_join_conditions import exact_call_argument_immediate_8616
from .call_argument_path_conditions import (
    CallArgumentPathConditionStatus8616,
    materialize_call_argument_path_expressions_8616,
)
import dataclasses
import operator
import builtins

__all__ = [
    "CallArgumentPathJoinDecision8616",
    "CallArgumentPathJoinResult8616",
    "materialize_call_argument_path_join_8616",
]


class CallArgumentPathJoinDecision8616(Enum):
    """Typed result of one N-predecessor call-argument attempt."""

    NOT_APPLICABLE = "not_applicable"
    REFUSED_EVIDENCE = "refused_evidence"
    REFUSED_CONDITION = "refused_condition"
    MATERIALIZED = "materialized"
    ALREADY_MATERIALIZED = "already_materialized"


@dataclasses.dataclass(frozen=True, )
class CallArgumentPathJoinResult8616:
    """Return one decision and its closed evidence counters."""

    decision: CallArgumentPathJoinDecision8616
    changed: cython.bint = False
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0


@dataclasses.dataclass(frozen=True, )
class _NormalizedPathJoin8616:
    """Complete path-indexed immediate values for varying physical lanes."""

    values_by_predecessor: object
    varying_lanes: object


def _is_path_join_candidate_8616(summary: CallsiteSummary8616) -> cython.bint:
    """Return whether evidence exceeds the existing binary single-lane pass."""
    merge: object
    merge = summary.predecessor_stack_merge
    return bool(
        merge is not None
        and merge.traces
        and (
            len(merge.traces) > 2
            or sum(source is None for source in iter(summary.push_arg_sources)) > 1
        )
    )


@cython.ccall
def _unique_sources_8616(
    sources: object,
) -> tuple[CallsiteSource8616 | None, ...]:
    """Deduplicate source facts without assuming payload hashability."""
    source: object
    unique: list[CallsiteSource8616 | None] = []
    for source in sources:
        if source not in unique:
            unique.append(source)
    return tuple(unique)


class _ClosedEvidence8616(Protocol):
    """Common closed-evidence counter shape shared by merge and join records."""

    @property
    def raw_fact_count(self) -> cython.longlong:
        """Raw predecessor trace count observed before normalization."""
        ...

    @property
    def normalized_fact_count(self) -> cython.longlong:
        """Trace count surviving normalization."""
        ...

    @property
    def classified_fact_count(self) -> cython.longlong:
        """Count of joins classified as materializable."""
        ...

    @property
    def materialized_count(self) -> cython.longlong:
        """Count of materialized join outputs."""
        ...

    @property
    def failure_count(self) -> cython.longlong:
        """Count of evidence failures."""
        ...


@cython.ccall
def _closed_evidence_counts_8616(evidence: _ClosedEvidence8616, trace_count: cython.longlong) -> cython.bint:
    """Check one merge/join evidence record closed exactly once per trace."""
    return (
        operator.eq(evidence.raw_fact_count, trace_count)
        and operator.eq(evidence.normalized_fact_count, trace_count)
        and evidence.classified_fact_count == 1
        and evidence.materialized_count == 1
        and evidence.failure_count == 0
    )


def _summary_lanes_align_8616(summary: CallsiteSummary8616, merge: CallsitePredecessorStackMerge8616) -> cython.bint:
    """Check the summary lanes are word-wide and agree with merge prefixes."""
    widths = summary.arg_widths
    sources = summary.push_arg_sources
    addresses = summary.push_arg_instruction_addrs
    if not widths or any(width != 2 for width in iter(widths)):
        return False
    if operator.ne(len(widths), len(sources)) or operator.ne(len(widths), len(addresses)):
        return False
    if len(merge.widths) > len(widths) or operator.ne(merge.widths, widths[: len(merge.widths)]):
        return False
    return bool(operator.eq(merge.sources, sources[: len(merge.sources)]))


def _register_join_lanes_8616(
    merge: CallsitePredecessorStackMerge8616,
    addresses: object,
    predecessors: object,
) -> object:
    """Bind the optional register-join lane to per-predecessor sources."""
    join: object
    join = merge.register_join
    if join is None:
        return None, {}
    if not _closed_evidence_counts_8616(join, len(merge.traces)) or operator.ne(len(join.traces), len(merge.traces)):
        return None
    join_lanes = tuple(index for index, addr in builtins.iter(enumerate(addresses)) if operator.eq(addr, join.push_instruction_addr))
    if len(join_lanes) != 1:
        return None
    register_sources = {trace.predecessor_addr: trace.source for trace in iter(join.traces)}
    if operator.ne(set(register_sources), set(predecessors)):
        return None
    return join_lanes[0], register_sources


@cython.ccall
def _predecessor_path_sources_8616(
    merge: CallsitePredecessorStackMerge8616,
    sources: object,
    register_lane: object,
    register_sources: object,
) -> object:
    """Expand each predecessor trace into complete physical lanes."""
    trace: object
    path_sources: dict[cython.longlong, tuple[CallsiteSource8616 | None, ...]] = {}
    for trace in merge.traces:
        predecessor_addr = trace.predecessor_addr
        if not isinstance(predecessor_addr, int) or not trace.is_well_formed() or operator.ne(trace.widths, merge.widths):
            return None
        physical = list(sources)
        physical[: len(trace.sources)] = trace.sources
        if register_lane is not None:
            physical[register_lane] = register_sources[predecessor_addr]
        path_sources[predecessor_addr] = tuple(physical)
    return path_sources


def _normalize_path_join_8616(summary: CallsiteSummary8616) -> _NormalizedPathJoin8616 | None:
    """Validate and expand predecessor traces into complete physical lanes."""
    joined: object
    merge: object
    path_sources: object
    path: object
    predecessor_addr: object
    merge = summary.predecessor_stack_merge
    if merge is None or len(merge.traces) < 2:
        return None
    traces = merge.traces
    if not _closed_evidence_counts_8616(merge, len(traces)):
        return None
    widths = summary.arg_widths
    sources = summary.push_arg_sources
    addresses = summary.push_arg_instruction_addrs
    if not _summary_lanes_align_8616(summary, merge):
        return None
    predecessors = tuple(trace.predecessor_addr for trace in iter(traces))
    if any(not isinstance(addr, int) for addr in iter(predecessors)) or operator.ne(len(set(predecessors)), len(predecessors)):
        return None

    joined = _register_join_lanes_8616(merge, addresses, predecessors)
    if joined is None:
        return None
    register_lane, register_sources = joined

    path_sources = _predecessor_path_sources_8616(merge, sources, register_lane, register_sources)
    if path_sources is None:
        return None

    varying_lanes = tuple(
        lane
        for lane in range(len(widths))
        if len(_unique_sources_8616(tuple(values[lane] for values in builtins.iter(path_sources.values())))) > 1
    )
    if not varying_lanes:
        return None
    values_by_predecessor: dict[cython.longlong, tuple[cython.longlong, ...]] = {}
    for predecessor_addr, path in path_sources.items():
        values = tuple(exact_call_argument_immediate_8616(path[lane]) for lane in iter(varying_lanes))
        if any(value is None for value in iter(values)):
            return None
        values_by_predecessor[predecessor_addr] = cast(tuple[int, ...], values)
    return _NormalizedPathJoin8616(values_by_predecessor, varying_lanes)


def materialize_call_argument_path_join_8616(
    project: object,
    codegen: object,
    call: CFunctionCall,
    summary: CallsiteSummary8616,
) -> CallArgumentPathJoinResult8616:
    """Replace every exact N-path immediate lane in one structured call."""
    normalized: object
    expression: object
    physical_lane: object
    if not _is_path_join_candidate_8616(summary):
        return CallArgumentPathJoinResult8616(CallArgumentPathJoinDecision8616.NOT_APPLICABLE)
    normalized = _normalize_path_join_8616(summary)
    if normalized is None:
        return CallArgumentPathJoinResult8616(
            CallArgumentPathJoinDecision8616.REFUSED_EVIDENCE,
            failure_count=1,
        )
    existing = tuple(call.args or ())
    if operator.ne(len(existing), len(summary.arg_widths)):
        return CallArgumentPathJoinResult8616(
            CallArgumentPathJoinDecision8616.REFUSED_EVIDENCE,
            normalized_fact_count=1,
            failure_count=1,
        )
    condition_result = materialize_call_argument_path_expressions_8616(
        project,
        codegen,
        summary,
        normalized.values_by_predecessor,
        normalized.varying_lanes,
    )
    if condition_result.status is not CallArgumentPathConditionStatus8616.MATERIALIZED:
        decision = (
            CallArgumentPathJoinDecision8616.REFUSED_EVIDENCE
            if condition_result.status is CallArgumentPathConditionStatus8616.REFUSED_TOPOLOGY
            else CallArgumentPathJoinDecision8616.REFUSED_CONDITION
        )
        return CallArgumentPathJoinResult8616(
            decision,
            normalized_fact_count=1,
            failure_count=1,
        )
    expected = list(existing)
    for physical_lane, expression in zip(
        normalized.varying_lanes,
        condition_result.expressions,
        strict=True,
    ):
        expected[len(expected) - 1 - physical_lane] = expression
    if all(_same_c_expression_8616(lhs, rhs) for lhs, rhs in builtins.iter(zip(existing, expected, strict=True))):
        return CallArgumentPathJoinResult8616(
            CallArgumentPathJoinDecision8616.ALREADY_MATERIALIZED,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
        )
    call.args = expected
    return CallArgumentPathJoinResult8616(
        CallArgumentPathJoinDecision8616.MATERIALIZED,
        changed=True,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
    )
