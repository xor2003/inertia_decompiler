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

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall

from ..alias.callsite_stack_merge import (
    CallsitePredecessorStackMerge8616,
    CallsiteSource8616,
)
from ..c_ast_utils import _same_c_expression_8616
from ..callsite_summary import CallsiteSummary8616
from .call_argument_join_conditions import exact_call_argument_immediate_8616
from .call_argument_path_conditions import (
    CallArgumentPathConditionStatus8616,
    materialize_call_argument_path_expressions_8616,
)

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


@dataclass(frozen=True, slots=True)
class CallArgumentPathJoinResult8616:
    """Return one decision and its closed evidence counters."""

    decision: CallArgumentPathJoinDecision8616
    changed: bool = False
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class _NormalizedPathJoin8616:
    """Complete path-indexed immediate values for varying physical lanes."""

    values_by_predecessor: dict[int, tuple[int, ...]]
    varying_lanes: tuple[int, ...]


def _is_path_join_candidate_8616(summary: CallsiteSummary8616) -> bool:
    """Return whether evidence exceeds the existing binary single-lane pass."""
    merge = summary.predecessor_stack_merge
    return bool(
        merge is not None
        and merge.traces
        and (
            len(merge.traces) > 2
            or sum(source is None for source in summary.push_arg_sources) > 1
        )
    )


def _unique_sources_8616(
    sources: tuple[CallsiteSource8616 | None, ...],
) -> tuple[CallsiteSource8616 | None, ...]:
    """Deduplicate source facts without assuming payload hashability."""
    unique: list[CallsiteSource8616 | None] = []
    for source in sources:
        if source not in unique:
            unique.append(source)
    return tuple(unique)


class _ClosedEvidence8616(Protocol):
    """Common closed-evidence counter shape shared by merge and join records."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


def _closed_evidence_counts_8616(evidence: _ClosedEvidence8616, trace_count: int) -> bool:
    """Check one merge/join evidence record closed exactly once per trace."""
    return (
        evidence.raw_fact_count == trace_count
        and evidence.normalized_fact_count == trace_count
        and evidence.classified_fact_count == 1
        and evidence.materialized_count == 1
        and evidence.failure_count == 0
    )


def _summary_lanes_align_8616(summary: CallsiteSummary8616, merge: CallsitePredecessorStackMerge8616) -> bool:
    """Check the summary lanes are word-wide and agree with merge prefixes."""
    widths = summary.arg_widths
    sources = summary.push_arg_sources
    addresses = summary.push_arg_instruction_addrs
    if not widths or any(width != 2 for width in widths):
        return False
    if len(widths) != len(sources) or len(widths) != len(addresses):
        return False
    if len(merge.widths) > len(widths) or merge.widths != widths[: len(merge.widths)]:
        return False
    return bool(merge.sources == sources[: len(merge.sources)])


def _register_join_lanes_8616(
    merge: CallsitePredecessorStackMerge8616,
    addresses: tuple[int, ...],
    predecessors: tuple[object, ...],
) -> tuple[int | None, dict[int, CallsiteSource8616 | None]] | None:
    """Bind the optional register-join lane to per-predecessor sources."""
    join = merge.register_join
    if join is None:
        return None, {}
    if not _closed_evidence_counts_8616(join, len(merge.traces)) or len(join.traces) != len(merge.traces):
        return None
    join_lanes = tuple(index for index, addr in enumerate(addresses) if addr == join.push_instruction_addr)
    if len(join_lanes) != 1:
        return None
    register_sources = {trace.predecessor_addr: trace.source for trace in join.traces}
    if set(register_sources) != set(predecessors):
        return None
    return join_lanes[0], register_sources


def _predecessor_path_sources_8616(
    merge: CallsitePredecessorStackMerge8616,
    sources: tuple[CallsiteSource8616 | None, ...],
    register_lane: int | None,
    register_sources: dict[int, CallsiteSource8616 | None],
) -> dict[int, tuple[CallsiteSource8616 | None, ...]] | None:
    """Expand each predecessor trace into complete physical lanes."""
    path_sources: dict[int, tuple[CallsiteSource8616 | None, ...]] = {}
    for trace in merge.traces:
        predecessor_addr = trace.predecessor_addr
        if not isinstance(predecessor_addr, int) or not trace.is_well_formed() or trace.widths != merge.widths:
            return None
        physical = list(sources)
        physical[: len(trace.sources)] = trace.sources
        if register_lane is not None:
            physical[register_lane] = register_sources[predecessor_addr]
        path_sources[predecessor_addr] = tuple(physical)
    return path_sources


def _normalize_path_join_8616(summary: CallsiteSummary8616) -> _NormalizedPathJoin8616 | None:
    """Validate and expand predecessor traces into complete physical lanes."""
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
    predecessors = tuple(trace.predecessor_addr for trace in traces)
    if any(not isinstance(addr, int) for addr in predecessors) or len(set(predecessors)) != len(predecessors):
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
        if len(_unique_sources_8616(tuple(values[lane] for values in path_sources.values()))) > 1
    )
    if not varying_lanes:
        return None
    values_by_predecessor: dict[int, tuple[int, ...]] = {}
    for predecessor_addr, path in path_sources.items():
        values = tuple(exact_call_argument_immediate_8616(path[lane]) for lane in varying_lanes)
        if any(value is None for value in values):
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
    if not _is_path_join_candidate_8616(summary):
        return CallArgumentPathJoinResult8616(CallArgumentPathJoinDecision8616.NOT_APPLICABLE)
    normalized = _normalize_path_join_8616(summary)
    if normalized is None:
        return CallArgumentPathJoinResult8616(
            CallArgumentPathJoinDecision8616.REFUSED_EVIDENCE,
            failure_count=1,
        )
    existing = tuple(call.args or ())
    if len(existing) != len(summary.arg_widths):
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
    if all(_same_c_expression_8616(lhs, rhs) for lhs, rhs in zip(existing, expected, strict=True)):
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
