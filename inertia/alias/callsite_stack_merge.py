"""Merge physical call-argument stack traces at CFG joins.

Layer: Alias.
Responsibility: prove common stack-slot widths and sources across every direct
predecessor of a call block. Differing values remain unknown while a width is
accepted only when all incoming traces agree exactly.
Owns storage identity across incoming stack traces.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "CallsitePredecessorStackMerge8616",
    "CallsitePushTrace8616",
    "CallsiteRegisterJoin8616",
    "CallsiteRegisterJoinTrace8616",
    "CallsiteSource8616",
    "merge_callsite_predecessor_stack_traces_8616",
    "merge_callsite_register_join_traces_8616",
]

type CallsiteSource8616 = tuple[object, ...]


@dataclass(frozen=True, slots=True)
class CallsitePushTrace8616:
    """One predecessor path's physical pushes in execution order."""

    widths: tuple[int, ...]
    sources: tuple[CallsiteSource8616 | None, ...]
    instruction_addrs: tuple[int, ...]
    predecessor_addr: int | None = None

    def is_well_formed(self) -> bool:
        """Return whether every physical push has width, source, and address slots."""
        return bool(self.widths) and len(self.widths) == len(self.sources) == len(self.instruction_addrs)


@dataclass(frozen=True, slots=True)
class CallsiteRegisterJoinTrace8616:
    """One predecessor's exact source for a register pushed at the join."""

    predecessor_addr: int
    register: str
    source: CallsiteSource8616 | None


@dataclass(frozen=True, slots=True)
class CallsiteRegisterJoin8616:
    """Path-indexed sources for one register value consumed after a CFG join."""

    register: str
    push_instruction_addr: int
    traces: tuple[CallsiteRegisterJoinTrace8616, ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class CallsitePredecessorStackMerge8616:
    """Closed evidence loop for one predecessor stack-trace merge."""

    widths: tuple[int, ...]
    sources: tuple[CallsiteSource8616 | None, ...]
    representative_instruction_addrs: tuple[int, ...]
    alternative_instruction_addrs: tuple[tuple[int, ...], ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    register_join: CallsiteRegisterJoin8616 | None = None
    traces: tuple[CallsitePushTrace8616, ...] = ()


def merge_callsite_register_join_traces_8616(
    traces: tuple[CallsiteRegisterJoinTrace8616, ...],
    *,
    push_instruction_addr: int,
) -> CallsiteRegisterJoin8616 | None:
    """Accept a join only when every predecessor resolves the same register."""
    if not traces or any(trace.source is None for trace in traces):
        return None
    register = traces[0].register
    if not register or any(trace.register != register for trace in traces[1:]):
        return None
    predecessor_addrs = tuple(trace.predecessor_addr for trace in traces)
    if len(set(predecessor_addrs)) != len(predecessor_addrs):
        return None
    return CallsiteRegisterJoin8616(
        register=register,
        push_instruction_addr=push_instruction_addr,
        traces=traces,
        raw_fact_count=len(traces),
        normalized_fact_count=len(traces),
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
    )


def merge_callsite_predecessor_stack_traces_8616(
    traces: tuple[CallsitePushTrace8616, ...],
    *,
    register_join: CallsiteRegisterJoin8616 | None = None,
) -> CallsitePredecessorStackMerge8616 | None:
    """Merge pushes only when every direct predecessor proves equal widths."""
    raw_count = len(traces)
    normalized = tuple(trace for trace in traces if trace.is_well_formed())
    if raw_count == 0 or len(normalized) != raw_count:
        return None
    widths = normalized[0].widths
    if any(trace.widths != widths for trace in normalized[1:]):
        return None
    merged_sources = tuple(
        lane_sources[0] if all(source == lane_sources[0] for source in lane_sources[1:]) else None
        for lane_sources in zip(*(trace.sources for trace in normalized), strict=True)
    )
    address_lanes = tuple(zip(*(trace.instruction_addrs for trace in normalized), strict=True))
    return CallsitePredecessorStackMerge8616(
        widths=widths,
        sources=merged_sources,
        representative_instruction_addrs=tuple(min(lane) for lane in address_lanes),
        alternative_instruction_addrs=tuple(tuple(sorted(set(lane))) for lane in address_lanes),
        raw_fact_count=raw_count,
        normalized_fact_count=len(normalized),
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        register_join=register_join,
        traces=normalized,
    )
