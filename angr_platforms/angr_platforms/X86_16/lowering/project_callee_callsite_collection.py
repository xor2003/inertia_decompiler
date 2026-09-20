"""Collect the complete project direct-caller census once.

Layer: Types/Lowering.
Responsibility: normalize one complete recovered function catalog into the
authoritative per-callee callsite registry before isolated workers are started.
Arity, width, value class, and generated-C interfaces remain downstream work.

Consumes alias, widening, and typed facts. Do not recover semantics from COD,
source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, cast

from ..analysis_helpers import collect_neighbor_call_targets
from ..callsite_summary import summarize_x86_16_callsite
from ..callsite_summary_program import (
    ProgramCallsiteSummaryFact8616,
    attach_program_callsite_summary_evidence_8616,
    program_callsite_summary_evidence_from_facts_8616,
)
from ..callsite_target_inventory import CallsiteTargetInventory8616
from ..frontend_boundary_transport import capture_function_boundary_8616
from ..semantics.callsite_summary_request import (
    CallsiteSummaryRequestCache8616,
    CallsiteSummaryRequestStats8616,
)
from .callee_callsite_contracts import (
    CalleeCallsiteCensus8616,
    CalleeCallsiteFact8616,
    attach_callee_callsite_censuses_8616,
    callee_callsite_censuses_by_addr_8616,
)
from .callee_range_callsite_facts import collect_range_callsite_facts_8616

__all__ = [
    "ProjectCalleeCallsiteCollection8616",
    "collect_complete_project_callee_callsites_8616",
]


class _FunctionSurface8616(Protocol):
    """Third-party function entry; executable bounds belong to Frontend."""

    addr: int


class _CallerRangeSurface8616(Protocol):
    """Optional exact caller ranges already attached to a project."""

    _inertia_caller_function_ranges_8616: tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True)
class ProjectCalleeCallsiteCollection8616:
    """Closed accounting for one complete project callsite collection."""

    target_addrs: tuple[int, ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    summary_request_stats: CallsiteSummaryRequestStats8616

    def validate(self) -> None:
        """Reject noncanonical targets or open fact accounting."""
        if self.target_addrs != tuple(sorted(set(self.target_addrs))):
            raise ValueError("project callee callsite targets are not canonical")
        counts = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
        )
        if any(count < 0 for count in counts):
            raise ValueError("project callee callsite counters must be nonnegative")
        if not (
            self.raw_fact_count == self.normalized_fact_count
            and self.normalized_fact_count
            == self.materialized_count + self.failure_count
            and self.classified_fact_count == self.materialized_count
        ):
            raise ValueError("project callee callsite accounting does not close")
        self.summary_request_stats.validate()


def _function_addr_8616(function: object) -> int | None:
    """Read one exact third-party function address."""
    try:
        value = cast(_FunctionSurface8616, function).addr
    except AttributeError:
        return None
    return value if isinstance(value, int) and value >= 0 else None


def _function_ranges_8616(
    project: object,
    functions: Sequence[object],
) -> tuple[tuple[int, int], ...]:
    """Use explicit ranges or closed Frontend witnesses, never summed CFG size."""
    try:
        attached = cast(
            _CallerRangeSurface8616,
            project,
        )._inertia_caller_function_ranges_8616
    except AttributeError:
        attached = ()
    if attached:
        if not isinstance(attached, tuple):
            raise TypeError("project caller function ranges must be a tuple")
        return tuple(
            (start, end)
            for start, end in attached
            if isinstance(start, int)
            and isinstance(end, int)
            and start >= 0
            and end > start
        )
    ranges: list[tuple[int, int]] = []
    for function in functions:
        witness = capture_function_boundary_8616(project, function)
        if witness is not None:
            ranges.append((witness.entry, witness.end))
    return tuple(sorted(set(ranges)))


def _build_census_8616(
    target_addr: int,
    facts: dict[int, CalleeCallsiteFact8616],
) -> CalleeCallsiteCensus8616:
    """Build one deterministic closed census from callsite-keyed facts."""
    ordered = tuple(facts[callsite] for callsite in sorted(facts))
    normalized = sum(fact.summary is not None for fact in ordered)
    census = CalleeCallsiteCensus8616(
        target_addr=target_addr,
        facts=ordered,
        raw_fact_count=len(ordered),
        normalized_fact_count=normalized,
        failure_count=len(ordered) - normalized,
    )
    census.validate()
    return census


def collect_complete_project_callee_callsites_8616(
    project: object,
    functions: Sequence[object],
) -> ProjectCalleeCallsiteCollection8616:
    """Scan one complete function catalog and publish every callee census."""
    facts_by_target: dict[int, dict[int, CalleeCallsiteFact8616]] = {}
    request_cache = CallsiteSummaryRequestCache8616()
    for function in functions:
        caller_addr = _function_addr_8616(function)
        targets = tuple(collect_neighbor_call_targets(function))
        target_inventory = CallsiteTargetInventory8616(targets)
        for target in targets:
            summary = summarize_x86_16_callsite(
                function,
                target.callsite_addr,
                target_inventory=target_inventory,
                request_cache=request_cache,
            )
            if summary is not None and summary.stack_probe_helper:
                summary = None
            facts_by_target.setdefault(target.target_addr, {})[target.callsite_addr] = (
                CalleeCallsiteFact8616(
                    evidence_project=project,
                    caller_function=function,
                    evidence_target_addr=target.target_addr,
                    caller_addr=caller_addr,
                    callsite_addr=target.callsite_addr,
                    summary=summary,
                )
            )
    classified_keys = frozenset(
        (target_addr, callsite_addr)
        for target_addr, facts in facts_by_target.items()
        for callsite_addr, fact in facts.items()
        if fact.summary is not None
    )
    for fact in collect_range_callsite_facts_8616(
        project,
        _function_ranges_8616(project, functions),
        excluded_fact_keys=classified_keys,
    ):
        facts_by_target.setdefault(fact.evidence_target_addr, {})[
            fact.callsite_addr
        ] = fact
    collected = {
        target_addr: _build_census_8616(target_addr, facts)
        for target_addr, facts in sorted(facts_by_target.items())
    }
    program_summaries = program_callsite_summary_evidence_from_facts_8616(
        ProgramCallsiteSummaryFact8616(
            caller_addr=fact.caller_addr,
            callsite_addr=fact.callsite_addr,
            summary=fact.summary,
        )
        for facts in facts_by_target.values()
        for fact in facts.values()
    )
    attach_program_callsite_summary_evidence_8616(project, program_summaries)
    retained = dict(callee_callsite_censuses_by_addr_8616(project))
    retained.update(collected)
    attach_callee_callsite_censuses_8616(project, retained)
    materialized = sum(
        census.normalized_fact_count for census in collected.values()
    )
    failures = sum(census.failure_count for census in collected.values())
    result = ProjectCalleeCallsiteCollection8616(
        target_addrs=tuple(collected),
        raw_fact_count=materialized + failures,
        normalized_fact_count=materialized + failures,
        classified_fact_count=materialized,
        materialized_count=materialized,
        failure_count=failures,
        summary_request_stats=request_cache.stats(),
    )
    result.validate()
    return result
