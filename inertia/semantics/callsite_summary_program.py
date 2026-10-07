"""Retain caller-indexed callsite summaries across project boundaries.

Layer: Traits/summaries/confidence.
Responsibility: own immutable, typed callsite-summary facts by caller address and
reuse only exact matching summaries. Missing or conflicting evidence is never
invented; downstream Semantics rebuilds only the missing callsites.

Package ownership contract (canonical inertia/semantics package):
Layer: Semantics.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol, cast

from .callsite_summary import (
    CallsiteSummary8616,
    build_callsite_summary_inventory_8616,
)

__all__ = [
    "ProgramCallsiteSummaryEvidence8616",
    "ProgramCallsiteSummaryFact8616",
    "attach_program_callsite_summary_evidence_8616",
    "build_callsite_summary_inventory_with_program_evidence_8616",
    "program_callsite_summary_evidence_8616",
    "program_callsite_summary_evidence_from_facts_8616",
    "retained_program_callsite_summary_inventory_8616",
]


@dataclass(frozen=True, slots=True)
class ProgramCallsiteSummaryFact8616:
    """One exact caller/callsite coordinate and its optional typed summary."""

    caller_addr: int | None
    callsite_addr: int
    summary: CallsiteSummary8616 | None


@dataclass(frozen=True, slots=True)
class ProgramCallsiteSummaryEvidence8616:
    """Closed accounting for retained caller-indexed summary facts."""

    facts: tuple[ProgramCallsiteSummaryFact8616, ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    def validate(self) -> None:
        """Reject duplicate coordinates, mismatched summaries, or open counts."""
        keys: list[tuple[int | None, int]] = []
        normalized = 0
        classified = 0
        for fact in self.facts:
            if fact.caller_addr is not None and (
                not isinstance(fact.caller_addr, int)
                or isinstance(fact.caller_addr, bool)
                or fact.caller_addr < 0
            ):
                raise ValueError("program callsite caller address is invalid")
            if (
                not isinstance(fact.callsite_addr, int)
                or isinstance(fact.callsite_addr, bool)
                or fact.callsite_addr < 0
            ):
                raise ValueError("program callsite address is invalid")
            if fact.summary is not None and fact.summary.callsite_addr != fact.callsite_addr:
                raise ValueError("program callsite summary address disagrees with its fact")
            keys.append((fact.caller_addr, fact.callsite_addr))
            normalized += int(fact.caller_addr is not None)
            classified += int(fact.caller_addr is not None and fact.summary is not None)
        if len(set(keys)) != len(keys):
            raise ValueError("program callsite summary evidence contains duplicate facts")
        counts = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
        )
        if any(count < 0 for count in counts):
            raise ValueError("program callsite summary counters must be nonnegative")
        if not (
            self.raw_fact_count == len(self.facts)
            and self.normalized_fact_count == normalized
            and self.classified_fact_count == classified
            and self.materialized_count == classified
            and self.failure_count == self.raw_fact_count - classified
        ):
            raise ValueError("program callsite summary accounting does not close")


class _ProgramSummaryOwner8616(Protocol):
    """Owned summary artifact carried by a dynamic third-party project."""

    _inertia_program_callsite_summary_evidence_8616: ProgramCallsiteSummaryEvidence8616


class _FunctionSurface8616(Protocol):
    """Third-party function coordinate consumed by exact summary lookup."""

    addr: int


def program_callsite_summary_evidence_8616(
    project: object,
) -> ProgramCallsiteSummaryEvidence8616 | None:
    """Return the validated project summary artifact when one is attached."""
    try:
        evidence = cast(
            _ProgramSummaryOwner8616,
            project,
        )._inertia_program_callsite_summary_evidence_8616
    except AttributeError:
        return None
    if not isinstance(evidence, ProgramCallsiteSummaryEvidence8616):
        raise TypeError("project callsite summary artifact has a wrong type")
    evidence.validate()
    return evidence


def attach_program_callsite_summary_evidence_8616(
    project: object,
    evidence: ProgramCallsiteSummaryEvidence8616,
) -> None:
    """Attach one already-derived, closed program summary artifact."""
    evidence.validate()
    cast(
        _ProgramSummaryOwner8616,
        project,
    )._inertia_program_callsite_summary_evidence_8616 = evidence


def program_callsite_summary_evidence_from_facts_8616(
    facts: Iterable[ProgramCallsiteSummaryFact8616],
) -> ProgramCallsiteSummaryEvidence8616:
    """Normalize exact facts into one deterministic closed artifact."""
    by_coordinate: dict[tuple[int | None, int], ProgramCallsiteSummaryFact8616] = {}
    for fact in facts:
        key = (fact.caller_addr, fact.callsite_addr)
        previous = by_coordinate.get(key)
        if previous is not None and previous != fact:
            raise ValueError("program callsite coordinate has conflicting summaries")
        by_coordinate[key] = fact
    ordered = tuple(
        by_coordinate[key]
        for key in sorted(
            by_coordinate,
            key=lambda item: (-1 if item[0] is None else item[0], item[1]),
        )
    )
    normalized = sum(fact.caller_addr is not None for fact in ordered)
    classified = sum(
        fact.caller_addr is not None and fact.summary is not None for fact in ordered
    )
    evidence = ProgramCallsiteSummaryEvidence8616(
        facts=ordered,
        raw_fact_count=len(ordered),
        normalized_fact_count=normalized,
        classified_fact_count=classified,
        materialized_count=classified,
        failure_count=len(ordered) - classified,
    )
    evidence.validate()
    return evidence


def retained_program_callsite_summary_inventory_8616(
    project: object,
    function: object,
    callsite_addrs: Iterable[int],
) -> dict[int, CallsiteSummary8616]:
    """Return exact transported summaries without rebuilding missing calls."""
    requested = tuple(sorted(set(callsite_addrs)))
    try:
        function_addr = cast(_FunctionSurface8616, function).addr
    except AttributeError:
        function_addr = None
    evidence = program_callsite_summary_evidence_8616(project)
    return {
        fact.callsite_addr: fact.summary
        for fact in (() if evidence is None else evidence.facts)
        if fact.caller_addr == function_addr
        and fact.callsite_addr in requested
        and fact.summary is not None
    }


def build_callsite_summary_inventory_with_program_evidence_8616(
    project: object,
    function: object,
    callsite_addrs: Iterable[int],
) -> dict[int, CallsiteSummary8616]:
    """Reuse exact transported summaries and build only unrepresented calls."""
    requested = tuple(sorted(set(callsite_addrs)))
    retained = retained_program_callsite_summary_inventory_8616(
        project,
        function,
        requested,
    )
    missing = tuple(addr for addr in requested if addr not in retained)
    if missing:
        retained.update(build_callsite_summary_inventory_8616(function, missing))
    return {address: retained[address] for address in requested if address in retained}
