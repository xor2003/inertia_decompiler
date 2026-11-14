# cython: language_level=3, infer_types=True
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
import typing
import cython

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol, cast

from .callsite_summary import (
    CallsiteSummary8616,
    build_callsite_summary_inventory_8616,
)
import dataclasses
import operator
import builtins

__all__ = [
    "ProgramCallsiteSummaryEvidence8616",
    "ProgramCallsiteSummaryFact8616",
    "attach_program_callsite_summary_evidence_8616",
    "build_callsite_summary_inventory_with_program_evidence_8616",
    "program_callsite_summary_evidence_8616",
    "program_callsite_summary_evidence_from_facts_8616",
    "retained_program_callsite_summary_inventory_8616",
]


@dataclasses.dataclass(frozen=True, )
class ProgramCallsiteSummaryFact8616:
    """One exact caller/callsite coordinate and its optional typed summary."""

    caller_addr: int | None
    callsite_addr: cython.longlong
    summary: CallsiteSummary8616 | None


@dataclasses.dataclass(frozen=True, )
class ProgramCallsiteSummaryEvidence8616:
    """Closed accounting for retained caller-indexed summary facts."""

    facts: object
    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong

    def validate(self) -> None:
        """Reject duplicate coordinates, mismatched summaries, or open counts."""
        fact: object
        keys: list[tuple[int | None, cython.longlong]] = []
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
            if fact.summary is not None and operator.ne(fact.summary.callsite_addr, fact.callsite_addr):
                raise ValueError("program callsite summary address disagrees with its fact")
            keys.append((fact.caller_addr, fact.callsite_addr))
            normalized += int(fact.caller_addr is not None)
            classified += int(fact.caller_addr is not None and fact.summary is not None)
        if operator.ne(len(set(keys)), len(keys)):
            raise ValueError("program callsite summary evidence contains duplicate facts")
        counts = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
        )
        if any(count < 0 for count in iter(counts)):
            raise ValueError("program callsite summary counters must be nonnegative")
        if not (
            operator.eq(self.raw_fact_count, len(self.facts))
            and operator.eq(self.normalized_fact_count, normalized)
            and operator.eq(self.classified_fact_count, classified)
            and operator.eq(self.materialized_count, classified)
            and operator.eq(self.failure_count, self.raw_fact_count - classified)
        ):
            raise ValueError("program callsite summary accounting does not close")


class _ProgramSummaryOwner8616(Protocol):
    """Owned summary artifact carried by a dynamic third-party project."""

    _inertia_program_callsite_summary_evidence_8616: ProgramCallsiteSummaryEvidence8616


class _FunctionSurface8616(Protocol):
    """Third-party function coordinate consumed by exact summary lookup."""

    addr: cython.longlong


@cython.ccall
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


@cython.ccall
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
    previous: object
    fact: object
    by_coordinate: dict[tuple[int | None, cython.longlong], ProgramCallsiteSummaryFact8616] = {}
    for fact in facts:
        key = (fact.caller_addr, fact.callsite_addr)
        previous = by_coordinate.get(key)
        if previous is not None and operator.ne(previous, fact):
            raise ValueError("program callsite coordinate has conflicting summaries")
        by_coordinate[key] = fact
    ordered = tuple(
        by_coordinate[key]
        for key in builtins.iter(sorted(
            by_coordinate,
            key=lambda item: (-1 if item[0] is None else item[0], item[1]),
        ))
    )
    normalized = sum(fact.caller_addr is not None for fact in iter(ordered))
    classified = sum(
        fact.caller_addr is not None and fact.summary is not None for fact in iter(ordered)
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


@cython.ccall
def retained_program_callsite_summary_inventory_8616(
    project: object,
    function: object,
    callsite_addrs: Iterable[cython.longlong],
) -> dict[cython.longlong, CallsiteSummary8616]:
    """Return exact transported summaries without rebuilding missing calls."""
    evidence: object
    requested = tuple(sorted(tuple(set(callsite_addrs))))
    try:
        function_addr = cast(_FunctionSurface8616, function).addr
    except AttributeError:
        function_addr = None
    evidence = program_callsite_summary_evidence_8616(project)
    return {
        fact.callsite_addr: fact.summary
        for fact in iter((() if evidence is None else evidence.facts))
        if operator.eq(fact.caller_addr, function_addr)
        and fact.callsite_addr in requested
        and fact.summary is not None
    }


def build_callsite_summary_inventory_with_program_evidence_8616(
    project: object,
    function: object,
    callsite_addrs: Iterable[cython.longlong],
) -> dict[cython.longlong, CallsiteSummary8616]:
    """Reuse exact transported summaries and build only unrepresented calls."""
    requested = tuple(sorted(tuple(set(callsite_addrs))))
    retained = retained_program_callsite_summary_inventory_8616(
        project,
        function,
        requested,
    )
    missing = tuple(addr for addr in iter(requested) if addr not in retained)
    if missing:
        retained.update(build_callsite_summary_inventory_8616(function, missing))
    return {address: retained[address] for address in iter(requested) if address in retained}
