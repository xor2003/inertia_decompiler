# cython: language_level=3, infer_types=True
"""Aggregate binary caller evidence for one callee's logical argument count.

Layer: Types/Lowering.
Responsibility: join direct incoming callsite summaries by callee address and
publish a typed, closed-census logical arity verdict for interface lowering.
Consumes alias, widening, and typed facts, including binary callsite summaries.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

import logging
import os
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Protocol, cast

from inertia.frontend.x86_16.calling_convention_compat import collect_wide_stack_argument_width_evidence_8616
from inertia.semantics.callsite_summary import (
    CallsiteSummary8616,
    logical_argument_widths_from_callsite_8616,
)
from inertia.widening.stack_argument_widths import project_logical_stack_argument_widths_8616

from .callee_callsite_census import (
    CalleeCallsiteFact8616,
    collect_callee_callsite_census_8616,
)
import dataclasses
import operator

_LOGGER = logging.getLogger(__name__)


class CalleeArgumentCountVerdict8616(StrEnum):
    """Typed outcome of joining all discovered direct callers."""

    UNKNOWN = "unknown"
    CONSISTENT = "consistent"
    CONFLICT = "conflict"


@dataclasses.dataclass(frozen=True, )
class CalleeArgumentCountEvidence8616:
    """Closed evidence census for one callee's incoming logical arity."""

    target_addr: cython.longlong
    verdict: CalleeArgumentCountVerdict8616
    argument_count: int | None = None
    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0
    callsite_addrs: tuple[cython.longlong, ...] = ()
    callsite_summaries: object = field(
        default=(),
        compare=False,
    )
    callsite_facts: object = field(
        default=(),
        compare=False,
    )

    @property
    def closes_census(self) -> cython.bint:
        """Return whether every discovered caller proves the same arity."""
        return (
            self.verdict is CalleeArgumentCountVerdict8616.CONSISTENT
            and isinstance(self.argument_count, int)
            and self.argument_count >= 0
            and self.raw_fact_count > 0
            and self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            and self.failure_count == 0
        )


class _ProjectSurface8616(Protocol):
    """Owned arity evidence extension on the dynamic angr project."""

    _inertia_callee_argument_count_evidence_8616: object


class _FunctionManager8616(Protocol):
    """Third-party angr function lookup used at the evidence boundary."""

    def function(self, *, addr: cython.longlong, create: cython.bint) -> object | None:
        """Return an existing function at one exact address."""
        ...


class _KnowledgeBase8616(Protocol):
    """Third-party knowledge-base surface needed for callee lookup."""

    functions: _FunctionManager8616


class _EvidenceProject8616(Protocol):
    """Third-party project surface needed for callee Widening evidence."""

    kb: _KnowledgeBase8616


@cython.ccall
def _logical_argument_count_8616(summary: CallsiteSummary8616) -> int | None:
    """Project one summary to logical arity without splitting wide values."""
    widths: object
    if summary.logical_arg_widths:
        return len(summary.logical_arg_widths)
    argument_count = summary.arg_count
    if isinstance(argument_count, int) and argument_count in {0, 1} and operator.eq(len(summary.arg_widths), argument_count):
        return argument_count
    if not isinstance(summary.arg_count, int) or summary.arg_count < 0:
        return None
    widths = logical_argument_widths_from_callsite_8616(
        summary,
        expected_arg_count=summary.arg_count,
    )
    return len(widths) if widths is not None else None


@cython.ccall
def _project_summary_through_callee_widening_8616(
    fact: CalleeCallsiteFact8616,
    wide_offsets_by_target: object,
) -> CalleeCallsiteFact8616:
    """Attach logical widths when the callee proves a closed wide stack object."""
    function: object
    logical_widths: object
    summary: object
    wide_offsets: object
    summary = fact.summary
    if summary is None or summary.logical_arg_widths:
        return fact
    physical_widths = summary.arg_widths
    if (
        not physical_widths
        or operator.ne(summary.arg_count, len(physical_widths))
        or operator.ne(summary.stack_cleanup, sum(physical_widths))
    ):
        return fact
    evidence_key = (id(fact.evidence_project), fact.evidence_target_addr)
    if evidence_key not in wide_offsets_by_target:
        try:
            function = cast(_EvidenceProject8616, fact.evidence_project).kb.functions.function(
                addr=fact.evidence_target_addr,
                create=False,
            )
        except (AttributeError, KeyError, TypeError, ValueError):
            function = None
        if function is None:
            wide_offsets_by_target[evidence_key] = None
        else:
            wide_evidence = collect_wide_stack_argument_width_evidence_8616(
                fact.evidence_project,
                function,
            )
            wide_offsets_by_target[evidence_key] = (
                wide_evidence.classified_offsets
                if wide_evidence.closes_classification
                else None
            )
    wide_offsets = wide_offsets_by_target[evidence_key]
    if wide_offsets is None:
        return fact
    logical_widths = project_logical_stack_argument_widths_8616(
        physical_widths,
        wide_offsets,
    )
    if logical_widths is None:
        return fact
    return replace(
        fact,
        summary=replace(
            summary,
            logical_arg_widths=logical_widths,
            logical_arg_classes=(),
        ),
    )


@cython.ccall
def _evidence_cache_8616(project: object) -> object:
    """Return the owned per-project arity evidence cache."""
    surface = cast(_ProjectSurface8616, project)
    try:
        cache = surface._inertia_callee_argument_count_evidence_8616
    except AttributeError:
        cache = {}
        surface._inertia_callee_argument_count_evidence_8616 = cache
    if not isinstance(cache, dict):
        raise TypeError("callee argument-count evidence cache must be a dict")
    return cache


def collect_callee_argument_count_evidence_8616(
    project: object,
    target_addr: cython.longlong,
) -> CalleeArgumentCountEvidence8616:
    """Collect and join logical argument counts from direct binary callers."""
    argument_count: object
    cached: object
    count: object
    summary: object
    fact: object
    cache = _evidence_cache_8616(project)
    cached = cache.get(target_addr)
    if cached is not None:
        return cached

    census = collect_callee_callsite_census_8616(project, target_addr)
    wide_offsets_by_target: dict[tuple[cython.longlong, cython.longlong], tuple[int, ...] | None] = {}
    facts = tuple(
        _project_summary_through_callee_widening_8616(
            fact,
            wide_offsets_by_target,
        )
        for fact in iter(census.facts)
    )
    counts: dict[tuple[cython.longlong, cython.longlong], cython.longlong] = {}
    summaries: list[CallsiteSummary8616] = []
    for fact in facts:
        summary = fact.summary
        if summary is None:
            continue
        summaries.append(summary)
        count = _logical_argument_count_8616(summary)
        if count is not None:
            counts[(id(fact.evidence_project), fact.callsite_addr)] = count

    distinct_counts = set(counts.values())
    unclassified_count = census.raw_fact_count - len(counts)
    if len(distinct_counts) == 1 and unclassified_count == 0:
        verdict = CalleeArgumentCountVerdict8616.CONSISTENT
        argument_count = next(iter(distinct_counts))
    elif len(distinct_counts) > 1:
        verdict = CalleeArgumentCountVerdict8616.CONFLICT
        argument_count = None
    else:
        verdict = CalleeArgumentCountVerdict8616.UNKNOWN
        argument_count = None
    evidence = CalleeArgumentCountEvidence8616(
        target_addr=target_addr,
        verdict=verdict,
        argument_count=argument_count,
        raw_fact_count=census.raw_fact_count,
        normalized_fact_count=census.normalized_fact_count,
        classified_fact_count=len(counts),
        materialized_count=len(counts),
        failure_count=unclassified_count + int(verdict is CalleeArgumentCountVerdict8616.CONFLICT),
        callsite_addrs=tuple(fact.callsite_addr for fact in iter(facts)),
        callsite_summaries=tuple(summaries),
        callsite_facts=facts,
    )
    if os.environ.get("INERTIA_DEBUG_CALLEE_ARITY") == "1":
        _LOGGER.warning(
            "callee arity evidence target=%#x verdict=%s count=%s raw=%d normalized=%d classified=%d failures=%d callsites=%s",
            target_addr,
            evidence.verdict.value,
            evidence.argument_count,
            evidence.raw_fact_count,
            evidence.normalized_fact_count,
            evidence.classified_fact_count,
            evidence.failure_count,
            evidence.callsite_addrs,
        )
    cache[target_addr] = evidence
    return evidence


__all__ = [
    "CalleeArgumentCountEvidence8616",
    "CalleeArgumentCountVerdict8616",
    "collect_callee_argument_count_evidence_8616",
]
