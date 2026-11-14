# cython: language_level=3, infer_types=True
"""Transport and report typed whole-program segment evidence.

Layer: CLI/fallback/reporting.
Responsibility: carry X86_16-owned facts across clean workers, invoke the core
program join, and attach/report its result. Never infer segment semantics here.
"""

from __future__ import annotations
import typing
import cython

import sys
from collections.abc import Iterable, Mapping
from dataclasses import replace
from typing import Protocol, cast

from inertia.cli.discovery_cache_contract import SourceRegionCatalogEvidence8616
from inertia.cli.work_items import FunctionWorkItem, FunctionWorkResult
from inertia.semantics.segment_function_summary import SegmentFunctionSummary8616
from inertia.semantics.segment_program_layout import build_x86_16_segment_program_layout
from inertia.semantics.segment_program_layout_codec import segment_program_function_evidence_8616
from inertia.semantics.segment_program_layout_contract import (
    SegmentProgramDiscoveryEvidence8616,
    SegmentProgramFunctionEvidence8616,
    SegmentProgramLayoutContract8616,
)


class _ProjectBoundary8616(Protocol):
    """Dynamic angr project fields used only to carry owned core contracts."""

    _inertia_segment_function_summaries_8616: Mapping[cython.longlong, SegmentFunctionSummary8616]
    _inertia_segment_program_layout_8616: SegmentProgramLayoutContract8616


class _FunctionBoundary8616(Protocol):
    """Minimal dynamic angr function address needed for reporting."""

    addr: cython.longlong


@cython.ccall
def segment_program_function_evidence_for_project_8616(
    project: object,
    function_addr: cython.longlong,
) -> SegmentProgramFunctionEvidence8616 | None:
    """Read one typed function summary from a dynamic project boundary."""
    summary: object
    boundary = cast(_ProjectBoundary8616, project)
    try:
        summaries = boundary._inertia_segment_function_summaries_8616
    except AttributeError:
        return None
    summary = summaries.get(function_addr)
    if not isinstance(summary, SegmentFunctionSummary8616):
        return None
    return segment_program_function_evidence_8616(summary)


@cython.ccall
def segment_program_function_evidence_for_function_8616(
    project: object,
    function: object,
) -> SegmentProgramFunctionEvidence8616 | None:
    """Read typed evidence from the owned project registry for one function."""
    boundary = cast(_FunctionBoundary8616, function)
    try:
        function_addr = boundary.addr
    except (AttributeError, TypeError):
        return None
    if not isinstance(function_addr, int):
        return None
    return segment_program_function_evidence_for_project_8616(project, function_addr)


@cython.ccall
def with_segment_program_function_evidence_8616(
    result: FunctionWorkResult,
    project: object,
) -> FunctionWorkResult:
    """Attach current core-owned function evidence to a clean-worker result."""
    evidence: object
    evidence = segment_program_function_evidence_for_function_8616(project, result.function)
    if evidence is None:
        return result
    return replace(result, segment_program_function_evidence=evidence)


@cython.ccall
def _expected_function_addrs_8616(items: Iterable[FunctionWorkItem]) -> tuple[cython.longlong, ...]:
    """Return exact selected recovery addresses without hiding missing results."""
    item: object
    addrs: list[cython.longlong] = []
    for item in items:
        if item.recovery_addr is not None:
            addrs.append(item.recovery_addr)
            continue
        function = cast(_FunctionBoundary8616, item.function)
        try:
            function_addr = function.addr
        except (AttributeError, TypeError):
            continue
        if isinstance(function_addr, int):
            addrs.append(function_addr)
    return tuple(sorted(addrs))


@cython.ccall
def segment_program_function_evidence_matches_item_8616(
    evidence: SegmentProgramFunctionEvidence8616,
    item: FunctionWorkItem,
) -> cython.bint:
    """Return whether transported evidence belongs to the requested function."""
    allowed: set[cython.longlong] = set()
    if item.recovery_addr is not None:
        allowed.add(item.recovery_addr)
    function = cast(_FunctionBoundary8616, item.function)
    try:
        function_addr = function.addr
    except (AttributeError, TypeError):
        function_addr = None
    if isinstance(function_addr, int):
        allowed.add(function_addr)
    return evidence.function_addr in allowed


@cython.ccall
def _discovery_contract_8616(
    expected_addrs: object,
    source: object,
) -> SegmentProgramDiscoveryEvidence8616:
    """Translate CLI discovery counts into the X86_16 program-summary input."""
    if source is None:
        return SegmentProgramDiscoveryEvidence8616(expected_addrs, 0, 0, 0, 0, 1)
    return SegmentProgramDiscoveryEvidence8616(
        expected_function_addrs=expected_addrs,
        raw_fact_count=source.raw_fact_count,
        normalized_fact_count=source.normalized_fact_count,
        classified_fact_count=source.classified_fact_count,
        materialized_count=source.materialized_count,
        failure_count=source.failure_count,
        failed_addrs=source.failed_addrs,
    )


def attach_segment_program_layout_8616(
    project: object,
    items: Iterable[FunctionWorkItem],
    results: Iterable[FunctionWorkResult],
    source_discovery: SourceRegionCatalogEvidence8616 | None,
) -> SegmentProgramLayoutContract8616:
    """Join transported facts, attach the core contract, and report its census."""
    expected_addrs = _expected_function_addrs_8616(items)
    evidence = tuple(
        result.segment_program_function_evidence
        for result in iter(results)
        if result.segment_program_function_evidence is not None
    )
    contract = build_x86_16_segment_program_layout(
        _discovery_contract_8616(expected_addrs, source_discovery),
        evidence,
    )
    cast(_ProjectBoundary8616, project)._inertia_segment_program_layout_8616 = contract
    summary = contract.summary
    print(
        "[dbg] segment program layout: "
        f"functions={summary['function_summary_count']}/{summary['expected_function_count']} "
        f"classified={summary['classified_fact_count']} "
        f"materialized={summary['materialized_count']} failures={summary['failure_count']}",
        file=sys.stderr,
    )
    return contract
