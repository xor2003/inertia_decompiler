# cython: language_level=3, infer_types=True
"""Publish complete binary caller ranges before worker isolation.

Layer: CLI/fallback/reporting.
Responsibility: run existing sidecar-free function-range discovery once and
attach only exact range coordinates for Types/Lowering project census owners.
No argument, callsite, arity, width, or value-class semantics are derived here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from typing import Protocol, cast

import angr

from .cli_function_discovery import (
    _pre_entry_source_function_ranges_8616,
    _rank_pre_entry_source_function_seeds_8616,
)
from .discovery_evidence_project import isolated_discovery_evidence_project_8616
import dataclasses
import operator

__all__ = [
    "ProjectArgumentEvidenceRanges8616",
    "attach_project_argument_evidence_ranges_8616",
]


class _CallerRangeOwner8616(Protocol):
    """Owned exact-range extension on a third-party project."""

    _inertia_caller_function_ranges_8616: object


@dataclasses.dataclass(frozen=True, )
class ProjectArgumentEvidenceRanges8616:
    """Closed discovery accounting for project caller ranges."""

    seed_addrs: object
    function_ranges: object
    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong

    @property
    def complete(self) -> cython.bint:
        """Return whether every discovered seed owns one exact range."""
        return bool(
            self.seed_addrs
            and operator.eq(self.raw_fact_count, len(self.seed_addrs))
            and self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            and self.failure_count == 0
            and len(self.function_ranges) >= len(self.seed_addrs)
        )


@cython.ccall
def attach_project_argument_evidence_ranges_8616(
    source_project: angr.Project,
    target_project: object,
) -> ProjectArgumentEvidenceRanges8616:
    """Discover exact caller ranges once and attach a closed snapshot."""
    evidence_project = isolated_discovery_evidence_project_8616(source_project)
    seeds = tuple(_rank_pre_entry_source_function_seeds_8616(evidence_project))
    ranges = _pre_entry_source_function_ranges_8616(evidence_project, seeds)
    normalized = min(len(seeds), len(ranges))
    result = ProjectArgumentEvidenceRanges8616(
        seed_addrs=seeds,
        function_ranges=ranges,
        raw_fact_count=len(seeds),
        normalized_fact_count=normalized,
        classified_fact_count=normalized,
        materialized_count=normalized,
        failure_count=len(seeds) - normalized,
    )
    if result.complete:
        cast(
            _CallerRangeOwner8616,
            target_project,
        )._inertia_caller_function_ranges_8616 = ranges
    return result
