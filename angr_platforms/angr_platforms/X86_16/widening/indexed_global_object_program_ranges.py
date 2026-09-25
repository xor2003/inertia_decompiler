"""Recover bounded global extents from the complete Alias program census.

Layer: Widening.
Responsibility: aggregate every function's exact indexed accesses, loop ranges,
and copies before atomically accepting one project-wide segmented extent.
Consumes alias-proven storage identity.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..alias.indexed_address_access_contracts import (
    IndexedAliasAccessFact8616,
    IndexedAliasAccessRole8616,
)
from ..alias.indexed_address_copy_contracts import IndexedAliasCopyFact8616
from ..alias.indexed_address_program import IndexedAliasProgramEvidence8616
from ..alias.indexed_address_range_contracts import IndexedAliasLoopRangeFact8616
from .global_object_layout import GlobalObjectLayout8616, GlobalObjectLayoutEvidence8616
from .indexed_global_object_range_layouts import (
    IndexedGlobalObjectKey8616,
    indexed_global_access_object_keys_8616,
    indexed_global_object_sort_key_8616,
    matching_indexed_global_layouts_8616,
    unmatched_indexed_global_layout_failure_8616,
)
from .indexed_global_object_range_solver import (
    build_provisional_indexed_global_ranges_8616,
    indexed_loop_range_proof_sites_8616,
    refuse_incompatible_indexed_global_copies_8616,
    refuse_indexed_global_range_overlaps_8616,
)
from .indexed_global_object_ranges import (
    BoundedGlobalObjectRange8616,
    BoundedGlobalObjectRangeFailureKind8616,
    BoundedGlobalObjectRangeRefusal8616,
    BoundedGlobalObjectRangeStats8616,
    indexed_global_access_key_8616,
)

__all__ = [
    "ProjectBoundedGlobalObjectRangeEvidence8616",
    "ProjectBoundedGlobalObjectRangeSource8616",
    "ProjectBoundedGlobalObjectRangeSourceKind8616",
    "ProjectBoundedGlobalObjectRangeSourceStatus8616",
    "recover_program_bounded_global_object_ranges_8616",
]


class ProjectBoundedGlobalObjectRangeSourceKind8616(StrEnum):
    """Stable provenance category for a final project-range artifact."""

    LIVE_ALIAS_PROGRAM = "live_alias_program"
    TRANSPORTED_RECORD = "transported_record"


class ProjectBoundedGlobalObjectRangeSourceStatus8616(StrEnum):
    """Typed completeness status of the source function census."""

    COMPLETE = "complete"
    FUNCTION_REFUSALS = "function_refusals"


@dataclass(frozen=True, slots=True)
class ProjectBoundedGlobalObjectRangeSource8616:
    """Reduced Alias census required to validate final bounded ranges."""

    kind: ProjectBoundedGlobalObjectRangeSourceKind8616
    status: ProjectBoundedGlobalObjectRangeSourceStatus8616
    selected_function_count: int
    materialized_function_count: int
    refused_function_count: int
    closed_function_range_count: int

    @property
    def closed(self) -> bool:
        """Return whether every selected function and range artifact is counted."""
        counts = (
            self.selected_function_count,
            self.materialized_function_count,
            self.refused_function_count,
            self.closed_function_range_count,
        )
        expected_status = (
            ProjectBoundedGlobalObjectRangeSourceStatus8616.FUNCTION_REFUSALS
            if self.refused_function_count
            else ProjectBoundedGlobalObjectRangeSourceStatus8616.COMPLETE
        )
        return bool(
            all(count >= 0 for count in counts)
            and self.selected_function_count
            == self.materialized_function_count + self.refused_function_count
            and self.closed_function_range_count == self.materialized_function_count
            and self.status is expected_status
        )


@dataclass(frozen=True, slots=True)
class ProjectBoundedGlobalObjectRangeEvidence8616:
    """Whole-program accepted ranges and atomic object refusals."""

    ranges: tuple[BoundedGlobalObjectRange8616, ...]
    refusals: tuple[BoundedGlobalObjectRangeRefusal8616, ...]
    stats: BoundedGlobalObjectRangeStats8616
    source: ProjectBoundedGlobalObjectRangeSource8616
    layouts: GlobalObjectLayoutEvidence8616

    @property
    def closed(self) -> bool:
        """Return whether the complete program census has one object outcome."""
        return bool(
            self.source.closed
            and self.layouts.closed
            and self.stats.closed
            and len(self.ranges) == self.stats.materialized_count
            and len(self.refusals) == self.stats.failure_count
            and all(item.complete for item in self.ranges)
            and all(item.complete for item in self.refusals)
            and (
                self.source.status
                is ProjectBoundedGlobalObjectRangeSourceStatus8616.COMPLETE
                or not self.ranges
            )
        )


def _program_source_8616(
    program: IndexedAliasProgramEvidence8616,
) -> ProjectBoundedGlobalObjectRangeSource8616:
    """Project one live Alias program into the durable Widening census."""
    source = ProjectBoundedGlobalObjectRangeSource8616(
        ProjectBoundedGlobalObjectRangeSourceKind8616.LIVE_ALIAS_PROGRAM,
        (
            ProjectBoundedGlobalObjectRangeSourceStatus8616.FUNCTION_REFUSALS
            if program.refusals
            else ProjectBoundedGlobalObjectRangeSourceStatus8616.COMPLETE
        ),
        program.stats.raw_fact_count,
        program.stats.materialized_count,
        program.stats.failure_count,
        sum(function.ranges.closed for function in program.functions),
    )
    if not source.closed:
        raise ValueError("project bounded-range source census did not close")
    return source


def _classify_access_8616(
    access: IndexedAliasAccessFact8616,
    layouts: GlobalObjectLayoutEvidence8616,
    accesses: dict[IndexedGlobalObjectKey8616, list[IndexedAliasAccessFact8616]],
    failures: dict[
        IndexedGlobalObjectKey8616,
        BoundedGlobalObjectRangeFailureKind8616,
    ],
) -> None:
    """Group one global-indexed access by layout keys or record its failure."""
    if access.role is not IndexedAliasAccessRole8616.GLOBAL_INDEXED:
        return
    matches = matching_indexed_global_layouts_8616(access, layouts)
    keys = (
        tuple(
            (layout.address.space, layout.address.offset)
            for layout in matches
        )
        if matches
        else (
            (
                access.source.storage.space,
                access.source.storage.base_offset,
            ),
        )
    )
    for key in keys:
        accesses.setdefault(key, []).append(access)
    if len(matches) != 1:
        failure = (
            BoundedGlobalObjectRangeFailureKind8616.LAYOUT_CONFLICT
            if matches
            else unmatched_indexed_global_layout_failure_8616(
                access,
                layouts,
            )
        )
        for key in keys:
            failures[key] = failure


def _collect_program_inputs_8616(
    program: IndexedAliasProgramEvidence8616,
    layouts: GlobalObjectLayoutEvidence8616,
) -> tuple[
    dict[IndexedGlobalObjectKey8616, list[IndexedAliasAccessFact8616]],
    dict[IndexedGlobalObjectKey8616, list[IndexedAliasLoopRangeFact8616]],
    dict[IndexedGlobalObjectKey8616, GlobalObjectLayout8616],
    dict[IndexedGlobalObjectKey8616, BoundedGlobalObjectRangeFailureKind8616],
]:
    """Group all function inputs by exact project-wide segmented layout."""
    accesses: dict[IndexedGlobalObjectKey8616, list[IndexedAliasAccessFact8616]] = {}
    ranges: dict[IndexedGlobalObjectKey8616, list[IndexedAliasLoopRangeFact8616]] = {}
    layout_by_key = {
        (layout.address.space, layout.address.offset): layout
        for layout in layouts.layouts
    }
    failures: dict[
        IndexedGlobalObjectKey8616,
        BoundedGlobalObjectRangeFailureKind8616,
    ] = {}
    for function in program.functions:
        for access in function.accesses.facts:
            _classify_access_8616(access, layouts, accesses, failures)
        for fact in function.ranges.facts:
            keys = indexed_global_access_object_keys_8616(fact.access, layouts)
            if len(keys) == 1:
                ranges.setdefault(keys[0], []).append(fact)
    if program.refusals:
        for key in accesses:
            failures[key] = (
                BoundedGlobalObjectRangeFailureKind8616.PROGRAM_CENSUS_INCOMPLETE
            )
    return accesses, ranges, layout_by_key, failures


def _program_copies_8616(
    program: IndexedAliasProgramEvidence8616,
) -> tuple[IndexedAliasCopyFact8616, ...]:
    """Return every accepted Alias copy from the complete function census."""
    return tuple(
        copy
        for function in program.functions
        for copy in function.copies.facts
    )


def recover_program_bounded_global_object_ranges_8616(
    program: IndexedAliasProgramEvidence8616,
    layouts: GlobalObjectLayoutEvidence8616,
) -> ProjectBoundedGlobalObjectRangeEvidence8616:
    """Materialize ranges only after every selected function is accounted."""
    if not program.closed or not layouts.closed:
        raise ValueError("program range Widening requires closed typed inputs")
    accesses, range_facts, layout_by_key, failures = _collect_program_inputs_8616(
        program,
        layouts,
    )
    provisional = build_provisional_indexed_global_ranges_8616(
        accesses,
        range_facts,
        layout_by_key,
        failures,
    )
    refuse_indexed_global_range_overlaps_8616(provisional, failures)
    refuse_incompatible_indexed_global_copies_8616(
        _program_copies_8616(program),
        layouts,
        provisional,
        failures,
    )
    ranges = tuple(
        provisional[key]
        for key in sorted(provisional, key=indexed_global_object_sort_key_8616)
        if key not in failures
    )
    refusals = tuple(
        BoundedGlobalObjectRangeRefusal8616(
            space=key[0],
            base=key[1],
            failure=failure,
            detail=f"program bounded global object refused: {failure.value}",
            access_keys=tuple(
                sorted(
                    {
                        indexed_global_access_key_8616(item)
                        for item in accesses[key]
                    }
                )
            ),
            proof_sites=indexed_loop_range_proof_sites_8616(
                tuple(range_facts.get(key, ()))
            ),
        )
        for key, failure in sorted(
            failures.items(),
            key=lambda item: indexed_global_object_sort_key_8616(item[0]),
        )
    )
    raw_count = len(accesses)
    result = ProjectBoundedGlobalObjectRangeEvidence8616(
        ranges,
        refusals,
        BoundedGlobalObjectRangeStats8616(
            raw_count,
            raw_count,
            raw_count,
            len(ranges),
            len(refusals),
        ),
        _program_source_8616(program),
        layouts,
    )
    if not result.closed:
        raise ValueError("program bounded global range accounting did not close")
    return result
