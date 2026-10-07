"""Recover exact bounded extents for Alias-backed global object layouts.

Layer: Widening.
Responsibility: combine closed indexed Alias loop ranges with the existing
project-wide element-layout proof. Byte field streams become one object only
through that layout; missing bounds, layout conflicts, overlap, or segment
differences refuse materialization. This module never supplies a default count.
Consumes alias-proven storage identity.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations

from inertia.alias.indexed_address_access_contracts import (
    IndexedAliasAccessFact8616,
    IndexedAliasAccessRole8616,
)
from inertia.alias.indexed_address_copy_contracts import IndexedAliasCopyFact8616
from inertia.alias.indexed_address_range_contracts import (
    IndexedAliasLoopRangeEvidence8616,
    IndexedAliasLoopRangeFact8616,
)

from .global_object_layout import (
    GlobalObjectLayout8616,
    GlobalObjectLayoutEvidence8616,
)
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
    BoundedGlobalObjectRangeEvidence8616,
    BoundedGlobalObjectRangeFailureKind8616,
    BoundedGlobalObjectRangeRefusal8616,
    BoundedGlobalObjectRangeStats8616,
    indexed_global_access_key_8616,
)


def _failure_detail_8616(
    failure: BoundedGlobalObjectRangeFailureKind8616,
) -> str:
    """Return a stable human diagnostic for one typed object refusal."""
    return f"bounded global object refused: {failure.value}"


def _collect_inputs_8616(
    source: IndexedAliasLoopRangeEvidence8616,
    layouts: GlobalObjectLayoutEvidence8616,
) -> tuple[
    dict[IndexedGlobalObjectKey8616, list[IndexedAliasAccessFact8616]],
    dict[IndexedGlobalObjectKey8616, list[IndexedAliasLoopRangeFact8616]],
    dict[IndexedGlobalObjectKey8616, GlobalObjectLayout8616],
    dict[IndexedGlobalObjectKey8616, BoundedGlobalObjectRangeFailureKind8616],
]:
    """Group exact accesses and accepted ranges by proven segmented layout."""
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
    global_accesses = tuple(
        access
        for access in source.accesses.facts
        if access.role is IndexedAliasAccessRole8616.GLOBAL_INDEXED
    )
    for access in global_accesses:
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
                else unmatched_indexed_global_layout_failure_8616(access, layouts)
            )
            for key in keys:
                failures[key] = failure
    for fact in source.facts:
        keys = indexed_global_access_object_keys_8616(fact.access, layouts)
        if len(keys) == 1:
            ranges.setdefault(keys[0], []).append(fact)
    return accesses, ranges, layout_by_key, failures


def recover_bounded_global_object_ranges_8616(
    source: IndexedAliasLoopRangeEvidence8616,
    layouts: GlobalObjectLayoutEvidence8616,
    copies: tuple[IndexedAliasCopyFact8616, ...] = (),
) -> BoundedGlobalObjectRangeEvidence8616:
    """Materialize exact layout-backed ranges or refuse each segmented object."""
    if (
        not source.closed
        or not layouts.closed
        or not all(copy.complete for copy in copies)
    ):
        raise ValueError("bounded global object Widening requires closed typed inputs")
    accesses, range_facts, layout_by_key, failures = _collect_inputs_8616(
        source,
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
        copies,
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
            detail=_failure_detail_8616(failure),
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
    result = BoundedGlobalObjectRangeEvidence8616(
        ranges=ranges,
        refusals=refusals,
        stats=BoundedGlobalObjectRangeStats8616(
            raw_fact_count=raw_count,
            normalized_fact_count=raw_count,
            classified_fact_count=raw_count,
            materialized_count=len(ranges),
            failure_count=len(refusals),
        ),
        source=source,
        layouts=layouts,
        copies=copies,
    )
    if not result.closed:
        raise ValueError("bounded global object Widening accounting did not close")
    return result


__all__ = ["recover_bounded_global_object_ranges_8616"]
