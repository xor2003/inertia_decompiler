# cython: language_level=3, infer_types=True
"""Solve bounded global extents from complete grouped Widening inputs.

Layer: Widening.
Responsibility: build provisional exact extents and atomically refuse overlap
or incompatible-copy conflicts after callers provide a complete access census.
Consumes alias-proven storage identity.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations
import cython

from inertia.alias.indexed_address_access_contracts import IndexedAliasAccessFact8616
from inertia.alias.indexed_address_copy_contracts import IndexedAliasCopyFact8616
from inertia.alias.indexed_address_range_contracts import IndexedAliasLoopRangeFact8616
from inertia.ir.indexed_address_range_contracts import IndexedLoopProofSite8616

from .global_object_layout import GlobalObjectLayout8616, GlobalObjectLayoutEvidence8616
from .indexed_global_object_range_layouts import (
    IndexedGlobalObjectKey8616,
    indexed_global_access_object_keys_8616,
    indexed_global_object_sort_key_8616,
)
from .indexed_global_object_ranges import (
    BoundedGlobalObjectRange8616,
    BoundedGlobalObjectRangeFailureKind8616,
    indexed_global_access_key_8616,
)
import operator

__all__ = [
    "build_provisional_indexed_global_ranges_8616",
    "indexed_loop_range_proof_sites_8616",
    "refuse_incompatible_indexed_global_copies_8616",
    "refuse_indexed_global_range_overlaps_8616",
]


@cython.ccall
def indexed_loop_range_proof_sites_8616(
    facts: object,
) -> tuple[IndexedLoopProofSite8616, ...]:
    """Return deterministic unique proof sites without losing semantic roles."""
    fact: object
    site: object
    sites: list[IndexedLoopProofSite8616] = []
    for fact in facts:
        for site in fact.source.proof_sites:
            if site not in sites:
                sites.append(site)
    return tuple(sites)


@cython.ccall
def build_provisional_indexed_global_ranges_8616(
    accesses: object,
    range_facts: object,
    layouts: object,
    failures: object,
) -> object:
    """Build exact provisional extents before overlap and copy validation."""
    layout: object
    lower: object
    upper: object
    key: object
    provisional: dict[IndexedGlobalObjectKey8616, BoundedGlobalObjectRange8616] = {}
    for key in sorted(accesses, key=indexed_global_object_sort_key_8616):
        if key in failures:
            continue
        layout = layouts.get(key)
        if layout is None:
            failures[key] = BoundedGlobalObjectRangeFailureKind8616.LAYOUT_NOT_PROVEN
            continue
        access_tuple = tuple(accesses[key])
        fact_tuple = tuple(range_facts.get(key, ()))
        access_keys = tuple(
            sorted({indexed_global_access_key_8616(item) for item in iter(access_tuple)})
        )
        covered_keys = {
            indexed_global_access_key_8616(item.access) for item in iter(fact_tuple)
        }
        if operator.ne(set(access_keys), covered_keys):
            failures[key] = BoundedGlobalObjectRangeFailureKind8616.UNCOVERED_ACCESS
            continue
        bounds = {(item.source.init, item.source.upper_bound) for item in iter(fact_tuple)}
        if len(bounds) != 1:
            failures[key] = BoundedGlobalObjectRangeFailureKind8616.CONFLICTING_BOUNDS
            continue
        lower, upper = next(iter(bounds))
        extent = (upper - lower) * layout.element_width
        if key[1] + extent > 0x10000:
            failures[key] = BoundedGlobalObjectRangeFailureKind8616.SEGMENT_WRAP
            continue
        item = BoundedGlobalObjectRange8616(
            space=key[0],
            base=key[1],
            lower_inclusive=lower,
            upper_exclusive=upper,
            element_width=layout.element_width,
            element_count=upper - lower,
            byte_extent=extent,
            covered_access_keys=access_keys,
            proof_sites=indexed_loop_range_proof_sites_8616(fact_tuple),
        )
        if item.complete:
            provisional[key] = item
        else:
            failures[key] = BoundedGlobalObjectRangeFailureKind8616.UNCOVERED_ACCESS
    return provisional


@cython.ccall
def refuse_indexed_global_range_overlaps_8616(
    provisional: object,
    failures: object,
) -> None:
    """Refuse both exact segmented objects when their extents overlap."""
    index: object
    left: object
    left_key: object
    right: object
    right_key: object
    items = tuple(provisional.items())
    for index, (left_key, left) in enumerate(items):
        for right_key, right in items[index + 1 :]:
            if (
                left.space is right.space
                and left.base < right.base + right.byte_extent
                and right.base < left.base + left.byte_extent
            ):
                failures[left_key] = BoundedGlobalObjectRangeFailureKind8616.OVERLAP
                failures[right_key] = BoundedGlobalObjectRangeFailureKind8616.OVERLAP


@cython.ccall
def refuse_incompatible_indexed_global_copies_8616(
    copies: object,
    layouts: GlobalObjectLayoutEvidence8616,
    provisional: object,
    failures: object,
) -> None:
    """Require whole-element copy endpoints to retain identical bounds."""
    destination_key: object
    destination_range: object
    key: object
    source_key: object
    source_range: object
    copy: object
    for copy in copies:
        source_keys = indexed_global_access_object_keys_8616(
            copy.source_access,
            layouts,
        )
        destination_keys = indexed_global_access_object_keys_8616(
            copy.destination_access,
            layouts,
        )
        source_key = source_keys[0] if len(source_keys) == 1 else None
        destination_key = destination_keys[0] if len(destination_keys) == 1 else None
        source_range = provisional.get(source_key) if source_key is not None else None
        destination_range = (
            provisional.get(destination_key) if destination_key is not None else None
        )
        compatible = bool(
            source_range is not None
            and destination_range is not None
            and source_key not in failures
            and destination_key not in failures
            and operator.eq(copy.source.storage.width, source_range.element_width)
            and operator.eq(copy.destination.storage.width, destination_range.element_width)
            and operator.eq(source_range.lower_inclusive, destination_range.lower_inclusive)
            and operator.eq(source_range.upper_exclusive, destination_range.upper_exclusive)
            and indexed_global_access_key_8616(copy.source_access)
            in source_range.covered_access_keys
            and indexed_global_access_key_8616(copy.destination_access)
            in destination_range.covered_access_keys
        )
        if compatible:
            continue
        for key in (source_key, destination_key):
            if key is not None and key in provisional:
                failures[key] = (
                    BoundedGlobalObjectRangeFailureKind8616.INCOMPATIBLE_COPY_ENDPOINTS
                )
