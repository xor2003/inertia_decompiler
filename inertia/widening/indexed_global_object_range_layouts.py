"""Resolve indexed global accesses against proven element layouts.

Layer: Widening.
Responsibility: map one exact Alias-backed indexed access to its unique
segmented global-object layout and classify missing or conflicting matches.
Consumes alias-proven storage identity.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations

from inertia.alias.indexed_address_access_contracts import IndexedAliasAccessFact8616
from inertia.ir.core import MemSpace

from .global_object_layout import (
    GlobalObjectLayout8616,
    GlobalObjectLayoutEvidence8616,
)
from .indexed_global_object_ranges import BoundedGlobalObjectRangeFailureKind8616

type IndexedGlobalObjectKey8616 = tuple[MemSpace, int]


def indexed_global_object_sort_key_8616(
    key: IndexedGlobalObjectKey8616,
) -> tuple[str, int]:
    """Return deterministic segmented-object ordering."""
    return key[0].value, key[1]


def _layout_contains_access_8616(
    layout: GlobalObjectLayout8616,
    access: IndexedAliasAccessFact8616,
) -> bool:
    """Return whether one exact access is a field of the proven layout."""
    storage = access.source.storage
    relative = storage.base_offset - layout.address.offset
    return bool(
        storage.space is layout.address.space
        and 0 <= relative < layout.element_width
        and relative in layout.field_offsets
        and relative + storage.width <= layout.element_width
        and (1 << storage.index_shift) == layout.element_width
    )


def matching_indexed_global_layouts_8616(
    access: IndexedAliasAccessFact8616,
    layouts: GlobalObjectLayoutEvidence8616,
) -> tuple[GlobalObjectLayout8616, ...]:
    """Return every proven element layout that contains one access."""
    return tuple(
        layout
        for layout in layouts.layouts
        if _layout_contains_access_8616(layout, access)
    )


def unmatched_indexed_global_layout_failure_8616(
    access: IndexedAliasAccessFact8616,
    layouts: GlobalObjectLayoutEvidence8616,
) -> BoundedGlobalObjectRangeFailureKind8616:
    """Classify why one global access has no unique element layout."""
    storage = access.source.storage
    numeric = tuple(
        layout
        for layout in layouts.layouts
        if 0 <= storage.base_offset - layout.address.offset < layout.element_width
    )
    if numeric and all(layout.address.space is not storage.space for layout in numeric):
        return BoundedGlobalObjectRangeFailureKind8616.SEGMENT_MISMATCH
    same_space = tuple(
        layout for layout in numeric if layout.address.space is storage.space
    )
    if same_space and all(
        (1 << storage.index_shift) != layout.element_width for layout in same_space
    ):
        return BoundedGlobalObjectRangeFailureKind8616.STRIDE_WIDTH_MISMATCH
    return BoundedGlobalObjectRangeFailureKind8616.LAYOUT_NOT_PROVEN


def indexed_global_access_object_keys_8616(
    access: IndexedAliasAccessFact8616,
    layouts: GlobalObjectLayoutEvidence8616,
) -> tuple[IndexedGlobalObjectKey8616, ...]:
    """Return layout-owned keys, or the exact unmatched segmented base."""
    matches = matching_indexed_global_layouts_8616(access, layouts)
    if matches:
        return tuple(
            (layout.address.space, layout.address.offset) for layout in matches
        )
    storage = access.source.storage
    return ((storage.space, storage.base_offset),)


__all__ = [
    "IndexedGlobalObjectKey8616",
    "indexed_global_access_object_keys_8616",
    "indexed_global_object_sort_key_8616",
    "matching_indexed_global_layouts_8616",
    "unmatched_indexed_global_layout_failure_8616",
]
