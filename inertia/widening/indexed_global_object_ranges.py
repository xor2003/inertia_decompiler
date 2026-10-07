"""Widen bounded indexed Alias ranges into exact global object extents.

Layer: Widening.
Responsibility: atomically materialize one bounded global object only when its
closed function access census, loop bounds, segment, stride, overlap, and copy
endpoint evidence all agree. Unknown or conflicting evidence refuses the whole
object; this module never supplies a default count.
Consumes alias-proven storage identity.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.alias.indexed_address_access_contracts import (
    IndexedAliasAccessFact8616,
)
from inertia.alias.indexed_address_copy_contracts import IndexedAliasCopyFact8616
from inertia.alias.indexed_address_range_contracts import (
    IndexedAliasLoopRangeEvidence8616,
)
from inertia.ir.core import MemSpace
from inertia.ir.indexed_address_contracts import IndexedAddressAccessKind8616
from inertia.ir.indexed_address_range_contracts import IndexedLoopProofSite8616

from .global_object_layout import GlobalObjectLayoutEvidence8616


class BoundedGlobalObjectRangeFailureKind8616(StrEnum):
    """Stable reason one complete object candidate was atomically refused."""

    LAYOUT_NOT_PROVEN = "layout_not_proven"
    LAYOUT_CONFLICT = "layout_conflict"
    UNCOVERED_ACCESS = "uncovered_access"
    CONFLICTING_BOUNDS = "conflicting_bounds"
    SEGMENT_MISMATCH = "segment_mismatch"
    SEGMENT_WRAP = "segment_wrap"
    OVERLAP = "overlap"
    STRIDE_WIDTH_MISMATCH = "stride_width_mismatch"
    INCOMPATIBLE_COPY_ENDPOINTS = "incompatible_copy_endpoints"
    PROGRAM_CENSUS_INCOMPLETE = "program_census_incomplete"


@dataclass(frozen=True, order=True, slots=True)
class IndexedGlobalAccessKey8616:
    """Exact function, machine instruction, and access-effect identity."""

    function_addr: int
    block_addr: int
    instr_index: int
    instr_addr: int
    kind: IndexedAddressAccessKind8616

    @property
    def complete(self) -> bool:
        """Return whether every machine coordinate is exact."""
        return (
            self.function_addr >= 0
            and self.block_addr >= 0
            and self.instr_index >= 0
            and self.instr_addr >= 0
        )


def indexed_global_access_key_8616(
    access: IndexedAliasAccessFact8616,
) -> IndexedGlobalAccessKey8616:
    """Return the exact key of an existing Alias access fact."""
    source = access.source.source
    return IndexedGlobalAccessKey8616(
        source.function_addr,
        source.block_addr,
        source.instr_index,
        source.instr_addr,
        source.kind,
    )


@dataclass(frozen=True, slots=True)
class BoundedGlobalObjectRange8616:
    """One exact segmented global object range proven from loop accesses."""

    space: MemSpace
    base: int
    lower_inclusive: int
    upper_exclusive: int
    element_width: int
    element_count: int
    byte_extent: int
    covered_access_keys: tuple[IndexedGlobalAccessKey8616, ...]
    proof_sites: tuple[IndexedLoopProofSite8616, ...]

    @property
    def complete(self) -> bool:
        """Return whether bounds, extent, access coverage, and segment agree."""
        return bool(
            self.space in {MemSpace.DS, MemSpace.ES}
            and 0 <= self.base <= 0xFFFF
            and self.lower_inclusive == 0
            and self.upper_exclusive > self.lower_inclusive
            and self.element_width > 0
            and self.element_count
            == self.upper_exclusive - self.lower_inclusive
            and self.byte_extent == self.element_count * self.element_width
            and self.base + self.byte_extent <= 0x10000
            and self.covered_access_keys
            and len(self.covered_access_keys) == len(set(self.covered_access_keys))
            and all(key.complete for key in self.covered_access_keys)
            and self.proof_sites
            and all(site.complete for site in self.proof_sites)
        )


@dataclass(frozen=True, slots=True)
class BoundedGlobalObjectRangeRefusal8616:
    """One global base and all of its accesses refused as one object."""

    space: MemSpace
    base: int
    failure: BoundedGlobalObjectRangeFailureKind8616
    detail: str
    access_keys: tuple[IndexedGlobalAccessKey8616, ...]
    proof_sites: tuple[IndexedLoopProofSite8616, ...]

    @property
    def complete(self) -> bool:
        """Return whether this refusal retains its object and access census."""
        return bool(
            self.space in {MemSpace.DS, MemSpace.ES}
            and 0 <= self.base <= 0xFFFF
            and self.detail
            and self.access_keys
            and all(key.complete for key in self.access_keys)
            and all(site.complete for site in self.proof_sites)
        )


@dataclass(frozen=True, slots=True)
class BoundedGlobalObjectRangeStats8616:
    """Closed accounting for object-level Widening candidates."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def closed(self) -> bool:
        """Return whether each global base has one accepted or refused result."""
        counts = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
        )
        return bool(
            all(count >= 0 for count in counts)
            and self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count + self.failure_count
        )


@dataclass(frozen=True, slots=True)
class BoundedGlobalObjectRangeEvidence8616:
    """Accepted object ranges and atomic refusals for one closed function census."""

    ranges: tuple[BoundedGlobalObjectRange8616, ...]
    refusals: tuple[BoundedGlobalObjectRangeRefusal8616, ...]
    stats: BoundedGlobalObjectRangeStats8616
    source: IndexedAliasLoopRangeEvidence8616
    layouts: GlobalObjectLayoutEvidence8616
    copies: tuple[IndexedAliasCopyFact8616, ...]

    @property
    def closed(self) -> bool:
        """Return whether source contracts and object accounting are coherent."""
        return bool(
            self.source.closed
            and self.layouts.closed
            and all(copy.complete for copy in self.copies)
            and self.stats.closed
            and len(self.ranges) == self.stats.materialized_count
            and len(self.refusals) == self.stats.failure_count
            and all(item.complete for item in self.ranges)
            and all(item.complete for item in self.refusals)
        )


__all__ = [
    "BoundedGlobalObjectRange8616",
    "BoundedGlobalObjectRangeEvidence8616",
    "BoundedGlobalObjectRangeFailureKind8616",
    "BoundedGlobalObjectRangeRefusal8616",
    "BoundedGlobalObjectRangeStats8616",
    "IndexedGlobalAccessKey8616",
    "indexed_global_access_key_8616",
]
