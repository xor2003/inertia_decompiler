# cython: language_level=3, infer_types=True
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
import typing
import cython

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
import dataclasses
import operator


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


@dataclasses.dataclass(frozen=True, order=True, )
class IndexedGlobalAccessKey8616:
    """Exact function, machine instruction, and access-effect identity."""

    function_addr: cython.longlong
    block_addr: cython.longlong
    instr_index: cython.longlong
    instr_addr: cython.longlong
    kind: IndexedAddressAccessKind8616

    @property
    def complete(self) -> cython.bint:
        """Return whether every machine coordinate is exact."""
        return (
            self.function_addr >= 0
            and self.block_addr >= 0
            and self.instr_index >= 0
            and self.instr_addr >= 0
        )


@cython.ccall
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


@dataclasses.dataclass(frozen=True, )
class BoundedGlobalObjectRange8616:
    """One exact segmented global object range proven from loop accesses."""

    space: MemSpace
    base: cython.longlong
    lower_inclusive: cython.longlong
    upper_exclusive: cython.longlong
    element_width: cython.longlong
    element_count: cython.longlong
    byte_extent: cython.longlong
    covered_access_keys: object
    proof_sites: object

    @property
    def complete(self) -> cython.bint:
        """Return whether bounds, extent, access coverage, and segment agree."""
        return bool(
            self.space in {MemSpace.DS, MemSpace.ES}
            and 0 <= self.base <= 0xFFFF
            and self.lower_inclusive == 0
            and self.upper_exclusive > self.lower_inclusive
            and self.element_width > 0
            and operator.eq(self.element_count, self.upper_exclusive - self.lower_inclusive)
            and operator.eq(self.byte_extent, self.element_count * self.element_width)
            and self.base + self.byte_extent <= 0x10000
            and self.covered_access_keys
            and operator.eq(len(self.covered_access_keys), len(set(self.covered_access_keys)))
            and all(key.complete for key in iter(self.covered_access_keys))
            and self.proof_sites
            and all(site.complete for site in iter(self.proof_sites))
        )


@dataclasses.dataclass(frozen=True, )
class BoundedGlobalObjectRangeRefusal8616:
    """One global base and all of its accesses refused as one object."""

    space: MemSpace
    base: cython.longlong
    failure: BoundedGlobalObjectRangeFailureKind8616
    detail: object
    access_keys: object
    proof_sites: object

    @property
    def complete(self) -> cython.bint:
        """Return whether this refusal retains its object and access census."""
        return bool(
            self.space in {MemSpace.DS, MemSpace.ES}
            and 0 <= self.base <= 0xFFFF
            and self.detail
            and self.access_keys
            and all(key.complete for key in iter(self.access_keys))
            and all(site.complete for site in iter(self.proof_sites))
        )


@dataclasses.dataclass(frozen=True, )
class BoundedGlobalObjectRangeStats8616:
    """Closed accounting for object-level Widening candidates."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0

    @property
    def closed(self) -> cython.bint:
        """Return whether each global base has one accepted or refused result."""
        counts = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
        )
        return bool(
            all(count >= 0 for count in iter(counts))
            and self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count + self.failure_count
        )


@dataclasses.dataclass(frozen=True, )
class BoundedGlobalObjectRangeEvidence8616:
    """Accepted object ranges and atomic refusals for one closed function census."""

    ranges: object
    refusals: object
    stats: BoundedGlobalObjectRangeStats8616
    source: IndexedAliasLoopRangeEvidence8616
    layouts: GlobalObjectLayoutEvidence8616
    copies: object

    @property
    def closed(self) -> cython.bint:
        """Return whether source contracts and object accounting are coherent."""
        return bool(
            self.source.closed
            and self.layouts.closed
            and all(copy.complete for copy in iter(self.copies))
            and self.stats.closed
            and operator.eq(len(self.ranges), self.stats.materialized_count)
            and operator.eq(len(self.refusals), self.stats.failure_count)
            and all(item.complete for item in iter(self.ranges))
            and all(item.complete for item in iter(self.refusals))
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
