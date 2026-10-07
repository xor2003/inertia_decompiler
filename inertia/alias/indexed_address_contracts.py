"""Typed Alias contracts for symbolic indexed segmented-memory accesses.

Layer: Alias.
Responsibility: represent an indexed DS/ES storage family without collapsing
its dynamic term, and retain the exact stack Alias identity that supplies the
index. These contracts do not infer bounds, arrays, fields, C types, or names.
Owns storage identity and exact Alias-domain relationships.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
Widening and Types/Lowering consume these facts only after Alias proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.core import IRValue, MemSpace
from inertia.ir.indexed_address_contracts import (
    IndexedAddressEvidence8616,
    IndexedAddressFact8616,
    IndexedAddressRefusal8616,
)

from .storage_fact_join import SegmentedAliasRange8616


class IndexedAddressAliasFailureKind8616(StrEnum):
    """Stable reason one indexed IR candidate has no Alias projection."""

    UPSTREAM_REFUSAL = "upstream_refusal"
    INCOMPLETE_SOURCE_FACT = "incomplete_source_fact"
    INDEX_SOURCE_ALIAS_FAILURE = "index_source_alias_failure"
    INDEX_SOURCE_UNCLASSIFIABLE = "index_source_unclassifiable"
    INDEX_SOURCE_RANGE_REFUSED = "index_source_range_refused"
    DUPLICATE_ACCESS = "duplicate_access"


@dataclass(frozen=True, slots=True)
class IndexedAliasStorage8616:
    """One symbolic DS/ES access family and its exact index storage proof."""

    space: MemSpace
    base_offset: int
    width: int
    index_value: IRValue
    index_source_range: SegmentedAliasRange8616
    index_shift: int

    @property
    def complete(self) -> bool:
        """Return whether symbolic target and stack source remain coherent."""
        source_addresses = self.index_source_range.addresses
        return bool(
            self.space in {MemSpace.DS, MemSpace.ES}
            and 0 <= self.base_offset <= 0xFFFF
            and self.width > 0
            and self.index_value.space is MemSpace.REG
            and self.index_value.name is not None
            and self.index_value.version is not None
            and self.index_source_range.space is MemSpace.SS
            and len(source_addresses) == 1
            and source_addresses[0].size == self.index_value.size
            and 0 <= self.index_shift <= 4
        )

    @property
    def family_key(self) -> tuple[object, ...]:
        """Return the Alias-owned object-family key without claiming bounds."""
        return (
            self.space,
            self.base_offset,
            self.index_source_range.storage.identity,
            self.index_shift,
        )

    @property
    def access_key(self) -> tuple[object, ...]:
        """Return the symbolic family plus exact access width."""
        return (*self.family_key, self.width)


@dataclass(frozen=True, slots=True)
class IndexedAddressAliasFact8616:
    """One indexed IR fact projected into symbolic Alias storage."""

    source: IndexedAddressFact8616
    storage: IndexedAliasStorage8616

    @property
    def complete(self) -> bool:
        """Return whether the IR source and Alias projection agree exactly."""
        source_address = self.source.address
        source_range = self.storage.index_source_range
        return bool(
            self.source.complete
            and self.storage.complete
            and self.storage.space is source_address.space
            and self.storage.base_offset == source_address.offset
            and self.storage.width == source_address.size
            and self.storage.index_value == self.source.index_value
            and source_range.addresses == (self.source.index_source,)
            and self.storage.index_shift == self.source.index_shift
        )


@dataclass(frozen=True, slots=True)
class IndexedAddressAliasRefusal8616:
    """One retained indexed candidate and its Alias refusal reason."""

    failure: IndexedAddressAliasFailureKind8616
    detail: str
    source_fact: IndexedAddressFact8616 | None = None
    source_refusal: IndexedAddressRefusal8616 | None = None

    @property
    def complete(self) -> bool:
        """Return whether this refusal identifies exactly one IR candidate."""
        return (self.source_fact is None) != (self.source_refusal is None)


@dataclass(frozen=True, slots=True)
class IndexedAddressAliasStats8616:
    """Closed accounting for the IR-to-Alias indexed-address projection."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def closed(self) -> bool:
        """Return whether every IR candidate became one fact or refusal."""
        return bool(
            self.raw_fact_count == self.materialized_count + self.failure_count
            and self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
        )


@dataclass(frozen=True, slots=True)
class IndexedAddressAliasEvidence8616:
    """Function-wide indexed Alias facts with all refusals retained."""

    function_addr: int
    facts: tuple[IndexedAddressAliasFact8616, ...]
    refusals: tuple[IndexedAddressAliasRefusal8616, ...]
    stats: IndexedAddressAliasStats8616
    source: IndexedAddressEvidence8616

    @property
    def closed(self) -> bool:
        """Return whether source and Alias accounting close without loss."""
        return bool(
            self.source.closed
            and self.function_addr == self.source.function_addr
            and self.stats.raw_fact_count == self.source.stats.normalized_fact_count
            and len(self.facts) == self.stats.materialized_count
            and len(self.refusals) == self.stats.failure_count
            and self.stats.closed
            and all(fact.complete for fact in self.facts)
            and all(refusal.complete for refusal in self.refusals)
        )


__all__ = [
    "IndexedAddressAliasEvidence8616",
    "IndexedAddressAliasFact8616",
    "IndexedAddressAliasFailureKind8616",
    "IndexedAddressAliasRefusal8616",
    "IndexedAddressAliasStats8616",
    "IndexedAliasStorage8616",
]
