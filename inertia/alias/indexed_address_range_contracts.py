"""Typed Alias contracts for bounded indexed-address range projection.

Layer: Alias.
Responsibility: retain the exact existing global access, canonical indexed
storage object, and stack Alias identity corresponding to each accepted IR
loop range. Alias does not choose counts, widen extents, join objects, or infer
missing range evidence.
Owns storage identity.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.indexed_address_range_contracts import (
    IndexedLoopRangeEvidence8616,
    IndexedLoopRangeFact8616,
    IndexedLoopRangeRefusal8616,
)

from .indexed_address_access_contracts import (
    IndexedAliasAccessEvidence8616,
    IndexedAliasAccessFact8616,
    IndexedAliasAccessRole8616,
)
from .indexed_address_contracts import IndexedAliasStorage8616


class IndexedLoopRangeAliasFailureKind8616(StrEnum):
    """Stable reason one IR loop-range outcome has no Alias projection."""

    UPSTREAM_REFUSAL = "upstream_refusal"
    ACCESS_MISSING = "access_missing"
    ACCESS_CONFLICT = "access_conflict"
    INCOMPLETE_ACCESS = "incomplete_access"
    NON_GLOBAL_ACCESS = "non_global_access"
    IDENTITY_MISMATCH = "identity_mismatch"


@dataclass(frozen=True, slots=True)
class IndexedAliasLoopRangeFact8616:
    """One IR range bound to an exact existing Alias access and storage."""

    source: IndexedLoopRangeFact8616
    access: IndexedAliasAccessFact8616
    storage: IndexedAliasStorage8616
    index_storage_identity: tuple[str, object]

    @property
    def complete(self) -> bool:
        """Return whether the projection reuses one coherent canonical identity."""
        source_range = self.storage.index_source_range
        return bool(
            self.source.complete
            and self.access.complete
            and self.access.role is IndexedAliasAccessRole8616.GLOBAL_INDEXED
            and self.access.source.source == self.source.source
            and self.storage is self.access.source.storage
            and source_range.storage.identity == self.index_storage_identity
            and len(source_range.source_facts) == 1
            and source_range.source_facts[0].identity == self.index_storage_identity
        )


@dataclass(frozen=True, slots=True)
class IndexedAliasLoopRangeRefusal8616:
    """One retained IR range outcome and its Alias refusal reason."""

    failure: IndexedLoopRangeAliasFailureKind8616
    detail: str
    source_fact: IndexedLoopRangeFact8616 | None = None
    source_refusal: IndexedLoopRangeRefusal8616 | None = None

    @property
    def complete(self) -> bool:
        """Return whether this refusal owns exactly one upstream outcome."""
        return bool(
            self.detail
            and (self.source_fact is None) != (self.source_refusal is None)
        )


@dataclass(frozen=True, slots=True)
class IndexedAliasLoopRangeStats8616:
    """Closed accounting for IR-range to Alias-range projection."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def closed(self) -> bool:
        """Return whether every IR range outcome has one Alias outcome."""
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
class IndexedAliasLoopRangeEvidence8616:
    """Function-local Alias range facts with every refusal retained."""

    function_addr: int
    facts: tuple[IndexedAliasLoopRangeFact8616, ...]
    refusals: tuple[IndexedAliasLoopRangeRefusal8616, ...]
    stats: IndexedAliasLoopRangeStats8616
    source: IndexedLoopRangeEvidence8616
    accesses: IndexedAliasAccessEvidence8616

    @property
    def closed(self) -> bool:
        """Return whether source identity and projection accounting are lossless."""
        projected_facts = tuple(fact.source for fact in self.facts) + tuple(
            refusal.source_fact
            for refusal in self.refusals
            if refusal.source_fact is not None
        )
        projected_refusals = tuple(
            refusal.source_refusal
            for refusal in self.refusals
            if refusal.source_refusal is not None
        )
        return bool(
            self.source.closed
            and self.accesses.closed
            and self.function_addr == self.source.function_addr == self.accesses.function_addr
            and self.stats.closed
            and self.stats.raw_fact_count == self.source.stats.raw_fact_count
            and len(self.facts) == self.stats.materialized_count
            and len(self.refusals) == self.stats.failure_count
            and all(fact.complete for fact in self.facts)
            and all(refusal.complete for refusal in self.refusals)
            and len(projected_facts) == len(self.source.facts)
            and all(projected_facts.count(item) == 1 for item in self.source.facts)
            and len(projected_refusals) == len(self.source.refusals)
            and all(projected_refusals.count(item) == 1 for item in self.source.refusals)
        )


__all__ = [
    "IndexedAliasLoopRangeEvidence8616",
    "IndexedAliasLoopRangeFact8616",
    "IndexedAliasLoopRangeRefusal8616",
    "IndexedAliasLoopRangeStats8616",
    "IndexedLoopRangeAliasFailureKind8616",
]
