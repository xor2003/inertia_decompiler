"""Typed Alias contracts for indexed-address access roles.

Layer: Alias.
Responsibility: distinguish exact pointer-relative dereferences from globally
based indexed accesses after storage identity is proven, while retaining every
ambiguous form as a typed refusal. These contracts do not infer bounds, arrays,
fields, C types, or names.
Owns storage identity and exact Alias-domain relationships.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
Widening may consume globally indexed facts only as candidates whose object
extent and bounds still require independent proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .indexed_address_contracts import (
    IndexedAddressAliasEvidence8616,
    IndexedAddressAliasFact8616,
    IndexedAddressAliasRefusal8616,
)


class IndexedAliasAccessRole8616(StrEnum):
    """Proven interpretation of the dynamic term in one Alias access."""

    POINTER_RELATIVE = "pointer_relative"
    GLOBAL_INDEXED = "global_indexed"


class IndexedAliasAccessFailureKind8616(StrEnum):
    """Stable reason one Alias access has no unique supported role."""

    UPSTREAM_REFUSAL = "upstream_refusal"
    INCOMPLETE_ALIAS_FACT = "incomplete_alias_fact"
    AMBIGUOUS_ADDRESS_FORM = "ambiguous_address_form"


@dataclass(frozen=True, slots=True)
class IndexedAliasAccessFact8616:
    """One exact Alias access and its proven pointer/global role."""

    source: IndexedAddressAliasFact8616
    role: IndexedAliasAccessRole8616

    @property
    def complete(self) -> bool:
        """Return whether the role follows from the exact address form."""
        storage = self.source.storage
        if self.role is IndexedAliasAccessRole8616.POINTER_RELATIVE:
            role_matches = storage.base_offset == 0 and storage.index_shift == 0
        else:
            role_matches = storage.base_offset != 0 and storage.index_shift > 0
        return bool(self.source.complete and role_matches)

    @property
    def is_pointer_argument(self) -> bool:
        """Return whether pointer-relative storage came from a BP argument."""
        return bool(
            self.role is IndexedAliasAccessRole8616.POINTER_RELATIVE
            and self.source.storage.index_source_range.offset >= 4
        )


@dataclass(frozen=True, slots=True)
class IndexedAliasAccessRefusal8616:
    """One retained Alias input and its access-role refusal reason."""

    failure: IndexedAliasAccessFailureKind8616
    detail: str
    source_fact: IndexedAddressAliasFact8616 | None = None
    source_refusal: IndexedAddressAliasRefusal8616 | None = None

    @property
    def complete(self) -> bool:
        """Return whether this refusal identifies exactly one Alias input."""
        return (self.source_fact is None) != (self.source_refusal is None)


@dataclass(frozen=True, slots=True)
class IndexedAliasAccessStats8616:
    """Closed accounting for Alias access-role classification."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def closed(self) -> bool:
        """Return whether every Alias input became one role or refusal."""
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
            == self.normalized_fact_count + self.failure_count
            and self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
        )


@dataclass(frozen=True, slots=True)
class IndexedAliasAccessEvidence8616:
    """Function-wide pointer/global roles with every refusal retained."""

    function_addr: int
    facts: tuple[IndexedAliasAccessFact8616, ...]
    refusals: tuple[IndexedAliasAccessRefusal8616, ...]
    stats: IndexedAliasAccessStats8616
    source: IndexedAddressAliasEvidence8616

    @property
    def closed(self) -> bool:
        """Return whether source identity and role accounting are lossless."""
        classified_sources = tuple(fact.source for fact in self.facts)
        refused_facts = tuple(
            refusal.source_fact
            for refusal in self.refusals
            if refusal.source_fact is not None
        )
        refused_upstream = tuple(
            refusal.source_refusal
            for refusal in self.refusals
            if refusal.source_refusal is not None
        )
        return bool(
            self.source.closed
            and self.function_addr == self.source.function_addr
            and self.stats.raw_fact_count == self.source.stats.raw_fact_count
            and len(self.facts) == self.stats.materialized_count
            and len(self.refusals) == self.stats.failure_count
            and self.stats.closed
            and all(fact.complete for fact in self.facts)
            and all(refusal.complete for refusal in self.refusals)
            and len(classified_sources) + len(refused_facts) == len(self.source.facts)
            and all(
                classified_sources.count(source) + refused_facts.count(source) == 1
                for source in self.source.facts
            )
            and len(refused_upstream) == len(self.source.refusals)
            and all(refused_upstream.count(source) == 1 for source in self.source.refusals)
        )


__all__ = [
    "IndexedAliasAccessEvidence8616",
    "IndexedAliasAccessFact8616",
    "IndexedAliasAccessFailureKind8616",
    "IndexedAliasAccessRefusal8616",
    "IndexedAliasAccessRole8616",
    "IndexedAliasAccessStats8616",
]
