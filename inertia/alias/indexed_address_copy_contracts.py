"""Typed Alias contracts for exact indexed value-copy relationships.

Layer: Alias.
Responsibility: bind both endpoints of an IR-proven indexed value copy to
canonical Alias storage and require matching global-indexed stack index
identity. These contracts do not infer aggregate families, bounds, layouts,
arrays, fields, C types, names, or rendered expressions.
Owns storage identity and exact Alias-domain relationships.
Widening is out of scope.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.indexed_address_copy_contracts import (
    IndexedAddressCopyEvidence8616,
    IndexedAddressCopyFact8616,
    IndexedAddressCopyRefusal8616,
)

from .indexed_address_access_contracts import (
    IndexedAliasAccessEvidence8616,
    IndexedAliasAccessFact8616,
    IndexedAliasAccessRole8616,
)
from .indexed_address_contracts import (
    IndexedAddressAliasEvidence8616,
    IndexedAddressAliasFact8616,
)


class IndexedAliasCopyFailureKind8616(StrEnum):
    """Stable reason one IR copy has no globally indexed Alias relation."""

    UPSTREAM_REFUSAL = "upstream_refusal"
    SOURCE_ALIAS_MISSING = "source_alias_missing"
    SOURCE_ALIAS_CONFLICT = "source_alias_conflict"
    DESTINATION_ALIAS_MISSING = "destination_alias_missing"
    DESTINATION_ALIAS_CONFLICT = "destination_alias_conflict"
    SOURCE_ACCESS_ROLE_MISSING = "source_access_role_missing"
    DESTINATION_ACCESS_ROLE_MISSING = "destination_access_role_missing"
    NON_GLOBAL_ENDPOINT = "non_global_endpoint"
    INDEX_IDENTITY_CONFLICT = "index_identity_conflict"
    WIDTH_CONFLICT = "width_conflict"


@dataclass(frozen=True, slots=True)
class IndexedAliasCopyFact8616:
    """One IR copy whose endpoints share an exact global index identity."""

    source_copy: IndexedAddressCopyFact8616
    source: IndexedAddressAliasFact8616
    destination: IndexedAddressAliasFact8616
    source_access: IndexedAliasAccessFact8616
    destination_access: IndexedAliasAccessFact8616

    @property
    def complete(self) -> bool:
        """Return whether value, storage, role, width, and index proofs agree."""
        source_range = self.source.storage.index_source_range
        destination_range = self.destination.storage.index_source_range
        return bool(
            self.source_copy.complete
            and self.source.complete
            and self.destination.complete
            and self.source_access.complete
            and self.destination_access.complete
            and self.source.source == self.source_copy.source
            and self.destination.source == self.source_copy.destination
            and self.source_access.source == self.source
            and self.destination_access.source == self.destination
            and self.source_access.role is IndexedAliasAccessRole8616.GLOBAL_INDEXED
            and self.destination_access.role
            is IndexedAliasAccessRole8616.GLOBAL_INDEXED
            and self.source.storage.width == self.destination.storage.width > 0
            and self.source.storage.index_shift
            == self.destination.storage.index_shift
            and source_range.space is destination_range.space
            and source_range.addresses == destination_range.addresses
            and source_range.storage.identity == destination_range.storage.identity
        )


@dataclass(frozen=True, slots=True)
class IndexedAliasCopyRefusal8616:
    """One retained IR copy input and its Alias refusal reason."""

    failure: IndexedAliasCopyFailureKind8616
    detail: str
    source_copy: IndexedAddressCopyFact8616 | None = None
    source_refusal: IndexedAddressCopyRefusal8616 | None = None

    @property
    def complete(self) -> bool:
        """Return whether this refusal identifies exactly one IR input."""
        return bool(
            self.detail
            and (self.source_copy is None) != (self.source_refusal is None)
        )


@dataclass(frozen=True, slots=True)
class IndexedAliasCopyStats8616:
    """Closed accounting for IR-copy to Alias-copy projection."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def closed(self) -> bool:
        """Return whether every IR input became one Alias copy or refusal."""
        return bool(
            self.raw_fact_count == self.materialized_count + self.failure_count
            and self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
        )


@dataclass(frozen=True, slots=True)
class IndexedAliasCopyEvidence8616:
    """Function-wide Alias copy facts with all IR outcomes retained."""

    function_addr: int
    facts: tuple[IndexedAliasCopyFact8616, ...]
    refusals: tuple[IndexedAliasCopyRefusal8616, ...]
    stats: IndexedAliasCopyStats8616
    source: IndexedAddressCopyEvidence8616
    aliases: IndexedAddressAliasEvidence8616
    accesses: IndexedAliasAccessEvidence8616

    @property
    def closed(self) -> bool:
        """Return whether IR, Alias, and access-role accounting is coherent."""
        projected_copies = tuple(fact.source_copy for fact in self.facts) + tuple(
            refusal.source_copy
            for refusal in self.refusals
            if refusal.source_copy is not None
        )
        projected_refusals = tuple(
            refusal.source_refusal
            for refusal in self.refusals
            if refusal.source_refusal is not None
        )
        return bool(
            self.source.closed
            and self.aliases.closed
            and self.accesses.closed
            and self.function_addr
            == self.source.function_addr
            == self.aliases.function_addr
            == self.accesses.function_addr
            and self.aliases.source == self.source.source
            and self.accesses.source == self.aliases
            and self.stats.raw_fact_count == self.source.stats.raw_fact_count
            and len(self.facts) == self.stats.materialized_count
            and len(self.refusals) == self.stats.failure_count
            and self.stats.closed
            and all(fact.complete for fact in self.facts)
            and all(refusal.complete for refusal in self.refusals)
            and len(projected_copies) == len(self.source.facts)
            and all(projected_copies.count(source) == 1 for source in self.source.facts)
            and len(projected_refusals) == len(self.source.refusals)
            and all(
                projected_refusals.count(source) == 1
                for source in self.source.refusals
            )
        )


__all__ = [
    "IndexedAliasCopyEvidence8616",
    "IndexedAliasCopyFact8616",
    "IndexedAliasCopyFailureKind8616",
    "IndexedAliasCopyRefusal8616",
    "IndexedAliasCopyStats8616",
]
