"""Typed contracts for widening stack-memory byte views into objects.

Layer: Widening.
Responsibility: describe Alias-proved overlap components that either have one
canonical containing stack object or must remain explicit byte views.
Consumes alias-proven storage identity from IR/Alias facts only. Do not infer
types, materialize C variables, structure control flow, or use sidecars. Do
not join values from rendered text, cosmetic shape, postprocess, or
CLI/reporting evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from inertia.alias.alias_model_impl import AliasStorageFacts
from inertia.alias.stack_memory_ssa_contracts import (
    StackMemoryAliasFactKind8616,
    StackMemorySSAAliasAccess8616,
    StackMemorySSAAliasArtifact8616,
    StackMemorySSAAliasFact8616,
)
from inertia.ir.core import IRAddress
from inertia.ir.ssa_memory_contracts import SSACallStackEffectSite8616

if TYPE_CHECKING:
    from inertia.alias.logical_stack_memory_projection import LogicalStackMemoryAliasRefusal8616


class StackMemoryObjectWideningRefusalKind8616(StrEnum):
    """Typed reason why one overlap component has no canonical object."""

    PARTIAL_OVERLAP = "partial_overlap"
    MISSING_UNIQUE_OWNER = "missing_unique_owner"
    OWNER_NOT_COMPOSED_ACCESS = "owner_not_composed_access"
    INCONSISTENT_STORAGE = "inconsistent_storage"
    ORPHAN_COMPOSED_ACCESS = "orphan_composed_access"
    SOURCE_LOGICAL_ALIAS_REFUSAL = "source_logical_alias_refusal"


@dataclass(frozen=True, slots=True)
class StackMemoryObjectWideningCandidate8616:
    """One nested overlap component with a unique containing stack range."""

    address: IRAddress
    storage: AliasStorageFacts
    covered_addresses: tuple[IRAddress, ...]
    source_accesses: tuple[StackMemorySSAAliasAccess8616, ...]
    source_facts: tuple[StackMemorySSAAliasFact8616, ...]
    versions: tuple[int, ...]
    fact_kinds: tuple[StackMemoryAliasFactKind8616, ...]
    call_effects: tuple[SSACallStackEffectSite8616, ...] = ()

    def calls_preserve_owner(self, callsite_addrs: tuple[int, ...]) -> bool:
        """Require one exact owner-preserving IR effect for every structured call."""
        if len(frozenset(callsite_addrs)) != len(callsite_addrs):
            return False
        for callsite_addr in callsite_addrs:
            matches = tuple(
                site for site in self.call_effects if site.callsite_addr == callsite_addr
            )
            if len(matches) != 1 or not matches[0].effect.preserves(self.address):
                return False
        return True

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "address": self.address.to_dict(),
            "covered_addresses": [address.to_dict() for address in self.covered_addresses],
            "source_access_count": len(self.source_accesses),
            "source_fact_count": len(self.source_facts),
            "versions": list(self.versions),
            "fact_kinds": [kind.value for kind in self.fact_kinds],
            "call_effect_count": len(self.call_effects),
        }


@dataclass(frozen=True, slots=True)
class StackMemoryObjectWideningRefusal8616:
    """One honestly retained overlap-component widening failure."""

    kind: StackMemoryObjectWideningRefusalKind8616
    detail: str
    addresses: tuple[IRAddress, ...]
    source_logical_refusal: LogicalStackMemoryAliasRefusal8616 | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "kind": self.kind.value,
            "detail": self.detail,
            "addresses": [address.to_dict() for address in self.addresses],
            "source_logical_refusal": (
                None
                if self.source_logical_refusal is None
                else self.source_logical_refusal.to_dict()
            ),
        }


@dataclass(frozen=True, slots=True)
class StackMemoryObjectWideningStats8616:
    """Closed evidence accounting for composed overlap components."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every component became one candidate or refusal."""
        return (
            self.raw_fact_count == self.materialized_count + self.failure_count
            and self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
        )

    def to_dict(self) -> dict[str, int]:
        """Return the five mandatory evidence counters."""
        return {
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
        }


@dataclass(frozen=True, slots=True)
class StackMemoryObjectWideningArtifact8616:
    """Widening outcomes for every composed Alias overlap component."""

    function_addr: int
    source_alias: StackMemorySSAAliasArtifact8616
    candidates: tuple[StackMemoryObjectWideningCandidate8616, ...] = ()
    refusals: tuple[StackMemoryObjectWideningRefusal8616, ...] = ()
    stats: StackMemoryObjectWideningStats8616 = StackMemoryObjectWideningStats8616()

    @property
    def complete(self) -> bool:
        """Return whether source and Widening accounting both close."""
        return self.source_alias.complete and self.stats.complete

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "function_addr": self.function_addr,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "refusals": [refusal.to_dict() for refusal in self.refusals],
            "stats": self.stats.to_dict(),
            "complete": self.complete,
        }


__all__ = [
    "StackMemoryObjectWideningArtifact8616",
    "StackMemoryObjectWideningCandidate8616",
    "StackMemoryObjectWideningRefusal8616",
    "StackMemoryObjectWideningRefusalKind8616",
    "StackMemoryObjectWideningStats8616",
]
