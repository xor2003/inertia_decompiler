"""Typed contracts for the stack-memory SSA Alias projection.

Layer: Alias.
Responsibility: define immutable Alias facts, byte-overlap projections,
refusals, and closed evidence accounting for stack-memory inputs.
Owns storage identity contracts only. Do not infer locals or types, widen
ranges, structure control flow, rewrite generated C, or inspect rendered text.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from ..ir.core import IRAddress, IRRefusal
from ..ir.ssa_memory_contracts import (
    SSACallStackEffectSite8616,
    SSAMemoryAccess8616,
    SSAMemoryAccessSlice8616,
    SSAMemoryOverlap8616,
)
from .alias_model_impl import AliasStorageFacts
from .stack_address_escape import StackAddressEscape8616

if TYPE_CHECKING:
    from ..ir.ssa_function import SSAFunctionArtifact
    from ..ir.stack_extent_evidence import ReleasedStackExtent8616, StackExtentEvidence8616
    from .logical_stack_memory_projection import (
        LogicalStackMemoryAliasAccess8616,
        LogicalStackMemoryAliasRefusal8616,
    )
    from .logical_stack_storage_identity import (
        LogicalStackStorageIdentity8616,
        LogicalStackStorageIdentityRefusal8616,
    )
    from .private_stack_writes import PrivateStackWriteDecision8616


class StackMemoryAliasFactKind8616(StrEnum):
    """Kind of versioned memory fact projected into Alias."""

    LOAD = "load"
    STORE = "store"
    PHI = "phi"


class StackMemoryAliasRefusalKind8616(StrEnum):
    """Typed reason why one stack-memory SSA input was not projected."""

    UPSTREAM_INCOMPLETE = "upstream_incomplete"
    UPSTREAM_MEMORY_REFUSAL = "upstream_memory_refusal"
    UNVERSIONED_ADDRESS = "unversioned_address"
    ALIAS_FAILURE = "alias_failure"
    UNCLASSIFIABLE_ADDRESS = "unclassifiable_address"
    UNVERSIONED_PHI = "unversioned_phi"
    INCONSISTENT_PHI_STORAGE = "inconsistent_phi_storage"
    INCONSISTENT_OVERLAP_STORAGE = "inconsistent_overlap_storage"
    INCOMPLETE_ACCESS_SLICES = "incomplete_access_slices"
    INCONSISTENT_ACCESS_STORAGE = "inconsistent_access_storage"
    ORPHAN_UPSTREAM_REFUSAL = "orphan_upstream_refusal"


@dataclass(frozen=True, slots=True)
class StackMemorySSAAliasFact8616:
    """One exact SSA memory version bound to an Alias storage identity."""

    kind: StackMemoryAliasFactKind8616
    block_addr: int
    instr_index: int | None
    address: IRAddress
    storage: AliasStorageFacts
    incoming_versions: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        identity = self.storage.identity
        return {
            "kind": self.kind.value,
            "block_addr": self.block_addr,
            "instr_index": self.instr_index,
            "address": self.address.to_dict(),
            "storage_kind": identity[0] if identity is not None else None,
            "incoming_versions": list(self.incoming_versions),
        }


@dataclass(frozen=True, slots=True)
class StackMemorySSAAliasAccessSlice8616:
    """Alias storage identity for one exact slice of a composed access."""

    source: SSAMemoryAccessSlice8616
    storage: AliasStorageFacts

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        identity = self.storage.identity
        return {
            "source": self.source.to_dict(),
            "storage_kind": identity[0] if identity is not None else None,
        }


@dataclass(frozen=True, slots=True)
class StackMemorySSAAliasAccess8616:
    """One original access and the ordered Alias identities of its byte views."""

    source: SSAMemoryAccess8616
    storage: AliasStorageFacts
    slices: tuple[StackMemorySSAAliasAccessSlice8616, ...]

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        identity = self.storage.identity
        return {
            "source": self.source.to_dict(),
            "storage_kind": identity[0] if identity is not None else None,
            "slices": [item.to_dict() for item in self.slices],
        }


@dataclass(frozen=True, slots=True)
class StackMemorySSAAliasOverlap8616:
    """Alias projection of one byte-exact IR overlap relationship."""

    source: SSAMemoryOverlap8616
    left_storage: AliasStorageFacts
    right_storage: AliasStorageFacts
    intersection_storage: AliasStorageFacts

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        left_identity = self.left_storage.identity
        right_identity = self.right_storage.identity
        intersection_identity = self.intersection_storage.identity
        return {
            "source": self.source.to_dict(),
            "left_storage_kind": left_identity[0] if left_identity is not None else None,
            "right_storage_kind": right_identity[0] if right_identity is not None else None,
            "intersection_storage_kind": (
                intersection_identity[0] if intersection_identity is not None else None
            ),
        }


@dataclass(frozen=True, slots=True)
class StackMemoryAliasRefusal8616:
    """One honestly retained Alias projection failure."""

    kind: StackMemoryAliasRefusalKind8616
    block_addr: int | None
    instr_index: int | None
    detail: str
    address: IRAddress | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "kind": self.kind.value,
            "block_addr": self.block_addr,
            "instr_index": self.instr_index,
            "detail": self.detail,
            "address": self.address.to_dict() if self.address is not None else None,
        }


@dataclass(frozen=True, slots=True)
class StackMemoryAliasStats8616:
    """Closed evidence accounting for the IR-to-Alias projection."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every input became one fact or one refusal."""
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
class StackMemorySSAAliasArtifact8616:
    """Alias facts and refusals projected from one function SSA artifact."""

    function_addr: int
    source_ssa: SSAFunctionArtifact
    facts: tuple[StackMemorySSAAliasFact8616, ...] = ()
    accesses: tuple[StackMemorySSAAliasAccess8616, ...] = ()
    overlaps: tuple[StackMemorySSAAliasOverlap8616, ...] = ()
    refusals: tuple[StackMemoryAliasRefusal8616, ...] = ()
    source_refusals: tuple[IRRefusal, ...] = ()
    call_effects: tuple[SSACallStackEffectSite8616, ...] = ()
    stats: StackMemoryAliasStats8616 = StackMemoryAliasStats8616()
    upstream_complete: bool = True
    logical_accesses: tuple[LogicalStackMemoryAliasAccess8616, ...] = ()
    logical_refusals: tuple[LogicalStackMemoryAliasRefusal8616, ...] = ()
    logical_stats: StackMemoryAliasStats8616 = StackMemoryAliasStats8616()
    logical_storage_identities: tuple[LogicalStackStorageIdentity8616, ...] = ()
    logical_storage_refusals: tuple[LogicalStackStorageIdentityRefusal8616, ...] = ()
    logical_storage_stats: StackMemoryAliasStats8616 = StackMemoryAliasStats8616()
    stack_extent_evidence: tuple[StackExtentEvidence8616, ...] = ()
    frame_address_escape: StackAddressEscape8616 = StackAddressEscape8616.UNKNOWN_REFUSE
    private_write_decisions: tuple[PrivateStackWriteDecision8616, ...] = ()

    @property
    def private_write_census(self) -> dict[str, int]:
        """Count source-group proofs, not downstream deleted C assignments."""
        proven = sum(decision.proven for decision in self.private_write_decisions)
        return {
            "raw_fact_count": len(self.private_write_decisions),
            "normalized_fact_count": sum(decision.source_addr is not None for decision in self.private_write_decisions),
            "classified_fact_count": proven,
            "materialized_count": proven,
            "failure_count": len(self.private_write_decisions) - proven,
        }

    @property
    def released_stack_extents(self) -> tuple[ReleasedStackExtent8616, ...]:
        """Derive coordinate spans without hiding the authoritative verdicts."""
        return tuple(extent for evidence in self.stack_extent_evidence for extent in evidence.extents)

    def __post_init__(self) -> None:
        """Reject artifacts whose function identity disagrees with their source."""
        if self.function_addr != self.source_ssa.function_addr:
            raise ValueError("Alias artifact function address must match its exact SSA source")

    @property
    def logical_complete(self) -> bool:
        """Return whether the separate logical Alias evidence loop closes."""
        return (
            self.logical_stats.complete
            and len(self.logical_accesses) == self.logical_stats.materialized_count
            and len(self.logical_refusals) == self.logical_stats.failure_count
        )

    @property
    def logical_storage_complete(self) -> bool:
        """Return whether unversioned logical storage identity closes."""
        return (
            self.logical_storage_stats.complete
            and len(self.logical_storage_identities)
            == self.logical_storage_stats.materialized_count
            and len(self.logical_storage_refusals)
            == self.logical_storage_stats.failure_count
        )

    @property
    def complete(self) -> bool:
        """Return whether upstream and Alias evidence accounting both close."""
        return (
            self.upstream_complete
            and self.stats.complete
            and self.logical_complete
            and self.logical_storage_complete
        )

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "function_addr": self.function_addr,
            "source_ssa_function_addr": self.source_ssa.function_addr,
            "released_stack_extents": [extent.to_dict() for extent in self.released_stack_extents],
            "stack_extent_evidence": [evidence.to_dict() for evidence in self.stack_extent_evidence],
            "frame_address_escape": self.frame_address_escape.name,
            "private_write_decisions": [decision.to_dict() for decision in self.private_write_decisions],
            "private_write_census": self.private_write_census,
            "facts": [fact.to_dict() for fact in self.facts],
            "accesses": [access.to_dict() for access in self.accesses],
            "overlaps": [overlap.to_dict() for overlap in self.overlaps],
            "refusals": [refusal.to_dict() for refusal in self.refusals],
            "source_refusals": [refusal.to_dict() for refusal in self.source_refusals],
            "call_effects": [effect.to_dict() for effect in self.call_effects],
            "stats": self.stats.to_dict(),
            "upstream_complete": self.upstream_complete,
            "logical_accesses": [access.to_dict() for access in self.logical_accesses],
            "logical_refusals": [refusal.to_dict() for refusal in self.logical_refusals],
            "logical_stats": self.logical_stats.to_dict(),
            "logical_complete": self.logical_complete,
            "logical_storage_identities": [
                identity.to_dict() for identity in self.logical_storage_identities
            ],
            "logical_storage_refusals": [
                refusal.to_dict() for refusal in self.logical_storage_refusals
            ],
            "logical_storage_stats": self.logical_storage_stats.to_dict(),
            "logical_storage_complete": self.logical_storage_complete,
            "complete": self.complete,
        }


__all__ = [
    "StackMemoryAliasFactKind8616",
    "StackMemoryAliasRefusal8616",
    "StackMemoryAliasRefusalKind8616",
    "StackMemoryAliasStats8616",
    "StackMemorySSAAliasAccess8616",
    "StackMemorySSAAliasAccessSlice8616",
    "StackMemorySSAAliasArtifact8616",
    "StackMemorySSAAliasFact8616",
    "StackMemorySSAAliasOverlap8616",
]
