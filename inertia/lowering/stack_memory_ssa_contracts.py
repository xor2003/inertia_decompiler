"""Typed contracts for stack-memory SSA object materialization.

Layer: Types/Lowering.
Responsibility: define immutable candidates, refusals, outcomes, and closed
evidence accounting for Alias-proved stack-memory SSA storage.
Consumes alias, widening, and typed facts without rediscovering storage semantics.
Do not recover semantics from COD, source, assembly, or rendered C text.
Do not perform structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.alias.alias_model_impl import AliasStorageFacts
from inertia.alias.stack_memory_ssa_contracts import StackMemoryAliasFactKind8616
from inertia.ir.core import IRAddress

from .stack_lowering_result import StackLoweringResult
from .stack_projection_retirement import StackProjectionRetirementArtifact8616


class StackMemoryObjectKind8616(StrEnum):
    """Lowering role proven by one exact BP offset."""

    LOCAL = "local"
    ARGUMENT = "argument"


class StackMemorySSALoweringRefusalKind8616(StrEnum):
    """Typed reason why one storage group did not become a C variable."""

    SOURCE_ALIAS_REFUSAL = "source_alias_refusal"
    SOURCE_WIDENING_REFUSAL = "source_widening_refusal"
    INCONSISTENT_ALIAS_STORAGE = "inconsistent_alias_storage"
    PHI_WITHOUT_ACCESS = "phi_without_access"
    FRAME_CONTROL_SLOT = "frame_control_slot"
    FRAME_COORDINATE_UNPROVEN = "frame_coordinate_unproven"
    ARGUMENT_STORAGE_TRIAL_REQUIRED = "argument_storage_trial_required"
    MATERIALIZATION_FAILED = "materialization_failed"


@dataclass(frozen=True, slots=True)
class StackMemorySSALoweringCandidate8616:
    """One exact Alias storage range ready for C-variable materialization."""

    role: StackMemoryObjectKind8616
    address: IRAddress
    entry_sp_offset: int
    storage: AliasStorageFacts
    versions: tuple[int, ...]
    fact_kinds: tuple[StackMemoryAliasFactKind8616, ...]

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "role": self.role.value,
            "address": self.address.to_dict(),
            "entry_sp_offset": self.entry_sp_offset,
            "versions": list(self.versions),
            "fact_kinds": [kind.value for kind in self.fact_kinds],
        }


@dataclass(frozen=True, slots=True)
class StackMemorySSALoweringRefusal8616:
    """One honestly retained stack-object materialization refusal."""

    kind: StackMemorySSALoweringRefusalKind8616
    detail: str
    address: IRAddress | None = None
    related_addresses: tuple[IRAddress, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "kind": self.kind.value,
            "detail": self.detail,
            "address": self.address.to_dict() if self.address is not None else None,
            "related_addresses": [address.to_dict() for address in self.related_addresses],
        }


@dataclass(frozen=True, slots=True)
class StackMemorySSALoweringStats8616:
    """Closed evidence accounting for exact storage materialization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every distinct storage input has one outcome."""
        return (
            self.raw_fact_count == self.materialized_count + self.failure_count
            and self.normalized_fact_count == self.classified_fact_count
            and self.classified_fact_count <= self.raw_fact_count
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
class StackMemorySSALoweringArtifact8616:
    """Exact stack-object candidates, outcomes, and materializer diagnostics."""

    function_addr: int
    candidates: tuple[StackMemorySSALoweringCandidate8616, ...] = ()
    refusals: tuple[StackMemorySSALoweringRefusal8616, ...] = ()
    result: StackLoweringResult | None = None
    projection_retirement: StackProjectionRetirementArtifact8616 = StackProjectionRetirementArtifact8616()  # noqa: RUF009
    stats: StackMemorySSALoweringStats8616 = StackMemorySSALoweringStats8616()

    @property
    def complete(self) -> bool:
        """Return whether evidence closes and the materializer accepted all candidates."""
        return self.stats.complete and (self.result is None or self.result.is_ok)

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "function_addr": self.function_addr,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "refusals": [refusal.to_dict() for refusal in self.refusals],
            "result": self.result.to_dict() if self.result is not None else None,
            "projection_retirement": self.projection_retirement.to_dict(),
            "stats": self.stats.to_dict(),
            "complete": self.complete,
        }


__all__ = [
    "StackMemoryObjectKind8616",
    "StackMemorySSALoweringArtifact8616",
    "StackMemorySSALoweringCandidate8616",
    "StackMemorySSALoweringRefusal8616",
    "StackMemorySSALoweringRefusalKind8616",
    "StackMemorySSALoweringStats8616",
]
