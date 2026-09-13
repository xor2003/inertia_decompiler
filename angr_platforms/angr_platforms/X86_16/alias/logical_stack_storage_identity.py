"""Publish storage identity for closed logical stack-memory operands.

Layer: Alias.
Responsibility: classify exact stable ``SS:BP`` logical operands as Alias
storage identities without claiming a reaching memory-SSA value or version.
Unknown call effects may invalidate values after a call, but cannot erase the
address identity of a complete operand executed before that call.
Owns storage identity; consumers must derive values from separate typed facts.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..ir.core import AddressStatus, IRAddress, MemSpace
from ..ir.logical_memory_contracts import (
    IRLogicalMemoryAccess8616,
    IRLogicalMemoryArtifact8616,
    IRLogicalMemoryRefusal8616,
)
from ..ir.ssa_memory_ranges import StackCoordinateAgreement8616
from .alias_model_impl import AliasStorageFacts, alias_facts_for_ir_address_8616
from .stack_memory_ssa_contracts import StackMemoryAliasStats8616


class LogicalStackStorageIdentityFailure8616(StrEnum):
    """Reason one logical operand has no exact stack storage identity."""

    UPSTREAM_INCOMPLETE = "upstream_incomplete"
    UPSTREAM_REFUSAL = "upstream_refusal"
    FUNCTION_IDENTITY_MISMATCH = "function_identity_mismatch"
    ACCESS_INCOMPLETE = "access_incomplete"
    NON_STACK_ADDRESS = "non_stack_address"
    UNSTABLE_BP_ADDRESS = "unstable_bp_address"
    ALIAS_FAILURE = "alias_failure"
    COORDINATE_CONFLICT = "coordinate_conflict"


@dataclass(frozen=True, slots=True)
class LogicalStackStorageIdentity8616:
    """One logical operand bound to exact Alias-owned stack storage."""

    source: IRLogicalMemoryAccess8616
    storage: AliasStorageFacts

    @property
    def address(self) -> IRAddress:
        """Return the exact unversioned logical stack range."""
        return self.source.address

    def to_dict(self) -> dict[str, object]:
        """Return deterministic identity diagnostics."""
        return {
            "source": self.source.to_dict(),
            "storage_identity": self.storage.identity,
        }


@dataclass(frozen=True, slots=True)
class LogicalStackStorageIdentityRefusal8616:
    """One retained non-identity outcome from the logical-memory census."""

    failure: LogicalStackStorageIdentityFailure8616
    detail: str
    source: IRLogicalMemoryAccess8616 | None = None
    source_refusal: IRLogicalMemoryRefusal8616 | None = None

    def to_dict(self) -> dict[str, object]:
        """Return deterministic refusal diagnostics."""
        return {
            "failure": self.failure.value,
            "detail": self.detail,
            "source": None if self.source is None else self.source.to_dict(),
            "source_refusal": (
                None if self.source_refusal is None else self.source_refusal.to_dict()
            ),
        }


@dataclass(frozen=True, slots=True)
class LogicalStackStorageIdentityProjection8616:
    """Closed Alias identity outcomes for one logical-memory artifact."""

    identities: tuple[LogicalStackStorageIdentity8616, ...]
    refusals: tuple[LogicalStackStorageIdentityRefusal8616, ...]
    stats: StackMemoryAliasStats8616

    @property
    def complete(self) -> bool:
        """Return whether every input has one identity or typed refusal."""
        return bool(
            self.stats.complete
            and len(self.identities) == self.stats.materialized_count
            and len(self.refusals) == self.stats.failure_count
        )


def _project_access_8616(
    function_addr: int,
    source: IRLogicalMemoryAccess8616,
    coordinate_agreement: StackCoordinateAgreement8616,
) -> LogicalStackStorageIdentity8616 | LogicalStackStorageIdentityRefusal8616:
    """Project one exact logical operand without claiming memory value state."""
    if source.key.function_addr != function_addr:
        return LogicalStackStorageIdentityRefusal8616(
            LogicalStackStorageIdentityFailure8616.FUNCTION_IDENTITY_MISMATCH,
            "logical operand belongs to another function",
            source,
        )
    if not source.complete:
        return LogicalStackStorageIdentityRefusal8616(
            LogicalStackStorageIdentityFailure8616.ACCESS_INCOMPLETE,
            "logical operand byte coverage is incomplete",
            source,
        )
    address = source.address
    if address.space is MemSpace.SS and coordinate_agreement is StackCoordinateAgreement8616.CONFLICT:
        return LogicalStackStorageIdentityRefusal8616(
            LogicalStackStorageIdentityFailure8616.COORDINATE_CONFLICT,
            "BP-relative storage has contradictory captured coordinates",
            source,
        )
    if address.space is not MemSpace.SS:
        return LogicalStackStorageIdentityRefusal8616(
            LogicalStackStorageIdentityFailure8616.NON_STACK_ADDRESS,
            "logical operand is not in SS stack memory",
            source,
        )
    if (
        address.status is not AddressStatus.STABLE
        or address.base != ("bp",)
        or address.size <= 0
    ):
        return LogicalStackStorageIdentityRefusal8616(
            LogicalStackStorageIdentityFailure8616.UNSTABLE_BP_ADDRESS,
            "logical stack operand is not an exact stable BP range",
            source,
        )
    storage = alias_facts_for_ir_address_8616(address)
    if not isinstance(storage, AliasStorageFacts) or storage.needs_synthesis():
        return LogicalStackStorageIdentityRefusal8616(
            LogicalStackStorageIdentityFailure8616.ALIAS_FAILURE,
            "canonical Alias model did not materialize exact stack storage",
            source,
        )
    return LogicalStackStorageIdentity8616(source, storage)


def project_logical_stack_storage_identities_8616(
    function_addr: int,
    source: IRLogicalMemoryArtifact8616 | None,
    *,
    coordinate_agreement: StackCoordinateAgreement8616 = StackCoordinateAgreement8616.NO_CONFLICT_OBSERVED,
) -> LogicalStackStorageIdentityProjection8616:
    """Classify logical operands while keeping value-version refusal separate."""
    if source is None:
        return LogicalStackStorageIdentityProjection8616(
            (), (), StackMemoryAliasStats8616()
        )
    if source.function_addr != function_addr or not source.closed:
        failure = (
            LogicalStackStorageIdentityFailure8616.FUNCTION_IDENTITY_MISMATCH
            if source.function_addr != function_addr
            else LogicalStackStorageIdentityFailure8616.UPSTREAM_INCOMPLETE
        )
        count = max(1, source.stats.raw_fact_count)
        refusals = tuple(
            LogicalStackStorageIdentityRefusal8616(
                failure,
                "logical-memory identity census is not closed",
            )
            for _index in range(count)
        )
        return LogicalStackStorageIdentityProjection8616(
            (),
            refusals,
            StackMemoryAliasStats8616(
                raw_fact_count=count,
                failure_count=count,
            ),
        )
    outcomes = tuple(_project_access_8616(function_addr, item, coordinate_agreement) for item in source.accesses)
    identities = tuple(
        item for item in outcomes if isinstance(item, LogicalStackStorageIdentity8616)
    )
    refusals = tuple(
        item
        for item in outcomes
        if isinstance(item, LogicalStackStorageIdentityRefusal8616)
    ) + tuple(
        LogicalStackStorageIdentityRefusal8616(
            LogicalStackStorageIdentityFailure8616.UPSTREAM_REFUSAL,
            item.detail,
            source_refusal=item,
        )
        for item in source.refusals
    )
    materialized_count = len(identities)
    stats = StackMemoryAliasStats8616(
        raw_fact_count=materialized_count + len(refusals),
        normalized_fact_count=materialized_count,
        classified_fact_count=materialized_count,
        materialized_count=materialized_count,
        failure_count=len(refusals),
    )
    return LogicalStackStorageIdentityProjection8616(identities, refusals, stats)


__all__ = [
    "LogicalStackStorageIdentity8616",
    "LogicalStackStorageIdentityFailure8616",
    "LogicalStackStorageIdentityProjection8616",
    "LogicalStackStorageIdentityRefusal8616",
    "project_logical_stack_storage_identities_8616",
]
