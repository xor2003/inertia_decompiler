"""Bind exact logical stack-word reloads to direct global word spills.

Layer: Widening.
Responsibility: join Alias-owned ``SS:BP`` storage identity with IR-proven
full-register reload/spill flow. The bounded proof accepts only one same-block,
same-SSA-register copy into an exact direct ``DS`` word address.
Consumes IR and Alias facts; it does not inspect C ASTs or materialize C.
Consumes alias-proven storage identity and joins only explicit typed values.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.alias.logical_stack_storage_identity import LogicalStackStorageIdentity8616
from inertia.alias.stack_memory_ssa_contracts import StackMemorySSAAliasArtifact8616
from inertia.ir.core import AddressStatus, MemSpace, SegmentOrigin
from inertia.ir.logical_memory_contracts import (
    IRLogicalMemoryAccess8616,
    IRMemoryAccessKind8616,
)
from inertia.ir.logical_memory_register_transfer import (
    trace_logical_word_register_transfer_8616,
)
from inertia.ir.logical_memory_register_transfer_contracts import (
    LogicalMemoryRegisterTransfer8616,
    LogicalMemoryRegisterTransferKind8616,
    LogicalMemoryRegisterTransferRefusal8616,
)


class LogicalWordMemoryCopyFailure8616(StrEnum):
    """Stable reason one direct word spill was not proven as a stack copy."""

    UPSTREAM_INCOMPLETE = "upstream_incomplete"
    DESTINATION_TRANSFER_REFUSED = "destination_transfer_refused"
    SOURCE_TRANSFER_MISSING = "source_transfer_missing"
    SOURCE_TRANSFER_AMBIGUOUS = "source_transfer_ambiguous"


@dataclass(frozen=True, slots=True)
class LogicalWordMemoryCopy8616:
    """One exact Alias stack word copied through one register to direct DS."""

    source_storage: LogicalStackStorageIdentity8616
    source_transfer: LogicalMemoryRegisterTransfer8616
    destination_transfer: LogicalMemoryRegisterTransfer8616

    @property
    def complete(self) -> bool:
        """Return whether storage, register SSA, address, and order agree."""
        source = self.source_transfer
        destination = self.destination_transfer
        source_address = source.access.address
        destination_address = destination.access.address
        return bool(
            source.complete
            and destination.complete
            and source.kind is LogicalMemoryRegisterTransferKind8616.RELOAD
            and destination.kind is LogicalMemoryRegisterTransferKind8616.SPILL
            and self.source_storage.source == source.access
            and not self.source_storage.storage.needs_synthesis()
            and source_address.space is MemSpace.SS
            and source_address.base == ("bp",)
            and source_address.size == 2
            and source_address.status is AddressStatus.STABLE
            and source_address.segment_origin is SegmentOrigin.PROVEN
            and destination_address.space is MemSpace.DS
            and not destination_address.base
            and destination_address.size == 2
            and destination_address.status is AddressStatus.STABLE
            and destination_address.segment_origin is SegmentOrigin.PROVEN
            and source.register == destination.register
            and source.register_site.block_addr
            == destination.register_site.block_addr
            and source.register_site.instr_index
            < destination.register_site.instr_index
        )


@dataclass(frozen=True, slots=True)
class LogicalWordMemoryCopyRefusal8616:
    """One retained direct-word spill that did not close a copy proof."""

    destination: IRLogicalMemoryAccess8616 | None
    failure: LogicalWordMemoryCopyFailure8616
    detail: str


@dataclass(frozen=True, slots=True)
class LogicalWordMemoryCopyStats8616:
    """Closed evidence counters for direct logical word-copy recovery."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every candidate became one fact or refusal."""
        return bool(
            self.raw_fact_count == self.materialized_count + self.failure_count
            and self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
        )


@dataclass(frozen=True, slots=True)
class LogicalWordMemoryCopyArtifact8616:
    """Closed Widening outcomes for direct DS word-spill candidates."""

    source_alias: StackMemorySSAAliasArtifact8616
    facts: tuple[LogicalWordMemoryCopy8616, ...]
    refusals: tuple[LogicalWordMemoryCopyRefusal8616, ...]
    stats: LogicalWordMemoryCopyStats8616

    @property
    def complete(self) -> bool:
        """Return whether source evidence and all copy outcomes close."""
        return bool(
            self.source_alias.complete
            and self.stats.complete
            and len(self.facts) == self.stats.materialized_count
            and len(self.refusals) == self.stats.failure_count
            and all(fact.complete for fact in self.facts)
        )


def _direct_ds_word_writes_8616(
    source: StackMemorySSAAliasArtifact8616,
) -> tuple[IRLogicalMemoryAccess8616, ...]:
    """Return deterministic exact direct-DS word writes from logical IR."""
    logical = source.source_ssa.logical_memory
    if logical is None or not logical.closed:
        return ()
    return tuple(
        access
        for access in logical.accesses
        if access.kind is IRMemoryAccessKind8616.WRITE
        and access.address.space is MemSpace.DS
        and not access.address.base
        and access.address.size == 2
        and access.address.status is AddressStatus.STABLE
        and access.address.segment_origin is SegmentOrigin.PROVEN
    )


def _matching_sources_8616(
    source: StackMemorySSAAliasArtifact8616,
    destination: LogicalMemoryRegisterTransfer8616,
) -> tuple[tuple[LogicalStackStorageIdentity8616, LogicalMemoryRegisterTransfer8616], ...]:
    """Return exact prior stack reloads carrying the destination SSA value."""
    matches: list[
        tuple[LogicalStackStorageIdentity8616, LogicalMemoryRegisterTransfer8616]
    ] = []
    for identity in source.logical_storage_identities:
        access = identity.source
        if (
            access.kind is not IRMemoryAccessKind8616.READ
            or access.address.size != 2
        ):
            continue
        transfer = trace_logical_word_register_transfer_8616(
            source.source_ssa,
            access,
        )
        if isinstance(transfer, LogicalMemoryRegisterTransferRefusal8616):
            continue
        if (
            transfer.kind is LogicalMemoryRegisterTransferKind8616.RELOAD
            and transfer.register == destination.register
            and transfer.register_site.block_addr
            == destination.register_site.block_addr
            and transfer.register_site.instr_index
            < destination.register_site.instr_index
        ):
            matches.append((identity, transfer))
    return tuple(matches)


def build_logical_word_memory_copy_artifact_8616(
    source: StackMemorySSAAliasArtifact8616,
) -> LogicalWordMemoryCopyArtifact8616:
    """Join every exact direct DS word spill to one Alias stack source."""
    if not source.complete:
        refusal = LogicalWordMemoryCopyRefusal8616(
            None,
            LogicalWordMemoryCopyFailure8616.UPSTREAM_INCOMPLETE,
            "stack-memory Alias evidence is incomplete",
        )
        return LogicalWordMemoryCopyArtifact8616(
            source,
            (),
            (refusal,),
            LogicalWordMemoryCopyStats8616(raw_fact_count=1, failure_count=1),
        )
    destinations = _direct_ds_word_writes_8616(source)
    facts: list[LogicalWordMemoryCopy8616] = []
    refusals: list[LogicalWordMemoryCopyRefusal8616] = []
    for access in destinations:
        destination = trace_logical_word_register_transfer_8616(
            source.source_ssa,
            access,
        )
        if isinstance(destination, LogicalMemoryRegisterTransferRefusal8616):
            refusals.append(
                LogicalWordMemoryCopyRefusal8616(
                    access,
                    LogicalWordMemoryCopyFailure8616.DESTINATION_TRANSFER_REFUSED,
                    f"{destination.failure.value}: {destination.detail}",
                )
            )
            continue
        matches = _matching_sources_8616(source, destination)
        if len(matches) != 1:
            refusals.append(
                LogicalWordMemoryCopyRefusal8616(
                    access,
                    (
                        LogicalWordMemoryCopyFailure8616.SOURCE_TRANSFER_MISSING
                        if not matches
                        else LogicalWordMemoryCopyFailure8616.SOURCE_TRANSFER_AMBIGUOUS
                    ),
                    f"matching stack reload count={len(matches)}",
                )
            )
            continue
        identity, source_transfer = matches[0]
        fact = LogicalWordMemoryCopy8616(
            identity,
            source_transfer,
            destination,
        )
        if fact.complete:
            facts.append(fact)
        else:
            refusals.append(
                LogicalWordMemoryCopyRefusal8616(
                    access,
                    LogicalWordMemoryCopyFailure8616.SOURCE_TRANSFER_MISSING,
                    "source and destination transfer contracts disagree",
                )
            )
    stats = LogicalWordMemoryCopyStats8616(
        raw_fact_count=len(destinations),
        normalized_fact_count=len(facts),
        classified_fact_count=len(facts),
        materialized_count=len(facts),
        failure_count=len(refusals),
    )
    return LogicalWordMemoryCopyArtifact8616(
        source,
        tuple(facts),
        tuple(refusals),
        stats,
    )


__all__ = [
    "LogicalWordMemoryCopy8616",
    "LogicalWordMemoryCopyArtifact8616",
    "LogicalWordMemoryCopyFailure8616",
    "LogicalWordMemoryCopyRefusal8616",
    "LogicalWordMemoryCopyStats8616",
    "build_logical_word_memory_copy_artifact_8616",
]
