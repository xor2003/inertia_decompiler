"""Bind logical word/register transfers to versioned stack storage.

Layer: Widening.
Responsibility: combine IR-proven 16-bit register transfers with Alias-owned
stack identity and exact memory-SSA byte versions. This module does not infer
pointer types, traverse CFG edges, materialize C, or inspect rendered text.
Consumes alias-proven storage identity.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations

from dataclasses import dataclass

from inertia.alias.alias_model_impl import AliasStorageFacts
from inertia.alias.domains import FULL16, register_domain_for_name, register_view_for_name
from inertia.alias.logical_stack_memory_projection import LogicalStackMemoryAliasAccess8616
from inertia.alias.stack_memory_ssa_contracts import (
    StackMemoryAliasStats8616,
    StackMemorySSAAliasArtifact8616,
)
from inertia.ir.core import MemSpace
from inertia.ir.logical_memory_register_transfer import trace_logical_word_register_transfer_8616
from inertia.ir.logical_memory_register_transfer_contracts import (
    LogicalMemoryRegisterTransfer8616,
    LogicalMemoryRegisterTransferFailure8616,
    LogicalMemoryRegisterTransferRefusal8616,
)


@dataclass(frozen=True, slots=True)
class StackWordStorageVersion8616:
    """One Alias-owned stack word and its exact ordered byte versions."""

    storage: AliasStorageFacts
    versions: tuple[int, int]

    @property
    def complete(self) -> bool:
        """Return whether this is one exact non-synthesized stack word."""
        identity = self.storage.identity
        return bool(
            identity is not None
            and identity[0] == "stack"
            and self.storage.domain.width == 2
            and not self.storage.needs_synthesis()
            and all(version > 0 for version in self.versions)
        )


@dataclass(frozen=True, slots=True)
class StackWordRegisterTransfer8616:
    """One IR register transfer bound to exact Alias stack versions."""

    source: LogicalMemoryRegisterTransfer8616
    alias_access: LogicalStackMemoryAliasAccess8616
    storage_version: StackWordStorageVersion8616

    @property
    def complete(self) -> bool:
        """Return whether IR, Alias, width, site, and versions agree."""
        access = self.alias_access
        return bool(
            self.source.complete
            and access.source == self.source.access
            and access.address.space is MemSpace.SS
            and access.address.base == ("bp",)
            and access.address.size == 2
            and access.storage == self.storage_version.storage
            and access.versions == self.storage_version.versions
            and self.storage_version.complete
            and register_domain_for_name(self.source.register.name) is not None
            and register_view_for_name(self.source.register.name) == FULL16
        )


@dataclass(frozen=True, slots=True)
class StackWordRegisterTransferRefusal8616:
    """One retained Widening refusal for a logical stack word."""

    alias_access: LogicalStackMemoryAliasAccess8616
    source_refusal: LogicalMemoryRegisterTransferRefusal8616


@dataclass(frozen=True, slots=True)
class StackWordRegisterTransferArtifact8616:
    """Closed Widening outcomes for every Alias-proven logical stack word."""

    source_alias: StackMemorySSAAliasArtifact8616
    transfers: tuple[StackWordRegisterTransfer8616, ...]
    refusals: tuple[StackWordRegisterTransferRefusal8616, ...]
    stats: StackMemoryAliasStats8616

    @property
    def complete(self) -> bool:
        """Return whether every candidate has one transfer or refusal."""
        return bool(
            self.source_alias.complete
            and self.stats.complete
            and len(self.transfers) == self.stats.materialized_count
            and len(self.refusals) == self.stats.failure_count
            and all(transfer.complete for transfer in self.transfers)
        )

    def by_instruction_addr(self) -> dict[int, tuple[StackWordRegisterTransfer8616, ...]]:
        """Index proven transfers by stable machine instruction identity."""
        grouped: dict[int, list[StackWordRegisterTransfer8616]] = {}
        for transfer in self.transfers:
            grouped.setdefault(transfer.alias_access.source.key.insn_addr, []).append(transfer)
        return {
            instruction_addr: tuple(
                sorted(
                    items,
                    key=lambda item: (
                        item.source.kind.value,
                        item.source.register.name or "",
                        item.storage_version.versions,
                    ),
                )
            )
            for instruction_addr, items in sorted(grouped.items())
        }


def build_stack_word_register_transfer_artifact_8616(
    source: StackMemorySSAAliasArtifact8616,
) -> StackWordRegisterTransferArtifact8616:
    """Bind every Alias-proven logical BP word to exact IR value evidence."""
    candidates = tuple(
        access
        for access in source.logical_accesses
        if access.address.space is MemSpace.SS
        and access.address.base == ("bp",)
        and access.address.size == 2
    )
    transfers: list[StackWordRegisterTransfer8616] = []
    refusals: list[StackWordRegisterTransferRefusal8616] = []
    for access in candidates:
        outcome = trace_logical_word_register_transfer_8616(source.source_ssa, access.source)
        if isinstance(outcome, LogicalMemoryRegisterTransferRefusal8616):
            refusals.append(StackWordRegisterTransferRefusal8616(access, outcome))
            continue
        versions = access.versions
        if len(versions) != 2:
            refusal = LogicalMemoryRegisterTransferRefusal8616(
                access.source,
                LogicalMemoryRegisterTransferFailure8616.EXECUTION_SITE_CONFLICT,
                "Alias logical word does not retain exactly two byte versions",
            )
            refusals.append(StackWordRegisterTransferRefusal8616(access, refusal))
            continue
        transfer = StackWordRegisterTransfer8616(
            outcome,
            access,
            StackWordStorageVersion8616(access.storage, (versions[0], versions[1])),
        )
        if transfer.complete:
            transfers.append(transfer)
        else:
            refusal = LogicalMemoryRegisterTransferRefusal8616(
                access.source,
                LogicalMemoryRegisterTransferFailure8616.EXECUTION_SITE_CONFLICT,
                "IR transfer and Alias stack-word identity disagree",
            )
            refusals.append(StackWordRegisterTransferRefusal8616(access, refusal))
    stats = StackMemoryAliasStats8616(
        raw_fact_count=len(candidates),
        normalized_fact_count=len(transfers),
        classified_fact_count=len(transfers),
        materialized_count=len(transfers),
        failure_count=len(refusals),
    )
    return StackWordRegisterTransferArtifact8616(source, tuple(transfers), tuple(refusals), stats)

__all__ = [
    "StackWordRegisterTransfer8616",
    "StackWordRegisterTransferArtifact8616",
    "StackWordRegisterTransferRefusal8616",
    "StackWordStorageVersion8616",
    "build_stack_word_register_transfer_artifact_8616",
]
