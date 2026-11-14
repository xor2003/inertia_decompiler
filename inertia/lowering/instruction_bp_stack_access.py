# cython: language_level=3, infer_types=True
"""Project exact Alias stack accesses by source instruction address.

Layer: Types/Lowering.
Responsibility: index already-proven ``SS:BP`` Alias accesses for C AST
materializers that carry exact instruction-origin tags. Alias remains the
authoritative storage owner; this module only projects its facts into a lookup
shape suitable for Lowering.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from inertia.alias.stack_memory_ssa_contracts import (
    StackMemoryAliasFactKind8616,
    StackMemorySSAAliasArtifact8616,
)
from inertia.ir.core import AddressStatus, IRAddress, MemSpace
from inertia.ir.logical_memory_contracts import IRMemoryAccessKind8616
from inertia.ir.ssa_memory_contracts import SSAMemoryAccessKind8616
import dataclasses
import operator
import builtins


@dataclasses.dataclass(frozen=True, )
class InstructionBpStackAccess8616:
    """One exact Alias-proven BP access at an instruction address."""

    displacement: cython.longlong
    size: cython.longlong
    kind: StackMemoryAliasFactKind8616
    evidence: InstructionBpStackAccessEvidence8616


class InstructionBpStackAccessEvidence8616(StrEnum):
    """Alias projection that determines an instruction access width."""

    EXECUTION_SLICE = "execution_slice"
    LOGICAL_ACCESS = "logical_access"


class InstructionBpStackAccessRefusalKind8616(StrEnum):
    """Reason one direct-BP Alias fact could not enter the instruction index."""

    SOURCE_INSTRUCTION_MISSING = "source_instruction_missing"


@dataclasses.dataclass(frozen=True, )
class InstructionBpStackAccessRefusal8616:
    """One typed refusal retained by the instruction projection."""

    kind: InstructionBpStackAccessRefusalKind8616
    block_addr: cython.longlong
    instr_index: cython.longlong
    detail: object


@dataclasses.dataclass(frozen=True, )
class InstructionBpStackAccessStats8616:
    """Closed evidence accounting for the Alias-to-Lowering projection."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0

    @property
    def complete(self) -> cython.bint:
        """Return whether every direct-BP input was indexed or refused."""
        return (
            operator.eq(self.raw_fact_count, self.materialized_count + self.failure_count)
            and self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
        )


@dataclasses.dataclass(frozen=True, )
class InstructionBpStackAccessIndex8616:
    """Immutable instruction lookup projected from one exact Alias artifact."""

    source_alias: StackMemorySSAAliasArtifact8616
    by_instruction_addr: Mapping[cython.longlong, tuple[InstructionBpStackAccess8616, ...]]
    refusals: object
    stats: InstructionBpStackAccessStats8616

    @property
    def fact_count(self) -> cython.longlong:
        """Return the number of distinct indexed instruction access facts."""
        return sum(len(facts) for facts in builtins.iter(self.by_instruction_addr.values()))

    @property
    def complete(self) -> cython.bint:
        """Return whether evidence accounting and source Alias both close."""
        return self.source_alias.complete and self.stats.complete

    @property
    def logical_inventory(self) -> tuple[tuple[cython.longlong, cython.longlong, cython.longlong, IRMemoryAccessKind8616], ...]:
        """Return logical machine address, BP range, and kind diagnostics."""
        return tuple(
            (
                identity.source.key.insn_addr,
                identity.address.offset,
                identity.address.size,
                identity.source.kind,
            )
            for identity in iter(self.source_alias.logical_storage_identities)
        )


class _CodegenBoundary8616(Protocol):
    """Dynamic codegen extension used to retain the typed index."""

    _inertia_instruction_bp_stack_access_index_8616: InstructionBpStackAccessIndex8616


@cython.ccall
def _is_direct_stable_bp_address_8616(address: IRAddress) -> cython.bint:
    """Return whether Alias proved one exact stable SS:BP range."""
    return (
        address.space is MemSpace.SS
        and address.base == ("bp",)
        and address.status is AddressStatus.STABLE
        and address.size > 0
    )


def _instruction_addr_8616(
    source: StackMemorySSAAliasArtifact8616,
    block_addr: cython.longlong,
    instr_index: cython.longlong,
) -> int | None:
    """Resolve one Alias source position through its exact SSA owner."""
    block: object
    block = next(
        (candidate for candidate in iter(source.source_ssa.blocks) if operator.eq(candidate.addr, block_addr)),
        None,
    )
    if block is None or not 0 <= instr_index < len(block.instrs):
        return None
    instruction_addr = block.instrs[instr_index].addr
    return instruction_addr if isinstance(instruction_addr, int) else None


@cython.ccall
def _access_kind_8616(kind: SSAMemoryAccessKind8616) -> StackMemoryAliasFactKind8616:
    """Project the IR access kind into the existing Alias fact enum."""
    return (
        StackMemoryAliasFactKind8616.STORE
        if kind is SSAMemoryAccessKind8616.STORE
        else StackMemoryAliasFactKind8616.LOAD
    )


@cython.ccall
def _logical_access_kind_8616(
    kind: IRMemoryAccessKind8616,
) -> StackMemoryAliasFactKind8616:
    """Project one authoritative logical access kind into Alias terminology."""
    return (
        StackMemoryAliasFactKind8616.STORE
        if kind is IRMemoryAccessKind8616.WRITE
        else StackMemoryAliasFactKind8616.LOAD
    )


def build_instruction_bp_stack_access_index_8616(
    source: StackMemorySSAAliasArtifact8616,
) -> InstructionBpStackAccessIndex8616:
    """Project direct stable BP accesses from one exact Alias artifact."""
    instruction_addr: object
    address: object
    block_addr: object
    instr_index: object
    kind: object
    candidates: list[tuple[cython.longlong, cython.longlong, IRAddress, StackMemoryAliasFactKind8616]] = [
        (fact.block_addr, fact.instr_index, fact.address, fact.kind)
        for fact in iter(source.facts)
        if fact.kind is not StackMemoryAliasFactKind8616.PHI
        and isinstance(fact.instr_index, int)
        and _is_direct_stable_bp_address_8616(fact.address)
    ]
    candidates.extend(
        (
            access.source.block_addr,
            access.source.instr_index,
            access.source.address,
            _access_kind_8616(access.source.kind),
        )
        for access in iter(source.accesses)
        if _is_direct_stable_bp_address_8616(access.source.address)
    )
    logical_candidates = tuple(
        (
            identity.source.key.insn_addr,
            identity.address,
            _logical_access_kind_8616(identity.source.kind),
        )
        for identity in iter(source.logical_storage_identities)
        if _is_direct_stable_bp_address_8616(identity.address)
    )
    collected: dict[cython.longlong, set[InstructionBpStackAccess8616]] = {}
    refusals: list[InstructionBpStackAccessRefusal8616] = []
    materialized_count = 0
    for block_addr, instr_index, address, kind in candidates:
        instruction_addr = _instruction_addr_8616(source, block_addr, instr_index)
        if instruction_addr is None:
            refusals.append(
                InstructionBpStackAccessRefusal8616(
                    InstructionBpStackAccessRefusalKind8616.SOURCE_INSTRUCTION_MISSING,
                    block_addr,
                    instr_index,
                    "Alias source position has no exact SSA instruction address",
                )
            )
            continue
        collected.setdefault(instruction_addr, set()).add(
            InstructionBpStackAccess8616(
                address.offset,
                address.size,
                kind,
                InstructionBpStackAccessEvidence8616.EXECUTION_SLICE,
            )
        )
        materialized_count += 1
    for instruction_addr, address, kind in logical_candidates:
        collected.setdefault(instruction_addr, set()).add(
            InstructionBpStackAccess8616(
                address.offset,
                address.size,
                kind,
                InstructionBpStackAccessEvidence8616.LOGICAL_ACCESS,
            )
        )
        materialized_count += 1
    stats = InstructionBpStackAccessStats8616(
        raw_fact_count=len(candidates) + len(logical_candidates),
        normalized_fact_count=materialized_count,
        classified_fact_count=materialized_count,
        materialized_count=materialized_count,
        failure_count=len(refusals),
    )
    return InstructionBpStackAccessIndex8616(
        source,
        {
            addr: tuple(
                sorted(
                    facts,
                    key=lambda fact: (
                        fact.displacement,
                        fact.size,
                        fact.kind.value,
                        fact.evidence.value,
                    ),
                )
            )
            for addr, facts in builtins.iter(sorted(tuple(collected.items())))
        },
        tuple(refusals),
        stats,
    )


@cython.ccall
def ensure_instruction_bp_stack_access_index_8616(
    codegen: object,
    source: StackMemorySSAAliasArtifact8616,
) -> InstructionBpStackAccessIndex8616:
    """Return the index consuming this exact immutable Alias artifact."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        existing = boundary._inertia_instruction_bp_stack_access_index_8616
    except AttributeError:
        existing = None
    if (
        isinstance(existing, InstructionBpStackAccessIndex8616)
        and existing.source_alias is source
    ):
        return existing
    built = build_instruction_bp_stack_access_index_8616(source)
    boundary._inertia_instruction_bp_stack_access_index_8616 = built
    return built


def select_instruction_bp_stack_access_8616(
    index: InstructionBpStackAccessIndex8616,
    instruction_addrs: object,
    *,
    displacement: cython.longlong,
    size: cython.longlong,
    kind: StackMemoryAliasFactKind8616 | None = None,
) -> InstructionBpStackAccess8616 | None:
    """Keep exact execution width; a wider logical owner is not a wider access."""
    sole_range: object
    candidates = {
        fact
        for instruction_addr in iter(instruction_addrs)
        for fact in builtins.iter(index.by_instruction_addr.get(instruction_addr, ()))
        if kind is None or fact.kind is kind
    }
    exact = tuple(
        fact
        for fact in iter(candidates)
        if operator.eq(fact.displacement, displacement) and operator.eq(fact.size, size)
    )
    exact_logical = tuple(
        fact
        for fact in iter(exact)
        if fact.evidence is InstructionBpStackAccessEvidence8616.LOGICAL_ACCESS
    )
    if exact_logical:
        return min(exact_logical, key=lambda fact: fact.kind.value)
    if exact:
        return min(exact, key=lambda fact: (fact.evidence.value, fact.kind.value))
    same_base_logical_owners = tuple(
        fact
        for fact in iter(candidates)
        if fact.evidence is InstructionBpStackAccessEvidence8616.LOGICAL_ACCESS
        and operator.eq(fact.displacement, displacement)
        and fact.size > size
    )
    if same_base_logical_owners:
        return min(same_base_logical_owners, key=lambda fact: (fact.size, fact.kind.value))
    logical = tuple(
        fact
        for fact in iter(candidates)
        if fact.evidence is InstructionBpStackAccessEvidence8616.LOGICAL_ACCESS
    )
    if len({(fact.displacement, fact.size) for fact in iter(logical)}) == 1:
        return min(logical, key=lambda fact: fact.kind.value)
    ranges = {(fact.displacement, fact.size) for fact in iter(candidates)}
    if len(ranges) != 1:
        return None
    sole_range = next(iter(ranges))
    return min(
        (fact for fact in iter(candidates) if operator.eq((fact.displacement, fact.size), sole_range)),
        key=lambda fact: fact.kind.value,
    )


__all__ = [
    "InstructionBpStackAccess8616",
    "InstructionBpStackAccessEvidence8616",
    "InstructionBpStackAccessIndex8616",
    "InstructionBpStackAccessRefusal8616",
    "InstructionBpStackAccessRefusalKind8616",
    "InstructionBpStackAccessStats8616",
    "build_instruction_bp_stack_access_index_8616",
    "ensure_instruction_bp_stack_access_index_8616",
    "select_instruction_bp_stack_access_8616",
]
