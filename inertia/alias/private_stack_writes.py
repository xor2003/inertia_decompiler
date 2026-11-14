# cython: language_level=3, infer_types=True
"""Classify exact unread writes inside released, non-escaping stack extents.

Layer: Alias.
Responsibility: consume IR lifetime/read evidence and authoritative Alias
identities to classify source stores, retaining explicit refusals.
Owns storage identity only. Do not infer C locals or types, widen adjacent
ranges, structure control flow, rewrite generated C, or inspect rendered text.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from inertia.ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from inertia.ir.ssa import SSABlock
from inertia.ir.ssa_memory_contracts import SSAMemoryAccessKind8616
from inertia.ir.ssa_memory_ranges import memory_range_key_8616
from inertia.ir.stack_extent_evidence import StackExtentEvidence8616
from inertia.ir.stack_range_overlap import stack_ranges_may_overlap_8616

from .stack_address_escape import StackAddressEscape8616
from .stack_memory_ssa_contracts import StackMemoryAliasFactKind8616
import dataclasses
import operator
StackMemorySSAAliasArtifact8616 = typing.TypeVar("StackMemorySSAAliasArtifact8616")

if TYPE_CHECKING:
    from .stack_memory_ssa_contracts import StackMemorySSAAliasArtifact8616


class PrivateStackWriteVerdict8616(StrEnum):
    """Per-source decision; every non-proven state keeps the write."""

    UNREAD_RELEASED = "unread_released"
    UNKNOWN_CONTEXT = "unknown_context"
    UNKNOWN_READ = "unknown_read"
    NO_ALIAS = "no_alias"
    OUTSIDE_LIFETIME = "outside_lifetime"
    READ_OVERLAP = "read_overlap"


@dataclasses.dataclass(frozen=True, )
class PrivateStackWriteDecision8616:
    """A complete group of raw stores from one source instruction."""

    block_addr: cython.longlong
    source_addr: int | None
    instruction_indices: object
    verdict: PrivateStackWriteVerdict8616

    @property
    def proven(self) -> cython.bint:
        """Return whether every source store passed the complete proof."""
        return self.verdict is PrivateStackWriteVerdict8616.UNREAD_RELEASED

    def to_dict(self) -> dict[str, object]:
        """Serialize exact source identity and a typed refusal or proof."""
        return {"block_addr": self.block_addr, "source_addr": self.source_addr,
                "instruction_indices": list(self.instruction_indices), "verdict": self.verdict.value}


@cython.ccall
def _entry_range(offset: cython.longlong, size: cython.longlong) -> IRAddress:
    """Use one common block-entry coordinate for circular overlap checks."""
    return IRAddress(MemSpace.SS, ("sp",), offset, size, AddressStatus.STABLE, SegmentOrigin.PROVEN)


@cython.ccall
def _read_ranges(block: SSABlock, evidence: StackExtentEvidence8616) -> object:
    """Refuse unresolved reads; a different unproven memory view is not disjoint."""
    offset: object
    index: object
    instruction: object
    reads = []
    for index, instruction in enumerate(block.instrs):
        if instruction.op != "LOAD":
            continue
        if not instruction.args or not isinstance(instruction.args[0], IRAddress):
            return None
        address = instruction.args[0]
        offset = evidence.address_entry_offset(block.addr, index, address)
        if offset is None:
            return None
        reads.append(_entry_range(offset, address.size))
    return tuple(reads)


def _store_verdict(
    block: SSABlock, index: cython.longlong, evidence: StackExtentEvidence8616,
    identities: object, reads: object,
) -> PrivateStackWriteVerdict8616:
    """Require exact Alias identity, allocation coverage and no overlapping read."""
    alias_address: object
    offset: object
    instruction = block.instrs[index]
    if not instruction.args or not isinstance(instruction.args[0], IRAddress):
        return PrivateStackWriteVerdict8616.NO_ALIAS
    address = instruction.args[0]
    alias_address = identities.get((block.addr, index))
    if alias_address is None or not _same_versioned_range(alias_address, address):
        return PrivateStackWriteVerdict8616.NO_ALIAS
    offset = evidence.address_entry_offset(block.addr, index, address)
    if offset is None:
        return PrivateStackWriteVerdict8616.OUTSIDE_LIFETIME
    contained = any(
        extent.allocation_index < index < extent.release_index
        and extent.lower_offset <= offset and offset + address.size <= extent.upper_offset
        for extent in iter(evidence.extents)
    )
    if not contained:
        return PrivateStackWriteVerdict8616.OUTSIDE_LIFETIME
    candidate = _entry_range(offset, address.size)
    if any(stack_ranges_may_overlap_8616(candidate, read) for read in iter(reads)):
        return PrivateStackWriteVerdict8616.READ_OVERLAP
    return PrivateStackWriteVerdict8616.UNREAD_RELEASED


@cython.ccall
def _same_versioned_range(alias_address: IRAddress, source: IRAddress) -> cython.bint:
    """Compare canonical Alias identity, not discarded expression provenance."""
    key: object
    key = memory_range_key_8616(alias_address)
    return (
        key is not None and operator.eq(key, memory_range_key_8616(source))
        and alias_address.version is not None and operator.eq(alias_address.version, source.version)
    )


def classify_private_stack_writes_8616(
    artifact: StackMemorySSAAliasArtifact8616,
) -> tuple[PrivateStackWriteDecision8616, ...]:
    """Classify every source store group without mutating IR or rendered C.

    The function escape verdict already requires one entry-to-return block.
    Every raw store belonging to a source instruction must pass: accepting
    just one byte of a word instruction would lose a live memory effect.
    """
    evidence: object
    reads: object
    source_addr: object
    verdict: object
    block: object
    index: object
    indices: object
    instruction: object
    function = artifact.source_ssa
    context_complete = (
        artifact.complete
        and artifact.frame_address_escape is StackAddressEscape8616.NO_DERIVED_ADDRESS_ESCAPE
        and len(function.blocks) == 1 and len(artifact.stack_extent_evidence) == 1
    )
    identities = {(fact.block_addr, fact.instr_index): fact.address for fact in iter(artifact.facts)
                  if fact.kind is StackMemoryAliasFactKind8616.STORE}
    identities.update({(access.source.block_addr, access.source.instr_index): access.source.address
                       for access in iter(artifact.accesses) if access.source.kind is SSAMemoryAccessKind8616.STORE})
    decisions = []
    for block in function.blocks:
        groups: dict[int | None, list[cython.longlong]] = {}
        for index, instruction in enumerate(block.instrs):
            if instruction.op == "STORE":
                groups.setdefault(instruction.addr, []).append(index)
        evidence = artifact.stack_extent_evidence[0] if context_complete else None
        reads = _read_ranges(block, evidence) if evidence is not None else None
        for source_addr, indices in groups.items():
            verdict = PrivateStackWriteVerdict8616.UNKNOWN_CONTEXT
            if evidence is not None and source_addr is not None:
                verdict = PrivateStackWriteVerdict8616.UNKNOWN_READ
                if reads is not None:
                    verdict = next((result for index in iter(indices)
                                    if (result := _store_verdict(block, index, evidence, identities, reads))
                                    is not PrivateStackWriteVerdict8616.UNREAD_RELEASED),
                                   PrivateStackWriteVerdict8616.UNREAD_RELEASED)
            decisions.append(PrivateStackWriteDecision8616(block.addr, source_addr, tuple(indices), verdict))
    return tuple(decisions)
