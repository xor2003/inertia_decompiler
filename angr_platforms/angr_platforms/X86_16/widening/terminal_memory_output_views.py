"""Project Alias-owned terminal-memory outputs into caller load views.

Layer: Widening.
Responsibility: bind exact caller LOAD ranges to one maximal Alias-owned output
and retain the byte offset of each whole or strictly contained value view.
Consumes alias-proven storage identity and typed SSA. This module does not
traverse CFG paths, infer C types, publish function contracts, or render code.
Indirect, crossing, width-conflicting, and unproven direct views remain explicit
refusals. Do not join values from rendered text, cosmetic shape, postprocess, or
CLI/reporting evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from ..alias.alias_model_impl import AliasStorageFacts, alias_facts_for_ir_address_8616
from ..alias.storage_fact_join import (
    SegmentedAccessRelation8616,
    SegmentedAliasRange8616,
    build_segmented_alias_range_8616,
    segmented_access_relation_8616,
)
from ..alias.terminal_memory_outputs import TerminalMemoryAliasFact8616
from ..ir import AddressStatus, IRAddress, IRInstr, MemSpace, SegmentOrigin
from ..ir.ssa_function import SSAFunctionArtifact


class TerminalMemoryOutputViewKind8616(StrEnum):
    """Value relation between one caller load and its maximal output owner."""

    WHOLE = "whole"
    CONTAINED = "contained"


class TerminalMemoryOutputViewFailure8616(StrEnum):
    """Stable reasons caller output-view widening cannot close."""

    OWNER_INCOMPLETE = "owner_incomplete"
    RANGE_BUILD_REFUSED = "range_build_refused"
    ACCESS_WIDTH_CONFLICT = "access_width_conflict"
    CROSSING_OVERLAP = "crossing_overlap"
    STORAGE_CONFLICT = "storage_conflict"


@dataclass(frozen=True, slots=True)
class TerminalMemoryOutputViewAccess8616:
    """One exact SSA LOAD contributing to a caller output view."""

    block_addr: int
    instr_index: int
    instr_addr: int
    address: IRAddress
    value_width: int

    @property
    def complete(self) -> bool:
        """Return whether the access retains one exact proven direct range."""
        return bool(
            self.block_addr >= 0
            and self.instr_index >= 0
            and self.instr_addr >= 0
            and self.address.space in {MemSpace.DS, MemSpace.ES}
            and not self.address.base
            and self.address.size > 0
            and self.value_width == self.address.size
            and self.address.status is AddressStatus.STABLE
            and self.address.segment_origin is SegmentOrigin.PROVEN
        )


@dataclass(frozen=True, slots=True)
class TerminalMemoryOutputViewFact8616:
    """One whole or contained caller view of an Alias-owned output."""

    alias_output: TerminalMemoryAliasFact8616
    storage_range: SegmentedAliasRange8616
    kind: TerminalMemoryOutputViewKind8616
    byte_offset: int
    accesses: tuple[TerminalMemoryOutputViewAccess8616, ...]

    @property
    def address(self) -> IRAddress:
        """Return the exact direct address represented by this view."""
        return self.storage_range.addresses[0]

    @property
    def width(self) -> int:
        """Return the exact value width represented by this view."""
        return int(self.storage_range.size)

    @property
    def complete(self) -> bool:
        """Return whether Alias owner, projection, and all accesses agree."""
        owner = self.alias_output.storage_range
        is_whole = self.storage_range == owner
        return bool(
            self.alias_output.complete
            and self.alias_output.is_owner
            and len(self.storage_range.addresses) == 1
            and owner.contains(self.storage_range)
            and self.byte_offset == self.storage_range.offset - owner.offset
            and self.byte_offset >= 0
            and (self.kind is TerminalMemoryOutputViewKind8616.WHOLE) == is_whole
            and self.accesses
            and all(
                access.complete and access.address == self.address
                for access in self.accesses
            )
        )


@dataclass(frozen=True, slots=True)
class TerminalMemoryOutputViewStats8616:
    """Closed evidence accounting for grouped caller output views."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every normalized view has one retained outcome."""
        return (
            self.raw_fact_count >= self.normalized_fact_count
            and self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            and self.failure_count == 0
        )


@dataclass(frozen=True, slots=True)
class TerminalMemoryOutputViewEvidence8616:
    """All caller views of one Alias owner or one atomic typed refusal."""

    alias_output: TerminalMemoryAliasFact8616
    facts: tuple[TerminalMemoryOutputViewFact8616, ...]
    failure: TerminalMemoryOutputViewFailure8616 | None
    stats: TerminalMemoryOutputViewStats8616

    @property
    def complete(self) -> bool:
        """Return whether grouped Widening evidence closes without refusal."""
        return bool(
            self.failure is None
            and self.stats.complete
            and len(self.facts) == self.stats.materialized_count
            and all(fact.complete for fact in self.facts)
        )


def _refused_8616(
    alias_output: TerminalMemoryAliasFact8616,
    failure: TerminalMemoryOutputViewFailure8616,
    raw_count: int,
    normalized_count: int = 0,
) -> TerminalMemoryOutputViewEvidence8616:
    """Build one atomic refusal without publishing partial view facts."""
    return TerminalMemoryOutputViewEvidence8616(
        alias_output,
        (),
        failure,
        TerminalMemoryOutputViewStats8616(
            raw_fact_count=max(1, raw_count),
            normalized_fact_count=normalized_count,
            failure_count=1,
        ),
    )


def _view_range_8616(address: IRAddress) -> SegmentedAliasRange8616 | None:
    """Build one exact caller view through the canonical Alias entry point."""
    storage = alias_facts_for_ir_address_8616(address)
    if not isinstance(storage, AliasStorageFacts):
        return None
    return build_segmented_alias_range_8616((address,), (storage,))


@dataclass(slots=True)
class _OutputViewScan8616:
    """Mutable grouping state for one terminal output-view scan."""

    alias_output: TerminalMemoryAliasFact8616
    owner: SegmentedAliasRange8616
    owner_address: IRAddress
    grouped: dict[
        tuple[MemSpace, int, int],
        tuple[SegmentedAliasRange8616, list[TerminalMemoryOutputViewAccess8616]],
    ] = field(default_factory=dict)
    raw_count: int = 0

    def _refuse(
        self,
        failure: TerminalMemoryOutputViewFailure8616,
    ) -> TerminalMemoryOutputViewEvidence8616:
        """Produce one refusal carrying the scan's closed counts."""
        return _refused_8616(
            self.alias_output,
            failure,
            self.raw_count,
            len(self.grouped),
        )

    def process(
        self,
        block_addr: int,
        instr_index: int,
        instruction: IRInstr,
    ) -> TerminalMemoryOutputViewEvidence8616 | None:
        """Classify one instruction or return the scan-closing refusal."""
        if instruction.op != "LOAD" or instruction.addr is None:
            return None
        address = instruction.args[0] if instruction.args else None
        if not isinstance(address, IRAddress):
            return None
        relation = segmented_access_relation_8616(address, self.owner_address)
        if relation in {
            SegmentedAccessRelation8616.DISJOINT,
            SegmentedAccessRelation8616.UNKNOWN,
        }:
            return None
        self.raw_count += 1
        if relation is SegmentedAccessRelation8616.UNPROVEN:
            return self._refuse(TerminalMemoryOutputViewFailure8616.RANGE_BUILD_REFUSED)
        if instruction.size != address.size:
            return self._refuse(TerminalMemoryOutputViewFailure8616.ACCESS_WIDTH_CONFLICT)
        view_range = _view_range_8616(address)
        if view_range is None:
            return self._refuse(TerminalMemoryOutputViewFailure8616.RANGE_BUILD_REFUSED)
        if relation in {
            SegmentedAccessRelation8616.CONTAINS,
            SegmentedAccessRelation8616.CROSSING,
        } or not self.owner.contains(view_range):
            return self._refuse(TerminalMemoryOutputViewFailure8616.CROSSING_OVERLAP)
        key = (view_range.space, view_range.offset, view_range.size)
        access = TerminalMemoryOutputViewAccess8616(
            block_addr,
            instr_index,
            instruction.addr,
            address,
            instruction.size,
        )
        previous = self.grouped.get(key)
        if previous is None:
            self.grouped[key] = (view_range, [access])
        elif previous[0] == view_range:
            previous[1].append(access)
        else:
            return self._refuse(TerminalMemoryOutputViewFailure8616.STORAGE_CONFLICT)
        return None


def collect_terminal_memory_output_views_8616(
    alias_output: TerminalMemoryAliasFact8616,
    artifact: SSAFunctionArtifact,
) -> TerminalMemoryOutputViewEvidence8616:
    """Group direct caller LOADs into whole or contained output views."""
    if not alias_output.complete or not alias_output.is_owner:
        return _refused_8616(
            alias_output,
            TerminalMemoryOutputViewFailure8616.OWNER_INCOMPLETE,
            1,
        )
    owner = alias_output.storage_range
    scan = _OutputViewScan8616(alias_output, owner, owner.addresses[0])
    for block in sorted(artifact.blocks, key=lambda item: item.addr):
        for instr_index, instruction in enumerate(block.instrs):
            refusal = scan.process(block.addr, instr_index, instruction)
            if refusal is not None:
                return refusal
    grouped = scan.grouped
    raw_count = scan.raw_count

    facts = tuple(
        TerminalMemoryOutputViewFact8616(
            alias_output=alias_output,
            storage_range=storage_range,
            kind=(
                TerminalMemoryOutputViewKind8616.WHOLE
                if storage_range == owner
                else TerminalMemoryOutputViewKind8616.CONTAINED
            ),
            byte_offset=storage_range.offset - owner.offset,
            accesses=tuple(accesses),
        )
        for _key, (storage_range, accesses) in sorted(
            grouped.items(),
            key=lambda item: (item[0][0].value, item[0][1], item[0][2]),
        )
    )
    count = len(facts)
    return TerminalMemoryOutputViewEvidence8616(
        alias_output,
        facts,
        None,
        TerminalMemoryOutputViewStats8616(raw_count, count, count, count),
    )


__all__ = [
    "TerminalMemoryOutputViewAccess8616",
    "TerminalMemoryOutputViewEvidence8616",
    "TerminalMemoryOutputViewFact8616",
    "TerminalMemoryOutputViewFailure8616",
    "TerminalMemoryOutputViewKind8616",
    "TerminalMemoryOutputViewStats8616",
    "collect_terminal_memory_output_views_8616",
]
