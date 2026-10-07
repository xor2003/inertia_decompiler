"""Typed contracts for a paired far-call result's caller use.

Layer: Types/Lowering.
Responsibility: retain the exact callee target, DX:AX to ES:BX alias, and logical-access proof,
or one nonpublishing refusal. An access width is not an input pointee type.
Consumes alias, widening, and typed facts through retained proof fields only.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from inertia.ir.logical_memory_contracts import IRLogicalMemoryAccessKey8616

from .interprocedural_storage_return_type_contracts import ReturnPointerAliasStep8616

__all__ = [
    "FarReturnPointerUseEvidence8616",
    "FarReturnPointerUseFailure8616",
    "FarReturnPointerUseResult8616",
    "FarReturnPointerUseStats8616",
    "FarReturnPointerUseVerdict8616",
]


class FarReturnPointerUseVerdict8616(StrEnum):
    """Whether one exact caller access consumes both return words."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


class FarReturnPointerUseFailure8616(StrEnum):
    """Stable reason this bounded far-result use cannot be published."""

    OUTPUT_SHAPE_MISMATCH = "output_shape_mismatch"
    CALLSITE_UNPROVEN = "callsite_unproven"
    CALL_TARGET_MISMATCH = "call_target_mismatch"
    CFG_INCOMPLETE = "cfg_incomplete"
    SEGMENT_COPY_MISSING = "segment_copy_missing"
    OFFSET_COPY_MISSING = "offset_copy_missing"
    CARRIER_CLOBBERED = "carrier_clobbered"
    LOGICAL_ACCESS_UNPROVEN = "logical_access_unproven"
    DEREFERENCE_NOT_FOUND = "dereference_not_found"


@dataclass(frozen=True, slots=True)
class FarReturnPointerUseStats8616:
    """Close one requested far-use fact through all five evidence stages."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class FarReturnPointerUseEvidence8616:
    """Exact target, register-pair copies, and one segmented logical access."""

    caller_addr: int
    callee_addr: int
    callsite_addr: int
    segment_copy: ReturnPointerAliasStep8616
    offset_copy: ReturnPointerAliasStep8616
    dereference_instruction_addr: int
    access_key: IRLogicalMemoryAccessKey8616
    address: IRAddress
    access_width_bytes: int

    @property
    def complete(self) -> bool:
        """Require both independent call-result carriers and exact ES:BX use."""
        segment = self.segment_copy
        offset = self.offset_copy
        exact_copies = (
            segment.complete
            and offset.complete
            and segment.source.space is MemSpace.REG
            and segment.source.name == "dx"
            and segment.source.version == 0
            and segment.target.space is MemSpace.REG
            and segment.target.name == "es"
            and offset.source.space is MemSpace.REG
            and offset.source.name == "ax"
            and offset.source.version == 0
            and offset.target.space is MemSpace.REG
            and offset.target.name == "bx"
        )
        exact_site = (
            segment.block_addr == offset.block_addr == self.access_key.block_addr
            and segment.instr_addr < self.dereference_instruction_addr
            and offset.instr_addr < self.dereference_instruction_addr
            and self.access_key.function_addr == self.caller_addr
            and self.access_key.insn_addr == self.dereference_instruction_addr
        )
        exact_address = (
            self.address.space is MemSpace.ES
            and self.address.base == ("bx",)
            and self.address.status is AddressStatus.STABLE
            and self.address.segment_origin is SegmentOrigin.PROVEN
            and self.address.size == self.access_width_bytes > 0
        )
        return bool(
            self.caller_addr >= 0
            and self.callee_addr >= 0
            and self.callsite_addr >= 0
            and exact_copies
            and exact_site
            and exact_address
        )


@dataclass(frozen=True, slots=True)
class FarReturnPointerUseResult8616:
    """One complete use witness or a typed, nonpublishing refusal."""

    verdict: FarReturnPointerUseVerdict8616
    failure: FarReturnPointerUseFailure8616 | None
    evidence: FarReturnPointerUseEvidence8616 | None
    stats: FarReturnPointerUseStats8616

    @property
    def complete(self) -> bool:
        """Return whether this result contains exactly one closed witness."""
        return bool(
            self.verdict is FarReturnPointerUseVerdict8616.PROVEN
            and self.failure is None
            and self.evidence is not None
            and self.evidence.complete
            and self.stats == FarReturnPointerUseStats8616(1, 1, 1, 1, 0)
        )
