"""Normalize Widening facts for wide call-output assignment Lowering.

Layer: Types/Lowering.
Responsibility: join exact call, arithmetic, source-range, and destination-store
instruction identities into one immutable Lowering fact before C-AST matching.
Consumes alias, widening, and typed facts without inspecting generated C.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from inertia.ir.core import MemSpace
from inertia.semantics.carry_borrow_contracts import CarryBorrowKind8616
from inertia.widening.carry_borrow_pipeline import CarryBorrowWideningPipeline8616
from inertia.widening.carry_borrow_storage import WideCarryBorrowStorage8616

from .wide_call_output_assignment_contracts import (
    WideCallOutputAssignmentFact8616,
    WideCallOutputAssignmentFailure8616,
)


def _instruction_addr_for_store_8616(
    pipeline: CarryBorrowWideningPipeline8616,
    block_addr: int,
    instr_index: int | None,
) -> int | None:
    """Return one exact machine address from a stack Alias store site."""
    block = next((item for item in pipeline.source_ssa.blocks if item.addr == block_addr), None)
    if block is None or not isinstance(instr_index, int) or not 0 <= instr_index < len(block.instrs):
        return None
    address = block.instrs[instr_index].addr
    return address if isinstance(address, int) else None


def normalize_wide_call_output_assignment_fact_8616(
    pipeline: CarryBorrowWideningPipeline8616,
    source: WideCarryBorrowStorage8616,
) -> WideCallOutputAssignmentFact8616 | WideCallOutputAssignmentFailure8616:
    """Normalize one upstream wide storage value without consulting C-AST shape."""
    call_output = source.value.lhs_call_output
    source_memory = source.value.source_memory
    if call_output is None or source_memory is None:
        return WideCallOutputAssignmentFailure8616.SOURCE_RANGE_MISMATCH
    if (
        source_memory.space is not MemSpace.SS
        or source_memory.size != 4
        or any(address.base != ("bp",) for address in source_memory.addresses)
    ):
        return WideCallOutputAssignmentFailure8616.SOURCE_RANGE_MISMATCH
    if source.value.kind not in {
        CarryBorrowKind8616.ADD_WITH_CARRY,
        CarryBorrowKind8616.SUB_WITH_BORROW,
    }:
        return WideCallOutputAssignmentFailure8616.UNSUPPORTED_OPERATION
    link = source.value.provenance
    low_store = source.destination.low_store
    high_store = source.destination.high_store
    low_store_addr = _instruction_addr_for_store_8616(
        pipeline, low_store.block_addr, low_store.instr_index
    )
    high_store_addr = _instruction_addr_for_store_8616(
        pipeline, high_store.block_addr, high_store.instr_index
    )
    raw_site_addrs = (
        link.low_arithmetic.instruction.addr,
        link.high_base_arithmetic.instruction.addr,
        link.high_final_arithmetic.instruction.addr,
        link.low_result_write.instruction.addr,
        link.high_result_write.instruction.addr,
        low_store_addr,
        high_store_addr,
    )
    site_addrs = tuple(address for address in raw_site_addrs if isinstance(address, int))
    if len(site_addrs) != len(raw_site_addrs):
        return WideCallOutputAssignmentFailure8616.INSTRUCTION_PROVENANCE_MISSING
    assert isinstance(low_store_addr, int) and isinstance(high_store_addr, int)
    carrier_addrs = tuple(sorted({call_output.provenance.callsite_addr, *site_addrs}))
    return WideCallOutputAssignmentFact8616(
        call_output=call_output.provenance,
        kind=source.value.kind,
        source_offset=source_memory.offset,
        destination_offset=source.address.offset,
        carrier_ins_addrs=carrier_addrs,
        store_ins_addrs=(low_store_addr, high_store_addr),
    )


__all__ = ["normalize_wide_call_output_assignment_fact_8616"]
