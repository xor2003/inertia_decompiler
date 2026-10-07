"""Layer: IR.

Responsibility: typed address artifacts bridged from resolved operands.
Forbidden: object/type guessing and rewrite ownership.

Package ownership contract (canonical inertia/ir package):
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass

from inertia.frontend.x86_16.addressing_helpers import ResolvedMemoryOperand
from inertia.ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin

__all__ = [
    "AddressIR8616",
    "build_address_ir_8616",
    "resolved_operand_to_address_ir_8616",
]


@dataclass(frozen=True, slots=True)
class AddressIR8616:
    """Root compatibility Address wrapper for proven segmented IR addresses."""

    space: MemSpace
    base: tuple[str, ...]
    offset: int
    size: int
    status: AddressStatus
    segment_origin: SegmentOrigin

    def to_ir_address(self) -> IRAddress:
        """Convert the compatibility wrapper into the canonical IR address."""
        return IRAddress(
            space=self.space,
            base=self.base,
            offset=self.offset,
            size=self.size,
            status=self.status,
            segment_origin=self.segment_origin,
        )


def build_address_ir_8616(
    space: MemSpace,
    base: tuple[str, ...] = (),
    *,
    offset: int = 0,
    size: int = 0,
    status: AddressStatus = AddressStatus.UNKNOWN,
    segment_origin: SegmentOrigin = SegmentOrigin.UNKNOWN,
) -> AddressIR8616:
    """Build a typed segmented address wrapper from explicit IR fields."""
    return AddressIR8616(
        space=space,
        base=base,
        offset=offset,
        size=size,
        status=status,
        segment_origin=segment_origin,
    )


def resolved_operand_to_address_ir_8616(operand: ResolvedMemoryOperand) -> IRAddress:
    """Convert a resolved frontend memory operand to the canonical IR address."""
    return operand.typed_address()
