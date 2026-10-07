"""Typed address-domain exports for x86-16 IR.

Layer: IR.
Responsibility: owns typed Address exports and lossless normalization helpers.
Owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from inertia.ir.address_ir_8616 import AddressIR8616, build_address_ir_8616, resolved_operand_to_address_ir_8616

from .core import AddressStatus, IRAddress, MemSpace, SegmentOrigin

__all__ = [
    "AddressIR8616",
    "AddressStatus",
    "IRAddress",
    "MemSpace",
    "SegmentOrigin",
    "build_address_ir_8616",
    "resolved_operand_to_address_ir_8616",
]
