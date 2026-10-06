"""Exact bounded widening products shared by invocation interpreters.

Layer: IR.
Responsibility: evaluate only typed VEX widening signed/unsigned products
within the existing 64-bit scalar storage boundary. No partial-bit inference.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
"""
from __future__ import annotations

from .core import IRBinaryValue, IRValue

# Reuse the effect owner's finite operation/width inventory. This value
# evaluator adds arithmetic, never a second backend operation allowlist.
from .scalar_instruction_effects import _WIDENING_PRODUCT_BYTES_8616


def wide_multiply_shape_8616(op: str) -> tuple[int, bool] | None:
    """Return exact operand bits and signedness; 128-bit results remain unknown."""
    operand_bytes = _WIDENING_PRODUCT_BYTES_8616.get(op)
    return None if operand_bytes is None else (operand_bytes * 8, op[8] == "S")


def wide_multiply_value_8616(
    op: str, left: int, right: int,
    operands: tuple[object, object] | None, result_size: int | None,
) -> int | None:
    """Multiply two exact typed lanes into their double-width bitvector.

    Both operand declarations must match the operation's source width and the
    result declaration must match twice that width. Signed inputs are decoded
    as two's complement before multiplication; masking happens at result width.
    """
    shape = wide_multiply_shape_8616(op)
    if shape is None or operands is None:
        return None
    bits, signed = shape
    if type(result_size) is not int or result_size * 8 != 2 * bits:
        return None
    for operand in operands:
        if not isinstance(operand, IRValue | IRBinaryValue):
            return None
        if type(operand.size) is not int or operand.size * 8 != bits:
            return None
        if (
            isinstance(operand, IRValue) and operand.active_unary is not None
            and operand.active_unary.result_bits != bits
        ):
            return None
    mask = (1 << bits) - 1
    left, right = left & mask, right & mask
    if signed:
        sign = 1 << (bits - 1)
        left -= (left & sign) << 1
        right -= (right & sign) << 1
    return (left * right) & ((1 << (bits * 2)) - 1)
