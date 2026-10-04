"""Exact bit provenance transport over Alias-proven entry-byte captures.

Layer: Widening.
Responsibility: transport captured byte bits through typed scalar operations;
unknown bits remain unknown. This calculus proves no producer, memory object,
frame, pointer or control-flow property on its own.
Consumes alias-proven storage identity.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..alias.entry_stack_byte_contracts import EntryStackByteRead8616
from ..ir.scalar_value_projection import (
    ScalarBinaryKind8616,
    ScalarProjection8616,
    ScalarProjectionKind8616,
)


@dataclass(frozen=True, slots=True)
class EntryStackWordBit8616:
    """One unchanged bit of an exact Alias-owned byte capture."""

    capture: EntryStackByteRead8616
    bit_index: int


type Bit8616 = EntryStackWordBit8616 | bool | None
type BitVector8616 = tuple[Bit8616, ...]


def constant_bits_8616(value: int, bits: int) -> BitVector8616:
    """Represent a width-bounded integer least-significant bit first."""
    return tuple(bool((value >> index) & 1) for index in range(bits))


def bit_vector_constant_8616(value: BitVector8616) -> int | None:
    """Return an integer only when every bit is an explicitly known Boolean."""
    if not all(isinstance(bit, bool) for bit in value):
        return None
    return sum(1 << index for index, bit in enumerate(value) if bit is True)


def project_entry_bits_8616(
    value: BitVector8616, projection: ScalarProjection8616,
) -> BitVector8616 | None:
    """Consume one shared, width-checked projection without guessing bits."""
    if len(value) != projection.source_bits:
        return None
    target = projection.target_bits
    if projection.kind is not ScalarProjectionKind8616.CONVERSION:
        return value if target == len(value) else None
    if target < len(value):
        return value[:target]
    extension: Bit8616 = value[-1] if projection.signed else False
    return value + (extension,) * (target - len(value))


def _and_or_bit_8616(
    kind: ScalarBinaryKind8616, left: Bit8616, right: Bit8616,
) -> Bit8616:
    """Transport exact forcing/identity bits for conjunction or disjunction."""
    forcing = kind is ScalarBinaryKind8616.OR
    identity = not forcing
    if left is forcing or right is forcing:
        return forcing
    if left is identity:
        return right
    if right is identity:
        return left
    return left if left is not None and left == right else None


def _boolean_bit_8616(
    kind: ScalarBinaryKind8616, left: Bit8616, right: Bit8616,
) -> Bit8616:
    """Apply a Boolean identity only when its exact bit inputs justify it."""
    if kind in {ScalarBinaryKind8616.AND, ScalarBinaryKind8616.OR}:
        return _and_or_bit_8616(kind, left, right)
    if kind is not ScalarBinaryKind8616.XOR:
        return None
    if left is False:
        return right
    if right is False:
        return left
    if isinstance(left, bool) and isinstance(right, bool):
        return left != right
    return False if left is not None and left == right else None


def binary_entry_bits_8616(
    kind: ScalarBinaryKind8616,
    left: BitVector8616,
    right: BitVector8616,
) -> BitVector8616 | None:
    """Transport exact Boolean/shift provenance and proven constant arithmetic.

    Symbolic arithmetic and unproven/out-of-range shift counts refuse. A source
    bit is not a numeric constant, and two unknown bits never establish identity.
    """
    width = len(left)
    if kind in {ScalarBinaryKind8616.SHL, ScalarBinaryKind8616.SHR}:
        count = bit_vector_constant_8616(right)
        if count is None or count >= width:
            return None
        if kind is ScalarBinaryKind8616.SHL:
            return (False,) * count + left[:width - count]
        return left[count:] + (False,) * count
    if len(right) != width:
        return None
    if kind in {
        ScalarBinaryKind8616.AND, ScalarBinaryKind8616.OR, ScalarBinaryKind8616.XOR,
    }:
        return tuple(_boolean_bit_8616(kind, a, b) for a, b in zip(left, right, strict=True))
    a, b = bit_vector_constant_8616(left), bit_vector_constant_8616(right)
    if a is None or b is None:
        return None
    if kind is ScalarBinaryKind8616.ADD:
        return constant_bits_8616(a + b, width)
    if kind is ScalarBinaryKind8616.SUB:
        return constant_bits_8616(a - b, width)
    return None
