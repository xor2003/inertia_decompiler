# cython: language_level=3, infer_types=True
"""Preserve exact signed conversion semantics in condition value provenance.

Layer: IR.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
Responsibility: express a proven CBW/CWDE conversion with existing typed value
operations, retaining the original storage and memory access width.
"""

from __future__ import annotations
import typing
import cython

from .core import IRBinaryValue, IRValue, MemSpace
import operator

_SIGNED_WIDENINGS: frozenset[tuple[cython.longlong, cython.longlong]] = frozenset({(1, 2), (2, 4)})
_BITS_PER_BYTE: cython.longlong = 8


@cython.ccall
def sign_extend_condition_value_8616(
    value: IRValue | IRBinaryValue, destination_size: cython.longlong,
) -> IRBinaryValue | None:
    """Return exact two-complement extension or refuse an unsupported width.

    Masking before toggling the sign bit also handles a previously extended
    signed expression. The load itself stays at its original width; changing
    its size would conflate value conversion with a larger memory access.
    """
    if (value.size, destination_size) not in _SIGNED_WIDENINGS:
        return None
    source_bits = value.size * _BITS_PER_BYTE
    sign_bit = IRValue(MemSpace.CONST, const=1 << (source_bits - 1), size=destination_size)
    source_mask = IRValue(MemSpace.CONST, const=(1 << source_bits) - 1, size=destination_size)
    unsigned_source = IRBinaryValue("and", value, source_mask, size=destination_size)
    biased_source = IRBinaryValue("xor", unsigned_source, sign_bit, size=destination_size)
    return IRBinaryValue("sub", biased_source, sign_bit, size=destination_size)


def signed_extension_source_8616(value: IRBinaryValue) -> IRValue | IRBinaryValue | None:
    """Prove the exact masked two-complement identity and return its source.

    All intermediate operations must use the declared destination width. This
    consumes typed arithmetic, never an instruction name or a rendered pattern.
    Near-matches retain their original arithmetic representation.
    """
    biased = value.lhs
    if value.op != "sub" or not isinstance(biased, IRBinaryValue) or biased.op != "xor":
        return None
    masked = biased.lhs
    if not isinstance(masked, IRBinaryValue) or masked.op != "and":
        return None
    source = masked.lhs
    if (source.size, value.size) not in _SIGNED_WIDENINGS:
        return None
    if operator.ne(biased.size, value.size) or operator.ne(masked.size, value.size):
        return None
    sign_bit = 1 << (source.size * _BITS_PER_BYTE - 1)
    mask = (1 << (source.size * _BITS_PER_BYTE)) - 1
    constants = ((masked.rhs, mask), (biased.rhs, sign_bit), (value.rhs, sign_bit))
    exact_constants = all(
        isinstance(atom, IRValue) and atom.space is MemSpace.CONST
        and type(atom.const) is int and operator.eq(atom.const, expected) and operator.eq(atom.size, value.size)
        for atom, expected in iter(constants)
    )
    return source if exact_constants else None
