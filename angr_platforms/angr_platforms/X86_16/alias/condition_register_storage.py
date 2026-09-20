"""Project proven reaching register sources into condition storage values.

Layer: Alias.
Responsibility: retain exact segmented storage identity and compose independently
proven byte sources when the complete upper view is zero. Do not infer values
from AST names, decode new instructions, or materialize C expressions.
Owns storage identity for these proven register sources.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from ..callsite_register_provenance import recover_register_source_before_instruction_8616
from ..ir.core import IRBinaryValue, IRValue, MemSpace
from ..semantics.register_value_preservation import (
    register_value_family_8616,
    register_value_projection_8616,
)
from .register_reaching_source import RegisterReachingSourceVerdict8616

_BYTE_BITS: int = 8
_WORD_BYTES: int = 2


def storage_from_reaching_source_8616(
    source: tuple[object, ...] | None,
    *,
    width_bits: int,
) -> IRValue | None:
    """Map one exact reaching source to a typed value without flattening."""
    width = max(1, (width_bits + _BYTE_BITS - 1) // _BYTE_BITS)
    match source:
        case ("imm", int(value)):
            mask = (1 << (width * _BYTE_BITS)) - 1
            return IRValue(MemSpace.CONST, const=value & mask, size=width)
        case ("global", int(offset), source_width) if source_width == width:
            return IRValue(MemSpace.DS, offset=offset, size=width)
        case ("bp", int(offset)) if width == _WORD_BYTES:
            return IRValue(MemSpace.SS, name="bp", offset=offset, size=width)
        case ("bp", int(offset), source_width) if source_width == width:
            return IRValue(MemSpace.SS, name="bp", offset=offset, size=width)
    return None


def zero_extended_register_storage_8616(
    function: object,
    *,
    instruction_addr: int,
    register: str,
    width_bits: int,
) -> IRBinaryValue | None:
    """Compose byte storage only when every remaining register bit is zero.

    Both lanes use the existing all-path Alias proof at the same instruction.
    Unknown paths, intervening memory writes and calls therefore remain refusal
    cases. Architectural views, not register-name patterns, establish coverage.
    """
    if width_bits <= _BYTE_BITS or register_value_projection_8616(register, register) != (0, width_bits):
        return None
    views = {
        register_value_projection_8616(register, member): member
        for member in sorted(register_value_family_8616(register))
    }
    low_name = views.get((0, _BYTE_BITS))
    high_name = views.get((_BYTE_BITS, width_bits - _BYTE_BITS))
    if low_name is None or high_name is None:
        return None
    high = recover_register_source_before_instruction_8616(
        function, instruction_addr=instruction_addr, register=high_name,
    )
    if high.verdict is not RegisterReachingSourceVerdict8616.PROVEN or high.source != ("imm", 0):
        return None
    low = recover_register_source_before_instruction_8616(
        function, instruction_addr=instruction_addr, register=low_name,
    )
    if low.verdict is not RegisterReachingSourceVerdict8616.PROVEN:
        return None
    storage = storage_from_reaching_source_8616(low.source, width_bits=_BYTE_BITS)
    if storage is None:
        return None
    width = width_bits // _BYTE_BITS
    # Keep a byte load; the unsigned mask describes its proven word value.
    return IRBinaryValue(
        "and", storage,
        IRValue(MemSpace.CONST, const=(1 << _BYTE_BITS) - 1, size=width),
        size=width,
    )
