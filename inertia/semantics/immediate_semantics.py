"""Normalize encoded x86 immediates before frontend effect construction.

Layer: Semantics.
Responsibility: preserve exact fixed-width immediate values without runtime-only
extension expressions.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

__all__ = ("sign_extend_u8_to_u16",)


def sign_extend_u8_to_u16(value: int) -> int:
    """Return the 16-bit bit pattern for one sign-extended encoded byte."""
    encoded = value & 0xFF
    return encoded | (0xFF00 if encoded & 0x80 else 0)
