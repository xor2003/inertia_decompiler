"""Canonical register-relative displacements at the VEX-to-IR boundary.

Layer: IR adapter.
Responsibility: interpret exact integer ADD/SUB bit widths when folding a
constant into an IRValue displacement. Absolute constants remain bit patterns;
relative displacements use their signed modular representative. Unknown or
mismatched operation widths are not normalized. No storage identity, DCE,
stack-frame recovery or rendered-text interpretation belongs here.
"""

from __future__ import annotations


def canonical_vex_integer_displacement_8616(operation: str, offset: int, size: int) -> int:
    """Canonicalize an affine offset only for an exact matching integer width."""
    bits = size * 8
    if bits <= 0 or operation not in {f"Iop_Add{bits}", f"Iop_Sub{bits}"}:
        return offset
    modulus = 1 << bits
    unsigned = offset & (modulus - 1)
    return unsigned - modulus if unsigned >= modulus // 2 else unsigned
