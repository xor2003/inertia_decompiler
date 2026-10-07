"""Advance segmented execution offsets without flattening away width.

Layer: Frontend.
Responsibility: apply address-width wrap before each segmented byte is
linearized for execution.
Do not publish semantic memory facts or perform IR, alias, widening, lowering,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from typing import Protocol, cast


class _AddableSegmentOffset8616(Protocol):
    """Frontend value supporting width-preserving offset addition."""

    def __add__(self, other: object) -> object:
        """Return this offset plus a same-width frontend constant."""
        ...


def advance_segment_offset_8616(
    offset: object,
    delta: int,
    address_bits: int,
    delta_value: object,
) -> object:
    """Advance one offset inside its address width before linearization."""
    if address_bits <= 0:
        raise ValueError("address_bits must be positive")
    if isinstance(offset, int):
        return (offset + delta) & ((1 << address_bits) - 1)
    return cast(_AddableSegmentOffset8616, offset) + delta_value


__all__ = ["advance_segment_offset_8616"]
