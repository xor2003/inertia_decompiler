"""Resolve effective segments from decoded 16/32-bit memory operands.

Layer: Frontend.
Responsibility: translate Capstone's absent override into the architectural
default segment before consumers classify a memory access. An EBP SIB index
does not select SS; the decoded base register determines the default.
"""

from __future__ import annotations

from capstone.x86_const import (
    X86_REG_BP,
    X86_REG_DS,
    X86_REG_EBP,
    X86_REG_ESP,
    X86_REG_INVALID,
    X86_REG_SP,
    X86_REG_SS,
)


def effective_capstone_memory_segment_8616(
    override: int | None, base: int | None,
) -> int | None:
    """Preserve an override or resolve the decoded base's default segment."""
    if override not in (None, X86_REG_INVALID):
        return override
    if base is None:
        return None
    return int(X86_REG_SS) if base in (X86_REG_BP, X86_REG_SP, X86_REG_EBP, X86_REG_ESP) else int(X86_REG_DS)
