"""Canonical instruction-kind predicates for decoded x86-16 instructions.

Layer: Frontend.
Responsibility: normalize backend mnemonic spelling into evidence-neutral
instruction kinds consumed by later recovery layers.
"""

from __future__ import annotations

__all__ = ("is_x86_16_call_mnemonic_8616",)


def is_x86_16_call_mnemonic_8616(mnemonic: str) -> bool:
    """Return whether Capstone's mnemonic denotes a near or far call."""
    normalized = mnemonic.strip().lower()
    return normalized == "lcall" or normalized.startswith("call")
