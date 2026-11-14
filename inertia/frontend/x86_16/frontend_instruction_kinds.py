# cython: language_level=3, infer_types=True
"""Canonical instruction-kind predicates for decoded x86-16 instructions.

Layer: Frontend.
Responsibility: normalize backend mnemonic spelling into evidence-neutral
instruction kinds consumed by later recovery layers.
"""

from __future__ import annotations
import typing
import cython

__all__ = ("is_x86_16_call_mnemonic_8616",)


@cython.ccall
def is_x86_16_call_mnemonic_8616(mnemonic: object) -> cython.bint:
    """Return whether Capstone's mnemonic denotes a near or far call."""
    normalized = mnemonic.strip().lower()
    return normalized == "lcall" or normalized.startswith("call")
