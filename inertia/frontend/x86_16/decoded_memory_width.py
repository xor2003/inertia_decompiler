# cython: language_level=3, infer_types=True
"""Normalize decoded memory operand extents.

Layer: Frontend.
Responsibility: expose instruction-defined byte extents at the Capstone boundary.
Does not infer object identity, argument grouping, or pointer types.
"""

from __future__ import annotations
import typing
import cython

from capstone.x86_const import (
    X86_INS_LDS,
    X86_INS_LES,
    X86_INS_LFS,
    X86_INS_LGS,
    X86_INS_LSS,
)

_FAR_LOAD_IDS: frozenset[cython.longlong] = frozenset({X86_INS_LDS, X86_INS_LES, X86_INS_LFS, X86_INS_LGS, X86_INS_LSS})
_OFFSET_WIDTHS: frozenset[cython.longlong] = frozenset({2, 4})
_SEGMENT_BYTES: cython.longlong = 2


@cython.ccall
def decoded_memory_operand_width_8616(
    instruction_id: cython.longlong, operand_index: cython.longlong, reported_width: int | None,
    destination_width: object,
) -> int | None:
    """Return memory extent, including the selector omitted by Capstone far loads.

    Call only for memory operands. The destination register establishes offset
    width independently of Capstone's memory-width convention.
    """
    far_source = instruction_id in _FAR_LOAD_IDS and operand_index == 1
    if far_source:
        if destination_width not in _OFFSET_WIDTHS:
            return None
        assert destination_width is not None
        return destination_width + _SEGMENT_BYTES
    return reported_width
