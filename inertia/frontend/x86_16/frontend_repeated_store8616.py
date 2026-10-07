"""Layer: Frontend.

Responsibility: project exact decoded repeated STOS into a typed width contract.
No VEX construction, instruction text matching, or new decoder instance is used.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, cast

from capstone.x86_const import X86_INS_STOSB, X86_INS_STOSW

from .frontend_capstone_block import DirectCapstoneInstruction8616
from .frontend_capstone_decode import decode_exact_capstone_block_8616


class _RepeatInstructionBoundary8616(Protocol):
    """Third-party Capstone detail fields consumed at this decode boundary."""

    id: int
    addr_size: int
    prefix: Sequence[int]


@dataclass(frozen=True, slots=True)
class RepeatedStore8616:
    """Exact repeated STOS instruction with 16-bit addressing and count."""

    address: int
    encoded: bytes
    width: int


_REPEAT_WIDTHS_8616: dict[int, int] = {X86_INS_STOSB: 1, X86_INS_STOSW: 2}


def decoded_repeated_store_8616(project: object, address: int, encoded: bytes) -> RepeatedStore8616 | None:
    """Use the configured frontend decoder; refuse unsupported repeat shapes."""
    decoded = decode_exact_capstone_block_8616(project, address, encoded)
    if not decoded.complete or decoded.block is None or len(decoded.block.instructions) != 1:
        return None
    view = decoded.block.instructions[0]
    if not isinstance(view, DirectCapstoneInstruction8616):
        return None
    instruction = cast(_RepeatInstructionBoundary8616, view.insn)
    width = _REPEAT_WIDTHS_8616.get(instruction.id)
    if width is None or instruction.addr_size != 2 or instruction.prefix[0] not in (0xF2, 0xF3):
        return None
    if view.bytes != encoded or view.size != len(encoded):
        return None
    return RepeatedStore8616(address, encoded, width)
