"""Validate a BIOS functionality-state table's bounded memory effects.

Layer: dosunit concrete execution contracts.
Responsibility: admit only complete conventional-memory reads and writes with
explicit segmented destinations, retaining unsupported aliasing as a refusal.
No bytes are read or written by this boundary owner.
"""

from __future__ import annotations

from enum import StrEnum

from tools.dosunit.real16_program_memory import SEGMENT_BYTES, ProgramMemoryLayout
from tools.dosunit.real16_program_video_state import (
    VIDEO_STATE_BDA_BYTES,
    VIDEO_STATE_ROW_BYTES,
    VIDEO_STATE_TABLE_BYTES,
)
from tools.dosunit.real16_replay_model import LinearRange, SegOffset

VIDEO_STATE_BYTES: int = VIDEO_STATE_TABLE_BYTES
VIDEO_BDA_MODE: LinearRange = LinearRange(0x449, VIDEO_STATE_BDA_BYTES)
VIDEO_BDA_ROWS: LinearRange = LinearRange(0x484, VIDEO_STATE_ROW_BYTES)
_BIOS_SOURCES: tuple[LinearRange, ...] = (VIDEO_BDA_MODE, VIDEO_BDA_ROWS)
_IVT: LinearRange = LinearRange(0, 1024)


class VideoStateBoundaryRefusal(StrEnum):
    """Missing or conflicting evidence for the declared table response."""

    WRAP = "video_state_destination_wrap"
    UNDECLARED = "video_state_destination_undeclared"
    BDA_UNDECLARED = "video_state_bda_undeclared"
    BDA_ALIAS = "video_state_bda_alias"
    VECTOR_ALIAS = "video_state_vector_alias"
    FRAME_ALIAS = "video_state_interrupt_frame_alias"
    CODE_WRITE = "video_state_code_write"


def video_state_buffer_refusal(
    destination: SegOffset, *, memory: ProgramMemoryLayout,
    interrupt_frame: LinearRange, code_ranges: tuple[LinearRange, ...],
) -> VideoStateBoundaryRefusal | None:
    """Check the table before effects, refusing order-sensitive source aliases.

    The native BIOS copies live BDA bytes sequentially. This bounded service
    deliberately refuses overlap instead of substituting a snapshot-copy rule
    where sequential reads and writes could differ. Likewise the modeled INT
    frame may not mutate those sources before the BIOS reads them.
    """
    if destination.offset + VIDEO_STATE_BYTES > SEGMENT_BYTES:
        return VideoStateBoundaryRefusal.WRAP
    address = destination.linear()
    if not memory.contains(address, VIDEO_STATE_BYTES):
        return VideoStateBoundaryRefusal.UNDECLARED
    if any(not memory.contains(source.address, source.size) for source in _BIOS_SOURCES):
        return VideoStateBoundaryRefusal.BDA_UNDECLARED
    if _IVT.overlaps(address, VIDEO_STATE_BYTES):
        return VideoStateBoundaryRefusal.VECTOR_ALIAS
    if any(source.overlaps(address, VIDEO_STATE_BYTES)
           or source.overlaps(interrupt_frame.address, interrupt_frame.size) for source in _BIOS_SOURCES):
        return VideoStateBoundaryRefusal.BDA_ALIAS
    if interrupt_frame.overlaps(address, VIDEO_STATE_BYTES):
        return VideoStateBoundaryRefusal.FRAME_ALIAS
    if any(code.overlaps(address, VIDEO_STATE_BYTES) for code in code_ranges):
        return VideoStateBoundaryRefusal.CODE_WRITE
    return None
