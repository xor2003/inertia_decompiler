"""Bind declared BIOS video queries to an unchanged external interrupt vector.

Layer: dosunit concrete execution contracts.
Responsibility: require initialized live IVT bytes and reject program-owned
handlers or interrupt-frame aliasing before applying any query response.
"""

from __future__ import annotations

from enum import StrEnum

from tools.dosunit.runtime.real16_program_memory import ProgramMemoryLayout
from tools.dosunit.runtime.real16_program_vectors import vector_bytes
from tools.dosunit.runtime.real16_program_video import VIDEO_VECTOR, VideoQueryPolicy
from tools.dosunit.runtime.real16_replay_model import LinearRange, SegOffset

VIDEO_VECTOR_RANGE: LinearRange = LinearRange(VIDEO_VECTOR * 4, 4)


class VideoDispatchRefusal(StrEnum):
    """Missing execution evidence for a declared external BIOS query."""

    REDIRECTED = "video_vector_redirected"
    OWNED_HANDLER = "video_vector_points_to_program_code"
    FRAME_ALIAS = "interrupt_frame_overlaps_video_vector"


def check_video_policy(policy: VideoQueryPolicy | None, memory: ProgramMemoryLayout) -> None:
    """Require an explicit typed policy and every byte of its initialized IVT slot."""
    if policy is None:
        return
    if not isinstance(policy, VideoQueryPolicy):
        raise ValueError("video_policy requires a typed VideoQueryPolicy")
    if not memory.contains(VIDEO_VECTOR_RANGE.address, VIDEO_VECTOR_RANGE.size):
        raise ValueError("video policy requires the complete declared INT10 vector")


def video_dispatch_refusal(
    policy: VideoQueryPolicy, live_vector: bytes, *, arena_start: int, arena_size: int,
) -> VideoDispatchRefusal | None:
    """Reject loaded-program handlers even when excluded from the code projection."""
    return video_entry_dispatch_refusal(policy.entry, live_vector, arena_start=arena_start, arena_size=arena_size)


def video_entry_dispatch_refusal(
    entry: SegOffset, live_vector: bytes, *, arena_start: int, arena_size: int,
) -> VideoDispatchRefusal | None:
    """Bind either declared video service to one unchanged external BIOS entry."""
    if arena_start <= entry.linear() < arena_start + arena_size:
        return VideoDispatchRefusal.OWNED_HANDLER
    if live_vector != vector_bytes(entry):
        return VideoDispatchRefusal.REDIRECTED
    return None
