"""State-table writes require exact, nonaliasing execution evidence."""

import pytest

from tools.dosunit.real16_program_memory import ProgramMemoryLayout
from tools.dosunit.real16_replay_model import LinearRange, SegOffset
from tools.dosunit.real16_video_state_boundary import (
    VideoStateBoundaryRefusal,
    video_state_buffer_refusal,
)


def check(destination, *, memory=None, frame=None, code=()):
    return video_state_buffer_refusal(
        destination, memory=memory or ProgramMemoryLayout(((0, bytes(0x10000)),)),
        interrupt_frame=frame or LinearRange(0x8000, 6), code_ranges=code,
    )


def test_disjoint_complete_buffer_is_admitted():
    assert check(SegOffset(0x200, 0)) is None


@pytest.mark.parametrize("offset", [0xFFC1, 0xFFFF])
def test_segment_wrap_refuses(offset):
    assert check(SegOffset(0, offset)) is VideoStateBoundaryRefusal.WRAP


def test_exact_segment_end_is_admitted():
    assert check(SegOffset(0, 0xFFC0)) is None


def test_partial_destination_is_not_page_padding():
    memory = ProgramMemoryLayout(((0, bytes(0x500)), (0x2000, bytes(63))))
    assert check(SegOffset(0x200, 0), memory=memory) is VideoStateBoundaryRefusal.UNDECLARED


@pytest.mark.parametrize("missing", [0x449, 0x466, 0x484, 0x486])
def test_missing_live_bda_byte_refuses(missing):
    memory = ProgramMemoryLayout(((0, bytes(missing)), (missing + 1, bytes(0x10000 - missing - 1))))
    assert check(SegOffset(0x200, 0), memory=memory) is VideoStateBoundaryRefusal.BDA_UNDECLARED


@pytest.mark.parametrize("start", [0x40, 0x84, 0x3FF])
def test_vector_overlap_refuses(start):
    assert check(SegOffset(0, start)) is VideoStateBoundaryRefusal.VECTOR_ALIAS


@pytest.mark.parametrize("start", [0x40A, 0x449, 0x466, 0x484, 0x486])
def test_output_cannot_overwrite_bda_source(start):
    assert check(SegOffset(0, start)) is VideoStateBoundaryRefusal.BDA_ALIAS


@pytest.mark.parametrize("start", [0x7FC1, 0x8000, 0x8005])
def test_output_cannot_overwrite_live_int_frame(start):
    assert check(SegOffset(0, start)) is VideoStateBoundaryRefusal.FRAME_ALIAS


def test_frame_cannot_mutate_live_bda_inputs():
    assert check(SegOffset(0x200, 0), frame=LinearRange(0x448, 6)) is VideoStateBoundaryRefusal.BDA_ALIAS


def test_output_cannot_overwrite_code():
    assert check(SegOffset(0x200, 0), code=(LinearRange(0x203F, 1),)) is VideoStateBoundaryRefusal.CODE_WRITE


def test_adjacent_frame_and_code_are_not_overlaps():
    assert check(SegOffset(0x200, 0), frame=LinearRange(0x2040, 6),
                 code=(LinearRange(0x1FFF, 1),)) is None
