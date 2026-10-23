"""Allocator header declarations retain their actual guest byte coordinates."""

import pytest

from inertia.frontend.real16_dosbox_resize import DosboxMcbEntry, DosboxResizePolicy
from tools.dosunit.runtime.real16_program_memory import InitialMemoryRegion, ProgramMemoryLayout, program_memory_layout
from tools.dosunit.runtime.real16_program_resize import DOSBOX_CHAIN_ENTRY_LIMIT
from tools.dosunit.runtime.real16_replay_model import SegOffset

pytestmark = pytest.mark.dosunit


def _policy():
    def image(marker, owner, size):
        return bytes((marker,)) + owner.to_bytes(2, "little") + size.to_bytes(2, "little") + b"\x55" * 11

    return DosboxResizePolicy(0x108, (
        DosboxMcbEntry(0x100, image(ord("M"), 8, 3)),
        DosboxMcbEntry(0x104, image(ord("M"), 0, 2)),
        DosboxMcbEntry(0x107, image(ord("Z"), 0x108, 0x20)),
    ))


def _read(layout, address, size):
    for base, data in layout.chunks:
        if base <= address and address + size <= base + len(data):
            return data[address - base:address - base + size]
    return None


def test_mcb_headers_keep_guest_coordinates_without_inventing_gap_bytes():
    policy = _policy()
    layout = program_memory_layout(0x108, b"\x99" * 0x200, (), policy)
    for entry in policy.chain:
        assert _read(layout, entry.address, 16) == entry.image
    assert not layout.contains(0x1010, 16)


def test_headers_already_in_snapshot_are_checked_without_duplicate_aliases():
    policy = _policy()
    before = bytearray(b"\x77" * 0x80)
    for entry in policy.chain:
        offset = entry.address - 0x1000
        before[offset:offset + 16] = entry.image
    snapshot = InitialMemoryRegion(SegOffset(0x100, 0), bytes(before))
    layout = program_memory_layout(0x108, b"\x99" * 0x200, (snapshot,), policy)
    assert _read(layout, 0x1000, 0x80) == bytes(before)
    assert len(layout.chunks) == 2


def test_conflicting_header_snapshot_is_rejected():
    snapshot = InitialMemoryRegion(SegOffset(0x100, 0), b"\x77" * 0x80)
    with pytest.raises(ValueError):
        program_memory_layout(0x108, b"\x99" * 0x200, (snapshot,), _policy())


def test_header_allowance_cannot_disable_initialization_budget():
    with pytest.raises(ValueError, match="bounded allocator declaration"):
        ProgramMemoryLayout(((0x1000, b"\x77"),), header_allowance=DOSBOX_CHAIN_ENTRY_LIMIT + 1)
