"""Tests for the authoritative Microsoft C x87 interrupt mapping."""

from inertia.frontend.x86_16.msvc_x87_interrupts import (
    is_msvc_x87_emulation_interrupt_8616,
    msvc_x87_escape_opcode_8616,
)


def test_msvc_x87_escape_vectors_map_to_hardware_opcodes() -> None:
    """Keep all four Microsoft ESC projections tied to one frontend owner."""
    assert {vector: msvc_x87_escape_opcode_8616(vector) for vector in (0x34, 0x35, 0x38, 0x39)} == {
        0x34: 0xD8,
        0x35: 0xD9,
        0x38: 0xDC,
        0x39: 0xDD,
    }


def test_msvc_x87_wait_and_escape_vectors_are_not_interrupt_boundaries() -> None:
    """Classify WAIT and ESC vectors while refusing unrelated interrupts."""
    assert all(is_msvc_x87_emulation_interrupt_8616(vector) for vector in (0x34, 0x35, 0x38, 0x39, 0x3D))
    assert not is_msvc_x87_emulation_interrupt_8616(0x21)
    assert msvc_x87_escape_opcode_8616(0x3D) is None
