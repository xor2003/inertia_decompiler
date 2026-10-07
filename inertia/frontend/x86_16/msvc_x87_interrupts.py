"""Microsoft C x87 emulator interrupt encodings.

Layer: Frontend/runtime.
Responsibility: own the binary mapping from Microsoft C interrupt escapes to
their original x87 opcodes and classify the emulated WAIT vector.
Forbidden: C rendering, signature recovery, or sample-specific behavior.
"""

from __future__ import annotations

__all__ = [
    "is_msvc_x87_emulation_interrupt_8616",
    "msvc_x87_escape_opcode_8616",
]

_MSVC_X87_INTERRUPT_TO_OPCODE_8616: dict[int, int] = {
    0x34: 0xD8,
    0x35: 0xD9,
    0x38: 0xDC,
    0x39: 0xDD,
}
_MSVC_X87_WAIT_INTERRUPT_8616 = 0x3D


def msvc_x87_escape_opcode_8616(vector: int) -> int | None:
    """Return the hardware x87 opcode represented by one interrupt vector."""
    return _MSVC_X87_INTERRUPT_TO_OPCODE_8616.get(vector & 0xFF)


def is_msvc_x87_emulation_interrupt_8616(vector: int) -> bool:
    """Return whether a vector is an x87 ESC or WAIT emulator encoding."""
    normalized = vector & 0xFF
    return normalized == _MSVC_X87_WAIT_INTERRUPT_8616 or normalized in _MSVC_X87_INTERRUPT_TO_OPCODE_8616
