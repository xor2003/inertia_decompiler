"""Architectural stack-memory effects for intercepted real16 DOS/BIOS services.

Layer: dosunit concrete execution contracts.
Responsibility: construct the six bytes pushed by an ordinary 16-bit INT21/INT10,
check exact writable coverage and reject code overlap before service dispatch.
Returning service summaries restore SP but cannot erase their pushed bytes.
This owner does not interpret service behavior or execute an interrupt handler.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from tools.dosunit.runtime.real16_program_memory import ProgramMemoryLayout
from tools.dosunit.runtime.real16_replay_model import LinearRange, SegOffset

INTERRUPT_ENTRY_MODEL: str = "real16_int21_stack_v1"
VIDEO_INTERRUPT_ENTRY_MODEL: str = "real16_int21_int10_stack_v2"


class InterruptFrameRefusal(StrEnum):
    """Unsupported instruction shape or insufficient evidence for stack writes."""

    ENCODING = "unsupported_interrupt_encoding"
    WRAP = "interrupt_frame_wrap"
    FALLTHROUGH_WRAP = "service_fallthrough_wrap"
    UNDECLARED = "interrupt_frame_undeclared"
    CODE_WRITE = "interrupt_frame_code_write"
    SERVICE_WRITE = "service_writes_interrupt_frame"


@dataclass(frozen=True, slots=True)
class InterruptFrame:
    """Checked bytes left on the stack by one summarized interrupt entry."""

    address: int
    data: bytes


def program_interrupt_frame(
    *, instruction: bytes, instruction_pointer: SegOffset, stack: SegOffset,
    flags: int, memory: ProgramMemoryLayout, code_ranges: tuple[LinearRange, ...],
    vector: int = 0x21,
) -> InterruptFrame | InterruptFrameRefusal:
    """Construct saved IP, CS and FLAGS in ascending physical-address order.

    Only the unprefixed 16-bit instruction is admitted. Offset wrap and partial
    faults remain outside this bounded execution model. All six destination
    bytes must be explicitly declared and disjoint from executable code.
    Validation happens before any guest state or external service is mutated.
    """
    if type(vector) is not int or vector not in (0x10, 0x21) or instruction != bytes((0xCD, vector)):
        return InterruptFrameRefusal.ENCODING
    if instruction_pointer.offset + 2 > 0xFFFF:
        return InterruptFrameRefusal.FALLTHROUGH_WRAP
    if stack.offset < 6:
        return InterruptFrameRefusal.WRAP
    address = stack.linear() - 6
    if not memory.contains(address, 6):
        return InterruptFrameRefusal.UNDECLARED
    if any(region.overlaps(address, 6) for region in code_ranges):
        return InterruptFrameRefusal.CODE_WRITE
    words = (instruction_pointer.offset + 2, instruction_pointer.segment, flags & 0xFFFF)
    return InterruptFrame(address, b"".join(word.to_bytes(2, "little") for word in words))
