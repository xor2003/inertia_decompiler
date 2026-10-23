"""Layer: Frontend / explicit DOS runtime contracts.

Responsibility: describe the guest-visible DOSBox INT21 entry writes for
declared version and resize services. This pure owner models the architectural
interrupt frame, PSP saved-stack pointer and nine register-save words. Service
responses, allocator changes, image authentication and write-overlap checks
remain consumer obligations. This is an explicit backend premise, never an
inferred universal DOS behavior or proof that the handler was executed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

_INTERRUPT_FRAME_BYTES: int = 6
_SAVE_BYTES: int = 18
_PSP_STACK_OFFSET: int = 0x2E
_REAL16_LIMIT: int = 0x100000


class DosBoxInt21FrameFailure8616(StrEnum):
    """Missing bounded input evidence for the declared entry effects."""

    COORDINATES_UNPROVED = "dosbox_int21_coordinates_unproved"
    REGISTER_UNPROVED = "dosbox_int21_saved_register_malformed"
    SERVICE_UNPROVED = "dosbox_int21_service_unproved"
    STACK_WRAP = "dosbox_int21_stack_wrap_unmodeled"
    ADDRESS_WRAP = "dosbox_int21_address_wrap_unmodeled"


@dataclass(frozen=True, slots=True)
class DosBoxInt21Registers8616:
    """Proven low-word inputs; None retains an unknown saved word's write."""

    ax: int | None
    bx: int | None
    cx: int | None
    dx: int | None
    si: int | None
    di: int | None
    bp: int | None
    ds: int | None
    es: int | None

    def saved_words(self) -> tuple[int | None, ...]:
        """Return words in the native DOS_21Handler store order."""
        return (self.ax, self.bx, self.cx, self.dx, self.si,
                self.di, self.bp, self.ds, self.es)


@dataclass(frozen=True, slots=True)
class DosBoxInt21Write8616:
    """One ordered write preserving its segment and offset coordinates.

    None data means the entire size is written with unknown contents; it
    never means no write. Consumers must retain tuple order even when the
    PSP and stack alias, and must check their image/IVT/frame boundaries.
    """

    segment: int
    offset: int
    size: int
    data: bytes | None

    @property
    def linear(self) -> int:
        """Project an already bounded declared guest coordinate for checks."""
        return (self.segment << 4) + self.offset


@dataclass(frozen=True, slots=True)
class DosBoxInt21FrameEffects8616:
    """Complete entry effects or an explicit refusal with no partial writes."""

    writes: tuple[DosBoxInt21Write8616, ...]
    failure: DosBoxInt21FrameFailure8616 | None


def _word(value: object) -> bool:
    """Accept an exact unsigned machine word, excluding Boolean values."""
    return type(value) is int and 0 <= value <= 0xFFFF


def _input_failure(
    psp_segment: int, ss: int, sp: int, registers: DosBoxInt21Registers8616,
) -> DosBoxInt21FrameFailure8616 | None:
    """Check every prerequisite before materializing any memory effect."""
    if not all(_word(value) for value in (psp_segment, ss, sp)) or psp_segment == 0:
        return DosBoxInt21FrameFailure8616.COORDINATES_UNPROVED
    if any(value is not None and not _word(value) for value in registers.saved_words()):
        return DosBoxInt21FrameFailure8616.REGISTER_UNPROVED
    if registers.ax is None or registers.ax >> 8 not in (0x30, 0x4A):
        return DosBoxInt21FrameFailure8616.SERVICE_UNPROVED
    if sp < _INTERRUPT_FRAME_BYTES + _SAVE_BYTES:
        return DosBoxInt21FrameFailure8616.STACK_WRAP
    stack_end = (ss << 4) + sp
    pointer_end = (psp_segment << 4) + _PSP_STACK_OFFSET + 4
    if max(stack_end, pointer_end) > _REAL16_LIMIT:
        return DosBoxInt21FrameFailure8616.ADDRESS_WRAP
    return None


def dosbox_int21_frame_effects_8616(
    *, psp_segment: int, ss: int, sp: int,
    registers: DosBoxInt21Registers8616,
) -> DosBoxInt21FrameEffects8616:
    """Compute declared entry writes from pre-INT architectural SP.

    DOSBox's DOS_21Handler sees SP after the six-byte interrupt frame,
    records SS:(SP-18) in PSP:2E, then saves AX/BX/CX/DX/SI/DI/BP/DS/ES.
    All eleven writes remain ordered; unknown register words still revoke
    their memory contents. Segment/20-bit wrapping refuses rather than
    assuming an A20 policy. The architectural frame's contents remain
    explicitly unknown because this owner does not receive flags or IP.
    """
    failure = _input_failure(psp_segment, ss, sp, registers)
    if failure is not None:
        return DosBoxInt21FrameEffects8616((), failure)
    frame_offset = sp - _INTERRUPT_FRAME_BYTES
    save_offset = frame_offset - _SAVE_BYTES
    pointer = save_offset.to_bytes(2, "little") + ss.to_bytes(2, "little")
    writes = [
        DosBoxInt21Write8616(ss, frame_offset, _INTERRUPT_FRAME_BYTES, None),
        DosBoxInt21Write8616(psp_segment, _PSP_STACK_OFFSET, 4, pointer),
    ]
    for index, value in enumerate(registers.saved_words()):
        data = None if value is None else value.to_bytes(2, "little")
        writes.append(DosBoxInt21Write8616(ss, save_offset + index * 2, 2, data))
    return DosBoxInt21FrameEffects8616(tuple(writes), None)
