"""Bounded caller-declared INT10/AH=1B/BX=0 video functionality-state contract for real16 replay.

Layer: dosunit concrete execution contracts.
Responsibility: declare the typed policy, manifest parsing, identity
projection, deterministic report payload, 64-byte functionality-state
table construction and receipt predicate for the VGA functionality-state
service (INT 0x10, AH=0x1B, selector BX=0x0000) available to whole-program
replay.

The contract is an explicit synthetic environment declaration: the caller
states every BIOS-static answer field — the static-functionality-table far
pointer, display combination code pair, colour count, page count,
scan-line code, miscellaneous flags and video-memory indicator — plus the
segmented service ``entry`` the declared IVT slot 0x10 must target. The
only live inputs are the two BIOS Data Area byte runs the native service
copies: thirty bytes starting at the current-mode byte, then a three-byte
run starting at the rows byte whose first byte is reported incremented
with 8-bit wraparound. Nothing here models an installed BIOS, walks a
save-pointer table or infers host video state; the declared fields are
bounded caller-supplied data, never proof of real firmware behavior.

The execution owner — not this module — checks the live IVT slot, the
interrupt frame, the destination buffer, live BDA availability and
executable-code aliasing before consuming one declared answer, and
performs every guest write. An admitted call's response effect is the
documented answer byte AL=0x1B plus the 64-byte table placed at the
checked ES:DI destination; preserving every other register bit, flag and
segment is the executor's obligation, as are architectural INT stack
writes. Only the unprefixed AH=0x1B/BX=0x0000 call is admitted by this
contract; nonzero selectors and every other INT10 service keep refusing.
"""

from __future__ import annotations

from dataclasses import dataclass

from tools.dosunit.runtime.real16_program_vectors import vector_bytes
from tools.dosunit.runtime.real16_replay_model import SegOffset

# INT10/AH=1B is the VGA functionality-state service. Only selector
# BX=0x0000 is admitted; the native handler answers AL=0 for other BX.
VIDEO_STATE_VECTOR: int = 0x10
VIDEO_STATE_FUNCTION: int = 0x1B
VIDEO_STATE_SELECTOR: int = 0x0000

# Live-input shape: the native service copies 0x1E BDA bytes starting at
# the current-mode byte, then 3 bytes starting at the rows byte. The
# destination addresses are execution-boundary evidence, not policy data.
VIDEO_STATE_BDA_BYTES: int = 0x1E
VIDEO_STATE_ROW_BYTES: int = 3
VIDEO_STATE_TABLE_BYTES: int = 0x40

# The deterministic report payload for one answered call: vector,
# function, the admitted 16-bit selector little-endian, then the complete
# 64-byte table so a report reader never needs to re-derive it.
VIDEO_STATE_PREFIX: bytes = bytes((VIDEO_STATE_VECTOR, VIDEO_STATE_FUNCTION))
VIDEO_STATE_SELECTOR_BYTES: bytes = VIDEO_STATE_SELECTOR.to_bytes(2, "little")
VIDEO_STATE_EVENT_BYTES: int = (
    len(VIDEO_STATE_PREFIX) + len(VIDEO_STATE_SELECTOR_BYTES) + VIDEO_STATE_TABLE_BYTES
)

# Table offsets of the declared static fields inside the zero-filled
# region, fixed by the Dynamic_Functionality layout.
_STATIC_STATE_OFFSET: int = 0x00
_BDA_OFFSET: int = 0x04
_ROWS_OFFSET: int = 0x22
_DCC_OFFSET: int = 0x25
_COLOURS_OFFSET: int = 0x27
_PAGES_OFFSET: int = 0x29
_SCANLINE_OFFSET: int = 0x2A
_MISC_OFFSET: int = 0x2D
_MEMORY_OFFSET: int = 0x31

_U8_MAX: int = 0xFF
_U16_MAX: int = 0xFFFF
# Scan-line codes 0..3 encode 200/350/400/480 lines; memory indicators
# 0..3 encode 64/128/192/256 KiB. Miscellaneous flags are written by the
# native service only as 0x01 (non-text mode) or 0x21 (text mode).
_SCANLINE_MAX: int = 3
_MEMORY_MAX: int = 3
_MISC_VALUES: frozenset[int] = frozenset((0x01, 0x21))
_PAGES_MIN: int = 1


def _checked_domain(value: int, name: str, low: int, high: int) -> int:
    """Validate one integer domain field, rejecting bool masquerades."""
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in [{low:#x}, {high:#x}]")
    return value


def _checked_pointer(value: SegOffset, name: str) -> SegOffset:
    """Require typed segmented coordinates with strict integer words."""
    if not isinstance(value, SegOffset):
        raise ValueError(f"{name} requires explicit segmented coordinates")
    if type(value.segment) is not int or type(value.offset) is not int:
        raise ValueError(f"{name} coordinates must be integer words")
    return value


@dataclass(frozen=True, slots=True)
class VideoStatePolicy:
    """Explicit caller-declared functionality-state answer and service entry.

    ``static_state`` is the far pointer the native service writes at table
    offset 0 (offset word, then segment word, little-endian). ``dcc`` and
    ``colours`` are the 16-bit words at offsets 0x25 and 0x27. ``pages``,
    ``scanline``, ``misc`` and ``memory`` are the bytes at offsets 0x29,
    0x2A, 0x2D and 0x31, each bounded to the domain the native writer can
    produce: a nonzero page count, scan-line codes 0..3, miscellaneous
    flags 0x01 or 0x21, and memory indicators 0..3. ``entry`` is the
    segmented service target the caller declares for IVT slot 0x10; the
    executor must confirm the live vector still targets it, that the
    interrupt frame, destination buffer, BDA inputs and program code do
    not alias it and that the dispatch stays inside the declared service
    scope before consuming any answer. The policy is immutable, has no
    defaults and carries no runtime state: one declared policy answers
    every admitted call identically given the same live BDA bytes, and
    never claims an installed BIOS exists.
    """

    static_state: SegOffset
    dcc: int
    colours: int
    pages: int
    scanline: int
    misc: int
    memory: int
    entry: SegOffset

    def __post_init__(self) -> None:
        """Bind the declared fields to the native-writable domains."""
        _checked_pointer(self.static_state, "static functionality table")
        _checked_domain(self.dcc, "display combination code", 0, _U16_MAX)
        _checked_domain(self.colours, "colour count", 0, _U16_MAX)
        _checked_domain(self.pages, "page count", _PAGES_MIN, _U8_MAX)
        _checked_domain(self.scanline, "scan-line code", 0, _SCANLINE_MAX)
        if type(self.misc) is not int or self.misc not in _MISC_VALUES:
            raise ValueError("miscellaneous flags must be 0x01 (non-text) or 0x21 (text)")
        _checked_domain(self.memory, "video memory indicator", 0, _MEMORY_MAX)
        _checked_pointer(self.entry, "video state entry")


def video_state_table(policy: VideoStatePolicy, bda: bytes, rows: bytes) -> bytes:
    """Build the complete 64-byte functionality-state table for one admitted call.

    ``bda`` is the exact 30-byte live BDA run starting at the current-mode
    byte; ``rows`` is the exact 3-byte live run starting at the rows byte.
    The layout is the native Dynamic_Functionality order: far
    ``static_state`` pointer, verbatim BDA copy, rows byte incremented
    with 8-bit wraparound plus the next two bytes verbatim, then the
    declared static fields inside an otherwise zero-filled tail. The
    caller supplies checked live bytes; this function performs no guest
    writes and the returned table is the entire documented response.
    """
    if not isinstance(policy, VideoStatePolicy):
        raise ValueError("video state table requires a declared VideoStatePolicy")
    if type(bda) is not bytes or len(bda) != VIDEO_STATE_BDA_BYTES:
        raise ValueError(f"video state table requires exactly {VIDEO_STATE_BDA_BYTES} live BDA bytes")
    if type(rows) is not bytes or len(rows) != VIDEO_STATE_ROW_BYTES:
        raise ValueError(f"video state table requires exactly {VIDEO_STATE_ROW_BYTES} live row bytes")
    table = bytearray(VIDEO_STATE_TABLE_BYTES)
    table[_STATIC_STATE_OFFSET:_STATIC_STATE_OFFSET + 4] = vector_bytes(policy.static_state)
    table[_BDA_OFFSET:_BDA_OFFSET + VIDEO_STATE_BDA_BYTES] = bda
    table[_ROWS_OFFSET] = (rows[0] + 1) & _U8_MAX
    table[_ROWS_OFFSET + 1:_ROWS_OFFSET + VIDEO_STATE_ROW_BYTES] = rows[1:]
    table[_DCC_OFFSET:_DCC_OFFSET + 2] = policy.dcc.to_bytes(2, "little")
    table[_COLOURS_OFFSET:_COLOURS_OFFSET + 2] = policy.colours.to_bytes(2, "little")
    table[_PAGES_OFFSET] = policy.pages
    table[_SCANLINE_OFFSET] = policy.scanline
    table[_MISC_OFFSET] = policy.misc
    table[_MEMORY_OFFSET] = policy.memory
    return bytes(table)


def video_state_event_data(policy: VideoStatePolicy, bda: bytes, rows: bytes) -> bytes:
    """Return the deterministic report payload for one answered call.

    The payload is vector, function, the admitted selector little-endian,
    then the complete 64-byte table — the complete declared response so a
    report reader never needs to re-derive it. ``entry`` is service
    routing evidence owned by the executor's IVT checks, not part of the
    answer payload.
    """
    data = VIDEO_STATE_PREFIX + VIDEO_STATE_SELECTOR_BYTES + video_state_table(policy, bda, rows)
    if not video_state_receipt_complete(data):
        raise ValueError("invalid video state receipt")
    return data


def video_state_receipt_complete(data: bytes) -> bool:
    """Reject truncated, extended or differently selected service receipts."""
    return (
        type(data) is bytes
        and len(data) == VIDEO_STATE_EVENT_BYTES
        and data[: len(VIDEO_STATE_PREFIX)] == VIDEO_STATE_PREFIX
        and data[len(VIDEO_STATE_PREFIX): len(VIDEO_STATE_PREFIX) + 2] == VIDEO_STATE_SELECTOR_BYTES
    )


def video_state_document(policy: VideoStatePolicy | None) -> dict[str, object] | None:
    """Project the declared functionality state and entry into deterministic identity data."""
    if policy is None:
        return None
    if not isinstance(policy, VideoStatePolicy):
        raise ValueError("video state document requires a declared VideoStatePolicy or None")
    return {
        "static_state": {"segment": policy.static_state.segment, "offset": policy.static_state.offset},
        "dcc": policy.dcc,
        "colours": policy.colours,
        "pages": policy.pages,
        "scanline": policy.scanline,
        "misc": policy.misc,
        "memory": policy.memory,
        "entry": {"segment": policy.entry.segment, "offset": policy.entry.offset},
    }


def _integer(value: object, name: str) -> int:
    """Accept explicit JSON integers/hex strings, never bool or float aliases."""
    if type(value) is int:
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as error:
            raise ValueError(f"{name}: invalid integer") from error
    raise ValueError(f"{name}: expected integer")


def _object(value: object, keys: set[str], name: str) -> dict[str, object]:
    """Require exactly the declared JSON members, without ignored fields."""
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{name}: expected exactly {sorted(keys)}")
    return value


def _pointer(value: object, name: str) -> SegOffset:
    """Read an explicit segmented pointer object with strict word members."""
    declared = _object(value, {"segment", "offset"}, name)
    return SegOffset(
        _integer(declared["segment"], f"{name} segment"),
        _integer(declared["offset"], f"{name} offset"),
    )


def parse_video_state_policy(value: object) -> VideoStatePolicy | None:
    """Read an explicit functionality-state object; absence keeps the service refused.

    The object must declare exactly ``static_state``, ``dcc``, ``colours``,
    ``pages``, ``scanline``, ``misc``, ``memory`` and ``entry`` — unknown
    or missing fields are malformed. Each numeric field must be an
    explicit integer or hexadecimal string inside its documented domain;
    ``static_state`` and ``entry`` must declare exactly ``segment`` and
    ``offset`` as explicit integers or hexadecimal strings inside the
    16-bit word domain. ``None`` declares "no functionality-state service"
    and every call refuses.
    """
    if value is None:
        return None
    declared = _object(
        value,
        {"static_state", "dcc", "colours", "pages", "scanline", "misc", "memory", "entry"},
        "bios_video_state",
    )
    return VideoStatePolicy(
        _pointer(declared["static_state"], "bios_video_state static_state"),
        _integer(declared["dcc"], "bios_video_state dcc"),
        _integer(declared["colours"], "bios_video_state colours"),
        _integer(declared["pages"], "bios_video_state pages"),
        _integer(declared["scanline"], "bios_video_state scanline"),
        _integer(declared["misc"], "bios_video_state misc"),
        _integer(declared["memory"], "bios_video_state memory"),
        _pointer(declared["entry"], "bios_video_state entry"),
    )
