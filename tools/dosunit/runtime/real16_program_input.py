"""Bounded opt-in DOS INT21 read-only file input contract for initialized MZ replay.

Layer: dosunit concrete execution contracts.
Responsibility: declare the typed policy, runtime state, outcome records and
pure admission logic for the input-only DOS file services available to
whole-program replay: AH=3F reads and AH=42 seeks over explicitly preopened
immutable byte files. The contract is an explicit synthetic environment
declaration: one accepted read is a complete transfer of the served bytes to
the caller's declared destination, and one accepted seek moves the declared
handle's cursor. It is not a model of real DOS file, device, console,
redirection or handle-table behavior — only explicitly declared regular-file
handles are in scope — and it is concrete execution evidence only, never
symbolic proof. The caller owns guest effects: an accepted read must store
``payload`` at the returned destination, set AX to the served count and clear
CF; an accepted seek reports the new cursor in DX:AX and clears CF. Every
other register and flag is the caller's documented preservation obligation.
This module performs no guest writes itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from tools.dosunit.runtime.real16_program_memory import ProgramMemoryLayout
from tools.dosunit.runtime.real16_replay_model import LinearRange, SegOffset

# DOS predefines handles 0-4 (stdin/stdout/stderr/stdaux/stdprn). This contract
# admits only explicitly declared regular-file handles, never the predefines
# and never a guessed PSP handle-table inheritance.
INPUT_HANDLE_MIN: int = 5
INPUT_HANDLE_MAX: int = 0xFFFF

# Declaration limits: at most 32 preopened files and 4 MiB of summed supplied
# content; one read's request is bounded by the 16-bit CX domain and the total
# served bytes under one execution cap at 4 MiB.
MAX_INPUT_FILES: int = 32
MAX_INPUT_BYTES: int = 0x400000

# One 64 KiB real-mode segment; a nonempty DS:DX payload destination may end
# at, never cross, its top. Straddling destinations are refused, not modeled.
SEGMENT_LIMIT: int = 0x10000

# File positions live in the 32-bit DOS cursor domain; seek distances are the
# signed 32-bit CX:DX domain.
U32_MAX: int = 0xFFFFFFFF
S32_MIN: int = -0x80000000
S32_MAX: int = 0x7FFFFFFF


def _checked_u16(value: int, name: str) -> int:
    """Validate one 16-bit domain field, rejecting bool masquerades."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFF:
        raise ValueError(f"{name} must be a 16-bit unsigned integer")
    return value


def _checked_u32(value: int, name: str) -> int:
    """Validate one 32-bit cursor field, rejecting bool masquerades."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= U32_MAX:
        raise ValueError(f"{name} must be a 32-bit unsigned integer")
    return value


def _checked_positive(value: int, name: str) -> int:
    """Validate one positive byte cap, rejecting bool masquerades."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


class SeekOrigin(StrEnum):
    """Declared AH=42 basis; raw AL mode codes are resolved by the caller."""

    BEGIN = "begin"
    CURRENT = "current"
    END = "end"


class InputRefusal(StrEnum):
    """Typed reason one declared input request was refused; never hidden."""

    UNSUPPORTED_HANDLE = "unsupported_handle"
    PER_CALL_EXCEEDED = "per_call_exceeded"
    TOTAL_EXCEEDED = "total_exceeded"
    SEGMENT_WRAP = "segment_wrap"
    OUTSIDE_ARENA = "outside_arena"
    CURSOR_BEFORE_START = "cursor_before_start"
    CURSOR_OVERFLOW = "cursor_overflow"


@dataclass(frozen=True, slots=True)
class InputFile:
    """One explicitly preopened immutable byte file.

    ``handle`` is the declared DOS handle in 5..0xFFFF — the 0-4 predefines
    are never regular files under this contract. ``data`` is the complete
    supplied content snapshot coerced to immutable bytes, and ``cursor`` is
    the explicit initial file position, which may already lie past the end.
    """

    handle: int
    data: bytes
    cursor: int

    def __post_init__(self) -> None:
        """Bind the record to the declared-handle and u32-cursor domain."""
        if isinstance(self.handle, bool) or not isinstance(self.handle, int):
            raise ValueError("input file handle must be an integer, never bool")
        if not INPUT_HANDLE_MIN <= self.handle <= INPUT_HANDLE_MAX:
            raise ValueError("input file handle must lie in 5..0xFFFF")
        if isinstance(self.data, bytearray):
            object.__setattr__(self, "data", bytes(self.data))
        if not isinstance(self.data, bytes):
            raise ValueError("input file data must be immutable bytes")
        _checked_u32(self.cursor, "cursor")


@dataclass(frozen=True, slots=True)
class InputPolicy:
    """Explicit opt-in input scope; no file or byte budget is implicit.

    ``files`` is the declared tuple of preopened immutable files; it may be
    empty, which declares "no input service" and refuses every call. Handles
    must be unique, at most ``MAX_INPUT_FILES`` files are admitted, and their
    summed content may not exceed ``MAX_INPUT_BYTES``. ``per_call_bytes``
    bounds one read's request and ``total_bytes`` bounds the summed payloads
    of every accepted read under one execution; both caps are positive. The
    policy is immutable — per-execution positions live in ``InputRuntime``.
    """

    files: tuple[InputFile, ...]
    per_call_bytes: int
    total_bytes: int

    def __post_init__(self) -> None:
        """Require declared immutable files, unique handles and positive caps."""
        if not isinstance(self.files, tuple):
            raise ValueError("input policy files must be a tuple")
        if any(not isinstance(file, InputFile) for file in self.files):
            raise ValueError("input policy files must be InputFile records")
        if len(self.files) > MAX_INPUT_FILES:
            raise ValueError("input policy declares too many files")
        handles = [file.handle for file in self.files]
        if len(set(handles)) != len(handles):
            raise ValueError("input policy handles must be unique")
        if sum(len(file.data) for file in self.files) > MAX_INPUT_BYTES:
            raise ValueError("input policy content exceeds the aggregate cap")
        _checked_positive(self.per_call_bytes, "per_call_bytes")
        if self.per_call_bytes > 0xFFFF:
            raise ValueError("per_call_bytes must fit the 16-bit CX domain")
        _checked_positive(self.total_bytes, "total_bytes")
        if self.total_bytes > MAX_INPUT_BYTES:
            raise ValueError("total_bytes exceeds the served-byte cap")


@dataclass(slots=True)
class InputRuntime:
    """Owned mutable per-execution input state; the policy never mutates.

    ``cursors`` holds each declared handle's current u32 position and
    ``served`` sums every accepted read payload against ``total_bytes``.
    Fresh runtime state comes only from ``program_input_runtime``; refused
    calls never mutate it.
    """

    cursors: dict[int, int]
    served: int = 0


def program_input_runtime(policy: InputPolicy) -> InputRuntime:
    """Build fresh runtime state; cursors start at each declared position."""
    if not isinstance(policy, InputPolicy):
        raise ValueError("input runtime requires a declared InputPolicy")
    return InputRuntime({file.handle: file.cursor for file in policy.files})


@dataclass(frozen=True, slots=True)
class ReadAccepted:
    """One completed read; the caller stores ``payload`` at ``destination``.

    ``ax`` equals the served count — zero at end-of-file or for a zero
    request — and ``carry`` is clear. ``next_cursor`` is the handle's
    position after the call; it advances only by the served length. Guest
    bytes beyond the payload are the caller's preservation obligation.
    """

    handle: int
    destination: SegOffset
    payload: bytes
    ax: int
    carry: bool
    next_cursor: int

    def __post_init__(self) -> None:
        """Bind the receipt to the served-byte register effects."""
        _checked_u16(self.handle, "handle")
        if self.handle < INPUT_HANDLE_MIN:
            raise ValueError("accepted read requires a declared regular-file handle")
        if not isinstance(self.destination, SegOffset):
            raise ValueError("accepted input requires a segmented destination")
        _checked_u16(self.destination.segment, "destination segment")
        _checked_u16(self.destination.offset, "destination offset")
        if isinstance(self.payload, bytearray):
            object.__setattr__(self, "payload", bytes(self.payload))
        if not isinstance(self.payload, bytes):
            raise ValueError("accepted input payload must be bytes")
        _checked_u16(self.ax, "ax")
        if self.ax != len(self.payload):
            raise ValueError("accepted input must report ax equal to the payload size")
        if self.carry is not False:
            raise ValueError("accepted input must report a clear carry flag")
        _checked_u32(self.next_cursor, "next_cursor")


@dataclass(frozen=True, slots=True)
class SeekAccepted:
    """One completed seek; DX:AX reports the new u32 cursor, CF clear.

    ``ax`` is the low word, ``dx`` the high word and ``next_cursor`` the
    combined position already installed in the runtime.
    """

    handle: int
    ax: int
    dx: int
    carry: bool
    next_cursor: int

    def __post_init__(self) -> None:
        """Bind the receipt to the DX:AX cursor effects."""
        _checked_u16(self.handle, "handle")
        if self.handle < INPUT_HANDLE_MIN:
            raise ValueError("accepted seek requires a declared regular-file handle")
        _checked_u16(self.ax, "ax")
        _checked_u16(self.dx, "dx")
        _checked_u32(self.next_cursor, "next_cursor")
        if (self.dx << 16) | self.ax != self.next_cursor:
            raise ValueError("accepted seek DX:AX must equal next_cursor")
        if self.carry is not False:
            raise ValueError("accepted seek must report a clear carry flag")


@dataclass(frozen=True, slots=True)
class InputRefused:
    """One refused request; the executor must stop, never emulate a DOS error."""

    handle: int
    refusal: InputRefusal

    def __post_init__(self) -> None:
        """Retain a typed refusal, never a text status."""
        _checked_u16(self.handle, "handle")
        if not isinstance(self.refusal, InputRefusal):
            raise ValueError("refused input requires a typed InputRefusal")


type InputReadResult = ReadAccepted | InputRefused
type InputSeekResult = SeekAccepted | InputRefused


def _declared_file(policy: InputPolicy, handle: int) -> InputFile | None:
    """Return the declared file for ``handle``; the policy tuple is the sole authority."""
    for file in policy.files:
        if file.handle == handle:
            return file
    return None


def _runtime_cursor(runtime: InputRuntime, handle: int) -> int:
    """Return a declared handle's current u32 cursor; corrupt state is loud."""
    if not isinstance(runtime.cursors, dict):
        raise ValueError("input runtime cursors must be a dict")
    cursor = runtime.cursors.get(handle)
    if cursor is None:
        raise ValueError("input runtime has no cursor for a declared handle")
    return _checked_u32(cursor, "cursor")


def _checked_service_arguments(policy: InputPolicy, runtime: InputRuntime) -> None:
    """Require the complete declared runtime denominator before any effect."""
    if not isinstance(policy, InputPolicy):
        raise ValueError("input service requires a declared InputPolicy")
    if not isinstance(runtime, InputRuntime):
        raise ValueError("input service requires an owned InputRuntime")
    if not isinstance(runtime.cursors, dict):
        raise ValueError("input runtime cursors must be a dict")
    if len(runtime.cursors) != len(policy.files):
        raise ValueError("input runtime requires every declared handle exactly once")
    for handle, cursor in runtime.cursors.items():
        _checked_u16(handle, "runtime handle")
        _checked_u32(cursor, "runtime cursor")
    if set(runtime.cursors) != {file.handle for file in policy.files}:
        raise ValueError("input runtime cannot contain undeclared handles")
    if isinstance(runtime.served, bool) or not isinstance(runtime.served, int):
        raise ValueError("input runtime served must be an integer, never bool")
    if not 0 <= runtime.served <= policy.total_bytes:
        raise ValueError("input runtime served must lie inside the declared total cap")


def _checked_read_arguments(
    policy: InputPolicy,
    runtime: InputRuntime,
    handle: int,
    segment: int,
    offset: int,
    count: int,
    allocation: LinearRange | ProgramMemoryLayout,
) -> None:
    """Raise ``ValueError`` for any malformed value at the read boundary."""
    _checked_service_arguments(policy, runtime)
    _checked_u16(handle, "handle")
    _checked_u16(segment, "segment")
    _checked_u16(offset, "offset")
    _checked_u16(count, "count")
    if not isinstance(allocation, (LinearRange, ProgramMemoryLayout)):
        raise ValueError("input service requires the declared arena LinearRange or ProgramMemoryLayout")


def _checked_seek_arguments(
    policy: InputPolicy,
    runtime: InputRuntime,
    handle: int,
    origin: SeekOrigin,
    distance: int,
) -> None:
    """Raise ``ValueError`` for any malformed value at the seek boundary."""
    _checked_service_arguments(policy, runtime)
    _checked_u16(handle, "handle")
    if not isinstance(origin, SeekOrigin):
        raise ValueError("seek origin must be a declared SeekOrigin")
    if isinstance(distance, bool) or not isinstance(distance, int):
        raise ValueError("seek distance must be an integer, never bool")
    if not S32_MIN <= distance <= S32_MAX:
        raise ValueError("seek distance must fit the signed 32-bit domain")


def program_input_read(
    policy: InputPolicy,
    runtime: InputRuntime,
    *,
    handle: int,
    segment: int,
    offset: int,
    count: int,
    allocation: LinearRange | ProgramMemoryLayout,
) -> InputReadResult:
    """Admit one INT21/AH=3F-shaped read under the declared policy.

    Malformed arguments — non-integer or bool fields, values outside their
    declared width, a non-policy ``policy``, a non-runtime ``runtime``, a
    ``served`` counter outside the declared total cap, or a declared handle
    whose runtime cursor is missing or outside the u32 domain — raise
    ``ValueError``. Scope violations return ``InputRefused`` in a fixed
    order — handle, per-call cap, total budget — before any state changes,
    and a nonempty payload additionally requires its DS:DX destination to
    end inside the 64 KiB segment and lie wholly inside ``allocation``. A
    refused call never mutates ``runtime``. Serving ``count`` bytes may be
    short at end-of-file; an empty payload (EOF or zero ``count``) touches
    no memory, so wrap and arena checks do not apply and the cursor does
    not move. Accepted calls advance the cursor and ``served`` only by the
    payload's actual length. This function performs no guest writes.
    """
    _checked_read_arguments(policy, runtime, handle, segment, offset, count, allocation)
    file = _declared_file(policy, handle)
    if file is None:
        return InputRefused(handle, InputRefusal.UNSUPPORTED_HANDLE)
    cursor = _runtime_cursor(runtime, handle)
    if count > policy.per_call_bytes:
        return InputRefused(handle, InputRefusal.PER_CALL_EXCEEDED)
    payload = file.data[cursor:cursor + count]
    if len(payload) > policy.total_bytes - runtime.served:
        return InputRefused(handle, InputRefusal.TOTAL_EXCEEDED)
    if not payload:
        return ReadAccepted(handle, SegOffset(segment, offset), b"", 0, False, cursor)
    if offset + len(payload) > SEGMENT_LIMIT:
        return InputRefused(handle, InputRefusal.SEGMENT_WRAP)
    if not allocation.contains(segment * 16 + offset, len(payload)):
        return InputRefused(handle, InputRefusal.OUTSIDE_ARENA)
    next_cursor = cursor + len(payload)
    runtime.cursors[handle] = next_cursor
    runtime.served += len(payload)
    return ReadAccepted(handle, SegOffset(segment, offset), payload, len(payload), False, next_cursor)


def program_input_seek(
    policy: InputPolicy,
    runtime: InputRuntime,
    *,
    handle: int,
    origin: SeekOrigin,
    distance: int,
) -> InputSeekResult:
    """Admit one INT21/AH=42-shaped seek under the declared policy.

    Malformed arguments — non-integer or bool fields, a non-``SeekOrigin``
    origin, or a ``distance`` outside the signed 32-bit domain — raise
    ``ValueError``. An undeclared handle refuses; a result below position
    zero refuses ``CURSOR_BEFORE_START`` and one above the u32 domain
    refuses ``CURSOR_OVERFLOW``. A refused seek never changes the cursor.
    An accepted seek installs the new cursor and reports it in DX:AX with
    CF clear. This function performs no guest writes and consumes no
    served-byte budget.
    """
    _checked_seek_arguments(policy, runtime, handle, origin, distance)
    file = _declared_file(policy, handle)
    if file is None:
        return InputRefused(handle, InputRefusal.UNSUPPORTED_HANDLE)
    cursor = _runtime_cursor(runtime, handle)
    if origin is SeekOrigin.BEGIN:
        basis = 0
    elif origin is SeekOrigin.CURRENT:
        basis = cursor
    else:
        basis = len(file.data)
    new_cursor = basis + distance
    if new_cursor < 0:
        return InputRefused(handle, InputRefusal.CURSOR_BEFORE_START)
    if new_cursor > U32_MAX:
        return InputRefused(handle, InputRefusal.CURSOR_OVERFLOW)
    runtime.cursors[handle] = new_cursor
    return SeekAccepted(handle, new_cursor & 0xFFFF, new_cursor >> 16, False, new_cursor)
