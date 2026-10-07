"""Bounded opt-in DOS INT21/AH=40 output contract for initialized MZ replay.

Layer: dosunit concrete execution contracts.
Responsibility: declare the typed policy, outcome records and pure admission
logic for the output-only DOS write service available to whole-program
replay. The contract is an explicit synthetic environment declaration: one
accepted call is a complete successful write of ``count`` bytes to the
requested handle's declared byte stream. It is not a model of real DOS file,
console, redirection, or handle-table behavior, and it is concrete execution
evidence only, never symbolic proof. The caller owns guest effects: an
accepted call sets AX to the written count and clears CF, and every other
register and flag is the caller's documented preservation obligation.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum

from tools.dosunit.runtime.real16_program_memory import ProgramMemoryLayout
from tools.dosunit.runtime.real16_program_rom import ProgramRom, check_rom, readable_memory_contains
from tools.dosunit.runtime.real16_replay_model import LinearRange

# DOS handles this contract may admit: 1 is the stdout stream and 2 the
# stderr stream. Handle 0 (input), real file handles and devices are never
# in scope; admission exists only for streams the caller declares as output.
OUTPUT_HANDLES: frozenset[int] = frozenset({1, 2})

# One 64 KiB real-mode segment; a DS:DX+CX buffer may end at, never cross,
# its top. Straddling buffers are refused rather than modeled.
SEGMENT_LIMIT: int = 0x10000

# Return exactly ``size`` bytes starting at the linear address. The callback
# is the owned memory boundary: it is invoked at most once per call, only
# after every refusal check, and is never asked to write.
type OutputReader = Callable[[int, int], bytes]


def _checked_u16(value: int, name: str) -> int:
    """Validate one 16-bit domain field, rejecting bool masquerades."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFF:
        raise ValueError(f"{name} must be a 16-bit unsigned integer")
    return value


def _checked_positive(value: int, name: str) -> int:
    """Validate one positive byte cap, rejecting bool masquerades."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


class OutputRefusal(StrEnum):
    """Typed reason one declared output request was refused; never hidden."""

    UNSUPPORTED_HANDLE = "unsupported_handle"
    PER_CALL_EXCEEDED = "per_call_exceeded"
    AGGREGATE_EXCEEDED = "aggregate_exceeded"
    SEGMENT_WRAP = "segment_wrap"
    OUTSIDE_ARENA = "outside_arena"
    SHORT_READ = "short_read"


@dataclass(frozen=True, slots=True)
class OutputPolicy:
    """Explicit opt-in output scope; no handle or byte budget is implicit.

    ``handles`` declares the subset of ``OUTPUT_HANDLES`` whose stream writes
    are admitted; it may be empty, which declares "no output service" and
    refuses every call. ``per_call_bytes`` bounds one write and
    ``aggregate_bytes`` bounds the summed payloads of every accepted call
    under one execution; both caps are positive.
    """

    handles: frozenset[int]
    per_call_bytes: int
    aggregate_bytes: int

    def __post_init__(self) -> None:
        """Require declared integer handles inside {1, 2} and positive caps."""
        if not isinstance(self.handles, frozenset):
            raise ValueError("output policy handles must be a frozenset")
        if any(isinstance(handle, bool) or not isinstance(handle, int) for handle in self.handles):
            raise ValueError("output policy handles must be integers, never bool")
        if not self.handles <= OUTPUT_HANDLES:
            raise ValueError("output policy may enable only DOS handles 1 and 2")
        _checked_positive(self.per_call_bytes, "per_call_bytes")
        _checked_positive(self.aggregate_bytes, "aggregate_bytes")


@dataclass(frozen=True, slots=True)
class OutputAccepted:
    """One completed stream write; event boundaries are diagnostic only.

    ``ax`` equals the written count and ``carry`` is clear — the entire
    register effect of the synthetic contract. Stream equality is defined
    over concatenated per-handle payloads, never over how many calls
    produced them.
    """

    handle: int
    payload: bytes
    ax: int
    carry: bool

    def __post_init__(self) -> None:
        """Bind the record to the complete-write invariant."""
        _checked_u16(self.handle, "handle")
        _checked_u16(self.ax, "ax")
        if self.handle not in OUTPUT_HANDLES:
            raise ValueError("accepted output requires a DOS output handle")
        if isinstance(self.payload, bytearray):
            object.__setattr__(self, "payload", bytes(self.payload))
        if not isinstance(self.payload, bytes):
            raise ValueError("accepted output payload must be bytes")
        if isinstance(self.ax, bool) or not isinstance(self.ax, int) or self.ax != len(self.payload):
            raise ValueError("accepted output must report ax equal to the payload size")
        if self.carry is not False:
            raise ValueError("accepted output must report a clear carry flag")


@dataclass(frozen=True, slots=True)
class OutputRefused:
    """One refused request; the executor must stop, never emulate a DOS error."""

    handle: int
    refusal: OutputRefusal

    def __post_init__(self) -> None:
        """Retain a typed refusal, never a text status."""
        _checked_u16(self.handle, "handle")
        if not isinstance(self.refusal, OutputRefusal):
            raise ValueError("refused output requires a typed OutputRefusal")


type OutputCallResult = OutputAccepted | OutputRefused


def _checked_arguments(
    policy: OutputPolicy,
    handle: int,
    segment: int,
    offset: int,
    count: int,
    allocation: LinearRange | ProgramMemoryLayout,
    aggregate_remaining: int,
    read: OutputReader,
) -> None:
    """Raise ``ValueError`` for any malformed value at the call boundary."""
    if not isinstance(policy, OutputPolicy):
        raise ValueError("output service requires a declared OutputPolicy")
    _checked_u16(handle, "handle")
    _checked_u16(segment, "segment")
    _checked_u16(offset, "offset")
    _checked_u16(count, "count")
    if not isinstance(allocation, (LinearRange, ProgramMemoryLayout)):
        raise ValueError("output service requires the declared arena LinearRange or ProgramMemoryLayout")
    if not callable(read):
        raise ValueError("output service requires a memory-read callback")
    if isinstance(aggregate_remaining, bool) or not isinstance(aggregate_remaining, int):
        raise ValueError("aggregate_remaining must be an integer, never bool")
    if not 0 <= aggregate_remaining <= policy.aggregate_bytes:
        raise ValueError("aggregate_remaining must lie inside the declared aggregate cap")


def program_output_call(
    policy: OutputPolicy,
    *,
    handle: int,
    segment: int,
    offset: int,
    count: int,
    allocation: LinearRange | ProgramMemoryLayout,
    aggregate_remaining: int,
    read: OutputReader,
    rom: ProgramRom | None = None,
) -> OutputCallResult:
    """Admit one INT21/AH=40-shaped write under the declared policy.

    Malformed arguments — non-integer or bool fields, values outside the
    16-bit domain, a remaining allowance outside the declared aggregate cap,
    an untyped memory domain, a non-policy ``policy`` or a non-callable
    ``read`` — raise ``ValueError``. Scope violations return
    ``OutputRefused`` in a fixed order — handle, per-call cap, aggregate
    budget, segment wrap, arena — before ``read`` is invoked, so a refused
    call never touches memory. A zero ``count`` completes with an empty
    payload without dereferencing DS:DX, so wrap and arena checks do not
    apply. ``read`` exceptions propagate unchanged; a read returning
    anything but exactly ``count`` bytes refuses as ``SHORT_READ``. This
    function performs no writes. Optional ``rom`` grants exact read-only
    sources in addition to RAM; it never changes any write destination domain.
    """
    _checked_arguments(policy, handle, segment, offset, count, allocation, aggregate_remaining, read)
    check_rom(rom)
    if handle not in policy.handles:
        return OutputRefused(handle, OutputRefusal.UNSUPPORTED_HANDLE)
    if count > policy.per_call_bytes:
        return OutputRefused(handle, OutputRefusal.PER_CALL_EXCEEDED)
    if count > aggregate_remaining:
        return OutputRefused(handle, OutputRefusal.AGGREGATE_EXCEEDED)
    if count == 0:
        return OutputAccepted(handle, b"", 0, False)
    if offset + count > SEGMENT_LIMIT:
        return OutputRefused(handle, OutputRefusal.SEGMENT_WRAP)
    start = segment * 16 + offset
    if not readable_memory_contains(allocation, rom, start, count):
        return OutputRefused(handle, OutputRefusal.OUTSIDE_ARENA)
    payload = read(start, count)
    if not isinstance(payload, (bytes, bytearray)) or len(payload) != count:
        return OutputRefused(handle, OutputRefusal.SHORT_READ)
    return OutputAccepted(handle, bytes(payload), count, False)


def output_stream_bytes(writes: Iterable[OutputAccepted]) -> dict[int, bytes]:
    """Concatenate accepted writes per handle in emission order.

    The returned streams are the comparison contract: relative ordering
    across handles is discarded, order within one handle is preserved, and
    call-split boundaries do not appear at all.
    """
    streams: dict[int, bytearray] = {}
    for write in writes:
        streams.setdefault(write.handle, bytearray()).extend(write.payload)
    return {handle: bytes(stream) for handle, stream in streams.items()}


def same_output_streams(
    oracle: Iterable[OutputAccepted], candidate: Iterable[OutputAccepted]
) -> bool:
    """Compare declared output streams; split/interleave is diagnostic only."""
    return output_stream_bytes(oracle) == output_stream_bytes(candidate)
