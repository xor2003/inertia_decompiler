"""Guarded boundary capture shares the replay execution loop and its guards.

The ``capture`` APIs run the same initialization, typed decode,
write/permission, interrupt and invalid-access hooks as ordinary replay on
both tracks; these tests prove positive caller-prefix captures plus typed
refusals for machine input, code writes, unmapped observations, wrong or
unreached boundaries and exhausted budgets, and unchanged replay behavior.
"""

from __future__ import annotations

import hashlib

import tools.dosunit.runtime.flat32_replay as flat32_replay
import tools.dosunit.runtime.real16_replay as real16_replay
from tools.dosunit.runtime.flat32_memory_permissions import DeclaredAccess, DeclaredRegion, MappingOrigin
from tools.dosunit.runtime.flat32_replay_model import (
    MemoryRange,
    ObservationStatus,
    ReplayImage,
    ReplayStatus,
    ReplayVector,
)
from tools.dosunit.runtime.real16_replay_model import (
    CallerFrame,
    FrameKind,
    LinearRange,
    Real16Image,
    Real16ReplayStatus,
    Real16Vector,
    SegOffset,
)
from tools.dosunit.runtime.replay_capture_model import CaptureObservationStatus, CaptureStatus

# --- real16 fixture: caller prefix -> callee boundary ----------------------
SEG = 0x1000
SS = 0x7000
SP = 0x0100
TRAP_OFF = 0x8000
R16_CALLEE = 0x000C
R16_OUT = 0x0300

R16_CODE = bytes.fromhex(
    "b8 34 12"          # 0x00 mov ax,0x1234
    "bb 00 02"          # 0x03 mov bx,0x0200
    "e8 03 00"          # 0x06 call +3 -> 0x0c
    "c3"                # 0x09 ret
    "90 90"             # 0x0a pad
    "31 c0"             # 0x0c callee: xor ax,ax
    "a3 00 03"          # 0x0e mov [0x0300],ax
    "c3"                # 0x11 ret
)

# Parent-flagged defect shape: CPUID sits in the executed caller prefix.
R16_CPUID_CODE = bytes.fromhex(
    "bb 00 02"          # 0x00 mov bx,0x0200
    "b9 04 00"          # 0x03 mov cx,0x0004
    "0f a2"             # 0x06 cpuid (undeclared machine input)
    "e8 03 00"          # 0x08 call +3 -> 0x0e
    "c3"                # 0x0b ret
    "90 90"             # 0x0c pad
    "31 c0"             # 0x0e callee: xor ax,ax
    "a3 00 03"          # 0x10 mov [0x0300],ax
    "c3"                # 0x13 ret
)

R16_WRITE_CODE = bytes.fromhex(
    "c6 06 00 00 90"    # 0x00 mov byte [0x0000],0x90 (into declared code)
    "e8 04 00"          # 0x05 call +4 -> 0x0c
    "c3"                # 0x08 ret
    "90 90 90"          # 0x09 pad
    "31 c0"             # 0x0c callee: xor ax,ax
    "c3"                # 0x0e ret
)


def _r16_image(code: bytes, *, code_size: int | None = None) -> Real16Image:
    """Loaded image with declared code ranges and data bytes at R16_OUT."""
    image = code.ljust(R16_OUT, b"\x00") + b"\x77\x66"
    digest = hashlib.sha256(image).hexdigest()
    return Real16Image(
        ((SEG * 16, image),),
        (LinearRange(SEG * 16, code_size if code_size is not None else len(code)),),
        SEG,
        len(image),
        0,
        digest,
        digest,
        hashlib.sha256(b"").hexdigest(),
    )


def _r16_vector() -> Real16Vector:
    """Near-frame vector with one declared output observation."""
    return Real16Vector(
        registers=(("sp", SP),),
        segments=(("ds", SEG), ("es", SEG), ("ss", SS)),
        frame=CallerFrame(FrameKind.NEAR16, SegOffset(SEG, TRAP_OFF)),
        observations=((SegOffset(SEG, R16_OUT), 2),),
    )


# --- flat32 fixture: caller prefix -> callee boundary ----------------------
F32_BASE = 0x10000
F32_CALLEE = 0x10011
F32_ESP = 0x28000
F32_OUT = 0x30000

F32_CODE = bytes.fromhex(
    "b8 34 12 00 00"      # 0x00 mov eax,0x1234
    "bb 00 00 03 00"      # 0x05 mov ebx,0x30000
    "e8 02 00 00 00"      # 0x0a call +2 -> 0x11
    "c3"                  # 0x0f ret
    "90"                  # 0x10 pad
    "31 c0"               # 0x11 callee: xor eax,eax
    "a3 00 00 03 00"      # 0x13 mov [0x30000],eax
    "c3"                  # 0x18 ret
)

F32_CPUID_CODE = bytes.fromhex(
    "b8 34 12 00 00"      # 0x00 mov eax,0x1234
    "0f a2"               # 0x05 cpuid (undeclared machine input)
    "e8 05 00 00 00"      # 0x07 call +5 -> 0x11
    "c3"                  # 0x0c ret
    "90 90 90 90"         # 0x0d pad
    "31 c0"               # 0x11 callee: xor eax,eax
    "c3"                  # 0x13 ret
)

F32_WRITE_CODE = bytes.fromhex(
    "c6 05 00 00 01 00 90"  # 0x00 mov byte [0x10000],0x90 (protected .text)
    "e8 05 00 00 00"        # 0x07 call +5 -> 0x11
    "c3"                    # 0x0c ret
    "90 90 90 90"           # 0x0d pad
    "31 c0"                 # 0x11 callee: xor eax,eax
    "c3"                    # 0x13 ret
)


def _f32_image(code: bytes) -> ReplayImage:
    """Loaded image; declared executable contract stands in as FILE access."""
    return ReplayImage(((F32_BASE, code),), (MemoryRange(F32_BASE, len(code)),))


def _f32_vector(*, observations: tuple[MemoryRange, ...] | None = None) -> ReplayVector:
    """Vector with declared scratch output cell, patch and observation."""
    return ReplayVector(
        (("esp", F32_ESP),),
        ((F32_OUT, b"\x77\x66\x55\x44"),),
        observations if observations is not None else (MemoryRange(F32_OUT, 4),),
        (DeclaredRegion(F32_OUT, 4, DeclaredAccess.READ | DeclaredAccess.WRITE, MappingOrigin.VECTOR),),
    )


# --- real16 captures --------------------------------------------------------

def test_real16_capture_caller_prefix_reaches_boundary() -> None:
    """Fetch at the callee boundary stops before the callee executes."""
    result = real16_replay.capture(
        _r16_image(R16_CODE), SegOffset(SEG, 0), _r16_vector(), SegOffset(SEG, R16_CALLEE),
        instruction_limit=1000,
    )
    assert result.status is CaptureStatus.CAPTURED
    assert result.execution_status is None
    registers = dict(result.registers)
    assert registers["ax"] == 0x1234 and registers["bx"] == 0x0200
    assert registers["cs"] == SEG and registers["ip"] == R16_CALLEE
    assert registers["ss"] == SS and registers["sp"] == SP - 2
    assert result.fetch_trace == (SEG * 16, SEG * 16 + 3, SEG * 16 + 6, SEG * 16 + R16_CALLEE)
    assert result.instructions == 3
    assert result.trap_linear == SEG * 16 + TRAP_OFF
    # The near call's pushed continuation is the only executed-prefix write.
    assert result.writes == ((SS * 16 + SP - 2, bytes.fromhex("0900")),)
    observation, = result.observations
    assert observation.request == SegOffset(SEG, R16_OUT)
    assert observation.linear == SEG * 16 + R16_OUT
    assert observation.status is CaptureObservationStatus.CAPTURED
    assert observation.data == bytes.fromhex("7766")


def test_real16_capture_refuses_cpuid_in_executed_prefix() -> None:
    """The parent-flagged defect: machine input in the prefix is a typed refusal."""
    result = real16_replay.capture(
        _r16_image(R16_CPUID_CODE), SegOffset(SEG, 0), _r16_vector(), SegOffset(SEG, 0x000E),
        instruction_limit=1000,
    )
    assert result.status is CaptureStatus.EXECUTION_REFUSED
    assert result.execution_status is Real16ReplayStatus.UNSUPPORTED
    assert result.detail == "undeclared_machine_input"
    assert result.fetch_trace == (SEG * 16, SEG * 16 + 3, SEG * 16 + 6)


def test_real16_capture_refuses_code_write() -> None:
    """A prefix store into declared instruction bytes is a typed refusal."""
    result = real16_replay.capture(
        _r16_image(R16_WRITE_CODE), SegOffset(SEG, 0), _r16_vector(), SegOffset(SEG, 0x000C),
        instruction_limit=1000,
    )
    assert result.status is CaptureStatus.EXECUTION_REFUSED
    assert result.execution_status is Real16ReplayStatus.UNSUPPORTED
    assert result.detail == "instruction_memory_write"


def test_real16_capture_returned_before_boundary() -> None:
    """A fetch stream that hits the caller frame first never reaches the boundary."""
    image = _r16_image(bytes.fromhex("c3 90 90 90 90 90 90 90"))
    result = real16_replay.capture(
        image, SegOffset(SEG, 0), _r16_vector(), SegOffset(SEG, 4), instruction_limit=1000,
    )
    assert result.status is CaptureStatus.RETURNED_BEFORE_BOUNDARY
    assert result.execution_status is Real16ReplayStatus.RETURNED
    assert result.fetch_trace == (SEG * 16,)


def test_real16_capture_budget_and_trace_bounds_are_typed() -> None:
    """Exhausted instruction and trace budgets are distinct typed outcomes."""
    image = _r16_image(bytes.fromhex("eb fe") + bytes(14))
    budget = real16_replay.capture(
        image, SegOffset(SEG, 0), _r16_vector(), SegOffset(SEG, 4), instruction_limit=16,
    )
    assert budget.status is CaptureStatus.BUDGET_EXHAUSTED
    assert budget.execution_status is Real16ReplayStatus.BUDGET_EXHAUSTED
    assert len(budget.fetch_trace) == 16
    overflow = real16_replay.capture(
        image, SegOffset(SEG, 0), _r16_vector(), SegOffset(SEG, 4),
        instruction_limit=1000, trace_limit=8,
    )
    assert overflow.status is CaptureStatus.TRACE_OVERFLOW
    assert overflow.execution_status is None
    assert len(overflow.fetch_trace) == 8


def test_real16_capture_refuses_wrong_boundary() -> None:
    """A boundary outside declared code ranges is a typed non-result, not a run."""
    result = real16_replay.capture(
        _r16_image(R16_CODE), SegOffset(SEG, 0), _r16_vector(), SegOffset(SEG, R16_OUT),
        instruction_limit=1000,
    )
    assert result.status is CaptureStatus.BOUNDARY_INVALID
    assert result.execution_status is None
    assert result.fetch_trace == ()


def test_real16_ordinary_replay_unchanged_on_same_fixture() -> None:
    """Replay of the whole fixture still returns through the caller frame."""
    image = _r16_image(R16_CODE)
    vector = _r16_vector()
    result = real16_replay.replay(image, SegOffset(SEG, 0), vector, instruction_limit=1000)
    assert result.status is Real16ReplayStatus.RETURNED
    assert dict(result.registers)["ax"] == 0
    assert result.observations == ((SEG * 16 + R16_OUT, bytes.fromhex("0000")),)
    assert result.writes == (
        (SEG * 16 + R16_OUT, bytes.fromhex("0000")),
        (SS * 16 + SP - 2, bytes.fromhex("0900")),
    )


# --- flat32 captures --------------------------------------------------------

def test_flat32_capture_caller_prefix_reaches_boundary() -> None:
    """Fetch at the callee boundary stops before the callee executes."""
    result = flat32_replay.capture(
        _f32_image(F32_CODE), F32_BASE, _f32_vector(), F32_CALLEE, instruction_limit=1000,
    )
    assert result.status is CaptureStatus.CAPTURED
    assert result.execution_status is None
    registers = dict(result.registers)
    assert registers["eax"] == 0x1234 and registers["ebx"] == F32_OUT
    assert registers["esp"] == F32_ESP - 4 and registers["eip"] == F32_CALLEE
    assert result.fetch_trace == (F32_BASE, F32_BASE + 5, F32_BASE + 0x0A, F32_CALLEE)
    assert result.instructions == 3
    assert result.trap == flat32_replay.RETURN_TRAP
    assert result.writes == ((F32_ESP - 4, bytes.fromhex("0f000100")),)
    observation, = result.observations
    assert observation.status is ObservationStatus.CAPTURED
    assert observation.data == bytes.fromhex("77665544")
    assert observation.origins == (MappingOrigin.VECTOR,)
    assert result.requested_observations == (MemoryRange(F32_OUT, 4),)


def test_flat32_capture_refuses_cpuid_in_executed_prefix() -> None:
    """Machine input in the executed prefix is a typed refusal, not a capture."""
    result = flat32_replay.capture(
        _f32_image(F32_CPUID_CODE), F32_BASE, _f32_vector(), 0x10011, instruction_limit=1000,
    )
    assert result.status is CaptureStatus.EXECUTION_REFUSED
    assert result.execution_status is ReplayStatus.UNSUPPORTED
    assert result.detail == "undeclared_machine_input"
    assert result.fetch_trace == (F32_BASE, F32_BASE + 5)


def test_flat32_capture_refuses_code_write() -> None:
    """A prefix store into a protected executable page faults as a typed refusal."""
    result = flat32_replay.capture(
        _f32_image(F32_WRITE_CODE), F32_BASE, _f32_vector(), 0x10011, instruction_limit=1000,
    )
    assert result.status is CaptureStatus.EXECUTION_REFUSED
    assert result.execution_status is ReplayStatus.FAULTED
    assert result.detail == "write_protected"


def test_flat32_capture_unmapped_observation_is_typed() -> None:
    """An observation without declared mapping is UNMAPPED, never zero-filled data."""
    vector = _f32_vector(observations=(MemoryRange(F32_OUT, 4), MemoryRange(0x50000, 4)))
    result = flat32_replay.capture(
        _f32_image(F32_CODE), F32_BASE, vector, F32_CALLEE, instruction_limit=1000,
    )
    assert result.status is CaptureStatus.CAPTURED
    declared, unmapped = result.observations
    assert declared.status is ObservationStatus.CAPTURED
    assert unmapped.status is ObservationStatus.UNMAPPED
    assert unmapped.data == b"" and unmapped.origins == ()


def test_flat32_capture_returned_before_boundary() -> None:
    """A fetch stream that hits the return trap first never reaches the boundary."""
    image = _f32_image(bytes.fromhex("c3 90 90 90 90 90 90 90"))
    result = flat32_replay.capture(image, F32_BASE, _f32_vector(), F32_BASE + 4, instruction_limit=1000)
    assert result.status is CaptureStatus.RETURNED_BEFORE_BOUNDARY
    assert result.execution_status is ReplayStatus.RETURNED
    assert result.fetch_trace == (F32_BASE,)


def test_flat32_capture_budget_and_trace_bounds_are_typed() -> None:
    """Exhausted instruction and trace budgets are distinct typed outcomes."""
    image = _f32_image(bytes.fromhex("eb fe") + bytes(14))
    budget = flat32_replay.capture(image, F32_BASE, _f32_vector(), F32_BASE + 4, instruction_limit=16)
    assert budget.status is CaptureStatus.BUDGET_EXHAUSTED
    assert budget.execution_status is ReplayStatus.BUDGET_EXHAUSTED
    assert len(budget.fetch_trace) == 16
    overflow = flat32_replay.capture(
        image, F32_BASE, _f32_vector(), F32_BASE + 4, instruction_limit=1000, trace_limit=8,
    )
    assert overflow.status is CaptureStatus.TRACE_OVERFLOW
    assert overflow.execution_status is None
    assert len(overflow.fetch_trace) == 8


def test_flat32_capture_refuses_wrong_boundary() -> None:
    """A boundary outside declared executable scope is a typed non-result."""
    outside = flat32_replay.capture(
        _f32_image(F32_CODE), F32_BASE, _f32_vector(), F32_OUT, instruction_limit=1000,
    )
    assert outside.status is CaptureStatus.BOUNDARY_INVALID
    assert outside.execution_status is None
    trap = flat32_replay.capture(
        _f32_image(F32_CODE), F32_BASE, _f32_vector(), flat32_replay.RETURN_TRAP,
        instruction_limit=1000,
    )
    assert trap.status is CaptureStatus.BOUNDARY_INVALID


def test_flat32_ordinary_replay_unchanged_on_same_fixture() -> None:
    """Replay of the whole fixture still returns through the harness frame."""
    image = _f32_image(F32_CODE)
    vector = _f32_vector()
    result = flat32_replay.replay(image, F32_BASE, vector, instruction_limit=1000)
    assert result.status is ReplayStatus.RETURNED
    assert dict(result.registers)["eax"] == 0
    observation, = result.observations
    assert observation.status is ObservationStatus.CAPTURED
    assert observation.data == bytes(4)
    repeated = flat32_replay.replay(image, F32_BASE, vector, instruction_limit=1000)
    assert result == repeated
    assert flat32_replay.compare_replays(result, repeated).value == "agreed"
