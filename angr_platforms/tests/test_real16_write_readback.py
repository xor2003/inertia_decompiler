"""Final write/observation readback never fabricates unreadable bytes.

A recorded write may straddle a mapped/unmapped boundary (the write hook
sees every touched address, including the half that faulted), and a post-run
snapshot read can fail even after RETURNED/CAPTURED/TERMINATED. These
controls prove all three consumers degrade to typed non-results carrying
cause and range instead of substituting zero bytes or publishing success.
"""

from __future__ import annotations

import pytest
import unicorn
from test_real16_program_replay import environment, mz
from unicorn import UcError
from unicorn.unicorn_py3.unicorn import Uc

from tools.dosunit import real16_mz_load as mz_load
from tools.dosunit import real16_replay as replay_mod
from tools.dosunit import real16_replay_model as model
from tools.dosunit.real16_program_boot import program_from_mz_bytes
from tools.dosunit.real16_program_model import (
    ProgramAgreement,
    ProgramEventKind,
    ProgramObservation,
    ProgramStatus,
    compare_programs,
)
from tools.dosunit.real16_program_replay import replay_program
from tools.dosunit.replay_capture_model import CaptureStatus

CallerFrame = model.CallerFrame
FrameKind = model.FrameKind
LinearRange = model.LinearRange
Real16Agreement = model.Real16Agreement
Real16ReplayPolicy = model.Real16ReplayPolicy
Real16ReplayStatus = model.Real16ReplayStatus
Real16Vector = model.Real16Vector
ReplayEventKind = model.ReplayEventKind
SegOffset = model.SegOffset
A20Policy = model.A20Policy

LOAD = 0x1000  # default load paragraph for fixture images
STACK_SEG = 0x7000
STACK_SP = 0x0100
TRAP_OFF = 0x8000  # near-frame return offset inside the entry CS, outside image bytes


def _mz(image: bytes) -> bytes:
    """Build a minimal MZ executable around load-module bytes."""
    header_size = 0x20
    file_size = header_size + len(image)
    blocks, lastsize = divmod(file_size, 512)
    if lastsize:
        blocks += 1
    header = bytearray(header_size)
    header[0:2] = b"MZ"
    header[0x02:0x04] = lastsize.to_bytes(2, "little")
    header[0x04:0x06] = blocks.to_bytes(2, "little")
    header[0x08:0x0A] = (header_size // 16).to_bytes(2, "little")
    header[0x0C:0x0E] = (0xFFFF).to_bytes(2, "little")
    header[0x0E:0x10] = (0x0080).to_bytes(2, "little")
    header[0x10:0x12] = (0xFFFE).to_bytes(2, "little")
    return bytes(header) + image


def _image(image: bytes, *, code_size: int | None = None) -> model.Real16Image:
    """Load fixture MZ bytes; ``code_size`` scopes declared instruction bytes."""
    base = LOAD * 16
    ranges = (LinearRange(base, code_size),) if code_size is not None else ()
    return mz_load.image_from_mz_bytes(
        _mz(image), load_segment=LOAD, code_ranges=ranges,
    )


def _vector(
    *,
    regs: dict[str, int] | None = None,
    sregs: dict[str, int] | None = None,
    observations: tuple[tuple[SegOffset, int], ...] = (),
) -> Real16Vector:
    """Concrete near-frame vector over explicit segments and registers."""
    base_regs = {"ax": 0, "bx": 0, "cx": 0, "dx": 0, "si": 0, "di": 0,
                 "bp": 0, "sp": STACK_SP, "flags": 0x0002}
    base_regs.update(regs or {})
    base_segs = {"ds": LOAD, "es": LOAD, "ss": STACK_SEG, "fs": 0, "gs": 0}
    base_segs.update(sregs or {})
    return Real16Vector(
        registers=tuple(sorted(base_regs.items())),
        segments=tuple(sorted(base_segs.items())),
        frame=CallerFrame(FrameKind.NEAR16, SegOffset(LOAD, TRAP_OFF)),
        observations=observations,
    )


def _fail_mem_read(monkeypatch: pytest.MonkeyPatch, *targets: int) -> None:
    """Make guest readback refuse reads covering the given linear addresses."""
    original = Uc.mem_read

    def patched(self: Uc, address: int, size: int) -> bytes:
        if any(address <= target < address + size for target in targets):
            raise UcError(unicorn.UC_ERR_READ_UNMAPPED)
        return original(self, address, size)

    monkeypatch.setattr(Uc, "mem_read", patched)


def _covered(result_writes: tuple[tuple[int, bytes], ...], address: int) -> bool:
    """Whether any emitted write group claims bytes for ``address``."""
    return any(start <= address < start + len(data) for start, data in result_writes)


def test_straddled_write_readback_never_fabricates_bytes() -> None:
    """A write crossing into unmapped space keeps real bytes, types the gap."""
    image = _image(bytes.fromhex("89 07 c3"), code_size=3)  # mov [bx],ax; ret
    vector = _vector(regs={"ax": 0xBEEF, "bx": 0x000F}, sregs={"ds": 0xFFFF})
    result = replay_mod.replay(
        image, SegOffset(LOAD, 0), vector,
        policy=Real16ReplayPolicy(a20=A20Policy.DISABLED_REFUSE),
    )
    # DS:BX = FFFF:000F writes 0xFFFFF (mapped) and 0x100000 (unmapped).
    assert result.status is Real16ReplayStatus.UNSUPPORTED
    assert result.detail == "a20_wrap_access"
    # The mapped half reads back as the real committed byte; the unmapped
    # half is a typed gap, never a substituted zero.
    assert result.writes == ((0xFFFFF, b"\xef"),)
    assert not _covered(result.writes, 0x100000)
    gap_event = result.events[-1]
    assert gap_event.kind is ReplayEventKind.UNMAPPED_ACCESS
    assert gap_event.address == 0x100000
    assert "UC_ERR_READ_UNMAPPED" in gap_event.detail
    assert "0x100000" in gap_event.detail


def test_returned_run_with_failed_readback_refuses_success(monkeypatch) -> None:
    """A RETURNED run cannot publish a complete outcome on a partial snapshot."""
    image = _image(bytes.fromhex("a3 00 03 c3"), code_size=4)  # mov [0x0300],ax; ret
    target = LOAD * 16 + 0x300
    _fail_mem_read(monkeypatch, target)
    result = replay_mod.replay(image, SegOffset(LOAD, 0), _vector(regs={"ax": 0xBEEF}))
    assert result.status is Real16ReplayStatus.UNSUPPORTED
    assert result.status is not Real16ReplayStatus.RETURNED
    assert "snapshot_unreadable" in result.detail
    assert hex(target) in result.detail
    # Only genuinely read bytes are emitted; the refused address is a typed gap.
    assert result.writes == ((target + 1, b"\xbe"),)
    assert not _covered(result.writes, target)
    assert result.events[-1].kind is ReplayEventKind.UNMAPPED_ACCESS
    assert result.events[-1].address == target
    assert replay_mod.compare_replays(result, result) is Real16Agreement.INCOMPLETE


def test_declared_observation_read_failure_refuses_replay(monkeypatch) -> None:
    """A failed declared-observation read after return is not silent evidence."""
    image = _image(bytes.fromhex("c3"))
    target = LOAD * 16 + 0x400
    _fail_mem_read(monkeypatch, target)
    result = replay_mod.replay(
        image, SegOffset(LOAD, 0),
        _vector(observations=((SegOffset(LOAD, 0x400), 2),)),
    )
    assert result.status is Real16ReplayStatus.UNSUPPORTED
    assert "snapshot_unreadable" in result.detail
    assert hex(target) in result.detail
    assert result.observations == ()
    assert result.events[-1].kind is ReplayEventKind.UNMAPPED_ACCESS
    assert result.events[-1].address == target


def test_capture_reached_boundary_with_failed_readback_refuses(monkeypatch) -> None:
    """A reached boundary cannot outrank a refused final write snapshot."""
    image = _image(bytes.fromhex("e8 01 00 90 c3"))  # call +1 -> offset 4 (boundary)
    pushed = STACK_SEG * 16 + STACK_SP - 2
    _fail_mem_read(monkeypatch, pushed)
    result = replay_mod.capture(
        image, SegOffset(LOAD, 0), _vector(), SegOffset(LOAD, 4), instruction_limit=1000,
    )
    assert result.status is not CaptureStatus.CAPTURED
    assert result.status is CaptureStatus.EXECUTION_REFUSED
    assert result.execution_status is Real16ReplayStatus.UNSUPPORTED
    assert "snapshot_unreadable" in result.detail
    assert hex(pushed) in result.detail
    # The reached-boundary trace evidence itself is real and retained.
    assert result.fetch_trace == (LOAD * 16, LOAD * 16 + 4)
    assert not _covered(result.writes, pushed)
    assert result.events[-1].kind is ReplayEventKind.UNMAPPED_ACCESS
    assert result.events[-1].address == pushed


def test_program_termination_with_failed_readback_refuses(monkeypatch) -> None:
    """A TERMINATED program cannot publish declared outputs it never read."""
    # push cs; pop ds; mov byte [0100],4; mov ax,4c07h; int 21h -> writes 0x10200.
    code = bytes.fromhex("0e1fc606000104b8074ccd21")
    boot = program_from_mz_bytes(mz(code), environment())
    observations = (ProgramObservation("buffer", LinearRange(0x10200, 1)),)
    _fail_mem_read(monkeypatch, 0x10200)
    result = replay_program(boot, observations=observations)
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.status is not ProgramStatus.TERMINATED
    assert "snapshot_unreadable" in result.detail
    assert "0x10200" in result.detail
    assert result.observations == ()
    assert not _covered(result.writes, 0x10200)
    assert result.events[-1].kind is ProgramEventKind.UNDECLARED_ACCESS
    assert result.events[-1].address == 0x10200
    assert compare_programs(result, result) is ProgramAgreement.INCOMPLETE


def test_unexpected_readback_error_propagates(monkeypatch) -> None:
    """Only named backend readback errors are typed; anything else raises."""
    image = _image(bytes.fromhex("a3 00 03 c3"), code_size=4)
    original = Uc.mem_read
    target = LOAD * 16 + 0x300

    def broken(self: Uc, address: int, size: int) -> bytes:
        if address <= target < address + size:
            raise RuntimeError("readback backend lost")
        return original(self, address, size)

    monkeypatch.setattr(Uc, "mem_read", broken)
    with pytest.raises(RuntimeError, match="readback backend lost"):
        replay_mod.replay(image, SegOffset(LOAD, 0), _vector(regs={"ax": 0xBEEF}))


def test_readable_writes_and_capture_snapshot_stay_exact() -> None:
    """Known readable bytes still coalesce exactly across replay and capture."""
    image = _image(bytes.fromhex("a3 00 03 c3"), code_size=4)
    result = replay_mod.replay(image, SegOffset(LOAD, 0), _vector(regs={"ax": 0xBEEF}))
    assert result.status is Real16ReplayStatus.RETURNED
    assert result.writes == ((LOAD * 16 + 0x300, bytes.fromhex("efbe")),)

    capture = replay_mod.capture(
        _image(bytes.fromhex("e8 01 00 90 c3")), SegOffset(LOAD, 0),
        _vector(), SegOffset(LOAD, 4), instruction_limit=1000,
    )
    assert capture.status is CaptureStatus.CAPTURED
    assert capture.execution_status is None
    pushed = STACK_SEG * 16 + STACK_SP - 2
    assert capture.writes == ((pushed, bytes.fromhex("0300")),)
