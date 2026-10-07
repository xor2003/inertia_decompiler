"""Observation-contract controls for real16 replay execute actual guest bytes.

These tests pin the admitted machine-state surface (all segments, control IP,
masked EFLAGS, 386 high halves), the typed compare contract and the
complete/incomplete outcome boundary.
"""

from __future__ import annotations

import tools.dosunit.runtime.real16_mz_load as mz_load
import tools.dosunit.runtime.real16_replay as replay_mod
import tools.dosunit.runtime.real16_replay_model as model

CallerFrame = model.CallerFrame
FrameKind = model.FrameKind
LinearRange = model.LinearRange
Real16Agreement = model.Real16Agreement
Real16Comparison = model.Real16Comparison
Real16ReplayStatus = model.Real16ReplayStatus
Real16Vector = model.Real16Vector
SegOffset = model.SegOffset
DEFAULT_FLAGS_MASK = model.DEFAULT_FLAGS_MASK
DEFAULT_OBSERVABLES = model.DEFAULT_OBSERVABLES

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


def _image(image: bytes, *, code_size: int | None = None):
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
    flags_mask: int = 0,
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
        flags_mask=flags_mask,
    )


def _run(image, vector=None, **kwargs):
    """Replay one fixture image/vector under the default explicit policy."""
    return replay_mod.replay(image, SegOffset(LOAD, 0), vector or _vector(), **kwargs)


def test_default_observables_cover_full_machine_state():
    """The default contract admits every segment, control IP and masked flags."""
    declared = set(DEFAULT_OBSERVABLES)
    assert declared >= set(model.GENERAL_REGS)
    assert declared >= set(model.HIGH_REGS)
    assert declared >= set(model.SEGMENT_REGS)
    assert {"ip", "eflags"} <= declared
    assert declared >= model.PRESERVED_OBSERVABLES


def test_stc_clc_flag_difference_mismatches_under_default():
    """A defined CF change is observed even when every register is equal."""
    set_carry = _run(_image(bytes.fromhex("f9 c3")))  # stc; ret
    clr_carry = _run(_image(bytes.fromhex("f8 c3")))  # clc; ret
    assert set_carry.status is Real16ReplayStatus.RETURNED
    assert clr_carry.status is Real16ReplayStatus.RETURNED
    assert dict(set_carry.registers)["eflags"] & 1 == 1
    assert dict(clr_carry.registers)["eflags"] & 1 == 0
    assert replay_mod.compare_replays(set_carry, clr_carry) is Real16Agreement.MISMATCHED
    # Undefined-flag honesty: a subset that drops "eflags" narrows the
    # declared observation and may agree.
    observables = tuple(name for name in DEFAULT_OBSERVABLES if name != "eflags")
    assert (
        replay_mod.compare_replays(set_carry, clr_carry, observables=observables)
        is Real16Agreement.AGREED
    )


def test_flags_mask_narrows_only_declared_flag_observations():
    """A declared mask excluding CF is the only way stc/clc may agree."""
    mask_without_cf = DEFAULT_FLAGS_MASK & ~0x1
    vector = _vector(flags_mask=mask_without_cf)
    set_carry = _run(_image(bytes.fromhex("f9 c3")), vector)
    clr_carry = _run(_image(bytes.fromhex("f8 c3")), vector)
    # The effective mask is carried on the typed result contract.
    assert set_carry.flags_mask == mask_without_cf
    comparison = replay_mod.compare_executions(set_carry, clr_carry)
    assert isinstance(comparison, Real16Comparison)
    assert comparison.agreement is Real16Agreement.AGREED
    assert comparison.flags_mask == mask_without_cf
    assert comparison.observables == DEFAULT_OBSERVABLES
    # A mask that still declares CF keeps the difference visible.
    kept = _run(_image(bytes.fromhex("f9 c3")), _vector(flags_mask=0x1))
    dropped = _run(_image(bytes.fromhex("f8 c3")), _vector(flags_mask=0x1))
    assert kept.flags_mask == 0x1
    assert replay_mod.compare_replays(kept, dropped) is Real16Agreement.MISMATCHED


def test_flags_mask_zero_resolves_to_default_defined_mask():
    """Undeclared masks default to the defined real-mode flag set."""
    result = _run(_image(bytes.fromhex("f9 c3")))
    assert result.flags_mask == DEFAULT_FLAGS_MASK
    assert model.effective_flags_mask(0) == DEFAULT_FLAGS_MASK
    assert model.effective_flags_mask(0x1234) == 0x1234


def test_changed_fs_gs_mismatch():
    """FS/GS are admitted observables; divergent segment loads must mismatch."""
    set_fs = _run(_image(bytes.fromhex("b8 34 12 8e e0 c3")))  # mov ax,1234h; mov fs,ax; ret
    set_gs = _run(_image(bytes.fromhex("b8 34 12 8e e8 c3")))  # mov ax,1234h; mov gs,ax; ret
    assert set_fs.status is Real16ReplayStatus.RETURNED
    assert dict(set_fs.registers)["fs"] == 0x1234
    assert dict(set_fs.registers)["gs"] == 0
    assert dict(set_gs.registers)["gs"] == 0x1234
    assert replay_mod.compare_replays(set_fs, set_gs) is Real16Agreement.MISMATCHED


def test_control_coverage_gap_remains_incomplete():
    """Execution outside declared code leaves subsequent behavior unknown."""
    returned = _run(_image(bytes.fromhex("c3")))
    # jmp far 4000h:0000h -> fetch outside mapped/declared space.
    escaped = _run(_image(bytes.fromhex("ea 00 00 00 40 c3"), code_size=6))
    assert returned.status is Real16ReplayStatus.RETURNED
    assert escaped.status is Real16ReplayStatus.CONTROL
    assert replay_mod.compare_replays(returned, escaped) is Real16Agreement.INCOMPLETE


def test_returned_vs_fault_is_known_unequal():
    """A clean return and a divide-error fault cannot be incomplete evidence."""
    returned = _run(_image(bytes.fromhex("c3")))
    fault = _run(_image(bytes.fromhex("31 d2 31 c0 f6 f1 c3")))  # xor; xor; div cl
    assert fault.status is Real16ReplayStatus.FAULTED
    assert replay_mod.compare_replays(returned, fault) is Real16Agreement.MISMATCHED
    assert replay_mod.compare_replays(fault, returned) is Real16Agreement.MISMATCHED


def test_equal_fault_stays_incomplete_distinct_outcomes_mismatch():
    """Identical fault evidence is recorded but never promoted to agreement."""
    div_a = _run(_image(bytes.fromhex("31 d2 31 c0 f6 f1 c3")))
    div_b = _run(_image(bytes.fromhex("31 d2 31 c0 f6 f1 c3")))
    escape = _run(_image(bytes.fromhex("ea 00 00 00 40 c3"), code_size=6))
    assert replay_mod.compare_replays(div_a, div_b) is Real16Agreement.INCOMPLETE
    # A coverage gap cannot establish an outcome different from a CPU fault.
    both = replay_mod.compare_executions(div_a, escape)
    assert both.agreement is Real16Agreement.INCOMPLETE


def test_budget_exhaustion_stays_incomplete():
    """Truncation is never a complete outcome, whatever the other side did."""
    forever = _run(_image(bytes.fromhex("eb fe")), instruction_limit=50)
    returned = _run(_image(bytes.fromhex("c3")))
    fault = _run(_image(bytes.fromhex("31 d2 31 c0 f6 f1 c3")))
    assert forever.status is Real16ReplayStatus.BUDGET_EXHAUSTED
    for other in (returned, fault, forever):
        assert replay_mod.compare_replays(forever, other) is Real16Agreement.INCOMPLETE
        assert replay_mod.compare_replays(other, forever) is Real16Agreement.INCOMPLETE
