"""Entry-prefix snapshot owner: strict producer-evidence obligations.

Cheap binary-free tests for ``EntryStackPointerSnapshots8616`` — the single
owner of entry-SP-relative frame coordinates and typed producer evidence.
Coordinates are canonical byte offsets modulo 2**16; only word-exact producers
whose descriptor a later read re-presents exactly earn a coordinate.
"""

from __future__ import annotations

from angr_platforms.X86_16.alias.entry_stack_pointer_snapshots import (
    EntryStackPointerSnapshots8616,
)
from angr_platforms.X86_16.ir.core import IRInstr, IRValue, MemSpace
from entry_stack_byte_test_support import (
    ENTRY_8616,
    _binop,
    _capture,
    _const,
    _mov,
    _reg,
    _tmp,
)


def _observe_all(engine: EntryStackPointerSnapshots8616, instrs: list[IRInstr]) -> None:
    """Feed instructions to the owner in order."""
    for index, instr in enumerate(instrs):
        engine.observe_entry_instruction(instr, index)


def test_exact_word_capture_earns_coordinate() -> None:
    """A word-exact ``t0 = sp`` capture earns coordinate 0."""
    engine = EntryStackPointerSnapshots8616()
    _observe_all(engine, [_capture()])
    assert engine.offsets[0] == 0
    assert engine.producers[0].dst_size == 2
    assert engine.current_sp == 0


def test_affine_displacement_not_counted_twice() -> None:
    """Re-reading an affine capture yields sp+2 once, never sp+4."""
    engine = EntryStackPointerSnapshots8616()
    _observe_all(engine, [
        _binop("Iop_Add16", 0, _reg("sp"), _const(2)),
        _mov(_tmp(1), _reg("sp", offset=2, expr=("Iop_Add16",), source_tmp=0)),
    ])
    assert engine.offsets[0] == 2
    assert engine.offsets[1] == 2
    assert engine.current_sp == 0


def test_bp_unknown_then_join() -> None:
    """BP starts unknown; a word-exact capture of SP through bp earns a join."""
    engine = EntryStackPointerSnapshots8616()
    assert engine.current_bp is None
    _observe_all(engine, [
        _capture(),
        _mov(_reg("bp"), _reg("sp", source_tmp=0)),
    ])
    assert engine.current_bp == 0
    assert engine.current_sp == 0


def test_redefinition_invalidates_stale_capture() -> None:
    """Redefining a captured tmp erases its earlier coordinate."""
    engine = EntryStackPointerSnapshots8616()
    _observe_all(engine, [
        _capture(),
        _mov(_tmp(0), _const(0x9000)),
    ])
    assert engine.offsets[0] is None


def test_full_parent_clobber_poisons_sp() -> None:
    """A full-parent ``esp`` write poisons the live SP coordinate."""
    engine = EntryStackPointerSnapshots8616()
    _observe_all(engine, [
        _capture(),
        _mov(_reg("esp", 4), _reg("esp", 4)),
    ])
    assert engine.current_sp is None


def test_narrow_clobber_poisons_sp() -> None:
    """A narrow ``sp`` write poisons the live SP coordinate."""
    engine = EntryStackPointerSnapshots8616()
    _observe_all(engine, [
        _capture(),
        _mov(_reg("sp", 1), _reg("sp", 1)),
    ])
    assert engine.current_sp is None


def test_instruction_size_mismatch_on_frame_mov_poisons() -> None:
    """A frame-register MOV whose instruction width disagrees poisons SP."""
    engine = EntryStackPointerSnapshots8616()
    _observe_all(engine, [
        _capture(),
        IRInstr(
            op="MOV", dst=_reg("sp"), args=(_reg("sp", source_tmp=0),),
            size=4, addr=ENTRY_8616,
        ),
    ])
    assert engine.current_sp is None


def test_shifted_destination_on_frame_mov_poisons() -> None:
    """A shifted frame-register destination cannot publish a coordinate."""
    engine = EntryStackPointerSnapshots8616()
    _observe_all(engine, [
        _capture(),
        IRInstr(
            op="MOV",
            dst=IRValue(MemSpace.REG, name="sp", size=2, index_shift=1),
            args=(_reg("sp", source_tmp=0),), size=2, addr=ENTRY_8616,
        ),
    ])
    assert engine.current_sp is None


def test_unknown_source_capture_earns_no_coordinate() -> None:
    """A non-frame value cannot earn a frame coordinate, even with an exact view."""
    engine = EntryStackPointerSnapshots8616()
    _observe_all(engine, [_mov(_tmp(0), _reg("ax"))])
    assert engine.offsets[0] is None
    assert engine.strict_value_coordinate(_reg("ax", source_tmp=0)) is None
    assert engine.current_sp == 0
    # Borrowing a frame-register view also refuses; neither view earns a coordinate.
    assert engine.strict_value_coordinate(_reg("sp", source_tmp=0)) is None


def test_borrowed_view_without_earned_decoration_refuses() -> None:
    """A matching source_tmp without the earned decoration is inconsistent."""
    engine = EntryStackPointerSnapshots8616()
    _observe_all(engine, [
        _capture(),
        _binop("Iop_Sub16", 4, _reg("sp", source_tmp=0), _const(4)),
    ])
    assert engine.offsets[4] == 0xFFFC
    # Re-presentation must carry the producer's exact earned descriptor.
    assert engine.strict_value_coordinate(_reg("sp", source_tmp=4)) is None
    assert (
        engine.strict_value_coordinate(
            _reg("sp", offset=-4, expr=("Iop_Sub16",), source_tmp=4)
        )
        == 0xFFFC
    )


def test_wide_producer_never_borrows_word_origin() -> None:
    """A 4-byte capture earns no word coordinate for later reads."""
    engine = EntryStackPointerSnapshots8616()
    _observe_all(engine, [
        _capture(),
        _mov(_tmp(3, 4), _reg("sp", size=4, expr=("Iop_16Uto32",), source_tmp=0)),
    ])
    assert engine.offsets[3] is None
    # A word-size read borrowing the wide producer's identity still refuses:
    # the recorded destination width is 4, not 2.
    assert engine.strict_value_coordinate(
        _reg("sp", size=2, expr=("Iop_16Uto32",), source_tmp=3)
    ) is None
