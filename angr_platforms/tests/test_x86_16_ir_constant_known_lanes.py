"""Proven bit lanes must survive masks, shifts, and partial register writes.

The public constant-flow contract uses typed IR and real instruction bytes.
Only immutable definitions and authoritative register views justify constants.
"""

from __future__ import annotations

import pytest
from angr_platforms.X86_16.ir.constant_flow import IRConstantFlow8616
from angr_platforms.X86_16.ir.core import IRInstr, IRValue, MemSpace
from test_x86_16_segment_stack_restore import _lift_function


def _reg(name: str, size: int) -> IRValue:
    """Return a register view read of the given byte width."""
    return IRValue(MemSpace.REG, name=name, size=size)


def _const(value: int, size: int) -> IRValue:
    """Return an exact integer constant operand."""
    return IRValue(MemSpace.CONST, const=value, size=size)


def _tmp(name: str, size: int, tmp: int, expr: tuple[str, ...] = ()) -> IRValue:
    """Return a temporary definition or read carrying ``source_tmp``."""
    return IRValue(MemSpace.TMP, name=name, size=size, expr=expr, source_tmp=tmp)


def _state(instrs: tuple[IRInstr, ...]) -> IRConstantFlow8616:
    """Observe ``instrs`` in order and return the resulting flow state."""
    state = IRConstantFlow8616()
    for instruction in instrs:
        state.observe(instruction)
    return state


def _composed_ax() -> tuple[IRInstr, ...]:
    """Return ``ax = Or16(And16(ax, 0x00FF), Shl16(0x12, 8))`` typed IR."""
    return (
        IRInstr("Iop_And16", _tmp("mask:ax", 2, 1), (_reg("ax", 2), _const(0x00FF, 2))),
        IRInstr("Iop_Shl16", _tmp("expr:Iop_Shl16", 2, 2), (_const(0x12, 2), _const(8, 1))),
        IRInstr("Iop_Or16", _tmp("expr:Iop_Or16", 2, 3), (
            _tmp("mask:ax", 2, 1, ("Iop_And16",)),
            _tmp("expr:Iop_Shl16", 2, 2, ("Iop_Shl16",)),
        )),
        IRInstr("MOV", _reg("ax", 2), (_tmp("expr:Iop_Or16", 2, 3, ("Iop_Or16",)),)),
    )


def test_masked_or_composition_proves_exact_ah_lane() -> None:
    """A proven AH lane composes from a masked unknown AX and shifted const."""
    state = _state(_composed_ax())
    assert state.constant(_reg("ah", 1)) == 0x12


def test_lane_proof_does_not_claim_wider_views() -> None:
    """Proving AH must not claim AX, AL, or EAX constants."""
    state = _state(_composed_ax())
    assert state.constant(_reg("ax", 2)) is None
    assert state.constant(_reg("al", 1)) is None
    assert state.constant(_reg("eax", 4)) is None


def test_sibling_byte_writes_compose_a_whole_word() -> None:
    """Independent byte writes merge lanes into a fully proven word."""
    state = _state((
        IRInstr("MOV", _reg("ah", 1), (_const(0x12, 1),)),
        IRInstr("MOV", _reg("al", 1), (_const(0x34, 1),)),
    ))
    assert state.constant(_reg("ax", 2)) == 0x1234
    assert state.constant(_reg("ah", 1)) == 0x12
    assert state.constant(_reg("al", 1)) == 0x34


def test_lifted_byte_writes_compose_ax_from_real_ir() -> None:
    """Raw-lifted ``mov ah,0x12; mov al,0x34`` proves the whole AX value."""
    artifact = _lift_function(bytes.fromhex("b4 12 b0 34 c3"))
    state = _state(tuple(i for block in artifact.blocks for i in block.instrs))
    assert state.constant(_reg("ax", 2)) == 0x1234


def test_overwritten_lane_loses_only_its_own_bits() -> None:
    """An unknown AH write clears the AH lane but preserves proven AL."""
    state = _state((
        IRInstr("MOV", _reg("ah", 1), (_const(0x12, 1),)),
        IRInstr("MOV", _reg("al", 1), (_const(0x34, 1),)),
        IRInstr("MOV", _reg("ah", 1), (_reg("bl", 1),)),
    ))
    assert state.constant(_reg("ah", 1)) is None
    assert state.constant(_reg("al", 1)) == 0x34
    assert state.constant(_reg("ax", 2)) is None


def test_poisoned_composed_lane_refuses() -> None:
    """An unknown word write over the composed AX destroys the AH proof."""
    state = _state((
        *_composed_ax(),
        IRInstr("MOV", _reg("ax", 2), (_reg("bx", 2),)),
    ))
    assert state.constant(_reg("ah", 1)) is None


def test_malformed_wider_write_poisons_the_storage_family() -> None:
    """A 16-bit write named AL disagrees with the view; all lanes refuse."""
    state = _state((
        IRInstr("MOV", _reg("ah", 1), (_const(0x4C, 1),)),
        IRInstr("MOV", _reg("al", 2), (_const(0x1234, 2),)),
    ))
    assert state.constant(_reg("ah", 1)) is None
    assert state.constant(_reg("al", 1)) is None
    assert state.constant(_reg("ax", 2)) is None
    assert state.constant(_reg("eax", 4)) is None


def test_mismatched_register_read_width_refuses() -> None:
    """A named view cannot be read at another width by implicit widening."""
    state = _state((IRInstr("MOV", _reg("ax", 2), (_const(0x1234, 2),)),))
    assert state.constant(_reg("ax", 2)) == 0x1234
    assert state.constant(_reg("ax", 4)) is None
    assert state.constant(_reg("ax", 1)) is None


def test_conversion_source_width_must_match_retained_width() -> None:
    """A conversion consumes only a retained definition of source width."""
    state = _state((
        IRInstr("MOV", _tmp("wide", 4, 7), (_const(0x01020304, 4),)),
        IRInstr("MOV", _tmp("word", 2, 8), (_const(0x1234, 2),)),
    ))
    bad = IRValue(MemSpace.TMP, source_tmp=7, size=1, expr=("Iop_16to8",))
    good = IRValue(MemSpace.TMP, source_tmp=8, size=1, expr=("Iop_16to8",))
    assert state.constant(bad) is None
    assert state.constant(good) == 0x34


def test_converted_tmp_reread_is_stable() -> None:
    """A temporary re-decorated with its own conversion stays provable."""
    state = _state((
        IRInstr("MOV", _tmp("raw", 1, 1), (_const(0x80, 1),)),
        IRInstr("MOV", _tmp("wide", 2, 2), (_tmp("raw", 2, 1, ("Iop_8Uto16",)),)),
    ))
    assert state.constant(_tmp("wide", 2, 2, ("Iop_8Uto16",))) == 0x0080


def test_unknown_full_width_write_invalidates_all_views() -> None:
    """An unknown EAX write clears every aliased family view."""
    state = _state((
        IRInstr("MOV", _reg("eax", 4), (_const(0x12345678, 4),)),
        IRInstr("MOV", _reg("eax", 4), (_reg("ecx", 4),)),
    ))
    for name, size in (("eax", 4), ("ax", 2), ("ah", 1), ("al", 1)):
        assert state.constant(_reg(name, size)) is None


def test_call_invalidates_register_lanes_not_temporaries() -> None:
    """CALL forgets register lanes; pre-call temporary constants survive."""
    state = _state((
        IRInstr("MOV", _reg("ah", 1), (_const(0x12, 1),)),
        IRInstr("MOV", _tmp("kept", 1, 5), (_reg("ah", 1),)),
        IRInstr("CALL", None, ()),
    ))
    assert state.constant(_reg("ah", 1)) is None
    assert state.constant(_tmp("kept", 1, 5)) == 0x12


def test_truncation_and_extensions() -> None:
    """Truncation and proven-sign extension transport known bits only."""
    state = _state((
        IRInstr("MOV", _reg("eax", 4), (_const(0x12345678, 4),)),
        IRInstr("MOV", _tmp("b", 1, 1), (_const(0x80, 1),)),
    ))
    low = IRValue(MemSpace.REG, name="eax", size=1, expr=("Iop_32to8",))
    assert state.constant(low) == 0x78
    assert state.constant(_tmp("b", 2, 1, ("Iop_8Uto16",))) == 0x0080
    assert state.constant(_tmp("b", 2, 1, ("Iop_8Sto16",))) == 0xFF80


def test_sign_extension_with_unknown_sign_stays_unknown() -> None:
    """Signed extension of an unknown byte cannot claim its high half."""
    state = _state((
        IRInstr("MOV", _tmp("u", 1, 1), (_reg("bl", 1),)),
    ))
    assert state.constant(_tmp("u", 2, 1, ("Iop_8Sto16",))) is None
    assert state.constant(_tmp("u", 2, 1, ("Iop_8Uto16",))) is None


def test_shift_boundaries_and_out_of_range_refuse() -> None:
    """In-range constant shifts transport lanes; out-of-range refuses."""
    state = _state((
        IRInstr("MOV", _reg("ax", 2), (_const(0x8001, 2),)),
        IRInstr("Iop_Shl16", _tmp("s0", 2, 1), (_reg("ax", 2), _const(0, 1))),
        IRInstr("Iop_Shl16", _tmp("s15", 2, 2), (_reg("ax", 2), _const(15, 1))),
        IRInstr("Iop_Shr16", _tmp("r15", 2, 3), (_reg("ax", 2), _const(15, 1))),
        IRInstr("Iop_Shl16", _tmp("s16", 2, 4), (_reg("ax", 2), _const(16, 1))),
        IRInstr("Iop_Shr16", _tmp("r16", 2, 5), (_reg("ax", 2), _const(16, 1))),
        IRInstr("Iop_Shl16", _tmp("su", 2, 6), (_reg("ax", 2), _reg("cl", 1))),
    ))
    assert state.constant(_tmp("s0", 2, 1)) == 0x8001
    assert state.constant(_tmp("s15", 2, 2)) == 0x8000
    assert state.constant(_tmp("r15", 2, 3)) == 1
    assert state.constant(_tmp("s16", 2, 4)) is None
    assert state.constant(_tmp("r16", 2, 5)) is None
    assert state.constant(_tmp("su", 2, 6)) is None


def test_shift_transports_partial_lanes() -> None:
    """Shr16 of a known-high-byte AX proves the extracted byte."""
    state = _state((
        *_composed_ax(),
        IRInstr("Iop_Shr16", _tmp("hi", 2, 9), (_reg("ax", 2), _const(8, 1))),
    ))
    assert state.constant(_tmp("hi", 2, 9)) == 0x12


@pytest.mark.parametrize(
    "op,operand_const,expected",
    [
        ("Iop_And16", 0x0000, 0x0000),
        ("Iop_And16", 0xFFFF, None),
        ("Iop_Or16", 0xFFFF, 0xFFFF),
        ("Iop_Or16", 0x0000, None),
        ("Iop_Xor16", 0x0000, None),
    ],
)
def test_unknown_boolean_operands(op: str, operand_const: int, expected: int | None) -> None:
    """Each Boolean op publishes only the bits its rule actually proves."""
    state = _state((
        IRInstr(op, _tmp("r", 2, 1), (_reg("bx", 2), _const(operand_const, 2))),
    ))
    assert state.constant(_tmp("r", 2, 1)) == expected


def test_xor_same_identity_clears_even_when_partial() -> None:
    """Xor of one temporary identity is zero on every bit, known or not."""
    state = _state((
        IRInstr("MOV", _tmp("same", 2, 1), (_reg("bx", 2),)),
        IRInstr("Iop_Xor16", _tmp("z", 2, 2), (
            _tmp("same", 2, 1), _tmp("same", 2, 1),
        )),
    ))
    assert state.constant(_tmp("z", 2, 2)) == 0


@pytest.mark.parametrize(
    "and_op,mask,or_op,lane,expected",
    [
        ("Iop_And8", 0x0F, "Iop_Or8", 0x50, 0x5F),
        ("Iop_And16", 0x00FF, "Iop_Or16", 0x1200, 0x12FF),
        ("Iop_And32", 0x00FFFFFF, "Iop_Or32", 0x12000000, 0x12FFFFFF),
        ("Iop_And64", 0x00FFFFFFFFFFFFFF, "Iop_Or64", 0x1200000000000000, 0x12FFFFFFFFFFFFFF),
    ],
)
def test_lane_masks_at_each_width(
    and_op: str, mask: int, or_op: str, lane: int, expected: int,
) -> None:
    """Mask/Or lane composition proves constants at every supported width."""
    size = {8: 1, 16: 2, 32: 4, 64: 8}[int(and_op.removeprefix("Iop_And"))]
    state = _state((
        IRInstr("MOV", _tmp("base", size, 1), (_const(expected & mask, size),)),
        IRInstr(and_op, _tmp("lane", size, 2), (
            _tmp("base", size, 1), _const(mask, size),
        )),
        IRInstr(or_op, _tmp("out", size, 3), (
            _tmp("lane", size, 2), _const(lane, size),
        )),
    ))
    assert state.constant(_tmp("out", size, 3)) == expected


@pytest.mark.parametrize(
    "bits,low_mask,lane_const,shift,expected",
    [
        (8, 0x0F, 0x50, 4, 0x5),
        (16, 0x00FF, 0x1200, 8, 0x12),
        (32, 0x00FFFFFF, 0x12000000, 24, 0x12),
        (64, 0x00FFFFFFFFFFFFFF, 0x1200000000000000, 56, 0x12),
    ],
)
def test_high_lane_proven_under_mask_at_each_width(
    bits: int, low_mask: int, lane_const: int, shift: int, expected: int,
) -> None:
    """A shifted-in constant lane is provable while other lanes stay unknown."""
    size = bits // 8
    state = _state((
        IRInstr("MOV", _tmp("u", size, 1), (
            IRValue(MemSpace.REG, name="bx", size=size),
        )),
        IRInstr(f"Iop_And{bits}", _tmp("low", size, 2), (
            _tmp("u", size, 1), _const(low_mask, size),
        )),
        IRInstr(f"Iop_Or{bits}", _tmp("out", size, 3), (
            _tmp("low", size, 2), _const(lane_const, size),
        )),
        IRInstr(f"Iop_Shr{bits}", _tmp("hi", size, 4), (
            _tmp("out", size, 3), _const(shift, 1),
        )),
    ))
    assert state.constant(_tmp("hi", size, 4)) == expected
    assert state.constant(_tmp("out", size, 3)) is None


def test_equal_labels_do_not_share_identity() -> None:
    """Two temporaries with the same descriptive name stay distinct."""
    state = _state((
        IRInstr("MOV", _tmp("expr:X", 2, 5), (_const(7, 2),)),
        IRInstr("MOV", _tmp("expr:X", 2, 6), (_reg("bx", 2),)),
        IRInstr("Iop_Sub16", _tmp("d", 2, 7), (
            _tmp("expr:X", 2, 5), _tmp("expr:X", 2, 6),
        )),
        IRInstr("Iop_Sub16", _tmp("z", 2, 8), (
            _tmp("expr:X", 2, 5), _tmp("expr:X", 2, 5),
        )),
    ))
    assert state.constant(_tmp("d", 2, 7)) is None
    assert state.constant(_tmp("z", 2, 8)) == 0


def test_aliased_register_views_share_storage() -> None:
    """Writes to wide and narrow views compose through one storage parent."""
    state = _state((
        IRInstr("MOV", _reg("eax", 4), (_const(0x12345678, 4),)),
    ))
    assert state.constant(_reg("ax", 2)) == 0x5678
    assert state.constant(_reg("ah", 1)) == 0x56
    assert state.constant(_reg("al", 1)) == 0x78
    state = _state((
        IRInstr("MOV", _reg("eax", 4), (_const(0x12345678, 4),)),
        IRInstr("MOV", _reg("ax", 2), (_const(0xABCD, 2),)),
    ))
    assert state.constant(_reg("eax", 4)) == 0x1234ABCD
    assert state.constant(_reg("ah", 1)) == 0xAB


def test_exact_constant_arithmetic_unchanged() -> None:
    """Whole-constant arithmetic keeps its previous exact answers."""
    state = _state((
        IRInstr("Iop_Add16", _tmp("a", 2, 1), (_const(3, 2), _const(4, 2))),
        IRInstr("Iop_Sub16", _tmp("s", 2, 2), (_const(9, 2), _const(4, 2))),
        IRInstr("Iop_Add16", _tmp("u", 2, 3), (_const(1, 2), _reg("bx", 2))),
    ))
    assert state.constant(_tmp("a", 2, 1)) == 7
    assert state.constant(_tmp("s", 2, 2)) == 5
    assert state.constant(_tmp("u", 2, 3)) is None
