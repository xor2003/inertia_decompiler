"""Typed scalar register-effect classification controls.

Layer: IR regression tests.
Responsibility: pin actual custom-emitter comparison spellings, exact widths,
control-pointer clobbers and the separation of effect closure from value proof.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from inertia.ir.core import IRAddress, IRCondition, IRInstr, IRValue, MemSpace
from inertia.ir.scalar_instruction_effects import (
    ScalarInstructionClobber8616 as Clobber,
)
from inertia.ir.scalar_instruction_effects import (
    ScalarInstructionEffectKind8616 as Kind,
)
from inertia.ir.scalar_instruction_effects import scalar_instruction_effect_8616 as _effect
from pyvex.lifting.util.vex_helper import make_format_op_generator
from tests.fixtures.entry_stack_byte_test_support import ENTRY_8616, _const, _mov, _reg, _tmp


def _binop(op: str, dst: IRValue, left: IRValue, right: IRValue, size: int) -> IRInstr:
    return IRInstr(op=op, dst=dst, args=(left, right), size=size, addr=ENTRY_8616)


def _compare(op: str, width: int) -> IRInstr:
    """A pure comparison of two same-width operands producing a 1-byte dst."""
    return _binop(
        op, _tmp(7, 1),
        _const(7, width), _const(3, width), size=1,
    )


def _cjmp(addr: int = 0x105D1) -> IRInstr:
    cond = IRCondition(op="eq", args=(_const(1, 1),))
    return IRInstr(op="CJMP", dst=None, args=(cond, _const(addr)), size=0,
                   addr=addr)


def _emitted_comparison_op(relation: str, bits: int, signedness: str = "") -> str:
    """Derive the op spelling through the emitter's own ``mkcmpop`` format path."""
    fmt = f"Iop_Cmp{relation}{{arg_t[0]}}{signedness}"
    return make_format_op_generator(fmt)((f"Ity_I{bits}",))


@pytest.mark.parametrize("bits", [8, 16, 32, 64])
@pytest.mark.parametrize("relation", ["LT", "LE", "GT", "GE"])
@pytest.mark.parametrize("signedness", ["S", "U"])
def test_emitted_ordered_comparisons_close(bits: int, relation: str, signedness: str) -> None:
    """The custom emitter produces width-then-sign ordered comparisons."""
    op = _emitted_comparison_op(relation, bits, signedness)
    assert op == f"Iop_Cmp{relation}{bits}{signedness}"
    effect = _effect(_compare(op, bits // 8))
    assert effect.kind is Kind.CLOSED_DESTINATION
    assert effect.clobber is Clobber.NONE


@pytest.mark.parametrize("bits", [1, 8, 16, 32, 64])
@pytest.mark.parametrize("relation", ["EQ", "NE"])
def test_equality_comparison_spellings_close(bits: int, relation: str) -> None:
    """Equality comparisons are emitted at all widths without signedness."""
    op = _emitted_comparison_op(relation, bits)
    assert op == f"Iop_Cmp{relation}{bits}"
    effect = _effect(_compare(op, max(1, bits // 8)))
    assert effect.kind is Kind.CLOSED_DESTINATION


def test_one_bit_comparison_register_destination_clobbers_only_it() -> None:
    """A REG predicate destination reports exactly that register clobber."""
    effect = _effect(_binop(
        "Iop_CmpEQ1", _reg("al", 1), _const(7, 1), _const(3, 1), size=1,
    ))
    assert effect.kind is Kind.CLOSED_DESTINATION
    assert effect.clobber is Clobber.DATA_REGISTER


@pytest.mark.parametrize("operand_bytes", [2, 4])
@pytest.mark.parametrize("op", ["Iop_CmpEQ1", "Iop_CmpNE1"])
def test_one_bit_comparison_rejects_wider_operands(op: str, operand_bytes: int) -> None:
    """A Cmp*1 spelling whose operands exceed one byte refuses."""
    assert _effect(_compare(op, operand_bytes)).kind is Kind.UNKNOWN


def test_one_bit_comparison_rejects_wide_destination() -> None:
    """A 2-byte predicate destination contradicts the one-byte IR shape."""
    instruction = _binop(
        "Iop_CmpEQ1", _tmp(7, 2), _const(7, 1), _const(3, 1), size=2,
    )
    assert _effect(instruction).kind is Kind.UNKNOWN


def test_one_bit_comparison_recomputes_on_mutated_shape() -> None:
    """Effects re-derive per instruction; decorated or widened shapes refuse."""
    instruction = _compare("Iop_CmpEQ1", 1)
    assert _effect(instruction).kind is Kind.CLOSED_DESTINATION
    decorated = replace(instruction, dst=replace(instruction.dst, expr=("Iop_8to1",)))
    assert _effect(decorated).kind is Kind.UNKNOWN
    wider = replace(instruction, args=(_const(7, 2), _const(3, 2)))
    assert _effect(wider).kind is Kind.UNKNOWN


@pytest.mark.parametrize("op", [
    "Iop_CmpLTU16",
    "Iop_CmpLTS16",
    "Iop_CmpLEU32",
    "Iop_CmpGES8",
    "Iop_CmpEQ16U",
    "Iop_CmpGT16",
    "Iop_CmpLT",
    "Iop_Cmp24U",
    "Iop_CmpEQ128",
    "Iop_CmpLT128U",
    "Iop_CmpEQ1S",
    "Iop_CmpEQ1U",
    "Iop_CmpNE1S",
    "Iop_CmpLT1U",
    "Iop_CmpGE1S",
    "Iop_CmpEQ0",
    "Iop_CmpEQ",
])
def test_misspelled_comparisons_refuse(op: str) -> None:
    """A spelling outside the emitter's format is not a closed opcode."""
    width = 16 if op in {"Iop_CmpEQ128", "Iop_CmpLT128U"} else 2
    assert _effect(_compare(op, width)).kind is Kind.UNKNOWN


def test_comparison_operand_width_must_match_spelling() -> None:
    """A registered Cmp32 spelling cannot close 2-byte operands."""
    instruction = _binop(
        "Iop_CmpLT32U", _tmp(7, 1),
        _reg("ax"), _reg("bx"), size=1,
    )
    assert _effect(instruction).kind is Kind.UNKNOWN


def test_comparison_destination_is_one_byte() -> None:
    """A 2-byte predicate destination contradicts the one-byte IR shape."""
    instruction = _binop(
        "Iop_CmpEQ16", _tmp(7, 2),
        _reg("ax"), _reg("bx"), size=2,
    )
    assert _effect(instruction).kind is Kind.UNKNOWN


def test_binary_widths_agree_with_operator() -> None:
    """A registered op closes only when instruction, dst, and operands agree."""
    good = _binop("Iop_Add16", _tmp(9), _reg("ax"), _const(1), size=2)
    effect = _effect(good)
    assert effect.kind is Kind.CLOSED_DESTINATION
    assert effect.clobber is Clobber.NONE

    wide_dst = IRInstr(
        "Iop_Add16", IRValue(MemSpace.REG, name="ecx", size=4),
        (_const(1), _const(2)), size=4,
    )
    assert _effect(wide_dst).kind is Kind.UNKNOWN

    narrow_operands = _binop("Iop_Add16", _tmp(9), _reg("al", 1), _const(1, 1), size=2)
    assert _effect(narrow_operands).kind is Kind.UNKNOWN


def test_shift_count_width_is_independent() -> None:
    """Shifts keep a data-width left operand and an independent count width."""
    for count_size in (1, 2, 4):
        instruction = _binop(
            "Iop_Shl16", _tmp(5), _reg("ax"), _const(8, count_size), size=2,
        )
        assert _effect(instruction).kind is Kind.CLOSED_DESTINATION
    bad_data = _binop("Iop_Shr16", _tmp(5), _reg("al", 1), _const(1, 1), size=2)
    assert _effect(bad_data).kind is Kind.UNKNOWN


def test_mov_load_close_regardless_of_source_decoration() -> None:
    """Effect closure is not value equality: decorated sources still only read."""
    decorated = _reg("ax", offset=0, expr=("Iop_8Uto16",), source_tmp=3)
    assert _effect(_mov(_reg("bx"), decorated)).kind is Kind.CLOSED_DESTINATION
    displaced = IRValue(MemSpace.REG, name="ax", offset=1, size=2)
    assert _effect(_mov(_reg("bx"), displaced)).kind is Kind.CLOSED_DESTINATION
    load = IRInstr(
        op="LOAD", dst=_reg("bx"), size=2,
        args=(IRAddress(space=MemSpace.DS, offset=4, size=2),),
    )
    effect = _effect(load)
    assert effect.kind is Kind.CLOSED_DESTINATION
    assert effect.clobber is Clobber.DATA_REGISTER


@pytest.mark.parametrize("dst,size", [
    (IRValue(MemSpace.REG, size=2), 2),                             # unnamed register
    (IRValue(MemSpace.TMP, name="t9", size=2), 2),                  # tmp sans producer
    (IRValue(MemSpace.REG, name="ax", size=2, const=7), 2),         # literal on a write
    (IRValue(MemSpace.REG, name="ax", size=2, expr=("op",)), 2),    # decorated dst
    (IRValue(MemSpace.REG, name="cx", size=2, source_tmp=99), 2),   # capture identity on REG
    (IRValue(MemSpace.REG, name="cx", size=0), 0),                  # nonpositive width
])
def test_contradictory_destination_stays_unknown(dst: IRValue, size: int) -> None:
    """Conflicting destination fields never manufacture a closed effect."""
    instruction = IRInstr(op="MOV", dst=dst, args=(_reg("bx"),), size=size)
    assert _effect(instruction).kind is Kind.UNKNOWN


def test_cjmp_writes_ip_not_nothing() -> None:
    """A proven control transfer clobbers IP; it is never "no register write"."""
    effect = _effect(_cjmp())
    assert effect.kind is Kind.INSTRUCTION_POINTER_WRITE
    assert effect.clobber is Clobber.INSTRUCTION_POINTER


def test_direct_jmp_has_exact_ip_effect_and_target() -> None:
    """A literal unconditional transfer is closed, not a hidden memory effect."""
    effect = _effect(IRInstr("JMP", None, (_const(0x1234),), size=0))
    assert effect.kind is Kind.INSTRUCTION_POINTER_WRITE
    assert effect.clobber is Clobber.INSTRUCTION_POINTER
    assert effect.control_target == 0x1234


@pytest.mark.parametrize("instruction", (
    IRInstr("JMP", _reg("ax"), (_const(0x1234),)),
    IRInstr("JMP", None, (_reg("ax"),)),
    IRInstr("JMP", None, ()),
    IRInstr("JMP", None, (_const(0x1234), _const(0))),
    IRInstr("JMP", None, (_const(0x1234),), size=2),
    IRInstr("JMP", None, (IRValue(MemSpace.CONST, const=True, size=2),)),
))
def test_unproved_jump_shape_remains_unknown(instruction: IRInstr) -> None:
    """Indirect, conflicting and malformed transfers earn no closed effect."""
    assert _effect(instruction).kind is Kind.UNKNOWN


@pytest.mark.parametrize("operation", ("Iop_Xor1", "Iop_And1", "Iop_Or1"))
def test_boolean_binary_effect_has_one_byte_predicate_storage(operation: str) -> None:
    """VEX one-bit predicates use one byte in IR, without hidden writes."""
    instruction = IRInstr(operation, _tmp(9, 1), (_tmp(1, 1), _tmp(2, 1)), size=1)
    effect = _effect(instruction)
    assert effect.kind is Kind.CLOSED_DESTINATION
    assert effect.clobber is Clobber.NONE
    assert _effect(replace(instruction, size=2)).kind is Kind.UNKNOWN
    assert _effect(replace(instruction, args=(_tmp(1, 2), _tmp(2, 1)))).kind is Kind.UNKNOWN


@pytest.mark.parametrize("instruction", [
    IRInstr(op="CJMP", dst=_reg("ax"),
            args=(IRCondition(op="eq", args=(_const(1, 1),)), _const(4)), size=0),
    IRInstr(op="CJMP", dst=None,
            args=(IRCondition(op="eq", args=(_const(1, 1),)), _reg("ax")), size=0),
    IRInstr(op="CJMP", dst=None, args=(_const(1, 1), _const(4)), size=0),
])
def test_malformed_cjmp_stays_unknown(instruction: IRInstr) -> None:
    """A control transfer without a proven shape refuses."""
    assert _effect(instruction).kind is Kind.UNKNOWN


def test_store_writes_memory_only() -> None:
    """A proven STORE has no register write at all."""
    instruction = IRInstr(
        op="STORE", dst=None, size=2,
        args=(IRAddress(space=MemSpace.DS, offset=4, size=2), _reg("ax")),
    )
    effect = _effect(instruction)
    assert effect.kind is Kind.NO_REGISTER_WRITE
    assert effect.clobber is Clobber.MEMORY
    with_dst = IRInstr(
        op="STORE", dst=_reg("ax"), size=2,
        args=(IRAddress(space=MemSpace.DS, offset=4, size=2), _reg("ax")),
    )
    assert _effect(with_dst).kind is Kind.UNKNOWN


@pytest.mark.parametrize("instruction", [
    IRInstr(op="CALL", dst=_const(0x2000), args=(), size=0),
    IRInstr(op="Iop_Sar16", dst=_tmp(1), args=(_reg("ax"), _const(1)), size=2),
    IRInstr(op="Iop_Add24", dst=_tmp(1), args=(_reg("ax"), _const(1)), size=2),
    IRInstr(op="MOV", dst=_tmp(1), args=(_reg("ax"), _reg("bx")), size=2),
    IRInstr(op="LOAD", dst=_tmp(1), args=(_reg("ax"),), size=2),
])
def test_unmodeled_effects_stay_unknown(instruction: IRInstr) -> None:
    """CALL and unsupported ops prove nothing and keep their clobber unknown."""
    effect = _effect(instruction)
    assert effect.kind is Kind.UNKNOWN
    assert effect.clobber is Clobber.UNKNOWN


def test_effect_serializes_typed_clobber_deterministically() -> None:
    """The effect record carries its typed clobber through serialization."""
    rendered = _effect(_cjmp()).to_dict()
    assert rendered == {
        "kind": "instruction_pointer_write",
        "clobber": "instruction_pointer",
        "detail": "cjmp",
        "control_target": 0x105D1,
    }
    assert rendered == _effect(_cjmp()).to_dict()
