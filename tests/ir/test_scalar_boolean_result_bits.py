"""Semantic one-bit result-width evidence over scalar IR.

Layer: IR regression tests.
Responsibility: pin that ``scalar_boolean_result_bits_8616`` grants a 1-bit
result only through the owning comparison and Boolean-binary classifiers'
validated CLOSED_DESTINATION shapes — never through operand values, widths
of other one-byte operations, operator-name substrings, or constant values.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

import pytest

from inertia.ir.core import IRAddress, IRAtom, IRInstr, IRValue, MemSpace
from inertia.ir.scalar_instruction_effects import (
    scalar_boolean_result_bits_8616 as _result_bits,
)
from tests.fixtures.entry_stack_byte_test_support import (
    ENTRY_8616,
    _const,
    _load,
    _mov,
    _reg,
    _tmp,
)

pytestmark = pytest.mark.decompiler


def _binop(op: str, dst: IRValue | None, left: IRAtom, right: IRAtom, size: int) -> IRInstr:
    return IRInstr(op=op, dst=dst, args=(left, right), size=size, addr=ENTRY_8616)


def _compare(op: str, operand_bytes: int) -> IRInstr:
    """A comparison of two same-width operands producing a 1-byte predicate."""
    return _binop(
        op, _tmp(7, 1),
        _const(7, operand_bytes), _const(3, operand_bytes), size=1,
    )


@pytest.mark.parametrize("op,operand_bytes", [
    ("Iop_CmpEQ1", 1),
    ("Iop_CmpNE1", 1),
    ("Iop_CmpEQ8", 1),
    ("Iop_CmpNE16", 2),
    ("Iop_CmpEQ64", 8),
    ("Iop_CmpLT8S", 1),
    ("Iop_CmpLE16U", 2),
    ("Iop_CmpGT32S", 4),
    ("Iop_CmpGE64U", 8),
])
def test_validated_comparisons_report_one_bit(op: str, operand_bytes: int) -> None:
    """Every exact comparison spelling yields a 1-bit predicate result."""
    assert _result_bits(_compare(op, operand_bytes)) == 1


def test_comparison_register_destination_still_one_bit() -> None:
    """A REG predicate destination does not widen the semantic result."""
    instruction = _binop(
        "Iop_CmpEQ16", _reg("al", 1), _reg("ax"), _reg("bx"), size=1,
    )
    assert _result_bits(instruction) == 1


@pytest.mark.parametrize("op", ["Iop_Xor1", "Iop_And1", "Iop_Or1"])
def test_validated_boolean_binops_report_one_bit(op: str) -> None:
    """VEX one-bit Boolean ops report a 1-bit result under the closed shape."""
    instruction = IRInstr(op, _tmp(9, 1), (_tmp(1, 1), _tmp(2, 1)), size=1)
    assert _result_bits(instruction) == 1


@pytest.mark.parametrize("op", [
    "Iop_Add8", "Iop_Sub8", "Iop_And8", "Iop_Or8", "Iop_Xor8",
    "Iop_Add16", "Iop_Shl8", "Iop_Shr16", "Iop_Not1", "Iop_Neg8",
    "Iop_MullS8", "Iop_MullU16",
])
def test_integer_ops_never_report_one_bit(op: str) -> None:
    """Byte arithmetic, wide Booleans, unary and widening ops carry no evidence."""
    instruction = _binop(op, _tmp(5, 1), _tmp(1, 1), _tmp(2, 1), size=1)
    assert _result_bits(instruction) is None


@pytest.mark.parametrize("literal", [0, 1])
def test_mov_of_zero_or_one_literal_is_not_one_bit(literal: int) -> None:
    """A constant value of 0 or 1 cannot manufacture a Boolean result width."""
    assert _result_bits(_mov(_tmp(3, 1), _const(literal, 1))) is None


def test_one_byte_load_is_not_one_bit() -> None:
    """A byte LOAD has storage width evidence only, never predicate semantics."""
    address = IRAddress(space=MemSpace.DS, offset=4, size=1)
    assert _result_bits(_load(4, address, size=1)) is None


@pytest.mark.parametrize("op", [
    "Iop_CmpLTU16", "Iop_CmpLTS16", "Iop_CmpEQ16S", "Iop_CmpEQ16U",
    "Iop_CmpGT16", "Iop_CmpLT", "Iop_CmpEQ", "Iop_CmpEQ128",
    "Iop_Andl1", "Iop_and1", "Iop_Xor01",
])
def test_misspelled_operators_report_no_evidence(op: str) -> None:
    """Spellings outside the emitter's formats are refused, not substring-matched."""
    assert _result_bits(_compare(op, 2)) is None


def test_comparison_operand_width_must_match_spelling() -> None:
    """A Cmp16 spelling with 1-byte or 4-byte operands grants no evidence."""
    assert _result_bits(_compare("Iop_CmpEQ16", 1)) is None
    assert _result_bits(_compare("Iop_CmpEQ16", 4)) is None


def test_comparison_requires_one_byte_predicate_destination() -> None:
    """A wider predicate destination contradicts the validated comparison shape."""
    instruction = _binop(
        "Iop_CmpEQ16", _tmp(7, 2), _reg("ax"), _reg("bx"), size=2,
    )
    assert _result_bits(instruction) is None


@pytest.mark.parametrize("dst", [
    None,
    IRValue(MemSpace.TMP, name="t7", size=1),                        # tmp sans producer
    IRValue(MemSpace.REG, size=1),                                   # unnamed register
    IRValue(MemSpace.REG, name="al", size=1, expr=("Iop_8to1",)),    # decorated dst
    IRValue(MemSpace.CONST, const=0, size=1),                        # literal destination
])
def test_comparison_without_closed_destination_reports_none(dst: IRValue | None) -> None:
    """Contradictory or missing destinations earn no Boolean-width evidence."""
    instruction = IRInstr(
        op="Iop_CmpEQ16", dst=dst, args=(_reg("ax"), _reg("bx")), size=1,
    )
    assert _result_bits(instruction) is None


@pytest.mark.parametrize("mutate", [
    lambda i: replace(i, size=2),                                        # wide instruction
    lambda i: replace(i, args=(_tmp(1, 2), _tmp(2, 1))),                 # wide operand
    lambda i: replace(i, args=(_tmp(1, 1),)),                            # missing operand
    lambda i: replace(i, args=(_tmp(1, 1), _tmp(2, 1), _tmp(3, 1))),     # extra operand
    lambda i: replace(i, dst=None),                                      # no destination
])
def test_malformed_boolean_binop_shapes_report_none(
    mutate: Callable[[IRInstr], IRInstr],
) -> None:
    """A Boolean spelling without its exact typed shape grants no evidence."""
    instruction = IRInstr("Iop_And1", _tmp(9, 1), (_tmp(1, 1), _tmp(2, 1)), size=1)
    assert _result_bits(instruction) == 1
    assert _result_bits(mutate(instruction)) is None


def test_non_scalar_operands_report_none() -> None:
    """Memory addresses or nested computations are not readable scalar reads."""
    address = IRAddress(space=MemSpace.DS, offset=4, size=2)
    instruction = _binop("Iop_CmpEQ16", _tmp(7, 1), address, _reg("ax"), size=1)
    assert _result_bits(instruction) is None


@pytest.mark.parametrize("instruction", [
    IRInstr("CJMP", None, (_const(1, 1), _const(0x1234, 2)), size=0),
    IRInstr("JMP", None, (_const(0x1234, 2),), size=0),
    IRInstr("STORE", None,
            (IRAddress(space=MemSpace.DS, offset=4, size=1), _const(1, 1)), size=1),
    IRInstr("CALL", None, (_const(0x2000, 2),), size=0),
    IRInstr("NOP", None, (), size=0),
    IRInstr("Iop_TotallyUnknown1", _tmp(1, 1), (_tmp(2, 1),), size=1),
])
def test_other_instructions_report_none(instruction: IRInstr) -> None:
    """Control, memory, call, and unknown ops carry no one-bit result evidence."""
    assert _result_bits(instruction) is None


def test_result_is_semantic_not_numeric() -> None:
    """Identical operand values do not change the reported semantic width."""
    assert _result_bits(_compare("Iop_CmpEQ8", 1)) == 1
    folded = IRInstr(
        "Iop_CmpEQ8", _tmp(7, 1), (_const(0, 1), _const(0, 1)), size=1,
    )
    assert _result_bits(folded) == 1


def test_decision_is_deterministic_and_non_mutating() -> None:
    """Repeated queries on one instruction return the same evidence."""
    instruction = _compare("Iop_CmpLT16U", 2)
    assert _result_bits(instruction) == 1
    assert _result_bits(instruction) == 1
