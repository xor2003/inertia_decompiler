"""Tests for typed multi-register return value construction."""

from __future__ import annotations

from angr import ailment

from inertia.structuring.wide_return_values import combine_word_return_sources_8616


def test_combines_constant_dx_ax_words_before_codegen() -> None:
    atoms = iter(range(10, 20))
    high = ailment.Expr.Const(1, 0x1234, 16)
    low = ailment.Expr.Const(2, 0x5678, 16)

    result = combine_word_return_sources_8616(high, low, next_atom=lambda: next(atoms), ins_addr=0x1004)

    assert isinstance(result, ailment.Expr.Const)
    assert result.bits == 32
    assert result.value == 0x12345678


def test_preserves_nonconstant_dx_ax_as_wide_shift_or() -> None:
    atoms = iter(range(3, 12))
    high = ailment.Expr.Register(1, 6, 16, reg_name="dx")
    low = ailment.Expr.Register(2, 0, 16, reg_name="ax")

    result = combine_word_return_sources_8616(high, low, next_atom=lambda: next(atoms), ins_addr=0x1004)

    assert isinstance(result, ailment.Expr.BinaryOp)
    assert result.op == "Or"
    shifted_high, low_wide = result.operands
    assert isinstance(shifted_high, ailment.Expr.BinaryOp)
    assert shifted_high.op == "Shl"
    high_wide, shift = shifted_high.operands
    assert isinstance(high_wide, ailment.Expr.Convert)
    assert high_wide.operand == high
    assert isinstance(shift, ailment.Expr.Const)
    assert shift.value == 16
    assert isinstance(low_wide, ailment.Expr.Convert)
    assert low_wide.operand == low


def test_consumes_materialized_wide_stack_owner_without_rebuilding_it() -> None:
    high = ailment.Expr.Load(1, ailment.Expr.Const(2, 6, 16), 2, "Iend_LE")
    low = ailment.Expr.Load(3, ailment.Expr.Const(4, 4, 16), 2, "Iend_LE")
    wide_owner = ailment.Expr.Load(5, ailment.Expr.Const(6, 4, 16), 4, "Iend_LE")

    result = combine_word_return_sources_8616(
        high,
        low,
        next_atom=lambda: 7,
        ins_addr=0x1004,
        wide_stack_owner=wide_owner,
    )

    assert result == wide_owner
