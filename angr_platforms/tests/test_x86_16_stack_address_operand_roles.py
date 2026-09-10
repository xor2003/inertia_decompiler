"""Numeric address calculations must not borrow stack-relative pointer proof."""

import pytest
from angr import ailment
from angr.ailment.expression import VirtualVariable, VirtualVariableCategory
from angr_platforms.X86_16.stack_compat import StackValueUse8616, classify_stack_value_use_8616


def _value() -> VirtualVariable:
    return VirtualVariable(1, 7, 16, VirtualVariableCategory.REGISTER, oident=16)


@pytest.mark.parametrize("operation", ["Mul", "Div", "Shl", "Shr", "And", "Xor", "CmpEQ"])
@pytest.mark.parametrize("access", ["load", "store"])
def test_nonlinear_stack_operand_is_numeric(operation: str, access: str) -> None:
    value = _value()
    constant = ailment.Expr.Const(2, 2, 16)
    address = ailment.Expr.BinaryOp(3, operation, (value, constant), False, bits=16)
    statement = (
        ailment.Stmt.Return(5, [ailment.Expr.Load(4, address, 2, "Iend_LE")])
        if access == "load" else ailment.Stmt.Store(5, address, constant, 2, "Iend_LE")
    )
    assert classify_stack_value_use_8616(statement, 7) is StackValueUse8616.VALUE


@pytest.mark.parametrize("operation", ["Add", "Sub"])
def test_repeated_stack_base_is_not_one_address_base(operation: str) -> None:
    address = ailment.Expr.BinaryOp(3, operation, (_value(), _value()), False, bits=16)
    statement = ailment.Stmt.Return(5, [ailment.Expr.Load(4, address, 2, "Iend_LE")])
    assert classify_stack_value_use_8616(statement, 7) is StackValueUse8616.VALUE


def test_subtractive_stack_operand_is_numeric() -> None:
    address = ailment.Expr.BinaryOp(3, "Sub", (ailment.Expr.Const(2, 0x200, 16), _value()), False, bits=16)
    statement = ailment.Stmt.Return(5, [ailment.Expr.Load(4, address, 2, "Iend_LE")])
    assert classify_stack_value_use_8616(statement, 7) is StackValueUse8616.VALUE


@pytest.mark.parametrize("operation", ["Add", "Sub"])
def test_affine_stack_address_keeps_positive_base(operation: str) -> None:
    address = ailment.Expr.BinaryOp(3, operation, (_value(), ailment.Expr.Const(2, 2, 16)), False, bits=16)
    statement = ailment.Stmt.Return(5, [ailment.Expr.Load(4, address, 2, "Iend_LE")])
    assert classify_stack_value_use_8616(statement, 7) is StackValueUse8616.ADDRESS_ONLY


def test_separate_memory_addresses_do_not_count_as_duplicate_bases() -> None:
    statement = ailment.Stmt.Store(5, _value(), ailment.Expr.Load(4, _value(), 2, "Iend_LE"), 2, "Iend_LE")
    assert classify_stack_value_use_8616(statement, 7) is StackValueUse8616.ADDRESS_ONLY


def test_segment_arithmetic_does_not_make_stack_offset_numeric() -> None:
    segment = VirtualVariable(8, 9, 16, VirtualVariableCategory.REGISTER, oident=50)
    segment_base = ailment.Expr.BinaryOp(3, "Shl", (segment, ailment.Expr.Const(2, 4, 16)), False, bits=32)
    address = ailment.Expr.BinaryOp(4, "Add", (segment_base, ailment.Expr.Convert(6, 16, 32, False, _value())), False, bits=32)
    statement = ailment.Stmt.Return(7, [ailment.Expr.Load(5, address, 2, "Iend_LE")])
    assert classify_stack_value_use_8616(statement, 7) is StackValueUse8616.ADDRESS_ONLY
    assert classify_stack_value_use_8616(statement, 9) is StackValueUse8616.VALUE
