"""Equivalent integer bit patterns produce one relative IR displacement."""

import pytest
from angr_platforms.X86_16.ir.core import IRValue, MemSpace
from angr_platforms.X86_16.ir.vex_import import _binary_value_from_operands_8616
from angr_platforms.X86_16.ir.vex_integer_displacement import canonical_vex_integer_displacement_8616


@pytest.mark.parametrize("size", [1, 2, 4])
@pytest.mark.parametrize("operation,delta", [("Add", -2), ("Sub", 2)])
@pytest.mark.parametrize("offset", [0, 7])
def test_register_displacement_uses_operation_width(size, operation, delta, offset):
    name = {1: "al", 2: "sp", 4: "eax"}[size]
    left = IRValue(MemSpace.REG, name=name, offset=offset, size=size)
    right = IRValue(MemSpace.CONST, const=(1 << (size * 8)) - 2, size=size)
    value = _binary_value_from_operands_8616(f"Iop_{operation}{size * 8}", left, right)
    assert value.space is MemSpace.REG and value.name == name
    assert value.size == size
    assert value.offset == offset + delta
    signed = IRValue(MemSpace.CONST, const=-2, size=size)
    assert value == _binary_value_from_operands_8616(f"Iop_{operation}{size * 8}", left, signed)


def test_accumulated_displacement_wraps_at_its_own_width():
    left = IRValue(MemSpace.REG, name="bp", offset=32767, size=2)
    right = IRValue(MemSpace.CONST, const=1, size=2)
    value = _binary_value_from_operands_8616("Iop_Add16", left, right)
    assert value.offset == -32768


@pytest.mark.parametrize("operation,size", [("Iop_Add32", 2), ("Iop_AddF64", 8), ("Iop_Add16", 0)])
def test_displacement_refuses_unknown_or_mismatched_integer_width(operation, size):
    assert canonical_vex_integer_displacement_8616(operation, 65534, size) == 65534
