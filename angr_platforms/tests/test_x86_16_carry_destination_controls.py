"""Exact byte extraction and captured carry-result lane controls."""
from dataclasses import replace

import pytest
from angr_platforms.X86_16.alias.carry_borrow_destinations import _value_reaches_result_lane
from angr_platforms.X86_16.alias.domains import register_domain_for_name
from angr_platforms.X86_16.ir import IRInstr, IRValue, MemSpace
from angr_platforms.X86_16.ir.core import IRActiveUnary8616


def _case():
    expected = IRValue(MemSpace.REG, name="ax", version=1, size=2)
    captured = IRValue(MemSpace.TMP, source_tmp=4, size=2)
    instructions = (IRInstr("MOV", captured, (expected,), size=2),)
    value = IRValue(MemSpace.TMP, size=1, active_unary=IRActiveUnary8616("Iop_16to8", captured, 8))
    return expected, captured, instructions, value


def _matches(expected, instructions, value, shift=0):
    return _value_reaches_result_lane(instructions, len(instructions), value, expected, register_domain_for_name("ax"), shift)


def test_low_byte_extraction_keeps_exact_result_lane():
    expected, _, instructions, value = _case()
    assert _matches(expected, instructions, value)
    assert not _matches(expected, instructions, value, 8)


@pytest.mark.parametrize("corruption", ["pin", "op", "width", "missing", "decoration", "capture_width", "offset", "fake_register"] )
def test_invalid_extraction_cannot_bind_result_lane(corruption):
    expected, captured, instructions, value = _case()
    if corruption == "pin":
        value = replace(value, source_tmp=4)
    elif corruption == "op":
        value = replace(value, active_unary=replace(value.active_unary, op="Iop_Not8"))
    elif corruption == "width":
        value = replace(value, size=2)
    elif corruption == "missing":
        value = replace(value, active_unary=replace(value.active_unary, operand=replace(captured, source_tmp=99)))
    elif corruption == "decoration":
        value = replace(captured, expr=("Iop_Not16",))
    elif corruption == "capture_width":
        value = replace(captured, size=4)
    elif corruption == "offset":
        value = replace(captured, offset=1)
    else:
        value = replace(expected, source_tmp=99)
    assert not _matches(expected, instructions, value)
