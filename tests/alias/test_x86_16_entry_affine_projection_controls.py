"""Earned scalar affine capture views and malformed proof controls."""
from dataclasses import replace

import pytest
from inertia.ir.core import IRActiveUnary8616, IRValue, MemSpace
from tests.fixtures.entry_stack_byte_test_support import _binop, _capture, _const, _reg

from inertia.alias.entry_stack_pointer_snapshots import EntryStackPointerSnapshots8616


def _engine():
    engine = EntryStackPointerSnapshots8616()
    engine.observe_entry_instruction(_capture(), 0)
    engine.observe_entry_instruction(_binop("Iop_Sub16", 4, _reg("sp", source_tmp=0), _const(4)), 1)
    return engine


def _view():
    return IRValue(MemSpace.TMP, name="arbitrary_display", size=2, expr=("Iop_Sub16",), source_tmp=4)


def test_native_scalar_capture_uses_producer_not_display_name():
    engine = _engine()
    value = _view()
    assert engine.strict_value_coordinate(value) == 0xFFFC
    assert engine.strict_value_coordinate(replace(value, name="another_display")) == 0xFFFC
    assert engine.strict_value_coordinate(_reg("sp", offset=-4, expr=("Iop_Sub16",), source_tmp=4)) == 0xFFFC


@pytest.mark.parametrize("corruption", ["missing", "other_producer", "no_capture", "width", "offset", "wrong_op", "no_expr", "active", "indexed", "version"])
def test_scalar_projection_requires_exact_earned_definition(corruption):
    engine = _engine()
    value = _view()
    if corruption == "missing":
        value = replace(value, source_tmp=99999)
    elif corruption == "other_producer":
        value = replace(value, source_tmp=0)
    elif corruption == "no_capture":
        value = replace(value, source_tmp=None)
    elif corruption == "width":
        value = replace(value, size=4)
    elif corruption == "offset":
        value = replace(value, offset=1)
    elif corruption == "wrong_op":
        value = replace(value, expr=("Iop_Add16",))
    elif corruption == "no_expr":
        value = replace(value, expr=None)
    elif corruption == "active":
        value = replace(value, active_unary=IRActiveUnary8616("Iop_Not16", value, 16))
    elif corruption == "indexed":
        value = replace(value, index=_const(1))
    else:
        value = replace(value, version=1)
    assert engine.strict_value_coordinate(value) is None


@pytest.mark.parametrize("corruption", ["wide_destination", "wide_instruction", "active_left", "missing_left", "unearned_left"])
def test_corrupt_affine_producer_never_earns_scalar_coordinate(corruption):
    engine = EntryStackPointerSnapshots8616()
    engine.observe_entry_instruction(_capture(), 0)
    left = _reg("sp", source_tmp=0)
    instruction = _binop("Iop_Sub16", 4, left, _const(4))
    if corruption == "wide_destination":
        instruction = replace(instruction, dst=replace(instruction.dst, size=4))
    elif corruption == "wide_instruction":
        instruction = replace(instruction, size=4)
    else:
        if corruption == "active_left":
            left = replace(left, active_unary=IRActiveUnary8616("Iop_Not16", left, 16))
        elif corruption == "missing_left":
            left = replace(left, source_tmp=99999)
        else:
            left = replace(left, expr=("Iop_Not16",))
        instruction = replace(instruction, args=(left, _const(4)))
    engine.observe_entry_instruction(instruction, 1)
    assert engine.strict_value_coordinate(_view()) is None
