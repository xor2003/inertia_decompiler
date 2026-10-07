"""Pending conversion dependencies and captured identity refusal controls."""
from dataclasses import replace

import pytest
from inertia.ir.core import (
    AddressStatus,
    IRActiveUnary8616,
    IRAddress,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)

from inertia.alias.stack_address_escape import StackAddressEscape8616
from tests.alias.test_x86_16_stack_address_escape import _classify, _restored_frame


def _captured(source):
    destination = IRValue(MemSpace.TMP, name="capture", size=2, source_tmp=99, version=0)
    instruction = IRInstr("MOV", destination, (source,), size=2)
    view = replace(source, source_tmp=99)
    return instruction, view


def _convert(value, op, bits):
    return IRValue(MemSpace.TMP, size=(bits + 7) // 8, expr=(op,), active_unary=IRActiveUnary8616(op, value, bits))


def _store(value):
    address = IRAddress(MemSpace.DS, (), 0x200, value.size, AddressStatus.STABLE, SegmentOrigin.PROVEN)
    return IRInstr("STORE", None, (address, value), size=value.size)


@pytest.mark.parametrize("sink", ["store", "register"])
def test_narrow_widen_preserves_derived_address_dependence(sink):
    source = IRValue(MemSpace.REG, name="bp", size=2, version=1)
    capture, view = _captured(source)
    value = _convert(_convert(view, "Iop_16to8", 8), "Iop_8Uto16", 16)
    destination = _store(value) if sink == "store" else IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=2, version=1), (value,), size=2)
    assert _classify((*_restored_frame(), capture, destination)) is StackAddressEscape8616.DERIVED_ADDRESS_ESCAPE


def test_capture_identity_precedes_incoming_register_fallback():
    source = IRValue(MemSpace.REG, name="bp", size=2, version=1)
    capture, _ = _captured(source)
    view = IRValue(MemSpace.REG, name="ax", size=2, version=0, source_tmp=99)
    assert _classify((*_restored_frame(), capture, _store(view))) is StackAddressEscape8616.DERIVED_ADDRESS_ESCAPE


def test_missing_capture_never_falls_back_to_live_frame_register():
    view = IRValue(MemSpace.REG, name="bp", size=2, version=1, source_tmp=99)
    assert _classify((*_restored_frame(), _store(view))) is StackAddressEscape8616.UNKNOWN_REFUSE


@pytest.mark.parametrize("corruption", ["pinned_wrapper", "wrong_op", "wrong_result", "wrong_expr", "missing_operand", "wrong_capture_width"])
def test_corrupt_conversion_never_proves_private_data(corruption):
    source = IRValue(MemSpace.REG, name="ax", size=2, version=0)
    capture, view = _captured(source)
    value = _convert(view, "Iop_16to8", 8)
    if corruption == "pinned_wrapper":
        value = replace(value, source_tmp=99)
    elif corruption == "wrong_op":
        value = replace(value, active_unary=replace(value.active_unary, op="Iop_Not8"))
    elif corruption == "wrong_result":
        value = replace(value, active_unary=replace(value.active_unary, result_bits=16))
    elif corruption == "wrong_expr":
        value = replace(value, expr=("Iop_32to8",))
    elif corruption == "missing_operand":
        value = replace(value, active_unary=replace(value.active_unary, operand=replace(view, source_tmp=777)))
    else:
        value = _convert(replace(view, size=1), "Iop_8Uto16", 16)
    assert _classify((*_restored_frame(), capture, _store(value))) is StackAddressEscape8616.UNKNOWN_REFUSE


@pytest.mark.parametrize("pending", [False, True])
def test_index_dependency_is_not_hidden_by_capture_or_conversion(pending):
    source = IRValue(MemSpace.REG, name="ax", size=2, version=0)
    capture, view = _captured(source)
    if pending:
        view = _convert(view, "Iop_16to8", 8)
    value = replace(view, index=IRValue(MemSpace.REG, name="bp", size=2, version=1))
    assert _classify((*_restored_frame(), capture, _store(value))) is StackAddressEscape8616.DERIVED_ADDRESS_ESCAPE
