"""Frame address escape decisions must survive copies and refuse unknowns."""

from dataclasses import replace

import pytest
from angr_platforms.X86_16.alias.stack_address_escape import (
    StackAddressEscape8616,
    classify_function_stack_address_escape_8616,
    classify_stack_address_escape_8616,
)
from angr_platforms.X86_16.alias.stack_memory_ssa import build_x86_16_stack_memory_ssa_alias_artifact
from angr_platforms.X86_16.ir import AddressStatus, IRAddress, IRInstr, IRValue, MemSpace, SegmentOrigin
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa
from angr_platforms.X86_16.ir.stack_extent_evidence import build_stack_extent_evidence_8616
from test_x86_16_stack_extent_evidence import _block, _move
from x86_16_logical_memory_fixtures import lift_ir_artifact


def _classify(instructions):
    block = replace(_block(), instrs=tuple(instructions))
    return classify_stack_address_escape_8616(block, build_stack_extent_evidence_8616(block))


def _restored_frame():
    return (*_block().instrs, _move("bp", 2, "bp", 0))


@pytest.mark.parametrize("register", ("ax", "es"))
def test_outgoing_register_frame_address_refuses_privacy(register):
    instructions = (*_restored_frame(), _move(register, 1, "bp", 1))
    assert _classify(instructions) is StackAddressEscape8616.DERIVED_ADDRESS_ESCAPE


def test_overwritten_general_register_does_not_escape_old_frame_address():
    constant = IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=2, version=2),
                       (IRValue(MemSpace.CONST, const=0, size=2),), size=2)
    instructions = (*_restored_frame(), _move("ax", 1, "bp", 1), constant)
    assert _classify(instructions) is StackAddressEscape8616.NO_DERIVED_ADDRESS_ESCAPE


def test_stored_frame_address_remains_escaped_after_register_overwrite():
    pointer = IRValue(MemSpace.REG, name="ax", size=2, version=1)
    address = IRAddress(MemSpace.DS, (), 0x200, 2, AddressStatus.STABLE, SegmentOrigin.PROVEN)
    store = IRInstr("STORE", None, (address, pointer), size=2)
    instructions = (*_restored_frame(), _move("ax", 1, "bp", 1), store)
    assert _classify(instructions) is StackAddressEscape8616.DERIVED_ADDRESS_ESCAPE


def test_real_bios_body_has_no_derived_address_data_escape():
    body = bytes.fromhex("558bec83ec04c746fc1704c746fe00002bdb8ec3bb1704268c078be55dc3")
    ssa = build_x86_16_function_ssa(lift_ir_artifact(body))
    block = ssa.blocks[0]
    evidence = build_stack_extent_evidence_8616(block)
    assert classify_stack_address_escape_8616(block, evidence) is StackAddressEscape8616.NO_DERIVED_ADDRESS_ESCAPE
    alias = build_x86_16_stack_memory_ssa_alias_artifact(ssa)
    assert alias.frame_address_escape is StackAddressEscape8616.NO_DERIVED_ADDRESS_ESCAPE
    assert alias.to_dict()["frame_address_escape"] == "NO_DERIVED_ADDRESS_ESCAPE"
    without_return = replace(ssa, blocks=(replace(block, instrs=block.instrs[:-1]),))
    assert classify_function_stack_address_escape_8616(without_return, (evidence,)) is StackAddressEscape8616.UNKNOWN_REFUSE


def test_unknown_stored_data_refuses_instead_of_assuming_a_numeric_value():
    address = IRAddress(MemSpace.DS, (), 0x200, 2, AddressStatus.STABLE, SegmentOrigin.PROVEN)
    value = IRValue(MemSpace.TMP, name="missing", size=2, version=0)
    store = IRInstr("STORE", None, (address, value), size=2)
    assert _classify((*_restored_frame(), store)) is StackAddressEscape8616.UNKNOWN_REFUSE


def test_copy_through_a_temporary_keeps_address_escape():
    pointer = IRValue(MemSpace.REG, name="bp", size=2, version=1)
    temporary = IRValue(MemSpace.TMP, name="copied", size=2, version=0, source_tmp=99)
    output = IRValue(MemSpace.REG, name="ax", size=2, version=1)
    instructions = (*_restored_frame(), IRInstr("MOV", temporary, (pointer,), size=2),
                    IRInstr("MOV", output, (temporary,), size=2))
    assert _classify(instructions) is StackAddressEscape8616.DERIVED_ADDRESS_ESCAPE


def test_unrestored_bp_is_an_outgoing_frame_address():
    assert _classify(_block().instrs) is StackAddressEscape8616.DERIVED_ADDRESS_ESCAPE


def test_partial_register_overwrite_cannot_clear_whole_pointer_escape():
    partial = IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=1, version=2),
                      (IRValue(MemSpace.CONST, const=0, size=1),), size=1)
    instructions = (*_restored_frame(), _move("ax", 1, "bp", 1), partial)
    assert _classify(instructions) is StackAddressEscape8616.UNKNOWN_REFUSE


@pytest.mark.parametrize("overwrite_size", (2, 4))
def test_dword_pointer_requires_a_complete_dword_overwrite(overwrite_size):
    pointer = IRValue(MemSpace.REG, name="eax", size=4, version=1)
    copied = IRInstr("MOV", pointer, (IRValue(MemSpace.REG, name="bp", size=2, version=1),), size=4)
    cleared = IRInstr("MOV", replace(pointer, size=overwrite_size, version=2),
                      (IRValue(MemSpace.CONST, const=0, size=overwrite_size),), size=overwrite_size)
    expected = (StackAddressEscape8616.NO_DERIVED_ADDRESS_ESCAPE if overwrite_size == pointer.size
                else StackAddressEscape8616.UNKNOWN_REFUSE)
    assert _classify((*_restored_frame(), copied, cleared)) is expected
