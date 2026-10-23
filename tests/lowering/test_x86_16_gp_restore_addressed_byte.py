"""Addressed saved-register bytes must bind exact Alias-owned stack storage."""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeChar, SimTypeNum, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from archinfo import ArchX86

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.gp_stack_restore import materialize_gp_stack_restores_8616
from inertia.lowering.gp_stack_restore_identity import matches_gp_restore_stack_bytes_8616
from inertia.lowering.segment_register_state import runtime_segment_state_cvar_8616
from inertia.lowering.semantic_cast import CSemanticCast8616
from tests.lowering.test_x86_16_gp_stack_restore import _artifact, _Codegen

pytestmark = pytest.mark.decompiler


def _addressed_word(segment="ss", delta=1, duplicate_segment=False, narrow_segment=False, wide_read=False, truncate_base=False, native_cast=False, narrow_reference=False, narrow_pointer=False, signed_selector=False, word_reference=False, word_pointer_reference=False):
    """Build typed native/runtime SS plus the address of one saved stack byte."""
    codegen = _Codegen(project=SimpleNamespace(arch=Arch86_16()))
    word, byte = SimTypeShort(False), SimTypeChar(False)
    low = c.CVariable(SimStackVariable(-2, 1, base="bp"), variable_type=byte, codegen=codegen)
    if word_reference:
        low = c.CVariable(SimStackVariable(-2, 2, base="bp"), variable_type=word, codegen=codegen)
    register = runtime_segment_state_cvar_8616(segment, codegen=codegen, variable_type=word, function_addr=0x1000)
    if signed_selector:
        register.variable_type = SimTypeShort(True).with_arch(codegen.project.arch)
    if native_cast:
        register = CSemanticCast8616(word, SimTypeNum(32, False), register, codegen=codegen)
    if narrow_segment:
        register = c.CTypeCast(word, byte, register, codegen=codegen)
    base = c.CBinaryOp("Shl", register, c.CConstant(4, word, codegen=codegen), codegen=codegen)
    if truncate_base:
        base = c.CTypeCast(None, byte, base, codegen=codegen)
    reference = c.CUnaryOp("Reference", low, codegen=codegen)
    if narrow_reference:
        reference = c.CTypeCast(None, byte, reference, codegen=codegen)
    if word_pointer_reference:
        reference = c.CTypeCast(None, SimTypePointer(word), reference, codegen=codegen)
        reference.dst_type = SimTypePointer(word).with_arch(ArchX86())
    address = c.CBinaryOp("Add", base, reference, codegen=codegen)
    address = c.CBinaryOp("Add", address, c.CConstant(delta, word, codegen=codegen), codegen=codegen)
    if duplicate_segment:
        address = c.CBinaryOp("Add", address, base, codegen=codegen)
    # The SS-scaled address is physical; its carrier cannot be a near pointer.
    pointer_type = SimTypePointer(word if wide_read else byte).with_arch(ArchX86())
    if narrow_pointer:
        pointer_type = pointer_type.with_arch(SimpleNamespace(bits=16))
    pointer = c.CTypeCast(None, pointer_type, address, codegen=codegen)
    # angr's constructor rebinds casts to guest architecture; this fixture
    # explicitly describes the physical-address carrier being tested.
    pointer.dst_type = pointer_type
    high = c.CUnaryOp("Dereference", pointer, codegen=codegen)
    expression = c.CBinaryOp("Or", low, c.CBinaryOp("Shl", high, c.CConstant(8, word, codegen=codegen), codegen=codegen), codegen=codegen)
    return codegen, expression, _artifact().facts[0]


@pytest.mark.parametrize("native_cast", [False, True])
def test_addressed_high_byte_matches_exact_saved_word(native_cast):
    codegen, expression, fact = _addressed_word(native_cast=native_cast)
    assert matches_gp_restore_stack_bytes_8616(codegen, expression, fact)


@pytest.mark.parametrize("options", [{"segment":"ds"}, {"delta":0}, {"delta":2}, {"duplicate_segment":True}, {"narrow_segment":True}, {"wide_read":True}, {"truncate_base":True}])
def test_foreign_or_nonadjacent_addressed_byte_refuses(options):
    codegen, expression, fact = _addressed_word(**options)
    assert not matches_gp_restore_stack_bytes_8616(codegen, expression, fact)


def test_materializes_snapshot_for_addressed_pop_word():
    """Consume the native Alias fact rather than accepting the raw dereference."""
    codegen, expression, _fact = _addressed_word(native_cast=True)
    offset, size = codegen.project.arch.registers['ax']
    target = c.CVariable(SimRegisterVariable(offset, size), variable_type=SimTypeShort(False), codegen=codegen)
    restore = c.CAssignment(target, expression, codegen=codegen, tags={'ins_addr':0x1008})
    marker = c.CAssignment(expression.lhs, c.CConstant(0, SimTypeChar(False), codegen=codegen), codegen=codegen, tags={'ins_addr':0x1000})
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=c.CStatements([marker, restore], codegen=codegen), unified_local_vars={}, variables_in_use={})
    codegen._inertia_stack_register_restore_artifact_8616 = _artifact()
    assert materialize_gp_stack_restores_8616(codegen)
    assert isinstance(restore.rhs,c.CVariable)
    assert restore.rhs.variable.size == 2
    assert codegen._inertia_gp_stack_restore_lowering_stats_8616.materialized_count == 1


@pytest.mark.parametrize("options", [{"narrow_reference": True}, {"narrow_pointer": True}, {"signed_selector": True}, {"word_reference": True}, {"word_pointer_reference": True}])
def test_address_changing_casts_or_signed_selector_refuse(options):
    """Flattening must not erase address truncation or a signed selector."""
    codegen, expression, fact = _addressed_word(**options)
    assert not matches_gp_restore_stack_bytes_8616(codegen, expression, fact)
