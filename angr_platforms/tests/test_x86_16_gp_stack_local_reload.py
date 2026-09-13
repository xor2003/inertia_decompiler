"""Prove complete local reload bindings and reject corrupted C projections."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as c
from angr.sim_type import SimTypeChar, SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.caller_return_use_contracts import CallsiteReturnUseKind8616
from angr_platforms.X86_16.lowering.gp_register_state import runtime_gp_state_expr_8616
from angr_platforms.X86_16.lowering.gp_stack_local_reload import has_materialized_gp_local_reload_8616
from angr_platforms.X86_16.lowering.gp_stack_restore import materialize_gp_stack_restores_8616
from test_x86_16_call_stack_effects import _summary
from test_x86_16_gp_stack_restore import _artifact, _Codegen


def _fixture():
    arch = Arch86_16()
    codegen = _Codegen(project=SimpleNamespace(arch=arch))
    word = SimTypeShort(False).with_arch(arch)
    local = c.CVariable(SimStackVariable(-2, 2, base="bp", name="local"), variable_type=word, codegen=codegen)

    def constant(value):
        return c.CConstant(value, word, codegen=codegen)

    def binary(op, left, right):
        return c.CBinaryOp(op, left, right, codegen=codegen)

    saved = runtime_gp_state_expr_8616("ax", codegen=codegen, function_addr=0x1000)
    parent = runtime_gp_state_expr_8616("eax", codegen=codegen, function_addr=0x1000)
    stores = []
    for byte in (0, 1):
        reference = c.CUnaryOp("Reference", local, codegen=codegen)
        pointer = c.CTypeCast(None, SimTypePointer(SimTypeChar(False)).with_arch(arch), reference, codegen=codegen)
        lhs = c.CIndexedVariable(pointer, constant(byte), codegen=codegen)
        rhs = binary("Shr", saved, constant(8)) if byte else saved
        stores.append(c.CAssignment(lhs, rhs, codegen=codegen, tags={"ins_addr": 0x1000}))
    restore = c.CAssignment(parent, binary("Or", binary("And", parent, constant(0xffff0000)),
                                         binary("And", local, constant(0xffff))),
                            codegen=codegen, tags={"ins_addr": 0x1008})
    container = c.CStatements([*stores, restore], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=container, unified_local_vars={}, variables_in_use={})
    codegen._inertia_stack_register_restore_artifact_8616 = _artifact()
    return codegen, container, local, _artifact().facts[0]


def test_full_local_reload_closes_production_fact_without_snapshot():
    codegen, container, _local, fact = _fixture()
    before = tuple(container.statements)

    assert has_materialized_gp_local_reload_8616(codegen, (container,), fact)
    assert materialize_gp_stack_restores_8616(codegen) is False
    assert tuple(container.statements) == before
    assert codegen._inertia_gp_stack_restore_lowering_stats_8616.materialized_count == 1


def test_transparent_child_sequence_retains_parent_dominance():
    codegen, container, _local, fact = _fixture()
    child = c.CStatements([container.statements.pop()], codegen=codegen)
    container.statements.append(child)

    assert has_materialized_gp_local_reload_8616(codegen, (container, child), fact)


def test_valid_reload_does_not_hide_a_corrupted_copy():
    codegen, container, local, fact = _fixture()
    original = container.statements[-1]
    corrupted = c.CAssignment(original.lhs, c.CConstant(0, local.variable_type, codegen=codegen),
                              codegen=codegen, tags=original.tags)
    other = c.CStatements([corrupted], codegen=codegen)

    assert not has_materialized_gp_local_reload_8616(codegen, (container, other), fact)


def test_intervening_call_refuses_dominance():
    codegen, container, _local, fact = _fixture()
    original = container.statements[-1]
    call = c.CFunctionCall("sub_2000", None, [], codegen=codegen)
    container.statements.insert(2, c.CAssignment(original.lhs, call, codegen=codegen))

    assert not has_materialized_gp_local_reload_8616(codegen, (container,), fact)


@pytest.mark.parametrize("corruption", ["missing", "duplicate", "offset", "narrow", "value", "byte", "late", "escape"])
def test_bad_local_reload_refuses(corruption):
    codegen, container, local, fact = _fixture()
    low, high, restore = container.statements
    if corruption == "missing":
        container.statements.remove(high)
    elif corruption == "duplicate":
        container.statements.insert(1, c.CAssignment(low.lhs, low.rhs, codegen=codegen, tags=low.tags))
    elif corruption == "offset":
        fact = replace(fact, stack_offsets=(-4, -3))
    elif corruption == "narrow":
        local.variable_type = SimTypeChar(False)
    elif corruption == "value":
        high.rhs = low.rhs
    elif corruption == "byte":
        high.lhs.index.value = 0
    elif corruption == "late":
        container.statements = [restore, low, high]
    else:
        container.statements.insert(2, c.CReturn(c.CUnaryOp("Reference", local, codegen=codegen), codegen=codegen))

    assert not has_materialized_gp_local_reload_8616(codegen, (container,), fact)


@pytest.mark.parametrize("corruption", [None, "upper-word", "wrong-mask", "missing-proof", "wrong-store", "wrong-width", "wrong-slot", "wrong-call"])
def test_folded_call_result_requires_exact_store_proof(corruption):
    codegen, container, local, fact = _fixture()
    summary = replace(_summary(), callsite_addr=0xff0, return_addr=0xff3,
                      return_store_instruction_addr=0x1000, return_store_destination=("bp", -2),
                      return_store_width=2, return_use_kind=CallsiteReturnUseKind8616.VALUE)
    if corruption == "wrong-store":
        summary = replace(summary, return_store_instruction_addr=0x1001)
    elif corruption == "wrong-width":
        summary = replace(summary, return_store_width=1)
    elif corruption == "wrong-slot":
        summary = replace(summary, return_store_destination=("bp", -4))
    codegen._inertia_callsite_summary_inventory_8616 = {} if corruption == "missing-proof" else {0xff0: summary}
    call = c.CFunctionCall("sub_2000", None, [], codegen=codegen,
                           tags={"ins_addr": 0xff1 if corruption == "wrong-call" else 0xff0})
    saved = c.CAssignment(local, call, codegen=codegen, tags={"ins_addr": 0xff0})
    if corruption in {"upper-word", "wrong-mask"}:
        parent = runtime_gp_state_expr_8616("eax", codegen=codegen, function_addr=0x1000)
        mask = 0xffff0000 if corruption == "upper-word" else 0xffffff00
        upper = c.CBinaryOp("And", parent, c.CConstant(mask, local.variable_type, codegen=codegen), codegen=codegen)
        lower = c.CBinaryOp("And", call, c.CConstant(0xffff, local.variable_type, codegen=codegen), codegen=codegen)
        saved.rhs = c.CBinaryOp("Or", upper, lower, codegen=codegen)
    container.statements = [saved, container.statements[-1]]

    assert has_materialized_gp_local_reload_8616(codegen, (container,), fact) is (corruption in {None, "upper-word"})
