"""Prove complete local reload bindings and reject corrupted C projections."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as c
from angr.sim_type import SimTypeChar, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable, SimTemporaryVariable
from angr_platforms.X86_16 import callsite_summary
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.caller_return_use_contracts import CallsiteReturnUseKind8616
from angr_platforms.X86_16.lowering.gp_register_state import runtime_gp_state_expr_8616
from angr_platforms.X86_16.lowering.gp_stack_local_reload import has_materialized_gp_local_reload_8616
from angr_platforms.X86_16.lowering.gp_stack_restore import materialize_gp_stack_restores_8616
from angr_platforms.X86_16.lowering.segment_register_state import runtime_segment_state_cvar_8616
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


def test_call_store_initializes_missing_binary_summary_inventory(monkeypatch):
    """Lowering must not depend on a later cleanup pass publishing evidence."""
    codegen, container, local, fact = _fixture()
    summary = replace(_summary(), callsite_addr=0xff0, return_addr=0xff3,
                      return_store_instruction_addr=0x1000, return_store_destination=("bp", -2),
                      return_store_width=2, return_use_kind=CallsiteReturnUseKind8616.VALUE)
    function = SimpleNamespace(get_call_sites=lambda: (0xff0,))
    codegen.project.kb = SimpleNamespace(functions=SimpleNamespace(function=lambda **kwargs: function))
    observed = []

    def summarize(owner, address, **kwargs):
        assert owner is function
        observed.append(address)
        return summary

    monkeypatch.setattr(callsite_summary.CallsiteTargetInventory8616, "collect", lambda *args: None)
    monkeypatch.setattr(callsite_summary, "summarize_x86_16_callsite", summarize)
    call = c.CFunctionCall("callee", None, [], codegen=codegen, tags={"ins_addr": 0xff0})
    saved = c.CAssignment(local, call, codegen=codegen, tags={"ins_addr": 0x1000})
    container.statements = [saved, container.statements[-1]]

    assert has_materialized_gp_local_reload_8616(codegen, (container,), fact)
    assert codegen._inertia_callsite_summary_inventory_8616 == {0xff0: summary}
    assert has_materialized_gp_local_reload_8616(codegen, (container,), fact)
    assert observed == [0xff0]


def test_transparent_child_sequence_retains_parent_dominance():
    codegen, container, _local, fact = _fixture()
    child = c.CStatements([container.statements.pop()], codegen=codegen)
    container.statements.append(child)

    assert has_materialized_gp_local_reload_8616(codegen, (container, child), fact)


@pytest.mark.parametrize("register,width", [("ax", 2), ("bx", 2), ("ax", 1), ("ax", 4)])
def test_native_register_reload_requires_exact_word_destination(register, width):
    """Native SSA register storage must agree with the Alias destination range."""
    codegen, container, local, fact = _fixture()
    offset = codegen.project.arch.registers[register][0]
    destination = c.CVariable(SimRegisterVariable(offset, width),
                              variable_type=local.variable_type, codegen=codegen)
    container.statements[-1] = c.CAssignment(destination, local, codegen=codegen,
                                             tags={"ins_addr": fact.restore_instruction_addr})

    assert has_materialized_gp_local_reload_8616(codegen, (container,), fact) is (register == "ax" and width == 2)


@pytest.mark.parametrize("corruption", [None, "signed", "shift", "other-local", "wrong-slot"])
def test_reload_byte_views_require_one_exact_word(corruption):
    """Two truncations are a word reload only with the same exact storage."""
    codegen, container, local, fact = _fixture()
    word = local.variable_type
    byte = SimTypeChar(corruption == "signed").with_arch(codegen.project.arch)
    upper_local = local
    if corruption == "other-local":
        upper_local = c.CVariable(SimStackVariable(-4, 2, base="bp"), variable_type=word, codegen=codegen)
    shift = c.CConstant(7 if corruption == "shift" else 8, word, codegen=codegen)
    upper = c.CTypeCast(word, byte, c.CBinaryOp("Shr", upper_local, shift, codegen=codegen), codegen=codegen)
    low = c.CTypeCast(word, byte, local, codegen=codegen)
    value = c.CBinaryOp("Or", low, c.CBinaryOp("Shl", upper, shift, codegen=codegen), codegen=codegen)
    container.statements[-1].rhs.rhs.lhs = value
    if corruption == "wrong-slot":
        fact = replace(fact, stack_offsets=(-4, -3))

    assert has_materialized_gp_local_reload_8616(codegen, (container,), fact) is (corruption is None)


def test_valid_reload_does_not_hide_a_corrupted_copy():
    codegen, container, local, fact = _fixture()
    original = container.statements[-1]
    corrupted = c.CAssignment(original.lhs, c.CConstant(0, local.variable_type, codegen=codegen),
                              codegen=codegen, tags=original.tags)
    other = c.CStatements([corrupted], codegen=codegen)

    assert not has_materialized_gp_local_reload_8616(codegen, (container, other), fact)


@pytest.mark.parametrize("effectful", [False, True])
def test_separate_segment_write_is_not_a_gp_restore(effectful):
    """A pure segment publication does not count as another GP destination."""
    codegen, container, local, fact = _fixture()
    segment = runtime_segment_state_cvar_8616("es", codegen=codegen,
                                              variable_type=local.variable_type, function_addr=0x1000)
    value = c.CFunctionCall("callee", None, [], codegen=codegen) if effectful else local
    container.statements.append(c.CAssignment(segment, value, codegen=codegen,
                                              tags={"ins_addr": fact.restore_instruction_addr}))

    assert has_materialized_gp_local_reload_8616(codegen, (container,), fact) is (not effectful)


@pytest.mark.parametrize("corruption", [None, "intervening", "missing-byte", "escape", "conditional"])
def test_complete_later_save_supersedes_initialization(corruption):
    """Earlier writes do not reach the reload when a complete save dominates it."""
    codegen, container, local, fact = _fixture()
    low, high, restore = container.statements
    initial = c.CAssignment(low.lhs, c.CConstant(0, local.variable_type, codegen=codegen),
                            codegen=codegen, tags={"ins_addr": 0xff0})
    container.statements.insert(0, initial)
    if corruption == "intervening":
        container.statements = [low, high, initial, restore]
    elif corruption == "missing-byte":
        container.statements.remove(high)
    elif corruption == "escape":
        container.statements.insert(0, c.CReturn(c.CUnaryOp("Reference", local, codegen=codegen), codegen=codegen))
    elif corruption == "conditional":
        container.statements[0] = c.CIfElse(c.CConstant(1, local.variable_type, codegen=codegen),
                                           c.CStatements([initial], codegen=codegen), codegen=codegen)

    assert has_materialized_gp_local_reload_8616(codegen, (container,), fact) is (corruption is None)


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


def _snapshot_fixture():
    """Project one captured call result into both AX and saved local bytes."""
    codegen, container, local, fact = _fixture()
    low, high, restore = container.statements
    temporary = c.CVariable(SimTemporaryVariable(7, 2), variable_type=local.variable_type, codegen=codegen)
    definition = c.CAssignment(temporary, c.CFunctionCall("callee", None, [], codegen=codegen), codegen=codegen)
    low.rhs = temporary
    high.rhs.lhs = temporary
    parent = restore.lhs
    upper = c.CBinaryOp("And", parent, c.CConstant(0xffff0000, local.variable_type, codegen=codegen), codegen=codegen)
    lower = c.CBinaryOp("And", temporary, c.CConstant(0xffff, local.variable_type, codegen=codegen), codegen=codegen)
    publication = c.CAssignment(parent, c.CBinaryOp("Or", upper, lower, codegen=codegen), codegen=codegen)
    container.statements = [definition, publication, low, high, restore]
    return codegen, container, local, fact, temporary


@pytest.mark.parametrize("corruption", [None, "missing-summary", "missing-definition", "late-definition",
                                       "duplicate-definition", "self-reference", "intervening-call", "source-escape"])
def test_native_call_result_byte_stores_need_value_and_initialization_proof(corruption):
    codegen, container, _local, fact, snapshot = _snapshot_fixture()
    definition, _publication, low, high, restore = container.statements
    snapshot.variable = SimRegisterVariable(0, 2)
    definition.rhs.tags = {"ins_addr": 0xff0}
    summary = replace(_summary(), callsite_addr=0xff0, return_addr=0xff3,
                      return_store_instruction_addr=0x1000, return_store_destination=("bp", -2),
                      return_store_width=2, return_use_kind=CallsiteReturnUseKind8616.VALUE)
    codegen._inertia_callsite_summary_inventory_8616 = {0xff0: summary}
    container.statements = [definition, low, high, restore]
    if corruption == "missing-summary":
        codegen._inertia_callsite_summary_inventory_8616 = {}
    elif corruption == "missing-definition":
        container.statements.remove(definition)
    elif corruption == "late-definition":
        container.statements = [low, high, definition, restore]
    elif corruption == "duplicate-definition":
        container.statements.insert(1, c.CAssignment(snapshot, definition.rhs, codegen=codegen))
    elif corruption == "self-reference":
        definition.rhs.args = [snapshot]
    elif corruption == "intervening-call":
        container.statements.insert(1, c.CFunctionCall("other", None, [], codegen=codegen))
    elif corruption == "source-escape":
        container.statements.append(c.CReturn(c.CUnaryOp("Reference", snapshot, codegen=codegen), codegen=codegen))

    assert has_materialized_gp_local_reload_8616(codegen, (container,), fact) is (corruption is None)


@pytest.mark.parametrize("corruption", [None, "undefined", "late-definition", "redefined", "escaped", "conditional", "self-read"])
def test_published_snapshot_bytes_require_initialized_unique_value(corruption):
    """Only an initialized, nonescaping, uniquely defined snapshot may prove a save."""
    codegen, container, local, fact, temporary = _snapshot_fixture()
    definition, publication, low, high, restore = container.statements
    if corruption == "undefined":
        container.statements.remove(definition)
    elif corruption == "late-definition":
        container.statements = [publication, low, high, definition, restore]
    elif corruption == "redefined":
        container.statements.insert(2, c.CAssignment(temporary, c.CConstant(1, local.variable_type, codegen=codegen), codegen=codegen))
    elif corruption == "escaped":
        container.statements.insert(0, c.CUnaryOp("Reference", temporary, codegen=codegen))
    elif corruption == "conditional":
        container.statements[0] = c.CIfElse(c.CConstant(1, local.variable_type, codegen=codegen), c.CStatements([definition], codegen=codegen), None, codegen=codegen)
    elif corruption == "self-read":
        definition.rhs = temporary

    assert has_materialized_gp_local_reload_8616(codegen, (container,), fact) is (corruption is None)
    if corruption is None:
        before = tuple(container.statements)
        assert materialize_gp_stack_restores_8616(codegen) is False
        assert tuple(container.statements) == before
        assert codegen._inertia_gp_stack_restore_lowering_stats_8616.materialized_count == 1


@pytest.mark.parametrize("corruption", [None, "wrong-value", "wrong-register", "call-clobber", "register-clobber", "signed", "wrong-shift"])
def test_snapshot_byte_stores_require_unchanged_register_publication(corruption):
    """An exact word publication must dominate the stores without clobbering."""
    codegen, container, local, fact, temporary = _snapshot_fixture()
    _definition, publication, _low, high, restore = container.statements
    parent = restore.lhs
    lower = publication.rhs.rhs
    if corruption == "wrong-value":
        lower.lhs = c.CConstant(1, local.variable_type, codegen=codegen)
    elif corruption == "wrong-register":
        publication.lhs = runtime_gp_state_expr_8616("edx", codegen=codegen, function_addr=0x1000)
    elif corruption == "call-clobber":
        container.statements.insert(2, c.CAssignment(parent, c.CFunctionCall("other", None, [], codegen=codegen), codegen=codegen))
    elif corruption == "register-clobber":
        container.statements.insert(2, c.CAssignment(parent, c.CConstant(0, local.variable_type, codegen=codegen), codegen=codegen))
    elif corruption == "signed":
        temporary.variable_type = SimTypeShort(True)
    elif corruption == "wrong-shift":
        high.rhs.rhs.value = 7

    assert has_materialized_gp_local_reload_8616(codegen, (container,), fact) is (corruption is None)


def test_snapshot_publication_refuses_nested_register_write():
    """A comma-expression register clobber cannot borrow the earlier publication."""
    codegen, container, local, fact, _temporary = _snapshot_fixture()
    parent = container.statements[-1].lhs
    zero = c.CConstant(0, local.variable_type, codegen=codegen)
    clobber = c.CAssignment(parent, zero, codegen=codegen)
    nested = c.CMultiStatementExpression(c.CStatements([clobber], codegen=codegen), zero, codegen=codegen)
    unrelated = c.CVariable(SimTemporaryVariable(8, 2), variable_type=local.variable_type, codegen=codegen)
    container.statements.insert(2, c.CAssignment(unrelated, nested, codegen=codegen))

    assert not has_materialized_gp_local_reload_8616(codegen, (container,), fact)
