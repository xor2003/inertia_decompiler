"""GP restore consumers must prove both instruction scope and byte identity."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as c
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.gp_register_state import (
    runtime_gp_state_assignment_8616,
    runtime_gp_state_expr_8616,
)
from angr_platforms.X86_16.lowering.gp_stack_restore import materialize_gp_stack_restores_8616
from angr_platforms.X86_16.pipeline.errors import PipelineHardError
from test_x86_16_gp_stack_restore import _artifact, _assignment, _Codegen


def _restore(codegen, offset, address, register="ax"):
    byte = SimTypeChar(False)
    low = c.CVariable(SimStackVariable(offset, 1, base="bp"), variable_type=byte, codegen=codegen)
    high = c.CVariable(SimStackVariable(offset + 1, 1, base="bp"), variable_type=byte, codegen=codegen)
    joined = c.CBinaryOp("Or", low, c.CBinaryOp(
        "Shl", high, c.CConstant(8, byte, codegen=codegen), codegen=codegen,
    ), codegen=codegen)
    reg_offset, reg_size = codegen.project.arch.registers[register]
    target = c.CVariable(SimRegisterVariable(reg_offset, reg_size, name=register),
                        variable_type=SimTypeShort(False), codegen=codegen)
    return c.CAssignment(target, joined, codegen=codegen, tags={"ins_addr": address})


def _codegen():
    codegen = _Codegen(project=SimpleNamespace(arch=Arch86_16()))
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=None,
                                   unified_local_vars={}, variables_in_use={})
    codegen._inertia_stack_register_restore_artifact_8616 = _artifact()
    return codegen


def test_restore_refuses_other_stack_bytes_despite_matching_instruction():
    codegen = _codegen()
    restore = _restore(codegen, -4, 0x1008)
    original = restore.rhs
    marker = _assignment(codegen, restore.lhs, 0x1001)
    codegen.cfunc.statements = c.CStatements([marker, restore], codegen=codegen)

    with pytest.raises(PipelineHardError, match="none materialized"):
        materialize_gp_stack_restores_8616(codegen)
    assert restore.rhs is original


def test_compound_container_does_not_transfer_restore_ownership_to_siblings():
    codegen = _codegen()
    restore = _restore(codegen, -2, 0x1008)
    unrelated = _restore(codegen, -2, 0x1009, "bx")
    original = unrelated.rhs
    marker = _assignment(codegen, restore.lhs, 0x1001)
    nested = c.CStatements([restore, unrelated], codegen=codegen)
    codegen.cfunc.statements = c.CStatements([marker, nested], codegen=codegen)

    assert materialize_gp_stack_restores_8616(codegen)
    assert isinstance(restore.rhs, c.CVariable)
    assert unrelated.rhs is original


def test_cross_register_restore_replay_does_not_duplicate_snapshot():
    """PUSH AX followed by POP BX has one durable save/restore identity."""
    codegen = _codegen()
    artifact = _artifact()
    fact = replace(artifact.facts[0], restore_register="bx")
    codegen._inertia_stack_register_restore_artifact_8616 = replace(artifact, facts=(fact,))
    restore = _restore(codegen, -2, fact.restore_instruction_addr, "bx")
    marker = _assignment(codegen, restore.lhs, fact.saved_instruction_addr + 1)
    codegen.cfunc.statements = c.CStatements([marker, restore], codegen=codegen)

    assert materialize_gp_stack_restores_8616(codegen)
    statements = tuple(codegen.cfunc.statements.statements)
    for _ in range(3):
        assert not materialize_gp_stack_restores_8616(codegen)
        assert tuple(codegen.cfunc.statements.statements) == statements
    stats = codegen._inertia_gp_stack_restore_lowering_stats_8616
    assert stats.materialized_count == 1
    assert stats.failure_count == 0
    assert stats.closed


@pytest.mark.parametrize("corruption", [None, "value", "order", "overwrite", "goto", "clone", "branch", "reader"])
@pytest.mark.parametrize("nested", [False, True])
def test_existing_byte_saves_need_no_duplicate_wide_snapshot(corruption, nested):
    """Existing byte storage counts only with matching values and dominance."""
    codegen = _codegen()
    fact = _artifact().facts[0]
    restore = _restore(codegen, -2, fact.restore_instruction_addr)
    low, high = restore.rhs.lhs, restore.rhs.rhs.lhs
    source = runtime_gp_state_expr_8616("ax", codegen=codegen, function_addr=0x1000)
    low_save = c.CAssignment(low, source, codegen=codegen,
                            tags={"ins_addr": fact.saved_instruction_addr})
    high_value = c.CBinaryOp("Shr", source, c.CConstant(8, SimTypeChar(False), codegen=codegen),
                            codegen=codegen)
    high_save = c.CAssignment(high, high_value, codegen=codegen,
                             tags={"ins_addr": fact.saved_instruction_addr})
    restore = runtime_gp_state_assignment_8616("ax", restore.rhs, codegen=codegen,
                                               function_addr=0x1000)
    restore.tags = {"ins_addr": fact.restore_instruction_addr}
    marker = _assignment(codegen, _restore(codegen, -8, 0x1001).lhs, 0x1001)
    statements = [low_save, high_save, marker, restore]
    if corruption == "value":
        high_save.rhs = low_save.rhs
    elif corruption == "order":
        statements = [marker, restore, low_save, high_save]
    elif corruption == "overwrite":
        statements.insert(2, _assignment(codegen, low, 0x1001))
    elif corruption == "goto":
        statements.insert(0, c.CGoto(fact.restore_instruction_addr, None, codegen=codegen))
    elif corruption == "clone":
        statements.append(_restore(codegen, -8, fact.restore_instruction_addr))
    elif corruption == "branch":
        body = c.CStatements([low_save, high_save], codegen=codegen)
        condition = c.CConstant(1, SimTypeChar(False), codegen=codegen)
        statements = [c.CIfElse([(condition, body)], codegen=codegen), marker, restore]
    elif corruption == "reader":
        marker.rhs = low
    if nested:
        statements = [c.CStatements(statements[:2], codegen=codegen),
                      c.CStatements(statements[2:], codegen=codegen)]
    codegen.cfunc.statements = c.CStatements(statements, codegen=codegen)
    before = tuple(statements)

    changed = materialize_gp_stack_restores_8616(codegen)

    if corruption in (None, "reader"):
        assert not changed
        assert tuple(codegen.cfunc.statements.statements) == before
        assert not codegen._inertia_gp_stack_restore_snapshots_8616
        assert not materialize_gp_stack_restores_8616(codegen)
    else:
        assert changed
    assert codegen._inertia_gp_stack_restore_lowering_stats_8616.materialized_count == 1
