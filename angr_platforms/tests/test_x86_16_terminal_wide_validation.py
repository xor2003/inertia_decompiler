"""Final terminal-wide validation must consume both CFG and storage proofs."""

from dataclasses import replace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CConstant, CStatements
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable, SimTemporaryVariable
from angr_platforms.X86_16.ir.condition_ir import condition_sort_key_8616
from angr_platforms.X86_16.lowering.wide_call_condition_binding import wide_call_identity_8616
from angr_platforms.X86_16.lowering.wide_call_condition_capture import (
    build_proven_wide_call_condition_8616,
    commit_wide_call_condition_captures_8616,
)
from angr_platforms.X86_16.structuring.condition_chain_provenance import bind_condition_chain_provenance_8616
from angr_platforms.X86_16.structuring.terminal_loop_exit_conditions import (
    materialize_terminal_loop_exit_conditions_8616,
)
from angr_platforms.X86_16.validation_branch_conditions import validate_materialized_branch_conditions_8616
from test_x86_16_terminal_loop_exit_conditions import _fixture


def _materialized(monkeypatch):
    codegen, loop, facts, topology, successors, artifact = _fixture(monkeypatch)
    codegen.cfunc.statements = CStatements([loop], codegen=codegen)
    codegen._inertia_typed_conditions = facts
    stats = materialize_terminal_loop_exit_conditions_8616(
        loop, facts, topology, successors, artifact,
        lambda plan: build_proven_wide_call_condition_8616(codegen, plan.conditions, plan.low_stack, plan.operator),
        lambda old, new: True,
    )
    assert stats.materialized_count == 1
    assert commit_wide_call_condition_captures_8616(codegen) == 1
    codegen.cfunc.unified_local_vars = {
        variable: {(cvar, cvar.variable_type)} for variable, cvar in codegen.cfunc.variables_in_use.items()
    }
    return codegen, loop, facts


def _validate(codegen):
    return validate_materialized_branch_conditions_8616(
        codegen, codegen.cfunc.statements,
        condition_fingerprint=lambda node: repr(node),
        condition_ir_fingerprint=lambda fact: None,
    )


def test_terminal_wide_proof_survives_consumed_scalar_registers(monkeypatch):
    codegen, _, _ = _materialized(monkeypatch)
    report = _validate(codegen)
    assert report.passed, report.issues
    assert report.classified_fact_count == report.materialized_count == 1


@pytest.mark.parametrize("target, expected", [(0x1137E, 0x1137E), (0x137E, 0x1137E),
                                           ("renamed", 0x1137E), (0x137F, None)])
def test_wide_call_identity_preserves_checked_binary_target(monkeypatch, target, expected):
    codegen, loop, _ = _materialized(monkeypatch)
    call = loop.body.statements[0].rhs
    codegen.project._inertia_original_linear_delta = 0x10000
    call.callee_func = None
    call.callee_target = target
    call.tags["inertia_target_addr_8616"] = 0x1137E
    assert wide_call_identity_8616(call) == expected


@pytest.mark.parametrize("fault", [
    "operator", "signedness", "width", "local", "call-target", "call-argument",
    "capture-after", "capture-outside", "duplicate-write", "fact", "missing-fact", "header",
    "declaration-type", "missing-declaration",
])
def test_terminal_wide_proof_refuses_corruption(monkeypatch, fault):
    codegen, loop, facts = _materialized(monkeypatch)
    capture, guard = loop.body.statements
    condition = guard.condition_and_nodes[0][0]
    if fault in {"operator", "signedness", "width", "local", "call-target", "call-argument",
                 "declaration-type", "missing-declaration"}:
        _damage_values(codegen, capture, condition, fault)
    elif fault == "capture-after":
        loop.body.statements = [guard, capture]
    elif fault == "capture-outside":
        loop.body.statements = [guard]
        codegen.cfunc.statements.statements.insert(0, capture)
    elif fault == "duplicate-write":
        loop.body.statements.insert(1, CAssignment(capture.lhs, capture.lhs, codegen=codegen))
    elif fault == "fact":
        codegen._inertia_typed_conditions = (replace(facts[0], op="slt"), *facts[1:])
        assert condition_sort_key_8616(codegen._inertia_typed_conditions[0]) != condition_sort_key_8616(facts[0])
    elif fault == "missing-fact":
        codegen._inertia_typed_conditions = facts[:-1]
    elif fault == "header":
        loop.tags["ins_addr"] += 1
    else:
        pytest.fail(fault)
    assert not _validate(codegen).passed


def _damage_values(codegen, capture, condition, fault):
    if fault == "declaration-type":
        codegen.cfunc.unified_local_vars[capture.lhs.variable] = {(capture.lhs, SimTypeShort(False))}
    elif fault == "missing-declaration":
        del codegen.cfunc.unified_local_vars[capture.lhs.variable]
    elif fault == "operator":
        condition.op = "CmpLT"
    elif fault == "signedness":
        condition.lhs.dst_type = SimTypeShort(False).with_arch(codegen.project.arch)
    elif fault == "width":
        condition.lhs.expr.variable.size = 2
    elif fault == "local":
        condition.rhs.expr.variable.offset -= 2
    elif fault == "call-target":
        capture.rhs.callee_target = "different_target"
    elif fault == "call-argument":
        capture.rhs.args = [CConstant(1, SimTypeShort(False), codegen=codegen)]
    else:
        pytest.fail(fault)


@pytest.mark.parametrize("fault", ["capture-unified", "stack-unified", "branch-provenance"])
def test_terminal_wide_proof_refuses_contradictory_projections(monkeypatch, fault):
    codegen, loop, facts = _materialized(monkeypatch)
    condition = loop.body.statements[-1].condition_and_nodes[0][0]
    if fault == "capture-unified":
        condition.lhs.expr.unified_variable = SimTemporaryVariable(99, 4)
    elif fault == "stack-unified":
        condition.rhs.expr.unified_variable = SimStackVariable(-20, 4, base="bp", region=0x1000)
    else:
        bind_condition_chain_provenance_8616(condition, facts[:1])
    assert not _validate(codegen).passed
