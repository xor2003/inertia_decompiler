"""Wide predicate captures preserve call placement and existing register users."""

import pytest
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from angr_platforms.X86_16.c_ast_utils import _iter_c_node_occurrences_8616
from angr_platforms.X86_16.lowering.wide_call_condition_capture import (
    build_proven_wide_call_condition_8616,
    commit_wide_call_condition_captures_8616,
)
from test_x86_16_call_output_stack_objects import _wide_condition_fixture


@pytest.mark.parametrize("register_carrier", [False, True])
def test_capture_is_once_in_place_and_reused_on_rematerialization(monkeypatch, register_carrier):
    codegen, _, chain, call, _ = _wide_condition_fixture(monkeypatch=monkeypatch)
    root = codegen.cfunc.statements
    original = None
    if register_carrier:
        register = CVariable(SimRegisterVariable(0, 2), variable_type=SimTypeShort(False), codegen=codegen)
        original = CAssignment(register, call, codegen=codegen)
        root.statements[0] = original
    predicate = build_proven_wide_call_condition_8616(codegen, chain, chain[-1].rhs, "sgt")
    assert predicate is not None
    assert commit_wide_call_condition_captures_8616(codegen) == 0
    conditional = root.statements[1]
    conditional.condition_and_nodes = [(predicate, conditional.condition_and_nodes[0][1])]
    assert commit_wide_call_condition_captures_8616(codegen) == 1
    value = predicate.lhs.expr
    assert codegen.cfunc.variables_in_use[value.variable] is value
    assert sum(node is call for node in _iter_c_node_occurrences_8616(root)) == 1
    if original is not None:
        assert original.rhs is value
        assert root.statements[0].statements[1] is original
    assert commit_wide_call_condition_captures_8616(codegen) == 0
    rebuilt = build_proven_wide_call_condition_8616(codegen, chain, chain[-1].rhs, "sgt")
    assert rebuilt is not None
    assert rebuilt.lhs.expr is value
    conditional.condition_and_nodes = [(rebuilt, conditional.condition_and_nodes[0][1])]
    assert commit_wide_call_condition_captures_8616(codegen) == 0
    assert sum(node is call for node in _iter_c_node_occurrences_8616(root)) == 1
