"""Typed field equivalence must retain width, signedness and branch polarity."""

import pytest
from angr.sim_type import SimTypeInt, SimTypeShort
from angr_platforms.X86_16.lowering.semantic_cast import CSemanticCast8616
from angr_platforms.X86_16.structuring.condition_materialization import materialize_condition_ir_expression_8616
from angr_platforms.X86_16.validation_condition_storage_views import condition_storage_views_match_8616
from test_x86_16_validation_loop_condition_ir import _Codegen, _indexed_condition_ir, _indexed_final_loop, _Project


def test_matching_signed_field_view_preserves_the_original_ast():
    project = _Project()
    codegen = _Codegen(project)
    root = _indexed_final_loop(codegen)
    guard = root.statements[0].body.statements[0].condition
    lhs, rhs = guard.lhs, guard.rhs
    field_type = lhs.type
    assert condition_storage_views_match_8616(project, codegen, _indexed_condition_ir(), guard, True)
    assert guard.lhs is lhs and guard.rhs is rhs
    assert lhs.type is field_type


@pytest.mark.parametrize("corruption", ["unsigned", "wide", "pivot_unsigned", "pivot_wide", "polarity", "pointer"])
def test_condition_storage_match_refuses_changed_value_interpretation(corruption):
    project = _Project()
    codegen = _Codegen(project)
    guard = _indexed_final_loop(codegen).statements[0].body.statements[0].condition
    if corruption == "unsigned":
        guard.lhs.field.struct_type.fields["field_0"] = SimTypeShort(False)
    elif corruption == "wide":
        guard.lhs.field.struct_type.fields["field_0"] = SimTypeInt(True)
    elif corruption == "pivot_unsigned":
        guard.rhs.variable_type = SimTypeShort(False).with_arch(project.arch)
    elif corruption == "pivot_wide":
        guard.rhs.variable.size = 4
    elif corruption == "polarity":
        guard.op = "CmpLE"
    elif corruption == "pointer":
        guard.lhs.var_is_ptr = True
    assert not condition_storage_views_match_8616(project, codegen, _indexed_condition_ir(), guard, True)


def test_decoded_comparison_requires_the_noninverted_polarity():
    project = _Project()
    codegen = _Codegen(project)
    guard = _indexed_final_loop(codegen).statements[0].body.statements[0].condition
    guard.op = "CmpLE"
    assert condition_storage_views_match_8616(project, codegen, _indexed_condition_ir(), guard, False)


@pytest.mark.parametrize("corruption", ["missing_evidence", "helper_width", "stack_base"])
def test_memory_view_match_refuses_unproven_or_contradictory_storage(corruption):
    project = _Project()
    codegen = _Codegen(project)
    condition = _indexed_condition_ir()
    candidate = materialize_condition_ir_expression_8616(project, codegen, condition)
    assert condition_storage_views_match_8616(project, codegen, condition, candidate, False)
    if corruption == "missing_evidence":
        candidate.lhs.expr.tags = {}
    elif corruption == "helper_width":
        candidate.lhs.expr.callee_target = "SEG_U32"
    elif corruption == "stack_base":
        operand = candidate.rhs.expr if isinstance(candidate.rhs, CSemanticCast8616) else candidate.rhs
        operand.variable.base = "sp"
    assert not condition_storage_views_match_8616(project, codegen, condition, candidate, False)
