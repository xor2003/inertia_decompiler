"""Reject missing required predicates even when surviving predicates are valid."""

from dataclasses import replace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CStatements
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.lowering.semantic_cast import CSemanticCast8616
from angr_platforms.X86_16.structuring.condition_chain_provenance import bind_condition_chain_provenance_8616
from angr_platforms.X86_16.structuring.condition_evidence_closure import ConditionEvidenceClosure8616
from angr_platforms.X86_16.tail_validation import _canonicalize_final_branch_condition_fingerprint_8616
from angr_platforms.X86_16.tail_validation_fingerprint import _expr_fingerprint
from angr_platforms.X86_16.validation_branch_conditions import validate_materialized_branch_conditions_8616
from angr_platforms.X86_16.validation_condition_coverage import missing_required_condition_keys_8616
from angr_platforms.X86_16.validation_condition_precision import (
    ConditionPrecisionEvidence8616,
    condition_precision_token_8616,
    record_condition_precision_evidence_8616,
)
from test_x86_16_validation_branch_conditions import (
    _Codegen,
    _fact,
    _fact_fingerprint,
    _fingerprint,
    _root,
)


@pytest.mark.parametrize("operator", ["CmpEQ", "CmpNE"])
@pytest.mark.parametrize("corrupted", [False, True])
def test_precision_evidence_survives_decrement_temporary_elimination(operator, corrupted):
    codegen = _Codegen(_fact())
    codegen._inertia_callsite_summary_inventory_8616 = {}
    root = _root(codegen, keep_increment=True)
    condition, body = root.statements[0].condition_and_nodes[0]
    one = CConstant(1, SimTypeShort(False), codegen=codegen)
    zero = CConstant(0, SimTypeShort(False), codegen=codegen)
    decrement = CBinaryOp("Sub", condition.lhs, one, codegen=codegen)
    recorded = CBinaryOp(
        operator, CBinaryOp("Sub", decrement, one, codegen=codegen), zero,
        codegen=codegen, tags=dict(condition.tags),
    )
    assert record_condition_precision_evidence_8616(codegen.project, codegen, condition, recorded)
    final = CBinaryOp(
        operator, decrement, CConstant(2 if corrupted else 1, SimTypeShort(False), codegen=codegen),
        codegen=codegen, tags=dict(condition.tags),
    )
    root.statements[0].condition_and_nodes = [(final, body)]
    report = validate_materialized_branch_conditions_8616(
        codegen, root,
        condition_fingerprint=lambda node: _expr_fingerprint(node, codegen.project),
        condition_ir_fingerprint=lambda _: "CmpEQ(reg:unavailable,const:0)",
    )
    assert report.passed is (not corrupted)


@pytest.mark.parametrize("recorded_complete", [False, True])
@pytest.mark.parametrize("current_present", [False, True])
def test_validation_rechecks_required_condition_coverage(recorded_complete, current_present):
    codegen = _Codegen(_fact())
    key = (0x4015, 0x4010)
    codegen._inertia_structuring_condition_evidence_closure_8616 = ConditionEvidenceClosure8616(
        frozenset({key}), frozenset({key}) if recorded_complete else frozenset(), frozenset(),
    )
    root = _root(codegen, keep_increment=True) if current_present else CStatements([], codegen=codegen)
    report = validate_materialized_branch_conditions_8616(
        codegen, root, condition_fingerprint=_fingerprint, condition_ir_fingerprint=_fact_fingerprint,
    )
    assert report.passed is current_present
    if not current_present:
        assert report.failure_count == 1
        assert report.classified_fact_count == 1
        assert report.materialized_count == 0
        assert "missing-surface:jcc=0x4015" in report.issues[0].token()
        assert "block=0x4010" in report.issues[0].token()


def test_prestructuring_validation_does_not_require_unpublished_coverage():
    codegen = _Codegen(_fact())
    report = validate_materialized_branch_conditions_8616(
        codegen, CStatements([], codegen=codegen),
        condition_fingerprint=_fingerprint, condition_ir_fingerprint=_fact_fingerprint,
    )
    assert report.passed


def test_coverage_consumes_composite_provenance_without_requiring_duplicate_branches():
    first = _fact()
    second = replace(first, src_insn=0x4025, block_addr=0x4020)
    codegen = _Codegen(first)
    keys = frozenset({(0x4015, 0x4010), (0x4025, 0x4020)})
    codegen._inertia_structuring_condition_evidence_closure_8616 = ConditionEvidenceClosure8616(
        keys, frozenset(), frozenset(),
    )
    root = _root(codegen, keep_increment=True)
    condition = root.statements[0].condition_and_nodes[0][0]
    bind_condition_chain_provenance_8616(condition, (first, second))
    assert missing_required_condition_keys_8616(codegen, root, (first, second)) == ()


def test_reduced_fact_inventory_does_not_erase_published_obligation():
    codegen = _Codegen(None)
    key = (0x4015, 0x4010)
    codegen._inertia_structuring_condition_evidence_closure_8616 = ConditionEvidenceClosure8616(
        frozenset({key}), frozenset({key}), frozenset(),
    )
    assert missing_required_condition_keys_8616(codegen, CStatements([], codegen=codegen), ()) == (key,)


@pytest.mark.parametrize("limit", [0, 16, 512])
@pytest.mark.parametrize("corrupted", [False, True])
def test_recorded_precision_uses_same_compaction_as_current_condition(monkeypatch, limit, corrupted):
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_FINGERPRINT_LIMIT", str(limit))
    codegen = _Codegen(_fact())
    root = _root(codegen, keep_increment=True)
    condition = root.statements[0].condition_and_nodes[0][0]
    before = _root(codegen, keep_increment=False).statements[0].condition_and_nodes[0][0]
    original_lhs = condition.lhs
    for _ in range(40):
        condition.lhs = CBinaryOp("Add", condition.lhs, original_lhs, codegen=codegen)
    assert record_condition_precision_evidence_8616(codegen.project, codegen, before, condition)
    if corrupted:
        condition.lhs = before.lhs
    report = validate_materialized_branch_conditions_8616(
        codegen, root,
        condition_fingerprint=lambda expression: _expr_fingerprint(expression, codegen.project),
        condition_ir_fingerprint=_fact_fingerprint,
    )
    assert report.passed is not corrupted


@pytest.mark.parametrize("identity", [False, True])
@pytest.mark.parametrize("changed_operator", [False, True])
@pytest.mark.parametrize("declaration_refined", [False, True])
def test_precision_cast_cleanup_requires_declaration_identity(identity, changed_operator, declaration_refined):
    codegen = _Codegen(_fact())
    root = _root(codegen, keep_increment=True)
    condition = root.statements[0].condition_and_nodes[0][0]
    before = _root(codegen, keep_increment=False).statements[0].condition_and_nodes[0][0]
    argument = condition.rhs
    argument.variable_type = SimTypeShort(identity and not declaration_refined).with_arch(codegen.project.arch)
    condition.lhs = CBinaryOp("Add", condition.lhs, condition.lhs, codegen=codegen)
    condition.rhs = CSemanticCast8616(
        SimTypeShort(False).with_arch(codegen.project.arch),
        SimTypeShort(True).with_arch(codegen.project.arch), argument, codegen=codegen,
    )
    assert record_condition_precision_evidence_8616(codegen.project, codegen, before, condition)
    assert isinstance(condition.rhs, CSemanticCast8616)
    argument.variable_type = SimTypeShort(identity).with_arch(codegen.project.arch)
    condition.rhs = argument
    if changed_operator:
        condition.op = "CmpGT"
    report = validate_materialized_branch_conditions_8616(
        codegen, root,
        condition_fingerprint=lambda expression: _expr_fingerprint(expression, codegen.project),
        condition_ir_fingerprint=_fact_fingerprint,
    )
    assert report.passed is (identity and not changed_operator)


@pytest.mark.parametrize("limit", [16, 512])
@pytest.mark.parametrize("mask,shift,base,accepted", [
    (65535, 16, "0x132", True),
    (65534, 16, "0x132", False),
    (65535, 15, "0x132", False),
    (65535, 16, "0x134", False),
])
def test_precision_consumes_proven_global_word_views(monkeypatch, limit, mask, shift, base, accepted):
    """Use the existing storage normalizer before compacting current evidence."""
    monkeypatch.setenv("INERTIA_TAIL_VALIDATION_FINGERPRINT_LIMIT", str(limit))
    codegen = _Codegen(_fact())
    root = _root(codegen, keep_increment=True)
    condition = root.statements[0].condition_and_nodes[0][0]
    raw = (
        f"LogicalAnd(CmpEQ(And(global:{base},const:{mask}),const:900),"
        f"CmpEQ(Shr(global:{base},const:{shift}),const:0))"
    )
    recorded = "LogicalAnd(CmpEQ(ds_global:0x132,const:900),CmpEQ(ds_global:0x134,const:0))"
    codegen._inertia_condition_precision_evidence_8616 = (
        ConditionPrecisionEvidence8616("before", condition_precision_token_8616(recorded), 0x4015),
    )
    report = validate_materialized_branch_conditions_8616(
        codegen, root,
        condition_fingerprint=lambda node: raw if node is condition else _fingerprint(node),
        condition_ir_fingerprint=_fact_fingerprint,
        condition_fingerprint_normalizer=_canonicalize_final_branch_condition_fingerprint_8616,
    )
    assert report.passed is accepted
