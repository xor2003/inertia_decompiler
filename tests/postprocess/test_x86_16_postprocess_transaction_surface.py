"""Transaction validation must compare the actual AST on both boundaries."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CStatements, CVariable
from angr.sim_type import SimTypeChar
from angr.sim_variable import SimStackVariable

import inertia.postprocess.decompiler_postprocess_stage as stage
from inertia.validation.tail_validation import (
    X86_16TailValidationSummary,
    compare_x86_16_tail_validation_summaries,
)
from inertia.validation.validation_dataflow import validate_structured_def_use_8616
from inertia.validation.validation_semantic_failures import collect_tail_semantic_failures_8616
from tests.validation.test_x86_16_validation_virtual_carriers import _Codegen, _register_dirty

pytestmark = pytest.mark.decompiler


def _codegen():
    codegen = _Codegen()
    statements = []
    for offset in (0, -1):
        target = CVariable(
            SimStackVariable(offset, 1, base="bp", region=0x1000),
            variable_type=SimTypeChar(False), codegen=codegen,
        )
        statements.append(CAssignment(target, _register_dirty(codegen, 23, 20), codegen=codegen))
    root = CStatements(statements, codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root, arg_list=[], addr=0x1000)
    return codegen


def _summary(_project, codegen, **_kwargs):
    report = validate_structured_def_use_8616(codegen.cfunc.statements)
    # Isolate collection policy: the observable-effect oracle is equal, while
    # the real def-use checker retains every native register read obligation.
    return X86_16TailValidationSummary(
        (), (), (), (), (), (), (), (),
        def_use_issues=report.semantic_issue_tokens(),
    )


@pytest.mark.parametrize("change", ["unchanged", "introduced", "removed"])
def test_transaction_keeps_actual_baseline_issues(monkeypatch, change):
    codegen = _codegen()
    owner = SimpleNamespace(project=codegen.project, codegen=codegen)
    clone = _codegen()
    clone.cfunc.statements.statements.clear()
    monkeypatch.setattr(stage, "_prepare_baseline_clone_or_none_8616", lambda *args, **kwargs: clone)
    monkeypatch.setattr(stage, "_postprocess_function_complexity_8616", lambda *args: stage._PostprocessFunctionComplexity8616())
    monkeypatch.setattr(stage._post, "_repair_unresolved_function_exit_gotos_8616", lambda *args: False)
    monkeypatch.setattr(stage, "collect_x86_16_tail_validation_summary", _summary)
    monkeypatch.setattr(stage, "fingerprint_x86_16_tail_validation_boundary", lambda *args, **kwargs: "boundary")

    fingerprint, before, _, _ = stage._collect_validation_baseline_8616(owner, 0x1000, "live_out")
    assert len(before.def_use_issues) == 2
    assert before.def_use_issues == _summary(owner.project, codegen).def_use_issues
    codegen._inertia_postprocess_mutation_generation_8616 = object()
    if change == "introduced":
        codegen.cfunc.statements.statements[0].rhs = _register_dirty(codegen, 99, 16)
    elif change == "removed":
        codegen.cfunc.statements.statements.clear()
    _, after, _ = stage._collect_after_validation_summary_8616(
        owner, 0x1000, "live_out", True, None, fingerprint, before,
    )
    result = compare_x86_16_tail_validation_summaries(before, after)
    assert result["changed"] is (change == "introduced")
    if change == "introduced":
        assert result["semantic_failures"]["def_use"]
    elif change == "unchanged":
        assert after.def_use_issues == before.def_use_issues
        # Local equivalence never clears the absolute final validation errors.
        assert len(collect_tail_semantic_failures_8616(after)["def_use"]) == 2
    else:
        assert not after.def_use_issues
        assert compare_x86_16_tail_validation_summaries(before, replace(after, returns=("changed",)))["changed"] is True


def test_rollback_collects_actual_restored_issues(monkeypatch):
    codegen = _codegen()
    owner = SimpleNamespace(project=codegen.project, codegen=codegen)
    before = _summary(owner.project, codegen)
    snapshot = stage._snapshot_codegen_cfunc(codegen)
    metadata = stage._snapshot_codegen_inertia_metadata_8616(codegen)
    codegen.cfunc.statements.statements[0].rhs = _register_dirty(codegen, 99, 16)
    collected = []
    persisted = []

    def collect(project, active_codegen, **kwargs):
        summary = _summary(project, active_codegen, **kwargs)
        collected.append(summary)
        return summary

    monkeypatch.setattr(stage, "collect_x86_16_tail_validation_summary", collect)
    monkeypatch.setattr(stage, "_prepare_baseline_clone_or_none_8616", lambda *args, **kwargs: pytest.fail("rollback must validate actual restored AST"))
    monkeypatch.setattr(stage, "_regenerate_text_safely", lambda *args, **kwargs: None)
    monkeypatch.setattr(stage, "_collect_discard_salvages_8616", lambda *args, **kwargs: stage._DiscardSalvageResult8616())
    monkeypatch.setattr(stage, "persist_x86_16_tail_validation_snapshot", lambda **kwargs: persisted.append(kwargs["validation"]))
    stage._discard_failed_postprocess_result_8616(
        owner, validation={"verdict": "failed", "changed": True, "semantic_failures": {"def_use": ("new",)}},
        validation_verdict_text="failed", validation_mode="live_out", snapshot_function_info={},
        before_fingerprint="before", before_summary=before,
        pre_postprocess_cfunc_snapshot=snapshot, pre_postprocess_metadata_snapshot=metadata,
        validation_timings={}, function=SimpleNamespace(addr=0x1000),
        log=SimpleNamespace(warning=lambda *args: None, info=lambda *args: None),
    )
    assert len(collected) == 1
    assert collected[0].def_use_issues == before.def_use_issues
    assert len(collect_tail_semantic_failures_8616(collected[0])["def_use"]) == 2
    assert persisted[0]["changed"] is False
