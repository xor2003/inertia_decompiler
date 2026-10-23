"""Declared-entry conditional/refused evidence stays honest through aggregation.

An authenticated entry premise is conditional proof, never unconditional
stable coverage: stage normalization, per-function accounting, aggregate
severity/coverage, and the surface merge gate must keep ``conditional`` and
``refused`` visible instead of collapsing them into stable/passed/clean
acceptance or uncollected noise.
"""
from types import SimpleNamespace

import pytest

from inertia.ir.scoped_function_ir_view import prove_scoped_function_ir_view_8616
from inertia.ir.segment_state import apply_x86_16_segment_state_artifact
from inertia.validation.declared_entry_premise import EntryPremiseStatus8616
from inertia.validation.tail_validation import (
    build_x86_16_tail_validation_surface,
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
    extract_x86_16_tail_validation_snapshot,
    persist_x86_16_tail_validation_snapshot,
    summarize_x86_16_tail_validation_records,
    x86_16_tail_validation_snapshot_passed,
)
from tests.ir.test_declared_entry_scoped_view import native_scope as native_scope

pytestmark = pytest.mark.decompiler


@pytest.fixture
def attached(native_scope):
    project, link, scope, proof = native_scope
    view = prove_scoped_function_ir_view_8616(link.artifact, link.boundary, proof, invocation_scope=scope)
    codegen = SimpleNamespace(_inertia_vex_ir_artifact=link.artifact)
    apply_x86_16_segment_state_artifact(project, codegen, invocation_scope=scope, scoped_view=view)
    return project, codegen


def _persisted_snapshot(codegen, result):
    """Run the canonical persist/extract transport for both tail stages."""
    info = {}
    for stage in ("structuring", "postprocess"):
        persist_x86_16_tail_validation_snapshot(
            function_info=info, codegen=codegen, stage=stage, validation=result
        )
    return extract_x86_16_tail_validation_snapshot(info)


def _record_from_snapshot(snapshot):
    return {
        "cod_file": "native.exe",
        "proc_name": "entry",
        "proc_kind": "NEAR",
        **snapshot,
    }


def test_conditional_premise_never_reports_unconditional_acceptance(attached):
    project, codegen = attached
    before = collect_x86_16_tail_validation_summary(project, codegen)
    result = compare_x86_16_tail_validation_summaries(before, before)
    assert result["status"] == EntryPremiseStatus8616.CONDITIONAL.value

    snapshot = _persisted_snapshot(codegen, result)
    assert snapshot["structuring"]["status"] == EntryPremiseStatus8616.CONDITIONAL.value
    assert snapshot["postprocess"]["status"] == EntryPremiseStatus8616.CONDITIONAL.value
    assert not x86_16_tail_validation_snapshot_passed(snapshot)

    summary = summarize_x86_16_tail_validation_records([_record_from_snapshot(snapshot)])
    for stage in ("structuring", "postprocess"):
        stage_summary = summary[stage]
        assert stage_summary["stable_count"] == 0
        assert stage_summary["changed_count"] == 0
        assert stage_summary["conditional_count"] == 1
        assert stage_summary["refused_count"] == 0
        assert stage_summary["coverage_count"] == 0
    assert summary["severity"] == EntryPremiseStatus8616.CONDITIONAL.value
    assert summary["conditional_count"] == 2
    assert summary["coverage_count"] == 0
    assert summary["function_status_counts"] == {"conditional": 1}
    assert summary["function_statuses"][0]["status"] == "conditional"
    assert summary["function_statuses"][0]["stage_statuses"] == {
        "postprocess": "conditional",
        "structuring": "conditional",
    }
    assert summary["passed_function_count"] == 0
    assert summary["conditional_function_count"] == 1
    assert summary["refused_function_count"] == 0

    surface = build_x86_16_tail_validation_surface(summary, scanned=1)
    assert surface["severity"] == EntryPremiseStatus8616.CONDITIONAL.value
    assert surface["merge_gate"] is False
    assert surface["coverage_count"] == 0
    assert surface["conditional_stage_total"] == 2
    assert surface["refused_stage_total"] == 0
    assert surface["conditional_function_count"] == 1
    assert surface["passed_function_count"] == 0
    assert "conditional" in surface["headline"]
    assert surface["consistency_issues"] == ()


def test_refused_mutated_condition_stays_visibly_refused(attached):
    project, codegen = attached
    before = collect_x86_16_tail_validation_summary(project, codegen)
    result = compare_x86_16_tail_validation_summaries(before, before)
    info = {}
    persist_x86_16_tail_validation_snapshot(
        function_info=info, codegen=codegen, stage="structuring", validation=result
    )
    stored = info["x86_16_tail_validation"]["structuring"]
    stored["entry_premise"]["payload"]["domain"]["entry_segment"] += 1
    snapshot = extract_x86_16_tail_validation_snapshot(info)

    refused_entry = snapshot["structuring"]
    assert refused_entry["status"] == EntryPremiseStatus8616.REFUSED.value
    assert not x86_16_tail_validation_snapshot_passed(snapshot)

    summary = summarize_x86_16_tail_validation_records([_record_from_snapshot(snapshot)])
    assert summary["severity"] != "clean"
    assert summary["function_statuses"][0]["status"] == EntryPremiseStatus8616.REFUSED.value
    assert summary["function_statuses"][0]["stage_statuses"]["structuring"] == "refused"
    assert summary["refused_function_count"] == 1
    assert summary["passed_function_count"] == 0

    surface = build_x86_16_tail_validation_surface(summary, scanned=1)
    assert surface["merge_gate"] is False
    assert surface["severity"] != "clean"
    assert surface["refused_function_count"] == 1
    assert surface["consistency_issues"] == ()


def test_forged_refused_entry_without_changed_flag_cannot_read_clean():
    """A damaged projection that dropped the changed flag is refused, not unknown."""
    refused_entry = {
        "status": EntryPremiseStatus8616.REFUSED.value,
        "premise_failure": "entry_premise_missing_or_invalid",
    }
    record = _record_from_snapshot({"structuring": dict(refused_entry), "postprocess": dict(refused_entry)})
    summary = summarize_x86_16_tail_validation_records([record])
    for stage in ("structuring", "postprocess"):
        assert summary[stage]["refused_count"] == 1
        assert summary[stage]["stable_count"] == 0
        assert summary[stage]["coverage_count"] == 0
    assert summary["severity"] == EntryPremiseStatus8616.REFUSED.value
    assert summary["function_statuses"][0]["status"] == "refused"
    surface = build_x86_16_tail_validation_surface(summary, scanned=1)
    assert surface["merge_gate"] is False
    assert surface["severity"] != "clean"
    assert surface["consistency_issues"] == ()


def test_forged_stable_status_beside_premise_stays_conditional():
    """A retained premise receipt blocks unconditional stable/passed claims."""
    entry = {
        "changed": False,
        "status": "stable",
        "entry_premise": {"status": "conditional", "payload": {}, "sha256": "0" * 64},
    }
    record = _record_from_snapshot({"structuring": dict(entry), "postprocess": dict(entry)})
    summary = summarize_x86_16_tail_validation_records([record])
    assert summary["structuring"]["conditional_count"] == 1
    assert summary["structuring"]["stable_count"] == 0
    assert summary["severity"] == EntryPremiseStatus8616.CONDITIONAL.value
    surface = build_x86_16_tail_validation_surface(summary, scanned=1)
    assert surface["merge_gate"] is False
    assert surface["consistency_issues"] == ()


@pytest.mark.parametrize(
    ("stage_entry", "expected_stage_status", "expected_severity", "expected_gate"),
    [
        ({"changed": False, "status": "stable"}, "passed", "clean", True),
        ({"changed": True, "status": "changed", "verdict": "changed: helper"}, "changed", "changed", False),
        ({"mode": "live_out"}, "unknown", "unknown", False),
    ],
)
def test_legacy_status_semantics_unchanged(stage_entry, expected_stage_status, expected_severity, expected_gate):
    record = _record_from_snapshot({"structuring": dict(stage_entry), "postprocess": dict(stage_entry)})
    summary = summarize_x86_16_tail_validation_records([record])
    assert summary["function_statuses"][0]["status"] == expected_stage_status
    assert summary["severity"] == expected_severity
    surface = build_x86_16_tail_validation_surface(summary, scanned=1)
    assert surface["merge_gate"] is expected_gate
    assert surface["consistency_issues"] == ()


def test_uncollected_records_keep_current_semantics():
    record = {"cod_file": "prog.exe", "proc_name": "sub_1", "proc_kind": "NEAR"}
    summary = summarize_x86_16_tail_validation_records([record])
    assert summary["severity"] == "uncollected"
    assert summary["function_statuses"][0]["status"] == "uncollected"
    surface = build_x86_16_tail_validation_surface(summary, scanned=1)
    assert surface["merge_gate"] is False


@pytest.mark.parametrize("other,expected", [
    ({"status": "unknown", "changed": False}, "unknown"),
    (None, "partial"),
    ({"status": "refused", "changed": True}, "refused"),
    ({"status": "changed", "changed": True}, "changed"),
])
def test_conditional_evidence_cannot_mask_incomplete_or_changed_stage(other, expected):
    record = _record_from_snapshot({
        "structuring": {"status": "conditional", "changed": False},
        "postprocess": other,
    })
    summary = summarize_x86_16_tail_validation_records([record])
    assert summary["severity"] == expected
    assert summary["postprocess"]["stable_count"] == 0
    surface = build_x86_16_tail_validation_surface(summary, scanned=1)
    assert not surface["merge_gate"]
    assert surface["consistency_issues"] == ()
    assert surface["consistency_issues"] == ()
