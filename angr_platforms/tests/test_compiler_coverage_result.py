"""Report acceptance must fail closed independently of legacy success booleans."""

import json

import pytest

from scripts.compiler_coverage_result import CoverageOutcome, classify_roundtrip_report, roundtrip_diagnostics


def test_diagnostics_retain_behavior_failure_without_dumping_profile():
    row = _row()
    row["decompile_run_exit_code"] = 5
    details = roundtrip_diagnostics([row])
    assert details["run_exit_code"] == 255
    assert details["decompile_run_exit_code"] == 5
    assert "decompile_profile" not in details


def test_legacy_aggregate_failure_does_not_hide_generated_c_compile_failure():
    row = _row()
    row["decompile_ok"] = False
    row["decompile_recompile_ok"] = False
    profile = json.loads(row["decompile_profile"])
    profile["fallback_rebuild"].update(decompile_ok=True, source_contracts_passed=True)
    row["decompile_profile"] = json.dumps(profile)
    assert classify_roundtrip_report([row], "sample", 1) is CoverageOutcome.RECOMPILE_FAILED


@pytest.mark.parametrize("reason,outcome", [
    ("validation_failed", CoverageOutcome.VALIDATION_FAILED),
    ("unknown_reason", CoverageOutcome.DECOMPILE_FAILED),
])
def test_failed_function_retains_structured_failure_reason(reason, outcome):
    row = _row()
    row["decompile_ok"] = False
    profile = json.loads(row["decompile_profile"])
    profile["fallback_rebuild"]["function_debug"][0][3].update(
        returncode=4, acceptance_reason=reason,
    )
    row["decompile_profile"] = json.dumps(profile)
    assert classify_roundtrip_report([row], "sample", 1) is outcome


@pytest.mark.parametrize("payload", [None, [], [{}, {}], [None]])
def test_malformed_report_has_compact_diagnostic(payload):
    assert "report_error" in roundtrip_diagnostics(payload)


def _row():
    profile = {
        "returncode": 0, "tail_validation_status": "clean", "asm_fallback": False,
        "timeout": False, "tail_validation_changed": False, "tail_validation_uncollected": False,
    }
    return {
        "name": "sample", "build_ok": True, "run_ok": True,
        "decompile_skipped": False, "decompile_ok": True, "decompile_recompile_ok": True,
        "decompile_run_ok": True, "run_exit_code": 255, "decompile_run_exit_code": 255,
        "run_stdout": "state=3\n", "decompile_run_stdout": "state=3\n",
        "decompile_profile": json.dumps({"fallback_rebuild": {
            "functions": ["f"], "function_debug": [["f", "f", "command", profile]],
        }}),
    }


def test_complete_roundtrip_is_accepted():
    assert classify_roundtrip_report([_row()], "sample", 0) is CoverageOutcome.PASSED


@pytest.mark.parametrize("field,outcome", [
    ("build_ok", CoverageOutcome.BUILD_FAILED),
    ("run_ok", CoverageOutcome.ORIGINAL_RUN_FAILED),
    ("decompile_ok", CoverageOutcome.DECOMPILE_FAILED),
    ("decompile_recompile_ok", CoverageOutcome.RECOMPILE_FAILED),
    ("decompile_run_ok", CoverageOutcome.BEHAVIOR_FAILED),
])
def test_stage_failures_remain_failures(field, outcome):
    row = _row()
    row[field] = False
    assert classify_roundtrip_report([row], "sample", 1) is outcome


@pytest.mark.parametrize("field,outcome", [
    ("build_ok", CoverageOutcome.BUILD_FAILED),
    ("run_ok", CoverageOutcome.ORIGINAL_RUN_FAILED),
])
def test_prior_failure_is_not_hidden_by_skipped_decompilation(field, outcome):
    row = _row()
    row[field] = False
    row["decompile_skipped"] = True
    assert classify_roundtrip_report([row], "sample", 1) is outcome


@pytest.mark.parametrize("attempt", [["f", "f", "command", None], ["f"], None])
def test_malformed_later_attempt_cannot_reuse_earlier_clean_result(attempt):
    row = _row()
    profile = json.loads(row["decompile_profile"])
    profile["fallback_rebuild"]["function_debug"].append(attempt)
    row["decompile_profile"] = json.dumps(profile)
    assert classify_roundtrip_report([row], "sample", 0) is CoverageOutcome.VALIDATION_FAILED


@pytest.mark.parametrize("functions", [["f", "f"], [""], [True]])
def test_invalid_function_inventory_is_not_validation_evidence(functions):
    row = _row()
    profile = json.loads(row["decompile_profile"])
    profile["fallback_rebuild"]["functions"] = functions
    row["decompile_profile"] = json.dumps(profile)
    assert classify_roundtrip_report([row], "sample", 0) is CoverageOutcome.VALIDATION_FAILED


@pytest.mark.parametrize("profile", [None, "{}", "not JSON", "[]", "null"])
def test_missing_validation_is_not_success(profile):
    row = _row()
    row["decompile_profile"] = profile
    assert classify_roundtrip_report([row], "sample", 0) is CoverageOutcome.VALIDATION_FAILED


@pytest.mark.parametrize("field,value", [
    ("tail_validation_status", "uncollected"), ("tail_validation_status", {}),
    ("asm_fallback", True), ("timeout", True), ("returncode", 4),
    ("tail_validation_changed", True), ("tail_validation_uncollected", True),
])
def test_final_function_evidence_cannot_be_hidden(field, value):
    row = _row()
    profile = json.loads(row["decompile_profile"])
    profile["fallback_rebuild"]["function_debug"][0][3][field] = value
    row["decompile_profile"] = json.dumps(profile)
    assert classify_roundtrip_report([row], "sample", 0) is CoverageOutcome.VALIDATION_FAILED


@pytest.mark.parametrize("field,value", [("decompile_run_exit_code", 1), ("decompile_run_stdout", "state=4\n")])
def test_different_observations_fail_even_with_success_flags(field, value):
    row = _row()
    row[field] = value
    assert classify_roundtrip_report([row], "sample", 0) is CoverageOutcome.BEHAVIOR_FAILED


def test_stale_wrong_missing_or_skipped_cases_cannot_pass():
    for payload in (None, [], [_row(), _row()], [{}]):
        assert classify_roundtrip_report(payload, "sample", 0) is CoverageOutcome.HARNESS_FAILED
    assert classify_roundtrip_report([_row()], "different", 0) is CoverageOutcome.HARNESS_FAILED
    assert classify_roundtrip_report([_row()], "sample", 1) is CoverageOutcome.HARNESS_FAILED
    row = _row()
    row["decompile_skipped"] = True
    assert classify_roundtrip_report([row], "sample", 0) is CoverageOutcome.NOT_ATTEMPTED
