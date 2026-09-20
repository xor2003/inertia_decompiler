"""Manifest execution must preserve selection and expose incomplete coverage."""

import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from scripts import compiler_coverage_suite as suite
from scripts.compiler_coverage_result import CoverageOutcome
from scripts.msc6_memory_model import MSCMemoryModel

MANIFEST = Path(__file__).resolve().parents[2] / "examples/compiler_coverage/pilot.json"


def test_obligation_selects_only_its_candidates(tmp_path, monkeypatch):
    execute = Mock(return_value=CoverageOutcome.PASSED)
    monkeypatch.setattr(suite, "run_existing_case", execute)
    output = tmp_path / "run"
    assert suite.run_suite(MANIFEST, output, obligation="calls.indirect")
    execute.assert_called_once_with("function_pointers", output / "case-000", timeout=600, memory_model=MSCMemoryModel.SMALL)
    summary = json.loads((output / "summary.json").read_text())
    assert summary["selected"] == summary["completed"] == 1
    assert summary["feature_coverage_verified"] is False


def test_failures_do_not_disappear_or_prevent_other_cases(tmp_path, monkeypatch):
    execute = Mock(side_effect=[CoverageOutcome.TIMED_OUT, OSError("launch"),
                               CoverageOutcome.PASSED, CoverageOutcome.VALIDATION_FAILED])
    monkeypatch.setattr(suite, "run_existing_case", execute)
    output = tmp_path / "run"
    assert not suite.run_suite(MANIFEST, output)
    summary = json.loads((output / "summary.json").read_text())
    assert summary["selected"] == summary["completed"] == 4
    assert [row["outcome"] for row in summary["cases"]] == [
        "timed_out", "harness_failed", "passed", "validation_failed",
    ]


def test_unapplied_compiler_profile_is_rejected(tmp_path, monkeypatch):
    payload = json.loads(MANIFEST.read_text())
    payload["profile"]["flags"] = ["/Os"]
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(payload))
    execute = Mock()
    monkeypatch.setattr(suite, "run_existing_case", execute)
    output = tmp_path / "run"
    with pytest.raises(ValueError, match="Adapter currently supports"):
        suite.run_suite(path, output)
    execute.assert_not_called()
    assert not output.exists()


def test_rerun_only_reexecutes_failures(tmp_path, monkeypatch):
    execute = Mock(side_effect=[CoverageOutcome.PASSED, CoverageOutcome.TIMED_OUT,
                               CoverageOutcome.PASSED, CoverageOutcome.BEHAVIOR_FAILED])
    monkeypatch.setattr(suite, "run_existing_case", execute)
    first = tmp_path / "first"
    assert not suite.run_suite(MANIFEST, first)
    execute.reset_mock(side_effect=True)
    execute.return_value = CoverageOutcome.PASSED
    assert suite.run_suite(MANIFEST, tmp_path / "second", rerun_failed=first / "summary.json")
    assert [call.args[0] for call in execute.call_args_list] == ["pointer_memory", "function_pointers"]


@pytest.mark.parametrize("fault", ["hash", "duplicate", "incomplete", "unknown", "outcome", "definition", "all_passed"])
def test_invalid_rerun_refused_before_execution(tmp_path, monkeypatch, fault):
    execute = Mock(return_value=CoverageOutcome.TIMED_OUT)
    monkeypatch.setattr(suite, "run_existing_case", execute)
    first = tmp_path / "first"
    suite.run_suite(MANIFEST, first)
    report = first / "summary.json"
    payload = json.loads(report.read_text())
    if fault == "hash":
        payload["manifest_sha256"] = "changed"
    elif fault == "duplicate":
        payload["cases"][1] = payload["cases"][0]
    elif fault == "incomplete":
        payload["completed"] = 3
    elif fault == "unknown":
        payload["cases"][0]["case"] = "unknown"
    elif fault == "outcome":
        payload["cases"][0]["outcome"] = "looks_ok"
    elif fault == "definition":
        payload["cases"][0]["construct"] = "another"
    else:
        for row in payload["cases"]:
            row["outcome"] = "passed"
    report.write_text(json.dumps(payload))
    execute.reset_mock()
    with pytest.raises(ValueError):
        suite.run_suite(MANIFEST, tmp_path / "second", rerun_failed=report)
    execute.assert_not_called()
