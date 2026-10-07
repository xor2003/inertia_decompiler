"""Saved comparator report accounting and evidence boundary regressions."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.comparator.comparator_refusal_report import ReportShapeError, build_report, main

pytestmark = pytest.mark.ssa_z3


def _document(root: str = "shared", *, reason: str = "mapping_missing") -> dict[str, object]:
    """Supply a minimal structurally valid saved comparator report."""
    return {"requested_functions": [root], "results": [
        {"function": {"name": root}, "status": "refused", "reason": reason,
         "additional_proof_attempts": {"calls": {"status": "refused", "reason": "block_limit"}}}]}


def _save(tmp_path: Path, name: str, document: dict[str, object]) -> Path:
    """Write an isolated comparison fixture."""
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_shared_roots_across_targets_remain_distinct(tmp_path: Path) -> None:
    """An aggregate lane counts two qualified functions, not one name."""
    first = _save(tmp_path, "first.json", _document())
    second = _save(tmp_path, "second.json", _document())
    report = build_report([first, second])
    assert report["requested"] == report["top"]["unique_functions"] == 2
    assert report["top"]["histogram"] == {"mapping_missing": 2}
    assert report["lanes"]["calls"]["unique_functions"] == 2
    assert report["status"] == {"refused": 2}
    assert all(target["top"]["unique_functions"] == 1 for target in report["targets"])
    assert report["targets"][0]["functions"][0]["source"] == _document()["results"][0]


def test_nested_explicit_details_and_unknown_retry_are_retained(tmp_path: Path) -> None:
    """Unknown lanes and statuses are diagnosed without parsing reason prose."""
    document = _document()
    row = document["results"][0]
    row["detail"] = {"blocker": {"side": "candidate", "root": "nested_root",
                                  "blocking_callee": "known_callee", "source_address": 123,
                                  "exhausted_limit": 64}}
    row["additional_proof_attempts"]["future_lane"] = {
        "status": "new_verdict", "reason": "call_target_unmapped:0xbeef",
        "detail": {"blocker": {"side": "oracle", "source_address": "0x22"}}}
    report = build_report([_save(tmp_path, "one.json", document)])
    function = report["targets"][0]["functions"][0]
    assert function["top"]["blocker"] == {"side": "candidate", "root": "nested_root",
        "blocking_callee": "known_callee", "source_address": 123, "exhausted_limit": 64}
    retry = function["attempts"]["future_lane"]
    assert retry["lane"] == "unknown" and retry["lane_name"] == "future_lane"
    assert retry["status"] is None and retry["raw_status"] == "new_verdict"
    assert retry["blocker"]["side"] == "oracle"
    assert retry["blocker"]["source_address"] == "0x22"
    assert retry["blocker"]["blocking_callee"] is None
    assert report["lanes"]["future_lane"]["histogram"] == {"call_target_unmapped:0xbeef": 1}


def test_missing_details_do_not_infer_from_reason(tmp_path: Path) -> None:
    """A reason containing an address is not structured address evidence."""
    document = _document(reason="call_target_unmapped:0xbeef")
    row = document["results"][0]
    row["additional_proof_attempts"] = {}
    report = build_report([_save(tmp_path, "one.json", document)])
    assert report["targets"][0]["functions"][0]["top"]["blocker"] == {
        "side": None, "root": "shared", "blocking_callee": None,
        "source_address": None, "exhausted_limit": None}
    assert report["lanes"] == {}


def test_return_proof_failure_supplies_structured_callee_evidence(tmp_path: Path) -> None:
    """The existing call producer's typed failure supplies known blocker fields."""
    document = _document()
    attempt = document["results"][0]["additional_proof_attempts"]["calls"]
    attempt["reason"] = "call_return_target_mismatch"
    attempt["return_proof_failure"] = {
        "side": "candidate", "callee": "leaf", "callsite": "0x12345000",
        "call_block": "0x12344ff0", "target": "0x12345600", "fallthrough": "0x12345005",
        "status": "counterexample", "selector": None, "solver_result": {"status": "failed"},
    }
    report = build_report([_save(tmp_path, "one.json", document)])
    blocker = report["targets"][0]["functions"][0]["attempts"]["calls"]["blocker"]
    assert blocker == {"side": "candidate", "root": "shared", "blocking_callee": "leaf",
                       "source_address": "0x12345000", "exhausted_limit": None}
    assert report["targets"][0]["functions"][0]["source"] == document["results"][0]


def test_unlabeled_return_failure_retains_missing_callee(tmp_path: Path) -> None:
    """A producer's empty label cannot be replaced by a target-derived guess."""
    document = _document()
    document["results"][0]["return_proof_failure"] = {
        "side": None, "callee": "", "callsite": 4096, "target": "0xbeef",
    }
    report = build_report([_save(tmp_path, "one.json", document)])
    blocker = report["targets"][0]["functions"][0]["top"]["blocker"]
    assert blocker["side"] is None and blocker["blocking_callee"] is None
    assert blocker["source_address"] == 4096


@pytest.mark.parametrize("proof", [[], {"callsite": []}, {"callee": []}])
def test_malformed_return_failure_cannot_supply_evidence(tmp_path: Path, proof: object) -> None:
    """Malformed structured producer fields fail visibly instead of disappearing."""
    document = _document()
    document["results"][0]["return_proof_failure"] = proof
    with pytest.raises(ReportShapeError):
        build_report([_save(tmp_path, "one.json", document)])


def test_legacy_rows_cannot_supply_missing_requested_identities(tmp_path: Path) -> None:
    """Legacy accounting retains every row but cannot claim request completeness."""
    document = _document()
    document.pop("requested_functions")
    report = build_report([_save(tmp_path, "legacy.json", document)])
    assert report["reported_functions"] == report["top"]["unique_functions"] == 1
    assert report["requested"] is None
    assert report["targets"][0]["request_accounting"] == "requested_roots_unavailable"


@pytest.mark.parametrize("change", [
    lambda doc: doc.update(results=[]),
    lambda doc: doc["results"].append(doc["results"][0]),
    lambda doc: doc.update(requested_functions=["shared", "shared"]),
    lambda doc: doc["results"][0].pop("function"),
    lambda doc: doc["results"][0].pop("status"),
    lambda doc: doc["results"][0].update(additional_proof_attempts={"calls": None}),
    lambda doc: doc["results"][0].update(detail={"blocker": {"source_address": []}}),
])
def test_invalid_rows_fail_accounting(tmp_path: Path, change: object) -> None:
    """No malformed or missing root/attempt may disappear from aggregates."""
    document = _document()
    change(document)
    with pytest.raises(ReportShapeError):
        build_report([_save(tmp_path, "bad.json", document)])


def test_cli_fails_without_writing_partial_report(tmp_path: Path) -> None:
    """Malformed inputs return nonzero and leave the output untouched."""
    source = _save(tmp_path, "bad.json", {"requested_functions": ["lost"], "results": []})
    destination = tmp_path / "report.json"
    with pytest.raises(SystemExit) as error:
        main([str(source), "--output", str(destination)])
    assert error.value.code == 2 and not destination.exists()
