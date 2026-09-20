"""Check durable COD scan outcomes without expensive live decompilations."""

import json
import subprocess

import pytest

from scripts import cod_stability_sweep as sweep


@pytest.mark.parametrize(("returncode", "stdout", "outcome"), [
    (0, "void f(void) {}", sweep.Outcome.CLI_OK_UNVERIFIED),
    (0, "", sweep.Outcome.NO_OUTPUT),
    (3, "partial C", sweep.Outcome.FAILED),
    (-11, "", sweep.Outcome.FAILED),
])
def test_attempt_preserves_success_and_failure(monkeypatch, tmp_path, returncode, stdout, outcome):
    item = sweep.Procedure("fixture.COD", "f", "NEAR", "input-hash")
    monkeypatch.setattr(sweep, "run_captured_subprocess_tree", lambda *args, **kwargs:
                        subprocess.CompletedProcess(args[0], returncode, stdout, "diagnostics"))
    assert not sweep.completed(tmp_path, item)
    assert sweep.attempt(tmp_path, item, 1, 768) == outcome
    assert sweep.completed(tmp_path, item)
    assert (tmp_path / f"{item.key}.c").read_text() == stdout
    (tmp_path / f"{item.key}.log").write_text("corrupted")
    with pytest.raises(ValueError, match="Missing or changed"):
        sweep.completed(tmp_path, item)


def test_timeout_is_durable_not_pending(monkeypatch, tmp_path):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 60, output=b"partial", stderr=b"timeout evidence")

    monkeypatch.setattr(sweep, "run_captured_subprocess_tree", timeout)
    item = sweep.Procedure("fixture.COD", "f", "FAR", "hash")
    assert sweep.attempt(tmp_path, item, 1, 768) == sweep.Outcome.TIMED_OUT
    assert sweep.completed(tmp_path, item)
    assert (tmp_path / f"{item.key}.log").read_text() == "timeout evidence"


def test_inventory_handles_case_and_duplicate_basenames(tmp_path):
    for directory, filename in (("one", "file.COD"), ("two", "file.cod")):
        path = tmp_path / directory / filename
        path.parent.mkdir()
        path.write_text("f\tPROC NEAR\n\t*** 000000 c3 \tret\nf\tENDP\n")
    entries = sweep.inventory(tmp_path)
    assert len(entries) == 2
    assert entries[0].key != entries[1].key


def test_inventory_refuses_empty_file(tmp_path):
    (tmp_path / "empty.COD").write_text("no procedures")
    with pytest.raises(ValueError, match="inventory is incomplete"):
        sweep.inventory(tmp_path)


def test_resume_refuses_changed_contract(tmp_path):
    item = sweep.Procedure("fixture.COD", "f", "NEAR", "hash")
    sweep.prepare(tmp_path, [item], 30, 768)
    sweep.prepare(tmp_path, [item], 30, 768)
    with pytest.raises(ValueError, match="changed"):
        sweep.prepare(tmp_path, [item], 31, 768)


def test_identity_changes_with_source_hash():
    first = sweep.Procedure("fixture.COD", "f", "NEAR", "before")
    second = sweep.Procedure("fixture.COD", "f", "NEAR", "after")
    assert first.key != second.key


@pytest.mark.parametrize("status", ["passed", "failed", "changed", "unknown", "uncollected"])
def test_tail_evidence_retains_structured_function_status(status):
    payload = {"summary": {"function_statuses": [{"proc_name": "f", "status": status}]}}
    stderr = "diagnostic\n@@INERTIA_TAIL_VALIDATION@@ " + json.dumps(payload)
    evidence = sweep.tail_evidence(stderr, "f")
    assert evidence.status.value == status
    assert evidence.payload == payload


@pytest.mark.parametrize("stderr", [
    "whole-tail validation passed", "", "@@INERTIA_TAIL_VALIDATION@@ {bad",
    '@@INERTIA_TAIL_VALIDATION@@ {"summary": {}}',
    '@@INERTIA_TAIL_VALIDATION@@ {"summary": {"function_statuses": '
    '[{"proc_name":"another", "status":"passed"}]}}',
    '@@INERTIA_TAIL_VALIDATION@@ {"summary": {"function_statuses": '
    '[{"proc_name":"f", "status":"new_unrecognized_status"}]}}',
])
def test_tail_evidence_never_infers_success(stderr):
    assert sweep.tail_evidence(stderr, "f").status.value in {"missing", "invalid"}


def test_tail_evidence_refuses_ambiguous_multiple_payloads():
    payload = {"summary": {"function_statuses": [{"proc_name": "f", "status": "passed"}]}}
    line = "@@INERTIA_TAIL_VALIDATION@@ " + json.dumps(payload)
    assert sweep.tail_evidence(line + "\n" + line, "f").status.value == "invalid"


def test_failed_cli_retains_passed_tail_evidence(monkeypatch, tmp_path):
    payload = {"summary": {"function_statuses": [{"proc_name": "f", "status": "passed"}]}}
    stderr = "@@INERTIA_TAIL_VALIDATION@@ " + json.dumps(payload)
    monkeypatch.setattr(sweep, "run_captured_subprocess_tree", lambda *args, **kwargs:
                        subprocess.CompletedProcess(args[0], 4, "partial C", stderr))
    item = sweep.Procedure("fixture.COD", "f", "NEAR", "hash")
    assert sweep.attempt(tmp_path, item, 1, 768) == sweep.Outcome.FAILED
    record = json.loads((tmp_path / f"{item.key}.json").read_text())
    assert record["validation"]["status"] == "passed"
    assert record["compilation"] == "not_checked"
