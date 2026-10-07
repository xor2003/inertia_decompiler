"""Matrix planning cannot masquerade as receipt-backed execution evidence."""

import hashlib
import json
from pathlib import Path

import pytest

from tools.compiler_toolchain.compiler_coverage_matrix import audit_matrix
from tools.compiler_toolchain.compiler_profile import resolve_case_toolchain
from tools.compiler_toolchain.tests.test_compiler_coverage_profile import _msc51_record, _registry

pytestmark = pytest.mark.compiler_toolchain


def _matrix(tmp_path: Path) -> tuple[Path, dict]:
    source = tmp_path / "sample.c"
    source.write_text("int sample(void) { return 255; }\n")
    profiles = ["msc51-small"]
    matrix = {
        "schema": "coverage-matrix-1",
        "profiles": [{"id": profiles[0], "compiler": "msc51", "config_evidence": "verified",
                      "receipt": "configuration.json"}],
        "sources": [{"id": "sample", "path": "sample.c", "state": "existing",
                     "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                     "kind": "runtime_case", "profiles": profiles,
                     "source_features": ["return.value"], "roundtrip": "not_attempted"}],
        "cells": [{"id": "value", "scope": "admitted", "witness": "sample",
                   "profiles": profiles, "covers": ["return.value"],
                   "emitted_evidence": "unverified", "roundtrip": "not_attempted"}],
        "deferred": {"later": [], "excluded": [], "undecided": []},
        "first_batch": {"sources": ["sample"], "baseline_sources": ["sample"],
                        "directed_sources": [], "csmith_sources": [], "profiles": profiles,
                        "subtotals": {"baseline_existing": 1, "directed_additions": 0, "csmith": 0},
                        "denominator": 1},
        "summary": {"sources_total": 1, "sources_existing": 1, "sources_planned_not_implemented": 0,
                    "sources_generated_retained": 0, "runtime_sources": 1, "compile_probes": 0,
                    "first_batch_cases": 1, "ms_borland_case_pairs": 1,
                    "watcom_case_pairs_not_started": 0, "cells": 1,
                    "admitted_cells": 1, "undecided_cells": 0},
    }
    path = tmp_path / "matrix.json"
    return path, matrix


def _audit(path: Path, matrix: dict):
    path.write_text(json.dumps(matrix))
    return audit_matrix(path, root=path.parent)


def _evidence(tmp_path: Path, matrix: dict) -> None:
    """Create a synthetic existing-runner receipt, never native acceptance."""
    function = {"returncode": 0, "tail_validation_status": "passed", "asm_fallback": False,
                "timeout": False, "tail_validation_changed": False, "tail_validation_uncollected": False}
    profile = {"fallback_rebuild": {"functions": ["sample"],
                                   "function_debug": [["sample", None, None, function]],
                                   "source_contracts_passed": True}}
    report = [{"name": "sample", "build_ok": True, "run_ok": True,
               "decompile_ok": True, "decompile_skipped": False, "decompile_recompile_ok": True,
               "decompile_run_ok": True, "run_exit_code": 255, "decompile_run_exit_code": 255,
               "run_stdout": "", "decompile_run_stdout": "", "decompile_profile": json.dumps(profile)}]
    (tmp_path / "report.json").write_text(json.dumps(report))
    registry = _registry(tmp_path, [_msc51_record(tmp_path / "msc51")])
    matrix["profiles"][0]["receipt"] = registry.name
    toolchain = resolve_case_toolchain("msc51-small", evidence_path=registry)
    receipt = {"schema": 1, "case": "sample", "outcome": "passed", "returncode": 0,
               "report": str(tmp_path / "report.json"), "compiler_profile": toolchain.to_dict(),
               "inputs": {"source": {"sha256": matrix["sources"][0]["sha256"],
                                      "path": str(tmp_path / "sample.c")}},
               "implementation_unchanged": True, "environment_unchanged": True}
    (tmp_path / "coverage-result.json").write_text(json.dumps(receipt))
    artifact = tmp_path / "mechanism.json"
    artifact.write_text('{"observation": "test-only return mechanism"}')
    matrix["cells"][0].update(
        roundtrip="passed", emitted_evidence="verified", evidence=[{
            "profile": "msc51-small", "receipt": "coverage-result.json",
            "observed_mechanism": "synthetic reviewed return observation",
            "mechanism_artifact": "mechanism.json", "mechanism_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        }],
    )


def test_existing_frozen_matrix_is_consistent() -> None:
    root = Path(__file__).resolve().parents[3]
    audit = audit_matrix(root / "examples/compiler_coverage/coverage-matrix.json", root=root)
    assert audit.passed, audit.issues
    assert audit.counts["first_batch_cases"] == 16


@pytest.mark.parametrize("section", ["sources", "cells", "profiles"])
def test_duplicate_ids_cannot_hide_a_row(tmp_path, section):
    path, matrix = _matrix(tmp_path)
    matrix[section].append(dict(matrix[section][0]))
    audit = _audit(path, matrix)
    assert not audit.passed
    assert "duplicate ID" in audit.issues[0].reason


def test_changed_source_bytes_refuse_stale_hash(tmp_path):
    path, matrix = _matrix(tmp_path)
    (tmp_path / "sample.c").write_text("int sample(void) { return 0; }\n")
    audit = _audit(path, matrix)
    assert not audit.passed
    assert any("source hash drift" in issue.reason for issue in audit.issues)


def test_partition_overlap_is_refused(tmp_path):
    path, matrix = _matrix(tmp_path)
    matrix["deferred"]["later"] = ["return.value"]
    assert not _audit(path, matrix).passed


def test_repeated_profile_cannot_inflate_case_denominators(tmp_path):
    path, matrix = _matrix(tmp_path)
    matrix["sources"][0]["profiles"] = ["msc51-small", "msc51-small"]
    matrix["summary"]["ms_borland_case_pairs"] = 2
    assert not _audit(path, matrix).passed


def test_missing_planned_source_is_valid_planning(tmp_path):
    path, matrix = _matrix(tmp_path)
    matrix["sources"][0].update(state="planned_not_implemented", path="future.c", sha256=None)
    matrix["summary"].update(sources_existing=0, sources_planned_not_implemented=1)
    assert _audit(path, matrix).passed


def test_passed_cell_cannot_use_planner_description_as_emission_proof(tmp_path):
    path, matrix = _matrix(tmp_path)
    matrix["cells"][0].update(roundtrip="passed", desired_emitted="return instruction")
    audit = _audit(path, matrix)
    assert not audit.passed
    assert any("lacks verified emitted mechanism" in issue.reason for issue in audit.issues)


def test_recorded_failures_do_not_require_a_passing_receipt(tmp_path):
    path, matrix = _matrix(tmp_path)
    matrix["cells"][0]["roundtrip"] = "timed_out"
    assert _audit(path, matrix).passed


def test_compatible_receipt_allows_progress_beyond_initial_state(tmp_path):
    path, matrix = _matrix(tmp_path)
    _evidence(tmp_path, matrix)
    assert _audit(path, matrix).passed


@pytest.mark.parametrize("corruption", ["missing_receipt", "source_identity", "profile", "report",
                                        "unstable", "mechanism_hash", "configuration", "missing_profile"])
def test_earned_status_refuses_corrupted_or_incomplete_evidence(tmp_path, corruption):
    path, matrix = _matrix(tmp_path)
    _evidence(tmp_path, matrix)
    receipt_path = tmp_path / "coverage-result.json"
    receipt = json.loads(receipt_path.read_text())
    if corruption == "missing_receipt":
        receipt_path.unlink()
    elif corruption == "source_identity":
        receipt["inputs"]["source"]["sha256"] = "wrong"
    elif corruption == "profile":
        receipt["compiler_profile"]["profile_id"] = "wrong"
    elif corruption == "report":
        report_path = tmp_path / "report.json"
        report = json.loads(report_path.read_text())
        report[0]["decompile_run_exit_code"] = 1
        report_path.write_text(json.dumps(report))
    elif corruption == "unstable":
        receipt["implementation_unchanged"] = False
    elif corruption == "mechanism_hash":
        (tmp_path / "mechanism.json").write_text("changed")
    elif corruption == "configuration":
        matrix["profiles"][0]["config_evidence"] = "unverified"
    else:
        matrix["cells"][0]["evidence"] = []
    if corruption != "missing_receipt":
        receipt_path.write_text(json.dumps(receipt))
    assert not _audit(path, matrix).passed


@pytest.mark.parametrize("field", ["source_path", "case"])
def test_receipt_must_describe_the_selected_source(tmp_path, field):
    path, matrix = _matrix(tmp_path)
    _evidence(tmp_path, matrix)
    receipt_path = tmp_path / "coverage-result.json"
    receipt = json.loads(receipt_path.read_text())
    if field == "case":
        receipt["case"] = "other"
    else:
        receipt["inputs"]["source"]["path"] = str(tmp_path / "other.c")
    receipt_path.write_text(json.dumps(receipt))
    assert not _audit(path, matrix).passed


@pytest.mark.parametrize("corruption", ["empty", "tool_drift", "model"])
def test_verified_label_cannot_replace_real_configuration_evidence(tmp_path, corruption):
    path, matrix = _matrix(tmp_path)
    _evidence(tmp_path, matrix)
    if corruption == "empty":
        (tmp_path / "toolchains.json").write_text("{}")
    elif corruption == "tool_drift":
        (tmp_path / "msc51/bin/CL.EXE").write_bytes(b"changed compiler")
    else:
        matrix["profiles"][0]["memory_model"] = "large"
    assert not _audit(path, matrix).passed


def test_compile_probe_does_not_become_a_runtime_roundtrip(tmp_path):
    path, matrix = _matrix(tmp_path)
    _evidence(tmp_path, matrix)
    matrix["sources"][0]["kind"] = "compile_probe"
    matrix["summary"].update(compile_probes=1, runtime_sources=0, ms_borland_case_pairs=0)
    audit = _audit(path, matrix)
    assert not audit.passed
    assert any("compile-probe evidence requires its own contract" in issue.reason for issue in audit.issues)


def test_empty_profile_set_cannot_vacuously_accept_an_earned_cell(tmp_path):
    path, matrix = _matrix(tmp_path)
    matrix["cells"][0].update(roundtrip="passed", emitted_evidence="verified", profiles=[], evidence=[])
    audit = _audit(path, matrix)
    assert not audit.passed
    assert any("nonempty distinct profile evidence" in issue.reason for issue in audit.issues)
