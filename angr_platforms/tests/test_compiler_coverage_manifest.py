"""Coverage inventories must not silently change scope or compiler settings."""

import json
from pathlib import Path

import pytest

from scripts.compiler_coverage_manifest import ScopeStatus, load_manifest


def _payload():
    return {
        "schema": 1,
        "profile": {"id": "test", "compiler": "MSC6", "flags": [], "memory_model": None},
        "scope": {"admitted": ["calls.direct"], "later": [], "excluded": [], "undecided": []},
        "cases": [{"id": "calls", "construct": "function_pointers", "obligations": ["calls.direct"]}],
    }


def _load(tmp_path, payload):
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return load_manifest(path)


def test_empty_optional_groups_and_default_options_are_valid(tmp_path):
    manifest = _load(tmp_path, _payload())
    assert manifest.compiler_flags == ()
    assert manifest.memory_model is None
    assert manifest.features[0].status is ScopeStatus.ADMITTED
    assert manifest.select(obligation="calls.direct") == manifest.cases


def test_compiler_option_sequence_is_preserved_including_repetitions(tmp_path):
    payload = _payload()
    payload["profile"]["flags"] = ["/Os", "/Ot", "/Os"]
    assert _load(tmp_path, payload).compiler_flags == ("/Os", "/Ot", "/Os")


@pytest.mark.parametrize("schema", [True, 0, 2, "1", None])
def test_invalid_schema_is_rejected(tmp_path, schema):
    payload = _payload()
    payload["schema"] = schema
    with pytest.raises(ValueError, match="schema"):
        _load(tmp_path, payload)


@pytest.mark.parametrize("fault", [
    "unknown_field", "multiple_statuses", "duplicate_feature", "duplicate_case",
    "unknown_obligation", "missing_witness", "empty_obligations", "unsafe_construct",
])
def test_invalid_inventory_is_rejected(tmp_path, fault):
    payload = _payload()
    if fault == "unknown_field":
        payload["extra"] = True
    elif fault == "multiple_statuses":
        payload["scope"]["later"] = ["calls.direct"]
    elif fault == "duplicate_feature":
        payload["scope"]["admitted"].append("calls.direct")
    elif fault == "duplicate_case":
        payload["cases"].append(payload["cases"][0].copy())
    elif fault == "unknown_obligation":
        payload["cases"][0]["obligations"] = ["unknown"]
    elif fault == "missing_witness":
        payload["scope"]["admitted"].append("calls.indirect")
    elif fault == "empty_obligations":
        payload["cases"][0]["obligations"] = []
    else:
        payload["cases"][0]["construct"] = "../escape"
    with pytest.raises(ValueError):
        _load(tmp_path, payload)


def test_unknown_selection_cannot_silently_run_no_tests(tmp_path):
    manifest = _load(tmp_path, _payload())
    with pytest.raises(ValueError, match="No admitted cases"):
        manifest.select(case="missing")
    with pytest.raises(ValueError, match="No admitted cases"):
        manifest.select(obligation="missing")


def test_repository_inventory_has_candidate_witnesses():
    root = Path(__file__).resolve().parents[2]
    manifest = load_manifest(root / "examples/compiler_coverage/pilot.json")
    for case in manifest.cases:
        assert (root / "examples/msc6_constructs" / f"{case.construct}.c").is_file()
