"""Coverage inventories must not silently change scope or compiler settings."""

import json
from pathlib import Path

import pytest

from tools.compiler_toolchain.compiler_coverage_manifest import ScopeStatus, load_manifest


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


def _frozen_payload(tmp_path):
    source = tmp_path / "fixture_source.c"
    source.write_text("int main(void) { return 0; }", encoding="utf-8")
    import hashlib

    source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    root = Path(__file__).resolve().parents[3]
    source_relative = source.relative_to(root).as_posix()
    return {
        "schema": 2,
        "id": "frozen-test",
        "batch": "first",
        "budgets": {"case_seconds": 600, "stage_seconds": 120},
        "scope": {"admitted": ["calls.direct"], "later": [], "excluded": [], "undecided": []},
        "cases": [{
            "id": "calls@msc51-small",
            "construct": "fixture_source",
            "compiler_profile": "msc51-small",
            "obligations": ["calls.direct"],
            "source": {"id": "fixture_source", "path": source_relative, "sha256": source_sha},
            "expected": {"exit_code": 0, "stdout_contains": "checksum = ABCD"},
            "runtime_headers": [],
            "runtime_sources": [],
            "signature_catalogs": [],
            "generated": None,
        }],
    }


def test_frozen_manifest_records_complete_rows(tmp_path):
    manifest = _load(tmp_path, _frozen_payload(tmp_path))
    assert manifest.schema == 2
    assert manifest.manifest_id == "frozen-test"
    assert manifest.batch == "first"
    assert manifest.case_budget_seconds == 600
    assert manifest.stage_budget_seconds == 120
    case = manifest.cases[0]
    assert case.compiler_profile == "msc51-small"
    assert case.expected_exit_code == 0
    assert case.expected_stdout_contains == "checksum = ABCD"
    assert case.runtime_headers == case.runtime_sources == case.signature_catalogs == ()
    assert case.generated is None


@pytest.mark.parametrize("fault", [
    "bad_sha", "missing_field", "unstaged_name", "bad_exit_code",
    "case_budget_over", "stage_budget_over", "duplicate_id", "stem_mismatch",
    "header_collision", "missing_witness",
])
def test_frozen_manifest_rejects_unpinned_or_ambiguous_rows(tmp_path, fault):
    payload = _frozen_payload(tmp_path)
    case = payload["cases"][0]
    if fault == "bad_sha":
        case["source"]["sha256"] = "0" * 63 + "g"
    elif fault == "missing_field":
        del case["expected"]
    elif fault == "unstaged_name":
        case["runtime_sources"] = [{"name": "RUNTIMESOURCE.C", "path": "x.c", "sha256": "0" * 64}]
    elif fault == "bad_exit_code":
        case["expected"]["exit_code"] = "0"
    elif fault == "case_budget_over":
        payload["budgets"]["case_seconds"] = 601
    elif fault == "stage_budget_over":
        payload["budgets"]["stage_seconds"] = 121
    elif fault == "duplicate_id":
        payload["cases"].append(dict(case))
    elif fault == "stem_mismatch":
        case["construct"] = "other_stem"
    elif fault == "header_collision":
        case["runtime_headers"] = [
            {"name": "RT.H", "path": "a.h", "sha256": "0" * 64},
            {"name": "rt.h", "path": "b.h", "sha256": "1" * 64},
        ]
    else:
        payload["scope"]["admitted"].append("calls.indirect")
    with pytest.raises(ValueError):
        _load(tmp_path, payload)


@pytest.mark.parametrize("path", ["/etc/passwd", "../outside.c", r"C:\\outside.c"])
def test_frozen_manifest_rejects_non_repo_relative_source_paths(tmp_path, path):
    payload = _frozen_payload(tmp_path)
    payload["cases"][0]["source"]["path"] = path
    with pytest.raises(ValueError, match="repo-relative"):
        _load(tmp_path, payload)


def test_frozen_manifest_retains_generation_provenance(tmp_path):
    payload = _frozen_payload(tmp_path)
    case = payload["cases"][0]
    case["generated"] = {
        "seed": 2,
        "generator_revision": "35e702de01e158bc948a2024d0e187c1803d1ebb",
        "generator_sha256": "f75bbeaacab98f1048340db1462700d035dd1f7c03e3470e6beb010b1f0511eb",
        "generator_branch": "ms-c-dos (user fork)",
        "options": ["--max-funcs", "1", "--max-block-depth", "2"],
    }
    manifest = _load(tmp_path, payload)
    generated = manifest.cases[0].generated
    assert generated is not None
    assert generated.seed == 2
    assert generated.options == ("--max-funcs", "1", "--max-block-depth", "2")


def test_first16_frozen_manifest_pins_all_sixteen_rows():
    """The frozen denominator keeps every row's inputs hash-pinned on disk."""
    import hashlib

    root = Path(__file__).resolve().parents[3]
    manifest = load_manifest(root / "examples/compiler_coverage/first16.json")
    assert manifest.schema == 2
    assert manifest.manifest_id == "first16-frozen-20261006"
    assert manifest.case_budget_seconds is not None and manifest.case_budget_seconds <= 600
    assert manifest.stage_budget_seconds is not None and manifest.stage_budget_seconds <= 120
    assert len(manifest.cases) == 16
    profiles = {case.compiler_profile for case in manifest.cases}
    assert profiles == {"msc51-small", "bc31-small"}
    sources = {case.source.identifier for case in manifest.cases}
    assert sources == {
        "word_comparisons", "array_pointer_writes", "branches_loops", "call_composition",
        "struct_value_abi", "bitfield_neighbors", "multidim_alias", "csmith_seed2",
    }
    pinned: list[tuple[str, str]] = []
    for case in manifest.cases:
        assert case.source is not None
        pinned.append((case.source.path, case.source.sha256))
        pinned.extend((item.path, item.sha256)
                      for item in (*case.runtime_headers, *case.runtime_sources,
                                   *case.signature_catalogs))
    for path_text, expected in pinned:
        file_path = root / path_text
        assert file_path.is_file(), f"missing pinned input {path_text}"
        actual = hashlib.sha256(file_path.read_bytes()).hexdigest()
        assert actual == expected, f"{path_text} drifted from the frozen pin"
    csmith = [case for case in manifest.cases if case.construct == "csmith"]
    assert len(csmith) == 2
    for row in csmith:
        assert row.expected_exit_code == 0
        assert row.expected_stdout_contains == "checksum = 637A4628"
        assert len(row.runtime_headers) == 5
        assert [item.name for item in row.runtime_sources] == ["CSMRT.C"]
        assert len(row.signature_catalogs) == 2
        assert row.generated is not None and row.generated.seed == 2
    handwritten = [case for case in manifest.cases if case.construct != "csmith"]
    for row in handwritten:
        assert row.expected_exit_code == 255
        assert row.expected_stdout_contains is None
        assert row.runtime_headers == row.runtime_sources == ()
        assert len(row.signature_catalogs) == 1


def test_repository_inventory_has_candidate_witnesses():
    root = Path(__file__).resolve().parents[3]
    manifest = load_manifest(root / "examples/compiler_coverage/pilot.json")
    for case in manifest.cases:
        assert (root / "examples/msc6_constructs" / f"{case.construct}.c").is_file()


def test_large_manifest_selects_only_admitted_far_function_pointer_witness():
    root = Path(__file__).resolve().parents[3]
    manifest = load_manifest(root / "examples/compiler_coverage/large.json")
    statuses = {feature.identifier: feature.status for feature in manifest.features}

    assert statuses["pointer.far_function"] is ScopeStatus.ADMITTED
    assert statuses["pointer.far_data"] is ScopeStatus.LATER
    assert statuses["calls.pointer_return"] is ScopeStatus.LATER
    assert {case.identifier for case in manifest.cases} == {
        "large_global_calls", "large_function_pointers",
    }
    assert manifest.select(case="large_function_pointers") == manifest.select(
        obligation="pointer.far_function",
    )
    for deferred in ("pointer.far_data", "calls.pointer_return"):
        with pytest.raises(ValueError, match="No admitted cases"):
            manifest.select(obligation=deferred)
    with pytest.raises(ValueError, match="No admitted cases"):
        manifest.select(case="large_pointer_arguments")
