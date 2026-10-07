"""Manifest execution must preserve selection and expose incomplete coverage."""

import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from tools.compiler_toolchain import compiler_coverage_suite as suite
from tools.compiler_toolchain.compiler_coverage_result import CoverageOutcome
from tools.compiler_toolchain.compiler_profile import (
    MSC6_AX_PROFILE_ID,
    CompilerIdentity,
    UnsupportedCompilerProfile,
)

MANIFEST = Path(__file__).resolve().parents[3] / "examples/compiler_coverage/pilot.json"


def _manifest(tmp_path, profile):
    payload = json.loads(MANIFEST.read_text())
    payload["profile"] = profile
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(payload))
    return path


def test_obligation_selects_only_its_candidates(tmp_path, monkeypatch):
    execute = Mock(return_value=CoverageOutcome.PASSED)
    monkeypatch.setattr(suite, "run_existing_case", execute)
    output = tmp_path / "run"
    assert suite.run_suite(MANIFEST, output, obligation="calls.indirect")
    execute.assert_called_once()
    call = execute.call_args
    assert call.args == ("function_pointers", output / "case-000")
    assert call.kwargs["timeout"] == 600
    profile = call.kwargs["compiler_profile"]
    assert profile.toolchain.profile_id == MSC6_AX_PROFILE_ID
    assert profile.toolchain.identity is CompilerIdentity.MSC6_AX
    summary = json.loads((output / "summary.json").read_text())
    assert summary["selected"] == summary["completed"] == 1
    assert summary["feature_coverage_verified"] is False
    assert summary["compiler_profile"]["profile_id"] == MSC6_AX_PROFILE_ID
    assert summary["compiler_profile"]["evidence_path"] is None


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


@pytest.mark.parametrize(
    "profile,message,evidence",
    [
        ({"id": "p", "compiler": "Microsoft C v6ax", "flags": ["/Os"], "memory_model": "small"},
         "do not match", None),
        ({"id": "p", "compiler": "Other C 99", "flags": ["/Od", "/AS"], "memory_model": "small"},
         "Unsupported compiler", None),
        ({"id": "p", "compiler": "Microsoft C v5.1", "flags": ["/Od", "/AS"], "memory_model": "small"},
         "registry unusable", "missing"),
    ],
)
def test_unapplied_compiler_profile_is_rejected(tmp_path, monkeypatch, profile, message, evidence):
    path = _manifest(tmp_path, profile)
    execute = Mock()
    monkeypatch.setattr(suite, "run_existing_case", execute)
    output = tmp_path / "run"
    with pytest.raises(UnsupportedCompilerProfile, match=message):
        suite.run_suite(
            path, output,
            profile_evidence=tmp_path / "absent.json" if evidence == "missing" else None,
        )
    execute.assert_not_called()
    assert not output.exists()


def _bc31_registry(tmp_path: Path) -> Path:
    """Write a minimal valid registry exposing one canonical bc31 profile."""
    import hashlib

    root = tmp_path / "bcc31"
    def pinned(dos_path: str, payload: bytes) -> dict[str, str]:
        host = root.joinpath(*dos_path[3:].split("\\"))
        host.parent.mkdir(parents=True, exist_ok=True)
        host.write_bytes(payload)
        return {"dos_path": dos_path, "sha256": hashlib.sha256(payload).hexdigest()}

    record = {
        "id": "bc31-small",
        "probe_id": "bcpp31-small",
        "aliases": ["bcpp31-small"],
        "dependency_group": "bcpp31",
        "compiler": "Borland C++ 3.1",
        "memory_model": "small",
        "declared_flags": ["-Od", "-ms"],
        "compile_backend": "dosbox",
        "run_backend": "kvikdos",
        "toolchain_root": str(root),
        "tools": {
            "compiler": pinned("e:\\BIN\\BCC.EXE", b"bcc"),
            "linker": pinned("e:\\BIN\\TLINK.EXE", b"tlink"),
        },
        "libraries": [pinned("e:\\LIB\\CS.LIB", b"cs")],
        "compiler_path_dos": ["e:\\BIN"],
        "linker_path_dos": ["e:\\BIN"],
        "compiler_environment": [["INCLUDE", "e:\\INCLUDE;c:\\"], ["LIB", "e:\\LIB"]],
        "linker_environment": [["LIB", "e:\\LIB"]],
        "compile_arguments": ["-Od", "-ms", "-c", "-oc:\\{obj}", "c:\\{source}"],
        "cod_argument": None,
        "link_argument": "e:\\LIB\\C0S+c:\\{obj}{extra_objs},c:\\{exe},c:\\{map},e:\\LIB\\CS",
        "extra_object_format": "+c:\\{extra_obj}",
    }
    dependency = pinned("e:\\BIN\\DPMILOAD.EXE", b"dpmi")
    inventory = {
        dependency["dos_path"]: dependency["sha256"],
        record["tools"]["linker"]["dos_path"]: record["tools"]["linker"]["sha256"],
    }
    probe = tmp_path / "probe.json"
    probe.write_text(json.dumps({"schema": 1, "profiles": [{
        "id": "bcpp31-small", "compiler": {"product": "Borland C++ 3.1"},
        "model": "small", "model_flag": "-ms",
        "compile_runner": "dosbox", "run_runner": "kvikdos",
    }], "toolchain_children": {"bcpp31": inventory}}))
    kvikdos = tmp_path / "kvikdos.bin"
    kvikdos.write_bytes(b"kvikdos")
    dosbox = tmp_path / "dosbox.bin"
    dosbox.write_bytes(b"dosbox")
    registry = {
        "schema": 1,
        "profiles": [record],
        "runners": {
            "kvikdos": {"path": str(kvikdos), "sha256": hashlib.sha256(b"kvikdos").hexdigest()},
            "dosbox": {
                "path": str(dosbox), "sha256": hashlib.sha256(b"dosbox").hexdigest(),
                "host_environment": {"SDL_VIDEODRIVER": "dummy"},
            },
        },
        "probe_evidence": {
            "path": str(probe), "sha256": hashlib.sha256(probe.read_bytes()).hexdigest(),
        },
        "dependencies": {"bcpp31": {dependency["dos_path"]: dependency["sha256"]}},
    }
    path = tmp_path / "toolchains.json"
    path.write_text(json.dumps(registry))
    return path


def test_probe_evidence_profile_routes_to_the_same_case_owner(tmp_path, monkeypatch):
    path = _manifest(
        tmp_path,
        {"id": "p", "compiler": "Borland C++ 3.1", "flags": ["-Od", "-ms"], "memory_model": "small"},
    )
    evidence = _bc31_registry(tmp_path)
    execute = Mock(return_value=CoverageOutcome.PASSED)
    monkeypatch.setattr(suite, "run_existing_case", execute)
    output = tmp_path / "run"
    assert suite.run_suite(
        path, output, case="word_comparisons", profile_evidence=evidence,
    )
    profile = execute.call_args.kwargs["compiler_profile"]
    assert profile.evidence_path == evidence
    assert profile.toolchain.identity is CompilerIdentity.BORLAND31
    assert profile.toolchain.toolchain_root == tmp_path / "bcc31"
    assert profile.toolchain.compiler_program == "e:\\BIN\\BCC.EXE"
    assert profile.toolchain.compile_backend.value == "dosbox"
    summary = json.loads((output / "summary.json").read_text())
    assert summary["compiler_profile"]["profile_id"] == "bc31-small"
    assert summary["compiler_profile"]["evidence_path"] == str(evidence)


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


def _frozen_manifest(tmp_path, cases):
    """Write a schema-2 manifest plus pinned fixture inputs under tmp_path."""
    import hashlib

    def pinned_file(name: str, payload: bytes) -> dict[str, str]:
        file = tmp_path / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(payload)
        return {"path": file.relative_to(suite.ROOT).as_posix(), "sha256": hashlib.sha256(payload).hexdigest()}

    obligations: list[str] = []
    rows: list[dict[str, object]] = []
    for index, (case_id, profile, stem, obligations_for_case) in enumerate(cases):
        source = pinned_file(f"case{index}/{stem}.c", b"int main(void) { return 0; }")
        obligations.extend(obligations_for_case)
        rows.append({
            "id": case_id,
            "construct": stem,
            "compiler_profile": profile,
            "obligations": obligations_for_case,
            "source": {"id": case_id.split("@")[0], "path": source["path"], "sha256": source["sha256"]},
            "expected": {"exit_code": 0, "stdout_contains": "checksum = X"},
            "runtime_headers": [
                {"name": "RT.H", **pinned_file(f"case{index}/rt.h", b"/* rt */")},
            ],
            "runtime_sources": [
                {"name": "RT.C", **pinned_file(f"case{index}/rt.c", b"void rt(void) {}")},
            ],
            "signature_catalogs": [
                {"name": "LIB.PAT", "provenance": "test catalog",
                 **pinned_file(f"case{index}/lib.pat", b"SPEC\n")},
            ],
            "generated": None,
        })
    payload = {
        "schema": 2,
        "id": "frozen-test",
        "batch": "first",
        "budgets": {"case_seconds": 300, "stage_seconds": 120},
        "scope": {"admitted": obligations, "later": [], "excluded": [], "undecided": []},
        "cases": rows,
    }
    path = tmp_path / "frozen.json"
    path.write_text(json.dumps(payload))
    return path


def _fake_toolchain(profile_id: str):
    """Build one structurally valid toolchain stand-in for dispatch tests."""
    from tools.compiler_toolchain.compiler_profile import (
        CompileBackend,
        CompilerIdentity,
        CompilerToolchain,
        ToolIdentity,
    )
    from tools.compiler_toolchain.msc6_memory_model import MSCMemoryModel

    return CompilerToolchain(
        profile_id=profile_id,
        identity=CompilerIdentity.MSC51,
        memory_model=MSCMemoryModel.SMALL,
        declared_flags=("/Od", "/AS"),
        compile_backend=CompileBackend.KVIKDOS,
        run_backend=CompileBackend.KVIKDOS,
        toolchain_root=Path("/opt/fake-toolchain"),
        compiler_tool=ToolIdentity(dos_path="e:\\BIN\\CL.EXE", sha256=None),
        linker_tool=ToolIdentity(dos_path="e:\\BIN\\LINK.EXE", sha256=None),
        libraries=(),
        compiler_path_dos=(),
        linker_path_dos=(),
        compiler_environment=(),
        linker_environment=(),
        compile_arguments=("/c", "/Foc:\\{obj}", "c:\\{source}"),
        cod_argument=None,
        link_argument="c:\\{obj}{extra_objs},c:\\{exe},c:\\{map};",
        extra_object_format="+c:\\{extra_obj}",
    )


def test_frozen_manifest_dispatches_each_row_with_its_pinned_profile(tmp_path, monkeypatch):
    """Schema-2 rows route through run_source_case with per-case toolchains."""
    manifest = _frozen_manifest(tmp_path, [
        ("word_comparisons@msc51-small", "msc51-small", "compare16", ["calls.direct"]),
        ("bitfield_neighbors@bc31-small", "bc31-small", "bitfield_neighbors", ["calls.indirect"]),
    ])
    resolve = Mock(side_effect=lambda **kwargs: _fake_toolchain(kwargs["profile_id"]))
    monkeypatch.setattr(suite, "resolve_case_toolchain", resolve)
    execute = Mock(return_value=CoverageOutcome.PASSED)
    monkeypatch.setattr(suite, "run_source_case", execute)
    output = tmp_path / "run"
    assert suite.run_suite(manifest, output)
    assert execute.call_count == 2
    calls = {call.args[0].stem: call for call in execute.call_args_list}
    first = calls["compare16"]
    assert first.kwargs["expected_exit_code"] == 0
    assert first.kwargs["expected_stdout_contains"] == "checksum = X"
    assert list(first.kwargs["runtime_headers"]) == ["RT.H"]
    assert list(first.kwargs["runtime_sources"]) == ["RT.C"]
    assert len(first.kwargs["signature_catalogs"]) == 1
    assert first.kwargs["timeout"] == 300  # Manifest case budget bounds the row.
    assert first.kwargs["stage_budget_seconds"] == 120
    profile = first.kwargs["compiler_profile"]
    assert profile.toolchain.profile_id == "msc51-small"
    second = calls["bitfield_neighbors"]
    assert second.kwargs["compiler_profile"].toolchain.profile_id == "bc31-small"
    assert resolve.call_args_list[0].kwargs["profile_id"] == "msc51-small"
    summary = json.loads((output / "summary.json").read_text())
    assert summary["manifest_schema"] == 2
    assert [row["compiler_profile"] for row in summary["cases"]] == ["msc51-small", "bc31-small"]
    assert [row["source_id"] for row in summary["cases"]] == [
        "word_comparisons", "bitfield_neighbors"]


def test_frozen_manifest_preserves_blocked_rows_in_the_denominator(tmp_path, monkeypatch):
    """A broken pin must record a row outcome, not vanish the selection."""
    manifest = _frozen_manifest(tmp_path, [
        ("word_comparisons@msc51-small", "msc51-small", "compare16", ["calls.direct"]),
        ("csmith_seed2@msc51-small", "msc51-small", "csmith", ["calls.indirect"]),
    ])
    payload = json.loads(manifest.read_text())
    payload["cases"][1]["source"]["sha256"] = "0" * 64
    manifest.write_text(json.dumps(payload))
    monkeypatch.setattr(suite, "resolve_case_toolchain", Mock(side_effect=lambda **kwargs: _fake_toolchain(kwargs["profile_id"])))
    execute = Mock(return_value=CoverageOutcome.PASSED)
    monkeypatch.setattr(suite, "run_source_case", execute)
    output = tmp_path / "run"
    assert not suite.run_suite(manifest, output)
    assert execute.call_count == 1  # The unpinned row still consumed a row.
    summary = json.loads((output / "summary.json").read_text())
    assert summary["selected"] == summary["completed"] == 2
    assert summary["cases"][1]["outcome"] == "harness_failed"
    assert "sha256 mismatch" in summary["cases"][1]["error"]
    assert summary["cases"][1]["case"] == "csmith_seed2@msc51-small"


def test_frozen_timeout_preserves_pending_denominator_rows(tmp_path, monkeypatch):
    manifest = _frozen_manifest(tmp_path, [
        ("word_comparisons@msc51-small", "msc51-small", "compare16", ["calls.direct"]),
        ("csmith_seed2@msc51-small", "msc51-small", "csmith", ["calls.indirect"]),
        ("bitfield_neighbors@bc31-small", "bc31-small", "bitfield_neighbors", ["calls.aggregate"]),
    ])
    monkeypatch.setattr(
        suite, "resolve_case_toolchain", Mock(side_effect=lambda **kwargs: _fake_toolchain(kwargs["profile_id"])),
    )
    monkeypatch.setattr(suite, "run_source_case", Mock(return_value=CoverageOutcome.TIMED_OUT))
    output = tmp_path / "run"
    assert not suite.run_suite(manifest, output)
    summary = json.loads((output / "summary.json").read_text())
    assert summary["denominator"] == 3
    assert summary["selected"] == 3
    assert summary["completed"] == 1
    assert len(summary["cases"]) == 3
    assert summary["cases"][0]["attempted"] is True
    assert summary["cases"][0]["outcome"] == "timed_out"
    assert summary["cases"][1]["outcome"] == "not_attempted"
    assert "stopped after word_comparisons@msc51-small: timed_out" in summary["cases"][1]["error"]
    assert summary["cases"][2]["attempted"] is False


def test_frozen_manifest_rejects_missing_pinned_input_as_row_failure(tmp_path, monkeypatch):
    manifest = _frozen_manifest(tmp_path, [
        ("word_comparisons@msc51-small", "msc51-small", "compare16", ["calls.direct"]),
    ])
    payload = json.loads(manifest.read_text())
    payload["cases"][0]["runtime_sources"][0]["path"] = ".cache/pytest-absent/absent.c"
    manifest.write_text(json.dumps(payload))
    execute = Mock(return_value=CoverageOutcome.PASSED)
    monkeypatch.setattr(suite, "run_source_case", execute)
    output = tmp_path / "run"
    assert not suite.run_suite(manifest, output)
    execute.assert_not_called()
    summary = json.loads((output / "summary.json").read_text())
    assert summary["cases"][0]["outcome"] == "harness_failed"
    assert "pinned input missing" in summary["cases"][0]["error"]


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
