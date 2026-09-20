from __future__ import annotations

import json
import subprocess
from pathlib import Path

from scripts import test_pipeline

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_unit_lane_promotes_postprocess_inventory_contract():
    assert "angr_platforms/tests/test_x86_16_package_exports.py" in test_pipeline.FOCUSED_PYTEST_TARGETS


def test_unit_lane_promotes_condition_transfer_contract():
    assert "angr_platforms/tests/test_x86_16_condition_transfer.py" in test_pipeline.FOCUSED_PYTEST_TARGETS


def test_unit_lane_promotes_semantics_expression_analysis_contract():
    assert "angr_platforms/tests/test_x86_16_semantics_expression_analysis.py" in test_pipeline.FOCUSED_PYTEST_TARGETS


def test_unit_lane_runs_typed_conditions_before_jcc_postprocess_tests():
    typed_conditions = "angr_platforms/tests/test_x86_16_decompiler_postprocess_typed_conditions.py"
    jcc = "angr_platforms/tests/test_x86_16_decompiler_postprocess_jcc.py"

    assert typed_conditions in test_pipeline.FOCUSED_PYTEST_TARGETS
    assert jcc in test_pipeline.FOCUSED_PYTEST_TARGETS
    assert test_pipeline.FOCUSED_PYTEST_TARGETS.index(typed_conditions) < test_pipeline.FOCUSED_PYTEST_TARGETS.index(jcc)


def test_unit_lane_promotes_pipeline_contract_guard():
    assert "angr_platforms/tests/test_x86_16_pipeline_contracts.py" in test_pipeline.FOCUSED_PYTEST_TARGETS


def test_unit_lane_promotes_pre_rewrite_invariant_guard():
    assert "angr_platforms/tests/test_x86_16_rewrite_boundary.py" in test_pipeline.FOCUSED_PYTEST_TARGETS


def test_unit_lane_promotes_type_object_recovery_contracts():
    assert "angr_platforms/tests/test_x86_16_array_matching.py" in test_pipeline.FOCUSED_PYTEST_TARGETS
    assert "angr_platforms/tests/test_x86_16_struct_merging.py" in test_pipeline.FOCUSED_PYTEST_TARGETS


def test_repository_architecture_guard_runs_as_a_separate_hard_gate():
    assert "angr_platforms/tests/test_decompiler_architecture_check.py" not in test_pipeline.FOCUSED_PYTEST_TARGETS
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    assert "decompiler-check-fast: architecture-check-fast" in makefile
    assert "quality-hard: linters-hard type-ratchet-changed architecture-check" in makefile
    assert 'pytest -q $(PYTEST_ARGS) -m "$(PYTEST_FOCUSED_MARKER_EXPR)"' in makefile


def test_unit_lane_promotes_pipeline_self_contract():
    assert "angr_platforms/tests/test_test_pipeline.py" in test_pipeline.FOCUSED_PYTEST_TARGETS


def test_repository_ownership_manifest_runs_as_a_separate_hard_gate():
    assert "angr_platforms/tests/test_test_ownership_manifest.py" not in test_pipeline.FOCUSED_PYTEST_TARGETS
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    assert "decompiler-check-fast: architecture-check-fast agent-context-check test-ownership-check" in makefile
    assert 'pytest_profile.py $(PYTEST_PROFILE_ARGS) -m "$(PYTEST_FOCUSED_MARKER_EXPR)"' in makefile


def test_complete_pytest_target_keeps_repository_contracts():
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")

    pytest_all_recipe = makefile.split("pytest-all:", maxsplit=1)[1].split("architecture-check:", maxsplit=1)[0]
    assert "PYTEST_FOCUSED_MARKER_EXPR" not in pytest_all_recipe
    assert "pytest-all: pytest-inventory" in makefile
    assert "scripts/pytest_partitioned.py" in pytest_all_recipe
    assert "--inventory-json $(PYTEST_INVENTORY_JSON)" in pytest_all_recipe
    assert "--heavy-shards $(PYTEST_ALL_HEAVY_SHARDS)" in pytest_all_recipe
    assert "--max-rss-mib $(PYTEST_ALL_MAX_RSS_MIB)" in pytest_all_recipe


def test_unit_lane_promotes_corpus_scan_timeout_contract():
    assert "angr_platforms/tests/test_x86_16_corpus_scan_timeout.py" in test_pipeline.FOCUSED_PYTEST_TARGETS


def test_unit_lane_promotes_type_ratchet_contract():
    assert "angr_platforms/tests/test_check_changed_non_test_types.py" in test_pipeline.FOCUSED_PYTEST_TARGETS


def test_unit_lane_promotes_segmented_runtime_and_cache_contracts():
    assert "angr_platforms/tests/test_x86_16_alu_effect_order.py" in test_pipeline.FOCUSED_PYTEST_TARGETS
    assert "angr_platforms/tests/test_x86_16_cod_regressions.py::test_cod_dos_loadprogram_wrapper_keeps_err_guard_and_segment_stores" in test_pipeline.FOCUSED_PYTEST_TARGETS
    assert "angr_platforms/tests/test_x86_16_segment_access_policy.py" in test_pipeline.FOCUSED_PYTEST_TARGETS
    assert "angr_platforms/tests/test_x86_16_segment_address_policy.py" in test_pipeline.FOCUSED_PYTEST_TARGETS
    assert "angr_platforms/tests/test_x86_16_segment_state.py" in test_pipeline.FOCUSED_PYTEST_TARGETS
    assert "angr_platforms/tests/test_x86_16_vex_import.py" in test_pipeline.FOCUSED_PYTEST_TARGETS
    assert "angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py" in test_pipeline.FOCUSED_PYTEST_TARGETS
    assert "angr_platforms/tests/test_x86_16_direct_stack_move_loop_entries.py" in test_pipeline.FOCUSED_PYTEST_TARGETS
    assert "angr_platforms/tests/test_x86_16_decompilation_cache_surface.py" in test_pipeline.FOCUSED_PYTEST_TARGETS


def test_unit_lane_promotes_ultradecompiler_borrow_contracts():
    assert "angr_platforms/tests/test_import_ultra_quickc_fixtures.py" in test_pipeline.FOCUSED_PYTEST_TARGETS
    assert "angr_platforms/tests/test_omf_pat_lidata.py" in test_pipeline.FOCUSED_PYTEST_TARGETS
    assert "angr_platforms/tests/test_x86_16_alias_register_mvp.py" in test_pipeline.FOCUSED_PYTEST_TARGETS
    assert "angr_platforms/tests/test_x86_16_decompiler_postprocess_callsites.py" in test_pipeline.FOCUSED_PYTEST_TARGETS
    assert "angr_platforms/tests/test_x86_16_stack_compat.py" in test_pipeline.FOCUSED_PYTEST_TARGETS


def test_default_tier_keeps_full_msc6_tiny_pipeline():
    args = test_pipeline._parse_args([])

    assert args.ultra_quickc_decompile_timeout == 180
    assert args.sortdemo_decompile_timeout == 360
    assert args.sortdemo_run_timeout == 2400
    assert test_pipeline._selected_lanes(args) == (
        "unit-focused",
        "ultra-quickc-fixtures",
        "msc6-tiny-full-pipeline",
    )


def test_fast_tier_runs_regular_local_unit_gate_only():
    args = test_pipeline._parse_args(["--tier", "fast"])

    assert test_pipeline._selected_lanes(args) == ("unit-focused",)


def test_unit_lane_excludes_broad_slow_corpus_pytest_targets():
    forbidden_targets = {
        "angr_platforms/tests/test_x86_16_cli.py",
        "angr_platforms/tests/test_x86_16_cod_samples.py",
        "angr_platforms/tests/test_x86_16_cod_regressions.py",
        "angr_platforms/tests/test_x86_16_life_decompile_regressions.py",
        "angr_platforms/tests/test_x86_16_msc6_regressions.py",
        "angr_platforms/tests/test_x86_16_sortdemo_regressions.py",
    }

    assert forbidden_targets.isdisjoint(test_pipeline.FOCUSED_PYTEST_TARGETS)


def test_expanded_tier_adds_sidecar_free_and_sortdemo_status_lanes():
    args = test_pipeline._parse_args(["--tier", "expanded"])

    assert test_pipeline._selected_lanes(args) == (
        "unit-focused",
        "ultra-quickc-fixtures",
        "msc6-tiny-full-pipeline",
        "sortd-sidecar-free",
        "sortdemo-status",
    )


def test_makefile_exposes_expanded_pipeline_targets():
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")

    assert (
        "decompiler-check-expanded: architecture-check agent-context-check "
        "test-ownership-check pytest test-pipeline-expanded"
    ) in makefile
    assert (
        "\ntest-pipeline-expanded: decompiler-contracts\n"
        '\tflock "/tmp/vextest-test-pipeline.lock" $(PYTHON) '
        "scripts/test_pipeline.py --tier expanded --require-external"
    ) in makefile


def test_makefile_exposes_fast_quality_target_with_linters():
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")

    assert "quality-fast: linters type-ratchet-changed decompiler-check-fast" in makefile
    assert "\ntype-ratchet-changed:\n" in makefile
    assert "decompiler-check-fast: architecture-check-fast agent-context-check test-ownership-check test-pipeline-fast" in makefile
    assert (
        '\ntest-pipeline: decompiler-contracts\n\tflock "/tmp/vextest-test-pipeline.lock" $(PYTHON) '
        "scripts/test_pipeline.py --require-external"
    ) in makefile
    assert (
        '\ntest-pipeline-fast: decompiler-contracts\n\tflock "/tmp/vextest-test-pipeline.lock" $(PYTHON) '
        "scripts/test_pipeline.py --tier fast --require-external"
    ) in makefile
    assert "\narchitecture-check-fast:\n\t$(PYTHON) -m scripts.check_decompiler_architecture --startup-only" in makefile
    assert "\ntest-ownership-check:\n\t$(PYTHON) scripts/test_ownership_manifest.py --check" in makefile


def test_project_map_documents_fast_and_expanded_pipeline_tiers():
    project_map = (REPO_ROOT / "reference" / "project-map.md").read_text(encoding="utf-8")

    assert "make test-pipeline-fast" in project_map
    assert "make test-pipeline-expanded" in project_map


def test_makefile_default_decompiler_check_validates_test_ownership_manifest():
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")

    assert "decompiler-check: architecture-check agent-context-check test-ownership-check pytest test-pipeline" in makefile


def test_makefile_focused_check_runs_architecture_guard():
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")

    assert "check-files: linters-files architecture-check-fast agent-context-check test-ownership-check pytest-files" in makefile


def test_makefile_focused_check_unions_explicit_and_owned_tests():
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")

    assert "for test_target in $$manifest_tests $(PYTEST_FILES)" in makefile
    assert "selected_tests=\"$$manifest_tests\"" not in makefile


def test_makefile_focused_type_ratchet_is_fatal():
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")

    assert "TYPE_RATCHET_SELECTED_FILES := $(PY_FILES)" in makefile
    assert "$(PYTHON) scripts/check_changed_non_test_types.py $(TYPE_RATCHET_SELECTED_FILES)" in makefile
    assert "QA_TYPE_RATCHET_LEGACY_FILES" not in makefile
    assert "TYPE_RATCHET_SKIPPED_FILES" not in makefile
    assert "type-ratchet-files: skipped explicit legacy debt:" not in makefile
    assert "non-fatal legacy typing debt remains" not in makefile
    assert "type-ratchet-files:" in makefile


def test_makefile_dce_type_batch_is_mandatory_and_bounded():
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")

    assert "PYRIGHT_DCE_TIMEOUT ?= 600" in makefile
    assert (
        "$(TIMEOUT) --foreground $(PYRIGHT_DCE_TIMEOUT) $(PYTHON) -m pyright "
        "angr_platforms/angr_platforms/X86_16/postprocess/optimization/dce.py"
        in makefile
    )
    assert "split its oversized function instead of suppressing types" in makefile


def test_msc6_workers_default_to_serial_until_shared_state_is_isolated():
    args = test_pipeline._parse_args([])

    assert args.msc6_workers == 1


def test_lane_result_records_duration_budget(monkeypatch):
    class FakeCompleted:
        returncode = 0

    monkeypatch.setattr(test_pipeline.time, "monotonic", iter((10.0, 15.0)).__next__)
    monkeypatch.setattr(test_pipeline.subprocess, "run", lambda *_args, **_kwargs: FakeCompleted())

    result = test_pipeline._run_command("unit-focused", ["pytest"])

    assert result.elapsed_seconds == 5.0
    assert result.budget_seconds == 30.0
    assert result.budget_status == test_pipeline.BudgetStatus.PASSED


def test_sortdemo_lane_budget_exceeds_its_internal_run_timeout():
    args = test_pipeline._parse_args([])

    assert (
        test_pipeline.LANE_BUDGET_SECONDS["sortdemo-status"]
        >= args.sortdemo_run_timeout + 60
    )
    assert (
        test_pipeline.LANE_BUDGET_SECONDS["sortdemo-status-proc-diagnostic"]
        >= args.sortdemo_run_timeout + 60
    )


def test_unit_lane_reports_slow_pytest_durations(monkeypatch):
    captured: list[list[str]] = []

    def fake_run_command(name, cmd, *, env=None):
        captured.append(cmd)
        return test_pipeline.LaneResult(name, test_pipeline.LaneStatus.PASSED, cmd, 0.1, returncode=0)

    monkeypatch.setattr(test_pipeline, "_run_command", fake_run_command)

    result = test_pipeline._unit_lane()

    assert result.status == test_pipeline.LaneStatus.PASSED
    assert captured
    assert "--durations=10" in captured[0]
    assert captured[0][captured[0].index("-n") + 1] == "7"
    assert captured[0][captured[0].index("--dist") + 1] == "loadgroup"
    assert "--durations-min=1.0" in captured[0]


def test_run_command_records_timed_out_status(monkeypatch):
    def fake_run(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(["pytest"], timeout=12)

    monkeypatch.setattr(test_pipeline.time, "monotonic", iter((10.0, 22.5)).__next__)
    monkeypatch.setattr(test_pipeline.subprocess, "run", fake_run)

    result = test_pipeline._run_command("unit-focused", ["pytest"])

    assert result.status == test_pipeline.LaneStatus.TIMED_OUT
    assert result.elapsed_seconds == 12.5
    assert result.returncode is None
    assert result.reason == "timed out after 12 seconds"


def test_ultra_quickc_fixture_lane_runs_importer_through_pipeline(monkeypatch, tmp_path):
    kvikdos = tmp_path / "kvikdos"
    kvikdos.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    kvikdos.chmod(kvikdos.stat().st_mode | 0o111)
    quickc_root = tmp_path / "QuickC"
    quickc_root.mkdir()
    (quickc_root / "QCL.EXE").write_bytes(b"")
    (quickc_root / "LINK.EXE").write_bytes(b"")
    captured: list[list[str]] = []

    def fake_run_captured_command(name, cmd, *, env=None):
        captured.append(cmd)
        out_dir = Path(cmd[cmd.index("--output-root") + 1])
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "ultra_quickc_fixtures.json").write_text(
            json.dumps(
                {
                    "summary": {
                        "selected_fixture_count": 4,
                        "passed_fixture_count": 4,
                        "excluded_fixture_count": 3,
                        "promoted_fixture_count": 1,
                        "decompile_passed_count": 4,
                        "validation_passed_count": 4,
                        "validation_unavailable_count": 0,
                        "validation_failed_count": 0,
                        "compiler_evidence_gap_count": 0,
                    }
                }
            ),
            encoding="utf-8",
        )
        return test_pipeline.LaneResult(
            name,
            test_pipeline.LaneStatus.PASSED,
            cmd,
            0.1,
            returncode=0,
            budget_seconds=180.0,
            budget_status=test_pipeline.BudgetStatus.PASSED,
            children=[{"stdout": "wrote report\n", "stderr": ""}],
        )

    monkeypatch.setattr(test_pipeline, "_run_captured_command", fake_run_captured_command)
    args = test_pipeline._parse_args(
        [
            "--kvikdos",
            str(kvikdos),
            "--ultra-quickc-root",
            str(quickc_root),
            "--ultra-quickc-out-dir",
            str(tmp_path / "out"),
        ]
    )

    result = test_pipeline._ultra_quickc_fixtures_lane(args)

    assert result.status == test_pipeline.LaneStatus.PASSED
    assert result.budget_seconds == 180.0
    assert result.details is not None
    assert result.details["report_path"] == str(tmp_path / "out" / "ultra_quickc_fixtures.json")
    assert result.details["selected_fixture_count"] == 4
    assert result.details["decompile_passed_count"] == 4
    assert result.details["validation_passed_count"] == 4
    assert result.details["promoted_fixture_count"] == 1
    assert captured
    cmd = captured[0]
    assert cmd[:2] == [test_pipeline.sys.executable, "scripts/import_ultra_quickc_fixtures.py"]
    assert cmd[cmd.index("--kvikdos") + 1] == str(kvikdos)
    assert cmd[cmd.index("--quickc-root") + 1] == str(quickc_root)
    assert cmd[cmd.index("--output-root") + 1] == str(tmp_path / "out")
    assert cmd[cmd.index("--decompile-timeout") + 1] == "180"


def test_ultra_quickc_fixture_lane_reports_missing_nested_report(monkeypatch, tmp_path):
    kvikdos = tmp_path / "kvikdos"
    kvikdos.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    kvikdos.chmod(kvikdos.stat().st_mode | 0o111)
    quickc_root = tmp_path / "QuickC"
    quickc_root.mkdir()
    (quickc_root / "QCL.EXE").write_bytes(b"")
    (quickc_root / "LINK.EXE").write_bytes(b"")

    def fake_run_captured_command(name, cmd, *, env=None):
        return test_pipeline.LaneResult(
            name,
            test_pipeline.LaneStatus.FAILED,
            cmd,
            0.1,
            returncode=1,
            children=[{"stdout": "", "stderr": "failed"}],
        )

    monkeypatch.setattr(test_pipeline, "_run_captured_command", fake_run_captured_command)
    args = test_pipeline._parse_args(
        [
            "--kvikdos",
            str(kvikdos),
            "--ultra-quickc-root",
            str(quickc_root),
            "--ultra-quickc-out-dir",
            str(tmp_path / "out"),
        ]
    )

    result = test_pipeline._ultra_quickc_fixtures_lane(args)

    assert result.status == test_pipeline.LaneStatus.FAILED
    assert result.details is not None
    assert result.details["report_error"] == "fixture report not produced"


def test_ultra_quickc_fixture_lane_skips_missing_tools_by_default(tmp_path):
    args = test_pipeline._parse_args(
        [
            "--kvikdos",
            str(tmp_path / "missing-kvikdos"),
            "--ultra-quickc-root",
            str(tmp_path / "missing-quickc"),
        ]
    )

    result = test_pipeline._ultra_quickc_fixtures_lane(args)

    assert result.status == test_pipeline.LaneStatus.SKIPPED
    assert "scripts/import_ultra_quickc_fixtures.py" in result.command


def test_ultra_quickc_fixture_lane_can_require_external_tools(tmp_path):
    args = test_pipeline._parse_args(
        [
            "--require-external",
            "--kvikdos",
            str(tmp_path / "missing-kvikdos"),
            "--ultra-quickc-root",
            str(tmp_path / "missing-quickc"),
        ]
    )

    result = test_pipeline._ultra_quickc_fixtures_lane(args)

    assert result.status == test_pipeline.LaneStatus.FAILED
    assert result.returncode == 1


def test_msc6_report_merge_preserves_construct_order(tmp_path):
    for construct in ("b", "a"):
        report_dir = tmp_path / construct
        report_dir.mkdir()
        (report_dir / "report.json").write_text(
            json.dumps([{"name": construct, "build_ok": True}]),
            encoding="utf-8",
        )

    rows = test_pipeline._merge_msc6_reports(tmp_path, ("a", "b"))

    assert [row["name"] for row in rows] == ["a", "b"]
    merged = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert [row["name"] for row in merged] == ["a", "b"]


def test_msc6_construct_timing_details_reports_slowest_constructs():
    details = test_pipeline._msc6_construct_timing_details(
        [
            {
                "name": "fast",
                "decompile_wall_seconds": 1.2,
                "decompile_selected_functions": 1,
                "decompile_run_exit_code": 255,
            },
            {
                "name": "slow",
                "decompile_wall_seconds": 10.5,
                "decompile_selected_functions": 3,
                "decompile_run_exit_code": 255,
            },
        ],
        limit=1,
    )

    assert details["construct_count"] == 2
    assert details["timed_construct_count"] == 2
    assert details["decompile_wall_seconds_total"] == 11.7
    assert details["slowest_constructs"] == [
        {
            "construct": "slow",
            "decompile_wall_seconds": 10.5,
            "selected_functions": 3,
            "run_exit_code": 255,
        }
    ]


def test_msc6_tiny_lane_uses_build_examples_full_pipeline(monkeypatch, tmp_path):
    kvikdos = tmp_path / "kvikdos"
    kvikdos.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    kvikdos.chmod(kvikdos.stat().st_mode | 0o111)
    msc6_root = tmp_path / "msc6"
    msc6_root.mkdir()
    captured: list[tuple[str, list[str]]] = []

    def fake_run_captured_command(name, cmd, *, env=None):
        captured.append((name, cmd))
        assert env["INERTIA_ENABLE_TAIL_VALIDATION"] == "1"
        assert env["INERTIA_DISABLE_TIMING"] == "1"
        assert env["INERTIA_DISABLE_SIGNATURES"] == "1"
        return test_pipeline.LaneResult(
            name,
            test_pipeline.LaneStatus.PASSED,
            cmd,
            0.1,
            returncode=0,
            children=[{"stdout": "", "stderr": ""}],
        )

    monkeypatch.setattr(test_pipeline, "_run_captured_command", fake_run_captured_command)
    monkeypatch.setattr(
        test_pipeline,
        "_merge_msc6_reports",
        lambda *_args, **_kwargs: [
            {"name": "compare16", "decompile_wall_seconds": 9.0, "decompile_selected_functions": 5}
        ],
    )
    args = test_pipeline._parse_args(
        [
            "--kvikdos",
            str(kvikdos),
            "--msc6-root",
            str(msc6_root),
            "--msc6-out-dir",
            str(tmp_path / "out"),
            "--msc6-workers",
            "2",
        ]
    )

    result = test_pipeline._msc6_tiny_lane(
        args,
        name="msc6-tiny-full-pipeline",
        constructs=test_pipeline.MSC6_TINY_CONSTRUCTS,
    )

    assert result.status == test_pipeline.LaneStatus.PASSED
    assert result.returncode == 0
    calls = {cmd[cmd.index("--only-constructs") + 1]: (name, cmd) for name, cmd in captured}
    assert set(calls) == set(test_pipeline.MSC6_TINY_CONSTRUCTS)
    for construct in test_pipeline.MSC6_TINY_CONSTRUCTS:
        _name, cmd = calls[construct]
        assert "scripts/build_msc6_examples.py" in cmd
        assert "scripts/compare_msc6_ssa_examples.py" not in cmd
        assert cmd[cmd.index("--only-constructs") + 1] == construct
        assert cmd[cmd.index("--out-dir") + 1] == str(tmp_path / "out" / construct)
    assert test_pipeline.MSC6_TINY_NEXT_CONSTRUCTS == ()
    assert result.children is not None
    assert result.details is not None
    assert result.details["slowest_constructs"] == [
        {
            "construct": "compare16",
            "decompile_wall_seconds": 9.0,
            "selected_functions": 5,
            "run_exit_code": None,
        }
    ]
    assert [child["name"] for child in result.children] == [
        "msc6-tiny:compare16",
        "msc6-tiny:mixwidth",
        "msc6-tiny:simple_control",
        "msc6-tiny:loops_jumps",
        "msc6-tiny:storage_classes",
            "msc6-tiny:function_pointers",
            "msc6-tiny:pointer_memory",
            "msc6-tiny:scalar_types_io",
        ]


def test_msc6_tiny_smoke_lane_uses_per_construct_output_dir(monkeypatch, tmp_path):
    kvikdos = tmp_path / "kvikdos"
    kvikdos.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    kvikdos.chmod(kvikdos.stat().st_mode | 0o111)
    msc6_root = tmp_path / "msc6"
    msc6_root.mkdir()
    captured: list[tuple[str, list[str]]] = []
    merged: list[tuple[object, ...]] = []

    def fake_run_captured_command(name, cmd, *, env=None):
        captured.append((name, cmd))
        return test_pipeline.LaneResult(
            name,
            test_pipeline.LaneStatus.PASSED,
            cmd,
            0.1,
            returncode=0,
            children=[{"stdout": "", "stderr": ""}],
        )

    monkeypatch.setattr(test_pipeline, "_run_captured_command", fake_run_captured_command)
    monkeypatch.setattr(test_pipeline, "_merge_msc6_reports", lambda *args, **_kwargs: merged.append(args) or [])
    args = test_pipeline._parse_args(
        [
            "--kvikdos",
            str(kvikdos),
            "--msc6-root",
            str(msc6_root),
            "--msc6-out-dir",
            str(tmp_path / "out"),
        ]
    )

    result = test_pipeline._msc6_tiny_lane(
        args,
        name="msc6-tiny-smoke",
        constructs=test_pipeline.MSC6_TINY_SMOKE_CONSTRUCTS,
    )

    assert result.status == test_pipeline.LaneStatus.PASSED
    assert result.children is not None
    assert [child["name"] for child in result.children] == ["msc6-tiny:storage_classes"]
    assert len(captured) == 1
    _name, cmd = captured[0]
    assert cmd[cmd.index("--only-constructs") + 1] == "storage_classes"
    assert cmd[cmd.index("--out-dir") + 1] == str(tmp_path / "out" / "storage_classes")
    assert merged == [(tmp_path / "out", test_pipeline.MSC6_TINY_SMOKE_CONSTRUCTS)]


def test_msc6_tiny_lane_reports_child_timeout_as_structured_status(monkeypatch, tmp_path):
    kvikdos = tmp_path / "kvikdos"
    kvikdos.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    kvikdos.chmod(kvikdos.stat().st_mode | 0o111)
    msc6_root = tmp_path / "msc6"
    msc6_root.mkdir()

    def fake_run_captured_command(name, cmd, *, env=None):
        status = (
            test_pipeline.LaneStatus.TIMED_OUT
            if name == "msc6-tiny:simple_control"
            else test_pipeline.LaneStatus.PASSED
        )
        return test_pipeline.LaneResult(
            name,
            status,
            cmd,
            0.1,
            returncode=None if status == test_pipeline.LaneStatus.TIMED_OUT else 0,
            reason="timed out after 60 seconds" if status == test_pipeline.LaneStatus.TIMED_OUT else None,
            children=[{"stdout": "", "stderr": ""}],
        )

    monkeypatch.setattr(test_pipeline, "_run_captured_command", fake_run_captured_command)
    monkeypatch.setattr(test_pipeline, "_merge_msc6_reports", lambda *_args, **_kwargs: [])
    args = test_pipeline._parse_args(
        [
            "--kvikdos",
            str(kvikdos),
            "--msc6-root",
            str(msc6_root),
            "--msc6-out-dir",
            str(tmp_path / "out"),
        ]
    )

    result = test_pipeline._msc6_tiny_lane(
        args,
        name="msc6-tiny-full-pipeline",
        constructs=test_pipeline.MSC6_TINY_CONSTRUCTS,
    )

    assert result.status == test_pipeline.LaneStatus.TIMED_OUT
    assert result.returncode is None
    assert "msc6-tiny:simple_control: timed out after 60 seconds" in (result.reason or "")
    assert result.children is not None
    child = next(child for child in result.children if child["name"] == "msc6-tiny:simple_control")
    assert child["status"] == test_pipeline.LaneStatus.TIMED_OUT


def test_msc6_tiny_lane_reports_child_failure_as_structured_status(monkeypatch, tmp_path):
    kvikdos = tmp_path / "kvikdos"
    kvikdos.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    kvikdos.chmod(kvikdos.stat().st_mode | 0o111)
    msc6_root = tmp_path / "msc6"
    msc6_root.mkdir()

    def fake_run_captured_command(name, cmd, *, env=None):
        status = (
            test_pipeline.LaneStatus.FAILED
            if name == "msc6-tiny:loops_jumps"
            else test_pipeline.LaneStatus.PASSED
        )
        return test_pipeline.LaneResult(
            name,
            status,
            cmd,
            0.1,
            returncode=2 if status == test_pipeline.LaneStatus.FAILED else 0,
            reason="exit 2" if status == test_pipeline.LaneStatus.FAILED else None,
            children=[{"stdout": "", "stderr": ""}],
        )

    monkeypatch.setattr(test_pipeline, "_run_captured_command", fake_run_captured_command)
    monkeypatch.setattr(test_pipeline, "_merge_msc6_reports", lambda *_args, **_kwargs: [])
    args = test_pipeline._parse_args(
        [
            "--kvikdos",
            str(kvikdos),
            "--msc6-root",
            str(msc6_root),
            "--msc6-out-dir",
            str(tmp_path / "out"),
        ]
    )

    result = test_pipeline._msc6_tiny_lane(
        args,
        name="msc6-tiny-full-pipeline",
        constructs=test_pipeline.MSC6_TINY_CONSTRUCTS,
    )

    assert result.status == test_pipeline.LaneStatus.FAILED
    assert result.returncode == 1
    assert "msc6-tiny:loops_jumps: exit 2" in (result.reason or "")
    assert result.children is not None
    child = next(child for child in result.children if child["name"] == "msc6-tiny:loops_jumps")
    assert child["status"] == test_pipeline.LaneStatus.FAILED


def test_msc6_tiny_lane_skips_missing_external_tools_by_default(tmp_path):
    args = test_pipeline._parse_args(
        [
            "--kvikdos",
            str(tmp_path / "missing-kvikdos"),
            "--msc6-root",
            str(tmp_path / "missing-msc6"),
        ]
    )

    result = test_pipeline._msc6_tiny_lane(
        args,
        name="msc6-tiny-full-pipeline",
        constructs=test_pipeline.MSC6_TINY_CONSTRUCTS,
    )

    assert result.status == test_pipeline.LaneStatus.SKIPPED
    assert "scripts/build_msc6_examples.py" in result.command


def test_msc6_tiny_lane_can_require_external_tools(tmp_path):
    args = test_pipeline._parse_args(
        [
            "--require-external",
            "--kvikdos",
            str(tmp_path / "missing-kvikdos"),
            "--msc6-root",
            str(tmp_path / "missing-msc6"),
        ]
    )

    result = test_pipeline._msc6_tiny_lane(
        args,
        name="msc6-tiny-full-pipeline",
        constructs=test_pipeline.MSC6_TINY_CONSTRUCTS,
    )

    assert result.status == test_pipeline.LaneStatus.FAILED
    assert result.returncode == 1


def test_sortdemo_status_lane_uses_normal_whole_binary_harness(monkeypatch, tmp_path):
    binary = tmp_path / "SORTDEMO.EXE"
    binary.write_bytes(b"MZ")
    captured: list[tuple[list[str], dict[str, str]]] = []

    def fake_run_command(name, cmd, *, env=None):
        captured.append((cmd, env or {}))
        return test_pipeline.LaneResult(name, test_pipeline.LaneStatus.PASSED, cmd, 0.1, returncode=0)

    monkeypatch.setattr(test_pipeline, "_run_command", fake_run_command)
    args = test_pipeline._parse_args(
        [
            "--sortdemo-binary",
            str(binary),
            "--sortdemo-max-functions",
            "3",
            "--sortdemo-decompile-timeout",
            "9",
            "--sortdemo-run-timeout",
            "123",
            "--sortdemo-status-out",
            str(tmp_path / "cache" / "status.json"),
            "--sortdemo-transcript-out",
            str(tmp_path / "cache" / "status.txt"),
        ]
    )

    result = test_pipeline._sortdemo_status_lane(args)

    assert result.status == test_pipeline.LaneStatus.PASSED
    assert captured
    cmd, env = captured[0]
    assert cmd[:3] == [test_pipeline.sys.executable, "scripts/sortdemo_decompiler_status.py", "--run-sortdemo"]
    assert "--per-function-proc" not in cmd
    assert "--require-passed" in cmd
    assert cmd[cmd.index("--binary") + 1] == str(binary)
    assert cmd[cmd.index("--max-functions") + 1] == "3"
    assert cmd[cmd.index("--decompile-timeout") + 1] == "9"
    assert cmd[cmd.index("--run-timeout") + 1] == "123"
    assert cmd[cmd.index("--out") + 1] == str(tmp_path / "cache" / "status.json")
    assert cmd[cmd.index("--transcript-out") + 1] == str(tmp_path / "cache" / "status.txt")
    assert env["INERTIA_ENABLE_TAIL_VALIDATION"] == "1"
    assert env["INERTIA_DISABLE_TIMING"] == "1"


def test_sortd_sidecar_free_lane_uses_executable_only_ratchet(monkeypatch, tmp_path):
    binary = tmp_path / "SORTDEMO.EXE"
    binary.write_bytes(b"MZ")
    captured: list[tuple[str, list[str]]] = []

    def fake_run_command(name, cmd, *, env=None):
        assert env is None
        captured.append((name, cmd))
        return test_pipeline.LaneResult(name, test_pipeline.LaneStatus.PASSED, cmd, 0.1, returncode=0)

    monkeypatch.setattr(test_pipeline, "_run_command", fake_run_command)
    args = test_pipeline._parse_args(
        [
            "--sortdemo-binary",
            str(binary),
            "--sortdemo-decompile-timeout",
            "9",
            "--sortd-run-timeout",
            "123",
            "--sortd-report-out",
            str(tmp_path / "sortd.json"),
            "--sortd-transcript-out",
            str(tmp_path / "sortd.txt"),
        ]
    )

    result = test_pipeline._sortd_sidecar_free_lane(args)

    assert result.status == test_pipeline.LaneStatus.PASSED
    assert tuple(name for name, _cmd in captured) == (
        "sortd-sidecar-free",
        "sortd-generated-translation-unit",
        "sortd-generated-sort-core",
    )
    cmd = captured[0][1]
    assert cmd[:2] == [test_pipeline.sys.executable, "scripts/check_sortd_sidecar_free.py"]
    assert cmd[cmd.index("--source-binary") + 1] == str(binary)
    assert cmd[cmd.index("--run-timeout") + 1] == "123"
    translation_unit_cmd = captured[1][1]
    assert translation_unit_cmd[:2] == [
        test_pipeline.sys.executable,
        "scripts/check_generated_translation_unit.py",
    ]
    assert "--function-c-dir" in translation_unit_cmd
    behavior_cmd = captured[2][1]
    assert behavior_cmd[:2] == [
        test_pipeline.sys.executable,
        "scripts/check_sortd_generated_sort_core.py",
    ]
    assert behavior_cmd[behavior_cmd.index("--transcript") + 1] == str(
        tmp_path / "sortd.txt"
    )


def test_sortdemo_proc_status_lane_is_explicitly_diagnostic(monkeypatch, tmp_path):
    binary = tmp_path / "SORTDEMO.EXE"
    binary.write_bytes(b"MZ")
    captured: list[list[str]] = []

    def fake_run_command(name, cmd, *, env=None):
        captured.append(cmd)
        return test_pipeline.LaneResult(
            name,
            test_pipeline.LaneStatus.PASSED,
            cmd,
            0.1,
            returncode=0,
        )

    monkeypatch.setattr(test_pipeline, "_run_command", fake_run_command)
    args = test_pipeline._parse_args(
        [
            "--sortdemo-binary",
            str(binary),
            "--sortdemo-status-out",
            str(tmp_path / "status.json"),
            "--sortdemo-transcript-out",
            str(tmp_path / "status.txt"),
        ]
    )

    result = test_pipeline._sortdemo_status_lane(args, per_function_proc=True)

    assert result.name == "sortdemo-status-proc-diagnostic"
    assert "--per-function-proc" in captured[0]
    assert "--max-functions" not in captured[0]
    assert captured[0][captured[0].index("--out") + 1].endswith(
        "status_proc_diagnostic.json"
    )


def test_sortdemo_status_lane_skips_missing_binary_by_default(tmp_path):
    args = test_pipeline._parse_args(["--sortdemo-binary", str(tmp_path / "missing.EXE")])

    result = test_pipeline._sortdemo_status_lane(args)

    assert result.status == test_pipeline.LaneStatus.SKIPPED
    assert result.reason == f"SORTDEMO binary not found: {tmp_path / 'missing.EXE'}"


def test_pipeline_main_writes_summary(monkeypatch, tmp_path):
    monkeypatch.setattr(
        test_pipeline,
        "_unit_lane",
        lambda: test_pipeline.LaneResult(
            "unit-focused",
            test_pipeline.LaneStatus.PASSED,
            ["pytest"],
            0.1,
            returncode=0,
            budget_seconds=30.0,
            budget_status=test_pipeline.BudgetStatus.PASSED,
        ),
    )

    rc = test_pipeline.main(["--lane", "unit-focused", "--out", str(tmp_path / "summary.json")])

    assert rc == 0
    assert (tmp_path / "summary.json").exists()
    summary = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert summary["timed_out"] == 0
    assert summary["results"][0]["status"] == "passed"
    assert summary["results"][0]["budget_status"] == "passed"


def test_pipeline_main_fails_when_lane_times_out(monkeypatch, tmp_path):
    monkeypatch.setattr(
        test_pipeline,
        "_unit_lane",
        lambda: test_pipeline.LaneResult(
            "unit-focused",
            test_pipeline.LaneStatus.TIMED_OUT,
            ["pytest"],
            31.0,
            reason="timed out after 30 seconds",
        ),
    )

    rc = test_pipeline.main(["--lane", "unit-focused", "--out", str(tmp_path / "summary.json")])

    assert rc == 1
    summary = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    assert summary["failed"] == 0
    assert summary["timed_out"] == 1
    assert summary["results"][0]["status"] == "timed_out"
