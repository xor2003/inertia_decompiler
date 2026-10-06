from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

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


def test_unit_lane_promotes_split_return_provenance_controls():
    """Physical-return witness provenance and jump transparency run routinely."""
    assert "angr_platforms/tests/test_x86_16_interprocedural_storage_return_split.py" in test_pipeline.FOCUSED_PYTEST_TARGETS


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


@pytest.mark.parametrize("target", (
    "angr_platforms/tests/test_x86_16_segment_state_call_boundary.py",
    "angr_platforms/tests/test_x86_16_segment_state_call_outputs.py",
    "angr_platforms/tests/test_x86_16_ir_constant_known_lanes.py",
    "angr_platforms/tests/test_x86_16_ir_constant_flow_refusals.py",
))
def test_routine_lanes_promote_ir_register_state_contract(target: str) -> None:
    """Keep register-state proofs and refusals in pipeline and both Make lists."""
    assert test_pipeline.FOCUSED_PYTEST_TARGETS.count(target) == 1
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    assert makefile.count(f"\t{target} \\\n") == 2


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
        "binary-budgeted",
        "unit-focused",
        "pytest-serial",
        "linux-process-controls",
        "makefile-gnu-oracle",
        "gp-word-native",
        "binary-relational",
        "ultra-quickc-fixtures",
        "msc6-tiny-full-pipeline",
    )


def test_fast_tier_keeps_budgeted_proofs_and_regular_local_units():
    args = test_pipeline._parse_args(["--tier", "fast"])

    assert test_pipeline._selected_lanes(args) == ("binary-budgeted", "unit-focused", "pytest-serial", "linux-process-controls")


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


def test_near_pointer_native_runtime_is_default_execution_only():
    """The new MS C/KVM representation control must not add a fast DOS dependency."""
    target = "angr_platforms/tests/test_x86_16_near_pointer_native_runtime.py"
    assert target not in test_pipeline.FOCUSED_PYTEST_TARGETS
    assert test_pipeline.RELATIONAL_BINARY_PYTEST_TARGETS.count(target) == 1
    for tier in ("default", "expanded"):
        assert "binary-relational" in test_pipeline.PIPELINE_TIERS[tier]
    assert "binary-relational" not in test_pipeline.PIPELINE_TIERS["fast"]


def test_expanded_tier_adds_sidecar_free_and_sortdemo_status_lanes():
    args = test_pipeline._parse_args(["--tier", "expanded"])

    assert test_pipeline._selected_lanes(args) == (
        "binary-budgeted",
        "unit-focused",
        "pytest-serial",
        "linux-process-controls",
        "makefile-gnu-oracle",
        "gp-word-native",
        "binary-relational",
        "ultra-quickc-fixtures",
        "msc6-tiny-full-pipeline",
        "sortd-sidecar-free",
        "sortdemo-status",
    )


def test_makefile_exposes_expanded_pipeline_targets():
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")

    assert "TEST_PIPELINE_LOCK ?= $(CURDIR)/.cache/locks/test-pipeline.lock" in makefile
    assert (
        "decompiler-check-expanded: architecture-check agent-context-check "
        "test-ownership-check pytest test-pipeline-expanded"
    ) in makefile
    assert (
        "\ntest-pipeline-expanded: decompiler-contracts\n"
        '\tmkdir -p "$(dir $(TEST_PIPELINE_LOCK))"\n'
        '\tflock "$(TEST_PIPELINE_LOCK)" $(PYTHON) '
        "scripts/test_pipeline.py --tier expanded --require-external"
    ) in makefile


def test_makefile_exposes_fast_quality_target_with_linters() -> None:
    """The fast gate retains contracts and admission before its broad pipeline."""
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")

    assert "quality-fast: linters type-ratchet-changed decompiler-check-fast" in makefile
    assert "\ntype-ratchet-changed:\n" in makefile
    assert "decompiler-check-fast: architecture-check-fast agent-context-check test-ownership-check test-pipeline-fast" in makefile
    assert (
        '\ntest-pipeline: decompiler-contracts\n'
        '\tmkdir -p "$(dir $(TEST_PIPELINE_LOCK))"\n'
        '\tflock "$(TEST_PIPELINE_LOCK)" $(PYTHON) '
        "scripts/test_pipeline.py --require-external"
    ) in makefile
    assert (
        '\ntest-pipeline-fast: comparator-check-fast\n'
        '\tmkdir -p "$(dir $(TEST_PIPELINE_LOCK))"\n'
        '\tflock "$(TEST_PIPELINE_LOCK)" $(PYTHON) '
        "scripts/test_pipeline.py --tier fast --require-external"
    ) in makefile
    assert "\ncomparator-check-fast: decompiler-contracts\n" in makefile
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


@pytest.mark.parametrize(("workers", "expected"), [(1, 1), (3, 2), (6, 2)])
def test_budgeted_binary_lane_caps_concurrency_without_losing_coverage(monkeypatch, workers, expected):
    """All standard tiers retain the proofs outside the six-worker unit pool."""
    commands = []

    def capture(name, command):
        commands.append(command)
        return test_pipeline.LaneResult(name, test_pipeline.LaneStatus.PASSED, command, 0.0, returncode=0)

    monkeypatch.setattr(test_pipeline, "_run_command", capture)
    result = test_pipeline._budgeted_binary_lane(workers)
    target = "angr_platforms/tests/test_dosunit_transitive_callees.py"
    assert result.status is test_pipeline.LaneStatus.PASSED
    assert commands[0][commands[0].index("-n") + 1] == str(expected)
    assert commands[0].count(target) == 1
    assert target not in test_pipeline.FOCUSED_PYTEST_TARGETS
    for lanes in test_pipeline.PIPELINE_TIERS.values():
        assert lanes.count("binary-budgeted") == 1
        assert lanes.index("binary-budgeted") < lanes.index("unit-focused")


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
    assert captured[0][captured[0].index("-n") + 1] == "3"
    assert captured[0][captured[0].index("--dist") + 1] == "loadgroup"
    assert "--durations-min=1.0" in captured[0]


@pytest.mark.parametrize("lane", ["unit-focused", "binary-relational"])
@pytest.mark.parametrize("workers", [1, 6])
def test_pipeline_forwards_selected_pytest_workers(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, lane: str, workers: int,
) -> None:
    """CLI worker selection reaches both pytest lanes without launching tests."""
    commands: list[list[str]] = []

    def capture(name: str, command: list[str]) -> test_pipeline.LaneResult:
        commands.append(command)
        return test_pipeline.LaneResult(name, test_pipeline.LaneStatus.PASSED, command, 0.0, returncode=0)

    monkeypatch.setattr(test_pipeline, "_run_command", capture)
    assert test_pipeline.main([
        "--lane", lane, "--pytest-workers", str(workers),
        "--out", str(tmp_path / "report.json"),
    ]) == 0
    assert len(commands) == 1
    assert commands[0][commands[0].index("-n") + 1] == str(workers)


@pytest.mark.parametrize("workers", ["0", "7"])
def test_pipeline_rejects_out_of_budget_pytest_workers(workers: str) -> None:
    """Invalid pool sizes refuse rather than silently oversubscribing."""
    with pytest.raises(SystemExit) as error:
        test_pipeline._parse_args(["--pytest-workers", workers])
    assert error.value.code == 2


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
        lambda workers: test_pipeline.LaneResult(
            "unit-focused",
            test_pipeline.LaneStatus.PASSED,
            ["pytest", "-n", str(workers)],
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
        lambda workers: test_pipeline.LaneResult(
            "unit-focused",
            test_pipeline.LaneStatus.TIMED_OUT,
            ["pytest", "-n", str(workers)],
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


def test_relational_binary_lane_keeps_expensive_proofs_in_default_pipeline(monkeypatch):
    """Real binary regressions run routinely without extending the fast unit lane."""
    expected = {
        "angr_platforms/tests/test_dosunit_signed_divmod.py",
        "angr_platforms/tests/test_flat32_dependency_cache.py",
        "angr_platforms/tests/test_flat32_loop_call_failure_report.py",
        "angr_platforms/tests/test_ordered_io_native.py",
        "angr_platforms/tests/test_ordered_io_native_extended.py",
        "angr_platforms/tests/test_pe32_import_service.py",
        "angr_platforms/tests/test_pe32_import_service_cli.py",
        "angr_platforms/tests/test_pe32_import_service_schema.py",
        "angr_platforms/tests/test_real16_indirect_call_composition.py",
        "angr_platforms/tests/test_real16_indirect_call_multiarm.py",
        "angr_platforms/tests/test_symbolic_terminal_configured_limits.py",
        "angr_platforms/tests/test_symbolic_terminal_faults.py",
        "angr_platforms/tests/test_symbolic_terminal_ivt_precision.py",
        "angr_platforms/tests/test_symbolic_terminal_pe32_thunk_census.py",
        "angr_platforms/tests/test_symbolic_terminal_service_census.py",
        "angr_platforms/tests/test_symbolic_terminal_services.py",
        "angr_platforms/tests/test_symbolic_terminal_signed_divmod.py",
        "angr_platforms/tests/test_x86_16_immediate_port_vex.py",
        "angr_platforms/tests/test_x86_16_native_helper_call_retention.py",
        "angr_platforms/tests/test_binary_callee_repeat_intake.py",
        "angr_platforms/tests/test_m4_exit_controls.py",
        "angr_platforms/tests/test_m4_pe32_relations.py",
        "angr_platforms/tests/test_flat32_loop_calls_public.py",
        "angr_platforms/tests/test_replay_capture_cohorts.py",
        "angr_platforms/tests/test_dosunit_kvikdos_strict_native.py",
        "angr_platforms/tests/test_dosunit_kvikdos_worker_native.py",
        "angr_platforms/tests/test_macro_step_admission.py",
        "angr_platforms/tests/test_macro_step_return_state.py",
        "angr_platforms/tests/test_macro_step_proof.py",
        "angr_platforms/tests/test_macro_step_deadlines.py",
        "angr_platforms/tests/test_macro_step_concat_exhaustion.py",
        "angr_platforms/tests/test_flat32_macro_retry.py",
        "angr_platforms/tests/test_flat32_term_budget.py",
        "angr_platforms/tests/test_x86_16_clinic_binary_terminal_control.py",
        "angr_platforms/tests/test_binary_callee_region_scan.py",
        "angr_platforms/tests/test_binary_callee_region_intake.py",
        "angr_platforms/tests/test_ssa_declared_scope.py",
        "angr_platforms/tests/test_real16_program_replay.py",
        "angr_platforms/tests/test_pe32_program_replay.py",
        "angr_platforms/tests/test_pe32_program_cli.py",
        "angr_platforms/tests/test_real16_program_output_integration.py",
        "angr_platforms/tests/test_real16_program_input_integration.py",
        "angr_platforms/tests/test_real16_program_file_copy.py",
        "angr_platforms/tests/test_real16_program_cli.py",
        "angr_platforms/tests/test_binary_callee_intake.py",
        "angr_platforms/tests/test_binary_callee_intake_review.py",
        "angr_platforms/tests/test_real16_uncatalogued_calls.py",
        "angr_platforms/tests/test_recursive_call_continuation_binding.py",
        "angr_platforms/tests/test_real16_admission_control_domains.py",
        "angr_platforms/tests/test_recursive_joint_actual_binary.py",
        "angr_platforms/tests/test_flat32_pe32_recursive_joint.py",
    "angr_platforms/tests/test_real16_recursive_public.py",
        "angr_platforms/tests/test_pe32_recursive_public.py",
        "angr_platforms/tests/test_symbolic_terminal.py",
        "angr_platforms/tests/test_symbolic_terminal_cli.py",
        "angr_platforms/tests/test_symbolic_terminal_read_permissions.py",
        "angr_platforms/tests/test_symbolic_terminal_partial_pe_data.py",
        "angr_platforms/tests/test_symbolic_terminal_output_coverage.py",
        "angr_platforms/tests/test_real16_normal_outcome_scope.py",
        "angr_platforms/tests/test_real16_bound_control_scope.py",
        "angr_platforms/tests/test_real16_symbolic_call_control.py",
        "angr_platforms/tests/test_real16_symbolic_successors.py",
        "angr_platforms/tests/test_x86_16_relative_control_edge.py",
        "angr_platforms/tests/test_x86_16_relative_condition_producers.py",
        "angr_platforms/tests/test_real16_native_control_scope.py",
        "angr_platforms/tests/test_real16_native_control_scope_edges.py",
        "angr_platforms/tests/test_real16_region_control.py",
        "angr_platforms/tests/test_real16_address_model_closure.py",
        "angr_platforms/tests/test_real16_loader_arch.py",
        "angr_platforms/tests/test_real16_direct_jmp_coordinates.py",
        "angr_platforms/tests/test_direct_near_call_target_binding.py",
        "angr_platforms/tests/test_x86_16_declared_call_consumption.py",
        "angr_platforms/tests/test_declared_call_transport.py",
        "angr_platforms/tests/test_projected_call_consumption.py",
        "angr_platforms/tests/test_declared_call_admission.py",
        "angr_platforms/tests/test_declared_call_schema.py",
        "angr_platforms/tests/test_declared_call_binding.py",
        "angr_platforms/tests/test_segment_call_binding_regression.py",
        "angr_platforms/tests/test_segment_nonleaf_native.py",
        "angr_platforms/tests/test_nop_census_8616.py",
        "angr_platforms/tests/test_nop_native_binding.py",
        "angr_platforms/tests/test_nop_cache_cost.py",
        "angr_platforms/tests/test_recursive_terminal_address_boundary.py",
        "angr_platforms/tests/test_recursive_static_control_shifts.py",
        "angr_platforms/tests/test_recursive_fetched_code_invariant.py",
        "angr_platforms/tests/test_x86_16_near_pointer_native_runtime.py",
        "angr_platforms/tests/test_real16_return_coordinates.py",
        "angr_platforms/tests/test_real16_branch_regions.py",
        "angr_platforms/tests/test_real16_rotation_regions.py",
        "angr_platforms/tests/test_flat32_rotation_regions.py",
        "angr_platforms/tests/test_rotation_concrete_replay.py",
        "angr_platforms/tests/test_relational_branch_public32.py",
        "angr_platforms/tests/test_relational_rotation_public32.py",
        "angr_platforms/tests/test_relational_saved_public32.py",
        "angr_platforms/tests/test_relational_saved_public16.py",
    }
    assert set(test_pipeline.RELATIONAL_BINARY_PYTEST_TARGETS) == expected
    assert expected.isdisjoint(test_pipeline.FOCUSED_PYTEST_TARGETS)
    for tier in ("default", "expanded"):
        assert "binary-relational" in test_pipeline._selected_lanes(
            test_pipeline._parse_args(["--tier", tier]))
    assert "binary-relational" not in test_pipeline._selected_lanes(
        test_pipeline._parse_args(["--tier", "fast"]))
    calls = []
    monkeypatch.setattr(test_pipeline, "_run_command", lambda name, command: calls.append((name, command)))
    test_pipeline._relational_binary_lane()
    assert len(calls) == 1
    name, command = calls[0]
    assert name == "binary-relational"
    assert command[command.index("-n") + 1] == "3"
    assert command[command.index("--dist") + 1] == "loadgroup"
    assert "--tb=short" in command
    assert expected <= set(command)


def test_capture_cohort_collection_preserves_one_shared_fixture(tmp_path: Path) -> None:
    """Keep four concrete assertions grouped without executing their costly fixture."""
    cohort = "angr_platforms/tests/test_replay_capture_cohorts.py"
    assert test_pipeline.RELATIONAL_BINARY_PYTEST_TARGETS.count(cohort) == 1
    assert cohort not in test_pipeline.FOCUSED_PYTEST_TARGETS
    for quick in ("test_flat32_loop_calls.py", "test_replay_capture_vectors.py"):
        path = f"angr_platforms/tests/{quick}"
        assert test_pipeline.FOCUSED_PYTEST_TARGETS.count(path) == 1
        assert path not in test_pipeline.RELATIONAL_BINARY_PYTEST_TARGETS
    receipt = tmp_path / "collection.json"
    plugin = tmp_path / "capture_collection.py"
    plugin.write_text(
        "import json, os\n"
        "from pathlib import Path\n"
        "def pytest_collection_finish(session):\n"
        "    rows = []\n"
        "    for item in session.items:\n"
        "        groups = [m.kwargs.get('name', m.args[0] if m.args else None) "
        "for m in item.iter_markers('xdist_group')]\n"
        "        fixture = item._fixtureinfo.name2fixturedefs['receipts'][-1]\n"
        "        rows.append({'name': item.name, 'groups': groups, 'scope': fixture.scope})\n"
        "    Path(os.environ['CAPTURE_COLLECTION_RECEIPT']).write_text(json.dumps(rows))\n"
    )
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join((str(tmp_path), str(REPO_ROOT), env.get("PYTHONPATH", "")))
    env["CAPTURE_COLLECTION_RECEIPT"] = str(receipt)
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-o", "addopts=", "--collect-only",
         "-p", "capture_collection", cohort],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=60, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    rows = json.loads(receipt.read_text())
    assert len(rows) == 4 and len({row["name"] for row in rows}) == 4
    assert all(row["groups"] == ["replay_capture_cohorts"] and row["scope"] == "session" for row in rows)


def test_guarded_controls_partition_complete_source_inventory():
    """Host and guarded lanes retain every original test exactly once."""
    import ast
    from collections import Counter

    all_targets = (*test_pipeline.FOCUSED_PYTEST_TARGETS,
                   *test_pipeline.SERIAL_PYTEST_TARGETS,
                   *test_pipeline.LINUX_PROCESS_PYTEST_TARGETS,
                   *test_pipeline.GP_NATIVE_PYTEST_TARGETS)
    for path in test_pipeline.SPLIT_CONTROL_TEST_FILES:
        expected = {
            f"{path}::{node.name}"
            for node in ast.parse((REPO_ROOT / path).read_text()).body
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
        }
        selected = [target for target in all_targets if target.partition("::")[0] == path]
        assert Counter(selected) == Counter(expected)
        assert path not in test_pipeline.FOCUSED_PYTEST_TARGETS


def test_guarded_control_lanes_follow_worker_pool():
    """Nested subprocesses start only after the outer worker pool exits."""
    for tier, lanes in test_pipeline.PIPELINE_TIERS.items():
        assert lanes.index("unit-focused") < lanes.index("pytest-serial") < lanes.index("linux-process-controls")
        assert ("gp-word-native" in lanes) == (tier != "fast")


def test_gnu_oracle_lane_is_routine_external_coverage():
    for tier, lanes in test_pipeline.PIPELINE_TIERS.items():
        assert ("makefile-gnu-oracle" in lanes) == (tier != "fast")
        if tier != "fast":
            assert lanes.index("linux-process-controls") < lanes.index("makefile-gnu-oracle") < lanes.index("gp-word-native")


@pytest.mark.parametrize("required,status", [(False, "skipped"), (True, "failed")])
def test_gnu_oracle_unavailable_does_not_pass(monkeypatch, required, status):
    monkeypatch.setattr(test_pipeline.shutil, "which", lambda _name: None)
    monkeypatch.setattr(test_pipeline, "_run_command", lambda *_args, **_kwargs: pytest.fail("must not launch"))
    result = test_pipeline._makefile_gnu_oracle_lane(test_pipeline._parse_args(["--require-external"] if required else []))
    assert result.status.value == status


@pytest.mark.parametrize("count,skipped,status", [(43, False, "passed"), (43, True, "skipped"), (0, False, "failed"), (42, False, "failed"), (1, True, "failed")])
def test_gnu_oracle_receipt_requires_exact_coverage(monkeypatch, count, skipped, status):
    monkeypatch.setattr(test_pipeline.shutil, "which", lambda _name: "/usr/bin/make")
    def capture(name, command, *, env=None):
        child = '<skipped message="make unavailable"/>' if skipped else ''
        Path(command[command.index("--junitxml") + 1]).write_text('<testsuites><testsuite>' + f'<testcase>{child}</testcase>' * count + '</testsuite></testsuites>')
        return test_pipeline.LaneResult(name, test_pipeline.LaneStatus.PASSED, command, 0.1, returncode=0)
    monkeypatch.setattr(test_pipeline, "_run_command", capture)
    result = test_pipeline._makefile_gnu_oracle_lane(test_pipeline._parse_args([]))
    assert result.status.value == status


def test_selected_gnu_oracle_parameter_has_one_case(monkeypatch):
    monkeypatch.setattr(test_pipeline.shutil, "which", lambda _name: "/usr/bin/make")
    calls = []
    def capture(name, targets, **options):
        calls.append((name, targets, options))
        return test_pipeline.LaneResult(name, test_pipeline.LaneStatus.PASSED, [], 0.0)
    monkeypatch.setattr(test_pipeline, "_guarded_pytest_lane", capture)
    target = test_pipeline.GNU_MAKE_ORACLE_PYTEST_TARGETS[0] + "[selected]"
    test_pipeline._makefile_gnu_oracle_lane(test_pipeline._parse_args([]), (target,))
    assert calls[0][1] == (target,)
    assert calls[0][2]["expected_cases"] == 1
    assert calls[0][2]["strict_count"] is True


def test_gnu_oracle_split_keeps_host_controls_without_skip_and_all_external_functions():
    import ast

    host = ast.parse((REPO_ROOT / "angr_platforms/tests/test_makefile_variable_expansion.py").read_text())
    oracle = ast.parse((REPO_ROOT / test_pipeline.GNU_MAKE_ORACLE_TEST_FILE).read_text())
    oracle_names = {
        node.name for node in oracle.body
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
    }
    assert len(oracle_names) == 9
    assert {target.split("::")[1] for target in test_pipeline.GNU_MAKE_ORACLE_PYTEST_TARGETS} == oracle_names
    assert sum(test_pipeline.GNU_MAKE_ORACLE_CASE_COUNTS.values()) == 43
    assert test_pipeline.GNU_MAKE_ORACLE_TEST_FILE not in test_pipeline.FOCUSED_PYTEST_TARGETS
    assert "angr_platforms/tests/test_makefile_variable_expansion.py" in test_pipeline.FOCUSED_PYTEST_TARGETS
    for node in host.body:
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
            assert node.name not in oracle_names
            assert not any("skip" in ast.unparse(decorator) for decorator in node.decorator_list)


@pytest.mark.parametrize("parameter", [False, True])
def test_make_profile_routes_only_selected_gnu_oracle_controls(parameter):
    target = test_pipeline.GNU_MAKE_ORACLE_PYTEST_TARGETS[0] + "[selected]" if parameter else test_pipeline.GNU_MAKE_ORACLE_TEST_FILE
    result = subprocess.run(
        ["make", "-n", "pytest-profile", f"PYTHON={sys.executable}",
         f"PYTEST_PROFILE_TARGETS={target}", "CONTROL_HOST_TARGETS_COMMAND=false"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "scripts/pytest_profile.py" not in result.stdout
    assert "--lane makefile-gnu-oracle" in result.stdout
    assert "--lane pytest-serial" not in result.stdout
    assert (f"--control-target {target!r}" in result.stdout) is parameter


def test_make_host_inventory_excludes_guarded_gnu_oracle_file():
    text = (REPO_ROOT / "Makefile").read_text()
    assert "QA_HOST_PYTEST_TARGETS = $(filter-out $(SPLIT_CONTROL_TEST_FILES) $(GNU_MAKE_ORACLE_TEST_FILE)," in text
    recipe = text.split("\npytest-files:\n", 1)[1].split("\npytest-all:", 1)[0]
    assert '$(GNU_MAKE_ORACLE_TEST_FILE)) control_lanes="$$control_lanes makefile-gnu-oracle"' in recipe
    assert '$(GNU_MAKE_ORACLE_TEST_FILE)::*) control_lanes="$$control_lanes makefile-gnu-oracle"; guarded_targets=' in recipe


@pytest.mark.parametrize("parameter", [False, True])
def test_make_selected_files_execute_only_selected_gnu_oracle_lane(tmp_path, parameter):
    """Selected oracle files and cases bypass the host pool without widening selection."""
    import json

    target = test_pipeline.GNU_MAKE_ORACLE_PYTEST_TARGETS[0] + "[selected]" if parameter else test_pipeline.GNU_MAKE_ORACLE_TEST_FILE
    log = tmp_path / "calls.jsonl"
    wrapper = tmp_path / "python-wrapper"
    wrapper.write_text(
        f"#!{sys.executable}\nimport json, pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "if args[:1] == ['-c']:\n"
        "    print(sys.executable)\n"
        "elif '--print-host-controls' in args:\n"
        f"    print({test_pipeline.SERIAL_PYTEST_TARGETS[0].split('::')[0] + '::test_nonfailure_reports_are_quiet'!r})\n"
        "elif args and args[0].endswith('test_ownership_manifest.py'):\n"
        "    print('')\n"
        "else:\n"
        f"    with pathlib.Path({str(log)!r}).open('a') as stream:\n"
        "        stream.write(json.dumps(args) + '\\n')\n"
    )
    wrapper.chmod(0o755)
    result = subprocess.run(
        ["make", "pytest-files", f"PYTHON={wrapper}", "FILES=", f"PYTEST_FILES={target}"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stderr
    commands = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(commands) == 1
    command = commands[0]
    assert command[:3] == ["scripts/test_pipeline.py", "--lane", "makefile-gnu-oracle"]
    assert ("--control-target" in command) is parameter
    if parameter:
        assert command[command.index("--control-target") + 1] == target


@pytest.mark.parametrize("xml,status", [
    ("<testsuites><testsuite><testcase/><testcase/></testsuite></testsuites>", "passed"),
    ("<testsuites><testsuite><testcase><skipped message=\"KVM denied\"/></testcase></testsuite></testsuites>", "skipped"),
    ("<testsuites><testsuite/></testsuites>", "failed"),
])
def test_serial_control_receipt_does_not_launder_missing_coverage(monkeypatch, xml, status):
    """A zero exit needs executed test cases; skipped coverage stays visible."""
    commands = []

    def capture(name, command, *, env=None):
        commands.append(command)
        Path(command[command.index("--junitxml") + 1]).write_text(xml)
        return test_pipeline.LaneResult(name, test_pipeline.LaneStatus.PASSED, command, 0.1, returncode=0)

    monkeypatch.setattr(test_pipeline, "_run_command", capture)
    result = test_pipeline._guarded_pytest_lane("pytest-serial", test_pipeline.SERIAL_PYTEST_TARGETS, expected_cases=2)
    assert result.status.value == status
    assert commands[0][commands[0].index("-n") + 1] == "0"
    assert commands[0][commands[0].index("-o") + 1] == "addopts="
    assert commands[0][-1] == test_pipeline.SERIAL_PYTEST_TARGETS[0]
    assert result.details is not None
    assert result.details["collected"] == (0 if status == "failed" else 1 if status == "skipped" else 2)


def test_linux_control_refuses_unsupported_host_before_launch(monkeypatch):
    """A platform-only control cannot pass just because pytest skips it."""
    monkeypatch.setattr(test_pipeline.sys, "platform", "win32")
    monkeypatch.setattr(test_pipeline, "_run_command", lambda *_args, **_kwargs: pytest.fail("must not launch"))
    assert test_pipeline._linux_process_lane().status is test_pipeline.LaneStatus.SKIPPED


@pytest.mark.parametrize("required,status", [(False, "skipped"), (True, "failed")])
def test_native_word_control_missing_device_is_accounted(monkeypatch, required, status):
    """Missing KVM is optional refusal or required failure, never host acceptance."""
    from scripts.compiler_coverage_provenance import KVMAccessEvidence, KVMAccessStatus

    monkeypatch.setattr(test_pipeline, "_external_tools_available", lambda *_args: (True, None))
    monkeypatch.setattr(test_pipeline, "kvm_access_evidence", lambda: KVMAccessEvidence(KVMAccessStatus.DENIED, 13))
    monkeypatch.setattr(test_pipeline, "_run_command", lambda *_args, **_kwargs: pytest.fail("must not launch"))
    args = test_pipeline._parse_args(["--require-external"] if required else [])
    result = test_pipeline._gp_word_native_lane(args)
    assert result.status.value == status
    assert "denied" in result.reason


def test_make_focused_coverage_sequences_guarded_controls():
    """Routine Make runs preserve guarded controls after its outer pytest pool."""
    text = (REPO_ROOT / "Makefile").read_text()
    recipe = text.split("\npytest:\n", 1)[1].split("\npytest-profile:", 1)[0]
    assert "$(QA_HOST_PYTEST_TARGETS)" in recipe
    assert recipe.index("-m pytest") < recipe.index("--lane pytest-serial")
    assert "--lane linux-process-controls" in recipe
    assert "--lane gp-word-native" in recipe


@pytest.mark.parametrize("required,status", [(False, "skipped"), (True, "failed")])
def test_native_control_accounts_for_runtime_skip_after_precheck(monkeypatch, required, status):
    """A race after prerequisite checks cannot turn skipped DOS coverage green."""
    def capture(name, command, *, env=None):
        assert "PYTEST_XDIST_WORKER" not in env
        assert env["PYTEST_ADDOPTS"] == ""
        Path(command[command.index("--junitxml") + 1]).write_text(
            "<testsuites><testsuite><testcase><skipped message=\"runtime unavailable\"/></testcase></testsuite></testsuites>",
        )
        return test_pipeline.LaneResult(name, test_pipeline.LaneStatus.PASSED, command, 0.1, returncode=0)

    monkeypatch.setenv("PYTEST_XDIST_WORKER", "gw0")
    monkeypatch.setattr(test_pipeline, "_run_command", capture)
    result = test_pipeline._guarded_pytest_lane(
        "gp-word-native", test_pipeline.GP_NATIVE_PYTEST_TARGETS, require_available=required,
    )
    assert result.status.value == status
    assert result.details["skipped"] == 1
    assert result.details["skip_reasons"] == ["runtime unavailable"]


@pytest.mark.parametrize("receipt", [None, "<invalid", "<testsuites><testsuite><testcase/></testsuite></testsuites>"])
def test_required_serial_control_rejects_missing_invalid_or_partial_receipt(monkeypatch, receipt):
    """Missing evidence and a dropped parameter case must fail closed."""
    def capture(name, command, *, env=None):
        if receipt is not None:
            Path(command[command.index("--junitxml") + 1]).write_text(receipt)
        return test_pipeline.LaneResult(name, test_pipeline.LaneStatus.PASSED, command, 0.1, returncode=0)

    monkeypatch.setattr(test_pipeline, "_run_command", capture)
    assert test_pipeline._serial_pytest_lane().status is test_pipeline.LaneStatus.FAILED


def test_host_control_selector_cli_derives_from_focused_owner(capsys):
    """Make reads its split inventory from the pipeline authoritative owner."""
    assert test_pipeline.main(["--print-host-controls"]) == 0
    assert capsys.readouterr().out.split() == [
        target for target in test_pipeline.FOCUSED_PYTEST_TARGETS
        if target.partition("::")[0] in test_pipeline.SPLIT_CONTROL_TEST_FILES
    ]


def test_make_selected_files_route_guarded_nodes_after_host_tests():
    """Explicit whole-file and guarded-node requests keep their serial controls."""
    text = (REPO_ROOT / "Makefile").read_text()
    recipe = text.split("\npytest-files:\n", 1)[1].split("\npytest-all:", 1)[0]
    for targets in (test_pipeline.SERIAL_PYTEST_TARGETS, test_pipeline.LINUX_PROCESS_PYTEST_TARGETS, test_pipeline.GP_NATIVE_PYTEST_TARGETS):
        assert targets[0] + "*" in recipe
    assert recipe.index("-m pytest") < recipe.index("scripts/test_pipeline.py $$lane_args")


@pytest.mark.parametrize("provider,error", [("false", "provider command failed"), ("true", "provider returned an empty inventory")])
def test_make_host_control_provider_failure_refuses_omitted_tests(provider, error):
    """Make must not silently turn a failed selector provider into lost tests."""
    result = subprocess.run(
        ["make", "-n", "pytest", f"PYTHON={sys.executable}", f"CONTROL_HOST_TARGETS_COMMAND={provider}"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode != 0
    assert error in result.stderr


@pytest.mark.parametrize("target", [
    "angr_platforms/tests/test_compact_paths.py",
    "angr_platforms/tests/test_pytest_live_failures.py::test_nonfailure_reports_are_quiet",
])
def test_make_profile_keeps_explicit_unrelated_or_host_selector(target):
    """Custom profile requests must not acquire unrelated control tests."""
    result = subprocess.run(
        ["make", "-n", "pytest-profile", f"PYTHON={sys.executable}",
         f"PYTEST_PROFILE_TARGETS={target}", "CONTROL_HOST_TARGETS_COMMAND=false"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert target in result.stdout
    assert "--lane" not in result.stdout
    assert "test_compiler_coverage_runner.py::" not in result.stdout
    assert "test_x86_16_gp_word_runtime.py::" not in result.stdout


def test_make_profile_preserves_explicit_guarded_parameter_case():
    """A selected nested case goes to its serial lane without broad collection."""
    target = test_pipeline.SERIAL_PYTEST_TARGETS[0] + "[2]"
    result = subprocess.run(
        ["make", "-n", "pytest-profile", f"PYTHON={sys.executable}",
         f"PYTEST_PROFILE_TARGETS={target}", "CONTROL_HOST_TARGETS_COMMAND=false"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "scripts/pytest_profile.py" not in result.stdout
    assert "--lane pytest-serial" in result.stdout
    assert f"--control-target {target!r}" in result.stdout
    assert "--lane gp-word-native" not in result.stdout


def test_selected_serial_parameter_keeps_exact_command_and_expected_count(monkeypatch):
    """An explicit single case must not silently expand into the other case."""
    captured = []
    target = test_pipeline.SERIAL_PYTEST_TARGETS[0] + "[2]"

    def capture(name, targets, *, expected_cases, require_available):
        captured.append((targets, expected_cases, require_available))
        return test_pipeline.LaneResult(name, test_pipeline.LaneStatus.PASSED, [], 0.0)

    monkeypatch.setattr(test_pipeline, "_guarded_pytest_lane", capture)
    test_pipeline._serial_pytest_lane(test_pipeline._selected_control_targets([target], test_pipeline.SERIAL_PYTEST_TARGETS))
    assert captured == [((target,), 1, True)]
