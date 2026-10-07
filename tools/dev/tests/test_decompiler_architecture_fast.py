"""Tests for architecture guard entrypoints and required pipeline lanes."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import inertia.cli.architecture_runtime_guard as architecture_runtime_guard
import tools.dev.check_decompiler_architecture as architecture_check


def _actual_pipeline_lanes() -> dict[str, tuple[str, ...]]:
    """Read the production lane declarations without importing the runner."""
    path = Path(__file__).resolve().parents[3] / "tools/dev/test_pipeline.py"
    return architecture_check._pipeline_tier_literals(ast.parse(path.read_text()))


def _lane_contract_errors(lanes: dict[str, tuple[str, ...]]) -> tuple[str, ...]:
    """Select lane-contract diagnostics independently of fixture marker checks."""
    root = Path(__file__).resolve().parents[3]
    path = root / "tools/dev/test_pipeline.py"
    violations = architecture_check._pipeline_lane_contract_violations_8616(
        path, path.read_text(), lanes, (), root,
    )
    return tuple(item.detail for item in violations if item.rule == "test-pipeline-tier-contract")


def test_full_guard_accepts_registered_budgeted_and_relational_lanes() -> None:
    """The full guard must agree with the independently registered runner lanes."""
    assert not _lane_contract_errors(_actual_pipeline_lanes())


@pytest.mark.parametrize("tier", ["fast", "default", "expanded"])
def test_full_guard_rejects_missing_budgeted_binary_admission(tier: str) -> None:
    """Every tier must retain the bounded proof lane before the unit pool."""
    lanes = _actual_pipeline_lanes()
    assert lanes[tier][0] == "binary-budgeted"
    lanes[tier] = lanes[tier][1:]
    assert any(repr(tier) in detail for detail in _lane_contract_errors(lanes))


@pytest.mark.parametrize("tier", ["fast", "default", "expanded"])
def test_full_guard_rejects_unit_pool_before_binary_admission(tier: str) -> None:
    """Coverage alone is insufficient: proof admission must run before the pool."""
    lanes = _actual_pipeline_lanes()
    first, second, *rest = lanes[tier]
    assert (first, second) == ("binary-budgeted", "unit-focused")
    lanes[tier] = (second, first, *rest)
    assert any(repr(tier) in detail for detail in _lane_contract_errors(lanes))


@pytest.mark.parametrize("tier", ["default", "expanded"])
def test_full_guard_rejects_missing_relational_binary_lane(tier: str) -> None:
    """Default and expanded validation must retain native relational controls."""
    lanes = _actual_pipeline_lanes()
    assert "binary-relational" in lanes[tier]
    lanes[tier] = tuple(lane for lane in lanes[tier] if lane != "binary-relational")
    assert any(repr(tier) in detail for detail in _lane_contract_errors(lanes))


def test_full_guard_still_rejects_external_compiler_in_fast_lane() -> None:
    """Updating local proof coverage must not admit slow external compilation."""
    lanes = _actual_pipeline_lanes()
    lanes["fast"] += ("msc6-tiny-full-pipeline",)
    assert any("'fast'" in detail for detail in _lane_contract_errors(lanes))


@pytest.mark.parametrize("tier", ["fast", "default", "expanded"])
@pytest.mark.parametrize("required", ["pytest-serial", "linux-process-controls"])
def test_full_guard_requires_sequenced_process_controls(tier: str, required: str) -> None:
    """Moving guarded tests out of the worker pool must retain their execution."""
    lanes = _actual_pipeline_lanes()
    assert required in lanes[tier]
    lanes[tier] = tuple(lane for lane in lanes[tier] if lane != required)
    assert any(repr(tier) in detail for detail in _lane_contract_errors(lanes))


@pytest.mark.parametrize("tier", ["default", "expanded"])
def test_full_guard_requires_external_gp_runtime_control(tier: str) -> None:
    """Host-only selectors cannot replace the original DOS execution coverage."""
    lanes = _actual_pipeline_lanes()
    assert "gp-word-native" in lanes[tier]
    lanes[tier] = tuple(lane for lane in lanes[tier] if lane != "gp-word-native")
    assert any(repr(tier) in detail for detail in _lane_contract_errors(lanes))


def _contract_gate_fixture(root: Path, name: str, body: str) -> None:
    """Write a minimal stage containing an explicit pipeline-contract owner."""
    (root / "decompiler_postprocess_stage.py").write_text(
        "from .pipeline.contracts import assert_pipeline_contracts_8616\n"
        f"def {name}(codegen, function):\n    {body}\n",
    )


def test_contract_guard_accepts_current_owned_gate_name(tmp_path: Path) -> None:
    """The guard follows the real 8616 owner rather than its retired spelling."""
    _contract_gate_fixture(tmp_path, "_run_pipeline_contract_gate_8616", "assert_pipeline_contracts_8616(codegen)")
    assert not architecture_check._check_postprocess_stage_runs_pipeline_contract_gate(tmp_path)


def test_contract_guard_rejects_retired_gate_name(tmp_path: Path) -> None:
    """An unrelated legacy helper cannot stand in for the current gate owner."""
    _contract_gate_fixture(tmp_path, "_run_pipeline_contract_gate", "assert_pipeline_contracts_8616(codegen)")
    violations = architecture_check._check_postprocess_stage_runs_pipeline_contract_gate(tmp_path)
    assert any("_run_pipeline_contract_gate_8616" in item.detail for item in violations)


def test_contract_guard_rejects_empty_current_gate(tmp_path: Path) -> None:
    """A present helper must still consume the actual pipeline assertions."""
    _contract_gate_fixture(tmp_path, "_run_pipeline_contract_gate_8616", "return None")
    violations = architecture_check._check_postprocess_stage_runs_pipeline_contract_gate(tmp_path)
    assert any("must call assert_pipeline_contracts_8616" in item.detail for item in violations)


def test_project_map_matches_current_binary_admission_contract() -> None:
    """Navigation must describe the budgeted lane now required by every tier."""
    root = Path(__file__).resolve().parents[3]
    path = root / "reference/project-map.md"
    assert not architecture_check._project_map_doc_violations_8616(path, path.read_text(), root)


@pytest.mark.parametrize("layer", ["build", "reporting", "pytest adapter", "sandbox"])
def test_script_tooling_subdomains_are_owned(tmp_path: Path, layer: str) -> None:
    """Tooling subclasses retain their accurate responsibility declarations."""
    path = tmp_path / "tool.py"
    path.write_text(f'"""Layer: Tooling/{layer}.\nResponsibility: own this tool boundary.\n"""\n')
    assert not architecture_check._check_python_module_layer_headers(
        tmp_path, rule="script-module-layer-header", expected_layer="Layer: Tooling",
    )


@pytest.mark.parametrize("layer", ["Alias", "ToolingFake", "Tooling_wrong"])
def test_script_header_cannot_claim_foreign_namespace(tmp_path: Path, layer: str) -> None:
    """Prefix similarity cannot make a foreign layer belong to Tooling."""
    (tmp_path / "tool.py").write_text(f'"""Layer: {layer}.\nResponsibility: own this boundary.\n"""\n')
    assert architecture_check._check_python_module_layer_headers(
        tmp_path, rule="script-module-layer-header", expected_layer="Layer: Tooling",
    )


def test_startup_checker_consumes_prechecked_import_violations(
    monkeypatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "X86_16"
    root.mkdir()
    cli_path = tmp_path / "cli_decompilation.py"
    cli_path.write_text("from __future__ import annotations\n", encoding="utf-8")
    violation = architecture_check.ArchitectureViolation(
        path="semantic.py",
        rule="semantic-layer-postprocess-import",
        detail="wrong-layer import",
    )

    def fail_import_rescan(*_args: object) -> tuple[architecture_check.ArchitectureViolation, ...]:
        raise AssertionError("prechecked import rules must not be rescanned")

    monkeypatch.setattr(architecture_check, "_check_postprocess_imports", fail_import_rescan)
    monkeypatch.setattr(
        architecture_check,
        "_check_semantic_layers_do_not_import_postprocess",
        fail_import_rescan,
    )
    monkeypatch.setattr(architecture_check, "_check_cli_imports", fail_import_rescan)

    violations = architecture_check.check_decompiler_startup_architecture(
        root,
        cli_path,
        tmp_path,
        prechecked_import_violations=(violation,),
    )

    assert violation in violations


def test_startup_main_uses_default_tree_import_attestation(
    monkeypatch,
    tmp_path: Path,
    capsys,
) -> None:
    root = tmp_path / "X86_16"
    cli_path = tmp_path / "cli_decompilation.py"
    violation = architecture_check.ArchitectureViolation(
        path="semantic.py",
        rule="semantic-layer-postprocess-import",
        detail="wrong-layer import",
    )
    observed: list[tuple[architecture_check.ArchitectureViolation, ...] | None] = []

    monkeypatch.setattr(architecture_check, "X86_16_ROOT", root)
    monkeypatch.setattr(architecture_check, "CLI_DECOMPILATION", cli_path)
    monkeypatch.setattr(architecture_check, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(
        architecture_runtime_guard,
        "cached_decompiler_architecture_import_violations",
        lambda: (violation,),
    )

    def record_startup_check(
        _root: Path,
        _cli_path: Path,
        _repo_root: Path,
        *,
        prechecked_import_violations: tuple[architecture_check.ArchitectureViolation, ...] | None = None,
    ) -> tuple[architecture_check.ArchitectureViolation, ...]:
        observed.append(prechecked_import_violations)
        return prechecked_import_violations or ()

    monkeypatch.setattr(
        architecture_check,
        "check_decompiler_startup_architecture",
        record_startup_check,
    )

    assert architecture_check.main(["--startup-only"]) == 1
    assert observed == [(violation,)]
    assert "semantic-layer-postprocess-import" in capsys.readouterr().err


def test_startup_main_scans_custom_tree_directly(
    monkeypatch,
    tmp_path: Path,
) -> None:
    observed: list[tuple[architecture_check.ArchitectureViolation, ...] | None] = []

    def reject_cache_use() -> tuple[architecture_check.ArchitectureViolation, ...]:
        raise AssertionError("custom roots must not reuse the default-tree attestation")

    monkeypatch.setattr(
        architecture_runtime_guard,
        "cached_decompiler_architecture_import_violations",
        reject_cache_use,
    )

    def record_startup_check(
        _root: Path,
        _cli_path: Path,
        _repo_root: Path,
        *,
        prechecked_import_violations: tuple[architecture_check.ArchitectureViolation, ...] | None = None,
    ) -> tuple[architecture_check.ArchitectureViolation, ...]:
        observed.append(prechecked_import_violations)
        return ()

    monkeypatch.setattr(
        architecture_check,
        "check_decompiler_startup_architecture",
        record_startup_check,
    )
    custom_root = tmp_path / "X86_16"

    assert architecture_check.main(["--startup-only", "--x86-16-root", str(custom_root)]) == 0
    assert observed == [None]
