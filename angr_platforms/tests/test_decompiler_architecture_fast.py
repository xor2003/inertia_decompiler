"""Tests for architecture guard entrypoints and required pipeline lanes."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from inertia_decompiler import architecture_runtime_guard
from scripts import check_decompiler_architecture as architecture_check


def _actual_pipeline_lanes() -> dict[str, tuple[str, ...]]:
    """Read the production lane declarations without importing the runner."""
    path = Path(__file__).resolve().parents[2] / "scripts/test_pipeline.py"
    return architecture_check._pipeline_tier_literals(ast.parse(path.read_text()))


def _lane_contract_errors(lanes: dict[str, tuple[str, ...]]) -> tuple[str, ...]:
    """Select lane-contract diagnostics independently of fixture marker checks."""
    root = Path(__file__).resolve().parents[2]
    path = root / "scripts/test_pipeline.py"
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
