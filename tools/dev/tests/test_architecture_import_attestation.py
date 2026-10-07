"""Regression tests for incremental runtime import-guard attestations."""

from __future__ import annotations

from pathlib import Path

import pytest

import inertia.cli.architecture_import_attestation as attestation


def _write_guard_tree(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    """Create two semantic files and one valid CLI orchestration module."""

    root = tmp_path / "X86_16"
    ir_root = root / "ir"
    ir_root.mkdir(parents=True)
    first = ir_root / "first.py"
    second = ir_root / "second.py"
    first.write_text("from __future__ import annotations\n", encoding="utf-8")
    second.write_text("from __future__ import annotations\n", encoding="utf-8")
    cli = tmp_path / "cli_decompilation.py"
    cli.write_text(
        '"""CLI orchestration that must not become the owner of decompiler semantics."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )
    return root, cli, first, second


def test_incremental_attestation_rechecks_only_changed_guarded_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A changed source invalidates its own verdict without replaying siblings."""

    root, cli, first, _second = _write_guard_tree(tmp_path)
    cache = tmp_path / "guard.json"
    checked: list[Path] = []
    original = attestation._evaluate_runtime_import_path

    def recording_evaluator(
        scan_root: Path,
        path: Path,
        rules: tuple[attestation._RuntimeImportGuardRule, ...],
    ) -> tuple[attestation.ArchitectureViolation, ...]:
        checked.append(path)
        return original(scan_root, path, rules)

    monkeypatch.setattr(attestation, "_evaluate_runtime_import_path", recording_evaluator)
    initial = attestation.evaluate_runtime_import_snapshot(cache, root, cli, "checker-v1")
    assert not initial.violations
    assert len(checked) == 3
    attestation.store_architecture_guard_cache(
        cache,
        "source-v1",
        "checker-v1",
        root,
        cli,
        initial,
    )

    checked.clear()
    first.write_text(
        "from __future__ import annotations\nVALUE = 1\n",
        encoding="utf-8",
    )
    updated = attestation.evaluate_runtime_import_snapshot(cache, root, cli, "checker-v1")

    assert not updated.violations
    assert checked == [first]


def test_incremental_attestation_retains_cached_violation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cached wrong-layer verdict still blocks and does not become clean."""

    root, cli, first, _second = _write_guard_tree(tmp_path)
    first.write_text(
        "from inertia.postprocess.flags_cleanup import cleanup\n",
        encoding="utf-8",
    )
    cache = tmp_path / "guard.json"
    initial = attestation.evaluate_runtime_import_snapshot(cache, root, cli, "checker-v1")
    assert any(
        violation.rule == "semantic-layer-postprocess-import"
        for violation in initial.violations
    )
    attestation.store_architecture_guard_cache(
        cache,
        "source-v1",
        "checker-v1",
        root,
        cli,
        initial,
    )
    assert not attestation.architecture_guard_cache_is_clean(cache, "source-v1")

    def fail_if_rechecked(
        _root: Path,
        _path: Path,
        _rules: tuple[attestation._RuntimeImportGuardRule, ...],
    ) -> tuple[attestation.ArchitectureViolation, ...]:
        raise AssertionError("unchanged violating source must reuse its exact verdict")

    monkeypatch.setattr(attestation, "_evaluate_runtime_import_path", fail_if_rechecked)
    repeated = attestation.evaluate_runtime_import_snapshot(cache, root, cli, "checker-v1")

    assert repeated.violations == initial.violations


def test_checker_change_invalidates_every_cached_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rule implementation changes invalidate all prior per-file verdicts."""

    root, cli, _first, _second = _write_guard_tree(tmp_path)
    cache = tmp_path / "guard.json"
    initial = attestation.evaluate_runtime_import_snapshot(cache, root, cli, "checker-v1")
    attestation.store_architecture_guard_cache(
        cache,
        "source-v1",
        "checker-v1",
        root,
        cli,
        initial,
    )
    checked: list[Path] = []
    original = attestation._evaluate_runtime_import_path

    def recording_evaluator(
        scan_root: Path,
        path: Path,
        rules: tuple[attestation._RuntimeImportGuardRule, ...],
    ) -> tuple[attestation.ArchitectureViolation, ...]:
        checked.append(path)
        return original(scan_root, path, rules)

    monkeypatch.setattr(attestation, "_evaluate_runtime_import_path", recording_evaluator)
    changed_checker = attestation.evaluate_runtime_import_snapshot(cache, root, cli, "checker-v2")

    assert not changed_checker.violations
    assert len(checked) == 3


def test_startup_verdict_round_trip_retains_violations(tmp_path: Path) -> None:
    """A cached startup failure remains a structured failing verdict."""
    cache = tmp_path / "startup.json"
    violation = attestation.ArchitectureViolation(
        path="bad.py",
        rule="wrong-layer",
        detail="semantic recovery crossed the rewrite boundary",
    )

    attestation.store_startup_architecture_verdict(cache, "source-v1", (violation,))

    assert attestation.load_startup_architecture_verdict(cache, "source-v1") == (violation,)
    assert attestation.load_startup_architecture_verdict(cache, "source-v2") is None


def test_startup_verdict_rejects_malformed_violation(tmp_path: Path) -> None:
    """Malformed cache data falls back to direct checking."""
    cache = tmp_path / "startup.json"
    cache.write_text(
        '{"schema": 1, "fingerprint": "source-v1", "violations": [{}]}',
        encoding="utf-8",
    )

    assert attestation.load_startup_architecture_verdict(cache, "source-v1") is None


def test_startup_fingerprint_tracks_all_owned_source_surfaces(tmp_path: Path) -> None:
    """Root, CLI package, and entrypoint edits invalidate startup verdicts."""
    root = tmp_path / "angr_platforms" / "angr_platforms" / "X86_16"
    cli_root = tmp_path / "inertia" / "cli"
    root.mkdir(parents=True)
    cli_root.mkdir(parents=True)
    root_source = root / "lowering.py"
    cli_source = cli_root / "cli.py"
    entrypoint = tmp_path / "decompile.py"
    for path in (root_source, cli_source, entrypoint):
        path.write_text("VALUE = 1\n", encoding="utf-8")
    initial = attestation.architecture_startup_source_fingerprint(root, tmp_path)

    root_source.write_text("VALUE = 2\n", encoding="utf-8")
    after_root = attestation.architecture_startup_source_fingerprint(root, tmp_path)
    cli_source.write_text("VALUE = 2\n", encoding="utf-8")
    after_cli = attestation.architecture_startup_source_fingerprint(root, tmp_path)
    entrypoint.write_text("VALUE = 2\n", encoding="utf-8")
    after_entrypoint = attestation.architecture_startup_source_fingerprint(root, tmp_path)

    assert len({initial, after_root, after_cli, after_entrypoint}) == 4
