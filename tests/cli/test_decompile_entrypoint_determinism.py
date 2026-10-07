"""Regression tests for deterministic decompiler CLI startup."""

from __future__ import annotations

import os
import runpy
import sys
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import NoReturn, cast

import pytest

import decompile as decompile_entrypoint
import inertia.cli.cli as decompiler_cli
import inertia.cli.cli_function_discovery as function_discovery
from inertia.cli.function_worker_policy import requires_isolated_function_decompilation
import tools.dev.batch_decompile_procs as batch_decompile_procs
import tools.compiler_toolchain.import_ultra_quickc_fixtures as ultra_qc

REPO_ROOT = Path(__file__).resolve().parents[2]


class _ExecIntercepted(RuntimeError):
    """Signal that the test intercepted an entrypoint restart."""


def test_batch_runner_uses_public_cli_initialization_boundary() -> None:
    assert batch_decompile_procs.decompiler_cli is decompiler_cli


def test_entrypoint_facade_monkeypatch_reaches_owner_module(monkeypatch: pytest.MonkeyPatch) -> None:
    def replacement(_project: object) -> list[int]:
        return [0x1000]

    monkeypatch.setattr(decompile_entrypoint, "_rank_exe_function_seeds", replacement)

    assert function_discovery._rank_exe_function_seeds is replacement


def test_whole_file_x86_16_executable_requires_isolated_workers() -> None:
    assert requires_isolated_function_decompilation(
        architecture="86_16",
        binary_suffix=".EXE",
        address_requested=False,
    )
    assert not requires_isolated_function_decompilation(
        architecture="86_16",
        binary_suffix=".EXE",
        address_requested=True,
    )


def test_caller_evidence_scan_uses_isolated_project(monkeypatch: pytest.MonkeyPatch) -> None:
    project = SimpleNamespace()
    evidence_project = SimpleNamespace()
    evidence = function_discovery.CallerReturnUseEvidence8616(
        target_addr=0x1004,
        verdict=function_discovery.CallerReturnUseVerdict8616.UNUSED,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        used_callsite_count=0,
        unused_callsite_count=1,
        callsite_addrs=(0x1080,),
    )
    scanned_projects: list[object] = []
    monkeypatch.setattr(function_discovery, "isolated_discovery_evidence_project_8616", lambda _project: evidence_project)
    monkeypatch.setattr(
        function_discovery,
        "_rank_pre_entry_source_function_seeds_8616",
        lambda scan_project: scanned_projects.append(scan_project) or [0x1004],
    )
    monkeypatch.setattr(function_discovery, "_binary_padding_entry_aliases_8616", lambda _project, _seed: (0x1004,))
    monkeypatch.setattr(function_discovery, "_pre_entry_source_function_ranges_8616", lambda _project, _seeds: ((0x1000, 0x1100),))
    monkeypatch.setattr(
        function_discovery,
        "_collect_caller_return_use_for_entry_aliases_8616",
        lambda scan_project, _aliases, _ranges: scanned_projects.append(scan_project) or evidence,
    )

    result = function_discovery.record_direct_target_caller_return_use_evidence_8616(project, 0x1004)

    assert result == evidence
    assert scanned_projects == [evidence_project, evidence_project]
    assert function_discovery.caller_return_use_evidence_by_addr_8616(project)[0x1004] == evidence


def _load_hash_seed_guard() -> Callable[[], None]:
    """Load the startup guard without executing the CLI main path."""

    namespace = runpy.run_path(str(REPO_ROOT / "decompile.py"), run_name="decompile_startup_test")
    return cast(Callable[[], None], namespace["_ensure_deterministic_hash_seed"])


def test_hash_seed_guard_restarts_entrypoint_with_zero_seed(monkeypatch: pytest.MonkeyPatch) -> None:
    guard = _load_hash_seed_guard()
    calls: list[tuple[str, list[str], dict[str, str]]] = []

    def fake_execvpe(executable: str, argv: list[str], env: dict[str, str]) -> NoReturn:
        calls.append((executable, argv, env))
        raise _ExecIntercepted

    monkeypatch.setenv("PYTHONHASHSEED", "random")
    monkeypatch.setattr(sys, "argv", [str(REPO_ROOT / "decompile.py"), "SORTD.EXE", "--brief"])
    monkeypatch.setattr(os, "execvpe", fake_execvpe)

    with pytest.raises(_ExecIntercepted):
        guard()

    executable, argv, env = calls[0]
    assert executable == sys.executable
    assert argv == [sys.executable, str(REPO_ROOT / "decompile.py"), "SORTD.EXE", "--brief"]
    assert env["PYTHONHASHSEED"] == "0"


def test_hash_seed_guard_keeps_stable_process(monkeypatch: pytest.MonkeyPatch) -> None:
    guard = _load_hash_seed_guard()
    monkeypatch.setenv("PYTHONHASHSEED", "0")

    def unexpected_execvpe(executable: str, argv: list[str], env: dict[str, str]) -> NoReturn:
        raise AssertionError((executable, argv, env))

    monkeypatch.setattr(os, "execvpe", unexpected_execvpe)
    guard()


def test_quickc_pending_decompile_uses_isolated_cli_helper(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    exe_path = tmp_path / "ARGS.EXE"
    exe_path.write_bytes(b"MZ")
    captured: dict[str, object] = {}

    def fake_decompile_fixture(
        binary: Path,
        *,
        selection: ultra_qc.DecompileTargetSelection,
        decompile: Path,
        timeout: int,
        generated_c_contract: ultra_qc.GeneratedCContract | None = None,
    ) -> dict[str, object]:
        captured["binary"] = binary
        captured["selection"] = selection
        captured["decompile"] = decompile
        captured["timeout"] = timeout
        captured["generated_c_contract"] = generated_c_contract
        return {
            "status": "passed",
            "wall_seconds": 1.0,
            "validation_status": "passed",
        }

    monkeypatch.setattr(ultra_qc, "_decompile_fixture", fake_decompile_fixture)
    result: dict[str, object] = {
        "name": "args",
        "status": "pending",
        "pre_decompile_passed": True,
        "exe": str(exe_path),
        "stages": [],
        "compiler_match": {"status": "passed"},
        "decompile_target_selection": {
            "mode": "auto",
            "evidence_source": "omf_public",
            "targets": ["sub_10058"],
            "addr": "0x10058",
            "reason": "test",
        },
    }

    ultra_qc._decompile_pending_results_serially(
        [result],
        decompile=REPO_ROOT / "decompile.py",
        decompile_timeout=30,
    )

    assert captured["binary"] == exe_path
    assert cast(ultra_qc.DecompileTargetSelection, captured["selection"]).addr == 0x10058
    assert captured["decompile"] == REPO_ROOT / "decompile.py"
    assert captured["timeout"] == 30
    assert result["status"] == "passed"
