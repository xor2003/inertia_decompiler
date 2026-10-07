"""Regression tests for consuming authoritative IR condition evidence."""

from __future__ import annotations

from inertia.ir.function_ssa_registry import (
    FunctionSSAArtifactVerdict8616,
    function_ssa_artifact_for_boundary_8616,
)
import inertia.lowering.condition_transfer as condition_transfer
from inertia.lowering.condition_transfer import (
    collect_typed_condition_artifacts_8616,
)
from pytest import MonkeyPatch

from inertia.cli.project_loading import _build_project_from_bytes


def test_complete_registered_ir_conditions_bypass_lowering_relift(
    monkeypatch: MonkeyPatch,
) -> None:
    project = _build_project_from_bytes(
        bytes.fromhex("09 c0 74 01 c3 c3"),
        base_addr=0x1000,
        entry_point=0x1000,
    )
    cfg = project.analyses.CFGFast(normalize=True, force_complete_scan=False)
    function = cfg.kb.functions[0x1000]
    registered = function_ssa_artifact_for_boundary_8616(
        project,
        0x1000,
        function,
    )

    assert registered.verdict is FunctionSSAArtifactVerdict8616.PROVEN
    assert registered.artifact is not None
    assert registered.artifact.condition_evidence is not None
    assert registered.artifact.condition_evidence.complete

    def refuse_relift(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("lowering must consume registered IR condition evidence")

    monkeypatch.setattr(
        condition_transfer,
        "relift_function_condition_cache_8616",
        refuse_relift,
    )

    conditions, _edges = collect_typed_condition_artifacts_8616(
        project,
        0x1000,
        function=function,
    )

    assert conditions
    assert conditions[0].producer_insn == 0x1000
