"""Independent parent controls for staged near-return scope transport."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
import tests.integration.test_x86_16_near_return_continuation as worker
from inertia.ir.ir_boundary_cfg import prove_ir_boundary_coverage_8616


@pytest.mark.parametrize("changed_side", ["caller", "callee"])
def test_retained_scope_rejects_changed_native_bytes(
    tmp_path: Path, changed_side: str,
) -> None:
    """An accepted view/coverage/closure cannot outlive its exact native bytes."""
    boot, project = worker._mz_world(tmp_path)
    try:
        artifact, boundary = worker._mz_pending_callee(project, boot)
        scope = worker.edcp.entry_domain_invocation_premise_8616(
            project, artifact, boundary, worker._MZ_JMP_HEAD,
        )
        assert scope is not None and scope.complete
        owner = worker.nrcv
        view = owner.prove_scoped_near_return_continuation_view_8616(
            artifact, boundary, invocation_scope=scope,
        )
        coverage = worker.prove_scoped_ir_boundary_coverage_8616(
            project, boundary, artifact, view,
        )
        resolver = worker.edcp._CalleeResolution8616(
            resolver=worker._mz_resolver(project),
        )
        closure, refusal = worker.edcp._callee_closure_8616(
            project, worker._MZ_CALLEE, resolver, invocation_scope=scope,
        )
        assert view.complete_for(scope) and coverage.complete_for(scope)
        assert refusal is None and closure is not None
        assert closure.complete_for(scope)
        address = worker._MZ_CALLER if changed_side == "caller" else worker._MZ_CALLEE
        original = project.loader.memory.load(address, 1)
        assert original != b"\x90"
        project.loader.memory.store(address, b"\x90")
        assert not view.complete_for(scope)
        assert not coverage.complete_for(scope)
        assert not closure.complete_for(scope)
    finally:
        worker.edcp.install_real16_invocation_source_8616(project, None)


def test_pending_actual_mz_artifact_cannot_be_published(tmp_path: Path) -> None:
    """The original publication leak stays closed on an authentic MZ surface."""
    boot, project = worker._mz_world(tmp_path)
    try:
        artifact, boundary = worker._mz_pending_callee(project, boot)
        before = prove_ir_boundary_coverage_8616(project, boundary, artifact)
        assert not before.complete
        publication = worker.publish_function_ir_artifact_8616(project, artifact)
        assert publication.verdict is not worker.FunctionIRArtifactVerdict8616.PROVEN
        after = prove_ir_boundary_coverage_8616(project, boundary, artifact)
        assert not after.complete
        block = next(row for row in artifact.blocks if row.addr == worker._MZ_CALLEE)
        assert block.instrs[-1].op == "JMP"
        assert any(row.kind == worker._PENDING_KIND for row in block.refusals)
    finally:
        worker.edcp.install_real16_invocation_source_8616(project, None)


@pytest.mark.parametrize("field,value", [
    ("raw_fact_count", 0),
    ("normalized_fact_count", 0),
    ("classified_fact_count", 0),
    ("materialized_count", 0),
    ("failure_count", 1),
])
def test_partial_view_ledger_cannot_authorize_coverage(
    tmp_path: Path, field: str, value: int,
) -> None:
    """A scope cannot turn incomplete evidence accounting into coverage."""
    boot, project = worker._mz_world(tmp_path)
    try:
        artifact, boundary = worker._mz_pending_callee(project, boot)
        scope = worker.edcp.entry_domain_invocation_premise_8616(
            project, artifact, boundary, worker._MZ_JMP_HEAD,
        )
        assert scope is not None and scope.complete
        owner = worker.nrcv
        view = owner.prove_scoped_near_return_continuation_view_8616(
            artifact, boundary, invocation_scope=scope,
        )
        assert view.complete_for(scope)
        incomplete = replace(view, **{field: value})
        coverage = worker.prove_scoped_ir_boundary_coverage_8616(
            project, boundary, artifact, incomplete,
        )
        assert not coverage.complete_for(scope)
        assert not incomplete.complete_for(scope)
    finally:
        worker.edcp.install_real16_invocation_source_8616(project, None)
