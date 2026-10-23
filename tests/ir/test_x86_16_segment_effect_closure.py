"""Require complete local body/state evidence before segment-effect publication."""

from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace

import pytest

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from inertia.ir import IRBlock, IRFunctionArtifact, IRInstr, build_x86_16_segment_state_artifact
from inertia.ir import ir_boundary_cfg as boundary_owner
from inertia.ir import real16_invocation_domain as domains
from inertia.ir.function_ir_registry import publish_function_ir_artifact_8616
from inertia.ir.ir_boundary_cfg import prove_ir_boundary_coverage_8616
from inertia.ir.scoped_function_ir_view import (
    ScopedFunctionCFGProjection8616,
    ScopedFunctionIRView8616,
)
from inertia.ir.segment_effect_closure import prove_segment_effect_closure_8616
from tests.ir.test_invocation_call_consumption import _world

_CALLER_CODE = bytes.fromhex("e80000c3")     # call $+3; ret
_NO_RETURN_CODE = bytes.fromhex("e8000090")  # call $+3; nop


def _load_native_bytes_8616(code: bytes):
    """Build a loader serving retained native bytes for the mock extent."""
    def _load(addr: int, size: int) -> bytes:
        if addr >= 0x1000 and addr + size <= 0x1000 + len(code):
            return code[addr - 0x1000: addr - 0x1000 + size]
        return b""
    return _load


def _decoded_block_8616(addr: int, code: bytes,
                        extents: tuple[tuple[int, int], ...]) -> object:
    """Mint the decoded-block surface bound-block authentication reads."""
    return SimpleNamespace(
        addr=addr, size=len(code), bytes=code,
        capstone=SimpleNamespace(insns=tuple(
            SimpleNamespace(address=head, size=size) for head, size in extents)),
    )


@pytest.mark.parametrize("defect", (None, "foreign", "missing_block", "missing_register", "no_return", "no_coverage"))
def test_segment_effect_closure_requires_complete_bound_evidence(defect: str | None) -> None:
    """Refuse partial state/body evidence even when a local contract could exist."""
    # Bound-block authentication requires a real arch, live loader bytes and
    # retained decoded blocks; the mock supplies that exact surface.
    code = _NO_RETURN_CODE if defect == "no_return" else _CALLER_CODE
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(
            memory=SimpleNamespace(load=_load_native_bytes_8616(code))),
    )
    terminal = "NOP" if defect == "no_return" else "RET"
    artifact = IRFunctionArtifact(0x1000, (IRBlock(0x1000, instrs=(
        IRInstr("CALL", None, (), addr=0x1000),
        IRInstr(terminal, None, (), addr=0x1003),
    )),))
    publish_function_ir_artifact_8616(project, artifact)
    boundary = ExactFunctionRangeBoundary8616(
        project, 0x1000, 4, frozenset({0x1000}), frozenset({0x1000, 0x1003}), (),
        blocks=(_decoded_block_8616(0x1000, code, ((0x1000, 3), (0x1003, 1))),),
    )
    coverage = prove_ir_boundary_coverage_8616(project, boundary, artifact)
    state = build_x86_16_segment_state_artifact(artifact)
    if defect == "foreign":
        state = replace(state, source_artifact=replace(artifact))
    elif defect == "missing_block":
        state = replace(state, exit_states={})
    elif defect == "missing_register":
        state.entry_states[0x1000].pop("ds")
    elif defect == "no_coverage":
        coverage = replace(coverage, materialized_count=0)
    result = prove_segment_effect_closure_8616(coverage, state)
    assert result.complete is (defect is None)
    assert result.raw_fact_count == result.normalized_fact_count == 1
    assert result.materialized_count + result.failure_count == 1
    if defect is None:
        assert result.callsite_addrs == (0x1000,)
        assert result.return_block_addrs == (0x1000,)
        assert not replace(result, callsite_addrs=()).complete


@pytest.mark.parametrize("revoke_scope", (False, True), ids=("stable", "revoked"))
def test_native_callback_must_not_reuse_revoked_scope(
    revoke_scope: bool, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Equal native bytes cannot authenticate a scope revoked during import."""
    project, _caller, _call, call_proof = _world()
    artifact = call_proof.callee.coverage.artifact
    boundary = call_proof.callee.coverage.boundary
    scope = replace(
        domains.prove_real16_invocation_domain_8616(
            project, None, 0, boot=object(), boot_recompute=None,
        ),
        failure=None,
    )
    view = ScopedFunctionIRView8616(
        artifact, boundary, None, None, None, "test admission boundary",
        1, 1, 1, 1, 0, invocation_scope=scope,
    )

    def project_view(
        self: ScopedFunctionIRView8616, offered: object, **kwargs: object,
    ) -> ScopedFunctionCFGProjection8616 | None:
        """Isolate semantic admission while retaining real native graph checks."""
        if offered is not scope or scope.failure is not None:
            return None
        return ScopedFunctionCFGProjection8616(
            artifact.function_addr, artifact, scope, (), artifact.blocks,
            {block.addr: block.successor_addrs for block in artifact.blocks},
            {block.addr: () for block in artifact.blocks},
            {block.addr: () for block in artifact.blocks},
        )

    def native_import(
        actual_project: object, actual_boundary: ExactFunctionRangeBoundary8616,
    ) -> IRFunctionArtifact:
        """Return unchanged IR after optionally revoking the consuming scope."""
        assert actual_project is project and actual_boundary is boundary
        result = deepcopy(artifact)
        if revoke_scope:
            object.__setattr__(
                scope, "failure",
                domains.Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED,
            )
        return result

    monkeypatch.setattr(ScopedFunctionIRView8616, "cfg_projection_for", project_view)
    monkeypatch.setattr(domains, "real16_native_census_import_8616", native_import)
    coverage = boundary_owner.IRBoundaryCoverageResult8616(
        artifact, boundary, None, 1, 1, 1, 1, 0, view,
    )
    state = replace(
        build_x86_16_segment_state_artifact(artifact),
        invocation_scope=scope, scoped_view=view,
    )
    result = prove_segment_effect_closure_8616(coverage, state)
    assert (result.failure is not None) is revoke_scope
