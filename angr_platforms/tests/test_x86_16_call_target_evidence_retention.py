"""Binary regressions for retained evidence admission and publication."""
from __future__ import annotations

import io
from dataclasses import dataclass, replace

import angr
import pytest
from angr_platforms.X86_16.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
    exact_function_range_boundary_8616,
)
from angr_platforms.X86_16.ir.function_ssa_registry import (
    FunctionSSAArtifactFailure8616,
    FunctionSSAArtifactStage8616,
    FunctionSSAArtifactVerdict8616,
)
from angr_platforms.X86_16.lowering.call_target_ssa_binder import CallTargetBindStage8616, bind_ssa_call_target_8616
from angr_platforms.X86_16.pipeline.errors import PipelineHardError
from angr_platforms.X86_16.semantics.call_stack_effect_pipeline import (
    CallSemanticProjection8616,
    _CodegenBoundary8616,
    _publish_semantic_artifacts_8616,
    semantic_function_ssa_artifact_at_address_8616,
)
from angr_platforms.X86_16.semantics.call_target_evidence_8616 import (
    CallTargetEvidenceFailure8616,
    CallTargetEvidencePublication8616,
    CallTargetEvidenceResolution8616,
    CallTargetEvidenceStats8616,
    CallTargetEvidenceVerdict8616,
    resolve_call_target_evidence_8616,
)


class _CodegenBoundaryDouble(_CodegenBoundary8616):
    """Typed codegen surface retaining its prior raw-stage publication."""

    def __init__(self, projection: CallSemanticProjection8616) -> None:
        self.cfunc = None
        self._inertia_vex_ir_artifact = projection.source_ir
        self._inertia_vex_ir_summary = projection.source_ir.summary
        self._inertia_vex_ir_function_ssa = projection.function_ssa
        self._inertia_vex_ir_function_ssa_stage_8616 = FunctionSSAArtifactStage8616.IR
        self._inertia_raw_vex_ir_artifact_8616 = projection.source_ir
        self._inertia_call_stack_effect_artifact_8616 = projection.effects
        self._inertia_call_output_artifact_8616 = projection.outputs
        self._inertia_call_semantic_projection_8616 = projection


@dataclass(frozen=True)
class _Fixture:
    project: angr.Project
    boundary: ExactFunctionRangeBoundary8616
    evidence: CallTargetEvidenceResolution8616


def _fixture(code: bytes | None = None) -> _Fixture:
    """Publish native two-call semantics and build one decoded caller census."""
    code = bytes.fromhex("e80d00 89c3 e80a00 c3") if code is None else code
    image = code + bytes(0x10 - len(code)) + bytes.fromhex("c3 90 c3")
    project = angr.Project(io.BytesIO(image), main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000}, auto_load_libs=False, simos="DOS")
    boundary = exact_function_range_boundary_8616(project, 0x1000, 0x1000 + len(code))
    assert boundary is not None
    ssa = semantic_function_ssa_artifact_at_address_8616(project, 0x1000, function=boundary)
    assert ssa.verdict is FunctionSSAArtifactVerdict8616.PROVEN
    evidence = resolve_call_target_evidence_8616(project, 0x1000, boundary=boundary, direct_target_resolver=lambda instruction: resolve_direct_call_target_from_instruction_8616(project, instruction))
    assert evidence.complete and evidence.projection is not None
    return _Fixture(project, boundary, evidence)


@pytest.fixture(scope="module")
def authentic() -> _Fixture:
    """Share immutable positive evidence across pure result-contract controls."""
    return _fixture()


@pytest.mark.parametrize("mutation", ["failure", "empty_stats", "wrong_caller"])
def test_publication_complete_rejects_invalid_result(authentic: _Fixture, mutation: str) -> None:
    """Reject failure, empty accounting and foreign caller publication results."""
    original = CallTargetEvidencePublication8616(0x1000, CallTargetEvidenceVerdict8616.PROVEN, None, authentic.evidence.projection, CallTargetEvidenceStats8616(1, 1, 1, 1, 0))
    assert original.complete
    if mutation == "failure":
        mutant = replace(original, failure=CallTargetEvidenceFailure8616.SOURCE_IR_CONFLICT)
    elif mutation == "empty_stats":
        mutant = replace(original, stats=CallTargetEvidenceStats8616(0, 0, 0, 0, 0))
    else:
        mutant = replace(original, caller_addr=0xDEAD)
    assert not mutant.complete


@pytest.mark.parametrize("mutation", ["failure", "empty_stats", "missing_source", "missing_boundary", "wrong_caller"])
def test_resolution_complete_rejects_invalid_result(authentic: _Fixture, mutation: str) -> None:
    """Require failure-free complete caller evidence before transport."""
    original = authentic.evidence
    assert original.complete
    if mutation == "failure":
        mutant = replace(original, failure=CallTargetEvidenceFailure8616.SOURCE_IR_CONFLICT)
    elif mutation == "empty_stats":
        mutant = replace(original, stats=CallTargetEvidenceStats8616(0, 0, 0, 0, 0))
    elif mutation == "missing_source":
        mutant = replace(original, source_ir=None)
    elif mutation == "missing_boundary":
        mutant = replace(original, boundary=None)
    else:
        mutant = replace(original, caller_addr=0xDEAD)
    assert not mutant.complete


def test_foreign_cached_census_refuses_without_explicit_boundary() -> None:
    """Reject another project census even when the caller omits a boundary."""
    local, foreign = _fixture(), _fixture()
    # Corrupt the third-party project's dynamic retention extension deliberately.
    vars(local.project)["_inertia_decoded_callsite_indexes_8616"][0x1000] = vars(foreign.project)["_inertia_decoded_callsite_indexes_8616"][0x1000]
    result = resolve_call_target_evidence_8616(local.project, 0x1000)
    assert not result.complete
    assert result.verdict is CallTargetEvidenceVerdict8616.CONFLICT
    assert result.failure is CallTargetEvidenceFailure8616.CALLER_BOUNDARY_CONFLICT
    assert result.stats.closed and result.stats.failure_count == 1


def test_semantic_publication_propagates_raw_registry_conflict() -> None:
    """Stop SSA publication when the raw registry refuses conflicting evidence."""
    fixture = _fixture()
    assert fixture.evidence.source_ir is not None
    vars(fixture.project)["_inertia_function_ssa_artifacts_8616"].pop(0x1000)
    vars(fixture.project)["_inertia_function_ssa_stages_8616"].pop(0x1000)
    vars(fixture.project)["_inertia_function_ir_artifacts_8616"][0x1000] = replace(fixture.evidence.source_ir, function_addr=0xDEAD)
    result = semantic_function_ssa_artifact_at_address_8616(fixture.project, 0x1000, function=fixture.boundary)
    assert result.verdict is FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE
    assert result.artifact is None
    assert result.failure is FunctionSSAArtifactFailure8616.ARTIFACT_CONFLICT
    assert 0x1000 not in vars(fixture.project)["_inertia_function_ssa_artifacts_8616"]


def test_fresh_resolution_keeps_raw_source_binding_required() -> None:
    """Keep native source binding mandatory after a fresh accessor result."""
    fixture, foreign = _fixture(), _fixture(bytes.fromhex("6a05 e80b00 c3"))
    assert fixture.evidence.ssa_artifact is not None
    positive = bind_ssa_call_target_8616(fixture.evidence.ssa_artifact, 0x1000, 0x1000, (0x1010,), project=fixture.project, callsite_index=fixture.evidence.callsite_index, projection=fixture.evidence.projection)
    assert positive.complete
    # Exercise the raw route explicitly, preserving the real SSA and decoded index.
    from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa
    assert fixture.evidence.source_ir is not None
    raw_ssa = build_x86_16_function_ssa(fixture.evidence.source_ir)
    vars(fixture.project)["_inertia_function_ssa_artifacts_8616"][0x1000] = raw_ssa
    vars(fixture.project)["_inertia_function_ssa_stages_8616"][0x1000] = FunctionSSAArtifactStage8616.IR
    vars(fixture.project)["_inertia_call_target_projections_8616"].pop(0x1000)
    vars(fixture.project)["_inertia_function_ir_artifacts_8616"][0x1000] = foreign.evidence.source_ir
    fresh = resolve_call_target_evidence_8616(fixture.project, 0x1000, boundary=fixture.boundary)
    assert fresh.complete
    rejected = bind_ssa_call_target_8616(raw_ssa, 0x1000, 0x1000, (0x1010,), project=fixture.project, callsite_index=fresh.callsite_index, projection=fresh.projection)
    assert not rejected.complete
    assert rejected.stage is CallTargetBindStage8616.SSA_RAW_INDEX_MISMATCH


@pytest.mark.parametrize("registry", ["raw", "projection"])
def test_codegen_publication_conflict_keeps_boundary_unmodified(registry: str) -> None:
    """Refuse registry conflicts before exposing codegen semantic artifacts."""
    fixture = _fixture()
    projection = fixture.evidence.projection
    assert projection is not None
    if registry == "raw":
        vars(fixture.project)["_inertia_function_ir_artifacts_8616"][0x1000] = replace(projection.source_ir, function_addr=0xDEAD)
    else:
        vars(fixture.project)["_inertia_call_target_projections_8616"][0x1000] = replace(projection, source_ir=replace(projection.source_ir, function_addr=0xDEAD))
    boundary = _CodegenBoundaryDouble(projection)
    before = vars(boundary).copy()
    with pytest.raises(PipelineHardError):
        _publish_semantic_artifacts_8616(fixture.project, boundary, projection.source_ir, projection.effects, projection.outputs, projection.function_ssa)
    assert vars(boundary) == before
