"""Connect exact call-stack Semantics to the pre-Alias function SSA path.

Layer: Semantics.
Responsibility: orchestrate IR import, authoritative callsite summaries,
Semantics-owned call effects, and function SSA before Alias consumes stack
versions. This module only coordinates owned typed artifacts at their earliest
valid boundary.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from ..callsite_summary_program import (
    build_callsite_summary_inventory_with_program_evidence_8616,
)
from ..ir import IRFunctionArtifact
from ..ir.function_ssa_registry import (
    FunctionSSAArtifactFailure8616,
    FunctionSSAArtifactResolution8616,
    FunctionSSAArtifactStage8616,
    FunctionSSAArtifactVerdict8616,
    function_boundary_at_address_8616,
    publish_function_ssa_artifact_8616,
    registered_function_ssa_artifact_8616,
)
from ..ir.ssa_function import SSAFunctionArtifact, build_x86_16_function_ssa
from ..ir.vex_import import build_x86_16_ir_function_artifact
from ..pipeline.errors import PipelineHardError
from .call_outputs import CallOutputArtifact8616, materialize_call_outputs_8616
from .call_return_segment import collect_return_segment_frames_8616
from .call_stack_allocation import collect_call_stack_allocation_proofs_8616
from .call_stack_effects import (
    CallStackEffectArtifact8616,
    materialize_call_stack_effects_8616,
)


class _FunctionManager8616(Protocol):
    """Third-party function-manager boundary used for exact lookup."""

    def function(self, *, addr: int, create: bool = False) -> object | None:
        """Return an existing function without inventing a boundary."""
        ...


class _KnowledgeBase8616(Protocol):
    """Third-party knowledge-base boundary used by this semantic pass."""

    functions: _FunctionManager8616


class _ProjectBoundary8616(Protocol):
    """Minimal angr project surface needed for exact function lookup."""

    kb: _KnowledgeBase8616


class _CFunctionBoundary8616(Protocol):
    """Minimal generated-function identity used by this pass."""

    addr: int


class _FunctionBoundary8616(Protocol):
    """Owned metadata extension on a third-party recovered function."""

    info: dict[str, object]


class _CodegenBoundary8616(Protocol):
    """Dynamic angr codegen plus owned semantic artifact extensions."""

    cfunc: _CFunctionBoundary8616 | None
    _inertia_vex_ir_artifact: IRFunctionArtifact
    _inertia_vex_ir_summary: dict[str, object]
    _inertia_vex_ir_function_ssa: SSAFunctionArtifact
    _inertia_vex_ir_function_ssa_stage_8616: FunctionSSAArtifactStage8616
    _inertia_raw_vex_ir_artifact_8616: IRFunctionArtifact
    _inertia_call_stack_effect_artifact_8616: CallStackEffectArtifact8616
    _inertia_call_output_artifact_8616: CallOutputArtifact8616
    _inertia_call_semantic_projection_8616: CallSemanticProjection8616


@dataclass(frozen=True, slots=True)
class CallSemanticProjection8616:
    """Coherent immutable IR-to-Semantics projection for one function snapshot."""

    source_ir: IRFunctionArtifact
    effects: CallStackEffectArtifact8616
    outputs: CallOutputArtifact8616
    function_ssa: SSAFunctionArtifact

    @property
    def complete(self) -> bool:
        """Return whether every projection has closed evidence accounting."""
        function_addr = self.source_ir.function_addr
        return bool(
            self.effects.stats.closed
            and self.outputs.stats.closed
            and self.effects.function.function_addr == function_addr
            and self.outputs.function.function_addr == function_addr
            and self.function_ssa.function_addr == function_addr
        )

    def matches_codegen(
        self,
        current_ir: IRFunctionArtifact,
        current_ssa: SSAFunctionArtifact,
    ) -> bool:
        """Return whether dynamic codegen fields still expose this projection."""
        return self.outputs.function is current_ir and self.function_ssa is current_ssa


def semantic_function_ssa_artifact_at_address_8616(
    project: object,
    function_addr: int,
    *,
    function: object | None = None,
) -> FunctionSSAArtifactResolution8616:
    """Build or return Semantics-ready SSA for an exact supplied boundary."""
    if function is not None:
        try:
            boundary_addr = cast(_CFunctionBoundary8616, function).addr
        except AttributeError:
            boundary_addr = None
        if boundary_addr != function_addr:
            return FunctionSSAArtifactResolution8616(
                function_addr,
                FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE,
                None,
                FunctionSSAArtifactFailure8616.FUNCTION_BOUNDARY_CONFLICT,
                None,
            )
    registered = registered_function_ssa_artifact_8616(project, function_addr)
    if (
        registered.verdict is FunctionSSAArtifactVerdict8616.PROVEN
        and registered.stage is FunctionSSAArtifactStage8616.SEMANTIC
    ):
        return registered
    if registered.failure is FunctionSSAArtifactFailure8616.ARTIFACT_CONFLICT:
        return registered
    if function is None:
        function = function_boundary_at_address_8616(project, function_addr)
    if function is None:
        return FunctionSSAArtifactResolution8616(
            function_addr,
            FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE,
            None,
            FunctionSSAArtifactFailure8616.FUNCTION_NOT_FOUND,
            None,
        )
    try:
        _effects, outputs, function_ssa = build_semantic_function_ssa_8616(
            project,
            function,
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        return FunctionSSAArtifactResolution8616(
            function_addr,
            FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE,
            None,
            FunctionSSAArtifactFailure8616.SEMANTIC_BUILD_FAILED,
            registered.stage,
        )
    if outputs.function.refusals:
        return FunctionSSAArtifactResolution8616(
            function_addr,
            FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE,
            None,
            FunctionSSAArtifactFailure8616.IR_BUILD_REFUSED,
            registered.stage,
        )
    return publish_function_ssa_artifact_8616(
        project,
        function_ssa,
        FunctionSSAArtifactStage8616.SEMANTIC,
    )


def build_semantic_function_ssa_8616(
    project: object,
    function: object,
    *,
    ir_artifact: IRFunctionArtifact | None = None,
) -> tuple[CallStackEffectArtifact8616, CallOutputArtifact8616, SSAFunctionArtifact]:
    """Build function SSA only after exact CALL effects have typed outcomes."""
    raw_ir = (
        build_x86_16_ir_function_artifact(project, function)
        if ir_artifact is None
        else ir_artifact
    )
    callsite_addrs = tuple(
        instruction.addr
        for block in raw_ir.blocks
        for instruction in block.instrs
        if instruction.op == "CALL" and instruction.addr is not None
    )
    summaries = build_callsite_summary_inventory_with_program_evidence_8616(
        project,
        function,
        callsite_addrs,
    )
    allocations = collect_call_stack_allocation_proofs_8616(project, raw_ir, summaries)
    return_frames = collect_return_segment_frames_8616(
        project, function,
        {address: summary.return_addr for address, summary in summaries.items() if summary.return_addr is not None},
    )
    effects = materialize_call_stack_effects_8616(
        raw_ir, summaries, project=project, allocation_proofs=allocations,
        return_segment_frames={frame.callsite_addr: frame for frame in return_frames},
    )
    if not effects.stats.closed or (
        effects.stats.classified_fact_count > 0
        and effects.stats.materialized_count == 0
    ):
        raise PipelineHardError(
            "call-stack Semantics did not retain one typed outcome per CALL",
            layer="semantics",
        )
    outputs = materialize_call_outputs_8616(effects.function, summaries)
    if not outputs.stats.closed or (
        outputs.stats.classified_fact_count > 0
        and outputs.stats.materialized_count == 0
    ):
        raise PipelineHardError(
            "call-output Semantics did not retain one typed outcome per CALL",
            layer="semantics",
        )
    return effects, outputs, build_x86_16_function_ssa(outputs.function)


def apply_x86_16_call_stack_effects_8616(project: object, codegen: object) -> bool:
    """Replace raw function SSA with the Semantics-enriched production artifact."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        cfunc = boundary.cfunc
        raw_ir = boundary._inertia_vex_ir_artifact
    except AttributeError:
        return False
    if cfunc is None or not isinstance(cfunc.addr, int):
        return False
    if not isinstance(raw_ir, IRFunctionArtifact) or raw_ir.function_addr != cfunc.addr:
        return False
    try:
        source_ir = boundary._inertia_raw_vex_ir_artifact_8616
    except AttributeError:
        try:
            source_ir = boundary._inertia_call_semantic_projection_8616.source_ir
        except AttributeError:
            source_ir = raw_ir
    if not isinstance(source_ir, IRFunctionArtifact) or source_ir.function_addr != cfunc.addr:
        return False
    project_boundary = cast(_ProjectBoundary8616, project)
    try:
        function = project_boundary.kb.functions.function(addr=cfunc.addr, create=False)
    except (AttributeError, KeyError, TypeError):
        return False
    if function is None:
        return False
    try:
        existing_projection = boundary._inertia_call_semantic_projection_8616
        existing_stage = boundary._inertia_vex_ir_function_ssa_stage_8616
        existing_ssa = boundary._inertia_vex_ir_function_ssa
    except AttributeError:
        existing_projection = None
    if (
        isinstance(existing_projection, CallSemanticProjection8616)
        and existing_projection.source_ir is source_ir
        and existing_stage is FunctionSSAArtifactStage8616.SEMANTIC
        and existing_projection.matches_codegen(raw_ir, existing_ssa)
    ):
        if not existing_projection.complete:
            raise PipelineHardError(
                "cached call Semantics projection has incomplete evidence accounting",
                layer="semantics",
            )
        return False
    effects, outputs, function_ssa = build_semantic_function_ssa_8616(
        project,
        function,
        ir_artifact=source_ir,
    )
    if not outputs.function.refusals:
        publication = publish_function_ssa_artifact_8616(
            project,
            function_ssa,
            FunctionSSAArtifactStage8616.SEMANTIC,
        )
        if (
            publication.verdict is not FunctionSSAArtifactVerdict8616.PROVEN
            or publication.artifact is None
        ):
            raise PipelineHardError(
                "Semantics function SSA conflicts with the project registry",
                layer="semantics",
                details={
                    "function_addr": cfunc.addr,
                    "failure": None
                    if publication.failure is None
                    else publication.failure.value,
                    "stage": None
                    if publication.stage is None
                    else publication.stage.value,
                },
            )
        function_ssa = publication.artifact
    boundary._inertia_vex_ir_artifact = outputs.function
    boundary._inertia_vex_ir_summary = outputs.function.summary
    boundary._inertia_vex_ir_function_ssa = function_ssa
    boundary._inertia_vex_ir_function_ssa_stage_8616 = (
        FunctionSSAArtifactStage8616.SEMANTIC
    )
    boundary._inertia_call_stack_effect_artifact_8616 = effects
    boundary._inertia_call_output_artifact_8616 = outputs
    boundary._inertia_call_semantic_projection_8616 = CallSemanticProjection8616(
        source_ir,
        effects,
        outputs,
        function_ssa,
    )
    typed_function = cast(_FunctionBoundary8616, function)
    try:
        info: dict[str, object] | None = typed_function.info
    except AttributeError:
        info = None
    if isinstance(info, dict):
        info["x86_16_vex_ir_artifact"] = outputs.function.to_dict()
        info["x86_16_vex_ir_summary"] = dict(outputs.function.summary)
        info["x86_16_vex_ir_function_ssa"] = function_ssa.to_dict()
        info["x86_16_vex_ir_function_ssa_stage"] = (
            FunctionSSAArtifactStage8616.SEMANTIC.value
        )
        info["x86_16_call_stack_effects"] = effects.to_dict()
        info["x86_16_call_outputs"] = outputs.to_dict()
    return False


__all__ = [
    "apply_x86_16_call_stack_effects_8616",
    "build_semantic_function_ssa_8616",
]
