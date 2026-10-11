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

from collections.abc import MutableMapping
from dataclasses import dataclass
from typing import Protocol, cast

from inertia.ir.core import IRFunctionArtifact
from inertia.ir.declared_entry_pipeline import (
    DeclaredEntryPipeline8616,
    UnprovedDeclaredEntry8616,
    _retained_input_8616,
)
from inertia.ir.function_ir_registry import (
    FunctionIRArtifactFailure8616,
    FunctionIRArtifactVerdict8616,
    publish_function_ir_artifact_8616,
)
from inertia.ir.function_ssa_registry import (
    FunctionSSAArtifactFailure8616,
    FunctionSSAArtifactResolution8616,
    FunctionSSAArtifactStage8616,
    FunctionSSAArtifactVerdict8616,
    function_boundary_at_address_8616,
    publish_function_ssa_artifact_8616,
    registered_function_ssa_artifact_8616,
)
from inertia.ir.ssa_function import SSAFunctionArtifact, build_x86_16_function_ssa
from inertia.ir.vex_import import build_x86_16_ir_function_artifact, codegen_function_8616
from inertia.pipeline.errors import PipelineHardError
from inertia.semantics.callsite_summary_program import (
    build_callsite_summary_inventory_with_program_evidence_8616,
)

from .call_outputs import CallOutputArtifact8616, materialize_call_outputs_8616
from .call_return_segment import collect_return_segment_frames_8616
from .call_stack_allocation import collect_call_stack_allocation_candidates_8616
from .call_stack_effects import (
    CallStackEffectArtifact8616,
    materialize_call_stack_effects_8616,
)
from .call_target_evidence_8616 import (
    publish_call_semantic_projection_8616,
)
from .scoped_call_projection import ScopedCallSemanticInput8616, scoped_call_semantic_input_8616


class _CFunctionBoundary8616(Protocol):
    """Minimal generated-function identity used by this pass."""

    addr: int


class _FunctionBoundary8616(Protocol):
    """Owned metadata extension on a third-party recovered function."""

    info: MutableMapping[str, object]


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
    scoped_input: ScopedCallSemanticInput8616 | None = None

    @property
    def complete(self) -> bool:
        """Return whether every projection has closed evidence accounting."""
        function_addr = self.source_ir.function_addr
        accounting = bool(
            self.effects.stats.closed
            and self.outputs.stats.closed
            and self.effects.function.function_addr == function_addr
            and self.outputs.function.function_addr == function_addr
            and self.function_ssa.function_addr == function_addr
        )
        if not accounting or self.scoped_input is None:
            return accounting
        return (
            self.scoped_input.source_ir is self.source_ir
            and self.scoped_input.authenticates_outputs(self.effects, self.outputs, self.function_ssa)
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
        raw_ir = build_x86_16_ir_function_artifact(project, function)
        effects, outputs, function_ssa = build_semantic_function_ssa_8616(
            project,
            function,
            ir_artifact=raw_ir,
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
    return _publish_resolved_semantic_8616(
        project, raw_ir, effects, outputs, function_ssa
    )


def _publish_resolved_semantic_8616(
    project: object,
    raw_ir: IRFunctionArtifact,
    effects: CallStackEffectArtifact8616,
    outputs: CallOutputArtifact8616,
    function_ssa: SSAFunctionArtifact,
) -> FunctionSSAArtifactResolution8616:
    """Publish raw IR, semantic SSA, and the coherent projection together."""
    ir_publication = publish_function_ir_artifact_8616(project, raw_ir)
    if ir_publication.verdict is not FunctionIRArtifactVerdict8616.PROVEN:
        return FunctionSSAArtifactResolution8616(
            raw_ir.function_addr,
            FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE,
            None,
            FunctionSSAArtifactFailure8616.ARTIFACT_CONFLICT,
            registered_function_ssa_artifact_8616(project, raw_ir.function_addr).stage,
        )
    projection = CallSemanticProjection8616(raw_ir, effects, outputs, function_ssa)
    retained = publish_call_semantic_projection_8616(project, projection)
    if not retained.complete:
        return FunctionSSAArtifactResolution8616(
            raw_ir.function_addr,
            FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE,
            None,
            FunctionSSAArtifactFailure8616.ARTIFACT_CONFLICT,
            registered_function_ssa_artifact_8616(project, raw_ir.function_addr).stage,
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
    allocations = collect_call_stack_allocation_candidates_8616(project, raw_ir, summaries)
    return_frames = collect_return_segment_frames_8616(
        project, function,
        {address: summary.return_addr for address, summary in summaries.items() if summary.return_addr is not None},
    )
    effects = materialize_call_stack_effects_8616(
        raw_ir, summaries, project=project, allocation_candidates=allocations,
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


def _proven_source_ir_8616(
    boundary: _CodegenBoundary8616,
) -> tuple[_CFunctionBoundary8616, IRFunctionArtifact, IRFunctionArtifact] | None:
    """Return the proven cfunc/raw/source IR triple, or None."""
    try:
        cfunc = boundary.cfunc
        raw_ir = boundary._inertia_vex_ir_artifact
    except AttributeError:
        return None
    if cfunc is None or not isinstance(cfunc.addr, int):
        return None
    if not isinstance(raw_ir, IRFunctionArtifact) or raw_ir.function_addr != cfunc.addr:
        return None
    try:
        source_ir = boundary._inertia_raw_vex_ir_artifact_8616
    except AttributeError:
        try:
            source_ir = boundary._inertia_call_semantic_projection_8616.source_ir
        except AttributeError:
            source_ir = raw_ir
    if not isinstance(source_ir, IRFunctionArtifact) or source_ir.function_addr != cfunc.addr:
        return None
    return cfunc, raw_ir, source_ir


def _reusable_projection_8616(
    boundary: _CodegenBoundary8616,
    source_ir: IRFunctionArtifact,
    raw_ir: IRFunctionArtifact,
    *, project: object, function: object,
) -> bool:
    """Reauthenticate retained Semantics only in the identical consuming context."""
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
        entry = _retained_input_8616(boundary)
        scoped = existing_projection.scoped_input
        if scoped is None:
            if entry is not None or source_ir.refusals:
                return False
        else:
            if (entry is None or type(entry) is not DeclaredEntryPipeline8616
                    or scoped.project is not project
                    or scoped.function is not function or scoped.source_ir is not source_ir):
                return False
            if (entry.bundle.artifact is not source_ir
                    or scoped.scope is not entry.scope or scoped.view is not entry.view):
                return False
        if not existing_projection.complete:
            raise PipelineHardError(
                "cached call Semantics projection has incomplete evidence accounting",
                layer="semantics",
            )
        return True
    return False


def _published_function_ssa_8616(
    project: object,
    function_ssa: SSAFunctionArtifact,
    outputs: CallOutputArtifact8616,
    function_addr: int,
) -> SSAFunctionArtifact:
    """Publish the SSA artifact to the project registry when unrefused."""
    if outputs.function.refusals:
        return function_ssa
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
                "function_addr": function_addr,
                "failure": None
                if publication.failure is None
                else publication.failure.value,
                "stage": None
                if publication.stage is None
                else publication.stage.value,
            },
        )
    return publication.artifact


def _publish_semantic_artifacts_8616(
    project: object,
    boundary: _CodegenBoundary8616,
    source_ir: IRFunctionArtifact,
    effects: CallStackEffectArtifact8616,
    outputs: CallOutputArtifact8616,
    function_ssa: SSAFunctionArtifact,
    *, scoped_input: ScopedCallSemanticInput8616 | None = None,
) -> None:
    """Publish all Semantics artifacts onto codegen and the project."""
    projection = CallSemanticProjection8616(source_ir, effects, outputs, function_ssa, scoped_input)
    if scoped_input is not None:
        if not projection.complete:
            raise PipelineHardError("conditional call projection failed revalidation", layer="semantics")
        _attach_semantic_artifacts_8616(boundary, projection)
        return
    ir_publication = publish_function_ir_artifact_8616(project, source_ir)
    if ir_publication.verdict is not FunctionIRArtifactVerdict8616.PROVEN:
        raise PipelineHardError(
            "Semantics raw IR conflicts with retained evidence",
            layer="semantics",
            details={"function_addr": source_ir.function_addr,
                     "failure": None if ir_publication.failure is None else ir_publication.failure.value},
        )
    publication = publish_call_semantic_projection_8616(project, projection)
    if not publication.complete:
        raise PipelineHardError(
            "Semantics call projection conflicts with retained evidence",
            layer="semantics",
            details={"function_addr": source_ir.function_addr,
                     "failure": None if publication.failure is None else publication.failure.value},
        )
    _attach_semantic_artifacts_8616(boundary, projection)


def _attach_semantic_artifacts_8616(
    boundary: _CodegenBoundary8616, projection: CallSemanticProjection8616,
) -> None:
    """Attach the same typed projection while keeping publication policy separate."""
    effects, outputs, function_ssa = projection.effects, projection.outputs, projection.function_ssa
    boundary._inertia_vex_ir_artifact = outputs.function
    boundary._inertia_vex_ir_summary = outputs.function.summary
    boundary._inertia_vex_ir_function_ssa = function_ssa
    boundary._inertia_vex_ir_function_ssa_stage_8616 = FunctionSSAArtifactStage8616.SEMANTIC
    boundary._inertia_call_stack_effect_artifact_8616 = effects
    boundary._inertia_call_output_artifact_8616 = outputs
    boundary._inertia_call_semantic_projection_8616 = projection


def _record_function_info_8616(
    function: object,
    outputs: CallOutputArtifact8616,
    effects: CallStackEffectArtifact8616,
    function_ssa: SSAFunctionArtifact,
) -> None:
    """Mirror Semantics artifacts into the function's info dict."""
    typed_function = cast(_FunctionBoundary8616, function)
    try:
        info: MutableMapping[str, object] | None = typed_function.info
    except AttributeError:
        info = None
    if isinstance(info, MutableMapping):
        info["x86_16_vex_ir_artifact"] = outputs.function.to_dict()
        info["x86_16_vex_ir_summary"] = dict(outputs.function.summary)
        info["x86_16_vex_ir_function_ssa"] = function_ssa.to_dict()
        info["x86_16_vex_ir_function_ssa_stage"] = (
            FunctionSSAArtifactStage8616.SEMANTIC.value
        )
        info["x86_16_call_stack_effects"] = effects.to_dict()
        info["x86_16_call_outputs"] = outputs.to_dict()


def apply_x86_16_call_stack_effects_8616(project: object, codegen: object) -> bool:
    """Replace raw function SSA with the Semantics-enriched production artifact."""
    boundary = cast(_CodegenBoundary8616, codegen)
    proven = _proven_source_ir_8616(boundary)
    if proven is None:
        return False
    cfunc, raw_ir, source_ir = proven
    resolved = codegen_function_8616(project, codegen)
    if resolved is None:
        return False
    function, _function_addr = resolved
    entry = _retained_input_8616(codegen)
    if type(entry) is UnprovedDeclaredEntry8616:
        if (
            entry.bundle.artifact is not source_ir
            or entry.view.source_artifact is not source_ir
            or raw_ir is not source_ir
            or entry.view.boundary.project is not project
        ):
            raise PipelineHardError(
                "unproved declared entry lost its authenticated raw source",
                layer="semantics", function_addr=cfunc.addr,
            )
        # No entry premise authorizes semantic enrichment or universal
        # publication. Keep the raw SSA and every unresolved effect attached.
        return False
    if _reusable_projection_8616(
        boundary, source_ir, raw_ir, project=project, function=function,
    ):
        return False
    scoped_input = scoped_call_semantic_input_8616(project, codegen, function, source_ir)
    if source_ir.refusals and scoped_input is None:
        # Import already retained the failure; no derived publication can
        # establish semantics for this source or erase its refusal evidence.
        raise PipelineHardError(
            "Semantics source IR contains retained refusals",
            layer="semantics",
            details={
                "function_addr": source_ir.function_addr,
                "failure": FunctionIRArtifactFailure8616.ARTIFACT_REFUSED.value,
                "refusals": [refusal.to_dict() for refusal in source_ir.refusals],
            },
        )
    effects, outputs, function_ssa = build_semantic_function_ssa_8616(
        project,
        function,
        ir_artifact=source_ir if scoped_input is None else scoped_input.input_ir,
    )
    if scoped_input is None:
        function_ssa = _published_function_ssa_8616(project, function_ssa, outputs, cfunc.addr)
    _publish_semantic_artifacts_8616(
        project, boundary, source_ir, effects, outputs, function_ssa, scoped_input=scoped_input,
    )
    _record_function_info_8616(function, outputs, effects, function_ssa)
    return False


__all__ = [
    "apply_x86_16_call_stack_effects_8616",
    "build_semantic_function_ssa_8616",
]
