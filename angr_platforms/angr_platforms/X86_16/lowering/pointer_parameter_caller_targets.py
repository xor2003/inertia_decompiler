"""Publish exact caller targets for pointer-parameter memory outputs.

Layer: Types/Lowering.
Responsibility: join the complete direct-caller census, exact caller SSA
argument definitions, IR-owned affine near offsets, and callee pointer-output
views into one atomic per-callee target registry. This module does not infer
pointee types, mutate function contracts or code generation, or render C.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from typing import Protocol, cast

from ..callsite_summary import CallsiteSummary8616
from ..ir.function_ssa_registry import (
    FunctionSSAArtifactFailure8616,
    FunctionSSAArtifactVerdict8616,
)
from ..ir.ssa_function import SSAFunctionArtifact
from ..pipeline.errors import PipelineHardError
from ..semantics.call_stack_effect_pipeline import (
    semantic_function_ssa_artifact_at_address_8616,
)
from .callee_callsite_census import (
    CalleeCallsiteCensus8616,
    collect_callee_callsite_census_8616,
)
from .callee_callsite_contracts import CalleeCallsiteFact8616
from .interprocedural_storage_reaching_contracts import (
    CallArgumentDefinitionFailure8616,
    CallArgumentDefinitionVerdict8616,
)
from .interprocedural_storage_reaching_defs import (
    resolve_call_argument_reaching_definition_8616,
)
from .pointer_parameter_caller_target_contracts import (
    PointerParameterCallerTarget8616,
    PointerParameterCallerTargetEvidence8616,
    PointerParameterCallerTargetFailure8616,
    PointerParameterCallerTargetStats8616,
)
from .pointer_parameter_output_contracts import (
    PointerParameterOutputContract8616,
    PointerParameterOutputEvidence8616,
)
from .pointer_parameter_outputs import publish_pointer_parameter_outputs_8616


class _ProjectSurface8616(Protocol):
    """Owned project registry for immutable caller-target evidence."""

    _inertia_pointer_parameter_caller_targets_8616: dict[
        int, PointerParameterCallerTargetEvidence8616
    ]


def _registry_8616(
    project: object,
) -> dict[int, PointerParameterCallerTargetEvidence8616]:
    """Return the owned per-project caller-target registry."""
    surface = cast(_ProjectSurface8616, project)
    try:
        registry = surface._inertia_pointer_parameter_caller_targets_8616
    except AttributeError:
        registry = {}
        surface._inertia_pointer_parameter_caller_targets_8616 = registry
    if not isinstance(registry, dict):
        raise TypeError("pointer-parameter caller-target registry must be a dict")
    return registry


def _publish_8616(
    project: object,
    evidence: PointerParameterCallerTargetEvidence8616,
) -> PointerParameterCallerTargetEvidence8616:
    """Publish once, replay equal evidence, and reject conflicting truth."""
    registry = _registry_8616(project)
    existing = registry.get(evidence.callee_addr)
    if existing is not None and existing != evidence:
        raise PipelineHardError(
            PointerParameterCallerTargetFailure8616.PUBLICATION_CONFLICT.value,
            layer="types/lowering",
            function_addr=evidence.callee_addr,
        )
    registry[evidence.callee_addr] = evidence
    return evidence


def _refused_8616(
    project: object,
    callee_addr: int,
    failure: PointerParameterCallerTargetFailure8616,
    *,
    outputs: PointerParameterOutputEvidence8616,
    census: CalleeCallsiteCensus8616,
    raw_count: int,
    normalized_count: int = 0,
    caller_addr: int | None = None,
    callsite_addr: int | None = None,
    logical_index: int | None = None,
    reaching_failure: CallArgumentDefinitionFailure8616 | None = None,
    ssa_failure: FunctionSSAArtifactFailure8616 | None = None,
) -> PointerParameterCallerTargetEvidence8616:
    """Publish one atomic refusal while retaining its exact location."""
    return _publish_8616(
        project,
        PointerParameterCallerTargetEvidence8616(
            callee_addr,
            (),
            failure,
            PointerParameterCallerTargetStats8616(
                raw_fact_count=max(1, raw_count),
                normalized_fact_count=normalized_count,
                failure_count=1,
            ),
            outputs,
            census,
            caller_addr,
            callsite_addr,
            logical_index,
            reaching_failure,
            ssa_failure,
        ),
    )


def pointer_parameter_caller_target_evidence_8616(
    project: object,
    callee_addr: int,
) -> PointerParameterCallerTargetEvidence8616 | None:
    """Return one published exact-callee caller-target result."""
    return _registry_8616(project).get(callee_addr)


def _output_target_8616(
    project: object,
    callee_addr: int,
    caller: CalleeCallsiteFact8616,
    caller_addr: int,
    summary: CallsiteSummary8616,
    artifact: SSAFunctionArtifact,
    output: PointerParameterOutputContract8616,
    outputs: PointerParameterOutputEvidence8616,
    census: CalleeCallsiteCensus8616,
    expected_count: int,
    normalized_count: int,
) -> tuple[PointerParameterCallerTarget8616 | None, PointerParameterCallerTargetEvidence8616 | None]:
    """Project one callee output through one proven caller callsite."""
    reaching = resolve_call_argument_reaching_definition_8616(
        artifact,
        summary,
        output.logical_index,
        project=caller.evidence_project,
        expected_target_addr=caller.evidence_target_addr,
    )
    if (
        reaching.verdict is not CallArgumentDefinitionVerdict8616.PROVEN
        or reaching.use is None
    ):
        return None, _refused_8616(
            project,
            callee_addr,
            PointerParameterCallerTargetFailure8616.REACHING_DEFINITION_REFUSED,
            outputs=outputs,
            census=census,
            raw_count=expected_count,
            normalized_count=normalized_count,
            caller_addr=caller_addr,
            callsite_addr=caller.callsite_addr,
            logical_index=output.logical_index,
            reaching_failure=reaching.failure,
        )
    near_offset = reaching.affine_expression
    if near_offset is None or not near_offset.complete:
        return None, _refused_8616(
            project,
            callee_addr,
            PointerParameterCallerTargetFailure8616.NEAR_OFFSET_UNPROVEN,
            outputs=outputs,
            census=census,
            raw_count=expected_count,
            normalized_count=normalized_count,
            caller_addr=caller_addr,
            callsite_addr=caller.callsite_addr,
            logical_index=output.logical_index,
        )
    view = output.output_view
    if near_offset.width != output.argument_storage.size:
        failure = PointerParameterCallerTargetFailure8616.TARGET_WIDTH_CONFLICT
    elif not view.complete:
        failure = PointerParameterCallerTargetFailure8616.TARGET_SEGMENT_UNPROVEN
    else:
        failure = None
    if failure is not None:
        return None, _refused_8616(
            project,
            callee_addr,
            failure,
            outputs=outputs,
            census=census,
            raw_count=expected_count,
            normalized_count=normalized_count,
            caller_addr=caller_addr,
            callsite_addr=caller.callsite_addr,
            logical_index=output.logical_index,
        )
    target = PointerParameterCallerTarget8616(
        callee_addr,
        caller_addr,
        caller.callsite_addr,
        output.logical_index,
        view.segment,
        near_offset,
        view.relative_offset,
        view.width,
        reaching.definitions,
        reaching.use,
        output,
    )
    if not target.complete:
        return None, _refused_8616(
            project,
            callee_addr,
            PointerParameterCallerTargetFailure8616.CALLSITE_PROJECTION_INCOMPLETE,
            outputs=outputs,
            census=census,
            raw_count=expected_count,
            normalized_count=normalized_count,
            caller_addr=caller_addr,
            callsite_addr=caller.callsite_addr,
            logical_index=output.logical_index,
        )
    return target, None


def _caller_targets_8616(
    project: object,
    callee_addr: int,
    caller: CalleeCallsiteFact8616,
    outputs: PointerParameterOutputEvidence8616,
    census: CalleeCallsiteCensus8616,
    expected_count: int,
    normalized_count: int,
) -> tuple[tuple[PointerParameterCallerTarget8616, ...], PointerParameterCallerTargetEvidence8616 | None]:
    """Project every callee output through one proven caller callsite."""
    summary = caller.summary
    caller_addr = caller.caller_addr
    if summary is None or caller_addr is None:
        return (), _refused_8616(
            project,
            callee_addr,
            PointerParameterCallerTargetFailure8616.CALLER_IDENTITY_UNPROVEN,
            outputs=outputs,
            census=census,
            raw_count=expected_count,
            normalized_count=normalized_count,
            caller_addr=caller_addr,
            callsite_addr=caller.callsite_addr,
        )
    ssa = semantic_function_ssa_artifact_at_address_8616(
        caller.evidence_project,
        caller_addr,
        function=caller.caller_function,
    )
    if ssa.verdict is not FunctionSSAArtifactVerdict8616.PROVEN or ssa.artifact is None:
        return (), _refused_8616(
            project,
            callee_addr,
            PointerParameterCallerTargetFailure8616.CALLER_SSA_UNAVAILABLE,
            outputs=outputs,
            census=census,
            raw_count=expected_count,
            normalized_count=normalized_count,
            caller_addr=caller_addr,
            callsite_addr=caller.callsite_addr,
            ssa_failure=ssa.failure,
        )
    targets: list[PointerParameterCallerTarget8616] = []
    for output in outputs.facts:
        target, refusal = _output_target_8616(
            project,
            callee_addr,
            caller,
            caller_addr,
            summary,
            ssa.artifact,
            output,
            outputs,
            census,
            expected_count,
            normalized_count + len(targets),
        )
        if refusal is not None:
            return (), refusal
        assert target is not None
        targets.append(target)
    return tuple(targets), None


def publish_pointer_parameter_caller_targets_8616(
    project: object,
    callee_addr: int,
    *,
    function: object | None = None,
    outputs: PointerParameterOutputEvidence8616 | None = None,
) -> PointerParameterCallerTargetEvidence8616:
    """Project every pointer output through every exact direct callsite."""
    if outputs is None:
        outputs = publish_pointer_parameter_outputs_8616(
            project,
            callee_addr,
            function=function,
        )
    census = collect_callee_callsite_census_8616(project, callee_addr)
    if not outputs.complete:
        return _refused_8616(
            project,
            callee_addr,
            PointerParameterCallerTargetFailure8616.CALLEE_OUTPUT_REFUSED,
            outputs=outputs,
            census=census,
            raw_count=len(outputs.facts),
        )
    if not outputs.facts:
        return _publish_8616(
            project,
            PointerParameterCallerTargetEvidence8616(
                callee_addr,
                (),
                None,
                PointerParameterCallerTargetStats8616(),
                outputs,
                census,
            ),
        )
    expected_count = len(outputs.facts) * len(census.facts)
    if not census.complete:
        return _refused_8616(
            project,
            callee_addr,
            PointerParameterCallerTargetFailure8616.CALLER_CENSUS_INCOMPLETE,
            outputs=outputs,
            census=census,
            raw_count=expected_count,
        )

    targets: list[PointerParameterCallerTarget8616] = []
    for caller in census.facts:
        caller_targets, refusal = _caller_targets_8616(
            project,
            callee_addr,
            caller,
            outputs,
            census,
            expected_count,
            len(targets),
        )
        if refusal is not None:
            return refusal
        targets.extend(caller_targets)
    count = len(targets)
    evidence = PointerParameterCallerTargetEvidence8616(
        callee_addr,
        tuple(targets),
        None,
        PointerParameterCallerTargetStats8616(count, count, count, count),
        outputs,
        census,
    )
    if not evidence.complete:
        raise PipelineHardError(
            "classified pointer-parameter caller targets were not materialized",
            layer="types/lowering",
            function_addr=callee_addr,
        )
    return _publish_8616(project, evidence)


__all__ = [
    "pointer_parameter_caller_target_evidence_8616",
    "publish_pointer_parameter_caller_targets_8616",
]
