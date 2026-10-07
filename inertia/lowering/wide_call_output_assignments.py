"""Materialize wide call-result arithmetic from the typed widening pipeline.

Layer: Types/Lowering.
Responsibility: consume exact CALL_OUTPUT, carry/borrow, source-range, and
destination-range evidence to emit one C assignment and retire only the
instruction-tagged carrier statements that assignment supersedes.
Consumes alias, widening, and typed facts without rediscovering semantics.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import logging
from typing import Protocol, cast

from inertia.pipeline.errors import PipelineHardError

from inertia.widening.carry_borrow_pipeline import CarryBorrowWideningPipeline8616

from .carry_borrow_stack_storage import WideCarryBorrowStackArtifact8616
from .wide_call_output_assignment_contracts import (
    WideCallOutputAssignmentArtifact8616,
    WideCallOutputAssignmentFact8616,
    WideCallOutputAssignmentFailure8616,
    WideCallOutputAssignmentResolution8616,
    WideCallOutputAssignmentStats8616,
    WideCallOutputAssignmentVerdict8616,
    refused_wide_call_output_assignment_8616,
)
from .wide_call_output_assignment_evidence import (
    normalize_wide_call_output_assignment_fact_8616,
)
from .wide_call_output_assignment_placement import (
    materialize_wide_call_output_assignment_8616,
)

_LOGGER = logging.getLogger(__name__)


class _CodegenBoundary8616(Protocol):
    """Dynamic codegen fields consumed and produced by this Lowering pass."""

    cfunc: object
    project: object
    _inertia_carry_borrow_widening_pipeline_8616: CarryBorrowWideningPipeline8616
    _inertia_wide_carry_borrow_stack_artifact: WideCarryBorrowStackArtifact8616
    _inertia_wide_call_output_assignment_artifact_8616: WideCallOutputAssignmentArtifact8616

def lower_wide_call_output_stack_assignments_8616(
    codegen: object,
) -> WideCallOutputAssignmentArtifact8616 | None:
    """Lower exact wide CALL_OUTPUT arithmetic after stack objects exist."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        previous_artifact = boundary._inertia_wide_call_output_assignment_artifact_8616
    except AttributeError:
        previous_artifact = None
    try:
        pipeline = boundary._inertia_carry_borrow_widening_pipeline_8616
        wide_stack = boundary._inertia_wide_carry_borrow_stack_artifact
    except AttributeError:
        return None
    if not isinstance(pipeline, CarryBorrowWideningPipeline8616) or not isinstance(
        wide_stack, WideCarryBorrowStackArtifact8616
    ):
        raise PipelineHardError(
            "wide call-output Lowering received invalid upstream contracts",
            layer="stack_lowering",
        )
    sources = tuple(
        source
        for source in pipeline.storage_widening.values
        if source.value.lhs_call_output is not None
    )
    resolutions: list[WideCallOutputAssignmentResolution8616] = []
    for source in sources:
        stack_candidates = tuple(
            candidate for candidate in wide_stack.candidates if candidate.source is source
        )
        if len(stack_candidates) != 1:
            resolutions.append(
                refused_wide_call_output_assignment_8616(
                    source,
                    WideCallOutputAssignmentFailure8616.DESTINATION_LOWERING_MISSING,
                )
            )
            continue
        normalized = normalize_wide_call_output_assignment_fact_8616(pipeline, source)
        if isinstance(normalized, WideCallOutputAssignmentFailure8616):
            resolutions.append(refused_wide_call_output_assignment_8616(source, normalized))
            continue
        resolutions.append(
            materialize_wide_call_output_assignment_8616(
                codegen,
                boundary.cfunc,
                source,
                normalized,
            )
        )
    materialized = sum(
        item.verdict is WideCallOutputAssignmentVerdict8616.MATERIALIZED
        for item in resolutions
    )
    failures = len(resolutions) - materialized
    artifact = WideCallOutputAssignmentArtifact8616(
        function_addr=pipeline.function_addr,
        resolutions=tuple(resolutions),
        stats=WideCallOutputAssignmentStats8616(
            raw_fact_count=len(resolutions),
            normalized_fact_count=sum(item.fact is not None for item in resolutions),
            classified_fact_count=sum(
                item.placement_classified for item in resolutions
            ),
            materialized_count=materialized,
            failure_count=failures,
            changed_count=sum(item.changed for item in resolutions),
            already_materialized_count=sum(
                item.already_materialized for item in resolutions
            ),
        ),
    )
    boundary._inertia_wide_call_output_assignment_artifact_8616 = artifact
    refused = tuple(
        item.failure.value
        for item in resolutions
        if item.failure is not None
    )
    previous_refused = (
        tuple(
            item.failure.value
            for item in previous_artifact.resolutions
            if item.failure is not None
        )
        if isinstance(previous_artifact, WideCallOutputAssignmentArtifact8616)
        else ()
    )
    if refused and refused != previous_refused:
        _LOGGER.warning(
            "wide call-output Lowering refused function=%#x failures=%s stats=%s",
            artifact.function_addr,
            refused,
            artifact.stats,
        )
    if not artifact.complete:
        raise PipelineHardError(
            "wide call-output assignment Lowering accounting is incomplete",
            layer="stack_lowering",
        )
    return artifact


__all__ = [
    "WideCallOutputAssignmentArtifact8616",
    "WideCallOutputAssignmentFact8616",
    "WideCallOutputAssignmentFailure8616",
    "WideCallOutputAssignmentResolution8616",
    "WideCallOutputAssignmentStats8616",
    "WideCallOutputAssignmentVerdict8616",
    "lower_wide_call_output_stack_assignments_8616",
]
