"""Lower proven numeric carry/borrow uses to explicit C predicates.

Layer: Types/Lowering.
Responsibility: consume the exact Semantics -> Alias -> Widening carry link,
orchestrate bounded C-AST placement, attach closed accounting, and hard-fail
classified evidence that cannot be materialized.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from typing import Protocol, cast

from inertia.pipeline.errors import PipelineHardError

from inertia.structuring.structuring_cfg_ownership import CFGOwnershipArtifact
from inertia.widening.carry_borrow_pipeline import CarryBorrowWideningPipeline8616

from .carry_borrow_bit_contracts import (
    CarryBorrowBitLoweringArtifact8616,
    CarryBorrowBitLoweringFailure8616,
    CarryBorrowBitLoweringResolution8616,
    CarryBorrowBitLoweringStats8616,
    CarryBorrowBitLoweringVerdict8616,
    refused_carry_borrow_bit_lowering_8616,
)
from .carry_borrow_bit_placement import (
    materialize_carry_borrow_bit_value_8616,
    normalize_carry_borrow_bit_fact_8616,
)


class _CFunctionBoundary8616(Protocol):
    """Third-party C function fields required by this Lowering pass."""

    statements: object


class _CodegenBoundary8616(Protocol):
    """Dynamic codegen fields consumed and produced by this Lowering pass."""

    cfunc: _CFunctionBoundary8616
    _inertia_carry_borrow_widening_pipeline_8616: CarryBorrowWideningPipeline8616
    _inertia_carry_borrow_bit_lowering_artifact_8616: CarryBorrowBitLoweringArtifact8616
    _inertia_cfg_execution_ownership_8616: CFGOwnershipArtifact


def lower_carry_borrow_bit_values_8616(codegen: object) -> bool:
    """Consume proven Widening values and attach closed Lowering evidence."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        pipeline = boundary._inertia_carry_borrow_widening_pipeline_8616
    except AttributeError:
        return False
    if not isinstance(pipeline, CarryBorrowWideningPipeline8616):
        raise PipelineHardError("carry-bit Lowering received an invalid Widening contract", layer="lowering")
    try:
        ownership = boundary._inertia_cfg_execution_ownership_8616
    except AttributeError as exc:
        raise PipelineHardError(
            "carry-bit Lowering requires pre-join Structuring CFG ownership",
            layer="lowering",
        ) from exc
    if not isinstance(ownership, CFGOwnershipArtifact):
        raise PipelineHardError("carry-bit Lowering received invalid CFG ownership", layer="lowering")
    root = boundary.cfunc.statements
    resolutions: list[CarryBorrowBitLoweringResolution8616] = []
    for source in pipeline.widening.values:
        fact = normalize_carry_borrow_bit_fact_8616(pipeline.function_addr, source)
        if isinstance(fact, CarryBorrowBitLoweringFailure8616):
            resolutions.append(refused_carry_borrow_bit_lowering_8616(source, fact))
        else:
            resolutions.append(materialize_carry_borrow_bit_value_8616(root, source, fact, ownership))
    materialized = sum(item.verdict is CarryBorrowBitLoweringVerdict8616.MATERIALIZED for item in resolutions)
    artifact = CarryBorrowBitLoweringArtifact8616(
        function_addr=pipeline.function_addr,
        resolutions=tuple(resolutions),
        stats=CarryBorrowBitLoweringStats8616(
            raw_fact_count=len(resolutions),
            normalized_fact_count=sum(item.fact is not None for item in resolutions),
            classified_fact_count=sum(item.placement_classified for item in resolutions),
            materialized_count=materialized,
            failure_count=len(resolutions) - materialized,
            changed_count=sum(item.changed for item in resolutions),
            already_materialized_count=sum(item.already_materialized for item in resolutions),
        ),
    )
    boundary._inertia_carry_borrow_bit_lowering_artifact_8616 = artifact
    if not artifact.complete:
        raise PipelineHardError("carry-bit Lowering accounting is incomplete", layer="lowering")
    classified_failures = tuple(item for item in resolutions if item.placement_classified and item.failure)
    if classified_failures:
        diagnostics = tuple(item.failure_diagnostic for item in classified_failures)
        raise PipelineHardError(
            f"carry-bit Lowering classified evidence but failed to materialize: {diagnostics}",
            layer="lowering",
        )
    return bool(artifact.stats.changed_count)


__all__ = ["lower_carry_borrow_bit_values_8616"]
