"""Run carry/borrow Semantics, Alias, and Widening before Lowering.

Layer: Widening orchestration.
Responsibility: execute the owned carry/borrow producers in pipeline order,
enforce closed evidence accounting, and attach one coherent immutable artifact
to the dynamic angr codegen boundary. No semantic proof is implemented here.
Consumes alias-proven storage identity before joining values or propagating widths.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from inertia.pipeline.errors import PipelineHardError

from inertia.alias.carry_borrow_destinations import (
    CarryBorrowDestinationAliasEvidence8616,
    project_carry_borrow_destination_aliases_8616,
)
from inertia.alias.carry_borrow_projection import (
    CarryBorrowAliasEvidence8616,
    project_carry_borrow_aliases_8616,
)
from inertia.alias.stack_memory_ssa_contracts import StackMemorySSAAliasArtifact8616
from inertia.ir.ssa_function import SSAFunctionArtifact
from inertia.semantics.carry_borrow_contracts import CarryBorrowEvidence8616
from inertia.semantics.carry_borrow_links import analyze_carry_borrow_links_8616

from .carry_borrow_storage import (
    WideCarryBorrowStorageEvidence8616,
    widen_carry_borrow_storage_8616,
)
from .carry_borrow_values import WideCarryBorrowEvidence8616, widen_carry_borrow_values_8616


@dataclass(frozen=True, slots=True)
class CarryBorrowWideningPipeline8616:
    """Coherent per-function projection from SSA through Widening."""

    source_ssa: SSAFunctionArtifact
    source_stack_alias: StackMemorySSAAliasArtifact8616 | None
    semantics: CarryBorrowEvidence8616
    aliases: CarryBorrowAliasEvidence8616
    widening: WideCarryBorrowEvidence8616
    destination_aliases: CarryBorrowDestinationAliasEvidence8616
    storage_widening: WideCarryBorrowStorageEvidence8616

    @property
    def function_addr(self) -> int:
        """Return the exact source function address."""
        return int(self.source_ssa.function_addr)

    @property
    def complete(self) -> bool:
        """Return whether every owned projection has closed accounting."""
        return bool(
            self.semantics.complete
            and self.aliases.complete
            and self.widening.complete
            and self.destination_aliases.complete
            and self.storage_widening.complete
            and (
                self.source_stack_alias is None
                or self.function_addr == self.source_stack_alias.function_addr
            )
            and self.function_addr == self.semantics.function_addr
            and self.function_addr == self.aliases.function_addr
            and self.function_addr == self.widening.function_addr
            and self.function_addr == self.destination_aliases.function_addr
            and self.function_addr == self.storage_widening.function_addr
        )


class _CarryBorrowCodegenBoundary8616(Protocol):
    """Dynamic angr codegen fields owned by this Widening bridge."""

    _inertia_vex_ir_function_ssa: SSAFunctionArtifact
    _inertia_stack_memory_ssa_alias_artifact: StackMemorySSAAliasArtifact8616
    _inertia_carry_borrow_widening_pipeline_8616: CarryBorrowWideningPipeline8616


class CarryBorrowProjection8616(StrEnum):
    """Name one closed-loop edge in the carry/borrow pipeline."""

    SEMANTICS_TO_ALIAS = "semantics_to_alias"
    ALIAS_TO_WIDENING = "alias_to_widening"
    DESTINATION_ALIAS_TO_WIDENING = "destination_alias_to_widening"


def _require_materialization_8616(
    *,
    classified_fact_count: int,
    materialized_count: int,
    layer: str,
    projection: CarryBorrowProjection8616,
    failure_contexts: tuple[tuple[StrEnum, StrEnum | None], ...] = (),
) -> None:
    """Fail with the exact projection and counts when classified facts vanish."""
    if classified_fact_count > 0 and materialized_count == 0:
        reasons = (
            ",".join(
                f"{reason.value}@{operand.value if operand is not None else 'projection'}"
                for reason, operand in failure_contexts
            )
            or "none"
        )
        raise PipelineHardError(
            "carry/borrow facts were classified but none reached "
            f"projection={projection.value} "
            f"classified={classified_fact_count} materialized={materialized_count} "
            f"failures={reasons}",
            layer=layer,
            details={
                "projection": projection,
                "classified_fact_count": classified_fact_count,
                "materialized_count": materialized_count,
                "failure_contexts": failure_contexts,
            },
        )


def build_carry_borrow_widening_pipeline_8616(
    function_ssa: SSAFunctionArtifact,
    stack_alias: StackMemorySSAAliasArtifact8616 | None = None,
) -> CarryBorrowWideningPipeline8616:
    """Build one closed Semantics-to-Widening artifact from exact function SSA."""
    if stack_alias is not None and (
        not stack_alias.complete or stack_alias.function_addr != function_ssa.function_addr
    ):
        raise PipelineHardError(
            "stack-memory Alias evidence is incoherent before carry Widening",
            layer="alias",
        )
    semantics = analyze_carry_borrow_links_8616(function_ssa)
    if not semantics.complete:
        raise PipelineHardError(
            "carry/borrow Semantics evidence accounting is incomplete",
            layer="semantics",
        )
    aliases = project_carry_borrow_aliases_8616(semantics, function_ssa)
    if not aliases.complete:
        raise PipelineHardError(
            "carry/borrow Alias evidence accounting is incomplete",
            layer="alias",
        )
    _require_materialization_8616(
        classified_fact_count=semantics.stats.classified_fact_count,
        materialized_count=aliases.stats.materialized_count,
        layer="alias",
        projection=CarryBorrowProjection8616.SEMANTICS_TO_ALIAS,
        failure_contexts=tuple(
            (item.failure, item.failure_operand)
            for item in aliases.resolutions
            if item.failure is not None
        ),
    )
    widening = widen_carry_borrow_values_8616(aliases)
    if not widening.complete:
        raise PipelineHardError(
            "carry/borrow Widening evidence accounting is incomplete",
            layer="widening",
        )
    _require_materialization_8616(
        classified_fact_count=aliases.stats.classified_fact_count,
        materialized_count=widening.stats.materialized_count,
        layer="widening",
        projection=CarryBorrowProjection8616.ALIAS_TO_WIDENING,
        failure_contexts=tuple(
            (item.failure, None)
            for item in widening.resolutions
            if item.failure is not None
        ),
    )
    destination_aliases = project_carry_borrow_destination_aliases_8616(
        function_ssa,
        aliases,
        stack_alias,
    )
    if not destination_aliases.complete:
        raise PipelineHardError(
            "carry/borrow destination Alias accounting is incomplete",
            layer="alias",
        )
    storage_widening = widen_carry_borrow_storage_8616(widening, destination_aliases)
    if not storage_widening.complete:
        raise PipelineHardError(
            "carry/borrow storage Widening accounting is incomplete",
            layer="widening",
        )
    _require_materialization_8616(
        classified_fact_count=destination_aliases.stats.classified_fact_count,
        materialized_count=storage_widening.stats.materialized_count,
        layer="widening",
        projection=CarryBorrowProjection8616.DESTINATION_ALIAS_TO_WIDENING,
        failure_contexts=tuple(
            (item.failure, None)
            for item in storage_widening.resolutions
            if item.failure is not None
        ),
    )
    artifact = CarryBorrowWideningPipeline8616(
        source_ssa=function_ssa,
        source_stack_alias=stack_alias,
        semantics=semantics,
        aliases=aliases,
        widening=widening,
        destination_aliases=destination_aliases,
        storage_widening=storage_widening,
    )
    if not artifact.complete:
        raise PipelineHardError(
            "carry/borrow pipeline projections disagree on function identity",
            layer="widening",
        )
    return artifact


def apply_carry_borrow_widening_pipeline_8616(
    _project: object,
    codegen: object,
) -> bool:
    """Attach fresh carry/borrow Widening evidence before Lowering runs."""
    boundary = cast(_CarryBorrowCodegenBoundary8616, codegen)
    try:
        function_ssa = boundary._inertia_vex_ir_function_ssa
    except AttributeError:
        return False
    if not isinstance(function_ssa, SSAFunctionArtifact):
        return False
    try:
        raw_stack_alias = boundary._inertia_stack_memory_ssa_alias_artifact
    except AttributeError:
        raw_stack_alias = None
    if raw_stack_alias is not None and not isinstance(
        raw_stack_alias, StackMemorySSAAliasArtifact8616
    ):
        raise PipelineHardError(
            "carry Widening received an invalid stack-memory Alias contract",
            layer="widening",
        )
    stack_alias = raw_stack_alias
    try:
        existing = boundary._inertia_carry_borrow_widening_pipeline_8616
    except AttributeError:
        existing = None
    if (
        isinstance(existing, CarryBorrowWideningPipeline8616)
        and existing.source_ssa is function_ssa
        and existing.source_stack_alias is stack_alias
    ):
        return False
    artifact = build_carry_borrow_widening_pipeline_8616(function_ssa, stack_alias)
    boundary._inertia_carry_borrow_widening_pipeline_8616 = artifact
    return False


__all__ = [
    "CarryBorrowProjection8616",
    "CarryBorrowWideningPipeline8616",
    "apply_carry_borrow_widening_pipeline_8616",
    "build_carry_borrow_widening_pipeline_8616",
]
