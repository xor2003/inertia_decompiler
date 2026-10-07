"""Typed caller-target contracts for pointer-parameter memory outputs.

Layer: Types/Lowering.
Responsibility: join one callee pointer-output view with one exact caller
argument affine expression, physical definitions, and CALL use. These
contracts retain segmented target identity without pretending a dynamic target
is direct global storage. They do not infer pointee types, mutate function
contracts or code generation, or render C.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from inertia.ir.core import MemSpace
from inertia.ir.function_ssa_registry import FunctionSSAArtifactFailure8616
from inertia.ir.scalar_affine_contracts import ScalarAffineExpression8616

from .callee_callsite_census import CalleeCallsiteCensus8616
from .interprocedural_storage_contracts import (
    StorageReachingDefinition8616,
    StorageUseEvidence8616,
)
from .interprocedural_storage_reaching_contracts import (
    CallArgumentDefinitionFailure8616,
)
from .pointer_parameter_output_contracts import (
    PointerParameterOutputContract8616,
    PointerParameterOutputEvidence8616,
)


class PointerParameterCallerTargetFailure8616(StrEnum):
    """Stable reasons caller-target projection cannot close atomically."""

    CALLEE_OUTPUT_REFUSED = "callee_output_refused"
    CALLER_CENSUS_INCOMPLETE = "caller_census_incomplete"
    CALLER_IDENTITY_UNPROVEN = "caller_identity_unproven"
    CALLER_SSA_UNAVAILABLE = "caller_ssa_unavailable"
    REACHING_DEFINITION_REFUSED = "reaching_definition_refused"
    NEAR_OFFSET_UNPROVEN = "near_offset_unproven"
    TARGET_SEGMENT_UNPROVEN = "target_segment_unproven"
    TARGET_WIDTH_CONFLICT = "target_width_conflict"
    CALLSITE_PROJECTION_INCOMPLETE = "callsite_projection_incomplete"
    PUBLICATION_CONFLICT = "publication_conflict"


@dataclass(frozen=True, slots=True)
class PointerParameterCallerTarget8616:
    """One exact segmented caller memory target for a callee output view."""

    callee_addr: int
    caller_addr: int
    callsite_addr: int
    logical_index: int
    segment: MemSpace
    near_offset: ScalarAffineExpression8616
    relative_offset: int
    width: int
    definitions: tuple[StorageReachingDefinition8616, ...]
    use: StorageUseEvidence8616
    source: PointerParameterOutputContract8616

    @property
    def target_base_offset(self) -> int:
        """Return the constant target component under near-offset wrapping."""
        mask = (1 << (self.near_offset.width * 8)) - 1
        return int((self.near_offset.constant + self.relative_offset) & mask)

    @property
    def complete(self) -> bool:
        """Return whether caller and callee evidence agree exactly."""
        view = self.source.output_view
        return bool(
            self.callee_addr >= 0
            and self.caller_addr >= 0
            and self.callsite_addr >= 0
            and self.logical_index == self.source.logical_index
            and self.source.complete
            and self.segment in {MemSpace.DS, MemSpace.ES}
            and self.segment is view.segment
            and self.near_offset.complete
            and self.near_offset.width == self.source.argument_storage.size
            and self.relative_offset == view.relative_offset
            and self.width == view.width > 0
            and self.definitions
            and all(item.is_complete for item in self.definitions)
            and sum(item.value.size for item in self.definitions)
            == self.near_offset.width
            and self.use.is_complete
            and self.use.callsite_addr == self.callsite_addr
        )


@dataclass(frozen=True, slots=True)
class PointerParameterCallerTargetStats8616:
    """Closed accounting for all expected caller/output projections."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every expected projection became one target."""
        return bool(
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            and self.failure_count == 0
        )


@dataclass(frozen=True, slots=True)
class PointerParameterCallerTargetEvidence8616:
    """Complete caller targets or one atomic location-bearing refusal."""

    callee_addr: int
    facts: tuple[PointerParameterCallerTarget8616, ...]
    failure: PointerParameterCallerTargetFailure8616 | None
    stats: PointerParameterCallerTargetStats8616
    outputs: PointerParameterOutputEvidence8616
    census: CalleeCallsiteCensus8616 = field(compare=False, repr=False)
    caller_addr: int | None = None
    callsite_addr: int | None = None
    logical_index: int | None = None
    reaching_failure: CallArgumentDefinitionFailure8616 | None = None
    ssa_failure: FunctionSSAArtifactFailure8616 | None = None

    @property
    def complete(self) -> bool:
        """Return whether the complete census and all targets close."""
        if self.outputs.complete and not self.outputs.facts:
            return bool(
                self.failure is None
                and not self.facts
                and self.stats.complete
                and self.stats.raw_fact_count == 0
            )
        expected = len(self.outputs.facts) * len(self.census.facts)
        return bool(
            self.failure is None
            and self.outputs.complete
            and self.census.complete
            and self.stats.complete
            and self.stats.raw_fact_count == expected == len(self.facts)
            and all(fact.complete for fact in self.facts)
            and len(
                {
                    (fact.caller_addr, fact.callsite_addr, fact.logical_index)
                    for fact in self.facts
                }
            )
            == expected
        )


__all__ = [
    "PointerParameterCallerTarget8616",
    "PointerParameterCallerTargetEvidence8616",
    "PointerParameterCallerTargetFailure8616",
    "PointerParameterCallerTargetStats8616",
]
