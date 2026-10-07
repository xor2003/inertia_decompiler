"""Typed pointee-object contracts for pointer-parameter memory outputs.

Layer: Types/Lowering.
Responsibility: retain the exact Widening-owned global layout matched by every
caller target of one accepted pointer-output object. These contracts do not
discover layouts, infer array bounds, mutate prototypes, or render C.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.core import MemSpace
from inertia.widening.global_object_layout import GlobalObjectLayout8616

from .pointer_parameter_memory_output_contracts import (
    PointerParameterMemoryOutputObject8616,
    PointerParameterMemoryOutputView8616,
)


class PointerParameterObjectTypeFailure8616(StrEnum):
    """Stable reasons pointee-object typing cannot close atomically."""

    UPSTREAM_CONTRACT_REFUSED = "upstream_contract_refused"
    LAYOUT_EVIDENCE_OPEN = "layout_evidence_open"
    DUPLICATE_LOGICAL_INDEX = "duplicate_logical_index"
    OUTPUT_SHAPE_UNSUPPORTED = "output_shape_unsupported"
    LAYOUT_ANCHOR_UNMATCHED = "layout_anchor_unmatched"
    LAYOUT_FAMILY_CONFLICT = "layout_family_conflict"
    TARGET_ALIGNMENT_UNPROVEN = "target_alignment_unproven"


@dataclass(frozen=True, slots=True)
class PointerParameterObjectTypeView8616:
    """One exact caller target matched to a canonical object layout."""

    source: PointerParameterMemoryOutputView8616
    layout: GlobalObjectLayout8616

    @property
    def complete(self) -> bool:
        """Return whether target shape and affine alignment match the layout."""
        effect = self.source.effect
        output = effect.source.output_view
        width = self.layout.element_width
        modulus = 1 << (effect.near_offset.width * 8)
        output_fields = tuple(
            sorted(
                {
                    alias_output.terminal_output.relative_offset
                    for alias_output in output.alias_outputs
                }
            )
        )
        return bool(
            self.source.complete
            and self.layout.complete
            and effect.segment is MemSpace.DS
            and self.layout.address.space is MemSpace.DS
            and output.segment is MemSpace.DS
            and effect.relative_offset == output.relative_offset == 0
            and effect.width == output.width == width
            and output_fields == self.layout.field_offsets
            and modulus % width == 0
            and (effect.target_base_offset - self.layout.address.offset) % width
            == 0
            and all(
                term.coefficient % width == 0
                for term in effect.near_offset.terms
            )
        )


@dataclass(frozen=True, slots=True)
class PointerParameterObjectTypeFact8616:
    """One logical pointer parameter proven to address one object family."""

    source: PointerParameterMemoryOutputObject8616
    layout: GlobalObjectLayout8616
    views: tuple[PointerParameterObjectTypeView8616, ...]

    @property
    def logical_index(self) -> int:
        """Return the exact callee parameter index owned by this fact."""
        return int(self.source.source.logical_index)

    @property
    def family_base_offset(self) -> int:
        """Return the canonical Widening-owned object-family base."""
        return int(self.layout.family_base_offset)

    @property
    def complete(self) -> bool:
        """Return whether every source view has one coherent layout match."""
        keys = tuple(
            (view.source.caller_addr, view.source.callsite_addr)
            for view in self.views
        )
        return bool(
            self.source.complete
            and self.layout.complete
            and self.views
            and len(self.views) == len(self.source.views)
            and len(set(keys)) == len(keys)
            and all(
                view.complete
                and view.layout == self.layout
                and view.source in self.source.views
                for view in self.views
            )
        )


@dataclass(frozen=True, slots=True)
class PointerParameterObjectTypeStats8616:
    """Closed evidence accounting for exact caller-target type matches."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every target produced one retained layout match."""
        return bool(
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            and self.failure_count == 0
        )


@dataclass(frozen=True, slots=True)
class PointerParameterObjectTypeEvidence8616:
    """All pointee-object facts or one atomic typed refusal."""

    function_addr: int
    facts: tuple[PointerParameterObjectTypeFact8616, ...]
    failure: PointerParameterObjectTypeFailure8616 | None
    stats: PointerParameterObjectTypeStats8616
    logical_index: int | None = None
    callsite_addr: int | None = None

    @property
    def complete(self) -> bool:
        """Return whether every unique pointer object closed without refusal."""
        indices = tuple(fact.logical_index for fact in self.facts)
        return bool(
            self.function_addr >= 0
            and self.failure is None
            and self.stats.complete
            and len(set(indices)) == len(indices)
            and sum(len(fact.views) for fact in self.facts)
            == self.stats.materialized_count
            and all(
                fact.complete
                and all(
                    view.source.callee_addr == self.function_addr
                    for view in fact.views
                )
                for fact in self.facts
            )
        )


__all__ = [
    "PointerParameterObjectTypeEvidence8616",
    "PointerParameterObjectTypeFact8616",
    "PointerParameterObjectTypeFailure8616",
    "PointerParameterObjectTypeStats8616",
    "PointerParameterObjectTypeView8616",
]
