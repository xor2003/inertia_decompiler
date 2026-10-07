"""Typed object contracts for pointer-parameter memory outputs.

Layer: Types/Lowering.
Responsibility: retain one callee pointer-output contract and every exact
caller-target binding without converting dynamic segmented targets into direct
storage identities. Grouping lives in ``pointer_parameter_memory_outputs``.
This module performs no CFG traversal, type inference, codegen, or rendering.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .pointer_parameter_caller_target_contracts import PointerParameterCallerTarget8616
from .pointer_parameter_output_contracts import PointerParameterOutputContract8616


class PointerParameterMemoryOutputFailure8616(StrEnum):
    """Stable reasons dynamic memory-output grouping cannot close."""

    INCOMPLETE_EFFECT = "incomplete_effect"
    DUPLICATE_EFFECT = "duplicate_effect"
    CALLSITE_CONFLICT = "callsite_conflict"
    SOURCE_CONFLICT = "source_conflict"


@dataclass(frozen=True, slots=True)
class PointerParameterMemoryOutputView8616:
    """One exact callsite binding for a dynamic pointer output."""

    caller_addr: int
    callee_addr: int
    callsite_addr: int
    effect: PointerParameterCallerTarget8616

    @property
    def complete(self) -> bool:
        """Return whether the binding and retained target agree exactly."""
        return bool(
            self.effect.complete
            and self.caller_addr == self.effect.caller_addr
            and self.callee_addr == self.effect.callee_addr
            and self.callsite_addr == self.effect.callsite_addr
        )


@dataclass(frozen=True, slots=True)
class PointerParameterMemoryOutputObject8616:
    """One callee pointer-output source and all exact caller bindings."""

    source: PointerParameterOutputContract8616
    views: tuple[PointerParameterMemoryOutputView8616, ...]

    @property
    def complete(self) -> bool:
        """Return whether every unique view retains this exact source."""
        keys = tuple(
            (view.caller_addr, view.callsite_addr, view.effect.logical_index)
            for view in self.views
        )
        return bool(
            self.source.complete
            and self.views
            and len(set(keys)) == len(keys)
            and all(view.complete and view.effect.source == self.source for view in self.views)
        )


@dataclass(frozen=True, slots=True)
class PointerParameterMemoryOutputStats8616:
    """Closed evidence accounting for dynamic memory-output views."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every dynamic effect became one retained view."""
        return bool(
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            and self.failure_count == 0
        )


@dataclass(frozen=True, slots=True)
class PointerParameterMemoryOutputJoin8616:
    """All dynamic output objects or one atomic typed refusal."""

    objects: tuple[PointerParameterMemoryOutputObject8616, ...]
    failure: PointerParameterMemoryOutputFailure8616 | None
    stats: PointerParameterMemoryOutputStats8616

    @property
    def complete(self) -> bool:
        """Return whether every effect is grouped exactly once."""
        return bool(
            self.failure is None
            and self.stats.complete
            and sum(len(item.views) for item in self.objects)
            == self.stats.materialized_count
            and all(item.complete for item in self.objects)
        )


__all__ = [
    "PointerParameterMemoryOutputFailure8616",
    "PointerParameterMemoryOutputJoin8616",
    "PointerParameterMemoryOutputObject8616",
    "PointerParameterMemoryOutputStats8616",
    "PointerParameterMemoryOutputView8616",
]
