# cython: language_level=3, infer_types=True
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
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum

from .pointer_parameter_caller_target_contracts import PointerParameterCallerTarget8616
from .pointer_parameter_output_contracts import PointerParameterOutputContract8616
import dataclasses
import operator


class PointerParameterMemoryOutputFailure8616(StrEnum):
    """Stable reasons dynamic memory-output grouping cannot close."""

    INCOMPLETE_EFFECT = "incomplete_effect"
    DUPLICATE_EFFECT = "duplicate_effect"
    CALLSITE_CONFLICT = "callsite_conflict"
    SOURCE_CONFLICT = "source_conflict"


@dataclasses.dataclass(frozen=True, )
class PointerParameterMemoryOutputView8616:
    """One exact callsite binding for a dynamic pointer output."""

    caller_addr: cython.longlong
    callee_addr: cython.longlong
    callsite_addr: cython.longlong
    effect: PointerParameterCallerTarget8616

    @property
    def complete(self) -> cython.bint:
        """Return whether the binding and retained target agree exactly."""
        return bool(
            self.effect.complete
            and operator.eq(self.caller_addr, self.effect.caller_addr)
            and operator.eq(self.callee_addr, self.effect.callee_addr)
            and operator.eq(self.callsite_addr, self.effect.callsite_addr)
        )


@dataclasses.dataclass(frozen=True, )
class PointerParameterMemoryOutputObject8616:
    """One callee pointer-output source and all exact caller bindings."""

    source: PointerParameterOutputContract8616
    views: object

    @property
    def complete(self) -> cython.bint:
        """Return whether every unique view retains this exact source."""
        keys = tuple(
            (view.caller_addr, view.callsite_addr, view.effect.logical_index)
            for view in iter(self.views)
        )
        return bool(
            self.source.complete
            and self.views
            and operator.eq(len(set(keys)), len(keys))
            and all(view.complete and operator.eq(view.effect.source, self.source) for view in iter(self.views))
        )


@dataclasses.dataclass(frozen=True, )
class PointerParameterMemoryOutputStats8616:
    """Closed evidence accounting for dynamic memory-output views."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0

    @property
    def complete(self) -> cython.bint:
        """Return whether every dynamic effect became one retained view."""
        return bool(
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            and self.failure_count == 0
        )


@dataclasses.dataclass(frozen=True, )
class PointerParameterMemoryOutputJoin8616:
    """All dynamic output objects or one atomic typed refusal."""

    objects: object
    failure: PointerParameterMemoryOutputFailure8616 | None
    stats: PointerParameterMemoryOutputStats8616

    @property
    def complete(self) -> cython.bint:
        """Return whether every effect is grouped exactly once."""
        return bool(
            self.failure is None
            and self.stats.complete
            and operator.eq(sum(len(item.views) for item in iter(self.objects)), self.stats.materialized_count)
            and all(item.complete for item in iter(self.objects))
        )


__all__ = [
    "PointerParameterMemoryOutputFailure8616",
    "PointerParameterMemoryOutputJoin8616",
    "PointerParameterMemoryOutputObject8616",
    "PointerParameterMemoryOutputStats8616",
    "PointerParameterMemoryOutputView8616",
]
