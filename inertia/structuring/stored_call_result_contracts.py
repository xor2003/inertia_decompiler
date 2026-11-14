# cython: language_level=3, infer_types=True
"""Typed status contracts for stored call-result occurrence ownership.

Layer: Structuring.
Responsibility: Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Preserve deterministic verdicts, closed evidence counters, and fail-closed
refusal reasons for stored call-result occurrence materialization.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import Enum
import dataclasses

__all__ = (
    "StoredCallResultOccurrenceResult8616",
    "StoredCallResultOccurrenceStats8616",
    "StoredCallResultOccurrenceVerdict8616",
    "StoredCallResultRefusal8616",
    "StoredCallResultRefusalReason8616",
)


class StoredCallResultOccurrenceVerdict8616(Enum):
    """Typed outcome of one stored-call occurrence ownership pass."""

    MATERIALIZED = "materialized"
    NO_CANDIDATE = "no_candidate"
    UNKNOWN_REFUSE = "unknown_refuse"


class StoredCallResultRefusalReason8616(Enum):
    """Evidence failures that prevent duplicate stored-call ownership."""

    SUMMARY_MISSING_OR_CONFLICTING = "summary_missing_or_conflicting"
    OCCURRENCE_SET_AMBIGUOUS = "occurrence_set_ambiguous"
    RETURN_STORE_NOT_PROVEN = "return_store_not_proven"
    CALL_SURFACE_CONFLICT = "call_surface_conflict"
    STRUCTURED_ORDER_UNKNOWN = "structured_order_unknown"


@dataclasses.dataclass(frozen=True, )
class StoredCallResultRefusal8616:
    """One exact callsite whose duplicate occurrence cannot be removed."""

    callsite_addr: cython.longlong
    reason: StoredCallResultRefusalReason8616


@cython.dataclasses.dataclass()
class StoredCallResultOccurrenceStats8616:
    """Closed evidence counters for stored-call occurrence ownership."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0
    removed_standalone_count: cython.longlong = 0


@dataclasses.dataclass(frozen=True, )
class StoredCallResultOccurrenceResult8616:
    """Typed result published by the Structuring stored-call owner."""

    verdict: StoredCallResultOccurrenceVerdict8616
    stats: StoredCallResultOccurrenceStats8616
    refusals: object

    @property
    def changed(self) -> cython.bint:
        """Return whether a proven duplicate standalone call was removed."""
        return self.stats.materialized_count > 0
