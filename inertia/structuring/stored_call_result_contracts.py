"""Typed status contracts for stored call-result occurrence ownership.

Layer: Structuring.
Responsibility: Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Preserve deterministic verdicts, closed evidence counters, and fail-closed
refusal reasons for stored call-result occurrence materialization.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

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


@dataclass(frozen=True, slots=True)
class StoredCallResultRefusal8616:
    """One exact callsite whose duplicate occurrence cannot be removed."""

    callsite_addr: int
    reason: StoredCallResultRefusalReason8616


@dataclass(slots=True)
class StoredCallResultOccurrenceStats8616:
    """Closed evidence counters for stored-call occurrence ownership."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    removed_standalone_count: int = 0


@dataclass(frozen=True, slots=True)
class StoredCallResultOccurrenceResult8616:
    """Typed result published by the Structuring stored-call owner."""

    verdict: StoredCallResultOccurrenceVerdict8616
    stats: StoredCallResultOccurrenceStats8616
    refusals: tuple[StoredCallResultRefusal8616, ...]

    @property
    def changed(self) -> bool:
        """Return whether a proven duplicate standalone call was removed."""
        return self.stats.materialized_count > 0
