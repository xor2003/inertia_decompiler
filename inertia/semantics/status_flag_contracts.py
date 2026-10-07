"""Typed contracts for x86 status-flag liveness decisions.

Layer: Semantics.
Responsibility: define per-bit flag identities, decoded effects, final liveness
verdicts, and closed evidence accounting consumed by frontend flag emission.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntFlag, StrEnum


class StatusFlag8616(IntFlag):
    """Status flags whose data dependencies affect recovered C expressions."""

    NONE = 0
    CARRY = 1 << 0
    PARITY = 1 << 2
    AUXILIARY = 1 << 4
    ZERO = 1 << 6
    SIGN = 1 << 7
    OVERFLOW = 1 << 11


STATUS_FLAGS_8616: StatusFlag8616 = (
    StatusFlag8616.CARRY
    | StatusFlag8616.PARITY
    | StatusFlag8616.AUXILIARY
    | StatusFlag8616.ZERO
    | StatusFlag8616.SIGN
    | StatusFlag8616.OVERFLOW
)
LOGICAL_STATUS_FLAG_WRITES_8616: StatusFlag8616 = STATUS_FLAGS_8616
INCDEC_STATUS_FLAG_WRITES_8616: StatusFlag8616 = STATUS_FLAGS_8616 & ~StatusFlag8616.CARRY
SHIFT_COUNT_ONE_STATUS_FLAG_WRITES_8616: StatusFlag8616 = STATUS_FLAGS_8616 & ~StatusFlag8616.AUXILIARY
SHIFT_COUNT_MANY_STATUS_FLAG_WRITES_8616: StatusFlag8616 = (
    SHIFT_COUNT_ONE_STATUS_FLAG_WRITES_8616 & ~StatusFlag8616.OVERFLOW
)


@dataclass(frozen=True, slots=True)
class DecodedStatusFlagInstruction8616:
    """Minimal decoded instruction evidence needed by flag liveness."""

    mnemonic: str
    immediate_count: int | None = None


@dataclass(frozen=True, slots=True)
class StatusFlagEffect8616:
    """Status flags read and definitely overwritten by one instruction."""

    reads: StatusFlag8616 = StatusFlag8616.NONE
    overwrites: StatusFlag8616 = StatusFlag8616.NONE


class StatusFlagLivenessVerdict8616(StrEnum):
    """Final action for one architectural status-flag definition."""

    KEEP_LIVE = "keep_live"
    KEEP_UNKNOWN = "keep_unknown"
    SUPPRESS_DEAD = "suppress_dead"


@dataclass(frozen=True, slots=True)
class StatusFlagLivenessStats8616:
    """Closed accounting for one final keep-or-suppress decision."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    def __post_init__(self) -> None:
        """Reject a classified decision that was not materialized."""
        if self.classified_fact_count > 0 and self.materialized_count == 0:
            raise ValueError("classified status-flag decision was not materialized")

    @property
    def closed(self) -> bool:
        """Return whether the candidate has one materialized typed outcome."""
        return (
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
        )

    @property
    def complete(self) -> bool:
        """Return whether the decision closed without unknown instruction effects."""
        return self.closed and self.failure_count == 0

    def to_dict(self) -> dict[str, int]:
        """Return the JSON-safe counter projection used by angr diagnostics."""
        return {
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
        }


@dataclass(frozen=True, slots=True)
class StatusFlagLivenessDecision8616:
    """Typed liveness outcome for one status-flag definition."""

    written: StatusFlag8616
    remaining: StatusFlag8616
    verdict: StatusFlagLivenessVerdict8616
    stats: StatusFlagLivenessStats8616

    @property
    def suppresses_write(self) -> bool:
        """Return whether frontend flag materialization may be omitted."""
        return self.verdict is StatusFlagLivenessVerdict8616.SUPPRESS_DEAD


__all__ = [
    "INCDEC_STATUS_FLAG_WRITES_8616",
    "LOGICAL_STATUS_FLAG_WRITES_8616",
    "SHIFT_COUNT_MANY_STATUS_FLAG_WRITES_8616",
    "SHIFT_COUNT_ONE_STATUS_FLAG_WRITES_8616",
    "STATUS_FLAGS_8616",
    "DecodedStatusFlagInstruction8616",
    "StatusFlag8616",
    "StatusFlagEffect8616",
    "StatusFlagLivenessDecision8616",
    "StatusFlagLivenessStats8616",
    "StatusFlagLivenessVerdict8616",
]
