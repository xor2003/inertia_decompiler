"""Typed contracts for exact-byte condition-cache relifting.

Layer: IR.
Responsibility: describe immutable relift requests, evidence, failures, and
closed counters without performing lifting, caching, or Lowering work.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .condition_ir import ConditionIR, ConditionSource

__all__ = (
    "ConditionCacheReliftArtifact8616",
    "ConditionCacheReliftFailure8616",
    "ConditionCacheReliftFailureReason8616",
    "ConditionCacheReliftStats8616",
    "ConditionReliftBlock8616",
)


@dataclass(frozen=True, slots=True, order=True)
class ConditionReliftBlock8616:
    """One exact current-function block range to pass through the lifter."""

    address: int
    size: int


class ConditionCacheReliftFailureReason8616(StrEnum):
    """Typed reasons why an exact condition-cache relift did not close."""

    INVALID_BLOCK_RANGE = "invalid_block_range"
    BYTE_READ_FAILED = "byte_read_failed"
    VEX_LIFT_FAILED = "vex_lift_failed"
    EXPECTED_CONDITION_MISSING = "expected_condition_missing"
    CONDITION_RECOVERY_FAILED = "condition_recovery_failed"


@dataclass(frozen=True, slots=True)
class ConditionCacheReliftFailure8616:
    """One exact block-level condition-cache relift refusal."""

    block_addr: int
    reason: ConditionCacheReliftFailureReason8616
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ConditionCacheReliftStats8616:
    """Closed evidence counters for expected conditional block owners."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def complete(self) -> bool:
        """Return whether every expected owner produced typed evidence."""
        return bool(
            self.raw_fact_count == self.normalized_fact_count
            and self.normalized_fact_count == self.classified_fact_count
            and self.classified_fact_count == self.materialized_count
            and self.failure_count == 0
        )


@dataclass(frozen=True, slots=True)
class ConditionCacheReliftArtifact8616:
    """Isolated typed condition and pending-source evidence from one relift."""

    conditions_by_block: tuple[tuple[int, tuple[ConditionIR, ...]], ...]
    pending_sources_by_addr: tuple[tuple[int, ConditionSource], ...]
    failures: tuple[ConditionCacheReliftFailure8616, ...]
    stats: ConditionCacheReliftStats8616

    def condition_cache(self) -> dict[int, list[ConditionIR]]:
        """Return a mutable cache projection for the existing transfer consumer."""
        return {address: list(conditions) for address, conditions in self.conditions_by_block}

    def pending_source_cache(self) -> dict[int, ConditionSource]:
        """Return a mutable pending-source projection for edge collection."""
        return dict(self.pending_sources_by_addr)
