"""Classify VEX temporaries that require eager Condition materialization.

Layer: IR.
Responsibility: identify direct conditional-exit temporary owners before VEX
statements are imported. This is scheduling evidence only; it does not infer,
rewrite, or simplify branch semantics.

Owns typed Value, Address, Condition, instruction facts, and lossless
normalization. Do not perform alias-state ownership, widening,
lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, SupportsInt, cast


class _VexStatementBoundary8616(Protocol):
    """Third-party VEX statement fields consumed by demand collection."""

    tag: object
    guard: object


class _VexExpressionBoundary8616(Protocol):
    """Third-party VEX expression fields consumed by demand collection."""

    tag: object
    tmp: object


@dataclass(frozen=True, slots=True)
class VexConditionDemandStats8616:
    """Closed accounting for direct temporary exit-guard candidates."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def closed(self) -> bool:
        """Return whether every candidate became typed demand or refusal."""
        return bool(
            self.raw_fact_count == self.materialized_count + self.failure_count
            and self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
        )


@dataclass(frozen=True, slots=True)
class VexConditionDemand8616:
    """Exact temporary IDs whose definitions feed a conditional exit."""

    eager_tmp_ids: frozenset[int]
    stats: VexConditionDemandStats8616

    @property
    def complete(self) -> bool:
        """Return whether demand collection can safely suppress other work."""
        return bool(
            self.stats.closed
            and self.stats.failure_count == 0
            and all(tmp_id >= 0 for tmp_id in self.eager_tmp_ids)
        )

    def requires_eager_condition(self, tmp_id: int) -> bool:
        """Keep legacy eager behavior when collection is incomplete."""
        return not self.complete or tmp_id in self.eager_tmp_ids


def _boundary_tag_8616(value: object) -> str:
    """Read one dynamic VEX tag at the third-party boundary."""
    try:
        tag = cast(_VexExpressionBoundary8616, value).tag
    except AttributeError:
        return ""
    return tag if isinstance(tag, str) else ""


def _direct_guard_tmp_8616(statement: object) -> tuple[bool, int | None]:
    """Return whether an Exit guard is a direct temporary and its ID."""
    try:
        guard = cast(_VexStatementBoundary8616, statement).guard
    except AttributeError:
        return False, None
    if _boundary_tag_8616(guard) != "Iex_RdTmp":
        return False, None
    try:
        raw_tmp = cast(_VexExpressionBoundary8616, guard).tmp
    except AttributeError:
        return True, None
    if isinstance(raw_tmp, bool):
        return True, None
    try:
        tmp_id = int(cast(SupportsInt, raw_tmp))
    except (TypeError, ValueError):
        return True, None
    return True, tmp_id if tmp_id >= 0 else None


def collect_vex_condition_demand_8616(
    statements: Sequence[object],
) -> VexConditionDemand8616:
    """Collect direct RdTmp exit guards before importing their definitions."""
    raw_fact_count = 0
    materialized_count = 0
    failure_count = 0
    eager_tmp_ids: set[int] = set()
    for statement in statements:
        if _boundary_tag_8616(statement) != "Ist_Exit":
            continue
        is_direct_tmp, tmp_id = _direct_guard_tmp_8616(statement)
        if not is_direct_tmp:
            continue
        raw_fact_count += 1
        if tmp_id is None:
            failure_count += 1
            continue
        materialized_count += 1
        eager_tmp_ids.add(tmp_id)
    stats = VexConditionDemandStats8616(
        raw_fact_count=raw_fact_count,
        normalized_fact_count=materialized_count,
        classified_fact_count=materialized_count,
        materialized_count=materialized_count,
        failure_count=failure_count,
    )
    return VexConditionDemand8616(frozenset(eager_tmp_ids), stats)


__all__ = [
    "VexConditionDemand8616",
    "VexConditionDemandStats8616",
    "collect_vex_condition_demand_8616",
]
