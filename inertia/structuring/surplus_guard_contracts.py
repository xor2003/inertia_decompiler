"""Durable evidence for removing surplus structured branch shells.

Layer: Structuring.
Responsibility: preserve the decoded branch-budget proof and closed candidate
census after a cleanup pass removes C ``if`` nodes that have no machine Jcc.
Rewrite and validation may consume this artifact but must not create it.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SurplusGuardCleanupStats8616:
    """Closed evidence accounting for one surplus-guard cleanup."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every candidate was removed or explicitly retained."""
        return (
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count + self.failure_count
        )


@dataclass(frozen=True, slots=True)
class SurplusGuardCleanupEvidence8616:
    """Binary branch budget and exact kinds removed by Structuring."""

    branch_count: int
    total_if_count: int
    noop_materialized_count: int
    empty_return_materialized_count: int
    identical_arms_materialized_count: int
    stats: SurplusGuardCleanupStats8616

    @property
    def complete(self) -> bool:
        """Return whether the budget and materialized-kind census agree."""
        return (
            self.stats.complete
            and self.branch_count >= 0
            and self.total_if_count >= self.branch_count
            and self.total_if_count - self.branch_count
            >= self.stats.materialized_count
            and self.stats.materialized_count
            == self.noop_materialized_count
            + self.empty_return_materialized_count
            + self.identical_arms_materialized_count
        )


__all__ = [
    "SurplusGuardCleanupEvidence8616",
    "SurplusGuardCleanupStats8616",
]
