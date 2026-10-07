"""Cache validation rollback snapshots across unchanged rewrite passes.

Layer: Rewrite/Postprocess cleanup.
Responsibility: retain one rollback snapshot while the accepted C-AST state is
unchanged and expose closed-loop cache evidence.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.

This module owns orchestration state only. It does not inspect or recover
semantics. The postprocess stage must invalidate the cache whenever a pass
changes state, a mutation is detected, or a snapshot is consumed by restore.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, cast

from inertia.pipeline.errors import PipelineHardError

__all__ = [
    "PostprocessRollbackSnapshot8616",
    "PostprocessRollbackSnapshotCache8616",
    "PostprocessRollbackSnapshotController8616",
    "PostprocessRollbackSnapshotStats8616",
    "RollbackSnapshotInvalidation8616",
]


class RollbackSnapshotInvalidation8616(Enum):
    """Reasons an accepted-state rollback snapshot can no longer be reused."""

    PREPASS_REPAIR = "prepass-repair"
    PASS_REPORTED_CHANGE = "pass-reported-change"
    PASS_MUTATION_DETECTED = "pass-mutation-detected"
    PASS_EXCEPTION = "pass-exception"
    RESTORE_CONSUMED = "restore-consumed"


@dataclass(frozen=True, slots=True)
class PostprocessRollbackSnapshot8616:
    """Rollback projections captured from one accepted postprocess state."""

    cfunc: object
    metadata: dict[str, object]
    text: dict[str, object]
    project_function: object
    cycle_path: tuple[str, ...] | None


@dataclass(frozen=True, slots=True)
class PostprocessRollbackSnapshotStats8616:
    """Closed-loop evidence for rollback snapshot requests."""

    request_count: int
    hit_count: int
    materialized_count: int
    failure_count: int
    invalidation_count: int
    invalidation_reasons: tuple[tuple[RollbackSnapshotInvalidation8616, int], ...]

    @property
    def is_closed(self) -> bool:
        """Return whether every request has exactly one recorded outcome."""
        return self.request_count == self.hit_count + self.materialized_count + self.failure_count


@dataclass(slots=True)
class PostprocessRollbackSnapshotCache8616:
    """Reuse a rollback snapshot until the accepted postprocess state changes."""

    _snapshot: PostprocessRollbackSnapshot8616 | None = None
    _request_count: int = 0
    _hit_count: int = 0
    _materialized_count: int = 0
    _failure_count: int = 0
    _invalidation_count: int = 0
    _invalidation_reasons: dict[RollbackSnapshotInvalidation8616, int] = field(default_factory=dict)

    def acquire(
        self,
        factory: Callable[[], PostprocessRollbackSnapshot8616 | None],
    ) -> PostprocessRollbackSnapshot8616 | None:
        """Return the current snapshot, materializing it once when absent."""
        self._request_count += 1
        if self._snapshot is not None:
            self._hit_count += 1
            return self._snapshot
        snapshot = factory()
        if snapshot is None:
            self._failure_count += 1
            return None
        self._snapshot = snapshot
        self._materialized_count += 1
        return snapshot

    def invalidate(self, reason: RollbackSnapshotInvalidation8616) -> bool:
        """Discard a cached snapshot and record why it became stale."""
        if self._snapshot is None:
            return False
        self._snapshot = None
        self._invalidation_count += 1
        self._invalidation_reasons[reason] = self._invalidation_reasons.get(reason, 0) + 1
        return True

    def stats(self) -> PostprocessRollbackSnapshotStats8616:
        """Return an immutable, deterministically ordered evidence snapshot."""
        reasons = tuple(sorted(self._invalidation_reasons.items(), key=lambda item: item[0].value))
        return PostprocessRollbackSnapshotStats8616(
            request_count=self._request_count,
            hit_count=self._hit_count,
            materialized_count=self._materialized_count,
            failure_count=self._failure_count,
            invalidation_count=self._invalidation_count,
            invalidation_reasons=reasons,
        )


class _RollbackEvidenceBoundary8616(Protocol):
    """Dynamic codegen boundary that publishes rollback-cache accounting."""

    _inertia_postprocess_rollback_snapshot_stats_8616: PostprocessRollbackSnapshotStats8616


@dataclass(slots=True)
class PostprocessRollbackSnapshotController8616:
    """Own cache mutation and closed evidence publication for one rewrite run."""

    evidence_owner: object
    cache: PostprocessRollbackSnapshotCache8616 = field(
        default_factory=PostprocessRollbackSnapshotCache8616,
    )

    def _publish(self) -> PostprocessRollbackSnapshotStats8616:
        """Publish and return closed cache accounting."""
        stats = self.cache.stats()
        if not stats.is_closed:
            raise PipelineHardError(
                "postprocess rollback snapshot cache evidence is not closed",
                layer="rewrite/postprocess:rollback_snapshot_cache",
            )
        cast(
            _RollbackEvidenceBoundary8616,
            self.evidence_owner,
        )._inertia_postprocess_rollback_snapshot_stats_8616 = stats
        return stats

    def acquire(
        self,
        factory: Callable[[], PostprocessRollbackSnapshot8616 | None],
    ) -> PostprocessRollbackSnapshot8616 | None:
        """Acquire one rollback snapshot and publish its request outcome."""
        snapshot = self.cache.acquire(factory)
        self._publish()
        return snapshot

    def invalidate(self, reason: RollbackSnapshotInvalidation8616) -> bool:
        """Invalidate accepted state and publish deterministic accounting."""
        invalidated = self.cache.invalidate(reason)
        self._publish()
        return invalidated

    def stats(self) -> PostprocessRollbackSnapshotStats8616:
        """Return and publish current closed cache accounting."""
        return self._publish()
