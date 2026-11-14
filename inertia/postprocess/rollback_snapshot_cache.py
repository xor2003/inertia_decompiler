# cython: language_level=3, infer_types=True
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
import typing
import cython

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, cast

from inertia.pipeline.errors import PipelineHardError
import dataclasses
import operator

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


@dataclasses.dataclass(frozen=True, )
class PostprocessRollbackSnapshot8616:
    """Rollback projections captured from one accepted postprocess state."""

    cfunc: object
    metadata: object
    text: object
    project_function: object
    cycle_path: object


@dataclasses.dataclass(frozen=True, )
class PostprocessRollbackSnapshotStats8616:
    """Closed-loop evidence for rollback snapshot requests."""

    request_count: cython.longlong
    hit_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong
    invalidation_count: cython.longlong
    invalidation_reasons: object

    @property
    def is_closed(self) -> cython.bint:
        """Return whether every request has exactly one recorded outcome."""
        return operator.eq(self.request_count, self.hit_count + self.materialized_count + self.failure_count)


@cython.dataclasses.dataclass()
class PostprocessRollbackSnapshotCache8616:
    """Reuse a rollback snapshot until the accepted postprocess state changes."""

    _snapshot: PostprocessRollbackSnapshot8616 | None = None
    _request_count: cython.longlong = 0
    _hit_count: cython.longlong = 0
    _materialized_count: cython.longlong = 0
    _failure_count: cython.longlong = 0
    _invalidation_count: cython.longlong = 0
    _invalidation_reasons: object = field(default_factory=dict)

    @cython.ccall
    def acquire(
        self,
        factory: Callable[[], PostprocessRollbackSnapshot8616 | None],
    ) -> PostprocessRollbackSnapshot8616 | None:
        """Return the current snapshot, materializing it once when absent."""
        snapshot: object
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

    @cython.ccall
    def invalidate(self, reason: RollbackSnapshotInvalidation8616) -> cython.bint:
        """Discard a cached snapshot and record why it became stale."""
        if self._snapshot is None:
            return False
        self._snapshot = None
        self._invalidation_count += 1
        self._invalidation_reasons[reason] = self._invalidation_reasons.get(reason, 0) + 1
        return True

    def stats(self) -> PostprocessRollbackSnapshotStats8616:
        """Return an immutable, deterministically ordered evidence snapshot."""
        reasons = tuple(sorted(tuple(self._invalidation_reasons.items()), key=lambda item: item[0].value))
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


@cython.dataclasses.dataclass()
class PostprocessRollbackSnapshotController8616:
    """Own cache mutation and closed evidence publication for one rewrite run."""

    evidence_owner: object
    cache: PostprocessRollbackSnapshotCache8616 = field(
        default_factory=PostprocessRollbackSnapshotCache8616,
    )

    @cython.ccall
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

    @cython.ccall
    def acquire(
        self,
        factory: Callable[[], PostprocessRollbackSnapshot8616 | None],
    ) -> PostprocessRollbackSnapshot8616 | None:
        """Acquire one rollback snapshot and publish its request outcome."""
        snapshot = self.cache.acquire(factory)
        self._publish()
        return snapshot

    @cython.ccall
    def invalidate(self, reason: RollbackSnapshotInvalidation8616) -> cython.bint:
        """Invalidate accepted state and publish deterministic accounting."""
        invalidated = self.cache.invalidate(reason)
        self._publish()
        return invalidated

    @cython.ccall
    def stats(self) -> PostprocessRollbackSnapshotStats8616:
        """Return and publish current closed cache accounting."""
        return self._publish()
