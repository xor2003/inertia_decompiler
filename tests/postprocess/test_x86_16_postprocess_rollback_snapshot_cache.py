"""Tests for postprocess rollback snapshot reuse and invalidation."""

from __future__ import annotations

from inertia.postprocess.rollback_snapshot_cache import (
    PostprocessRollbackSnapshot8616,
    PostprocessRollbackSnapshotCache8616,
    PostprocessRollbackSnapshotController8616,
    RollbackSnapshotInvalidation8616,
)


def _snapshot(marker: object) -> PostprocessRollbackSnapshot8616:
    return PostprocessRollbackSnapshot8616(
        cfunc=marker,
        metadata={},
        text={},
        project_function=None,
        cycle_path=None,
    )


def test_reuses_snapshot_across_unchanged_passes() -> None:
    cache = PostprocessRollbackSnapshotCache8616()
    marker = object()
    factory_calls = 0

    def factory() -> PostprocessRollbackSnapshot8616:
        nonlocal factory_calls
        factory_calls += 1
        return _snapshot(marker)

    first = cache.acquire(factory)
    second = cache.acquire(factory)

    assert first is second
    assert factory_calls == 1
    stats = cache.stats()
    assert stats.request_count == 2
    assert stats.hit_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0
    assert stats.is_closed


def test_invalidation_rebuilds_snapshot_after_accepted_change() -> None:
    cache = PostprocessRollbackSnapshotCache8616()
    markers = iter((object(), object()))

    first = cache.acquire(lambda: _snapshot(next(markers)))
    assert cache.invalidate(RollbackSnapshotInvalidation8616.PASS_REPORTED_CHANGE)
    second = cache.acquire(lambda: _snapshot(next(markers)))

    assert first is not second
    stats = cache.stats()
    assert stats.materialized_count == 2
    assert stats.invalidation_count == 1
    assert stats.invalidation_reasons == ((RollbackSnapshotInvalidation8616.PASS_REPORTED_CHANGE, 1),)
    assert stats.is_closed


def test_restore_consumes_snapshot_once() -> None:
    cache = PostprocessRollbackSnapshotCache8616()
    snapshot = _snapshot(object())
    assert cache.acquire(lambda: snapshot) is snapshot

    assert cache.invalidate(RollbackSnapshotInvalidation8616.RESTORE_CONSUMED)
    assert not cache.invalidate(RollbackSnapshotInvalidation8616.RESTORE_CONSUMED)

    stats = cache.stats()
    assert stats.invalidation_count == 1
    assert stats.invalidation_reasons == ((RollbackSnapshotInvalidation8616.RESTORE_CONSUMED, 1),)
    assert stats.is_closed


def test_failed_factory_is_counted_and_retried() -> None:
    cache = PostprocessRollbackSnapshotCache8616()
    snapshot = _snapshot(object())

    assert cache.acquire(lambda: None) is None
    assert cache.acquire(lambda: snapshot) is snapshot

    stats = cache.stats()
    assert stats.request_count == 2
    assert stats.materialized_count == 1
    assert stats.failure_count == 1
    assert stats.is_closed


def test_controller_publishes_every_snapshot_request_and_invalidation() -> None:
    """The typed owner must keep dynamic codegen evidence coherent."""

    class _EvidenceOwner:
        pass

    owner = _EvidenceOwner()
    controller = PostprocessRollbackSnapshotController8616(owner)
    snapshot = _snapshot(object())

    assert controller.acquire(lambda: snapshot) is snapshot
    first_stats = owner._inertia_postprocess_rollback_snapshot_stats_8616
    assert first_stats.request_count == 1
    assert first_stats.materialized_count == 1
    assert first_stats.is_closed

    assert controller.invalidate(RollbackSnapshotInvalidation8616.PASS_REPORTED_CHANGE)
    final_stats = owner._inertia_postprocess_rollback_snapshot_stats_8616
    assert final_stats.invalidation_count == 1
    assert final_stats.invalidation_reasons == (
        (RollbackSnapshotInvalidation8616.PASS_REPORTED_CHANGE, 1),
    )
    assert final_stats.is_closed
