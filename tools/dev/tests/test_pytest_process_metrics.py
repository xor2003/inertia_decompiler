"""Regression tests for one-snapshot pytest worker process metrics."""

from __future__ import annotations

from pytest import MonkeyPatch

from tools.dev import process_metrics as metrics


def test_process_trees_rss_kib_attributes_descendants_per_root(monkeypatch: MonkeyPatch) -> None:
    """Measure concurrent worker trees independently without repeated procfs scans."""

    statuses = {
        10: metrics._ProcessStatus(parent_pid=1, rss_kib=100),
        11: metrics._ProcessStatus(parent_pid=10, rss_kib=30),
        12: metrics._ProcessStatus(parent_pid=11, rss_kib=20),
        20: metrics._ProcessStatus(parent_pid=1, rss_kib=200),
        21: metrics._ProcessStatus(parent_pid=20, rss_kib=40),
    }
    monkeypatch.setattr(metrics, "_process_statuses", lambda: statuses)

    assert metrics.process_trees_rss_kib((10, 20)) == {10: 150, 20: 240}


def test_process_trees_rss_kib_handles_empty_and_unavailable_snapshots(
    monkeypatch: MonkeyPatch,
) -> None:
    """Preserve explicit empty and unsupported metric states."""

    assert metrics.process_trees_rss_kib(()) == {}
    monkeypatch.setattr(metrics, "_process_statuses", lambda: None)
    assert metrics.process_trees_rss_kib((10,)) is None
