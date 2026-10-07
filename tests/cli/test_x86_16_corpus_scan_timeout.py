from __future__ import annotations

import inspect
import signal

import pytest
import inertia.cli.corpus_scan as corpus_scan


def test_scan_alarm_defers_async_timeout_inside_finalizer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    retries: list[tuple[int, float]] = []

    def record_retry(timer: int, seconds: float) -> tuple[float, float]:
        retries.append((timer, seconds))
        return (0.0, 0.0)

    def __del__() -> None:
        frame = inspect.currentframe()
        assert frame is not None
        corpus_scan._alarm_handler(signal.SIGALRM, frame)

    monkeypatch.setattr(corpus_scan, "_SCAN_ACTIVE", True)
    monkeypatch.setattr(corpus_scan.signal, "setitimer", record_retry)

    __del__()

    assert corpus_scan._SCAN_ACTIVE is True
    assert retries == [
        (
            signal.ITIMER_REAL,
            corpus_scan._SCAN_TIMEOUT_FINALIZER_RETRY_SECONDS,
        )
    ]


def test_scan_alarm_raises_and_clears_outside_finalizer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alarm_clears: list[bool] = []
    frame = inspect.currentframe()
    assert frame is not None
    monkeypatch.setattr(corpus_scan, "_SCAN_ACTIVE", True)
    monkeypatch.setattr(corpus_scan, "_clear_alarm", lambda: alarm_clears.append(True))

    with pytest.raises(corpus_scan.ScanTimeout, match="timed out"):
        corpus_scan._alarm_handler(signal.SIGALRM, frame)

    assert corpus_scan._SCAN_ACTIVE is False
    assert alarm_clears == [True]
