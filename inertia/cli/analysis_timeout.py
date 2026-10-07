"""Provide finalizer-safe process-alarm timeouts for bounded analysis.

Layer: CLI/fallback/reporting.
Responsibility: turn process alarms into typed analysis timeouts without raising unraisable exceptions in finalizers.
"""

from __future__ import annotations

import contextlib
import signal
import threading
from collections.abc import Iterator
from types import FrameType

_FINALIZER_RETRY_SECONDS: float = 0.01


class AnalysisTimeout(BaseException):
    """Signal expiration of a bounded in-process analysis scope."""


def raise_timeout(_signum: int, frame: FrameType | None) -> None:
    """Raise a timeout outside finalizers, deferring briefly when necessary."""
    if frame is not None and frame.f_code.co_name == "__del__":
        signal.setitimer(signal.ITIMER_REAL, _FINALIZER_RETRY_SECONDS)
        return
    raise AnalysisTimeout


@contextlib.contextmanager
def analysis_timeout(timeout: int) -> Iterator[None]:
    """Bound an analysis scope with a main-thread process alarm."""
    if timeout <= 0 or threading.current_thread() is not threading.main_thread():
        yield
        return
    old_handler = signal.signal(signal.SIGALRM, raise_timeout)
    signal.alarm(timeout)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)
