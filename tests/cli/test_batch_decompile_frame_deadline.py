"""Complete-frame children must still exit before their scheduler deadline."""

from __future__ import annotations

import contextlib
import os
import signal
import time
from collections.abc import Iterator
from pathlib import Path
from types import FrameType
from typing import TYPE_CHECKING

import pytest
from tests.cli.test_batch_decompile_scheduler import (
    _assert_dead,
    _assert_descendant_dead,
    scheduler,
)

import inertia.cli.fork_timeout as fork_timeout

if TYPE_CHECKING:
    from tools.dev.batch_decompile_scheduler import JobEnd


class _ReapGuardExpired(RuntimeError):
    """A broken scheduler exceeded the regression's outer safety budget."""


@contextlib.contextmanager
def _bounded_reap_guard() -> Iterator[None]:
    """Fail a red regression loudly while still letting scheduler cleanup run."""
    def expire(signum: int, frame: FrameType | None) -> None:
        raise _ReapGuardExpired("complete-frame child bypassed its job deadline")

    previous_handler = signal.signal(signal.SIGALRM, expire)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, 5.0)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        signal.setitimer(signal.ITIMER_REAL, *previous_timer)


@pytest.mark.parametrize("with_descendant", [False, True])
def test_complete_frame_nonexiting_child_keeps_deadline_and_sibling_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, with_descendant: bool,
) -> None:
    """A valid frame neither authorizes success nor blocks a finished sibling."""
    assert scheduler is not None
    pid_file = tmp_path / "stopped.pid"
    descendant_file = tmp_path / "descendant.pid"
    original_write = fork_timeout._write_result

    def stop_after_frame(fd: int, result: fork_timeout._ForkResult) -> None:
        original_write(fd, result)
        if result.kind is fork_timeout._ForkResultKind.OK and result.value == "stopped":
            pid_file.write_text(str(os.getpid()), encoding="utf-8")
            os.kill(os.getpid(), signal.SIGSTOP)

    def stopped_work() -> str:
        if with_descendant:
            descendant = os.fork()
            if descendant == 0:
                time.sleep(30)
                os._exit(0)
            descendant_file.write_text(str(descendant), encoding="utf-8")
        return "stopped"

    monkeypatch.setattr(fork_timeout, "_write_result", stop_after_frame)
    outcomes: list[tuple[int, JobEnd[str], float]] = []
    started = time.monotonic()
    try:
        with _bounded_reap_guard():
            scheduler.run_jobs_bounded(
                [
                    scheduler.ScheduledJob("stopped", stopped_work, timeout=2),
                    scheduler.ScheduledJob("fast", lambda: "fast", timeout=3),
                ],
                workers=2,
                on_end=lambda index, end: outcomes.append((index, end, time.monotonic() - started)),
            )
    finally:
        _assert_dead(pid_file)
        if with_descendant:
            _assert_descendant_dead(descendant_file)
    assert [index for index, _end, _seconds in outcomes] == [1, 0]
    fast, stopped = outcomes
    assert fast[1].kind is scheduler.JobEndKind.COMPLETED
    assert fast[1].value == "fast"
    assert fast[2] < 1.5, "sibling was delayed by the stalled child reap"
    assert stopped[1].kind is scheduler.JobEndKind.TIMED_OUT
    assert stopped[1].value is None
    assert 1.8 <= stopped[2] < 4.0
