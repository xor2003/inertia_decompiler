"""Parallel batch result collection must never silently drop requested jobs."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from test_batch_decompile_scheduler import batch, scheduler

if TYPE_CHECKING:
    from scripts.batch_decompile_procs import BatchProcResult
    from scripts.batch_decompile_scheduler import JobEnd, ScheduledJob


@pytest.mark.parametrize(
    ("missing_callback", "expected_error"), [(False, TypeError), (True, RuntimeError)],
)
def test_parallel_batch_refuses_unmaterialized_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    missing_callback: bool, expected_error: type[Exception],
) -> None:
    """A missing/invalid completion is a failed contract, not an empty success."""
    assert scheduler is not None
    args = batch._parse_args([
        "input.exe", "--out-dir", str(tmp_path), "--proc", "one", "--workers", "2",
    ])
    job = batch._proc_job(args, "one")

    def broken_dispatch(
        jobs: Sequence[ScheduledJob[BatchProcResult]], *, workers: int,
        on_end: Callable[[int, JobEnd[BatchProcResult]], None],
    ) -> None:
        if not missing_callback:
            on_end(0, scheduler.JobEnd(
                index=0, kind=scheduler.JobEndKind.COMPLETED, wall_seconds=0.0,
            ))

    monkeypatch.setattr(scheduler, "run_jobs_bounded", broken_dispatch)
    with pytest.raises(expected_error):
        batch._run_jobs_parallel(args, [job], workers=2)
