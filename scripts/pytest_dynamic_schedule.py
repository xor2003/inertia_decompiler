"""Backfill measured pytest jobs under exact CPU and RSS reservations.

Layer: Tooling/gates.
Responsibility: keep independently measured pytest workers busy without wave
barriers while enforcing conservative reservations and a live aggregate limit.
"""

from __future__ import annotations

import os
import time
from collections.abc import Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

if __package__:
    from .pytest_partition_execution import (
        WaveResult,
        WorkerProcess,
        WorkerSpec,
        start_pytest_worker,
        terminate_worker_processes,
    )
    from .pytest_partition_plugin import WorkerActivity, WorkerReport
    from .pytest_process_metrics import process_trees_rss_kib
else:
    from pytest_partition_execution import (
        WaveResult,
        WorkerProcess,
        WorkerSpec,
        start_pytest_worker,
        terminate_worker_processes,
    )
    from pytest_partition_plugin import WorkerActivity, WorkerReport
    from pytest_process_metrics import process_trees_rss_kib


@dataclass(frozen=True, slots=True)
class ScheduledWorkerSpec:
    """One worker plus its conservative admission-control reservation."""

    spec: WorkerSpec
    reserved_rss_kib: int


@dataclass(slots=True)
class _WaveScheduler8616:
    """Mutable admission-control state for one scheduled pytest wave."""

    pending: list[ScheduledWorkerSpec]
    max_workers: int
    reservation_limit_kib: int
    max_rss_kib: int
    executor: ThreadPoolExecutor
    repo_root: Path
    run_root: Path
    weights_path: Path
    durations: int
    workers: list[WorkerProcess] = field(default_factory=list)
    active: dict[Future[tuple[str, str | None]], tuple[WorkerProcess, int]] = field(
        default_factory=dict
    )
    outputs: dict[str, str] = field(default_factory=dict)
    exit_codes: dict[str, int] = field(default_factory=dict)
    worker_peak_rss_kib: dict[str, int] = field(default_factory=dict)
    peak_rss_kib: int = 0
    memory_exceeded: bool = False

    def launch_available(self) -> None:
        """Fill free CPU and reservation capacity without queue blocking."""
        while self.pending and len(self.active) < self.max_workers:
            reserved = sum(reservation for _worker, reservation in self.active.values())
            available = self.reservation_limit_kib - reserved
            selected = next(
                (
                    index
                    for index, item in enumerate(self.pending)
                    if item.reserved_rss_kib <= available
                ),
                None,
            )
            if selected is None:
                if self.active:
                    return
                selected = 0
            item = self.pending.pop(selected)
            worker = start_pytest_worker(
                item.spec,
                repo_root=self.repo_root,
                run_root=self.run_root,
                weights_path=self.weights_path,
                durations=self.durations,
            )
            self.workers.append(worker)
            self.worker_peak_rss_kib[worker.name] = 0
            self.active[self.executor.submit(worker.process.communicate)] = (
                worker,
                item.reserved_rss_kib,
            )

    def poll_active(self) -> bool:
        """Sample live RSS, collect finished workers, and enforce the limit."""
        roots = (os.getpid(), *(worker.process.pid for worker, _rss in self.active.values()))
        rss_by_root = process_trees_rss_kib(roots)
        if rss_by_root is not None:
            aggregate_rss_kib = rss_by_root.get(os.getpid(), 0)
            self.peak_rss_kib = max(self.peak_rss_kib, aggregate_rss_kib)
            for worker, _reservation in self.active.values():
                self.worker_peak_rss_kib[worker.name] = max(
                    self.worker_peak_rss_kib[worker.name],
                    rss_by_root.get(worker.process.pid, 0),
                )
            if aggregate_rss_kib > self.max_rss_kib:
                self.memory_exceeded = True
                terminate_worker_processes([worker for worker, _rss in self.active.values()])
        completed = [future for future in self.active if future.done()]
        for future in completed:
            worker, _reservation = self.active.pop(future)
            stdout, _stderr = future.result()
            self.outputs[worker.name] = stdout
            self.exit_codes[worker.name] = worker.process.returncode
        return bool(completed)

    def drain_active(self) -> None:
        """Collect remaining active workers after the main loop exits."""
        for future, (worker, _reservation) in self.active.items():
            stdout, _stderr = future.result()
            self.outputs[worker.name] = stdout
            self.exit_codes[worker.name] = worker.process.returncode

    def terminate_active(self) -> None:
        """Terminate every live worker process."""
        terminate_worker_processes([worker for worker, _rss in self.active.values()])


def run_pytest_schedule(
    scheduled_specs: Sequence[ScheduledWorkerSpec],
    *,
    repo_root: Path,
    run_root: Path,
    weights_path: Path,
    durations: int,
    max_workers: int,
    reservation_limit_kib: int,
    max_rss_kib: int,
) -> WaveResult:
    """Backfill measured workers while enforcing reservations and live RSS."""

    if max_workers < 1 or reservation_limit_kib < 1 or max_rss_kib < 1:
        raise ValueError("schedule limits must be positive")
    if any(item.reserved_rss_kib < 1 for item in scheduled_specs):
        raise ValueError("worker reservations must be positive")
    names = [item.spec.name for item in scheduled_specs]
    if len(names) != len(set(names)):
        raise ValueError("scheduled worker names must be unique")
    if not scheduled_specs:
        return WaveResult({}, (), {}, {}, 0, {}, False)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        sched = _WaveScheduler8616(
            pending=list(scheduled_specs),
            max_workers=max_workers,
            reservation_limit_kib=reservation_limit_kib,
            max_rss_kib=max_rss_kib,
            executor=executor,
            repo_root=repo_root,
            run_root=run_root,
            weights_path=weights_path,
            durations=durations,
        )
        try:
            sched.launch_available()
            while sched.active:
                had_completions = sched.poll_active()
                if sched.memory_exceeded:
                    break
                sched.launch_available()
                if sched.active and not had_completions:
                    time.sleep(0.2)
        except KeyboardInterrupt:
            sched.terminate_active()
            raise
        sched.drain_active()

    reports = tuple(
        WorkerReport.from_path(worker.report_path) for worker in sched.workers if worker.report_path.exists()
    )
    active_nodeids = {
        worker.name: WorkerActivity.from_path(worker.activity_path).nodeid
        for worker in sched.workers
        if worker.activity_path.exists()
    }
    return WaveResult(
        outputs=sched.outputs,
        reports=reports,
        exit_codes=sched.exit_codes,
        active_nodeids=active_nodeids,
        peak_rss_kib=sched.peak_rss_kib,
        worker_peak_rss_kib=sched.worker_peak_rss_kib,
        memory_exceeded=sched.memory_exceeded,
    )
