"""Execute bounded waves of pre-partitioned pytest workers.

Layer: Tooling/gates.
Responsibility: launch, monitor, and terminate independent pytest process
groups while preserving structured reports and an aggregate RSS limit.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from collections.abc import Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from tools.dev.process_metrics import process_tree_pids, process_trees_rss_kib
from tools.dev.pytest_worker_contract import WorkerSpec as WorkerSpec

from .pytest_partition_plugin import (
    SHARD_ACTIVITY_ENV,
    SHARD_COUNT_ENV,
    SHARD_INDEX_ENV,
    SHARD_REPORT_ENV,
    SHARD_WEIGHTS_ENV,
    WorkerActivity,
    WorkerReport,
)


@dataclass(frozen=True, slots=True)
class WorkerProcess:
    """Controller-owned pytest process and its structured report path."""

    name: str
    process: subprocess.Popen[str]
    report_path: Path
    activity_path: Path


@dataclass(frozen=True, slots=True)
class WaveResult:
    """Outputs and resource facts collected from one concurrent worker wave."""

    outputs: dict[str, str]
    reports: tuple[WorkerReport, ...]
    exit_codes: dict[str, int]
    active_nodeids: dict[str, str]
    peak_rss_kib: int
    worker_peak_rss_kib: dict[str, int]
    memory_exceeded: bool


def _worker_command(spec: WorkerSpec, cache_dir: Path, base_temp: Path, durations: int) -> list[str]:
    """Build one serial pytest command over explicit test paths."""

    return [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        f"--durations={durations}",
        "-p",
        "tools.dev.pytest_partition_plugin",
        "-o",
        f"cache_dir={cache_dir}",
        f"--basetemp={base_temp}",
        *spec.paths,
    ]


def _worker_environment(
    spec: WorkerSpec,
    report_path: Path,
    activity_path: Path,
    weights_path: Path,
) -> dict[str, str]:
    """Build one isolated process environment with its exact node shard."""
    env = os.environ.copy()
    env.pop("PYTEST_XDIST_WORKER", None)
    env["PYTEST_ADDOPTS"] = ""
    env[SHARD_COUNT_ENV] = str(spec.shard_count)
    env[SHARD_ACTIVITY_ENV] = str(activity_path)
    env[SHARD_INDEX_ENV] = str(spec.shard_index)
    env[SHARD_REPORT_ENV] = str(report_path)
    env[SHARD_WEIGHTS_ENV] = str(weights_path)
    return env


def start_pytest_worker(
    spec: WorkerSpec,
    *,
    repo_root: Path,
    run_root: Path,
    weights_path: Path,
    durations: int,
) -> WorkerProcess:
    """Start one isolated pytest worker process."""

    report_path = run_root / f"{spec.name}.json"
    activity_path = run_root / f"{spec.name}.active.json"
    process = subprocess.Popen(
        _worker_command(
            spec,
            run_root / f"{spec.name}-cache",
            run_root / f"{spec.name}-tmp",
            durations,
        ),
        cwd=repo_root,
        env=_worker_environment(spec, report_path, activity_path, weights_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    return WorkerProcess(spec.name, process, report_path, activity_path)


def terminate_worker_processes(workers: Sequence[WorkerProcess]) -> None:
    """Terminate every worker and detached descendant after a resource failure."""

    root_pids = tuple(worker.process.pid for worker in workers)
    tree_pids = process_tree_pids(root_pids) or root_pids
    for worker in workers:
        if worker.process.poll() is None:
            try:
                os.killpg(worker.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                continue
    for pid in reversed(tree_pids):
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            continue
    time.sleep(0.5)
    for pid in reversed(tree_pids):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            continue
    for worker in workers:
        try:
            os.killpg(worker.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            continue


def run_pytest_wave(
    specs: Sequence[WorkerSpec],
    *,
    repo_root: Path,
    run_root: Path,
    weights_path: Path,
    durations: int,
    max_rss_kib: int,
) -> WaveResult:
    """Run one bounded wave and return only structured process facts."""

    workers = [
        start_pytest_worker(
            spec,
            repo_root=repo_root,
            run_root=run_root,
            weights_path=weights_path,
            durations=durations,
        )
        for spec in specs
    ]
    peak_rss_kib = 0
    worker_peak_rss_kib = {worker.name: 0 for worker in workers}
    memory_exceeded = False
    outputs: dict[str, str] = {}
    exit_codes: dict[str, int] = {}
    with ThreadPoolExecutor(max_workers=len(workers)) as executor:
        futures: dict[Future[tuple[str, str | None]], WorkerProcess] = {
            executor.submit(worker.process.communicate): worker for worker in workers
        }
        try:
            while not all(future.done() for future in futures):
                roots = (os.getpid(), *(worker.process.pid for worker in workers))
                rss_by_root = process_trees_rss_kib(roots)
                if rss_by_root is not None:
                    aggregate_rss_kib = rss_by_root.get(os.getpid(), 0)
                    peak_rss_kib = max(peak_rss_kib, aggregate_rss_kib)
                    for worker in workers:
                        worker_peak_rss_kib[worker.name] = max(
                            worker_peak_rss_kib[worker.name],
                            rss_by_root.get(worker.process.pid, 0),
                        )
                    if aggregate_rss_kib > max_rss_kib:
                        memory_exceeded = True
                        terminate_worker_processes(workers)
                        break
                time.sleep(0.2)
        except KeyboardInterrupt:
            terminate_worker_processes(workers)
            raise
        for future, worker in futures.items():
            stdout, _stderr = future.result()
            outputs[worker.name] = stdout
            exit_codes[worker.name] = worker.process.returncode
    reports = tuple(
        WorkerReport.from_path(worker.report_path) for worker in workers if worker.report_path.exists()
    )
    active_nodeids = {
        worker.name: WorkerActivity.from_path(worker.activity_path).nodeid
        for worker in workers
        if worker.activity_path.exists()
    }
    return WaveResult(
        outputs=outputs,
        reports=reports,
        exit_codes=exit_codes,
        active_nodeids=active_nodeids,
        peak_rss_kib=peak_rss_kib,
        worker_peak_rss_kib=worker_peak_rss_kib,
        memory_exceeded=memory_exceeded,
    )
