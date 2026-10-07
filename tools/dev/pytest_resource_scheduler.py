"""Build memory-bounded pytest worker waves from measured process facts.

Layer: Tooling/gates.
Responsibility: preserve deterministic test partitioning while using only exact,
accepted worker contracts to raise heavy-test concurrency above the conservative
unknown-work limit.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from tools.dev.pytest_resource_history import (
    DEFAULT_CONTROLLER_RESERVE_KIB,
    DEFAULT_WORKER_HEADROOM_PERCENT,
    WorkerResourceContract,
    WorkerResourceHistory,
    worker_contract_sort_key,
)
from tools.dev.pytest_worker_contract import WorkerSpec

MAX_PATHS_PER_WORKER: Final[int] = 32


@dataclass(frozen=True, slots=True)
class HeavyWorkerJobs:
    """Parallelizable jobs and paths that require exclusive process waves."""

    parallel: tuple[tuple[WorkerSpec, ...], ...]
    exclusive: tuple[tuple[WorkerSpec, ...], ...]


def partition_paths(
    paths: Sequence[str],
    weights: dict[str, float],
    shard_count: int,
) -> tuple[tuple[str, ...], ...]:
    """Assign each test file once using deterministic greedy weight balancing."""

    if shard_count < 1:
        raise ValueError("shard_count must be positive")
    buckets: list[list[str]] = [[] for _index in range(min(shard_count, len(paths)))]
    totals = [0.0] * len(buckets)
    for path in sorted(paths, key=lambda value: (-weights.get(value, 1.0), value)):
        shard = min(range(len(buckets)), key=lambda index: (totals[index], index))
        buckets[shard].append(path)
        totals[shard] += max(weights.get(path, 1.0), 0.001)
    return tuple(tuple(sorted(bucket)) for bucket in buckets)


def _partition_paths_with_limit(
    paths: Sequence[str],
    weights: dict[str, float],
    max_paths: int,
) -> tuple[tuple[str, ...], ...]:
    """Balance paths while enforcing a hard import-owner cardinality limit."""

    if max_paths < 1:
        raise ValueError("max_paths must be positive")
    bucket_count = max(1, math.ceil(len(paths) / max_paths))
    buckets: list[list[str]] = [[] for _index in range(bucket_count)]
    totals = [0.0] * bucket_count
    for path in sorted(paths, key=lambda value: (-weights.get(value, 1.0), value)):
        eligible = [index for index, bucket in enumerate(buckets) if len(bucket) < max_paths]
        shard = min(eligible, key=lambda index: (totals[index], len(buckets[index]), index))
        buckets[shard].append(path)
        totals[shard] += max(weights.get(path, 1.0), 0.001)
    return tuple(tuple(sorted(bucket)) for bucket in buckets)


def build_heavy_worker_jobs(
    paths: Sequence[str],
    path_weights: dict[str, float],
    batch_count: int,
    worker_slots: int,
    exclusive_paths: frozenset[str] = frozenset(),
) -> HeavyWorkerJobs:
    """Split overweight batches into typed atomic jobs and exclusive paths."""

    if worker_slots < 1:
        raise ValueError("worker_slots must be positive")
    serial_paths = tuple(sorted(set(paths) & exclusive_paths))
    parallel_paths = tuple(path for path in paths if path not in exclusive_paths)
    batches = partition_paths(parallel_paths, path_weights, batch_count)
    parallel_weight = sum(max(path_weights.get(path, 1.0), 0.001) for path in parallel_paths)
    target_weight = parallel_weight / len(batches) if batches else 0.0
    jobs: list[tuple[WorkerSpec, ...]] = []
    for batch_index, batch_paths in enumerate(batches):
        path_batches = _partition_paths_with_limit(batch_paths, path_weights, MAX_PATHS_PER_WORKER)
        for path_batch_index, path_batch in enumerate(path_batches):
            batch_weight = sum(max(path_weights.get(path, 1.0), 0.001) for path in path_batch)
            shard_count = 1
            if worker_slots > 1 and target_weight > 0.0 and batch_weight > target_weight * 1.5:
                shard_count = min(worker_slots, max(2, math.ceil(batch_weight / target_weight)))
            base_name = (
                f"heavy-{batch_index}"
                if len(path_batches) == 1
                else f"heavy-{batch_index}-part-{path_batch_index}"
            )
            jobs.append(
                tuple(
                    WorkerSpec(
                        name=base_name if shard_count == 1 else f"{base_name}-shard-{shard_index}",
                        paths=path_batch,
                        shard_count=shard_count,
                        shard_index=shard_index,
                    )
                    for shard_index in range(shard_count)
                )
            )
    exclusive = tuple(
        (WorkerSpec(name=f"heavy-exclusive-{index}", paths=(path,)),)
        for index, path in enumerate(serial_paths)
    )
    return HeavyWorkerJobs(parallel=tuple(jobs), exclusive=exclusive)


def _pack_conservative_jobs(
    jobs: Sequence[tuple[WorkerSpec, ...]],
    worker_slots: int,
) -> tuple[tuple[WorkerSpec, ...], ...]:
    """Pack unknown jobs under the measured conservative worker limit."""

    waves: list[tuple[WorkerSpec, ...]] = []
    current: list[WorkerSpec] = []
    for job in jobs:
        if current and len(current) + len(job) > worker_slots:
            waves.append(tuple(current))
            current = []
        current.extend(job)
    if current:
        waves.append(tuple(current))
    return tuple(waves)


def _job_weight(job: tuple[WorkerSpec, ...], path_weights: dict[str, float]) -> float:
    """Estimate one job's wall contribution from accepted node durations."""

    paths = job[0].paths
    total = sum(max(path_weights.get(path, 1.0), 0.001) for path in paths)
    return total / len(job)


def _reusable_measured_jobs(
    paths: Sequence[str],
    history: WorkerResourceHistory,
) -> tuple[tuple[tuple[WorkerSpec, ...], ...], frozenset[str]]:
    """Reuse exact jobs while retiring import-wide unsharded contracts."""

    available_paths = set(paths)
    grouped: dict[
        tuple[tuple[str, ...], int],
        list[WorkerResourceContract],
    ] = {}
    for measurement in history.accepted:
        contract = measurement.contract
        if not contract.paths or not set(contract.paths) <= available_paths:
            continue
        if contract.shard_count == 1 and len(contract.paths) > MAX_PATHS_PER_WORKER:
            continue
        grouped.setdefault((contract.paths, contract.shard_count), []).append(contract)
    jobs: list[tuple[WorkerSpec, ...]] = []
    covered_paths: set[str] = set()
    for (job_paths, shard_count), contracts in sorted(grouped.items()):
        if set(job_paths) & covered_paths:
            continue
        contracts_by_index = {contract.shard_index: contract for contract in contracts}
        if set(contracts_by_index) != set(range(shard_count)):
            continue
        job_index = len(jobs)
        jobs.append(
            tuple(
                WorkerSpec(
                    name=(
                        f"measured-{job_index}"
                        if shard_count == 1
                        else f"measured-{job_index}-shard-{shard_index}"
                    ),
                    paths=job_paths,
                    shard_count=shard_count,
                    shard_index=shard_index,
                )
                for shard_index in range(shard_count)
            )
        )
        covered_paths.update(job_paths)
    return tuple(jobs), frozenset(covered_paths)


def _pack_measured_jobs(
    jobs: Sequence[tuple[WorkerSpec, ...]],
    path_weights: dict[str, float],
    history: WorkerResourceHistory,
    *,
    max_worker_slots: int,
    max_rss_kib: int,
    controller_reserve_kib: int,
    worker_headroom_percent: int,
) -> tuple[tuple[WorkerSpec, ...], ...]:
    """Pack exact measured jobs by duration under a conservative RSS envelope."""

    usable_rss_kib = max(1, max_rss_kib - controller_reserve_kib)
    job_facts: list[tuple[tuple[WorkerSpec, ...], int, float]] = []
    for job in jobs:
        measured_rss_kib = sum(history.conservative_peak_for(spec) or 0 for spec in job)
        estimated_rss_kib = math.ceil(
            measured_rss_kib * (100 + worker_headroom_percent) / 100
        )
        job_facts.append((job, estimated_rss_kib, _job_weight(job, path_weights)))
    job_facts.sort(
        key=lambda fact: (
            -fact[2],
            -fact[1],
            tuple(worker_contract_sort_key(WorkerResourceContract.from_spec(spec)) for spec in fact[0]),
        )
    )
    waves: list[list[WorkerSpec]] = []
    wave_rss: list[int] = []
    wave_duration: list[float] = []
    for job, job_rss, job_duration in job_facts:
        candidates: list[tuple[float, int, int]] = []
        for index, wave in enumerate(waves):
            if len(wave) + len(job) > max_worker_slots or wave_rss[index] + job_rss > usable_rss_kib:
                continue
            new_duration = max(wave_duration[index], job_duration)
            remaining_rss = usable_rss_kib - wave_rss[index] - job_rss
            candidates.append((new_duration - wave_duration[index], remaining_rss, index))
        if candidates:
            _duration_cost, _remaining_rss, selected = min(candidates)
            waves[selected].extend(job)
            wave_rss[selected] += job_rss
            wave_duration[selected] = max(wave_duration[selected], job_duration)
        else:
            waves.append(list(job))
            wave_rss.append(job_rss)
            wave_duration.append(job_duration)
    return tuple(tuple(wave) for wave in waves)


def build_resource_aware_heavy_worker_waves(
    paths: Sequence[str],
    path_weights: dict[str, float],
    batch_count: int,
    conservative_worker_slots: int,
    max_worker_slots: int,
    max_rss_kib: int,
    history: WorkerResourceHistory,
    exclusive_paths: frozenset[str] = frozenset(),
    *,
    controller_reserve_kib: int = DEFAULT_CONTROLLER_RESERVE_KIB,
    worker_headroom_percent: int = DEFAULT_WORKER_HEADROOM_PERCENT,
) -> tuple[tuple[WorkerSpec, ...], ...]:
    """Raise concurrency only for jobs with exact accepted resource evidence."""

    if conservative_worker_slots < 1 or max_worker_slots < conservative_worker_slots:
        raise ValueError("worker slots must satisfy 1 <= conservative <= maximum")
    if max_rss_kib < 1 or controller_reserve_kib < 0 or worker_headroom_percent < 0:
        raise ValueError("RSS budget and headroom values must be non-negative")
    parallel_paths = tuple(path for path in paths if path not in exclusive_paths)
    measured, measured_paths = _reusable_measured_jobs(parallel_paths, history)
    remaining_paths = tuple(path for path in paths if path not in measured_paths)
    jobs = build_heavy_worker_jobs(
        remaining_paths,
        path_weights,
        batch_count,
        conservative_worker_slots,
        exclusive_paths,
    )
    conservative_waves = _pack_conservative_jobs(jobs.parallel, conservative_worker_slots)
    measured_waves = _pack_measured_jobs(
        measured,
        path_weights,
        history,
        max_worker_slots=max_worker_slots,
        max_rss_kib=max_rss_kib,
        controller_reserve_kib=controller_reserve_kib,
        worker_headroom_percent=worker_headroom_percent,
    )
    return (*conservative_waves, *measured_waves, *jobs.exclusive)


def build_heavy_worker_waves(
    paths: Sequence[str],
    path_weights: dict[str, float],
    batch_count: int,
    worker_slots: int,
    exclusive_paths: frozenset[str] = frozenset(),
) -> tuple[tuple[WorkerSpec, ...], ...]:
    """Build conservative waves for callers without accepted RSS history."""

    jobs = build_heavy_worker_jobs(
        paths,
        path_weights,
        batch_count,
        worker_slots,
        exclusive_paths,
    )
    return (*_pack_conservative_jobs(jobs.parallel, worker_slots), *jobs.exclusive)
