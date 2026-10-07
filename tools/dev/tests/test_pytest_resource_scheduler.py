"""Regression tests for evidence-driven pytest worker resource packing."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

from tools.dev.pytest_partition_execution import WorkerSpec
from tools.dev.pytest_resource_history import (
    WorkerResourceContract,
    WorkerResourceHistory,
    WorkerResourceMeasurement,
)
from tools.dev.pytest_resource_scheduler import (
    build_heavy_worker_jobs,
    build_resource_aware_heavy_worker_waves,
)


def test_historical_resource_modules_and_worker_contract_keep_identity() -> None:
    from tools.dev.pytest_worker_contract import WorkerSpec as QualifiedWorkerSpec

    assert WorkerSpec is QualifiedWorkerSpec
    for name in ("pytest_resource_history", "pytest_resource_scheduler"):
        assert importlib.import_module(f"scripts.{name}") is importlib.import_module(f"tools.dev.{name}")


def _accepted_history(
    specs: tuple[WorkerSpec, ...],
    peak_rss_kib: int,
) -> WorkerResourceHistory:
    """Build exact accepted resource evidence for scheduler unit tests."""

    return WorkerResourceHistory(
        accepted=tuple(
            WorkerResourceMeasurement(
                contract=WorkerResourceContract.from_spec(spec),
                peak_rss_kib=peak_rss_kib,
            )
            for spec in specs
        )
    )


def test_schema_five_history_migrates_unique_unsharded_path_contract(tmp_path: Path) -> None:
    """Migrate unique paths without treating a display name as shard identity."""

    path = tmp_path / "summary.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 5,
                "succeeded": True,
                "memory_exceeded": False,
                "worker_paths": {"heavy-0": ["a.py"]},
                "worker_peak_rss_kib": {"heavy-0": 300_000},
            }
        ),
        encoding="utf-8",
    )

    history = WorkerResourceHistory.load(path)

    assert history.peak_for(WorkerSpec("renamed", ("a.py",))) == 300_000
    assert history.peak_for(WorkerSpec("heavy-0", ("a.py",), 2, 0)) is None
    assert history.peak_for(WorkerSpec("heavy-0", ("b.py",))) is None


def test_schema_five_duplicate_paths_migrate_as_conservative_shards(tmp_path: Path) -> None:
    """Recover shard count from exact path multiplicity and use the maximum peak."""

    path = tmp_path / "summary.json"
    path.write_text(
        json.dumps(
            {
                "succeeded": True,
                "memory_exceeded": False,
                "worker_paths": {
                    "worker-a": ["shared.py"],
                    "worker-b": ["shared.py"],
                },
                "worker_peak_rss_kib": {
                    "worker-a": 300_000,
                    "worker-b": 350_000,
                },
            }
        ),
        encoding="utf-8",
    )

    history = WorkerResourceHistory.load(path)

    assert history.peak_for(WorkerSpec("renamed-a", ("shared.py",), 2, 0)) == 350_000
    assert history.peak_for(WorkerSpec("renamed-b", ("shared.py",), 2, 1)) == 350_000
    assert history.peak_for(WorkerSpec("unsharded", ("shared.py",))) is None


def test_failed_legacy_history_is_not_scheduling_evidence(tmp_path: Path) -> None:
    """Reject partial or failed run peaks as accepted concurrency evidence."""

    path = tmp_path / "summary.json"
    path.write_text(
        json.dumps(
            {
                "succeeded": False,
                "worker_paths": {"heavy-0": ["a.py"]},
                "worker_peak_rss_kib": {"heavy-0": 300_000},
            }
        ),
        encoding="utf-8",
    )

    assert WorkerResourceHistory.load(path) == WorkerResourceHistory()


def test_typed_history_matches_shards_without_worker_name_semantics(tmp_path: Path) -> None:
    """Match accepted resource facts by explicit path and shard fields."""

    contract = WorkerResourceContract(paths=("a.py",), shard_count=2, shard_index=1)
    path = tmp_path / "summary.json"
    path.write_text(
        json.dumps(
            {
                "accepted_worker_resource_source_sha256": "source-a",
                "accepted_worker_resources": [
                    WorkerResourceMeasurement(contract, 400_000).as_dict()
                ]
            }
        ),
        encoding="utf-8",
    )

    history = WorkerResourceHistory.load(path).accepted_for_source("source-a")

    assert history.peak_for(WorkerSpec("renamed", ("a.py",), 2, 1)) == 400_000
    assert history.peak_for(WorkerSpec("renamed", ("a.py",), 2, 0)) is None


def test_accepted_history_refuses_changed_or_unversioned_source(tmp_path: Path) -> None:
    """Never authorize measured concurrency after source or schema drift."""

    spec = WorkerSpec("measured", ("a.py",))
    measurement = WorkerResourceMeasurement(WorkerResourceContract.from_spec(spec), 400_000)
    path = tmp_path / "summary.json"
    path.write_text(
        json.dumps({"accepted_worker_resources": [measurement.as_dict()]}),
        encoding="utf-8",
    )
    unversioned = WorkerResourceHistory.load(path)
    versioned = WorkerResourceHistory(
        accepted=(measurement,),
        observed_lower_bounds=(measurement,),
        accepted_source_sha256="source-a",
    )

    assert unversioned.accepted_for_source("source-a").accepted == ()
    changed = versioned.accepted_for_source("source-b")
    assert changed.accepted == ()
    assert changed.observed_lower_bounds == (measurement,)


def test_failed_typed_peak_is_only_a_conservative_lower_bound(tmp_path: Path) -> None:
    """Use failed-run peaks to reduce packing without accepting new concurrency."""

    spec = WorkerSpec("measured", ("a.py",))
    contract = WorkerResourceContract.from_spec(spec)
    path = tmp_path / "summary.json"
    path.write_text(
        json.dumps(
            {
                "succeeded": False,
                "memory_exceeded": True,
                "accepted_worker_resources": [
                    WorkerResourceMeasurement(contract, 300_000).as_dict()
                ],
                "worker_contracts": {spec.name: contract.as_dict()},
                "worker_peak_rss_kib": {spec.name: 700_000},
            }
        ),
        encoding="utf-8",
    )

    history = WorkerResourceHistory.load(path)

    assert history.peak_for(spec) == 300_000
    assert history.conservative_peak_for(spec) == 700_000


def test_unknown_jobs_remain_at_conservative_worker_limit() -> None:
    """Keep new or changed work at two heavy workers until measured."""

    waves = build_resource_aware_heavy_worker_waves(
        ("a.py", "b.py", "c.py", "d.py"),
        dict.fromkeys(("a.py", "b.py", "c.py", "d.py"), 1.0),
        batch_count=4,
        conservative_worker_slots=2,
        max_worker_slots=7,
        max_rss_kib=2 * 1024 * 1024,
        history=WorkerResourceHistory(),
    )

    assert [len(wave) for wave in waves] == [2, 2]


def test_exact_measured_jobs_use_available_cpu_slots_with_headroom() -> None:
    """Pack measured low-memory jobs above the conservative unknown-work limit."""

    paths = ("a.py", "b.py", "c.py", "d.py")
    weights = dict.fromkeys(paths, 1.0)
    jobs = build_heavy_worker_jobs(paths, weights, batch_count=4, worker_slots=2)
    specs = tuple(spec for job in jobs.parallel for spec in job)

    waves = build_resource_aware_heavy_worker_waves(
        paths,
        weights,
        batch_count=4,
        conservative_worker_slots=2,
        max_worker_slots=7,
        max_rss_kib=2 * 1024 * 1024,
        history=_accepted_history(specs, 300_000),
    )

    assert len(waves) == 1
    assert len(waves[0]) == 4
    assert sorted(spec.paths[0] for spec in waves[0]) == sorted(paths)


def test_observed_lower_bound_can_only_split_an_accepted_wave() -> None:
    """Never let an aborted high-water mark authorize or preserve unsafe packing."""

    paths = ("a.py", "b.py", "c.py", "d.py")
    weights = dict.fromkeys(paths, 1.0)
    jobs = build_heavy_worker_jobs(paths, weights, batch_count=4, worker_slots=2)
    specs = tuple(spec for job in jobs.parallel for spec in job)
    accepted = _accepted_history(specs, 300_000)
    high_water = WorkerResourceMeasurement(
        contract=WorkerResourceContract.from_spec(specs[0]),
        peak_rss_kib=1_500_000,
    )
    history = WorkerResourceHistory(
        accepted=accepted.accepted,
        observed_lower_bounds=(high_water,),
    )

    waves = build_resource_aware_heavy_worker_waves(
        paths,
        weights,
        batch_count=4,
        conservative_worker_slots=2,
        max_worker_slots=7,
        max_rss_kib=2 * 1024 * 1024,
        history=history,
    )

    assert len(waves) == 2
    assert tuple(WorkerResourceContract.from_spec(spec) for spec in waves[0]) == (
        WorkerResourceContract.from_spec(specs[0]),
    )


def test_accepted_path_groups_survive_duration_rebalancing() -> None:
    """Do not discard RSS evidence merely because newer durations changed."""

    paths = ("a.py", "b.py", "c.py", "d.py")
    original_weights = dict.fromkeys(paths, 1.0)
    original_jobs = build_heavy_worker_jobs(
        paths,
        original_weights,
        batch_count=2,
        worker_slots=2,
    )
    original_specs = tuple(spec for job in original_jobs.parallel for spec in job)
    original_groups = {spec.paths for spec in original_specs}

    waves = build_resource_aware_heavy_worker_waves(
        paths,
        {"a.py": 100.0, "b.py": 10.0, "c.py": 2.0, "d.py": 1.0},
        batch_count=2,
        conservative_worker_slots=2,
        max_worker_slots=4,
        max_rss_kib=2 * 1024 * 1024,
        history=_accepted_history(original_specs, 300_000),
    )

    assert {spec.paths for wave in waves for spec in wave} == original_groups


def test_import_wide_measured_contract_is_conservatively_repartitioned() -> None:
    """Retire coarse exact RSS evidence before admitting smaller import owners."""

    paths = tuple(f"test_{index:02d}.py" for index in range(65))
    weights = dict.fromkeys(paths, 1.0)
    coarse = WorkerSpec("coarse", paths)

    waves = build_resource_aware_heavy_worker_waves(
        paths,
        weights,
        batch_count=1,
        conservative_worker_slots=2,
        max_worker_slots=7,
        max_rss_kib=2 * 1024 * 1024,
        history=_accepted_history((coarse,), 800_000),
    )

    specs = tuple(spec for wave in waves for spec in wave)
    assert [len(wave) for wave in waves] == [2, 1]
    assert {path for spec in specs for path in spec.paths} == set(paths)
    assert all(len(spec.paths) <= 22 for spec in specs)
    assert all(spec.paths != coarse.paths for spec in specs)


def test_measured_jobs_respect_rss_headroom_and_exclusive_paths() -> None:
    """Keep estimated peaks below budget and marked paths in isolated waves."""

    paths = ("a.py", "b.py", "c.py", "exclusive.py")
    weights = dict.fromkeys(paths, 1.0)
    exclusive = frozenset({"exclusive.py"})
    jobs = build_heavy_worker_jobs(
        paths,
        weights,
        batch_count=3,
        worker_slots=2,
        exclusive_paths=exclusive,
    )
    specs = tuple(spec for job in jobs.parallel for spec in job)

    waves = build_resource_aware_heavy_worker_waves(
        paths,
        weights,
        batch_count=3,
        conservative_worker_slots=2,
        max_worker_slots=7,
        max_rss_kib=2 * 1024 * 1024,
        history=_accepted_history(specs, 600_000),
        exclusive_paths=exclusive,
    )

    assert [len(wave) for wave in waves] == [2, 1, 1]
    assert waves[-1][0].paths == ("exclusive.py",)


def test_failed_run_retains_previous_accepted_measurements() -> None:
    """A partial run must not erase the last safe resource schedule."""

    spec = WorkerSpec("heavy-0", ("a.py",))
    history = _accepted_history((spec,), 300_000)

    retained = history.retained_measurements((spec,), {spec.name: 500_000}, accepted=False)

    assert retained == history.accepted


def test_observed_lower_bounds_retain_the_largest_exact_peak() -> None:
    """Carry a killed worker's high-water mark forward without accepting it."""

    spec = WorkerSpec("heavy-0", ("a.py",))
    previous = WorkerResourceMeasurement(WorkerResourceContract.from_spec(spec), 500_000)
    history = WorkerResourceHistory(observed_lower_bounds=(previous,))

    retained = history.retained_lower_bounds((spec,), {spec.name: 700_000})

    assert retained == (
        WorkerResourceMeasurement(WorkerResourceContract.from_spec(spec), 700_000),
    )
