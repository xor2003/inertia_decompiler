#!/usr/bin/env python3
"""Run complete pytest inventory with import-aware bounded parallelism.

Layer: Tooling/gates.
Responsibility: partition the complete pytest inventory before execution so
only a bounded number of workers import the angr-heavy test graph.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import time
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

if __package__:
    from .pytest_dynamic_schedule import ScheduledWorkerSpec, run_pytest_schedule
    from .pytest_partition_execution import WorkerSpec
    from .pytest_partition_plugin import (
        WorkerReport,
        atomic_json_write,
    )
    from .pytest_resource_history import (
        DEFAULT_CONTROLLER_RESERVE_KIB,
        DEFAULT_WORKER_HEADROOM_PERCENT,
        WorkerResourceContract,
        WorkerResourceHistory,
    )
    from .pytest_resource_scheduler import (
        build_resource_aware_heavy_worker_waves,
        partition_paths,
    )
    from .pytest_source_state import source_tree_snapshot
else:
    from pytest_dynamic_schedule import ScheduledWorkerSpec, run_pytest_schedule
    from pytest_partition_execution import WorkerSpec
    from pytest_partition_plugin import (
        WorkerReport,
        atomic_json_write,
    )
    from pytest_resource_history import (
        DEFAULT_CONTROLLER_RESERVE_KIB,
        DEFAULT_WORKER_HEADROOM_PERCENT,
        WorkerResourceContract,
        WorkerResourceHistory,
    )
    from pytest_resource_scheduler import (
        build_resource_aware_heavy_worker_waves,
        partition_paths,
    )
    from pytest_source_state import source_tree_snapshot

REPO_ROOT: Path = Path(__file__).resolve().parents[1]


class PytestOutcome(StrEnum):
    """Typed pytest terminal outcomes used for history comparisons."""

    PASSED = "passed"
    SKIPPED = "skipped"
    FAILED = "failed"


RESOURCE_SERIAL_MARKER: str = "resource_serial"


# New and unlisted files default to the heavy lane. This allowlist contains
# tooling-only modules whose imports do not reach the decompiler/angr graph.
LIGHT_TEST_PATHS: frozenset[str] = frozenset(
    {
        "angr_platforms/tests/test_agent_context_check.py",
        "angr_platforms/tests/test_agent_test_focus.py",
        "angr_platforms/tests/test_build_msc6_artifact_names.py",
        "angr_platforms/tests/test_check_changed_non_test_types.py",
        "angr_platforms/tests/test_check_sortd_sidecar_free.py",
        "angr_platforms/tests/test_cli_batch_c_output.py",
        "angr_platforms/tests/test_compact_trace_script.py",
        "angr_platforms/tests/test_compare_ghidra_function_coverage.py",
        "angr_platforms/tests/test_generated_translation_unit_gate.py",
        "angr_platforms/tests/test_msc6_toolchain_lock.py",
        "angr_platforms/tests/test_omf_pat_far_transfer_variants.py",
        "angr_platforms/tests/test_omf_pat_fixup_widths.py",
        "angr_platforms/tests/test_omf_pat_lidata.py",
        "angr_platforms/tests/test_omf_pat_x87_emulator_variants.py",
        "angr_platforms/tests/test_omf_pat_zero_displacement.py",
        "angr_platforms/tests/test_pytest_inventory_check.py",
        "angr_platforms/tests/test_pytest_source_index.py",
        "angr_platforms/tests/test_pytest_source_state.py",
        "angr_platforms/tests/test_report_compiler_matches_flags.py",
        "angr_platforms/tests/test_test_ownership_manifest.py",
    }
)


def is_light_test_path(path: str) -> bool:
    """Return whether a reviewed test file may use a lightweight worker."""

    return path.replace("\\", "/") in LIGHT_TEST_PATHS


def default_heavy_worker_count(total_workers: int) -> int:
    """Use the measured two-worker decompiler limit under the 2 GiB monitor."""

    return min(2, max(1, total_workers))


def _measured_worker_reservation(
    history: WorkerResourceHistory, spec: WorkerSpec
) -> int:
    """Apply configured headroom to one exact accepted worker peak."""

    peak_rss_kib: int | None = history.conservative_peak_for(spec)
    if peak_rss_kib is None:
        raise ValueError(f"worker has no exact RSS evidence: {spec.name}")
    return int((peak_rss_kib * (100 + DEFAULT_WORKER_HEADROOM_PERCENT) + 99) // 100)


def _inventory_records(
    path: Path,
) -> tuple[
    list[str],
    dict[str, set[str]],
    dict[str, float],
    dict[str, str],
    set[str],
]:
    """Scan one inventory payload into node, lane, and weight tables."""

    payload = json.loads(path.read_text(encoding="utf-8"))
    records = payload.get("records") if isinstance(payload, dict) else None
    if not isinstance(records, list):
        raise ValueError(f"inventory has no records: {path}")
    expected: list[str] = []
    lane_paths: dict[str, set[str]] = {"heavy": set(), "light": set()}
    weights: dict[str, float] = {}
    node_paths: dict[str, str] = {}
    resource_serial_paths: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            raise ValueError(f"inventory record is not an object: {path}")
        nodeid = record.get("nodeid")
        test_path = record.get("path")
        if not isinstance(nodeid, str) or not isinstance(test_path, str):
            raise ValueError(f"inventory record lacks nodeid/path: {path}")
        expected.append(nodeid)
        node_paths[nodeid] = test_path
        lane_paths["light" if is_light_test_path(test_path) else "heavy"].add(test_path)
        markers = record.get("markers", ())
        if isinstance(markers, list) and RESOURCE_SERIAL_MARKER in markers:
            resource_serial_paths.add(test_path)
        subprocess_count = record.get("static_subprocess_count", 0)
        weights[nodeid] = 30.0 if isinstance(subprocess_count, int) and subprocess_count > 0 else 1.0
    if len(expected) != len(set(expected)):
        raise ValueError("inventory contains duplicate node IDs")
    return expected, lane_paths, weights, node_paths, resource_serial_paths


def _historical_weights(
    history: object, node_paths: dict[str, str]
) -> dict[str, float]:
    """Collect per-node historical scheduling durations from prior history."""

    historical_weights: dict[str, float] = {}
    scheduling_durations = history.get("scheduling_node_durations") if isinstance(history, dict) else None
    if isinstance(scheduling_durations, dict):
        for nodeid, seconds in scheduling_durations.items():
            if isinstance(nodeid, str) and nodeid in node_paths and isinstance(seconds, (int, float)):
                historical_weights[nodeid] = float(seconds)
    else:
        historical_weights.update(_legacy_historical_weights(history, node_paths))
    return historical_weights


def _legacy_historical_weights(
    history: object, node_paths: dict[str, str]
) -> dict[str, float]:
    """Collect durations from the older records/node_durations schema."""

    historical_weights: dict[str, float] = {}
    history_records = history.get("records", []) if isinstance(history, dict) else []
    if isinstance(history_records, list):
        for record in history_records:
            if not isinstance(record, dict):
                continue
            nodeid = record.get("nodeid")
            seconds = record.get("call_seconds")
            if isinstance(nodeid, str) and nodeid in node_paths and isinstance(seconds, (int, float)):
                historical_weights[nodeid] = float(seconds)
    node_durations = history.get("node_durations", {}) if isinstance(history, dict) else {}
    if isinstance(node_durations, dict):
        for nodeid, seconds in node_durations.items():
            if isinstance(nodeid, str) and nodeid in node_paths and isinstance(seconds, (int, float)):
                historical_weights[nodeid] = float(seconds)
    return historical_weights


def _historical_memory_serial_paths(
    history: object, resource_serial_paths: set[str]
) -> set[str]:
    """Recover paths that previously needed exclusive memory scheduling."""

    memory_serial_paths: set[str] = set()
    worker_paths = history.get("worker_paths", {}) if isinstance(history, dict) else {}
    wave_facts = history.get("wave_resource_facts", []) if isinstance(history, dict) else []
    if isinstance(worker_paths, dict) and isinstance(wave_facts, list):
        for wave in wave_facts:
            if not isinstance(wave, dict) or wave.get("memory_exceeded") is not True:
                continue
            workers = wave.get("workers", ())
            if not isinstance(workers, list):
                continue
            heavy_workers = [
                worker
                for worker in workers
                if isinstance(worker, str) and worker.startswith("heavy-")
            ]
            if len(heavy_workers) != 1:
                continue
            paths = worker_paths.get(heavy_workers[0], ())
            if isinstance(paths, list):
                memory_serial_paths.update(path for path in paths if isinstance(path, str))
    persisted_serial_paths = history.get("memory_serial_paths", ()) if isinstance(history, dict) else ()
    if not persisted_serial_paths and isinstance(history, dict):
        legacy_exclusive_paths = history.get("exclusive_paths", ())
        if isinstance(legacy_exclusive_paths, list):
            persisted_serial_paths = [
                path for path in legacy_exclusive_paths if path not in resource_serial_paths
            ]
    if isinstance(persisted_serial_paths, list):
        memory_serial_paths.update(path for path in persisted_serial_paths if isinstance(path, str))
    return memory_serial_paths


def _load_inventory(
    path: Path,
    history_path: Path | None,
) -> tuple[
    tuple[str, ...],
    dict[str, tuple[str, ...]],
    dict[str, float],
    dict[str, float],
    frozenset[str],
    frozenset[str],
    dict[str, str],
]:
    """Load expected nodes, lane paths, and compact scheduling weights."""

    expected, lane_paths, weights, node_paths, resource_serial_paths = _inventory_records(path)
    memory_serial_paths: set[str] = set()
    historical_outcomes: dict[str, str] = {}
    if history_path is not None and history_path.exists():
        history = json.loads(history_path.read_text(encoding="utf-8"))
        for nodeid, seconds in _historical_weights(history, node_paths).items():
            weights[nodeid] = max(seconds, 0.001)
        memory_serial_paths = _historical_memory_serial_paths(history, resource_serial_paths)
        node_outcomes = history.get("accepted_node_outcomes") if isinstance(history, dict) else None
        if not isinstance(node_outcomes, dict):
            node_outcomes = history.get("node_outcomes", {}) if isinstance(history, dict) else {}
        if isinstance(node_outcomes, dict):
            historical_outcomes = {
                nodeid: outcome
                for nodeid, outcome in node_outcomes.items()
                if nodeid in node_paths and isinstance(nodeid, str) and isinstance(outcome, str)
            }
    path_weights: dict[str, float] = {}
    for nodeid, weight in weights.items():
        test_path = node_paths[nodeid]
        path_weights[test_path] = path_weights.get(test_path, 0.0) + weight
    return (
        tuple(sorted(expected)),
        {lane: tuple(sorted(paths)) for lane, paths in lane_paths.items()},
        weights,
        path_weights,
        frozenset(path for path in resource_serial_paths if path in path_weights),
        frozenset(path for path in memory_serial_paths if path in path_weights),
        historical_outcomes,
    )


def find_outcome_regressions(
    previous: dict[str, str],
    current: dict[str, str],
) -> dict[str, dict[str, str]]:
    """Return pass-to-nonpass and skip-to-failure outcome regressions."""

    regressions: dict[str, dict[str, str]] = {}
    for nodeid, previous_text in previous.items():
        current_text = current.get(nodeid)
        if current_text is None:
            continue
        try:
            previous_outcome = PytestOutcome(previous_text)
            current_outcome = PytestOutcome(current_text)
        except ValueError:
            continue
        regressed = (
            previous_outcome is PytestOutcome.PASSED
            and current_outcome is not PytestOutcome.PASSED
        ) or (
            previous_outcome is PytestOutcome.SKIPPED
            and current_outcome is PytestOutcome.FAILED
        )
        if regressed:
            regressions[nodeid] = {
                "previous": previous_outcome.value,
                "current": current_outcome.value,
            }
    return regressions


def retain_accepted_run_history(
    scheduling_weights: dict[str, float],
    current_durations: dict[str, float],
    previous_outcomes: dict[str, str],
    current_outcomes: dict[str, str],
    *,
    accepted: bool,
) -> tuple[dict[str, float], dict[str, str]]:
    """Keep scheduling data across failed runs and advance outcomes only on acceptance."""

    durations = dict(scheduling_weights)
    durations.update(current_durations)
    outcomes = current_outcomes if accepted else previous_outcomes
    return durations, dict(outcomes)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    """Parse bounded partition-runner options."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory-json", type=Path, required=True)
    parser.add_argument("--history-json", type=Path)
    parser.add_argument("--summary-json", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 1) - 1))
    parser.add_argument(
        "--heavy-workers",
        type=int,
        default=default_heavy_worker_count(max(1, (os.cpu_count() or 1) - 1)),
    )
    parser.add_argument("--heavy-shards", type=int, default=16)
    parser.add_argument("--max-rss-mib", type=int, default=2048)
    parser.add_argument("--durations", type=int, default=25)
    return parser.parse_args(argv)


def _build_schedules(
    args: argparse.Namespace,
    lane_paths: dict[str, tuple[str, ...]],
    path_weights: dict[str, float],
    light_slots: int,
    heavy_waves: Sequence[tuple[WorkerSpec, ...]],
    resource_history: WorkerResourceHistory,
    exclusive_paths: frozenset[str],
) -> list[tuple[tuple[ScheduledWorkerSpec, ...], int]]:
    """Build ordered schedule waves from light, heavy, and exclusive workers."""

    light_specs = [
        WorkerSpec(name=f"light-{index}", paths=paths)
        for index, paths in enumerate(partition_paths(lane_paths["light"], path_weights, light_slots))
    ]
    schedules: list[tuple[tuple[ScheduledWorkerSpec, ...], int]] = []
    if light_specs:
        schedules.append(
            (tuple(ScheduledWorkerSpec(spec, 1) for spec in light_specs), args.workers)
        )
    conservative_specs: list[WorkerSpec] = []
    measured_specs: list[WorkerSpec] = []
    exclusive_schedules: list[tuple[ScheduledWorkerSpec, ...]] = []
    for wave in heavy_waves:
        if all(set(spec.paths) <= exclusive_paths for spec in wave):
            exclusive_schedules.append(tuple(ScheduledWorkerSpec(spec, 1) for spec in wave))
        elif all(resource_history.peak_for(spec) is not None for spec in wave):
            measured_specs.extend(wave)
        else:
            conservative_specs.extend(wave)
    if conservative_specs:
        schedules.append(
            (
                tuple(ScheduledWorkerSpec(spec, 1) for spec in conservative_specs),
                args.heavy_workers,
            )
        )
    if measured_specs:
        schedules.append(
            (
                tuple(
                    ScheduledWorkerSpec(
                        spec,
                        _measured_worker_reservation(resource_history, spec),
                    )
                    for spec in measured_specs
                ),
                args.workers,
            )
        )
    schedules.extend((schedule, 1) for schedule in exclusive_schedules)
    return schedules


@dataclass(slots=True)
class _RunOutcome:
    """Aggregated results from executing every schedule wave."""

    peak_rss_kib: int = 0
    memory_exceeded: bool = False
    outputs: dict[str, str] = field(default_factory=dict)
    reports: list[WorkerReport] = field(default_factory=list)
    exit_codes: dict[str, int] = field(default_factory=dict)
    worker_peak_rss_kib: dict[str, int] = field(default_factory=dict)
    last_active_nodeids: dict[str, str] = field(default_factory=dict)
    wave_resource_facts: list[dict[str, object]] = field(default_factory=list)


def _run_schedules(
    args: argparse.Namespace,
    schedules: Sequence[tuple[tuple[ScheduledWorkerSpec, ...], int]],
    run_root: Path,
    weights_path: Path,
) -> _RunOutcome:
    """Execute each schedule wave in order, stopping early on memory pressure."""

    run = _RunOutcome()
    for schedule, schedule_worker_limit in schedules:
        specs = tuple(item.spec for item in schedule)
        wave_started = time.monotonic()
        result = run_pytest_schedule(
            schedule,
            repo_root=REPO_ROOT,
            run_root=run_root,
            weights_path=weights_path,
            durations=args.durations,
            max_workers=schedule_worker_limit,
            reservation_limit_kib=max(
                1,
                args.max_rss_mib * 1024 - DEFAULT_CONTROLLER_RESERVE_KIB,
            ),
            max_rss_kib=args.max_rss_mib * 1024,
        )
        run.peak_rss_kib = max(run.peak_rss_kib, result.peak_rss_kib)
        run.memory_exceeded = run.memory_exceeded or result.memory_exceeded
        run.outputs.update(result.outputs)
        run.exit_codes.update(result.exit_codes)
        run.worker_peak_rss_kib.update(result.worker_peak_rss_kib)
        run.reports.extend(result.reports)
        run.wave_resource_facts.append(
            {
                "workers": [spec.name for spec in specs],
                "max_workers": schedule_worker_limit,
                "peak_rss_kib": result.peak_rss_kib,
                "worker_peak_rss_kib": dict(sorted(result.worker_peak_rss_kib.items())),
                "memory_exceeded": result.memory_exceeded,
                "elapsed_seconds": time.monotonic() - wave_started,
            }
        )
        if result.memory_exceeded:
            run.last_active_nodeids.update(result.active_nodeids)
        if run.memory_exceeded:
            break
    return run


def main(argv: Sequence[str] | None = None) -> int:
    """Run every inventoried node exactly once with bounded import ownership."""

    args = _parse_args(argv)
    if args.workers < 1 or args.heavy_workers < 1 or args.heavy_workers > args.workers:
        raise SystemExit("worker counts must satisfy 1 <= heavy-workers <= workers")
    if args.heavy_shards < 1:
        raise SystemExit("heavy-shards must be positive")
    started = time.monotonic()
    source_start = source_tree_snapshot(REPO_ROOT)
    loaded_resource_history = WorkerResourceHistory.load(args.history_json)
    resource_history = loaded_resource_history.accepted_for_source(
        source_start.sha256 if not source_start.unstable_paths else None
    )
    (
        expected,
        lane_paths,
        weights,
        path_weights,
        resource_serial_paths,
        memory_serial_paths,
        historical_outcomes,
    ) = _load_inventory(
        args.inventory_json,
        args.history_json,
    )
    exclusive_paths = resource_serial_paths | memory_serial_paths
    (REPO_ROOT / ".cache" / "pytest").mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="pytest-partition-", dir=REPO_ROOT / ".cache" / "pytest") as raw_run_root:
        run_root = Path(raw_run_root)
        weights_path = run_root / "weights.json"
        atomic_json_write(weights_path, dict(sorted(weights.items())))
        light_slots = max(1, args.workers - args.heavy_workers)
        heavy_waves = build_resource_aware_heavy_worker_waves(
            lane_paths["heavy"],
            path_weights,
            args.heavy_shards,
            conservative_worker_slots=args.heavy_workers,
            max_worker_slots=args.workers,
            max_rss_kib=args.max_rss_mib * 1024,
            history=resource_history,
            exclusive_paths=exclusive_paths,
        )
        schedules = _build_schedules(
            args,
            lane_paths,
            path_weights,
            light_slots,
            heavy_waves,
            resource_history,
            exclusive_paths,
        )
        worker_specs = {
            item.spec.name: item.spec
            for schedule, _worker_limit in schedules
            for item in schedule
        }
        worker_paths = {name: list(spec.paths) for name, spec in worker_specs.items()}
        run = _run_schedules(args, schedules, run_root, weights_path)
        peak_rss_kib = run.peak_rss_kib
        memory_exceeded = run.memory_exceeded
        worker_outputs = run.outputs
        worker_reports = run.reports
        worker_exit_codes = run.exit_codes
        worker_peak_rss_kib = run.worker_peak_rss_kib
        last_active_nodeids = run.last_active_nodeids
        wave_resource_facts = run.wave_resource_facts
    for name in sorted(worker_outputs):
        print(f"===== pytest shard {name} =====")
        print(worker_outputs[name], end="" if worker_outputs[name].endswith("\n") else "\n")
    observed = Counter(nodeid for report in worker_reports for nodeid in report.selected_nodeids)
    expected_set = set(expected)
    missing = sorted(expected_set - observed.keys())
    unexpected = sorted(observed.keys() - expected_set)
    duplicates = sorted(nodeid for nodeid, count in observed.items() if count != 1)
    outcome_counts = Counter(outcome for report in worker_reports for outcome in report.outcomes.values())
    node_outcomes = {
        nodeid: outcome for report in worker_reports for nodeid, outcome in report.outcomes.items()
    }
    missing_outcomes = sorted(expected_set - node_outcomes.keys())
    unexpected_outcomes = sorted(node_outcomes.keys() - expected_set)
    outcome_regressions = find_outcome_regressions(historical_outcomes, node_outcomes)
    failed_nodeids = sorted(
        nodeid
        for report in worker_reports
        for nodeid, outcome in report.outcomes.items()
        if outcome == "failed"
    )
    node_durations = {
        nodeid: seconds for report in worker_reports for nodeid, seconds in report.durations.items()
    }
    failure_details = {
        nodeid: detail for report in worker_reports for nodeid, detail in report.failure_details.items()
    }
    skip_details = {
        nodeid: detail for report in worker_reports for nodeid, detail in report.skip_details.items()
    }
    skip_detail_counts = Counter(skip_details.values())
    source_finish = source_tree_snapshot(REPO_ROOT)
    source_stable = source_start.is_stable_with(source_finish)
    succeeded = (
        not memory_exceeded
        and source_stable
        and not missing
        and not unexpected
        and not duplicates
        and not missing_outcomes
        and not unexpected_outcomes
        and not outcome_regressions
        and len(worker_reports) == len(worker_exit_codes)
        and all(code == 0 for code in worker_exit_codes.values())
        and all(report.exit_status == 0 for report in worker_reports)
    )
    scheduling_node_durations, accepted_node_outcomes = retain_accepted_run_history(
        weights,
        node_durations,
        historical_outcomes,
        node_outcomes,
        accepted=succeeded,
    )
    accepted_worker_resources = resource_history.retained_measurements(
        tuple(worker_specs.values()),
        worker_peak_rss_kib,
        accepted=succeeded,
    )
    observed_worker_resource_lower_bounds = resource_history.retained_lower_bounds(
        tuple(worker_specs.values()),
        worker_peak_rss_kib,
    )
    summary = {
        "schema_version": 9,
        "elapsed_seconds": time.monotonic() - started,
        "expected_count": len(expected),
        "observed_count": sum(observed.values()),
        "missing_nodeids": missing,
        "unexpected_nodeids": unexpected,
        "duplicate_nodeids": duplicates,
        "outcome_counts": dict(sorted(outcome_counts.items())),
        "node_outcomes": dict(sorted(node_outcomes.items())),
        "missing_outcomes": missing_outcomes,
        "unexpected_outcomes": unexpected_outcomes,
        "accepted_node_outcomes": dict(sorted(accepted_node_outcomes.items())),
        "outcome_regressions": dict(sorted(outcome_regressions.items())),
        "failed_nodeids": failed_nodeids,
        "failure_details": dict(sorted(failure_details.items())),
        "skip_details": dict(sorted(skip_details.items())),
        "skip_detail_counts": dict(sorted(skip_detail_counts.items())),
        "node_durations": dict(sorted(node_durations.items())),
        "scheduling_node_durations": dict(sorted(scheduling_node_durations.items())),
        "worker_exit_codes": dict(sorted(worker_exit_codes.items())),
        "worker_contracts": {
            name: WorkerResourceContract.from_spec(spec).as_dict()
            for name, spec in sorted(worker_specs.items())
        },
        "worker_peak_rss_kib": dict(sorted(worker_peak_rss_kib.items())),
        "accepted_worker_resources": [
            measurement.as_dict() for measurement in accepted_worker_resources
        ],
        "accepted_worker_resource_source_sha256": (
            source_finish.sha256 if succeeded else resource_history.accepted_source_sha256
        ),
        "observed_worker_resource_lower_bounds": [
            measurement.as_dict() for measurement in observed_worker_resource_lower_bounds
        ],
        "worker_paths": dict(sorted(worker_paths.items())),
        "worker_report_count": len(worker_reports),
        "last_active_nodeids": dict(sorted(last_active_nodeids.items())),
        "wave_resource_facts": wave_resource_facts,
        "peak_rss_kib": peak_rss_kib,
        "memory_limit_kib": args.max_rss_mib * 1024,
        "memory_exceeded": memory_exceeded,
        "exclusive_paths": sorted(exclusive_paths),
        "memory_serial_paths": sorted(memory_serial_paths),
        "resource_serial_paths": sorted(resource_serial_paths),
        "source_state": {
            "stable": source_stable,
            "start": source_start.as_dict(),
            "finish": source_finish.as_dict(),
        },
        "succeeded": succeeded,
    }
    atomic_json_write(args.summary_json, summary)
    print(
        "partitioned pytest: "
        f"selected={sum(observed.values())}/{len(expected)} "
        f"outcomes={dict(sorted(outcome_counts.items()))} "
        f"peak_rss_kib={peak_rss_kib} source_stable={source_stable} succeeded={succeeded}"
    )
    return 0 if succeeded else 2


if __name__ == "__main__":
    raise SystemExit(main())
