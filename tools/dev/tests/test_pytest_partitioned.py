"""Regression tests for import-aware complete-suite partitioning."""

from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import pytest
from pytest import MonkeyPatch

from tools.dev import pytest_partition_plugin as plugin
from tools.dev import pytest_partitioned as runner
from tools.dev.pytest_dynamic_schedule import ScheduledWorkerSpec
from tools.dev.pytest_partition_execution import (
    WaveResult,
    WorkerProcess,
    WorkerSpec,
    _worker_environment,
    terminate_worker_processes,
)
from tools.dev.pytest_resource_scheduler import build_heavy_worker_waves
from tools.dev.source_state import SourceTreeSnapshot


def test_partition_runner_defaults_to_three_workers() -> None:
    """A direct complete-suite run must not expand its pool with the CPU count."""
    args = runner._parse_args([
        "--inventory-json", "inventory.json", "--summary-json", "summary.json",
    ])
    assert args.workers == 3
    assert 1 <= args.heavy_workers <= args.workers


@dataclass(frozen=True)
class _FakeMarker:
    args: tuple[str, ...]


@dataclass(frozen=True)
class _FakeItem:
    nodeid: str
    group: str | None = None

    def iter_markers(self, *, name: str) -> tuple[_FakeMarker, ...]:
        """Expose an xdist-compatible marker surface for the plugin hook."""

        if name == "xdist_group" and self.group is not None:
            return (_FakeMarker((self.group,)),)
        return ()


class _FakeHook:
    def __init__(self) -> None:
        self.deselected: list[_FakeItem] = []

    def pytest_deselected(self, *, items: list[_FakeItem]) -> None:
        """Capture the plugin's deselected collection."""

        self.deselected.extend(items)


@dataclass(frozen=True)
class _FakeConfig:
    hook: _FakeHook


@dataclass(frozen=True)
class _FakeTestReport:
    nodeid: str
    duration: float
    failed: bool
    skipped: bool
    passed: bool
    when: str
    longreprtext: str = ""
    longrepr: object = ""


def test_assign_work_items_keeps_groups_atomic_and_balances_weights() -> None:
    """Keep grouped integration contracts on exactly one deterministic shard."""

    items = (
        plugin.ShardWorkItem("a", "shared", 8.0),
        plugin.ShardWorkItem("b", "shared", 2.0),
        plugin.ShardWorkItem("c", "node:c", 9.0),
        plugin.ShardWorkItem("d", "node:d", 1.0),
    )

    assignments = plugin.assign_work_items(items, 2)

    assert assignments == plugin.assign_work_items(items, 2)
    assert set(assignments) == {"a", "b", "c", "d"}
    assert assignments["a"] == assignments["b"]
    assert assignments["c"] != assignments["a"]


def test_assign_work_items_refuses_nonpositive_shard_count() -> None:
    """Reject an invalid worker contract before collection is modified."""

    with pytest.raises(ValueError, match="positive"):
        plugin.assign_work_items((), 0)


def test_partition_paths_is_deterministic_and_exact() -> None:
    """Pre-import file batches must cover every path exactly once."""

    paths = ("a.py", "b.py", "c.py", "d.py")
    weights = {"a.py": 8.0, "b.py": 7.0, "c.py": 2.0, "d.py": 1.0}

    batches = runner.partition_paths(paths, weights, 2)

    assert batches == runner.partition_paths(tuple(reversed(paths)), weights, 2)
    assert sorted(path for batch in batches for path in batch) == sorted(paths)
    assert set(batches[0]).isdisjoint(batches[1])


def test_partition_paths_refuses_nonpositive_shard_count() -> None:
    """Reject invalid batch counts before starting pytest processes."""

    with pytest.raises(ValueError, match="positive"):
        runner.partition_paths(("a.py",), {}, 0)


def test_default_heavy_worker_count_uses_bounded_parallelism() -> None:
    """Use available CPUs up to the measured two-heavy-worker memory limit."""

    assert [runner.default_heavy_worker_count(count) for count in (1, 2, 3, 4, 7)] == [1, 2, 2, 2, 2]


def test_overweight_heavy_batch_splits_into_atomic_node_shards() -> None:
    """Use all bounded heavy slots when one file dominates historical cost."""

    waves = build_heavy_worker_waves(
        ("dominant.py", "small-a.py", "small-b.py"),
        {"dominant.py": 30.0, "small-a.py": 5.0, "small-b.py": 5.0},
        3,
        2,
    )

    assert waves[0] == (
        WorkerSpec("heavy-0-shard-0", ("dominant.py",), shard_count=2, shard_index=0),
        WorkerSpec("heavy-0-shard-1", ("dominant.py",), shard_count=2, shard_index=1),
    )
    assert tuple(spec.name for spec in waves[1]) == ("heavy-1", "heavy-2")
    assert sorted({path for wave in waves for spec in wave for path in spec.paths}) == [
        "dominant.py",
        "small-a.py",
        "small-b.py",
    ]


def test_worker_environment_carries_exact_node_shard(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """Pass each split worker the same count and a distinct shard index."""

    monkeypatch.setenv("PYTEST_XDIST_WORKER", "stale-worker")
    spec = WorkerSpec("heavy-0-shard-1", ("dominant.py",), 2, 1)
    report_path = tmp_path / "report.json"
    activity_path = tmp_path / "activity.json"
    weights_path = tmp_path / "weights.json"

    env = _worker_environment(spec, report_path, activity_path, weights_path)

    assert "PYTEST_XDIST_WORKER" not in env
    assert env["PYTEST_PARTITION_COUNT"] == "2"
    assert env["PYTEST_PARTITION_INDEX"] == "1"
    assert env["PYTEST_PARTITION_REPORT"] == str(report_path)
    assert env["PYTEST_PARTITION_ACTIVITY"] == str(activity_path)
    assert env["PYTEST_PARTITION_WEIGHTS"] == str(weights_path)


def test_inventory_ignores_historical_nodes_absent_from_current_collection(tmp_path: Path) -> None:
    """A renamed or retired test must not poison current scheduling weights."""

    inventory_path = tmp_path / "inventory.json"
    history_path = tmp_path / "history.json"
    inventory_path.write_text(
        json.dumps({"records": [{"nodeid": "current", "path": "current.py"}]}),
        encoding="utf-8",
    )
    history_path.write_text(
        json.dumps(
            {
                "records": [
                    {"nodeid": "current", "call_seconds": 3.0},
                    {"nodeid": "retired", "call_seconds": 90.0},
                ],
                "scheduling_node_durations": {"current": 4.0, "renamed": 120.0},
                "accepted_node_outcomes": {"current": "passed", "retired": "failed"},
            }
        ),
        encoding="utf-8",
    )

    (
        expected,
        lane_paths,
        weights,
        path_weights,
        resource_serial_paths,
        memory_serial_paths,
        historical_outcomes,
    ) = runner._load_inventory(inventory_path, history_path)

    assert expected == ("current",)
    assert lane_paths == {"heavy": ("current.py",), "light": ()}
    assert weights == {"current": 4.0}
    assert path_weights == {"current.py": 4.0}
    assert resource_serial_paths == frozenset()
    assert memory_serial_paths == frozenset()
    assert historical_outcomes == {"current": "passed"}


def test_inventory_prefers_measured_duration_over_static_subprocess_guess(tmp_path: Path) -> None:
    """Schedule measured fast subprocess contracts by evidence, not a 30s guess."""

    inventory_path = tmp_path / "inventory.json"
    history_path = tmp_path / "history.json"
    inventory_path.write_text(
        json.dumps(
            {
                "records": [
                    {
                        "nodeid": "measured",
                        "path": "measured.py",
                        "static_subprocess_count": 1,
                    },
                    {
                        "nodeid": "new",
                        "path": "new.py",
                        "static_subprocess_count": 1,
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    history_path.write_text(
        json.dumps({"node_durations": {"measured": 0.25}}),
        encoding="utf-8",
    )

    (
        _expected,
        _lane_paths,
        weights,
        path_weights,
        _resource_serial_paths,
        _memory_serial_paths,
        _historical_outcomes,
    ) = runner._load_inventory(
        inventory_path,
        history_path,
    )

    assert weights == {"measured": 0.25, "new": 30.0}
    assert path_weights == {"measured.py": 0.25, "new.py": 30.0}


def test_inventory_combines_marked_and_learned_exclusive_paths(tmp_path: Path) -> None:
    inventory_path = tmp_path / "inventory.json"
    history_path = tmp_path / "history.json"
    inventory_path.write_text(
        json.dumps(
            {
                "records": [
                    {"nodeid": "large", "path": "large.py"},
                    {
                        "nodeid": "compiler",
                        "path": "compiler.py",
                        "markers": ["resource_serial"],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    history_path.write_text(
        json.dumps(
            {
                "worker_paths": {"heavy-2-shard-0": ["large.py"]},
                "wave_resource_facts": [
                    {
                        "workers": ["heavy-2-shard-0"],
                        "peak_rss_kib": 2_200_000,
                        "memory_exceeded": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    (
        _expected,
        _lane_paths,
        _weights,
        _path_weights,
        resource_serial_paths,
        memory_serial_paths,
        _historical_outcomes,
    ) = runner._load_inventory(inventory_path, history_path)
    exclusive_paths = resource_serial_paths | memory_serial_paths
    waves = build_heavy_worker_waves(
        ("compiler.py", "large.py", "small.py"),
        {"compiler.py": 1.0, "large.py": 100.0, "small.py": 1.0},
        batch_count=2,
        worker_slots=2,
        exclusive_paths=exclusive_paths,
    )

    assert waves[0] == (WorkerSpec("heavy-0", ("small.py",)),)
    assert waves[1] == (WorkerSpec("heavy-exclusive-0", ("compiler.py",)),)
    assert waves[2] == (WorkerSpec("heavy-exclusive-1", ("large.py",)),)


def test_inventory_does_not_blame_every_path_in_multi_worker_memory_abort(tmp_path: Path) -> None:
    """Treat a concurrent OOM as scheduler evidence, not path exclusivity proof."""

    inventory_path = tmp_path / "inventory.json"
    history_path = tmp_path / "history.json"
    inventory_path.write_text(
        json.dumps(
            {
                "records": [
                    {"nodeid": "a", "path": "a.py"},
                    {"nodeid": "b", "path": "b.py"},
                ]
            }
        ),
        encoding="utf-8",
    )
    history_path.write_text(
        json.dumps(
            {
                "worker_paths": {"heavy-0": ["a.py"], "heavy-1": ["b.py"]},
                "wave_resource_facts": [
                    {"workers": ["heavy-0", "heavy-1"], "memory_exceeded": True}
                ],
            }
        ),
        encoding="utf-8",
    )

    *_inventory, resource_serial_paths, memory_serial_paths, _outcomes = runner._load_inventory(
        inventory_path, history_path
    )

    assert resource_serial_paths == frozenset()
    assert memory_serial_paths == frozenset()


def test_worker_termination_kills_detached_descendants(tmp_path: Path) -> None:
    """A resource abort must not leave a nested decompiler holding pipes open."""

    parent = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import subprocess,sys,time; "
                "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],"
                " start_new_session=True); print(child.pid,flush=True); time.sleep(60)"
            ),
        ],
        stdout=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    assert parent.stdout is not None
    child_pid = int(parent.stdout.readline())
    try:
        terminate_worker_processes(
            (WorkerProcess("worker", parent, tmp_path / "report.json", tmp_path / "activity.json"),)
        )
        parent.wait(timeout=3.0)
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline and _process_is_active(child_pid):
            time.sleep(0.05)
        assert not _process_is_active(child_pid)
    finally:
        for pid in (child_pid, parent.pid):
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)


def _process_is_active(pid: int) -> bool:
    """Return whether a Linux process exists and is not an unreaped zombie."""

    try:
        fields = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").split()
    except FileNotFoundError:
        return False
    return len(fields) > 2 and fields[2] != "Z"


def test_partition_plugin_selects_every_node_once_and_preserves_group(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    """Prove two independently collected shards form one exact partition."""

    weights_path = tmp_path / "weights.json"
    weights_path.write_text(json.dumps({"a": 8.0, "b": 2.0, "c": 9.0, "d": 1.0}), encoding="utf-8")
    monkeypatch.setenv(plugin.SHARD_COUNT_ENV, "2")
    monkeypatch.setenv(plugin.SHARD_WEIGHTS_ENV, str(weights_path))
    selected_by_shard: list[set[str]] = []
    for shard_index in range(2):
        monkeypatch.setenv(plugin.SHARD_INDEX_ENV, str(shard_index))
        items = [_FakeItem("a", "shared"), _FakeItem("b", "shared"), _FakeItem("c"), _FakeItem("d")]
        plugin.pytest_collection_modifyitems(_FakeConfig(_FakeHook()), items)  # type: ignore[arg-type]
        selected_by_shard.append({item.nodeid for item in items})

    assert selected_by_shard[0].isdisjoint(selected_by_shard[1])
    assert selected_by_shard[0] | selected_by_shard[1] == {"a", "b", "c", "d"}
    assert ({"a", "b"} <= selected_by_shard[0]) != ({"a", "b"} <= selected_by_shard[1])


def test_worker_report_round_trip_is_structured(tmp_path: Path) -> None:
    """Keep selection, outcomes, durations, and exit status machine-readable."""

    path = tmp_path / "worker.json"
    expected = plugin.WorkerReport(
        selected_nodeids=("a", "b"),
        outcomes={"a": "passed", "b": "skipped"},
        durations={"a": 1.25, "b": 0.5},
        exit_status=0,
        failure_details={"b": "assertion detail"},
        skip_details={"b": "missing fixture"},
    )
    plugin.atomic_json_write(path, expected.as_dict())

    assert plugin.WorkerReport.from_path(path) == expected


def test_worker_report_retains_failure_traceback(monkeypatch: MonkeyPatch) -> None:
    """Keep the assertion evidence needed to diagnose a full-suite-only failure."""

    with monkeypatch.context() as context:
        context.setattr(plugin, "_DURATIONS", {})
        context.setattr(plugin, "_OUTCOMES", {})
        context.setattr(plugin, "_FAILURE_DETAILS", {})
        context.setattr(plugin, "_SKIP_DETAILS", {})

        plugin.pytest_runtest_logreport(
            _FakeTestReport(
                nodeid="tests/test_sample.py::test_failure",
                duration=0.25,
                failed=True,
                skipped=False,
                passed=False,
                when="call",
                longreprtext="AssertionError: exact failure",
            )
        )

        assert plugin._FAILURE_DETAILS == {
            "tests/test_sample.py::test_failure": "AssertionError: exact failure"
        }

        plugin.pytest_runtest_logreport(
            _FakeTestReport(
                nodeid="tests/test_sample.py::test_skip",
                duration=0.0,
                failed=False,
                skipped=True,
                passed=False,
                when="setup",
                longrepr=("tests/test_sample.py", 7, "missing fixture"),
            )
        )

        assert plugin._SKIP_DETAILS == {"tests/test_sample.py::test_skip": "missing fixture"}


def test_outcome_history_rejects_pass_to_skip_without_rejecting_improvement() -> None:
    """Treat a hidden skip as regression while allowing skipped tests to pass."""

    regressions = runner.find_outcome_regressions(
        {"lost": "passed", "improved": "skipped", "stable": "passed"},
        {"lost": "skipped", "improved": "passed", "stable": "passed"},
    )

    assert regressions == {"lost": {"previous": "passed", "current": "skipped"}}


def test_failed_attempt_retains_complete_scheduling_and_outcome_history() -> None:
    """A partial failure may refine timings but must not erase accepted outcomes."""

    durations, outcomes = runner.retain_accepted_run_history(
        {"observed": 8.0, "missing": 20.0},
        {"observed": 3.0},
        {"observed": "passed", "missing": "passed"},
        {"observed": "failed"},
        accepted=False,
    )

    assert durations == {"observed": 3.0, "missing": 20.0}
    assert outcomes == {"observed": "passed", "missing": "passed"}


def test_worker_activity_round_trip_is_structured(tmp_path: Path) -> None:
    """Keep resource abort attribution independent from terminal text."""

    path = tmp_path / "activity.json"
    expected = plugin.WorkerActivity(nodeid="tests/test_sample.py::test_case", pid=123)
    plugin.atomic_json_write(path, expected.as_dict())

    assert plugin.WorkerActivity.from_path(path) == expected


def test_unknown_test_file_defaults_to_heavy_lane() -> None:
    """Prevent new test files from silently entering the low-memory allowlist."""

    assert runner.is_light_test_path("tools/dev/tests/test_agent_context_check.py")
    assert not runner.is_light_test_path("angr_platforms/tests/test_new_decompiler_contract.py")


@pytest.mark.parametrize(("record_outcomes", "expected_exit_status"), [(True, 0), (False, 2)])
def test_partitioned_controller_runs_short_lived_heavy_waves_exactly_once(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
    record_outcomes: bool,
    expected_exit_status: int,
) -> None:
    """Keep memory-reset waves coherent with exact inventory accounting."""

    monkeypatch.setattr(runner, "REPO_ROOT", tmp_path)
    assert not (tmp_path / ".cache").exists()
    nodes_by_path = {"heavy-a.py": "heavy-a", "heavy-b.py": "heavy-b", "light.py": "light"}
    observed_waves: list[tuple[str, ...]] = []
    observed_worker_limits: list[int] = []

    def fake_load_inventory(
        _path: Path,
        _history_path: Path | None,
    ) -> tuple[
        tuple[str, ...],
        dict[str, tuple[str, ...]],
        dict[str, float],
        dict[str, float],
        frozenset[str],
        frozenset[str],
        dict[str, str],
    ]:
        return (
            tuple(sorted(nodes_by_path.values())),
            {"heavy": ("heavy-a.py", "heavy-b.py"), "light": ("light.py",)},
            dict.fromkeys(nodes_by_path.values(), 1.0),
            dict.fromkeys(nodes_by_path, 1.0),
            frozenset({"heavy-b.py"}),
            frozenset(),
            {},
        )

    def fake_run_schedule(
        scheduled_specs: Sequence[ScheduledWorkerSpec], **kwargs: object
    ) -> WaveResult:
        worker_specs = tuple(item.spec for item in scheduled_specs)
        observed_waves.append(tuple(spec.name for spec in worker_specs))
        observed_worker_limits.append(int(kwargs["max_workers"]))
        reports = tuple(
            plugin.WorkerReport(
                selected_nodeids=tuple(nodes_by_path[path] for path in spec.paths),
                outcomes=(
                    {nodes_by_path[path]: "passed" for path in spec.paths}
                    if record_outcomes
                    else {}
                ),
                durations={nodes_by_path[path]: 0.1 for path in spec.paths},
                exit_status=0,
            )
            for spec in worker_specs
        )
        return WaveResult(
            outputs={spec.name: "" for spec in worker_specs},
            reports=reports,
            exit_codes={spec.name: 0 for spec in worker_specs},
            active_nodeids={},
            peak_rss_kib=1024,
            worker_peak_rss_kib={spec.name: 512 for spec in worker_specs},
            memory_exceeded=False,
        )

    monkeypatch.setattr(runner, "_load_inventory", fake_load_inventory)
    monkeypatch.setattr(runner, "run_pytest_schedule", fake_run_schedule)
    monkeypatch.setattr(runner, "source_tree_snapshot", lambda _root: SourceTreeSnapshot("stable", 1, 1))
    summary_path = tmp_path / "summary.json"

    exit_status = runner.main(
        [
            "--inventory-json",
            str(tmp_path / "inventory.json"),
            "--summary-json",
            str(summary_path),
            "--workers",
            "2",
            "--heavy-workers",
            "1",
            "--heavy-shards",
            "2",
        ]
    )

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert list((tmp_path / ".cache" / "pytest").iterdir()) == []
    assert exit_status == expected_exit_status
    assert summary["schema_version"] == 9
    assert observed_waves == [("light-0",), ("heavy-0",), ("heavy-exclusive-0",)]
    assert observed_worker_limits == [2, 1, 1]
    assert summary["observed_count"] == summary["expected_count"] == 3
    assert summary["outcome_counts"] == ({"passed": 3} if record_outcomes else {})
    assert summary["missing_outcomes"] == (
        [] if record_outcomes else ["heavy-a", "heavy-b", "light"]
    )
    assert summary["unexpected_outcomes"] == []
    assert summary["accepted_node_outcomes"] == (
        {"heavy-a": "passed", "heavy-b": "passed", "light": "passed"}
        if record_outcomes
        else {}
    )
    assert summary["scheduling_node_durations"] == {
        "heavy-a": 0.1,
        "heavy-b": 0.1,
        "light": 0.1,
    }
    assert summary["failed_nodeids"] == []
    assert summary["skip_details"] == {}
    assert summary["skip_detail_counts"] == {}
    assert summary["worker_paths"] == {
        "heavy-0": ["heavy-a.py"],
        "heavy-exclusive-0": ["heavy-b.py"],
        "light-0": ["light.py"],
    }
    assert summary["worker_peak_rss_kib"] == {
        "heavy-0": 512,
        "heavy-exclusive-0": 512,
        "light-0": 512,
    }
    assert len(summary["accepted_worker_resources"]) == (3 if record_outcomes else 0)
    assert summary["accepted_worker_resource_source_sha256"] == (
        "stable" if record_outcomes else None
    )
    assert len(summary["observed_worker_resource_lower_bounds"]) == 3
    assert all(fact["elapsed_seconds"] >= 0 for fact in summary["wave_resource_facts"])
    assert summary["succeeded"] is record_outcomes


@pytest.mark.parametrize("exclusive_input", [("light-exclusive.py",), ("light-z.py", "light-a.py")])
def test_light_exclusive_paths_run_alone_without_losing_regular_coverage(exclusive_input):
    """Marked or learned exclusive light files cannot share a worker wave."""
    from collections import Counter

    from tools.dev.pytest_resource_history import WorkerResourceHistory

    args = runner._parse_args([
        "--inventory-json", "inventory.json", "--summary-json", "summary.json",
        "--workers", "6", "--heavy-workers", "2", "--max-rss-mib", "2048",
    ])
    light = ("light-normal-b.py", *exclusive_input, "light-normal-a.py")
    heavy = WorkerSpec("heavy-0", ("heavy-normal.py",))
    heavy_exclusive = WorkerSpec("heavy-exclusive-0", ("heavy-exclusive.py",))
    exclusive_paths = frozenset((*exclusive_input, "heavy-exclusive.py"))
    schedules = runner._build_schedules(
        args, {"light": light, "heavy": (*heavy.paths, *heavy_exclusive.paths)},
        dict.fromkeys((*light, *heavy.paths, *heavy_exclusive.paths), 1.0), 2,
        [(heavy,), (heavy_exclusive,)], WorkerResourceHistory(), exclusive_paths,
    )
    scheduled_paths = [path for specs, _limit in schedules for scheduled in specs for path in scheduled.spec.paths]
    assert Counter(scheduled_paths) == Counter((*light, *heavy.paths, *heavy_exclusive.paths))
    assert schedules[0][1] == 6
    assert schedules[1][1] == 2
    assert schedules[1][0][0].spec == heavy
    assert schedules[2][0][0].spec == heavy_exclusive
    light_exclusive_order = []
    for specs, limit in schedules:
        paths = [path for scheduled in specs for path in scheduled.spec.paths]
        if set(paths) & exclusive_paths:
            assert limit == 1
            assert len(specs) == 1
            assert len(paths) == 1
        if set(paths) & set(exclusive_input):
            light_exclusive_order.extend(paths)
    assert light_exclusive_order == sorted(exclusive_input)
    assert args.max_rss_mib == 2048


def test_nested_pytest_only_integration_function_requests_exclusive_resources():
    """Keep the lightweight observer tests independent of nested worker controls."""
    import ast

    path = Path(__file__).resolve().parents[3] / "tools/dev/tests/test_pytest_live_failures.py"
    marked = [
        node.name for node in ast.parse(path.read_text()).body
        if isinstance(node, ast.FunctionDef)
        and any(isinstance(marker, ast.Attribute) and marker.attr == "resource_serial" for marker in node.decorator_list)
    ]
    assert marked == ["test_live_failures_preserve_reports_and_emit_before_session_end"]


def test_all_light_exclusive_inventory_creates_no_empty_concurrent_wave():
    """An all-exclusive light inventory still executes each path exactly once."""
    from tools.dev.pytest_resource_history import WorkerResourceHistory

    args = runner._parse_args(["--inventory-json", "inventory.json", "--summary-json", "summary.json"])
    schedules = runner._build_schedules(
        args, {"light": ("b.py", "a.py"), "heavy": ()}, {"a.py": 1.0, "b.py": 1.0},
        2, [], WorkerResourceHistory(), frozenset({"a.py", "b.py"}),
    )
    assert [(specs[0].spec.paths, limit) for specs, limit in schedules] == [(("a.py",), 1), (("b.py",), 1)]
    assert all(len(specs) == 1 for specs, _limit in schedules)
