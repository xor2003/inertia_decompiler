"""Pytest worker plugin for deterministic pre-execution sharding.

Layer: Tooling/gates.
Responsibility: assign collected nodes to one shard while preserving atomic
xdist groups and publish a structured worker report.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

SHARD_COUNT_ENV: str = "PYTEST_PARTITION_COUNT"
SHARD_INDEX_ENV: str = "PYTEST_PARTITION_INDEX"
SHARD_REPORT_ENV: str = "PYTEST_PARTITION_REPORT"
SHARD_WEIGHTS_ENV: str = "PYTEST_PARTITION_WEIGHTS"
SHARD_ACTIVITY_ENV: str = "PYTEST_PARTITION_ACTIVITY"


@dataclass(frozen=True, slots=True)
class ShardWorkItem:
    """One collected pytest node with an atomic scheduling group and weight."""

    nodeid: str
    group: str
    weight: float


@dataclass(frozen=True, slots=True)
class WorkerReport:
    """Structured result emitted by one independent pytest shard."""

    selected_nodeids: tuple[str, ...]
    outcomes: dict[str, str]
    durations: dict[str, float]
    exit_status: int
    failure_details: dict[str, str] = field(default_factory=dict)
    skip_details: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        """Serialize the worker result for the controller."""

        return {
            "selected_nodeids": list(self.selected_nodeids),
            "outcomes": dict(sorted(self.outcomes.items())),
            "durations": dict(sorted(self.durations.items())),
            "exit_status": self.exit_status,
            "failure_details": dict(sorted(self.failure_details.items())),
            "skip_details": dict(sorted(self.skip_details.items())),
        }

    @classmethod
    def from_path(cls, path: Path) -> WorkerReport:
        """Read and validate one worker report."""

        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"worker report is not an object: {path}")
        nodeids = payload.get("selected_nodeids")
        outcomes = payload.get("outcomes")
        durations = payload.get("durations")
        exit_status = payload.get("exit_status")
        failure_details = payload.get("failure_details", {})
        skip_details = payload.get("skip_details", {})
        if not isinstance(nodeids, list) or not all(isinstance(value, str) for value in nodeids):
            raise ValueError(f"worker report has invalid node IDs: {path}")
        if not isinstance(outcomes, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in outcomes.items()
        ):
            raise ValueError(f"worker report has invalid outcomes: {path}")
        if not isinstance(durations, dict) or not all(
            isinstance(key, str) and isinstance(value, (int, float)) for key, value in durations.items()
        ):
            raise ValueError(f"worker report has invalid durations: {path}")
        if not isinstance(exit_status, int):
            raise ValueError(f"worker report has invalid exit status: {path}")
        if not isinstance(failure_details, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in failure_details.items()
        ):
            raise ValueError(f"worker report has invalid failure details: {path}")
        if not isinstance(skip_details, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in skip_details.items()
        ):
            raise ValueError(f"worker report has invalid skip details: {path}")
        return cls(
            selected_nodeids=tuple(nodeids),
            outcomes=dict(outcomes),
            durations={key: float(value) for key, value in durations.items()},
            exit_status=exit_status,
            failure_details=dict(failure_details),
            skip_details=dict(skip_details),
        )


@dataclass(frozen=True, slots=True)
class WorkerActivity:
    """Last pytest node started by one independently monitored worker."""

    nodeid: str
    pid: int

    def as_dict(self) -> dict[str, object]:
        """Serialize the active-node checkpoint."""

        return {"nodeid": self.nodeid, "pid": self.pid}

    @classmethod
    def from_path(cls, path: Path) -> WorkerActivity:
        """Read and validate one active-node checkpoint."""

        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(f"worker activity is not an object: {path}")
        nodeid = payload.get("nodeid")
        pid = payload.get("pid")
        if not isinstance(nodeid, str) or not isinstance(pid, int):
            raise ValueError(f"worker activity fields are invalid: {path}")
        return cls(nodeid=nodeid, pid=pid)


def assign_work_items(items: Sequence[ShardWorkItem], shard_count: int) -> dict[str, int]:
    """Assign atomic groups greedily while preserving deterministic ordering."""

    if shard_count < 1:
        raise ValueError("shard_count must be positive")
    grouped: dict[str, list[ShardWorkItem]] = defaultdict(list)
    for item in items:
        grouped[item.group].append(item)
    group_weights = {
        group: sum(max(item.weight, 0.001) for item in group_items) for group, group_items in grouped.items()
    }
    shard_weights = [0.0] * shard_count
    assignments: dict[str, int] = {}
    for group in sorted(grouped, key=lambda value: (-group_weights[value], value)):
        shard = min(range(shard_count), key=lambda index: (shard_weights[index], index))
        for item in grouped[group]:
            assignments[item.nodeid] = shard
        shard_weights[shard] += group_weights[group]
    return assignments


def atomic_json_write(path: Path, payload: dict[str, object]) -> None:
    """Write structured state atomically without leaving partial reports."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.tmp-{os.getpid()}")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _xdist_group(item: object) -> str:
    """Return the third-party pytest marker group or the node's own identity."""

    dynamic_item = cast(Any, item)
    nodeid = str(dynamic_item.nodeid)
    markers = tuple(dynamic_item.iter_markers(name="xdist_group"))
    if markers and markers[0].args and isinstance(markers[0].args[0], str):
        return f"xdist:{markers[0].args[0]}"
    return f"node:{nodeid}"


_DURATIONS: dict[str, float] = {}
_OUTCOMES: dict[str, str] = {}
_FAILURE_DETAILS: dict[str, str] = {}
_SKIP_DETAILS: dict[str, str] = {}
_FAILURE_DETAIL_MAX_CHARS: int = 16_000


def _skip_detail(report: object) -> str:
    """Return pytest's structured skip reason across its dynamic report boundary."""

    longrepr = cast(Any, report).longrepr
    if isinstance(longrepr, tuple) and len(longrepr) >= 3 and isinstance(longrepr[2], str):
        return longrepr[2]
    return str(longrepr)


def pytest_collection_modifyitems(config: object, items: list[object]) -> None:
    """Select one deterministic shard after lane-local collection."""

    raw_count = os.environ.get(SHARD_COUNT_ENV)
    raw_index = os.environ.get(SHARD_INDEX_ENV)
    weights_path = os.environ.get(SHARD_WEIGHTS_ENV)
    if raw_count is None or raw_index is None or weights_path is None:
        return
    shard_count = int(raw_count)
    shard_index = int(raw_index)
    weights_payload = json.loads(Path(weights_path).read_text(encoding="utf-8"))
    weights = weights_payload if isinstance(weights_payload, dict) else {}
    work_items = [
        ShardWorkItem(
            nodeid=str(cast(Any, item).nodeid),
            group=_xdist_group(item),
            weight=float(weights.get(str(cast(Any, item).nodeid), 1.0)),
        )
        for item in items
    ]
    assignments = assign_work_items(work_items, shard_count)
    selected = [item for item in items if assignments[str(cast(Any, item).nodeid)] == shard_index]
    deselected = [item for item in items if assignments[str(cast(Any, item).nodeid)] != shard_index]
    cast(Any, config).hook.pytest_deselected(items=deselected)
    items[:] = selected


def pytest_runtest_logreport(report: object) -> None:
    """Record typed per-node duration and final outcome facts."""

    dynamic_report = cast(Any, report)
    nodeid = str(dynamic_report.nodeid)
    _DURATIONS[nodeid] = _DURATIONS.get(nodeid, 0.0) + float(dynamic_report.duration)
    if bool(dynamic_report.failed):
        _OUTCOMES[nodeid] = "failed"
        longrepr_text = dynamic_report.longreprtext
        if not isinstance(longrepr_text, str):
            longrepr_text = str(dynamic_report.longrepr)
        if longrepr_text:
            _FAILURE_DETAILS.setdefault(nodeid, longrepr_text[-_FAILURE_DETAIL_MAX_CHARS:])
    elif bool(dynamic_report.skipped) and _OUTCOMES.get(nodeid) != "failed":
        _OUTCOMES[nodeid] = "skipped"
        _SKIP_DETAILS[nodeid] = _skip_detail(report)
    elif dynamic_report.when == "call" and bool(dynamic_report.passed):
        _OUTCOMES[nodeid] = "passed"


def pytest_runtest_logstart(nodeid: str, location: tuple[str, int | None, str]) -> None:
    """Publish the current node so resource aborts remain attributable."""

    del location
    activity_path = os.environ.get(SHARD_ACTIVITY_ENV)
    if activity_path is not None:
        atomic_json_write(Path(activity_path), WorkerActivity(nodeid=nodeid, pid=os.getpid()).as_dict())


def pytest_sessionfinish(session: object, exitstatus: int) -> None:
    """Publish one atomic structured shard report."""

    report_path = os.environ.get(SHARD_REPORT_ENV)
    if report_path is None:
        return
    # Dynamic pytest boundary: session owns the final post-deselection item list.
    selected_nodeids = tuple(str(item.nodeid) for item in cast(Any, session).items)
    report = WorkerReport(
        selected_nodeids=selected_nodeids,
        outcomes=dict(_OUTCOMES),
        durations=dict(_DURATIONS),
        exit_status=int(exitstatus),
        failure_details=dict(_FAILURE_DETAILS),
        skip_details=dict(_SKIP_DETAILS),
    )
    atomic_json_write(Path(report_path), report.as_dict())
