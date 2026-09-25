#!/usr/bin/env python3
"""Collect machine-readable pytest duration and contract metadata.

Layer: Tooling/gates.
Responsibility: observe pytest collection and execution without changing test
selection, assertions, or pass/fail semantics.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Final, TypeVar, cast

import pytest

_IMPORT_ROOT = Path(__file__).resolve().parents[1]
if not __package__ and str(_IMPORT_ROOT) not in sys.path:
    sys.path.insert(0, str(_IMPORT_ROOT))

if __package__:
    from scripts.pytest_cache_events import begin_cache_event_capture, finish_cache_event_capture
    from scripts.pytest_process_metrics import ChildUsageSnapshot, current_rss_kib
    from scripts.pytest_profile_merge import WorkerEvent, merge_worker_payloads
    from scripts.pytest_profile_rankings import profile_cost_rankings
    from scripts.pytest_source_state import (
        SOURCE_SNAPSHOT_ENV,
        SourceTreeSnapshot,
        profile_artifact_has_stable_source,
        source_tree_snapshot,
    )
    from scripts.pytest_test_inventory import record_for_item
    from scripts.pytest_test_record import TestRecord
else:
    from pytest_cache_events import begin_cache_event_capture, finish_cache_event_capture
    from pytest_process_metrics import ChildUsageSnapshot, current_rss_kib
    from pytest_profile_merge import WorkerEvent, merge_worker_payloads
    from pytest_profile_rankings import profile_cost_rankings
    from pytest_source_state import (
        SOURCE_SNAPSHOT_ENV,
        SourceTreeSnapshot,
        profile_artifact_has_stable_source,
        source_tree_snapshot,
    )
    from pytest_test_inventory import record_for_item
    from pytest_test_record import TestRecord

REPO_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
SCHEMA_VERSION: Final[int] = 11
_HookFunction = TypeVar("_HookFunction", bound=Callable[..., object])
_HOOK_IMPL = cast(Callable[[_HookFunction], _HookFunction], pytest.hookimpl)
_OPTIONAL_HOOK_IMPL = cast(Callable[[_HookFunction], _HookFunction], pytest.hookimpl(optionalhook=True))


class PytestProfilePlugin:
    """Observe pytest events and write a deterministic JSON profile."""

    def __init__(self) -> None:
        self.records: dict[str, TestRecord] = {}
        self.started_at = time.monotonic()
        self.profile_path: Path | None = None
        self.exit_status: int | None = None
        self.worker_events: list[WorkerEvent] = []
        self.worker_id: str | None = None
        self.run_id = "serial"
        self.source_snapshot_start: SourceTreeSnapshot | None = None
        self.child_usage_starts: dict[str, ChildUsageSnapshot] = {}
        self.cache_event_paths: dict[str, Path] = {}

    @_HOOK_IMPL
    def pytest_configure(self, config: pytest.Config) -> None:
        """Capture the configured output path from the process environment."""
        self.profile_path = Path(os.environ.get("PYTEST_PROFILE_JSON", ".cache/pytest/profile.json"))
        self.worker_id = os.environ.get("PYTEST_XDIST_WORKER")
        self.run_id = os.environ.get("PYTEST_PROFILE_RUN_ID", "serial")
        raw_source_snapshot = os.environ.get(SOURCE_SNAPSHOT_ENV)
        self.source_snapshot_start = (
            SourceTreeSnapshot.from_json(raw_source_snapshot) if raw_source_snapshot is not None else None
        )

    @_HOOK_IMPL
    def pytest_collection_modifyitems(self, items: list[pytest.Item]) -> None:
        """Record every collected node before execution begins."""
        self.records = {item.nodeid: record_for_item(item) for item in items}

    @_HOOK_IMPL
    def pytest_runtest_logstart(self, nodeid: str, location: tuple[str, int | None, str]) -> None:
        """Snapshot cumulative child CPU before one complete test protocol."""

        del location
        output_path = self._output_path()
        if output_path is not None:
            worker_id = self.worker_id or "serial"
            self.cache_event_paths[nodeid] = begin_cache_event_capture(
                output_path,
                self.run_id,
                worker_id,
                nodeid,
            )
        snapshot = ChildUsageSnapshot.capture()
        if snapshot is not None:
            self.child_usage_starts[nodeid] = snapshot

    @_HOOK_IMPL
    def pytest_runtest_logfinish(self, nodeid: str, location: tuple[str, int | None, str]) -> None:
        """Attribute cumulative child-CPU delta to one completed test protocol."""

        del location
        event_path = self.cache_event_paths.pop(nodeid, None)
        cache_summary = finish_cache_event_capture(event_path) if event_path is not None else None
        earlier = self.child_usage_starts.pop(nodeid, None)
        current = ChildUsageSnapshot.capture()
        record = self.records.get(nodeid)
        if record is None:
            return
        if cache_summary is not None:
            record.cache_keys = list(cache_summary.keys)
            record.cache_operations = [operation.as_dict() for operation in cache_summary.operations]
            record.cache_hit_count = cache_summary.hit_count
            record.cache_miss_count = cache_summary.miss_count
            record.cache_invalid_count = cache_summary.invalid_count
            record.cache_store_count = cache_summary.store_count
            record.cache_store_failed_count = cache_summary.store_failed_count
            record.validation_statuses = list(cache_summary.validation_statuses)
        if earlier is not None and current is not None:
            delta = current.delta_since(earlier)
            record.record_child_cpu(user_seconds=delta.user_seconds, system_seconds=delta.system_seconds)

    @_HOOK_IMPL
    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        """Accumulate phase duration and terminal outcome evidence."""
        record = self.records.get(report.nodeid)
        if record is None:
            return
        self._record_rss_sample(record, report)
        duration = float(report.duration)
        if report.when == "setup":
            record.setup_seconds += duration
        elif report.when == "call":
            record.call_seconds += duration
        elif report.when == "teardown":
            record.teardown_seconds += duration
        self._record_outcome(record, report)

    @staticmethod
    def _record_rss_sample(record: TestRecord, report: pytest.TestReport) -> None:
        """Track start/peak/finish RSS evidence for one phase report."""
        rss_kib = current_rss_kib()
        if rss_kib is None:
            return
        if record.rss_start_kib is None:
            record.rss_start_kib = rss_kib
        record.rss_peak_kib = max(record.rss_peak_kib or 0, rss_kib)
        if report.when == "teardown":
            record.rss_finish_kib = rss_kib

    @staticmethod
    def _record_outcome(record: TestRecord, report: pytest.TestReport) -> None:
        """Accumulate terminal outcome flags for one phase report."""
        if report.failed:
            record.failure_count += 1
        if report.skipped:
            record.was_skipped = True
        # Dynamic third-party pytest boundary: older reports omit ``wasxfail``.
        if getattr(report, "wasxfail", False):
            record.was_xfailed = True
        if report.when == "call" or (report.when == "setup" and report.skipped):
            record.outcome = str(report.outcome)

    @_OPTIONAL_HOOK_IMPL
    def pytest_testnodedown(self, node: object, error: object | None) -> None:
        """Record exits across the dynamic third-party xdist worker boundary."""

        # Dynamic third-party xdist boundary: worker controllers are plugin-owned objects.
        gateway = getattr(node, "gateway", None)
        worker_id = str(getattr(gateway, "id", "unknown"))
        worker_output = getattr(node, "workeroutput", {})
        raw_exit_status = worker_output.get("exitstatus") if isinstance(worker_output, dict) else None
        exit_status = int(raw_exit_status) if isinstance(raw_exit_status, int) else None
        self.worker_events.append(
            WorkerEvent(
                worker_id=worker_id,
                exit_status=exit_status,
                error=None if error is None else str(error),
            )
        )

    def _output_path(self) -> Path | None:
        """Return the resolved profile output path."""

        if self.profile_path is None:
            return None
        return self.profile_path if self.profile_path.is_absolute() else REPO_ROOT / self.profile_path

    def _local_payload(self, session: pytest.Session) -> dict[str, object]:
        """Build this process's deterministic profile payload."""
        records = sorted(
            (record.as_dict() for record in self.records.values()),
            key=lambda record: (-float(record["total_seconds"]), str(record["nodeid"])),
        )
        payload: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "exit_status": self.exit_status,
            "elapsed_seconds": time.monotonic() - self.started_at,
            "pytest_args": list(session.config.invocation_params.args),
            "worker_id": self.worker_id,
            "collected_count": len(self.records),
            "records": records,
            "rankings": profile_cost_rankings(records),
        }
        if self.worker_id is None:
            source_snapshot_finish = source_tree_snapshot(REPO_ROOT)
            payload["source_state"] = {
                "start": self.source_snapshot_start.as_dict() if self.source_snapshot_start is not None else None,
                "finish": source_snapshot_finish.as_dict(),
                "stable": (
                    self.source_snapshot_start.is_stable_with(source_snapshot_finish)
                    if self.source_snapshot_start is not None
                    else False
                ),
            }
        return payload

    def _worker_fragment_path(self, output_path: Path, worker_id: str) -> Path:
        """Return the run-isolated fragment path for one xdist worker."""

        return output_path.with_name(f".{output_path.name}.{self.run_id}.{worker_id}.json")

    @_HOOK_IMPL
    def pytest_sessionfinish(self, session: pytest.Session, exitstatus: int) -> None:
        """Write the profile even when pytest reports a failure."""
        self.exit_status = int(exitstatus)
        output_path = self._output_path()
        if output_path is None:
            return
        output_path.parent.mkdir(parents=True, exist_ok=True)
        payload = self._local_payload(session)
        if self.worker_id is not None:
            output_path = self._worker_fragment_path(output_path, self.worker_id)
        elif self.worker_events or any(output_path.parent.glob(f".{output_path.name}.{self.run_id}.*.json")):
            payload = merge_worker_payloads(output_path, self.run_id, payload, self.worker_events)
        output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


_PLUGIN = PytestProfilePlugin()


@_HOOK_IMPL
def pytest_configure(config: pytest.Config) -> None:
    """Configure the process-local profile observer."""

    _PLUGIN.pytest_configure(config)


@_HOOK_IMPL
def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Record collection in the process-local profile observer."""

    _PLUGIN.pytest_collection_modifyitems(items)


@_HOOK_IMPL
def pytest_runtest_logstart(nodeid: str, location: tuple[str, int | None, str]) -> None:
    """Snapshot child CPU before one test protocol."""

    _PLUGIN.pytest_runtest_logstart(nodeid, location)


@_HOOK_IMPL
def pytest_runtest_logfinish(nodeid: str, location: tuple[str, int | None, str]) -> None:
    """Attribute child CPU after one test protocol."""

    _PLUGIN.pytest_runtest_logfinish(nodeid, location)


@_HOOK_IMPL
def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    """Record one test phase in the process-local profile observer."""

    _PLUGIN.pytest_runtest_logreport(report)


@_OPTIONAL_HOOK_IMPL
def pytest_testnodedown(node: object, error: object | None) -> None:
    """Record one xdist worker shutdown in the controller observer."""

    _PLUGIN.pytest_testnodedown(node, error)


@_HOOK_IMPL
def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Write or merge the process-local profile artifact."""

    _PLUGIN.pytest_sessionfinish(session, exitstatus)


def _parse_args(argv: list[str]) -> tuple[argparse.Namespace, list[str]]:
    """Parse only profile-tool options and preserve the remaining pytest args."""
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--profile-json", default=".cache/pytest/profile.json")
    return parser.parse_known_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run pytest with the non-invasive profiling plugin."""
    raw_args = list(sys.argv[1:] if argv is None else argv)
    parsed, pytest_args = _parse_args(raw_args)
    os.environ["PYTEST_PROFILE_JSON"] = parsed.profile_json
    os.environ["PYTEST_PROFILE_RUN_ID"] = uuid.uuid4().hex
    os.environ[SOURCE_SNAPSHOT_ENV] = source_tree_snapshot(REPO_ROOT).to_json()
    python_path = os.environ.get("PYTHONPATH", "")
    os.environ["PYTHONPATH"] = os.pathsep.join(part for part in (str(REPO_ROOT), python_path) if part)
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    pytest_status = int(pytest.main(["-p", "scripts.pytest_profile", *pytest_args]))
    if pytest_status != 0:
        return pytest_status
    profile_path = Path(parsed.profile_json)
    resolved_profile_path = profile_path if profile_path.is_absolute() else REPO_ROOT / profile_path
    if not profile_artifact_has_stable_source(resolved_profile_path):
        print(
            f"pytest profile rejected: source tree changed during execution ({resolved_profile_path})",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
