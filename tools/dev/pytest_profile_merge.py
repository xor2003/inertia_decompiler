"""Merge xdist worker fragments for pytest profiling.

Layer: Tooling/gates.
Responsibility: preserve one executed record per node and aggregate worker
shutdown evidence into the controller profile artifact.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .pytest_profile_rankings import profile_cost_rankings


@dataclass(frozen=True, slots=True)
class WorkerEvent:
    """Record one xdist worker shutdown or crash notification."""

    worker_id: str
    exit_status: int | None
    error: str | None

    def as_dict(self) -> dict[str, object]:
        """Serialize stable worker shutdown evidence."""

        return {"worker_id": self.worker_id, "exit_status": self.exit_status, "error": self.error}


def _total_seconds(record: dict[str, object]) -> float:
    """Return one record's numeric total duration."""

    raw_seconds = record.get("total_seconds", 0.0)
    return float(raw_seconds) if isinstance(raw_seconds, int | float) else 0.0


def merge_worker_payloads(
    output_path: Path,
    run_id: str,
    local_payload: dict[str, object],
    worker_events: list[WorkerEvent],
) -> dict[str, object]:
    """Merge run-isolated fragments into one deterministic controller artifact."""

    fragments = sorted(output_path.parent.glob(f".{output_path.name}.{run_id}.*.json"))
    records: dict[str, dict[str, object]] = {}
    worker_results: list[dict[str, object]] = []
    for fragment in fragments:
        payload = json.loads(fragment.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            continue
        worker_results.append(
            {
                "worker_id": payload.get("worker_id"),
                "exit_status": payload.get("exit_status"),
                "elapsed_seconds": payload.get("elapsed_seconds"),
            }
        )
        raw_records = payload.get("records", [])
        if not isinstance(raw_records, list):
            continue
        for raw_record in raw_records:
            if not isinstance(raw_record, dict) or not isinstance(raw_record.get("nodeid"), str):
                continue
            nodeid = raw_record["nodeid"]
            previous = records.get(nodeid)
            if previous is None or (previous.get("outcome") == "not-run" and raw_record.get("outcome") != "not-run"):
                records[nodeid] = raw_record
    for fragment in fragments:
        fragment.unlink(missing_ok=True)
    merged_records = sorted(records.values(), key=lambda record: (-_total_seconds(record), str(record.get("nodeid", ""))))
    local_payload["collected_count"] = len(records)
    local_payload["records"] = merged_records
    local_payload["rankings"] = profile_cost_rankings(merged_records)
    local_payload["worker_results"] = sorted(worker_results, key=lambda item: str(item.get("worker_id", "")))
    local_payload["worker_events"] = [event.as_dict() for event in sorted(worker_events, key=lambda item: item.worker_id)]
    return local_payload
