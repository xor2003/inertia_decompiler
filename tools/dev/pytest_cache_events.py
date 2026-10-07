"""Capture typed decompiler cache events for one pytest node.

Layer: Tooling/gates.
Responsibility: provide isolated event paths to child processes and summarize
cache keys, outcomes, and structured validation statuses after each test.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from inertia.cli.cache_io import (
    CACHE_OBSERVATION_PATH_ENV,
    CacheIoAction,
    ValidationObservationStatus,
)


@dataclass(frozen=True, slots=True)
class CacheKeyObservation:
    """Aggregate outcomes and validation statuses for one exact cache key."""

    key: str
    hit_count: int = 0
    miss_count: int = 0
    invalid_count: int = 0
    store_count: int = 0
    store_failed_count: int = 0
    validation_statuses: tuple[str, ...] = ()
    context: dict[str, object] | None = None

    def as_dict(self) -> dict[str, object]:
        """Serialize one exact-key observation."""

        return {
            "key": self.key,
            "hit_count": self.hit_count,
            "miss_count": self.miss_count,
            "invalid_count": self.invalid_count,
            "store_count": self.store_count,
            "store_failed_count": self.store_failed_count,
            "validation_statuses": list(self.validation_statuses),
            "context": self.context,
        }


@dataclass(frozen=True, slots=True)
class CacheEventSummary:
    """Aggregate typed cache observations emitted during one test protocol."""

    keys: tuple[str, ...] = ()
    hit_count: int = 0
    miss_count: int = 0
    invalid_count: int = 0
    store_count: int = 0
    store_failed_count: int = 0
    validation_statuses: tuple[str, ...] = ()
    operations: tuple[CacheKeyObservation, ...] = ()


def begin_cache_event_capture(profile_path: Path, run_id: str, worker_id: str, nodeid: str) -> Path:
    """Create one deterministic run-isolated event path and export it to children."""

    node_digest = hashlib.sha256(nodeid.encode("utf-8")).hexdigest()
    event_path = profile_path.parent / f".{profile_path.name}.events" / run_id / worker_id / f"{node_digest}.jsonl"
    event_path.unlink(missing_ok=True)
    os.environ[CACHE_OBSERVATION_PATH_ENV] = str(event_path)
    return event_path


def _load_event_objects(event_path: Path) -> list[dict[str, object]]:
    """Load valid event objects while refusing malformed or partial lines."""

    try:
        lines = event_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    events: list[dict[str, object]] = []
    for line in lines:
        try:
            decoded = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(decoded, dict) and decoded.get("schema_version") in {1, 2}:
            events.append(decoded)
    return events


def finish_cache_event_capture(event_path: Path) -> CacheEventSummary:
    """Summarize and remove one node's cache event artifact."""

    if os.environ.get(CACHE_OBSERVATION_PATH_ENV) == str(event_path):
        os.environ.pop(CACHE_OBSERVATION_PATH_ENV, None)
    events = _load_event_objects(event_path)
    event_path.unlink(missing_ok=True)
    for directory in (event_path.parent, event_path.parent.parent, event_path.parent.parent.parent):
        with contextlib.suppress(OSError):
            directory.rmdir()
    action_counts: dict[str, Counter[str]] = {}
    statuses_by_key: dict[str, set[str]] = {}
    contexts_by_key: dict[str, dict[str, object]] = {}
    known_statuses = {item.value for item in ValidationObservationStatus}
    for event in events:
        namespace = event.get("namespace")
        key = event.get("key")
        action = event.get("action")
        if not isinstance(namespace, str) or not isinstance(key, str) or not isinstance(action, str):
            continue
        label = f"{namespace}:{key}"
        action_counts.setdefault(label, Counter())[action] += 1
        raw_statuses = event.get("validation_statuses")
        if isinstance(raw_statuses, list):
            statuses_by_key.setdefault(label, set()).update(
                status for status in raw_statuses if isinstance(status, str) and status in known_statuses
            )
        raw_context = event.get("key_context")
        if isinstance(raw_context, dict):
            contexts_by_key.setdefault(label, raw_context)
    operations = tuple(
        CacheKeyObservation(
            key=key,
            hit_count=counts[CacheIoAction.HIT.value],
            miss_count=counts[CacheIoAction.MISS.value],
            invalid_count=counts[CacheIoAction.INVALID.value],
            store_count=counts[CacheIoAction.STORE.value],
            store_failed_count=counts[CacheIoAction.STORE_FAILED.value],
            validation_statuses=tuple(sorted(statuses_by_key.get(key, set()))),
            context=contexts_by_key.get(key),
        )
        for key, counts in sorted(action_counts.items())
    )
    return CacheEventSummary(
        keys=tuple(operation.key for operation in operations),
        hit_count=sum(operation.hit_count for operation in operations),
        miss_count=sum(operation.miss_count for operation in operations),
        invalid_count=sum(operation.invalid_count for operation in operations),
        store_count=sum(operation.store_count for operation in operations),
        store_failed_count=sum(operation.store_failed_count for operation in operations),
        validation_statuses=tuple(
            sorted({status for operation in operations for status in operation.validation_statuses})
        ),
        operations=operations,
    )
