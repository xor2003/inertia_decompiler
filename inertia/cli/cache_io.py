"""Read and write content-addressed decompiler cache records atomically.

Layer: CLI/fallback/reporting.
Responsibility: own JSON cache I/O and optionally emit typed profile events
without changing cache identity, payloads, or normal diagnostics.
"""

from __future__ import annotations

import json
import os
import tempfile
from enum import StrEnum
from pathlib import Path

CACHE_OBSERVATION_PATH_ENV: str = "PYTEST_INERTIA_CACHE_EVENTS"


class CacheIoAction(StrEnum):
    """Typed outcomes for one content-addressed cache operation."""

    HIT = "hit"
    MISS = "miss"
    INVALID = "invalid"
    STORE = "store"
    STORE_FAILED = "store-failed"


class ValidationObservationStatus(StrEnum):
    """Typed validation statuses preserved in accepted cache records."""

    STABLE = "stable"
    PASSED = "passed"
    CHANGED = "changed"
    FAILED = "failed"
    UNCOLLECTED = "uncollected"


def _validation_statuses(payload: dict[str, object] | None) -> tuple[ValidationObservationStatus, ...]:
    """Extract recognized structured stage statuses from one cache payload."""
    if payload is None:
        return ()
    tail_validation = payload.get("tail_validation")
    if not isinstance(tail_validation, dict):
        return ()
    known = {status.value: status for status in ValidationObservationStatus}
    statuses: set[ValidationObservationStatus] = set()
    for stage in tail_validation.values():
        if not isinstance(stage, dict):
            continue
        raw_status = stage.get("status")
        if isinstance(raw_status, str) and raw_status in known:
            statuses.add(known[raw_status])
    return tuple(sorted(statuses, key=lambda status: status.value))


def _emit_cache_observation(
    namespace: str,
    path: Path,
    action: CacheIoAction,
    payload: dict[str, object] | None = None,
    key_context: dict[str, object] | None = None,
) -> None:
    """Append one bounded profile event when explicitly requested by pytest."""
    raw_event_path = os.environ.get(CACHE_OBSERVATION_PATH_ENV)
    if not raw_event_path:
        return
    event_path = Path(raw_event_path)
    event = {
        "schema_version": 2,
        "pid": os.getpid(),
        "namespace": namespace,
        "key": path.stem,
        "action": action.value,
        "validation_statuses": [status.value for status in _validation_statuses(payload)],
    }
    if key_context is not None:
        event["key_context"] = key_context
    encoded = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    descriptor: int | None = None
    try:
        event_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(event_path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o644)
        os.write(descriptor, encoded)
    except OSError:
        return
    finally:
        if descriptor is not None:
            os.close(descriptor)


def load_cache_json_path(
    namespace: str,
    path: Path,
    *,
    key_context: dict[str, object] | None = None,
) -> dict[str, object] | None:
    """Load one object cache record and emit its typed observation outcome."""
    try:
        decoded = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        _emit_cache_observation(namespace, path, CacheIoAction.MISS, key_context=key_context)
        return None
    if not isinstance(decoded, dict):
        _emit_cache_observation(namespace, path, CacheIoAction.INVALID, key_context=key_context)
        return None
    payload: dict[str, object] = decoded
    _emit_cache_observation(namespace, path, CacheIoAction.HIT, payload, key_context)
    return payload


def store_cache_json_path(
    namespace: str,
    path: Path,
    payload: dict[str, object],
    *,
    key_context: dict[str, object] | None = None,
) -> None:
    """Atomically store one object cache record and emit the resulting outcome."""
    temporary_path: Path | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            json.dump(payload, stream, sort_keys=True)
            stream.write("\n")
        os.replace(temporary_path, path)
    except OSError:
        _emit_cache_observation(namespace, path, CacheIoAction.STORE_FAILED, payload, key_context)
        return
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    _emit_cache_observation(namespace, path, CacheIoAction.STORE, payload, key_context)
