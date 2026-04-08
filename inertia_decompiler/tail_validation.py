from __future__ import annotations

import hashlib
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from angr_platforms.X86_16.milestone_report import (
    cache_x86_16_tail_validation_detail_artifact,
    render_x86_16_tail_validation_console_summary,
)
from angr_platforms.X86_16.tail_validation import (
    build_x86_16_tail_validation_aggregate,
    extract_x86_16_tail_validation_snapshot,
    x86_16_tail_validation_snapshot_passed,
)


ROOT = Path(__file__).resolve().parents[1]
TAIL_VALIDATION_STDERR_PREFIX = "[tail-validation] "
TAIL_VALIDATION_METADATA_ENV = "INERTIA_TAIL_VALIDATION_STDERR_JSON"
TAIL_VALIDATION_METADATA_PREFIX = "@@INERTIA_TAIL_VALIDATION@@ "
TAIL_VALIDATION_CONSOLE_CACHE_DIR = ROOT / "angr_platforms" / ".cache" / "decompile_cli"
TAIL_VALIDATION_DETAIL_CACHE_DIR = ROOT / "angr_platforms" / ".cache" / "tail_validation_details"
TAIL_VALIDATION_FALLBACK_PROJECT_SNAPSHOT_KINDS = frozenset(
    {"sidecar_slice", "peer_sidecar", "partial_timeout"}
)
TAIL_VALIDATION_ENABLE_ENV = "INERTIA_ENABLE_TAIL_VALIDATION"


def parse_env_bool(value: str | None) -> bool | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return None


def tail_validation_runtime_enabled(project) -> bool:
    return bool(getattr(project, "_inertia_tail_validation_enabled", True))


def set_tail_validation_runtime_enabled(project, enabled: bool) -> None:
    setattr(project, "_inertia_tail_validation_enabled", bool(enabled))


def inherit_tail_validation_runtime_policy(project, source_project) -> None:
    set_tail_validation_runtime_enabled(project, tail_validation_runtime_enabled(source_project))


def tail_validation_enabled_for_run(binary_path: Path | None, *, proc: str | None = None) -> bool:
    forced = parse_env_bool(os.environ.get(TAIL_VALIDATION_ENABLE_ENV))
    if forced is not None:
        return forced
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return True
    if os.environ.get(TAIL_VALIDATION_METADATA_ENV) == "1":
        return True
    suffix = binary_path.suffix.lower() if isinstance(binary_path, Path) else ""
    if proc is not None or suffix == ".cod":
        return True
    return False


def tail_validation_record_for_result(item: Any, result: Any) -> dict[str, object] | None:
    snapshot = getattr(result, "tail_validation", None)
    if not isinstance(snapshot, dict) or not snapshot:
        return None
    function = getattr(result, "function", None) or getattr(item, "function", None)
    return {
        "function_addr": getattr(function, "addr", 0),
        "function_name": getattr(function, "name", "sub"),
        **snapshot,
    }


def collect_tail_validation_records(
    function_tasks: Sequence[Any],
    result_map: Mapping[int, Any],
) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for item in function_tasks:
        result = result_map.get(getattr(item, "index"))
        if result is None:
            continue
        record = tail_validation_record_for_result(item, result)
        if record is not None:
            records.append(record)
    return records


def tail_validation_snapshot_for_function_run(project, function) -> dict[str, object]:
    snapshot = extract_x86_16_tail_validation_snapshot(getattr(function, "info", None))
    if snapshot:
        return snapshot
    fallback_snapshot = getattr(project, "_inertia_last_tail_validation_snapshot", None)
    if isinstance(fallback_snapshot, dict):
        return dict(fallback_snapshot)
    return {}


def tail_validation_snapshot_for_fallback(
    project,
    function,
    *,
    allow_project_fallback: bool,
) -> dict[str, object]:
    current_snapshot = getattr(project, "_inertia_partial_tail_validation_snapshot", None)
    if isinstance(current_snapshot, dict):
        setattr(project, "_inertia_partial_tail_validation_snapshot", None)
        return dict(current_snapshot)
    snapshot = extract_x86_16_tail_validation_snapshot(getattr(function, "info", None))
    if snapshot:
        return snapshot
    if not allow_project_fallback:
        return {}
    fallback_snapshot = getattr(project, "_inertia_last_tail_validation_snapshot", None)
    if isinstance(fallback_snapshot, dict):
        return dict(fallback_snapshot)
    return {}


def tail_validation_fallback_allows_project_snapshot(kind: str) -> bool:
    return kind in TAIL_VALIDATION_FALLBACK_PROJECT_SNAPSHOT_KINDS


def emit_tail_validation_console_summary(
    function_tasks: Sequence[Any],
    result_map: Mapping[int, Any],
    *,
    binary_path: Path | None = None,
) -> None:
    emitted_any = False
    for item in function_tasks:
        project = getattr(getattr(item, "function", None), "project", None)
        if project is not None:
            if not tail_validation_runtime_enabled(project):
                return
            break
    records = collect_tail_validation_records(function_tasks, result_map)
    scanned = len(function_tasks)
    aggregate = build_x86_16_tail_validation_aggregate(records, scanned=scanned)
    surface = dict(aggregate.get("surface", {}) or {})
    console_cache_path = tail_validation_console_cache_path(binary_path, function_tasks)
    detail_cache_path = tail_validation_detail_cache_path(binary_path, function_tasks)
    rendered = render_x86_16_tail_validation_console_summary(surface, cache_path=console_cache_path)
    detail_artifact = cache_x86_16_tail_validation_detail_artifact(surface, cache_path=detail_cache_path)
    for line in rendered.get("lines", ()):
        if isinstance(line, str) and line:
            print(f"{TAIL_VALIDATION_STDERR_PREFIX}{line}", file=sys.stderr)
            emitted_any = True
    if surface.get("severity") != "clean":
        if detail_cache_path is not None:
            print(f"{TAIL_VALIDATION_STDERR_PREFIX}detail artifact {detail_cache_path}", file=sys.stderr)
            emitted_any = True
        if rendered.get("cache_hit"):
            print(f"{TAIL_VALIDATION_STDERR_PREFIX}console summary cache hit", file=sys.stderr)
            emitted_any = True
        if detail_artifact.get("cache_hit"):
            print(f"{TAIL_VALIDATION_STDERR_PREFIX}detail artifact cache hit", file=sys.stderr)
            emitted_any = True
    if os.environ.get(TAIL_VALIDATION_METADATA_ENV) == "1":
        payload = {
            "scanned": scanned,
            "records": records,
            "summary": dict(aggregate.get("summary", {}) or {}),
            "surface": surface,
            "console_cache_hit": bool(rendered.get("cache_hit")),
            "console_cache_path": str(console_cache_path) if console_cache_path is not None else None,
            "detail_cache_hit": bool(detail_artifact.get("cache_hit")),
            "detail_cache_path": str(detail_cache_path) if detail_cache_path is not None else None,
        }
        print(
            f"{TAIL_VALIDATION_METADATA_PREFIX}{json.dumps(payload, sort_keys=True)}",
            file=sys.stderr,
        )
        emitted_any = True
    if emitted_any:
        sys.stderr.flush()


def tail_validation_cache_label(binary_path: Path | None, function_tasks: Sequence[Any]) -> str | None:
    if binary_path is None:
        return None
    resolved = Path(binary_path).resolve()
    base_name = resolved.stem or resolved.name or "binary"
    labels: list[str] = []
    for item in function_tasks:
        function = getattr(item, "function", None)
        name = getattr(function, "name", None)
        addr = getattr(function, "addr", None)
        if isinstance(name, str) and name:
            label = name
        elif isinstance(addr, int):
            label = f"sub_{addr:x}"
        else:
            label = "function"
        if isinstance(addr, int):
            label = f"{label}@{addr:x}"
        labels.append(label)
    payload = f"{resolved}\n" + "\n".join(labels or ["whole-binary"])
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    if len(labels) == 1:
        return f"{base_name}.{digest}"
    return f"{base_name}.{max(len(labels), 1)}f.{digest}"


def tail_validation_console_cache_path(
    binary_path: Path | None,
    function_tasks: Sequence[Any],
) -> Path | None:
    label = tail_validation_cache_label(binary_path, function_tasks)
    if label is None:
        return None
    return TAIL_VALIDATION_CONSOLE_CACHE_DIR / f"{label}.tail_validation_console.json"


def tail_validation_detail_cache_path(
    binary_path: Path | None,
    function_tasks: Sequence[Any],
) -> Path | None:
    label = tail_validation_cache_label(binary_path, function_tasks)
    if label is None:
        return None
    return TAIL_VALIDATION_DETAIL_CACHE_DIR / f"{label}.tail_validation_surface.json"


def tail_validation_display_status(
    snapshot: Mapping[str, object] | None,
    *,
    expected_stages: Sequence[str] = ("structuring", "postprocess"),
) -> str:
    if not isinstance(snapshot, Mapping) or not snapshot:
        return "uncollected"
    if x86_16_tail_validation_snapshot_passed(dict(snapshot), expected_stages=expected_stages):
        return "passed"
    if any(bool(stage.get("changed")) for stage in snapshot.values() if isinstance(stage, Mapping)):
        return "changed"
    return "unknown"
