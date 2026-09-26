"""Tail-validation reporting helpers for CLI and batch decompilation runs.

Layer: CLI/fallback/reporting.
Responsibility: report collected tail-validation evidence without changing semantic verdicts.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import typing
from collections.abc import Iterable, Mapping, Sequence
from enum import Enum
from pathlib import Path
from typing import cast

from angr_platforms.X86_16.milestone_report import (
    cache_x86_16_tail_validation_detail_artifact,
    render_x86_16_tail_validation_console_summary,
)
from angr_platforms.X86_16.tail_validation import (
    build_x86_16_tail_validation_aggregate,
    extract_x86_16_tail_validation_snapshot,
    x86_16_tail_validation_snapshot_passed,
)

from inertia_decompiler.telemetry import annotate_current_span, trace_function

ROOT: Path = Path(__file__).resolve().parents[1]
TAIL_VALIDATION_STDERR_PREFIX: str = "[tail-validation] "
TAIL_VALIDATION_METADATA_ENV: str = "INERTIA_TAIL_VALIDATION_STDERR_JSON"
TAIL_VALIDATION_METADATA_PREFIX: str = "@@INERTIA_TAIL_VALIDATION@@ "
TAIL_VALIDATION_CONSOLE_CACHE_DIR: Path = ROOT / "angr_platforms" / ".cache" / "decompile_cli"
TAIL_VALIDATION_DETAIL_CACHE_DIR: Path = ROOT / "angr_platforms" / ".cache" / "tail_validation_details"
TAIL_VALIDATION_FALLBACK_PROJECT_SNAPSHOT_KINDS: frozenset[str] = frozenset({"sidecar_slice", "partial_timeout"})
TAIL_VALIDATION_ENABLE_ENV: str = "INERTIA_ENABLE_TAIL_VALIDATION"


class TailValidationDisplayStatus(Enum):
    """Display verdicts shown in decompiler attempt status lines."""

    PASSED = "passed"
    FAILED = "failed"
    UNCOLLECTED = "uncollected"


class TailValidationResultStatus(Enum):
    """Typed result statuses that affect tail-validation acceptance summaries."""

    VALIDATION_FAILED = "validation_failed"
    OTHER = "other"

    @classmethod
    def from_result_status(cls, raw_status: object) -> TailValidationResultStatus:
        """Normalize raw string or enum work-result statuses."""
        if isinstance(raw_status, Enum):
            raw_status = raw_status.value
        try:
            return cls(raw_status)
        except ValueError:
            return cls.OTHER


_TAIL_VALIDATION_STABLE_STATUSES = frozenset({"stable", "passed"})


def _dynamic_cli_attr(obj: object, name: str, default: object = None) -> object:
    # Dynamic CLI/angr compatibility boundary: work items, projects, and results are heterogeneous.
    return getattr(obj, name, default)


def _as_mapping(value: object) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return cast(Mapping[str, object], value)
    return {}


def _as_string_tuple(value: object) -> tuple[str, ...]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return tuple(item for item in value if isinstance(item, str) and item)
    return ()


def _as_int(value: object) -> int | None:
    return value if isinstance(value, int) else None


def _as_iterable(value: object) -> Iterable[object]:
    if isinstance(value, Iterable) and not isinstance(value, (str, bytes, bytearray)):
        return value
    return ()


def _has_acceptance_validation_failure(results: Iterable[object]) -> bool:
    for result in results:
        status = _dynamic_cli_attr(result, "status", None)
        snapshot = _dynamic_cli_attr(result, "tail_validation", None)
        snapshot_mapping = _as_mapping(snapshot)
        if (
            TailValidationResultStatus.from_result_status(status) is TailValidationResultStatus.VALIDATION_FAILED
            and not x86_16_tail_validation_snapshot_passed(snapshot_mapping if snapshot_mapping else None)
        ):
            return True
    return False


def parse_env_bool(value: str | None) -> bool | None:
    """Parse common environment boolean spellings."""
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    return None


def tail_validation_runtime_enabled(project: object) -> bool:
    """Return whether tail validation is enabled for a project object."""
    return bool(_dynamic_cli_attr(project, "_inertia_tail_validation_enabled", True))


def set_tail_validation_runtime_enabled(project: object, enabled: bool) -> None:
    """Set the runtime tail-validation policy on a project object."""
    typing.cast(typing.Any, project)._inertia_tail_validation_enabled = bool(enabled)


def inherit_tail_validation_runtime_policy(project: object, source_project: object) -> None:
    """Copy the tail-validation runtime policy between project objects."""
    set_tail_validation_runtime_enabled(project, tail_validation_runtime_enabled(source_project))


def tail_validation_enabled_for_run(binary_path: Path | None, *, proc: str | None = None) -> bool:
    """Enable semantic validation by default for executable and COD runs."""
    forced = parse_env_bool(os.environ.get(TAIL_VALIDATION_ENABLE_ENV))
    if forced is not None:
        return forced
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return True
    if os.environ.get(TAIL_VALIDATION_METADATA_ENV) == "1":
        return True
    suffix = binary_path.suffix.lower() if isinstance(binary_path, Path) else ""
    return bool(proc is not None or suffix in {".cod", ".exe"})


def _compute_cfg_hash_from_result(result: object, item: object) -> str | None:
    """Compute a lightweight CFG hash from function block addresses."""
    function = _dynamic_cli_attr(result, "function", None) or _dynamic_cli_attr(item, "function", None)
    block_addrs = _dynamic_cli_attr(function, "block_addrs_set", None)
    if not block_addrs:
        return None
    payload = ",".join(str(addr) for addr in sorted(_as_iterable(block_addrs), key=str))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def tail_validation_record_for_result(item: object, result: object) -> dict[str, object] | None:
    """Convert one function work result into a tail-validation record."""

    def _impl() -> dict[str, object]:
        snapshot = _dynamic_cli_attr(result, "tail_validation", None)
        identity = _tail_record_identity_8616(item, result)
        block_count = _dynamic_cli_attr(result, "block_count", None)
        byte_count = _dynamic_cli_attr(result, "byte_count", None)
        cfg_hash = _compute_cfg_hash_from_result(result, item)
        if isinstance(snapshot, dict) and snapshot:
            record = {
                **identity,
                **snapshot,
            }
            _attach_tail_record_counts_8616(record, block_count, byte_count, cfg_hash)
            return record
        record = _missing_snapshot_tail_record_8616(identity, result)
        _attach_tail_record_counts_8616(record, block_count, byte_count, cfg_hash)
        return record

    return _impl()


def _tail_record_identity_8616(item: object, result: object) -> dict[str, object]:
    function = _dynamic_cli_attr(result, "function", None) or _dynamic_cli_attr(item, "function", None)
    project = _dynamic_cli_attr(function, "project", None)
    binary_name = _dynamic_cli_attr(project, "filename", None)
    cod_file = Path(binary_name).name if isinstance(binary_name, (str, os.PathLike)) else None
    proc_name = _dynamic_cli_attr(function, "name", None) or "sub"
    proc_kind = None
    lst_metadata = _dynamic_cli_attr(project, "_inertia_lst_metadata", None)
    cod_proc_kinds = _dynamic_cli_attr(lst_metadata, "cod_proc_kinds", None)
    if isinstance(cod_proc_kinds, Mapping):
        kind = cod_proc_kinds.get(_dynamic_cli_attr(function, "addr", None))
        if isinstance(kind, str) and kind:
            proc_kind = kind.upper()
    return {
        "cod_file": cod_file,
        "proc_name": proc_name,
        "proc_kind": proc_kind,
        "function_addr": _dynamic_cli_attr(function, "addr", 0),
        "function_name": proc_name,
    }


def _attach_tail_record_counts_8616(
    record: dict[str, object],
    block_count: object,
    byte_count: object,
    cfg_hash: object,
) -> None:
    if block_count is not None:
        record["block_count"] = block_count
    if byte_count is not None:
        record["byte_count"] = byte_count
    if cfg_hash is not None:
        record["cfg_hash"] = cfg_hash


def _missing_snapshot_tail_record_8616(identity: dict[str, object], result: object) -> dict[str, object]:
    status = _dynamic_cli_attr(result, "status", None)
    payload = _dynamic_cli_attr(result, "payload", None)
    debug_output = _dynamic_cli_attr(result, "debug_output", None)
    exit_detail = None
    for candidate in (payload, debug_output):
        if isinstance(candidate, str) and candidate.strip():
            exit_detail = candidate.strip()
            break
    if exit_detail is None:
        exit_detail = "tail validation snapshot missing"
    exit_kind = status if isinstance(status, str) and status else "uncollected"
    return {
        **identity,
        "tail_validation_uncollected": True,
        "exit_kind": exit_kind,
        "exit_detail": exit_detail,
    }


def collect_tail_validation_records(
    function_tasks: Sequence[object],
    result_map: Mapping[int, object],
) -> list[dict[str, object]]:
    """Collect tail-validation records for all selected function tasks."""
    records: list[dict[str, object]] = []
    for item in function_tasks:
        result = result_map.get(_as_int(_dynamic_cli_attr(item, "index")) or -1)
        if result is None:
            function = _dynamic_cli_attr(item, "function", None)
            project = _dynamic_cli_attr(function, "project", None)
            binary_name = _dynamic_cli_attr(project, "filename", None)
            cod_file = Path(binary_name).name if isinstance(binary_name, (str, os.PathLike)) else None
            records.append(
                {
                    "cod_file": cod_file,
                    "proc_name": _dynamic_cli_attr(function, "name", None) or "sub",
                    "proc_kind": None,
                    "function_addr": _dynamic_cli_attr(function, "addr", 0),
                    "function_name": _dynamic_cli_attr(function, "name", None) or "sub",
                    "tail_validation_uncollected": True,
                    "exit_kind": "missing_result",
                    "exit_detail": "function result missing from tail-validation aggregate input",
                }
            )
            continue
        record = tail_validation_record_for_result(item, result)
        if record is not None:
            records.append(record)
    return records


def emit_tail_validation_surface_summary(
    *,
    records: Sequence[Mapping[str, object]],
    scanned: int,
    summary: Mapping[str, object],
    surface: Mapping[str, object],
    console_cache_path: Path | None,
    detail_cache_path: Path | None,
) -> None:
    """Render and cache the aggregate tail-validation surface summary."""

    def _impl() -> None:
        emitted_any = False
        rendered = _as_mapping(render_x86_16_tail_validation_console_summary(surface, cache_path=console_cache_path))
        detail_artifact = _as_mapping(cache_x86_16_tail_validation_detail_artifact(surface, cache_path=detail_cache_path))
        for line in _as_string_tuple(rendered.get("lines", ())):
            print(f"{TAIL_VALIDATION_STDERR_PREFIX}{line}", file=sys.stderr)
            emitted_any = True
        if surface.get("severity") != "clean":
            detail_artifact_path = detail_artifact.get("path")
            if isinstance(detail_artifact_path, Path):
                print(f"{TAIL_VALIDATION_STDERR_PREFIX}detail artifact {detail_artifact_path}", file=sys.stderr)
                emitted_any = True
            elif detail_cache_path is not None:
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
                "scanned": int(scanned),
                "records": [dict(record) for record in records if isinstance(record, Mapping)],
                "summary": dict(summary or {}),
                "surface": dict(surface or {}),
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

    return _impl()


def tail_validation_snapshot_for_function_run(project: object, function: object) -> dict[str, object]:
    """Return the latest tail-validation snapshot for a function run."""
    merged: dict[str, object] = {}
    fallback_snapshot = _dynamic_cli_attr(project, "_inertia_last_tail_validation_snapshot", None)
    if isinstance(fallback_snapshot, dict):
        if all(stage in fallback_snapshot for stage in ("structuring", "postprocess")):
            return dict(fallback_snapshot)
        merged.update(fallback_snapshot)
    snapshot = extract_x86_16_tail_validation_snapshot(_as_mapping(_dynamic_cli_attr(function, "info", None)))
    if snapshot:
        merged.update(snapshot)
    return merged


def tail_validation_snapshot_for_fallback(
    project: object,
    function: object,
    *,
    allow_project_fallback: bool,
) -> dict[str, object]:
    """Return the snapshot available to a fallback emission lane."""
    forced_snapshot = _dynamic_cli_attr(project, "_inertia_forced_tail_validation_snapshot", None)
    if isinstance(forced_snapshot, dict):
        typing.cast(typing.Any, project)._inertia_forced_tail_validation_snapshot = None
        return cast(
            dict[str, object],
            extract_x86_16_tail_validation_snapshot({"x86_16_tail_validation": forced_snapshot}),
        )

    current_snapshot = _dynamic_cli_attr(project, "_inertia_partial_tail_validation_snapshot", None)
    if isinstance(current_snapshot, dict):
        typing.cast(typing.Any, project)._inertia_partial_tail_validation_snapshot = None
        return dict(current_snapshot)
    snapshot = extract_x86_16_tail_validation_snapshot(_as_mapping(_dynamic_cli_attr(function, "info", None)))
    if snapshot:
        return cast(dict[str, object], snapshot)
    if not allow_project_fallback:
        return {}
    fallback_snapshot = _dynamic_cli_attr(project, "_inertia_last_tail_validation_snapshot", None)
    if isinstance(fallback_snapshot, dict):
        return cast(
            dict[str, object],
            extract_x86_16_tail_validation_snapshot({"x86_16_tail_validation": fallback_snapshot}),
        )
    return {}


def tail_validation_fallback_allows_project_snapshot(kind: str) -> bool:
    """Return whether a fallback lane may consult project-level snapshots."""
    return kind in TAIL_VALIDATION_FALLBACK_PROJECT_SNAPSHOT_KINDS


@cast(typing.Callable[..., typing.Any], trace_function(name="tail_validation.summary"))
def emit_tail_validation_console_summary(
    function_tasks: Sequence[object],
    result_map: Mapping[int, object],
    *,
    binary_path: Path | None = None,
) -> None:
    """Emit the decompiler run tail-validation summary to stderr."""
    annotate_current_span(functions=len(function_tasks), binary=binary_path.name if binary_path is not None else None)
    for item in function_tasks:
        project = _dynamic_cli_attr(_dynamic_cli_attr(item, "function", None), "project", None)
        if project is not None:
            if not tail_validation_runtime_enabled(project):
                return
            break
    records = collect_tail_validation_records(function_tasks, result_map)
    scanned = len(function_tasks)
    aggregate = _as_mapping(build_x86_16_tail_validation_aggregate(records, scanned=scanned))
    summary: dict[str, object] = dict(_as_mapping(aggregate.get("summary", {})))
    surface: dict[str, object] = dict(_as_mapping(aggregate.get("surface", {})))
    acceptance_validation_failed = _has_acceptance_validation_failure(result_map.values())
    if acceptance_validation_failed and str(surface.get("severity", "")).strip().lower() == "clean":
        # Acceptance gates are part of semantic validation policy; if they fail,
        # the surface summary must not claim clean.
        surface["severity"] = "changed"
        surface["merge_gate"] = "hold"
        surface["headline"] = f"whole-tail validation failed across {max(1, int(scanned or 1))} functions"
    cache_payload = {
        "surface": surface,
        "summary": summary,
    }
    cache_salt = hashlib.sha256(
        json.dumps(cache_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:12]
    console_cache_path = tail_validation_console_cache_path(binary_path, function_tasks, cache_salt=cache_salt)
    detail_cache_path = tail_validation_detail_cache_path(binary_path, function_tasks, cache_salt=cache_salt)
    emit_tail_validation_surface_summary(
        records=records,
        scanned=scanned,
        summary=summary,
        surface=surface,
        console_cache_path=console_cache_path,
        detail_cache_path=detail_cache_path,
    )


def tail_validation_cache_label(
    binary_path: Path | None,
    function_tasks: Sequence[object],
    *,
    cache_salt: str | None = None,
) -> str | None:
    """Build a deterministic cache label for a tail-validation summary."""

    def _impl() -> str | None:
        if binary_path is None:
            return None
        resolved = Path(binary_path).resolve()
        base_name = resolved.stem or resolved.name or "binary"
        labels: list[str] = []
        for item in function_tasks:
            function = _dynamic_cli_attr(item, "function", None)
            name = _dynamic_cli_attr(function, "name", None)
            addr = _dynamic_cli_attr(function, "addr", None)
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
        if isinstance(cache_salt, str) and cache_salt:
            payload += f"\ncache_salt={cache_salt}"
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
        if len(labels) == 1:
            return f"{base_name}.{digest}"
        return f"{base_name}.{max(len(labels), 1)}f.{digest}"

    return _impl()


def tail_validation_console_cache_path(
    binary_path: Path | None,
    function_tasks: Sequence[object],
    *,
    cache_salt: str | None = None,
) -> Path | None:
    """Return the cache path for the rendered console summary."""
    label = tail_validation_cache_label(binary_path, function_tasks, cache_salt=cache_salt)
    if label is None:
        return None
    return TAIL_VALIDATION_CONSOLE_CACHE_DIR / f"{label}.tail_validation_console.json"


def tail_validation_detail_cache_path(
    binary_path: Path | None,
    function_tasks: Sequence[object],
    *,
    cache_salt: str | None = None,
) -> Path | None:
    """Return the cache path for the detailed summary artifact."""
    label = tail_validation_cache_label(binary_path, function_tasks, cache_salt=cache_salt)
    if label is None:
        return None
    return TAIL_VALIDATION_DETAIL_CACHE_DIR / f"{label}.tail_validation_surface.json"


def tail_validation_display_status(
    snapshot: Mapping[str, object] | None,
    *,
    expected_stages: Sequence[str] = ("structuring", "postprocess"),
    fallback_kind: str | None = None,
) -> str:
    """Return a compact validation status string for attempt reporting."""

    def _impl() -> str:
        if fallback_kind is not None:
            return TailValidationDisplayStatus.FAILED.value
        if not isinstance(snapshot, Mapping) or not snapshot:
            return TailValidationDisplayStatus.UNCOLLECTED.value
        if bool(snapshot.get("tail_validation_uncollected")):
            return TailValidationDisplayStatus.FAILED.value
        passed = x86_16_tail_validation_snapshot_passed(dict(snapshot), expected_stages=expected_stages)
        if passed:
            return TailValidationDisplayStatus.PASSED.value

        if _collect_failed_stages_8616(snapshot, expected_stages):
            return TailValidationDisplayStatus.FAILED.value
        return TailValidationDisplayStatus.FAILED.value

    return _impl()


def _collect_failed_stages_8616(snapshot: Mapping[str, object], expected_stages: Sequence[str]) -> list[str]:
    failed_stages: list[str] = []
    for stage_name in expected_stages:
        entry = snapshot.get(stage_name)
        if not isinstance(entry, Mapping):
            failed_stages.append(f"{stage_name}=missing")
            continue
        changed = bool(entry.get("changed"))
        if changed:
            failed_stages.append(f"{stage_name}=changed")
            continue
        status = entry.get("status")
        if not isinstance(status, str):
            failed_stages.append(f"{stage_name}=missing_status")
            continue
        if status not in _TAIL_VALIDATION_STABLE_STATUSES:
            failed_stages.append(f"{stage_name}={status}")
    return failed_stages


def format_tail_validation_diagnostic(
    snapshot: Mapping[str, object] | None,
    *,
    function_addr: int = 0,
    function_name: str = "sub",
    block_count: int | None = None,
    byte_count: int | None = None,
    cfg_hash: str | None = None,
    exit_kind: str | None = None,
    exit_detail: str | None = None,
) -> list[str]:
    """Format a tail validation snapshot as human-readable diagnostic lines.

    Returns lines suitable for printing as stdout comments (/* ... */).
    When the snapshot is missing or uncollected, reports the exit kind/detail.
    """

    def _impl() -> list[str]:
        lines: list[str] = []
        header = f"/* tail validation: {function_name} ({function_addr:#x}) */"
        lines.append(header)

        # Block/byte/cfg metadata
        meta_parts: list[str] = []
        if block_count is not None:
            meta_parts.append(f"blocks={block_count}")
        if byte_count is not None:
            meta_parts.append(f"bytes={byte_count}")
        if cfg_hash is not None:
            meta_parts.append(f"cfg_hash={cfg_hash}")
        if meta_parts:
            lines.append(f"/* tail validation metadata: {', '.join(meta_parts)} */")

        if not isinstance(snapshot, Mapping) or not snapshot:
            reason = exit_kind or "uncollected"
            detail = exit_detail or "no tail validation snapshot available"
            lines.append(f"/* tail validation result: {reason} — {detail} */")
            return lines

        if snapshot.get("tail_validation_uncollected"):
            reason = exit_kind or str(snapshot.get("exit_kind", "uncollected"))
            detail = exit_detail or str(snapshot.get("exit_detail", "snapshot marked uncollected"))
            lines.append(f"/* tail validation result: {reason} — {detail} */")
            return lines

        for stage_key in ("structuring", "postprocess"):
            _append_stage_diagnostic_lines_8616(lines, snapshot, stage_key)
        return lines

    return _impl()


def _append_stage_diagnostic_lines_8616(
    lines: list[str], snapshot: Mapping[str, object], stage_key: str
) -> None:
    entry = snapshot.get(stage_key)
    if not isinstance(entry, Mapping):
        lines.append(f"/* tail validation {stage_key}: missing */")
        return
    changed = bool(entry.get("changed", False))
    status = entry.get("status", "changed" if changed else "stable")
    mode = entry.get("mode", "unknown")
    if isinstance(mode, str) and mode:
        status_str = f"status={status} mode={mode} changed={changed}"
    else:
        status_str = f"status={status} changed={changed}"
    lines.append(f"/* tail validation {stage_key}: {status_str} */")
    verdict = entry.get("verdict")
    if isinstance(verdict, str) and verdict:
        lines.append(f"/* tail validation {stage_key} verdict: {verdict} */")
    summary_text = entry.get("summary_text")
    if isinstance(summary_text, str) and summary_text:
        lines.append(f"/* tail validation {stage_key} detail: {summary_text} */")
