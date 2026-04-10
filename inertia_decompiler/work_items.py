from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import os
from pathlib import Path
import sys
import time

from inertia_decompiler.tail_validation import (
    emit_tail_validation_console_summary,
    tail_validation_display_status,
    tail_validation_runtime_enabled,
    tail_validation_snapshot_for_fallback,
)


def _diagnostic_print(line: str) -> None:
    if "PYTEST_CURRENT_TEST" in os.environ:
        print(line)
        return
    print(f"{time.strftime('[%H:%M:%S]')} {line}", file=sys.stderr)


@dataclass(frozen=True)
class FunctionDecompileTask:
    index: int
    cfg: object
    function: object


@dataclass(frozen=True)
class FunctionDecompileResult:
    index: int
    status: str
    payload: str
    debug_output: str
    elapsed: float


@dataclass(frozen=True)
class FunctionWorkItem:
    index: int
    function_cfg: object
    function: object


@dataclass(frozen=True)
class FunctionWorkResult:
    index: int
    status: str
    payload: str
    debug_output: str
    function: object
    function_cfg: object
    partial_payload: str | None = None
    tail_validation: dict[str, object] | None = None
    skip_heavy_fallbacks: bool = False
    elapsed: float | None = None
    from_cache: bool = False
    failure_stage: str | None = None
    block_count: int | None = None
    byte_count: int | None = None


def emit_tail_validation_for_function_run_or_uncollected(
    project,
    function_cfg,
    function,
    *,
    allow_project_fallback: bool = True,
    binary_path: Path | None = None,
) -> None:
    if not tail_validation_runtime_enabled(project):
        return
    snapshot = tail_validation_snapshot_for_fallback(
        project,
        function,
        allow_project_fallback=allow_project_fallback,
    )
    item = FunctionWorkItem(index=1, function_cfg=function_cfg, function=function)
    result = FunctionWorkResult(
        index=1,
        status="ok" if snapshot else "uncollected",
        payload="",
        debug_output="",
        function=function,
        function_cfg=function_cfg,
        tail_validation=snapshot,
    )
    emit_tail_validation_console_summary([item], {1: result}, binary_path=binary_path)


def emit_tail_validation_snapshot_or_uncollected(
    function_cfg,
    function,
    snapshot: Mapping[str, object] | None,
    *,
    binary_path: Path | None = None,
) -> None:
    project = getattr(function, "project", None)
    if project is not None and not tail_validation_runtime_enabled(project):
        return
    normalized_snapshot = dict(snapshot) if isinstance(snapshot, Mapping) else {}
    item = FunctionWorkItem(index=1, function_cfg=function_cfg, function=function)
    result = FunctionWorkResult(
        index=1,
        status="ok" if normalized_snapshot else "uncollected",
        payload="",
        debug_output="",
        function=function,
        function_cfg=function_cfg,
        tail_validation=normalized_snapshot,
    )
    emit_tail_validation_console_summary([item], {1: result}, binary_path=binary_path)


def function_attempt_display_status(result: FunctionWorkResult) -> str:
    if result.status == "ok":
        return "decompiled"
    if result.partial_payload:
        return "fallback"
    if result.status == "timeout":
        return "timed_out"
    if result.status == "empty":
        return "empty"
    return result.status


def print_function_attempt_status(
    function,
    *,
    attempt: str,
    validation_snapshot: Mapping[str, object] | None,
) -> None:
    project = getattr(function, "project", None)
    validation_status = (
        "disabled"
        if project is not None and not tail_validation_runtime_enabled(project)
        else tail_validation_display_status(validation_snapshot)
    )
    _diagnostic_print(
        f"/* info: function {getattr(function, 'addr', 0):#x} {getattr(function, 'name', 'sub')} "
        f"attempt={attempt} validation={validation_status} */"
    )


def recovery_evidence_line(binary_path: Path, metadata) -> str:
    if metadata is None:
        return "/* info: recovery evidence: pure binary recovery mode (no helper metadata/debug info found) */"
    source_format = getattr(metadata, "source_format", "") or "sidecars"
    source_parts = tuple(part for part in source_format.split("+") if part)
    debug_markers = ("codeview", "turbo_debug", "tdinfo", "debug")
    has_debug_info = any(any(marker in part for marker in debug_markers) for part in source_parts)
    if has_debug_info:
        return f"/* info: recovery evidence: sidecar/debug-assisted recovery ({source_format}) */"
    return f"/* info: recovery evidence: sidecar-assisted recovery ({source_format}) */"
