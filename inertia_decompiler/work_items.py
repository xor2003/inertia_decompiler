"""Define queued decompilation work items and per-item reporting state.

Layer: CLI/fallback/reporting.
Responsibility: carry decompiler work-item status and reporting snapshots without owning semantic recovery.
"""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from angr_platforms.X86_16.segment_program_layout_contract import SegmentProgramFunctionEvidence8616

    from inertia_decompiler.direct_addr_failure_family import FailureFamilySnapshot

from inertia_decompiler.metadata_evidence import has_only_binary_signatures
from inertia_decompiler.sidecar_cache import lst_metadata_content_digest_8616
from inertia_decompiler.tail_validation import (
    emit_tail_validation_console_summary,
    tail_validation_display_status,
    tail_validation_runtime_enabled,
    tail_validation_snapshot_for_fallback,
)
from inertia_decompiler.x86_16_exact_slice import function_original_addr


class WorkItemStatus(StrEnum):
    """Typed status for a single decompiler work item."""

    OK = "ok"
    ERROR = "error"
    VALIDATION_FAILED = "validation_failed"
    UNKNOWN = "unknown"
    UNCOLLECTED = "uncollected"
    TIMEOUT = "timeout"
    EMPTY = "empty"


class FunctionWorkExecutionOrigin8616(StrEnum):
    """Execution boundary that produced one function-work result."""

    IN_PROCESS = "in_process"
    CLEAN_PROCESS = "clean_process"


class TailValidationDisplayOutcome(StrEnum):
    """Typed display status normalized from tail-validation snapshots."""

    PASSED = "passed"
    FAILED = "failed"
    CHANGED = "changed"
    STABLE = "stable"
    UNKNOWN = "unknown"
    UNCOLLECTED = "uncollected"


def _normalize_tail_validation_status(raw_status: str | None) -> TailValidationDisplayOutcome:
    if raw_status == "" or raw_status is None:
        return TailValidationDisplayOutcome.UNCOLLECTED
    try:
        return TailValidationDisplayOutcome(raw_status)
    except ValueError:
        return TailValidationDisplayOutcome.UNCOLLECTED


def _tail_validation_to_item_status(
    raw_status: str | None,
) -> WorkItemStatus:
    status = _normalize_tail_validation_status(raw_status)
    if status in (
        TailValidationDisplayOutcome.FAILED,
        TailValidationDisplayOutcome.CHANGED,
    ):
        return WorkItemStatus.VALIDATION_FAILED
    if status in (
        TailValidationDisplayOutcome.PASSED,
        TailValidationDisplayOutcome.STABLE,
    ):
        return WorkItemStatus.OK
    if status in (TailValidationDisplayOutcome.UNKNOWN, TailValidationDisplayOutcome.UNCOLLECTED):
        return WorkItemStatus(status.value)
    return WorkItemStatus.UNCOLLECTED


def _work_item_status_display(result: WorkItemStatus | str) -> WorkItemStatus:
    if isinstance(result, WorkItemStatus):
        return result
    try:
        return WorkItemStatus(result)
    except (TypeError, ValueError):
        return WorkItemStatus.UNCOLLECTED


def _diagnostic_print(line: str) -> None:
    """Emit work-item diagnostics without contaminating generated-C stdout."""
    if "PYTEST_CURRENT_TEST" in os.environ:
        print(line, file=sys.stderr)
        return
    print(f"{time.strftime('[%H:%M:%S]')} {line}", file=sys.stderr)


def _visible_source_format(source_format: str | None) -> str:
    raw = source_format or ""
    parts = [part for part in raw.split("+") if part]
    return "+".join(parts) or "sidecars"


@dataclass(frozen=True)
class FunctionDecompileTask:
    """Inputs needed to decompile one discovered function."""

    index: int
    cfg: Any
    function: Any


@dataclass(frozen=True)
class FunctionDecompileResult:
    """Raw result produced by one function decompilation attempt."""

    index: int
    status: str
    payload: str
    debug_output: str
    elapsed: float


@dataclass(frozen=True)
class FunctionWorkItem:
    """Queue entry used by CLI recovery, decompilation, and fallback reporting.

    ``recovery_addr`` preserves the requested binary/catalog boundary when an
    angr function canonicalizes its active address past padding or a prefix.
    ``retained_project`` keeps a freshly recovered function's weak angr owner
    alive for in-process retries; worker IPC must continue to rebuild projects.
    """

    index: int
    function_cfg: Any
    function: Any
    recovery_addr: int | None = None
    retained_project: Any | None = field(default=None, repr=False, compare=False)

    @property
    def c_target(self) -> str:
        """Return the compiler target attached at the dynamic angr boundary."""
        try:
            target = self.function.project._inertia_c_target
        except AttributeError:
            return "portable-flat"
        return target if isinstance(target, str) and target else "portable-flat"

    @property
    def name(self) -> str | None:
        """Return the function label exposed by the dynamic angr boundary."""
        try:
            name = self.function.name
        except AttributeError:
            return None
        return name if isinstance(name, str) and name else None

    @property
    def active_addr(self) -> int:
        """Return the address used by the active recovered function project."""
        try:
            active_addr = self.function.addr
        except AttributeError:
            return 0
        return active_addr if isinstance(active_addr, int) else 0

    @property
    def original_addr(self) -> int:
        """Return the function address in the original binary address space."""
        original_addr: int = function_original_addr(cast(object, self.function))
        return original_addr

    @property
    def sidecar_metadata_digest(self) -> str | None:
        """Return content identity for sidecar evidence attached to the project."""
        try:
            metadata = self.function.project._inertia_lst_metadata
        except AttributeError:
            return None
        if metadata is None:
            return None
        metadata_digest: str = lst_metadata_content_digest_8616(metadata)
        return metadata_digest


@dataclass(frozen=True)
class FunctionWorkResult:
    """Reported result plus its retry-relevant execution provenance."""

    index: int
    status: str
    payload: str
    debug_output: str
    function: Any
    function_cfg: Any
    partial_payload: str | None = None
    tail_validation: dict[str, object] | None = None
    skip_heavy_fallbacks: bool = False
    elapsed: float | None = None
    from_cache: bool = False
    failure_stage: str | None = None
    block_count: int | None = None
    byte_count: int | None = None
    same_family_retry_stops: int = 0
    fallback_family_labels: tuple[str, ...] = ()
    validated_payload_hash: str | None = None
    gcc_checked_payload_hash: str | None = None
    segment_program_function_evidence: SegmentProgramFunctionEvidence8616 | None = None
    failure_family_snapshot: FailureFamilySnapshot | None = None
    execution_origin: FunctionWorkExecutionOrigin8616 = (
        FunctionWorkExecutionOrigin8616.IN_PROCESS
    )

    def retry_may_change_evidence(self, *, sidecar_available: bool) -> bool:
        """Return whether a recovery retry can consume distinct evidence."""
        return (
            self.execution_origin is not FunctionWorkExecutionOrigin8616.CLEAN_PROCESS
            or sidecar_available
        )


def emit_tail_validation_for_function_run_or_uncollected(
    project: object,
    function_cfg: object,
    function: object,
    *,
    allow_project_fallback: bool = True,
    binary_path: Path | None = None,
) -> None:
    """Emit a tail-validation line or an explicit uncollected result for one function."""
    if not tail_validation_runtime_enabled(project):
        return
    snapshot = tail_validation_snapshot_for_fallback(
        project,
        function,
        allow_project_fallback=allow_project_fallback,
    )
    result_status = (
        WorkItemStatus.UNCOLLECTED
        if not snapshot
        else _tail_validation_to_item_status(tail_validation_display_status(snapshot))
    )
    item = FunctionWorkItem(index=1, function_cfg=function_cfg, function=function)
    result = FunctionWorkResult(
        index=1,
        status=result_status.value,
        payload="",
        debug_output="",
        function=function,
        function_cfg=function_cfg,
        tail_validation=snapshot,
    )
    emit_tail_validation_console_summary([item], {1: result}, binary_path=binary_path)


def emit_tail_validation_snapshot_or_uncollected(
    function_cfg: object,
    function: object,
    snapshot: Mapping[str, object] | None,
    *,
    binary_path: Path | None = None,
) -> None:
    """Emit an existing tail-validation snapshot or an uncollected placeholder."""
    # Dynamic angr boundary: Function objects expose project through angr-managed attributes.
    project = getattr(function, "project", None)
    if project is not None and not tail_validation_runtime_enabled(project):
        return
    normalized_snapshot = dict(snapshot) if isinstance(snapshot, Mapping) else {}
    result_status = (
        WorkItemStatus.UNCOLLECTED
        if not normalized_snapshot
        else _tail_validation_to_item_status(tail_validation_display_status(normalized_snapshot))
    )
    item = FunctionWorkItem(index=1, function_cfg=function_cfg, function=function)
    result = FunctionWorkResult(
        index=1,
        status=result_status.value,
        payload="",
        debug_output="",
        function=function,
        function_cfg=function_cfg,
        tail_validation=normalized_snapshot,
    )
    emit_tail_validation_console_summary([item], {1: result}, binary_path=binary_path)


def function_attempt_display_status(result: FunctionWorkResult) -> str:
    """Return the compact display status for one work result."""
    result_status = _work_item_status_display(result.status)
    if result_status == WorkItemStatus.OK:
        return "decompiled"
    if result_status == WorkItemStatus.TIMEOUT:
        return "timed_out"
    if result_status == WorkItemStatus.EMPTY:
        return "empty"
    if result.partial_payload:
        return "fallback"
    return result_status.value


def print_function_attempt_status(
    function: object,
    *,
    attempt: str,
    validation_snapshot: Mapping[str, object] | None,
) -> None:
    """Print one diagnostic line for a function attempt."""
    # Dynamic angr boundary: Function exposes project/addr/name through angr-managed attributes.
    project = getattr(function, "project", None)
    validation_status = (
        TailValidationDisplayOutcome.UNCOLLECTED.value
        if project is not None and not tail_validation_runtime_enabled(project)
        else tail_validation_display_status(validation_snapshot)
    )
    # Dynamic angr boundary: Function exposes addr/name through angr-managed attributes.
    function_addr = getattr(function, "addr", 0)
    # Dynamic angr boundary: Function exposes addr/name through angr-managed attributes.
    function_name = getattr(function, "name", "sub")
    _diagnostic_print(
        f"/* info: function {function_addr:#x} {function_name} "
        f"attempt={attempt} validation={validation_status} */"
    )


def recovery_evidence_line(binary_path: Path, metadata: object) -> str:
    """Return the CLI evidence banner for sidecar/debug metadata availability."""
    if metadata is None:
        return "/* info: recovery evidence: pure binary recovery mode (no helper metadata/debug info found) */"
    if has_only_binary_signatures(metadata):
        return "/* info: recovery evidence: pure binary recovery mode (binary signatures only; no local source/debug evidence) */"
    # Dynamic sidecar compatibility boundary: callers may pass legacy metadata carriers.
    source_format = _visible_source_format(getattr(metadata, "source_format", None))
    source_parts = tuple(part for part in source_format.split("+") if part)
    debug_markers = ("codeview", "turbo_debug", "tdinfo", "debug")
    has_debug_info = any(any(marker in part for marker in debug_markers) for part in source_parts)
    if has_debug_info:
        return f"/* info: recovery evidence: sidecar/debug-assisted recovery ({source_format}) */"
    return f"/* info: recovery evidence: sidecar-assisted recovery ({source_format}) */"
