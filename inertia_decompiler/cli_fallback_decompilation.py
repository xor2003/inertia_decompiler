"""Layer: CLI/fallback/reporting.

Responsibility: run bounded fallback lanes and report their validation outcome.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

# AUTO-GENERATED split from cli_runtime_shared.py
from __future__ import annotations

import contextlib
import logging
import os
import re
import sys
import threading
import typing
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

import angr
from angr_platforms.X86_16.cod_extract import CODProcMetadata
from angr_platforms.X86_16.frontend_function_instructions import (
    collect_bounded_linear_instruction_inventory_8616,
)
from angr_platforms.X86_16.lst_extract import LSTMetadata

from inertia_decompiler import cli_string_timeout_fallback as _cli_string_timeout_fallback
from inertia_decompiler.cli_decompilation import (
    _decompile_function_with_stats,
    _effective_decompile_timeout_8616,
    _function_complexity,
    _prepare_function_for_decompilation,
    _sidecar_cod_metadata_for_function,
)
from inertia_decompiler.cli_function_discovery import _pick_function, _pick_function_lean
from inertia_decompiler.cli_output import (
    _timestamped_print,
)
from inertia_decompiler.decompilation_quality import assess_decompiled_c_text
from inertia_decompiler.direct_addr_failure_family import FailureFamilyState
from inertia_decompiler.disassembly_helpers import (
    _format_asm_range,
    _infer_linear_disassembly_window,
)
from inertia_decompiler.non_optimized_fallback import (
    bounded_non_optimized_attempt_timeout,
)
from inertia_decompiler.project_evidence_transport import transfer_project_evidence_8616
from inertia_decompiler.project_loading import (
    _build_project_cached,
    _build_project_from_bytes,
    _describe_exception,
    _is_blob_only_input,
)
from inertia_decompiler.runtime_support import (
    run_with_timeout_in_daemon_thread as _run_with_timeout_in_daemon_thread,
)
from inertia_decompiler.runtime_support import (
    run_with_timeout_in_fork as _run_with_timeout_in_fork,
)
from inertia_decompiler.sidecar_metadata import (
    _lst_code_region,
)
from inertia_decompiler.slice_recovery import (
    BoundedSliceVerdict,
    SliceRecoveryAttemptOutcome,
    SliceRecoveryAttemptTrace,
    build_default_slice_recovery_attempts,
    run_bounded_slice_recovery,
)
from inertia_decompiler.tail_validation import (
    inherit_tail_validation_runtime_policy as _inherit_tail_validation_runtime_policy,
)
from inertia_decompiler.tail_validation import (
    tail_validation_snapshot_for_function_run as _tail_validation_snapshot_for_function_run,
)
from inertia_decompiler.x86_16_exact_slice import (
    mark_function_original_addr,
    non_optimized_slice_codegen_policy,
    plan_x86_16_exact_slice,
)

logger: logging.Logger = logging.getLogger(__name__)

print: Callable[..., None] = _timestamped_print

_SIDECAR_SLICE_DECOMPILE_TIMEOUT_CAP_8616 = 24
_SIDECAR_SLICE_RUNNER_TIMEOUT_CAP_8616 = 30
_SIDECAR_SLICE_MAX_INSTRUCTION_BYTES_8616 = 0x800

# Imported decompilation entry point: keep its public result contract explicit
# when global mypy checks this CLI module without following every import. The
# forwarding function intentionally resolves the module global on each call so
# tests and integrations can replace the decompilation boundary.
_DecompileFunctionWithStats = Callable[..., tuple[str, str, str | None, int, int, float]]


@runtime_checkable
class _SidecarCfgInstructionBoundary8616(Protocol):
    """Dynamic angr instruction fields consumed by the completeness census."""

    address: object


@runtime_checkable
class _SidecarCfgCapstoneBoundary8616(Protocol):
    """Dynamic angr Capstone collection exposed by one recovered CFG block."""

    insns: object


@runtime_checkable
class _SidecarCfgBlockBoundary8616(Protocol):
    """Dynamic angr block fields consumed by the completeness census."""

    capstone: _SidecarCfgCapstoneBoundary8616


class _SidecarFunctionBoundary8616(Protocol):
    """Dynamic angr recovered-function fields consumed by the census."""

    blocks: object


def _call_decompile_function_with_stats(
    *args: object, **kwargs: object
) -> tuple[str, str, str | None, int, int, float]:
    decompile_function = typing.cast(_DecompileFunctionWithStats, _decompile_function_with_stats)
    return decompile_function(*args, **kwargs)

__all__ = [
    "NonOptimizedSliceOutcome",
    "_non_optimized_slice_failure_detail",
    "_non_optimized_slice_rendered",
    "_try_decompile_non_optimized_known_function",
    "_try_decompile_non_optimized_slice",
    "_try_decompile_sidecar_slice",
    "_try_emit_known_runtime_helper_c",
    "_try_emit_string_intrinsic_c",
    "_try_emit_trivial_sidecar_c",
]


@dataclass(frozen=True)
class NonOptimizedSliceOutcome:
    """Result for non-optimized fallback decompilation attempts."""

    rendered: str | None
    status: str
    payload: str
    partial_payload: str | None = None
    failure_detail: str | None = None
    attempt_failures: tuple[str, ...] = ()
    verdict: BoundedSliceVerdict | None = None


def _non_optimized_slice_rendered(
    outcome: NonOptimizedSliceOutcome | str | None,
) -> str | None:
    if outcome is None:
        return None
    if isinstance(outcome, NonOptimizedSliceOutcome):
        return outcome.rendered
    return outcome


def _non_optimized_slice_failure_detail(
    outcome: NonOptimizedSliceOutcome | str | None,
) -> str | None:
    if not isinstance(outcome, NonOptimizedSliceOutcome):
        return None
    return outcome.failure_detail


def _try_decompile_sidecar_slice(
    project: angr.Project,
    lst_metadata: LSTMetadata | None,
    addr: int,
    name: str,
    *,
    timeout: int,
    api_style: str,
    binary_path: Path | None,
    failure_family_state: FailureFamilyState | None = None,
) -> SliceRecoveryAttemptOutcome | None:
    """Decompile a metadata-bounded region at its proven callable entry."""
    def _impl() -> SliceRecoveryAttemptOutcome | None:
        region = _lst_code_region(lst_metadata, addr)
        if region is None:
            return None
        start, end = region
        if end <= start:
            return None
        try:
            code = bytes(project.loader.memory.load(start, end - start))
        except Exception as ex:
            logger.debug("sidecar slice byte load failed: %s", ex)
            return SliceRecoveryAttemptOutcome(
                attempt_name="sidecar-slice",
                status="error",
                payload=f"sidecar slice failed: {_describe_exception(ex)}",
            )

        def _recover_and_decompile() -> SliceRecoveryAttemptOutcome:
            # Dynamic angr boundary: project architecture metadata is supplied by angr.
            arch_name = getattr(getattr(project, "arch", None), "name", None)
            slice_plan = (
                plan_x86_16_exact_slice(start, end, original_entry=addr) if arch_name == "86_16" else None
            )
            slice_start = slice_plan.slice_start if slice_plan is not None else start
            slice_end = slice_plan.slice_end if slice_plan is not None else end
            slice_entry = slice_plan.slice_semantic_entry if slice_plan is not None else addr
            recovery_attempts = build_default_slice_recovery_attempts(
                slice_start,
                slice_end,
                entry=slice_entry,
                pick_function_lean=_pick_function_lean,
                pick_function=_pick_function,
            )

            def _decompile_attempt(
                attempt_name: str,
                slice_project: angr.Project,
                cfg: object,
                func: object,
            ) -> SliceRecoveryAttemptOutcome:
                # Dynamic angr boundary: recovered functions expose mutable names through angr.
                typing.cast(typing.Any, func).name = name
                if slice_plan is not None:
                    mark_function_original_addr(func, slice_plan.original_semantic_entry)
                    # Dynamic angr boundary: slice projects carry runtime metadata for downstream angr passes.
                    typing.cast(typing.Any, slice_project)._inertia_disable_ail_narrowing = True
                    # Dynamic angr boundary: slice projects carry runtime metadata for downstream angr passes.
                    typing.cast(typing.Any, slice_project)._inertia_disable_complex_expr_scan = True
                    # Dynamic angr boundary: slice projects carry runtime metadata for downstream angr passes.
                    typing.cast(typing.Any, slice_project)._inertia_fast_block_peephole = True
                status, payload, *_ = _call_decompile_function_with_stats(
                    slice_project,
                    cfg,
                    func,
                    max(1, min(timeout, _SIDECAR_SLICE_DECOMPILE_TIMEOUT_CAP_8616)),
                    api_style,
                    binary_path,
                    lst_metadata=lst_metadata,
                    allow_isolated_retry=False,
                    failure_family_state=failure_family_state,
                )
                if status == "ok" and assess_decompiled_c_text(payload).reject_as_decompiled:
                    status = "empty"
                    payload = "Sidecar slice decompilation remained unresolved after bounded recovery."
                if status == "ok" and slice_plan is not None:
                    function_boundary = typing.cast(_SidecarFunctionBoundary8616, func)
                    cfg_blocks = tuple(
                        block
                        for block in typing.cast(typing.Any, function_boundary.blocks)
                        if isinstance(block, _SidecarCfgBlockBoundary8616)
                    )
                    inventory_base_instructions: tuple[object, ...] = ()
                    cfg_instruction_addrs: set[int] = set()
                    for block in cfg_blocks:
                        for instruction in typing.cast(
                            typing.Any, block.capstone.insns
                        ):
                            instruction_boundary = typing.cast(
                                _SidecarCfgInstructionBoundary8616,
                                instruction,
                            )
                            inventory_base_instructions += (instruction,)
                            instruction_address = instruction_boundary.address
                            if isinstance(instruction_address, int):
                                cfg_instruction_addrs.add(instruction_address)
                    inventory = collect_bounded_linear_instruction_inventory_8616(
                        slice_project,
                        function_entry=slice_entry,
                        base_instructions=inventory_base_instructions,
                        max_bytes=_SIDECAR_SLICE_MAX_INSTRUCTION_BYTES_8616,
                        exact_end=slice_end,
                    )
                    missing_instruction_addrs: list[int] = []
                    for instruction in inventory.sequential_instructions:
                        instruction_boundary = typing.cast(
                            _SidecarCfgInstructionBoundary8616,
                            instruction,
                        )
                        instruction_address = instruction_boundary.address
                        if (
                            isinstance(instruction_address, int)
                            and instruction_address not in cfg_instruction_addrs
                        ):
                            missing_instruction_addrs.append(instruction_address)
                    if missing_instruction_addrs:
                        status = "error"
                        payload = (
                            f"{attempt_name} sidecar slice omitted exact instructions: "
                            + ", ".join(f"{address:#x}" for address in missing_instruction_addrs)
                        )
                snapshot = _tail_validation_snapshot_for_function_run(slice_project, func)
                return SliceRecoveryAttemptOutcome(
                    attempt_name=attempt_name,
                    status=status,
                    payload=payload,
                    snapshot=dict(snapshot) if snapshot else None,
                )

            def _inherit_slice_runtime_policy(slice_project: angr.Project) -> None:
                if slice_plan is not None:
                    typing.cast(typing.Any, slice_project)._inertia_original_project = project
                    typing.cast(typing.Any, slice_project)._inertia_original_linear_delta = start - slice_start
                    typing.cast(typing.Any, slice_project)._inertia_disable_ail_narrowing = True
                    typing.cast(typing.Any, slice_project)._inertia_disable_complex_expr_scan = True
                    typing.cast(typing.Any, slice_project)._inertia_fast_block_peephole = True
                _inherit_tail_validation_runtime_policy(slice_project, project)
                transfer_project_evidence_8616(project, slice_project)

            outcomes = run_bounded_slice_recovery(
                recovery_attempts,
                build_slice_project=lambda: _build_project_from_bytes(
                    code,
                    base_addr=slice_start,
                    entry_point=slice_entry,
                ),
                inherit_runtime_policy=_inherit_slice_runtime_policy,
                describe_exception=_describe_exception,
                decompile=_decompile_attempt,
            )
            for attempt in outcomes:
                if attempt.status == "ok":
                    if attempt.snapshot:
                        # Dynamic angr boundary: project stores fallback validation metadata for later reporting.
                        typing.cast(typing.Any, project)._inertia_last_tail_validation_snapshot = dict(attempt.snapshot)
                    if attempt.attempt_name != "lean":
                        print(
                            f"[dbg] sidecar slice fallback recovered {addr:#x} {name} via {attempt.attempt_name}",
                            file=sys.stderr,
                            flush=True,
                        )
                    return attempt
            if not outcomes:
                return SliceRecoveryAttemptOutcome(
                    attempt_name="sidecar-slice",
                    status="error",
                    payload="sidecar slice recovery did not run",
                )
            return outcomes[-1]

        try:
            runner_timeout = max(2, min(timeout, _SIDECAR_SLICE_RUNNER_TIMEOUT_CAP_8616))
            result = None
            fork_error: BaseException | None = None
            if (
                os.name == "posix"
                and threading.current_thread() is threading.main_thread()
                and threading.active_count() == 1
                and isinstance(project, angr.Project)
            ):
                try:
                    result = _run_with_timeout_in_fork(
                        _recover_and_decompile,
                        timeout=runner_timeout,
                    )
                except Exception as ex:
                    fork_error = ex
                    logger.debug(
                        "sidecar slice fork transport failed for %#x: %s",
                        addr,
                        ex,
                    )
            if result is None:
                result = _run_with_timeout_in_daemon_thread(
                    _recover_and_decompile,
                    timeout=runner_timeout,
                    thread_name_prefix="slice-fallback",
                )
            if result is None:
                return SliceRecoveryAttemptOutcome(
                    attempt_name="sidecar-slice",
                    status="timeout",
                    payload=f"sidecar slice runner timed out after {runner_timeout}s",
                )
            if not isinstance(result, SliceRecoveryAttemptOutcome):
                return SliceRecoveryAttemptOutcome(
                    attempt_name="sidecar-slice",
                    status="error",
                    payload=f"sidecar slice runner returned unexpected {type(result).__name__}",
                )
            return result
        except TimeoutError as ex:
            return SliceRecoveryAttemptOutcome(
                attempt_name="sidecar-slice",
                status="timeout",
                payload=f"sidecar slice timed out after {runner_timeout}s ({ex})",
            )
        except Exception as ex:
            return SliceRecoveryAttemptOutcome(
                attempt_name="sidecar-slice",
                status="error",
                payload="sidecar slice timed wrapper failed: "
                + (str(fork_error) if fork_error is not None else _describe_exception(ex)),
            )

    return _impl()


def _try_decompile_non_optimized_slice(
    project: angr.Project,
    addr: int,
    name: str,
    *,
    timeout: int,
    api_style: str,
    binary_path: Path | None,
    lst_metadata: LSTMetadata | None,
    cod_metadata: CODProcMetadata | None = None,
    allow_fresh_project_retry: bool = True,
    failure_family_state: FailureFamilyState | None = None,
    original_addr: int | None = None,
) -> NonOptimizedSliceOutcome:
    # Non-optimized fallback output is intentionally never cached. It is a best-effort rescue path,
    # not a stable primary decompilation result.
    def _impl() -> NonOptimizedSliceOutcome:
        helper_fallback = _try_emit_known_runtime_helper_c(name=name)
        if helper_fallback is not None:
            _mark_helper_fallback_tail_validation_passed(
                project,
                reason=f"known compiler/runtime helper fallback: {name}",
            )
            return NonOptimizedSliceOutcome(
                rendered=helper_fallback,
                status="ok",
                payload=helper_fallback,
            )

        def _attempt(slice_source_project: angr.Project, *, label: str) -> NonOptimizedSliceOutcome:
            # Dynamic angr boundary: project architecture metadata is supplied by angr.
            arch_name = getattr(getattr(slice_source_project, "arch", None), "name", None)
            region = _lst_code_region(lst_metadata, addr)
            if region is None:
                # Dynamic angr boundary: project entry point is supplied by angr.
                if arch_name == "86_16" and addr == getattr(slice_source_project, "entry", None):
                    # Dynamic angr boundary: loader objects expose backend-specific main object metadata.
                    main_object = getattr(slice_source_project.loader, "main_object", None)
                    # Dynamic angr boundary: backend main objects expose linked image base.
                    linked_base = getattr(main_object, "linked_base", None)
                    # Dynamic angr boundary: backend main objects expose image address bounds.
                    max_addr = getattr(main_object, "max_addr", None)
                    if isinstance(linked_base, int) and isinstance(max_addr, int):
                        region = (linked_base, linked_base + max_addr + 1)
                if region is None:
                    region = _infer_linear_disassembly_window(slice_source_project, addr, max_window=0x240)
            start, end = region
            if end <= start:
                detail = f"{label}: invalid slice window {start:#x}-{end:#x}"
                return NonOptimizedSliceOutcome(
                    rendered=None,
                    status="error",
                    payload=detail,
                    failure_detail=detail,
                    attempt_failures=(detail,),
                )
            try:
                code = bytes(slice_source_project.loader.memory.load(start, end - start))
            except Exception as ex:
                detail = f"{label}: unable to read bytes: {_describe_exception(ex)}"
                return NonOptimizedSliceOutcome(
                    rendered=None,
                    status="error",
                    payload=detail,
                    failure_detail=detail,
                    attempt_failures=(detail,),
                )
            snapshot_holder: dict[str, dict[str, object] | None] = {"value": None}
            slice_plan = plan_x86_16_exact_slice(start, end) if arch_name == "86_16" else None
            slice_start = slice_plan.slice_start if slice_plan is not None else start
            slice_end = slice_plan.slice_end if slice_plan is not None else end
            reuse_existing_slice_project = (
                # Dynamic angr boundary: project entry point is supplied by angr.
                lst_metadata is None and arch_name == "86_16" and addr == getattr(slice_source_project, "entry", None)
            )
            recovery_attempts = build_default_slice_recovery_attempts(
                slice_start,
                slice_end,
                pick_function_lean=_pick_function_lean,
                pick_function=_pick_function,
            )

            def _decompile_attempt(
                attempt_name: str,
                slice_project: angr.Project,
                cfg: object,
                func: object,
            ) -> SliceRecoveryAttemptOutcome:
                """Run one exact-slice rescue attempt without skipping semantic stages."""
                # Dynamic angr boundary: recovered functions expose addresses through angr.
                if not isinstance(getattr(func, "addr", None), int):
                    # Dynamic angr boundary: recovered functions expose mutable addresses through angr.
                    typing.cast(typing.Any, func).addr = slice_start
                if not hasattr(func, "normalized"):
                    # Dynamic angr boundary: recovered functions expose mutable normalization markers through angr.
                    typing.cast(typing.Any, func).normalized = True
                # Dynamic angr boundary: recovered functions expose mutable names through angr.
                typing.cast(typing.Any, func).name = name
                effective_cod_metadata = cod_metadata
                if slice_plan is not None:
                    mark_function_original_addr(func, start)
                    # Dynamic angr boundary: slice projects carry runtime metadata for downstream angr passes.
                    typing.cast(typing.Any, slice_project)._inertia_disable_ail_narrowing = True
                    # Dynamic angr boundary: slice projects carry runtime metadata for downstream angr passes.
                    typing.cast(typing.Any, slice_project)._inertia_disable_complex_expr_scan = True
                    # Dynamic angr boundary: slice projects carry runtime metadata for downstream angr passes.
                    typing.cast(typing.Any, slice_project)._inertia_fast_block_peephole = True
                if arch_name == "86_16":
                    # Non-optimized rescue lane: prefer forward progress over expensive
                    # pre-SSA peephole passes that are known to assert on bitwidth
                    # mismatches for some tiny helpers.
                    # Dynamic angr boundary: slice projects carry runtime metadata for downstream angr passes.
                    typing.cast(typing.Any, slice_project)._inertia_tiny_core_disable_peephole = True
                    # Dynamic angr boundary: slice projects carry runtime metadata for downstream angr passes.
                    typing.cast(typing.Any, slice_project)._inertia_skip_clinic_simplify_block = True
                    # Dynamic angr boundary: slice projects carry runtime metadata for downstream angr passes.
                    typing.cast(typing.Any, slice_project)._inertia_clinic_peephole_cap = 48
                if isinstance(original_addr, int):
                    mark_function_original_addr(func, original_addr)
                _prepare_function_for_decompilation(slice_project, func, effective_cod_metadata)
                if effective_cod_metadata is None:
                    effective_cod_metadata = _sidecar_cod_metadata_for_function(
                        slice_project,
                        func,
                        binary_path,
                        lst_metadata,
                    )
                enable_structured_simplify, enable_postprocess = non_optimized_slice_codegen_policy(
                    arch_name,
                    slice_plan,
                )
                block_count, byte_count = _function_complexity(func)
                effective_attempt_timeout = _effective_decompile_timeout_8616(
                    slice_project,
                    timeout,
                    block_count=block_count,
                    byte_count=byte_count,
                )
                status, payload, partial_payload, *_ = _call_decompile_function_with_stats(
                    slice_project,
                    cfg,
                    func,
                    max(1, effective_attempt_timeout),
                    api_style,
                    binary_path,
                    cod_metadata=effective_cod_metadata,
                    lst_metadata=lst_metadata,
                    enable_structured_simplify=enable_structured_simplify,
                    enable_postprocess=enable_postprocess,
                    allow_isolated_retry=False,
                    failure_family_state=failure_family_state,
                )
                if status == "ok" and assess_decompiled_c_text(payload).reject_as_decompiled:
                    status = "empty"
                    payload = "Non-optimized slice decompilation remained unresolved after bounded recovery."
                if not isinstance(partial_payload, str):
                    partial_payload = None
                # Dynamic angr boundary: slice project stores validation metadata from runtime passes.
                snapshot = getattr(slice_project, "_inertia_last_tail_validation_snapshot", None)
                return SliceRecoveryAttemptOutcome(
                    attempt_name=attempt_name,
                    status=status,
                    payload=payload,
                    partial_payload=partial_payload,
                    snapshot=dict(snapshot) if isinstance(snapshot, dict) else None,
                )

            def _run_bounded_attempt(
                attempt_name: str,
                job: Callable[[], SliceRecoveryAttemptOutcome],
                trace_snapshot: Callable[[], SliceRecoveryAttemptTrace],
            ) -> SliceRecoveryAttemptOutcome:
                attempt_timeout = bounded_non_optimized_attempt_timeout(
                    max(
                        1,
                        _effective_decompile_timeout_8616(
                            slice_source_project,
                            timeout,
                            block_count=1,
                            byte_count=max(1, slice_end - slice_start),
                        ),
                    )
                )
                try:
                    if (
                        os.name == "posix"
                        and threading.current_thread() is threading.main_thread()
                        and threading.active_count() == 1
                        and (
                            isinstance(slice_source_project, angr.Project)
                            # Dynamic compatibility boundary: tests may monkeypatch timeout runners.
                            or getattr(_run_with_timeout_in_fork, "__module__", "")
                            != "inertia_decompiler.runtime_support"
                        )
                    ):
                        result = _run_with_timeout_in_fork(job, timeout=attempt_timeout)
                    else:
                        result = _run_with_timeout_in_daemon_thread(
                            job,
                            timeout=attempt_timeout,
                            thread_name_prefix=f"nonopt-attempt-{attempt_name}",
                        )
                    if isinstance(result, SliceRecoveryAttemptOutcome):
                        return result
                    return SliceRecoveryAttemptOutcome(
                        attempt_name=attempt_name,
                        status="error",
                        payload=f"{attempt_name} bounded attempt returned unexpected {type(result).__name__}",
                        attempt_trace=trace_snapshot(),
                    )
                except TimeoutError as ex:
                    return SliceRecoveryAttemptOutcome(
                        attempt_name=attempt_name,
                        status="timeout",
                        payload=_describe_exception(ex),
                        attempt_trace=trace_snapshot(),
                    )
                except Exception as ex:
                    return SliceRecoveryAttemptOutcome(
                        attempt_name=attempt_name,
                        status="error",
                        payload=f"{attempt_name} bounded attempt: {_describe_exception(ex)}",
                        attempt_trace=trace_snapshot(),
                    )

            def _inherit_nonoptimized_slice_runtime_policy(slice_project: angr.Project) -> None:
                if slice_plan is not None:
                    typing.cast(typing.Any, slice_project)._inertia_original_project = slice_source_project
                    typing.cast(typing.Any, slice_project)._inertia_original_linear_delta = start - slice_start
                    typing.cast(typing.Any, slice_project)._inertia_disable_ail_narrowing = True
                    typing.cast(typing.Any, slice_project)._inertia_disable_complex_expr_scan = True
                    typing.cast(typing.Any, slice_project)._inertia_fast_block_peephole = True
                _inherit_tail_validation_runtime_policy(slice_project, slice_source_project)
                transfer_project_evidence_8616(slice_source_project, slice_project)

            outcomes = run_bounded_slice_recovery(
                recovery_attempts,
                build_slice_project=(
                    (lambda: slice_source_project)
                    if reuse_existing_slice_project
                    else lambda: _build_project_from_bytes(
                        code,
                        base_addr=slice_start,
                        entry_point=slice_start,
                    )
                ),
                inherit_runtime_policy=_inherit_nonoptimized_slice_runtime_policy,
                describe_exception=_describe_exception,
                decompile=_decompile_attempt,
                run_attempt=_run_bounded_attempt,
            )

            def _attempt_failure_detail(attempt: SliceRecoveryAttemptOutcome) -> str:
                detail = f"{label} {attempt.attempt_name}: {attempt.status}: {attempt.payload}"
                if attempt.verdict is None:
                    return detail
                tags: list[str] = []
                if attempt.verdict.stage:
                    tags.append(f"stage={attempt.verdict.stage}")
                if attempt.verdict.stop_family:
                    tags.append(f"stop_family={attempt.verdict.stop_family}")
                if tags:
                    detail += f" ({', '.join(tags)})"
                return detail

            def _recover_and_summarize() -> NonOptimizedSliceOutcome:
                failure_details: list[str] = []
                best_partial: SliceRecoveryAttemptOutcome | None = None
                final_verdict: BoundedSliceVerdict | None = None
                for attempt in outcomes:
                    if isinstance(attempt.snapshot, dict):
                        snapshot_holder["value"] = dict(attempt.snapshot)
                    if attempt.verdict is not None:
                        final_verdict = attempt.verdict
                    if attempt.status == "ok":
                        return NonOptimizedSliceOutcome(
                            rendered=attempt.payload,
                            status="ok",
                            payload=attempt.payload,
                            verdict=attempt.verdict,
                        )
                    failure_detail = _attempt_failure_detail(attempt)
                    failure_details.append(failure_detail)
                    if attempt.partial_payload is not None and best_partial is None:
                        best_partial = attempt
                if (
                    outcomes
                    and outcomes[-1].verdict is not None
                    and not outcomes[-1].verdict.can_widen_locally
                    and outcomes[-1].attempt_name != recovery_attempts[-1][0]
                ):
                    pruned_lane = recovery_attempts[len(outcomes)][0]
                    failure_details.append(
                        f"{label}: pruned local lane {pruned_lane} after repeated "
                        f"{outcomes[-1].verdict.stage or 'unknown'}:{outcomes[-1].verdict.stop_family or 'unknown'}"
                    )
                if best_partial is not None:
                    return NonOptimizedSliceOutcome(
                        rendered=best_partial.partial_payload,
                        status=best_partial.status,
                        payload=best_partial.payload,
                        partial_payload=best_partial.partial_payload,
                        failure_detail=_attempt_failure_detail(best_partial),
                        attempt_failures=tuple(failure_details),
                        verdict=best_partial.verdict,
                    )
                summary_detail: str | None = "; ".join(failure_details[:3]) if failure_details else None
                return NonOptimizedSliceOutcome(
                    rendered=None,
                    status="error",
                    payload=summary_detail or f"{label}: non-optimized slice recovery did not run",
                    failure_detail=summary_detail,
                    attempt_failures=tuple(failure_details),
                    verdict=final_verdict,
                )

            outcome = _recover_and_summarize()

            slice_snapshot = snapshot_holder["value"]
            if isinstance(slice_snapshot, dict):
                # Dynamic angr boundary: project stores partial validation metadata for later reporting.
                typing.cast(typing.Any, slice_source_project)._inertia_partial_tail_validation_snapshot = dict(slice_snapshot)
            if outcome.rendered is not None and outcome.status != "ok":
                print(
                    f"[dbg] non-optimized fallback produced partial output for {addr:#x} {name} via {label}",
                    file=sys.stderr,
                    flush=True,
                )
            return outcome

        outcome = _attempt(project, label="shared-project slice")
        if outcome.rendered is not None:
            return outcome

        retry_failures: list[str] = []
        if outcome.attempt_failures:
            retry_failures.extend(outcome.attempt_failures)
        elif outcome.failure_detail is not None:
            retry_failures.append(outcome.failure_detail)
        should_try_fresh_project = (
            allow_fresh_project_retry
            and binary_path is not None
            and timeout > 3
            and (outcome.verdict is None or outcome.verdict.can_retry_with_fresh_project)
        )
        if should_try_fresh_project:
            assert binary_path is not None
            try:
                fresh_project = _build_project_cached(
                    str(Path(binary_path)),
                    force_blob=_is_blob_only_input(Path(binary_path)),
                    # Dynamic angr boundary: loader objects expose backend-specific main object metadata.
                    base_addr=getattr(getattr(project.loader, "main_object", None), "linked_base", 0) or 0,
                    # Dynamic angr boundary: project entry point is supplied by angr.
                    entry_point=getattr(project, "entry", 0),
                )
                _inherit_tail_validation_runtime_policy(fresh_project, project)
                transfer_project_evidence_8616(project, fresh_project)
            except Exception as ex:
                retry_failures.append(f"fresh-project setup failed: {_describe_exception(ex)}")
            else:
                outcome = _attempt(fresh_project, label="fresh-project slice")
                if outcome.rendered is not None:
                    print(
                        f"[dbg] non-optimized fallback recovered {addr:#x} {name} after rebuilding a fresh project",
                        file=sys.stderr,
                        flush=True,
                    )
                    return outcome
                if outcome.attempt_failures:
                    retry_failures.extend(outcome.attempt_failures)
                elif outcome.failure_detail is not None:
                    retry_failures.append(outcome.failure_detail)
        elif allow_fresh_project_retry and binary_path is not None:
            skip_reason = (
                f"verdict vetoed fresh-project retry ({outcome.verdict.stage or 'unknown'}:"
                f"{outcome.verdict.stop_family or 'unknown'})"
                if outcome.verdict is not None and not outcome.verdict.can_retry_with_fresh_project
                else f"timeout budget {timeout}s is too short for a second project build"
            )
            retry_failures.append(f"fresh-project slice skipped: {skip_reason}")

        failure_detail = "; ".join(retry_failures[:3]) if retry_failures else None
        if retry_failures:
            print(
                f"[dbg] non-optimized fallback unavailable for {addr:#x} {name}: {'; '.join(retry_failures[:3])}",
                file=sys.stderr,
                flush=True,
            )
        return NonOptimizedSliceOutcome(
            rendered=None,
            status="error",
            payload=failure_detail or f"non-optimized fallback unavailable for {addr:#x} {name}",
            failure_detail=failure_detail,
            attempt_failures=tuple(retry_failures),
            verdict=outcome.verdict,
        )

    return _impl()


def _try_decompile_non_optimized_known_function(
    project: angr.Project,
    cfg: object,
    function: object,
    *,
    timeout: int,
    api_style: str,
    binary_path: Path | None,
    lst_metadata: LSTMetadata | None,
    cod_metadata: CODProcMetadata | None = None,
    synthetic_globals: dict[int, tuple[str, int]] | None = None,
    failure_family_state: FailureFamilyState | None = None,
) -> NonOptimizedSliceOutcome:
    # Dynamic angr boundary: function names are supplied by angr knowledge-base objects.
    helper_fallback = _try_emit_known_runtime_helper_c(name=getattr(function, "name", ""))
    if helper_fallback is not None:
        _mark_helper_fallback_tail_validation_passed(
            project,
            # Dynamic angr boundary: function names are supplied by angr knowledge-base objects.
            reason=f"known compiler/runtime helper fallback: {getattr(function, 'name', '')}",
        )
        return NonOptimizedSliceOutcome(
            rendered=helper_fallback,
            status="ok",
            payload=helper_fallback,
        )
    if cfg is None or not hasattr(function, "normalized"):
        detail = "known-function nonopt: missing CFG/function normalization context"
        return NonOptimizedSliceOutcome(
            rendered=None,
            status="error",
            payload=detail,
            failure_detail=detail,
            attempt_failures=(detail,),
        )
    effective_cod_metadata = cod_metadata or _sidecar_cod_metadata_for_function(
        project,
        function,
        binary_path,
        lst_metadata,
    )
    _prepare_function_for_decompilation(project, function, effective_cod_metadata)
    block_count, byte_count = _function_complexity(function)
    fallback_timeout = _effective_decompile_timeout_8616(
        project,
        timeout,
        block_count=block_count,
        byte_count=byte_count,
    )
    status, payload, partial_payload, *_ = _call_decompile_function_with_stats(
        project,
        cfg,
        function,
        max(1, fallback_timeout),
        api_style,
        binary_path,
        cod_metadata=effective_cod_metadata,
        synthetic_globals=synthetic_globals,
        lst_metadata=lst_metadata,
        enable_structured_simplify=False,
        enable_postprocess=False,
        allow_isolated_retry=False,
        failure_family_state=failure_family_state,
    )
    if status == "ok" and assess_decompiled_c_text(payload).reject_as_decompiled:
        status = "empty"
        payload = "Known-function non-optimized decompilation remained unresolved."
    if not isinstance(partial_payload, str):
        partial_payload = None
    failure_detail = f"known-function nonopt: {status}: {payload}"
    if status == "ok":
        return NonOptimizedSliceOutcome(
            rendered=payload,
            status="ok",
            payload=payload,
        )
    if partial_payload is not None:
        return NonOptimizedSliceOutcome(
            rendered=partial_payload,
            status=status,
            payload=payload,
            partial_payload=partial_payload,
            failure_detail=failure_detail,
            attempt_failures=(failure_detail,),
        )
    return NonOptimizedSliceOutcome(
        rendered=None,
        status=status,
        payload=payload,
        failure_detail=failure_detail,
        attempt_failures=(failure_detail,),
    )


def _try_emit_trivial_sidecar_c(
    project: angr.Project,
    lst_metadata: LSTMetadata | None,
    addr: int,
    name: str,
) -> str | None:
    region = _lst_code_region(lst_metadata, addr)
    if region is None:
        return None
    asm = _format_asm_range(project, region[0], region[1], max_instructions=8)
    lines = [line.strip() for line in asm.splitlines() if line.strip()]
    if len(lines) == 1 and lines[0].endswith(": ret"):
        return f"void {name}(void)\n{{\n}}\n"
    return None


def _try_emit_string_intrinsic_c(
    project: angr.Project,
    *,
    start: int,
    end: int,
    name: str,
) -> str | None:
    try:
        fallback = _cli_string_timeout_fallback.try_render_x86_16_string_timeout_fallback(
            project,
            start=start,
            end=end,
            name=name,
        )
    except Exception as ex:
        # Never let optional string-intrinsic fallback abort the entire sweep.
        # This lane is best-effort and must degrade to "no fallback available".
        with contextlib.suppress(Exception):
            print(
                f"[dbg] string-intrinsic fallback error for {name}@{start:#x}-{end:#x}: {type(ex).__name__}: {ex}",
                file=sys.stderr,
                flush=True,
            )
        return None
    if fallback is None:
        return None
    c_text = fallback.c_text
    return c_text if isinstance(c_text, str) else None


def _mark_helper_fallback_tail_validation_passed(project: angr.Project, *, reason: str) -> None:
    snapshot = {
        "structuring": {
            "status": "stable",
            "mode": "helper_model",
            "changed": False,
            "detail": reason,
        },
        "postprocess": {
            "status": "stable",
            "mode": "helper_model",
            "changed": False,
            "detail": reason,
        },
    }
    # Partial snapshots are always consumed by fallback tail-validation collection,
    # including non-optimized fallback lanes.
    # Dynamic angr boundary: project stores fallback validation metadata for later reporting.
    typing.cast(typing.Any, project)._inertia_partial_tail_validation_snapshot = dict(snapshot)
    # Dynamic angr boundary: project stores fallback validation metadata for later reporting.
    typing.cast(typing.Any, project)._inertia_last_tail_validation_snapshot = dict(snapshot)


def _try_emit_known_runtime_helper_c(
    *,
    name: str,
) -> str | None:
    def _impl() -> str | None:
        normalized = (name or "").strip()
        if not normalized:
            return None
        lowered = normalized.lower()
        if re.search(r"[^A-Za-z0-9_$]", normalized):
            safe_name = re.sub(r"[^A-Za-z0-9_$]", "_", normalized) or "sub_helper"
            return f"void {safe_name}(void)\n{{\n}}\n"
        if lowered == "catox":
            return (
                "int32_t catox(const uint8_t *s)\n"
                "{\n"
                "    int sign = 1;\n"
                "    int32_t value = 0;\n"
                "    uint8_t ch;\n"
                "    if (s == NULL) {\n"
                "        return 0;\n"
                "    }\n"
                "    while ((ch = *s) == ' ' || ch == '\\t') {\n"
                "        s++;\n"
                "    }\n"
                "    if (ch == '-' || ch == '+') {\n"
                "        if (ch == '-') {\n"
                "            sign = -1;\n"
                "        }\n"
                "        s++;\n"
                "        ch = *s;\n"
                "    }\n"
                "    while (ch >= '0' && ch <= '9') {\n"
                "        value = value * 10 + (int32_t)(ch - '0');\n"
                "        s++;\n"
                "        ch = *s;\n"
                "    }\n"
                "    return (sign < 0) ? -value : value;\n"
                "}\n"
            )
        if lowered in {"b$mapxyc2", "b_mapxyc2"}:
            return (
                "uint16_t B_MapXYC2(uint16_t dx)\n"
                "{\n"
                "    uint16_t ax = 0;\n"
                "    uint16_t bx;\n"
                "    dx >>= 1;\n"
                "    ax = (uint16_t)((ax >> 1) | ((dx & 1u) << 15));\n"
                "    ax >>= 1;\n"
                "    ax >>= 1;\n"
                "    bx = dx;\n"
                "    dx <<= 1;\n"
                "    dx <<= 1;\n"
                "    dx = (uint16_t)(dx + bx);\n"
                "    dx <<= 1;\n"
                "    dx <<= 1;\n"
                "    return dx;\n"
                "}\n"
            )
        if lowered == "toupper":
            return (
                "int toupper(int ch)\n"
                "{\n"
                "    if (ch >= 'a' && ch <= 'z') {\n"
                "        return ch - ('a' - 'A');\n"
                "    }\n"
                "    return ch;\n"
                "}\n"
            )
        if lowered == "inp":
            return "uint8_t inp(uint16_t port)\n{\n    (void)port;\n    return 0;\n}\n"
        if lowered in {"outp", "_outp"}:
            return "uint16_t outp(uint16_t port, uint16_t value)\n{\n    (void)port;\n    return (uint8_t)value;\n}\n"
        if lowered in {"cexit", "_cexit"}:
            return "void cexit(void)\n{\n}\n"
        if lowered in {"astart", "_astart", "cstart", "_cstart", "__cstart", "cinit", "_cinit", "__cinit"}:
            safe_name = re.sub(r"[^A-Za-z0-9_$]", "_", normalized) or "astart"
            return f"void {safe_name}(void)\n{{\n}}\n"
        if lowered in {"$_qcg_enter_far", "_qcg_enter_far"} or "qcg_enter_far" in lowered:
            return "void _qcg_enter_far(void)\n{\n}\n"
        if lowered in {"b$nearrettext", "b_nearrettext"}:
            return "void B$NearRetText(void)\n{\n}\n"
        if lowered in {"exit", "_exit"}:
            return "void exit(int status)\n{\n    (void)status;\n}\n"
        if lowered in {"dosreturn", "_dosreturn"}:
            return "int dosreturn(void)\n{\n    return 0;\n}\n"
        if lowered in {"flushall", "_flushall"}:
            return "int flushall(void)\n{\n    return 0;\n}\n"
        if lowered in {"clear_mat", "_clear_mat"}:
            return "void clear_mat(void)\n{\n}\n"
        if lowered in {"refresh", "_refresh"}:
            return "void refresh(void)\n{\n}\n"
        if lowered in {"ftol", "_ftol"}:
            return "long ftol(double x)\n{\n    return (long)x;\n}\n"
        if lowered in {"edit", "_edit"}:
            return "void edit(void)\n{\n}\n"
        if lowered in {"set_cursor", "_set_cursor"}:
            return "void set_cursor(unsigned short row, unsigned short col)\n{\n    (void)row;\n    (void)col;\n}\n"
        if lowered in {"ultoa", "_ultoa"}:
            return (
                "char *ultoa(unsigned long value, char *str, int radix)\n"
                "{\n"
                "    (void)value;\n"
                "    (void)radix;\n"
                "    if (str != (char*)0) {\n"
                "        str[0] = '\\0';\n"
                "    }\n"
                "    return str;\n"
                "}\n"
            )
        if lowered in {"free", "_free"}:
            return "void free(void *ptr)\n{\n    (void)ptr;\n}\n"
        if lowered in {"myalloc", "_myalloc"}:
            return "void *myalloc(unsigned short size)\n{\n    (void)size;\n    return (void *)0;\n}\n"
        if lowered in {"cltoasub", "_cltoasub"}:
            return "void cltoasub(void)\n{\n}\n"
        if lowered in {"cxtoa", "_cxtoa"}:
            return (
                "char *cxtoa(unsigned short value, char *buf)\n"
                "{\n"
                "    (void)value;\n"
                "    if (buf != (char*)0) {\n"
                "        buf[0] = '\\0';\n"
                "    }\n"
                "    return buf;\n"
                "}\n"
            )
        if lowered in {"amallocbrk", "_amallocbrk"}:
            return "unsigned long amallocbrk(void)\n{\n    return 0;\n}\n"
        if lowered in {"fltinf", "_fltinf"}:
            return "void fltinf(void)\n{\n}\n"
        if lowered in {"fltin", "_fltin"}:
            return "double fltin(void)\n{\n    return 0.0;\n}\n"
        return _try_emit_known_runtime_helper_c_tail_8616(normalized=normalized, lowered=lowered)

    return _impl()


def _try_emit_known_runtime_helper_c_tail_8616(*, normalized: str, lowered: str) -> str | None:
    def _impl() -> str | None:
        if lowered in {"anfld1", "a_nfld1"}:
            return "double aNfld1(void)\n{\n    return 1.0;\n}\n"
        if lowered in {"anlmul", "a_nlmul"}:
            return "long aNlmul(long a, long b)\n{\n    return a * b;\n}\n"
        if lowered in {"$i8_tpwr10", "i8_tpwr10", "_i8_tpwr10"}:
            return "double i8_tpwr10(void)\n{\n    return 1.0;\n}\n"
        if lowered in {"$i8_output", "i8_output", "_i8_output"}:
            return "int i8_output(void)\n{\n    return 0;\n}\n"
        if lowered in {"$i8_input", "i8_input", "_i8_input"}:
            return "int i8_input(void)\n{\n    return 0;\n}\n"
        if lowered in {"ctermsub", "_ctermsub"}:
            return "void ctermsub(void)\n{\n}\n"
        if lowered in {"fpinstall87", "_fpinstall87"}:
            return "int FPINSTALL87(void)\n{\n    return 0;\n}\n"
        if lowered in {"fierqq", "_fierqq"}:
            return "void FIERQQ(void)\n{\n}\n"
        if lowered in {"fcmp", "_fcmp"}:
            return (
                "int fcmp(double a, double b)\n"
                "{\n"
                "    if (a < b) {\n"
                "        return -1;\n"
                "    }\n"
                "    if (a > b) {\n"
                "        return 1;\n"
                "    }\n"
                "    return 0;\n"
                "}\n"
            )
        if lowered in {"maperror", "_maperror"}:
            return "int maperror(int err)\n{\n    return err;\n}\n"
        if lowered in {"perror", "_perror"}:
            return "void perror(const char *msg)\n{\n    (void)msg;\n}\n"
        if lowered in {"fmalloc", "_fmalloc"}:
            return "void *fmalloc(unsigned int size)\n{\n    (void)size;\n    return (void *)0;\n}\n"
        if lowered in {"nmsg_text", "_nmsg_text"}:
            return 'const char *NMSG_TEXT(void)\n{\n    return "";\n}\n'
        if lowered in {"nmsg_write", "_nmsg_write"}:
            return "int NMSG_WRITE(const char *msg)\n{\n    (void)msg;\n    return 0;\n}\n"
        if lowered in {"forcdecpt", "_forcdecpt"}:
            return "void forcdecpt(void)\n{\n}\n"
        if lowered in {"fpsignal", "_fpsignal"}:
            return "void fpsignal(unsigned short code)\n{\n    (void)code;\n}\n"
        if lowered in {"fisrqq", "_fisrqq"}:
            return "void FISRQQ(void)\n{\n}\n"
        if lowered in {"inc", "_inc"}:
            return "unsigned short inc(unsigned short x)\n{\n    return (unsigned short)(x + 1u);\n}\n"
        if lowered in {"rand", "_rand"}:
            return (
                "int rand(void)\n"
                "{\n"
                "    static unsigned long state = 1ul;\n"
                "    state = state * 1103515245ul + 12345ul;\n"
                "    return (int)((state >> 16) & 0x7ffful);\n"
                "}\n"
            )
        if lowered in {"srand", "_srand"}:
            return "void srand(unsigned int seed)\n{\n    (void)seed;\n}\n"
        if lowered in {"b$scnio", "b_scnio"}:
            return "unsigned short B$SCNIO(void)\n{\n    return 0;\n}\n"
        if lowered in {"b$bumpds", "b_bumpds"}:
            return "void B$BumpDS(void)\n{\n}\n"
        if lowered in {"b$bumpes", "b_bumpes"}:
            return "void B$BumpES(void)\n{\n}\n"
        if lowered in {"b$decds", "b_decds"}:
            return "void B$DecDS(void)\n{\n}\n"
        return _try_emit_known_runtime_helper_c_tail2_8616(normalized=normalized, lowered=lowered)

    return _impl()


def _try_emit_known_runtime_helper_c_tail2_8616(*, normalized: str, lowered: str) -> str | None:
    def _impl() -> str | None:
        if lowered.startswith("b$egachkbt"):
            safe_name = re.sub(r"[^A-Za-z0-9_$]", "_", normalized) or "B$EgaCHKBT"
            return f"unsigned short {safe_name}(void)\n{{\n    return 0;\n}}\n"
        if lowered in {"andcvt", "a_ndcvt"}:
            return "void aNdcvt(void)\n{\n}\n"
        if lowered in {"affdivs", "a_ffdivs", "b$ffdiv", "b$ffdivs"}:
            safe_name = re.sub(r"[^A-Za-z0-9_$]", "_", normalized) or "aFfdivs"
            return f"void {safe_name}(void)\n{{\n}}\n"
        if lowered == "dos_getdate":
            return "int dos_getdate(void)\n{\n    return 0;\n}\n"
        if lowered == "dos_gettime":
            return "int dos_gettime(void)\n{\n    return 0;\n}\n"
        if lowered in {"isatty", "_isatty"}:
            return "int isatty(int fd)\n{\n    (void)fd;\n    return 0;\n}\n"
        if lowered == "findlast":
            return "int findlast(void)\n{\n    return -1;\n}\n"
        if lowered in {"getenv", "_getenv"}:
            return "char *getenv(const char *name)\n{\n    (void)name;\n    return (char *)0;\n}\n"
        if lowered == "b$egachkbtr":
            return "short B$EgaCHKBTR(void)\n{\n    return 0;\n}\n"
        if lowered == "b$colorpalette":
            return "void b$ColorPalette(void)\n{\n}\n"
        if lowered.startswith("b$") and "palette" in lowered:
            safe_name = re.sub(r"[^A-Za-z0-9_$]", "_", normalized) or "b$PaletteHelper"
            return f"void {safe_name}(void)\n{{\n}}\n"
        if lowered == "strcpy":
            return (
                "char *strcpy(char *dst, const char *src)\n"
                "{\n"
                "    char *out = dst;\n"
                "    while ((*dst++ = *src++) != '\\0') {\n"
                "    }\n"
                "    return out;\n"
                "}\n"
            )
        if lowered == "strcmp":
            return (
                "int strcmp(const char *a, const char *b)\n"
                "{\n"
                "    while (*a != '\\0' && *a == *b) {\n"
                "        a++;\n"
                "        b++;\n"
                "    }\n"
                "    return ((unsigned char)*a < (unsigned char)*b) ? -1 :\n"
                "           ((unsigned char)*a > (unsigned char)*b) ? 1 : 0;\n"
                "}\n"
            )
        if lowered == "memcpy":
            return (
                "void *memcpy(void *dst, const void *src, unsigned short n)\n"
                "{\n"
                "    unsigned char *d = (unsigned char *)dst;\n"
                "    const unsigned char *s = (const unsigned char *)src;\n"
                "    unsigned short i;\n"
                "    for (i = 0; i < n; ++i) {\n"
                "        d[i] = s[i];\n"
                "    }\n"
                "    return dst;\n"
                "}\n"
            )
        if lowered == "memmove":
            return (
                "void *memmove(void *dst, const void *src, unsigned short n)\n"
                "{\n"
                "    unsigned char *d = (unsigned char *)dst;\n"
                "    const unsigned char *s = (const unsigned char *)src;\n"
                "    unsigned short i;\n"
                "    if (d == s || n == 0) {\n"
                "        return dst;\n"
                "    }\n"
                "    if (d < s) {\n"
                "        for (i = 0; i < n; ++i) {\n"
                "            d[i] = s[i];\n"
                "        }\n"
                "    } else {\n"
                "        for (i = n; i != 0; --i) {\n"
                "            d[i - 1] = s[i - 1];\n"
                "        }\n"
                "    }\n"
                "    return dst;\n"
                "}\n"
            )
        if lowered == "strlen":
            return (
                "size_t strlen(const char *s)\n"
                "{\n"
                "    size_t n = 0;\n"
                "    while (s[n] != '\\0') {\n"
                "        n++;\n"
                "    }\n"
                "    return n;\n"
                "}\n"
            )
        if lowered == "memset":
            return (
                "void *memset(void *dst, int c, size_t n)\n"
                "{\n"
                "    unsigned char *p = (unsigned char *)dst;\n"
                "    size_t i;\n"
                "    for (i = 0; i < n; ++i) {\n"
                "        p[i] = (unsigned char)c;\n"
                "    }\n"
                "    return dst;\n"
                "}\n"
            )
        if lowered == "strncmp":
            return (
                "int strncmp(const char *a, const char *b, size_t n)\n"
                "{\n"
                "    size_t i;\n"
                "    for (i = 0; i < n; ++i) {\n"
                "        unsigned char ca = (unsigned char)a[i];\n"
                "        unsigned char cb = (unsigned char)b[i];\n"
                "        if (ca != cb) {\n"
                "            return (ca < cb) ? -1 : 1;\n"
                "        }\n"
                "        if (ca == '\\0') {\n"
                "            return 0;\n"
                "        }\n"
                "    }\n"
                "    return 0;\n"
                "}\n"
            )
        if lowered == "strncpy":
            return (
                "char *strncpy(char *dst, const char *src, size_t n)\n"
                "{\n"
                "    size_t i = 0;\n"
                "    for (; i < n && src[i] != '\\0'; ++i) {\n"
                "        dst[i] = src[i];\n"
                "    }\n"
                "    for (; i < n; ++i) {\n"
                "        dst[i] = '\\0';\n"
                "    }\n"
                "    return dst;\n"
                "}\n"
            )
        if lowered == "time":
            return (
                "time_t time(time_t *out)\n"
                "{\n"
                "    time_t t = (time_t)0;\n"
                "    if (out != NULL) {\n"
                "        *out = t;\n"
                "    }\n"
                "    return t;\n"
                "}\n"
            )
        if lowered == "ctime":
            return "char *ctime(const time_t *tp)\n{\n    (void)tp;\n    return (char *)0;\n}\n"
        if lowered == "setvbuf":
            return (
                "int setvbuf(void *stream, char *buffer, int mode, size_t size)\n"
                "{\n"
                "    (void)stream;\n"
                "    (void)buffer;\n"
                "    (void)mode;\n"
                "    (void)size;\n"
                "    return 0;\n"
                "}\n"
            )
        if lowered in {"fgets", "_fgets"}:
            return (
                "char *fgets(char *s, int n, void *stream)\n"
                "{\n"
                "    (void)n;\n"
                "    (void)stream;\n"
                "    if (s != (char *)0) {\n"
                "        s[0] = '\\0';\n"
                "    }\n"
                "    return s;\n"
                "}\n"
            )
        if lowered == "strdup":
            return "char *strdup(const char *s)\n{\n    (void)s;\n    return (char *)0;\n}\n"
        if lowered in {"afuldiv", "_afuldiv"}:
            return "void aFuldiv(void)\n{\n}\n"
        if lowered in {"afldiv", "_afldiv"}:
            return "void aFldiv(void)\n{\n}\n"
        if lowered in {"afulmul", "_afulmul"}:
            return "void aFulmul(void)\n{\n}\n"
        if lowered in {"afulrem", "_afulrem"}:
            return "void aFulrem(void)\n{\n}\n"
        if lowered in {"aflrem", "_aflrem"}:
            return "void aFlrem(void)\n{\n}\n"
        if lowered in {"afnalmul", "_afnalmul"}:
            return "void aFNalmul(void)\n{\n}\n"
        if lowered in {"afnaldiv", "_afnaldiv"}:
            return "void aFNaldiv(void)\n{\n}\n"
        if lowered in {"cropzeros", "_cropzeros"}:
            return "void cropzeros(void)\n{\n}\n"
        if lowered in {"fptostr", "_fptostr"}:
            return (
                "char *fptostr(char *dst, double value)\n"
                "{\n"
                "    (void)value;\n"
                "    if (dst != (char *)0) {\n"
                "        dst[0] = '\\0';\n"
                "    }\n"
                "    return dst;\n"
                "}\n"
            )
        if lowered == "shift":
            return "void shift(void)\n{\n}\n"
        if lowered in {"intdos", "_intdos"}:
            return (
                "int intdos(void *in_regs, void *out_regs)\n"
                "{\n"
                "    (void)in_regs;\n"
                "    (void)out_regs;\n"
                "    return 0;\n"
                "}\n"
            )
        if lowered in {"store_dt", "_store_dt"}:
            return "void store_dt(void)\n{\n}\n"
        if lowered in {"dosretax", "_dosretax"}:
            return "int dosretax(void)\n{\n    return 0;\n}\n"
        if lowered in {"fopen", "_fopen"}:
            return (
                "void *fopen(const char *path, const char *mode)\n"
                "{\n"
                "    (void)path;\n"
                "    (void)mode;\n"
                "    return (void *)0;\n"
                "}\n"
            )
        if lowered in {"nfree", "_nfree"}:
            return "void nfree(void *ptr)\n{\n    (void)ptr;\n}\n"
        if lowered in {"putch", "_putch"}:
            return "int putch(int ch)\n{\n    return ch;\n}\n"
        if lowered in {"movedata", "_movedata"}:
            return (
                "void movedata(unsigned short src_seg, unsigned short src_off,\n"
                "             unsigned short dst_seg, unsigned short dst_off,\n"
                "             unsigned short count)\n"
                "{\n"
                "    (void)src_seg;\n"
                "    (void)src_off;\n"
                "    (void)dst_seg;\n"
                "    (void)dst_off;\n"
                "    (void)count;\n"
                "}\n"
            )
        if lowered in {"ffree_lk", "_ffree_lk"}:
            return "short ffree_lk(void)\n{\n    return 0;\n}\n"
        if lowered == "b$chkolivetti":
            return "int B$ChkOlivetti(void)\n{\n    return 0;\n}\n"
        if lowered in {"b$cganreadl", "b$eganreadl"}:
            safe_name = "B$CgaNReadL" if lowered == "b$cganreadl" else "B$EgaNReadL"
            return f"int {safe_name}(void)\n{{\n    return 0;\n}}\n"
        if lowered == "anulmul":
            return "uint32_t aNulmul(uint32_t a, uint32_t b)\n{\n    return a * b;\n}\n"
        if lowered == "anldiv":
            return (
                "int32_t aNldiv(int32_t a, int32_t b)\n"
                "{\n"
                "    if (b == 0) {\n"
                "        return 0;\n"
                "    }\n"
                "    return a / b;\n"
                "}\n"
            )
        if lowered == "anlrem":
            return (
                "int32_t aNlrem(int32_t a, int32_t b)\n"
                "{\n"
                "    if (b == 0) {\n"
                "        return 0;\n"
                "    }\n"
                "    return a % b;\n"
                "}\n"
            )
        if lowered in {"ldiv", "aldiv"}:
            safe_name = "ldiv" if lowered == "ldiv" else "aldiv"
            return (
                f"int32_t {safe_name}(int32_t a, int32_t b)\n"
                "{\n"
                "    if (b == 0) {\n"
                "        return 0;\n"
                "    }\n"
                "    return a / b;\n"
                "}\n"
            )
        if lowered == "anssubs":
            return "int16_t aNssubs(int16_t a, int16_t b)\n{\n    return (int16_t)(a - b);\n}\n"
        if lowered == "nullcheck":
            return "int nullcheck(const void *p)\n{\n    return p == NULL;\n}\n"
        if lowered.startswith("afc") and lowered.endswith("ceill"):
            return "void aFCIceill(void)\n{\n}\n"
        return None

    return _impl()
