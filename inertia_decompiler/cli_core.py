"""Layer: CLI/fallback/reporting.

Responsibility: orchestrate commands, fallback lanes, diagnostics, and output policy.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
Dynamic attributes in this CLI boundary are limited to third-party angr/codegen compatibility objects.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import typing
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence, Sized
from concurrent.futures import FIRST_COMPLETED, wait
from concurrent.futures import TimeoutError as FuturesTimeoutError
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import angr
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr_platforms.X86_16.analysis_helpers import collect_neighbor_call_targets
from angr_platforms.X86_16.annotations import annotate_function
from angr_platforms.X86_16.callsite_summary import (
    CallerReturnUseEvidence8616,
    caller_return_use_evidence_by_addr_8616,
)
from angr_platforms.X86_16.cod_analysis_image import build_cod_analysis_image_8616
from angr_platforms.X86_16.cod_extract import (
    CODProcMetadata,
    extract_cod_function_entries,
    extract_cod_proc_metadata,
    extract_simple_cod_logic_entries,
    extract_small_two_arg_cod_logic_entries,
    infer_cod_logic_start,
)
from angr_platforms.X86_16.compiler_helpers import is_x86_16_stack_probe_name_8616
from angr_platforms.X86_16.lowering.c_runtime_header import render_c_runtime_header_8616
from angr_platforms.X86_16.lst_extract import LSTMetadata
from angr_platforms.X86_16.pipeline.errors import PipelineHardError
from angr_platforms.X86_16.segment_program_layout_codec import segment_program_function_evidence_from_record_8616
from angr_platforms.X86_16.segment_program_layout_contract import SegmentProgramFunctionEvidence8616
from angr_platforms.X86_16.structuring.compare32_recovery import recover_32bit_compare_c_8616
from angr_platforms.X86_16.structuring.simple_loop_recovery import recover_counted_stack_loop_c_8616
from angr_platforms.X86_16.synthetic_call_stub_evidence import record_synthetic_call_stubs_8616
from angr_platforms.X86_16.tail_validation import (
    extract_x86_16_tail_validation_snapshot as _extract_x86_16_tail_validation_snapshot,
)
from angr_platforms.X86_16.tail_validation import x86_16_tail_validation_snapshot_passed

from inertia_decompiler.accepted_payload_integrity import (
    AcceptedPayloadIntegrityVerdict8616,
    verify_function_work_result_payload_integrity_8616,
)
from inertia_decompiler.architecture_runtime_guard import (
    ARCHITECTURE_GUARD_VERIFIED_PARENT_PID_ENV,
    DecompilerArchitectureGuardError,
    assert_decompiler_architecture_clean,
)
from inertia_decompiler.binary_signature_metadata import load_binary_signature_metadata
from inertia_decompiler.c_text_cleanup import normalize_unresolved_c_text
from inertia_decompiler.cache import (
    _cache_key_lock,
    _load_cache_json,
    _store_cache_json,
)
from inertia_decompiler.cli_arg_parser import CliArguments, parse_cli_arguments
from inertia_decompiler.cli_batch_c_output import BatchCOutputStatus8616, build_batch_c_output_8616
from inertia_decompiler.cli_c_text_postprocess import _prune_invalid_simple_function_prototypes_text
from inertia_decompiler.cli_output import (
    _print_asm_fallback_text,
    _print_diagnostic_text,
    _timestamped_print,
)
from inertia_decompiler.cli_timeout import (
    PARALLEL_CLEAN_WORKER_TIMEOUT_CAP,
    _AdaptivePerByteTimeoutModel,
    _default_recovery_timeout,
    _stdout_is_interactive,
    build_parallel_clean_worker_timeout_model,
    retry_timeout_after_failed_attempt,
)
from inertia_decompiler.cod_module_caller_evidence import record_cod_module_caller_return_use_evidence_8616
from inertia_decompiler.decompilation_quality import assess_decompiled_c_text, assess_final_generated_c_text
from inertia_decompiler.decompile_file_summary import emit_file_decompilation_summary
from inertia_decompiler.default_signature_catalog import default_signature_catalog_path
from inertia_decompiler.direct_addr_failure_family import (
    FailureFamilySnapshot,
    FailureFamilyState,
    build_failure_family_snapshot,
)
from inertia_decompiler.direct_request_cache import (
    DirectRequestCacheArtifact8616,
    DirectRequestCacheLookup8616,
    DirectRequestCacheVerdict8616,
    load_direct_request_cache_8616,
    render_direct_request_tail_snapshot_diagnostic_8616,
    store_direct_request_cache_8616,
)
from inertia_decompiler.direct_request_identity import (
    DirectRequestCacheInputs8616,
    build_direct_request_cache_key_8616,
    direct_request_cache_enabled_8616,
)
from inertia_decompiler.disassembly_helpers import (
    _format_asm_range,
    _format_first_block_asm,
    _infer_linear_disassembly_window,
    _probe_lift_break,
)
from inertia_decompiler.fork_timeout import run_captured_subprocess_tree
from inertia_decompiler.function_cache_context import function_decompilation_cache_key_8616
from inertia_decompiler.function_worker_policy import (
    FunctionWorkerMode8616,
    clean_process_override_8616,
    prioritize_clean_function_work_8616,
    requires_isolated_function_decompilation,
    select_function_worker_policy_8616,
)
from inertia_decompiler.generated_c_artifacts import (
    write_generated_function_c,
    write_generated_translation_unit_c,
)
from inertia_decompiler.generated_c_function_extraction import relabel_generated_function_definition
from inertia_decompiler.library_function_classifier import (
    filter_code_labels_for_library_policy,
    is_library_like_function_name,
)
from inertia_decompiler.metadata_evidence import has_only_binary_signatures
from inertia_decompiler.non_optimized_fallback import (
    allows_heavy_fallbacks_for_run,
    describe_non_optimized_unavailable,
    sidecar_verdict_closes_non_optimized_lane,
)
from inertia_decompiler.project_argument_evidence_ranges import (
    attach_project_argument_evidence_ranges_8616,
)
from inertia_decompiler.project_evidence_transport import (
    transfer_project_evidence_8616,
)
from inertia_decompiler.project_loading import (
    PackedExecutableRefusedError,
    _build_project,
    _build_project_cached,
    _build_project_from_bytes,
    _describe_exception,
)
from inertia_decompiler.recompile_check import RecompileCheckResult, check_c_recompiles_8616
from inertia_decompiler.rizin_discovery import (
    RizinDiscoveryResult,
    RizinDiscoveryStatus,
    discover_rizin_function_entries,
)
from inertia_decompiler.rizin_evidence import RizinEvidence, RizinEvidenceStatus, collect_rizin_evidence
from inertia_decompiler.runtime_support import (
    FORCE_SERIAL_FUNCTION_DECOMP_ENV as _FORCE_SERIAL_FUNCTION_DECOMP_ENV,
)
from inertia_decompiler.runtime_support import (
    AnalysisTimeout as _AnalysisTimeout,
)
from inertia_decompiler.runtime_support import (
    DaemonThreadPoolExecutor,
)
from inertia_decompiler.runtime_support import (
    apply_memory_limit as _apply_memory_limit,
)
from inertia_decompiler.runtime_support import (
    capture_thread_output as _capture_thread_output,
)
from inertia_decompiler.runtime_support import (
    choose_function_parallelism as _choose_function_parallelism,
)
from inertia_decompiler.runtime_support import (
    default_exe_showcase_cap as _default_exe_showcase_cap,
)
from inertia_decompiler.runtime_support import (
    emit_timeout_and_exit as _emit_timeout_and_exit,
)
from inertia_decompiler.runtime_support import (
    lower_process_priority as _lower_process_priority,
)
from inertia_decompiler.runtime_support import (
    prefer_low_memory_path as _prefer_low_memory_path,
)
from inertia_decompiler.runtime_support import (
    run_with_timeout_in_daemon_thread as _run_with_timeout_in_daemon_thread,
)
from inertia_decompiler.runtime_support import (
    run_with_timeout_in_fork as _run_with_timeout_in_fork,
)
from inertia_decompiler.runtime_support import (
    should_force_serial_supplemental_decompilation as _should_force_serial_supplemental_decompilation,
)
from inertia_decompiler.runtime_support import (
    timing_output_enabled as _timing_output_enabled,
)
from inertia_decompiler.segment_program_layout_reporting import (
    attach_segment_program_layout_8616,
    segment_program_function_evidence_for_function_8616,
    segment_program_function_evidence_matches_item_8616,
    with_segment_program_function_evidence_8616,
)
from inertia_decompiler.serial_clean_worker_evidence import (
    _SERIAL_CLEAN_WORKER_EVIDENCE_ENV_8616,
    _hydrate_serial_clean_worker_evidence_8616,
    _read_serial_clean_worker_evidence_8616,
    _write_serial_clean_worker_evidence_8616,
)
from inertia_decompiler.serial_worker_cache import (
    SerialWorkerCacheLookup8616,
    SerialWorkerCacheVerdict8616,
    load_serial_worker_cache_8616,
    serial_worker_cache_inputs_8616,
    store_serial_worker_cache_8616,
)
from inertia_decompiler.sidecar_metadata import (
    _function_discovery_code_labels,
    _load_lst_metadata,
    _lst_code_label,
    _lst_code_region,
    _recovery_code_labels,
    _signature_matched_code_addrs,
    _visible_code_labels,
    attach_lst_metadata_to_project,
)
from inertia_decompiler.sidecar_policy import metadata_has_precise_code_regions
from inertia_decompiler.slice_recovery import (
    SliceRecoveryAttemptOutcome,
)
from inertia_decompiler.tail_validation import (
    emit_tail_validation_console_summary as _emit_tail_validation_console_summary,
)
from inertia_decompiler.tail_validation import (
    format_tail_validation_diagnostic as _format_tail_validation_diagnostic,
)
from inertia_decompiler.tail_validation import (
    inherit_tail_validation_runtime_policy as _inherit_tail_validation_runtime_policy,
)
from inertia_decompiler.tail_validation import (
    set_tail_validation_runtime_enabled as _set_tail_validation_runtime_enabled,
)
from inertia_decompiler.tail_validation import tail_validation_display_status as _tail_validation_display_status
from inertia_decompiler.tail_validation import (
    tail_validation_enabled_for_run as _tail_validation_enabled_for_run,
)
from inertia_decompiler.tail_validation import (
    tail_validation_fallback_allows_project_snapshot as _tail_validation_fallback_allows_project_snapshot,
)
from inertia_decompiler.tail_validation import (
    tail_validation_runtime_enabled as _tail_validation_runtime_enabled,
)
from inertia_decompiler.tail_validation import (
    tail_validation_snapshot_for_fallback as _tail_validation_snapshot_for_fallback,
)
from inertia_decompiler.tail_validation import (
    tail_validation_snapshot_for_function_run as _tail_validation_snapshot_for_function_run,
)
from inertia_decompiler.telemetry import (
    annotate_current_span,
    configure_telemetry_from_env,
    emit_compact_summary,
    span,
    trace_function,
)
from inertia_decompiler.work_items import (
    FunctionWorkExecutionOrigin8616,
    FunctionWorkItem,
    FunctionWorkResult,
    WorkItemStatus,
)
from inertia_decompiler.work_items import (
    emit_tail_validation_for_function_run_or_uncollected as _emit_tail_validation_for_function_run_or_uncollected,
)
from inertia_decompiler.work_items import (
    emit_tail_validation_snapshot_or_uncollected as _emit_tail_validation_snapshot_or_uncollected,
)
from inertia_decompiler.work_items import (
    function_attempt_display_status as _function_attempt_display_status,
)
from inertia_decompiler.work_items import (
    print_function_attempt_status as _print_function_attempt_status,
)
from inertia_decompiler.work_items import (
    recovery_evidence_line as _recovery_evidence_line,
)
from inertia_decompiler.x86_16_exact_slice import (
    function_original_addr,
    mark_function_original_addr,
)

from .cli_c_text_postprocess import (
    _coalesce_redundant_split_global_incdec_text,
    _dedupe_duplicate_local_declarations_text,
    _hoist_c89_local_declarations_text,
    _materialize_missing_direct_call_prototypes_text,
    _materialize_missing_generic_local_declarations_text,
    _materialize_missing_segment_macro_locals_text,
    _materialize_missing_synthetic_global_declarations_text,
    _materialize_opaque_pointer_typedefs_text,
    _materialize_stack_base_placeholder_declaration_text,
    _normalize_anonymous_call_targets,
    _normalize_boolean_conditions,
    _normalize_function_signature_arg_names,
    _normalize_scalar_gb_array_declarations_text,
    _normalize_seg_offset_void_pointer_args_text,
    _normalize_unsupported_computed_goto_text,
    _prune_parameter_shadow_declarations_text,
    _prune_standalone_memory_helper_reads_text,
    _prune_undefined_fragment_carrier_assignments_text,
    _prune_unused_local_declarations_text,
    _prune_void_call_assignments_text,
    _strip_register_fragment_suffixes_text,
)
from .cli_decompilation import (
    _apply_binary_specific_annotations,
    _apply_function_annotations_for_active_and_original_8616,
    _decompile_function_with_stats,
    _effective_decompile_timeout_8616,
    _emit_optional_source_sidecar_c_block,
    _function_complexity,
)
from .cli_fallback_decompilation import (
    NonOptimizedSliceOutcome,
    _non_optimized_slice_failure_detail,
    _non_optimized_slice_rendered,
    _try_decompile_non_optimized_known_function,
    _try_decompile_non_optimized_slice,
    _try_decompile_sidecar_slice,
    _try_emit_known_runtime_helper_c,
    _try_emit_string_intrinsic_c,
    _try_emit_trivial_sidecar_c,
)
from .cli_function_discovery import (
    _X86_16_EXACT_REGION_PADDING_SCAN_LIMIT,
    DisplayCatalogCachePolicy8616,
    _catalog_address_cache_key_8616,
    _configure_display_catalog_cache_policy_8616,
    _expanded_exe_discovery_limit,
    _format_sidecar_function_catalog,
    _function_binary_exact_region_8616,
    _interesting_functions,
    _load_catalog_address_cache,
    _lookup_persistent_recovery_timeout,
    _make_placeholder_function,
    _rank_exe_function_seeds,
    _rank_function_cfg_pairs_for_display,
    _rank_labeled_function_entries_cached,
    _recover_cached_function_pairs,
    _recover_candidate_function_pair,
    _recover_cfg,
    _recover_direct_addr_function,
    _recover_fast_exe_catalog,
    _recover_fast_seed_functions,
    _recover_lst_function,
    _recover_partial_cfg,
    _recover_ranked_binary_function,
    _recover_seeded_exe_functions,
    _resolve_x86_16_function_start,
    _source_region_catalog_evidence_8616,
    _store_catalog_address_cache,
    _supplement_cached_seeded_recovery,
    _supplement_functions_from_prologue_scan,
    attach_direct_target_argument_evidence_context_8616,
    record_direct_target_caller_return_use_evidence_8616,
)
from .indexed_alias_program_context import (
    prepare_direct_indexed_alias_program_context_8616,
    publish_discovered_indexed_alias_program_8616,
)

print: Callable[..., object] = _timestamped_print
type _AngrFunction = Any
type _StructuredCNode8616 = Any
type _SyntheticGlobals8616 = Any
type _FunctionCfgPair8616 = tuple[object, _AngrFunction]
type _DirectDecompileJobResult8616 = tuple[
    str,
    str,
    str | None,
    int,
    int,
    float,
    dict[str, object],
    SegmentProgramFunctionEvidence8616 | None,
    FailureFamilyState,
    str,
]
__all__ = [
    "_argument_was_explicit",
    "_bounded_non_optimized_timeout",
    "_direct_addr_wall_clock_budget",
    "_emit_function_timing_summary",
    "_function_recovery_detail",
    "_function_work_cache_lookup",
    "_function_work_result_for_fork_ipc",
    "_helper_name",
    "_iter_c_nodes",
    "_parse_int",
    "_prepare_ranked_binary_preview_items",
    "_read_serial_clean_worker_evidence_8616",
    "_run_function_work_item",
    "_supplement_function_cfg_pairs_with_ranked_preview",
    "_supplement_function_cfg_pairs_with_seeded_recovery",
    "main",
]


_ARCHITECTURE_GUARD_STATUS_8616: bool | None = None


def _ensure_runtime_architecture_guard_8616() -> None:
    """Re-run architecture boundary checks in execution path."""
    global _ARCHITECTURE_GUARD_STATUS_8616
    if _ARCHITECTURE_GUARD_STATUS_8616 is not None:
        return
    try:
        assert_decompiler_architecture_clean()
    except DecompilerArchitectureGuardError:
        _ARCHITECTURE_GUARD_STATUS_8616 = False
        raise
    _ARCHITECTURE_GUARD_STATUS_8616 = True


_TRUTHY_ENV_VALUES_8616 = frozenset({"1", "true", "yes", "on"})

_DIRECT_ADDR_FORCE_THREAD_LANE_ENV_8616 = "INERTIA_DIRECT_ADDR_FORCE_THREAD"
_ANALYSIS_TIMEOUT_FORCE_THREAD_LANES_ENV_8616 = "INERTIA_FORCE_TIMEOUT_LANES_THREAD"


class DirectClinicPolicy8616(Enum):
    """Clinic resource policy selected from direct-function complexity evidence."""

    STANDARD = "standard"
    FAST_PEEPHOLE = "fast_peephole"


def _direct_clinic_policy_8616(
    *,
    arch_name: str,
    direct_addr_mode: bool,
    block_count: int,
    byte_count: int,
    call_site_count: int,
) -> DirectClinicPolicy8616:
    """Select bounded Clinic work without disabling semantic variable recovery."""
    if arch_name != "86_16" or not direct_addr_mode:
        return DirectClinicPolicy8616.STANDARD
    if block_count >= 32 or byte_count >= 280:
        return DirectClinicPolicy8616.FAST_PEEPHOLE
    if call_site_count >= 6 and block_count >= 10 and byte_count >= 160:
        return DirectClinicPolicy8616.FAST_PEEPHOLE
    return DirectClinicPolicy8616.STANDARD


def _safe_function_callsite_count_8616(func: object) -> int:
    counts: list[int] = []
    get_call_sites = getattr(func, "get_call_sites", None)
    if callable(get_call_sites):
        try:
            call_sites = get_call_sites()
            counts.append(len(tuple(call_sites)) if isinstance(call_sites, Sequence) else 0)
        except Exception:
            counts.append(0)
    try:
        counts.append(len(tuple(collect_neighbor_call_targets(func) or ())))
    except Exception:
        counts.append(0)
    return max(counts, default=0)


def _clinic_policy_needs_callsite_count_8616(
    *,
    arch_name: str,
    direct_addr_mode: bool,
    block_count: int,
    byte_count: int,
) -> bool:
    if arch_name != "86_16" or not direct_addr_mode:
        return False
    if block_count >= 32 or byte_count >= 280:
        return False
    return block_count >= 10 and byte_count >= 160


@contextlib.contextmanager
def _temporary_clinic_policy_8616(
    project_obj: angr.Project,
    policy: DirectClinicPolicy8616,
) -> Iterator[None]:
    """Apply reversible Clinic cost bounds while preserving semantic stages."""
    if policy is DirectClinicPolicy8616.STANDARD:
        yield
        return
    prev_disable_narrowing = getattr(project_obj, "_inertia_disable_ail_narrowing", False)
    prev_disable_complex_expr_scan = getattr(project_obj, "_inertia_disable_complex_expr_scan", False)
    prev_fast_block_peephole = getattr(project_obj, "_inertia_fast_block_peephole", False)
    prev_skip_simplify = getattr(project_obj, "_inertia_skip_clinic_simplify_block", False)
    prev_peephole_cap = getattr(project_obj, "_inertia_clinic_peephole_cap", None)
    try:
        if policy is DirectClinicPolicy8616.FAST_PEEPHOLE:
            typing.cast(typing.Any, project_obj)._inertia_disable_complex_expr_scan = True
            typing.cast(typing.Any, project_obj)._inertia_fast_block_peephole = True
            typing.cast(typing.Any, project_obj)._inertia_clinic_peephole_cap = 48
        yield
    finally:
        typing.cast(typing.Any, project_obj)._inertia_disable_ail_narrowing = prev_disable_narrowing
        typing.cast(typing.Any, project_obj)._inertia_disable_complex_expr_scan = prev_disable_complex_expr_scan
        typing.cast(typing.Any, project_obj)._inertia_fast_block_peephole = prev_fast_block_peephole
        typing.cast(typing.Any, project_obj)._inertia_skip_clinic_simplify_block = prev_skip_simplify
        if prev_peephole_cap is None:
            with contextlib.suppress(Exception):
                delattr(project_obj, "_inertia_clinic_peephole_cap")
        else:
            typing.cast(typing.Any, project_obj)._inertia_clinic_peephole_cap = prev_peephole_cap


def _env_truthy_8616(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _TRUTHY_ENV_VALUES_8616


def _analysis_timeout_lane_allows_fork() -> bool:
    """Return true when timeout wrapper state supports fork isolation."""
    return (
        os.name == "posix"
        and threading.current_thread() is threading.main_thread()
        and threading.active_count() == 1
    )


def _analysis_timeout_use_fork_8616() -> bool:
    """Return whether timeout-heavy lanes should use fork isolation."""
    return (
        _analysis_timeout_lane_allows_fork()
        and not _env_truthy_8616(_ANALYSIS_TIMEOUT_FORCE_THREAD_LANES_ENV_8616)
        and not _env_truthy_8616("INERTIA_OTEL_PROFILE_IN_PROCESS")
    )


def _direct_addr_use_fork_lane_8616(*, tail_validation_enabled: bool) -> bool:
    del tail_validation_enabled
    if _env_truthy_8616(_DIRECT_ADDR_FORCE_THREAD_LANE_ENV_8616):
        return False
    return _analysis_timeout_use_fork_8616()


def _argument_was_explicit(name: str) -> bool:
    flag = name.strip()
    return any(token == flag or token.startswith(f"{flag}=") for token in sys.argv[1:])


def _configure_cli_telemetry_8616(args: CliArguments) -> None:
    configure_telemetry_from_env(
        enabled=args.otel_spans,
        file_path=args.otel_span_file,
        top_n=args.otel_top_n,
        min_ms=args.otel_min_ms,
        full_jsonl=args.otel_full_jsonl,
        stderr_summary=args.otel_stderr,
        output_format=args.otel_format,
        text_max_spans=args.otel_text_max_spans,
        otlp_export=args.otel_export_otlp,
        service_name=args.otel_service_name,
        force_flush_ms=args.otel_force_flush_ms,
        otlp_endpoint=args.otel_endpoint,
    )


def _parse_int(value: str) -> int:
    return int(value, 0)


def _collect_rizin_library_offsets_8616(evidence: object | None) -> set[int]:
    """Collect library-like entry addresses reported by rizin evidence."""
    if evidence is None:
        return set()
    out: set[int] = set()
    functions = getattr(evidence, "functions", ())
    symbols = getattr(evidence, "symbols", ())
    for function_fact in functions if isinstance(functions, Sequence) else ():
        if is_library_like_function_name(function_fact.name):
            out.add(function_fact.addr)
    for symbol_fact in symbols if isinstance(symbols, Sequence) else ():
        if is_library_like_function_name(symbol_fact.name):
            out.add(symbol_fact.vaddr)
    return out


def _has_local_sidecar_evidence_8616(binary_path: Path) -> bool:
    """Check whether local sidecar hint files exist next to the binary."""
    if os.environ.get("INERTIA_IGNORE_LOCAL_SIDECAR_HINTS_8616", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        return False
    stem = binary_path.stem
    parent = binary_path.parent
    if not parent.exists():
        return False
    sidecar_exts = {
        ".cod",
        ".lst",
        ".map",
        ".idc",
        ".inc",
        ".sym",
        ".dbg",
        ".tds",
        ".pdb",
    }
    for candidate in parent.glob(f"{stem}.*"):
        if candidate.resolve() == binary_path.resolve():
            continue
        if candidate.suffix.lower() in sidecar_exts:
            return True
    return False


def _auto_rizin_enabled_for_binary_8616(project: angr.Project, binary_path: Path) -> bool:
    """Resolve the auto-backend rizin preference for the current binary."""
    # For non-86_16 keep auto as hybrid-friendly behavior.
    if str(getattr(project.arch, "name", "") or "") != "86_16":
        return True
    env = os.environ.get("INERTIA_AUTO_RIZIN_8616", "").strip().lower()
    if env in {"1", "true", "yes", "on"}:
        return True
    if env in {"0", "false", "no", "off"}:
        return False
    # Default: rizin-first when local sidecar hints are not available.
    return not _has_local_sidecar_evidence_8616(binary_path)


def _wants_rizin_8616(project: angr.Project, args: CliArguments, binary_path: Path, backend: str) -> bool:
    """Check whether rizin discovery should run for this backend/binary pair."""
    if args.binary.suffix.lower() != ".exe":
        return False
    if backend in {"rizin", "hybrid"}:
        return True
    return backend == "auto" and _auto_rizin_enabled_for_binary_8616(project, binary_path)


def _rizin_offsets_status_8616(rz_evidence: RizinEvidence | None, rz: RizinDiscoveryResult | None) -> tuple[list[int], float, str]:
    """Resolve ranked rizin offsets, elapsed time, and status from evidence lanes."""
    if rz_evidence is not None and rz_evidence.status is RizinEvidenceStatus.OK and rz_evidence.functions:
        return list(rz_evidence.function_offsets), rz_evidence.elapsed_ms, rz_evidence.status.value
    if rz is not None and rz.status is RizinDiscoveryStatus.OK:
        return list(rz.offsets), rz.elapsed_ms, rz.status.value
    return [], 0.0, "error"


def _merged_or_rizin_offsets_8616(
    project: angr.Project,
    rizin_offsets: list[int],
    rizin_library_offsets: set[int],
    include_library_functions: bool,
    status_value: str,
    elapsed_ms: float,
    backend: str,
) -> list[int]:
    """Return rizin offsets directly or merged with angr-ranked seeds."""
    if not include_library_functions and rizin_library_offsets:
        original_count = len(rizin_offsets)
        rizin_offsets = [offset for offset in rizin_offsets if offset not in rizin_library_offsets]
        if len(rizin_offsets) != original_count:
            print(
                f"/* rizin discovery: dropped {original_count - len(rizin_offsets)} library-like entries by default */"
            )
    print(
        f"/* rizin discovery: status={status_value} entries={len(rizin_offsets)} elapsed={elapsed_ms:.1f}ms "
        f"backend={backend} */"
    )
    if backend == "rizin":
        return rizin_offsets
    angr_offsets = _rank_exe_function_seeds(
        project,
        include_library_functions=include_library_functions,
    )
    merged: list[int] = []
    seen: set[int] = set()
    for addr in angr_offsets:
        if addr not in seen:
            merged.append(addr)
            seen.add(addr)
    for addr in rizin_offsets:
        if addr not in seen:
            merged.append(addr)
            seen.add(addr)
    print(f"/* hybrid discovery: angr={len(angr_offsets)} rizin={len(rizin_offsets)} merged={len(merged)} */")
    return merged


def _print_rizin_fallback_diagnostics_8616(rz_evidence: RizinEvidence | None, rz: RizinDiscoveryResult | None) -> None:
    """Print rizin lane diagnostics before the angr-ranked fallback."""
    if rz_evidence is not None:
        detail = rz_evidence.detail or rz_evidence.status.value
        print(
            f"/* rizin evidence: status={rz_evidence.status.value} elapsed={rz_evidence.elapsed_ms:.1f}ms detail={detail} */"
        )
    if rz is not None:
        detail = rz.detail or rz.status.value
        print(
            f"/* rizin discovery: status={rz.status.value} elapsed={rz.elapsed_ms:.1f}ms detail={detail}; "
            "falling back to angr-ranked discovery. */"
        )


def _discover_ranked_binary_offsets(
    project: angr.Project,
    *,
    args: CliArguments,
) -> list[int]:
    binary_path = args.binary
    include_library_functions = args.include_library_functions
    typing.cast(typing.Any, project)._inertia_include_library_functions = include_library_functions

    backend = args.function_discovery_backend.strip().lower()
    if backend == "auto":
        legacy_seed_engine = args.seed_engine.strip().lower()
        if legacy_seed_engine in {"angr", "rizin"}:
            backend = legacy_seed_engine
    rizin_timeout = max(1, args.rizin_timeout)
    wants_rizin = _wants_rizin_8616(project, args, binary_path, backend)
    rz_evidence = collect_rizin_evidence(binary_path, timeout_sec=rizin_timeout) if wants_rizin else None
    if rz_evidence is not None:
        typing.cast(typing.Any, project)._inertia_rizin_evidence = rz_evidence
        typing.cast(typing.Any, project)._inertia_rizin_function_names = rz_evidence.function_name_by_addr
    rz = discover_rizin_function_entries(args.binary, timeout_sec=rizin_timeout) if wants_rizin else None
    rizin_library_offsets = _collect_rizin_library_offsets_8616(rz_evidence)
    rizin_offsets, elapsed_ms, status_value = _rizin_offsets_status_8616(rz_evidence, rz)
    if rizin_offsets:
        return _merged_or_rizin_offsets_8616(
            project,
            rizin_offsets,
            rizin_library_offsets,
            include_library_functions,
            status_value,
            elapsed_ms,
            backend,
        )
    _print_rizin_fallback_diagnostics_8616(rz_evidence, rz)
    return cast(
        list[int],
        _rank_exe_function_seeds(
            project,
            include_library_functions=include_library_functions,
        ),
    )


def _function_recovery_detail(stage: str | None) -> str | None:
    if stage == "recovery":
        return "during x86-16 function recovery"
    if isinstance(stage, str) and stage.startswith("recovery:"):
        recovery_stage = stage.split(":", 1)[1]
        if recovery_stage == "fast":
            return "during x86-16 function recovery (fast CFGFast)"
        if recovery_stage.startswith("narrow"):
            return "during x86-16 function recovery (narrow CFGFast)"
        if recovery_stage == "full":
            return "during x86-16 function recovery (full CFGFast)"
        return f"during x86-16 function recovery ({recovery_stage})"
    return None


def _sanitize_direct_timeout_stage_token(token: str) -> str:
    """Normalize timeout stage fragments into parser-friendly tokens."""
    return re.sub(r"\s+", "_", token.strip()) or "timeout"


def _direct_timeout_failure_stage_from_payload(payload: object | None, *, default: str = "decompilation") -> str:
    message = str(payload or "").lower()
    if not message:
        return default

    if "during x86-16 structuring pass " in message:
        detail = message.split("during x86-16 structuring pass ", 1)[1].strip().rstrip(".")
        normalized_detail = _sanitize_direct_timeout_stage_token(detail)
        return f"structuring:{normalized_detail}"
    if "during x86-16 structuring" in message:
        return "structuring"
    if "during x86-16 postprocess pass " in message:
        detail = message.split("during x86-16 postprocess pass ", 1)[1].strip().rstrip(".")
        normalized_detail = _sanitize_direct_timeout_stage_token(detail)
        return f"postprocess:{normalized_detail}"
    if "during x86-16 postprocess" in message:
        return "postprocess"
    if "during core decompilation" in message:
        return "decompilation:core"
    if "during clinic" in message:
        return "decompilation:clinic"
    if "during decompilation" in message:
        return "decompilation"
    return default


def _bounded_non_optimized_timeout(timeout: int) -> int:
    # The non-optimized slice path is our recovery fallback after bounded
    # function discovery times out. Very small caps cause deterministic
    # failures for medium procedures that need project/slice setup plus
    # decompiler warmup before emitting fallback C.
    return min(max(1, timeout), 60)


_DEFAULT_FUNCTION_TIMEOUT_CAP = 240


def _parse_env_timeout_cap(default_timeout_cap: int | None = None) -> int | None:
    """Return the environment override or one caller-selected default cap."""
    default_cap = (
        _DEFAULT_FUNCTION_TIMEOUT_CAP
        if default_timeout_cap is None
        else max(1, int(default_timeout_cap))
    )
    cap = os.environ.get("INERTIA_MAX_FUNCTION_TIMEOUT")
    if not cap:
        return default_cap
    try:
        cap_value = int(cap)
    except ValueError:
        return default_cap
    if cap_value <= 0:
        return None
    return max(1, cap_value)


def _enforce_function_timeout_cap(
    timeout: int,
    *,
    context: str,
    explicit_timeout_floor: int | None = None,
    default_timeout_cap: int | None = None,
) -> int:
    cap = _parse_env_timeout_cap(default_timeout_cap)
    if cap is not None and explicit_timeout_floor is not None and "INERTIA_MAX_FUNCTION_TIMEOUT" not in os.environ:
        cap = max(cap, max(1, int(explicit_timeout_floor)))
    if cap is None:
        return max(1, int(timeout))
    bounded = max(1, min(int(timeout), cap))
    if bounded != max(1, int(timeout)):
        logging.getLogger(__name__).debug(
            "%s timeout capped: requested=%s cap=%s applied=%s",
            context,
            int(timeout),
            cap,
            bounded,
        )
    return bounded


def _direct_addr_wall_clock_budget(
    timeout: int,
    *,
    effective_timeout: int | None = None,
    explicit_timeout: bool = False,
) -> int:
    # One-function direct-address recovery may chain bounded recovery,
    # non-optimized fallback, and final attribution. Keep that lane inside a
    # deterministic wall-clock budget so callers see an explicit timeout class
    # instead of an outer subprocess kill.
    if explicit_timeout:
        # Shape-based analysis may estimate a larger useful budget, but an
        # explicit CLI timeout is the user's wall-clock contract. Reserve only
        # bounded IPC/finalization overhead so an outer caller can reliably
        # wait for the decompiler's structured timeout result.
        configured = max(1, int(timeout))
        budget = configured + min(8, max(3, configured // 10))
    # Default direct-address mode should bias toward successful recovery over
    # early timeout. Keep a larger bounded budget so non-optimized and sidecar
    # fallback lanes can actually execute on medium x86-16 functions.
    else:
        base = max(1, effective_timeout if isinstance(effective_timeout, int) else timeout)
        if timeout <= 6:
            budget = max(8, base + min(14, max(8, base + 4)))
        else:
            budget = max(2, base + max(40, _bounded_non_optimized_timeout(base)) + 2)
    return _enforce_function_timeout_cap(
        int(budget),
        context="direct address wall clock",
        explicit_timeout_floor=int(budget) if explicit_timeout else None,
    )


def _direct_addr_validation_retry_count_8616(*, timeout_was_explicit: bool, args_timeout: int) -> int:
    # A retry must construct a fresh project/function/codegen graph. The direct
    # worker currently closes over one mutable angr graph, so retrying after a
    # validation failure can reuse a partially rewritten AST and lose calls.
    # Keep fallback lanes available, but never treat mutation of the same graph
    # as an independent validation attempt.
    del timeout_was_explicit, args_timeout
    return 0


def _direct_addr_robust_retry_enabled_8616(*, timeout_was_explicit: bool) -> bool:
    # Robust retry is useful for default interactive recovery, but it must not
    # silently double a caller-provided direct-address timeout budget.
    return not timeout_was_explicit


def _direct_addr_should_skip_heavy_validation_fallbacks_8616(
    *,
    timeout_was_explicit: bool,
    args_timeout: object,
    direct_status: object,
    partial_payload: object,
) -> bool:
    """Return True when explicit-timeout validation failure should emit the direct partial."""
    return (
        timeout_was_explicit
        and isinstance(args_timeout, int)
        and str(direct_status) == "validation_failed"
        and isinstance(partial_payload, str)
        and bool(partial_payload.strip())
    )


def _direct_addr_project_local_fallback_addr_8616(
    *,
    function: object,
    direct_display_addr: int,
    using_rebased_direct_slice: bool,
) -> int:
    """Return the address valid for reads in the current fallback project.

    ``direct_display_addr`` is the original binary address and must remain the
    reporting/evidence identity. Rebased exact-slice projects are loaded at a
    safe local base, so fallback lanes that read bytes from that project must
    use the function's project-local address instead.
    """
    if not using_rebased_direct_slice:
        return direct_display_addr
    local_addr = getattr(function, "addr", None)
    return local_addr if isinstance(local_addr, int) else direct_display_addr


@dataclass(frozen=True, slots=True)
class DirectAddrCanonicalization8616:
    """Sidecar-proven canonical entry for a requested direct address."""

    requested_addr: int
    canonical_addr: int
    region: tuple[int, int]
    name: str | None


def _canonicalize_direct_addr_from_sidecar_padding_8616(
    project: angr.Project,
    lst_metadata: LSTMetadata | None,
    requested_addr: int | None,
    *,
    function_label: str | None = None,
) -> DirectAddrCanonicalization8616 | None:
    if lst_metadata is None or requested_addr is None or getattr(getattr(project, "arch", None), "name", "") != "86_16":
        return None
    region = _lst_code_region(lst_metadata, requested_addr)
    if region is None or len(region) != 2:
        return None
    start, end = region
    if not isinstance(start, int) or not isinstance(end, int) or not (start <= requested_addr < end):
        return None
    scan_size = min(_X86_16_EXACT_REGION_PADDING_SCAN_LIMIT, max(0, end - start))
    if scan_size <= 0:
        return None
    try:
        code = bytes(project.loader.memory.load(start, scan_size))
    except Exception:
        return None
    canonical_offset = _resolve_x86_16_function_start(
        code,
        0,
        max_padding=_X86_16_EXACT_REGION_PADDING_SCAN_LIMIT,
    )
    if not isinstance(canonical_offset, int) or canonical_offset <= 0:
        return None
    canonical_addr = start + canonical_offset
    if not (requested_addr <= canonical_addr < end):
        return None
    canonical_name = function_label or _lst_code_label(lst_metadata, canonical_addr, project.entry)
    return DirectAddrCanonicalization8616(
        requested_addr=requested_addr,
        canonical_addr=canonical_addr,
        region=(start, end),
        name=canonical_name,
    )


def _canonicalize_sidecar_work_offset_8616(
    project: angr.Project,
    lst_metadata: LSTMetadata | None,
    offset: int,
    name: str | None,
) -> tuple[int, str | None]:
    canonical = _canonicalize_direct_addr_from_sidecar_padding_8616(
        project,
        lst_metadata,
        offset,
        function_label=name,
    )
    if canonical is None:
        return offset, name
    return canonical.canonical_addr, canonical.name or name


def _prepare_ranked_binary_preview_items(
    project: angr.Project,
    ranked_binary_offsets: Sequence[int],
    *,
    max_count: int,
    timeout: int,
    window: int,
    low_memory: bool,
) -> list[FunctionWorkItem]:
    def _impl() -> list[FunctionWorkItem]:
        if max_count <= 0 or not ranked_binary_offsets:
            return []

        preview_items: list[FunctionWorkItem] = []
        selected_addrs: set[int] = set()
        quick_timeout = min(timeout, 2)
        probe_budget = min(len(ranked_binary_offsets), max(max_count * 6, 12))

        for addr in ranked_binary_offsets[:probe_budget]:
            try:
                if _analysis_timeout_use_fork_8616():
                    function_cfg, function = cast(
                        tuple[object, object],
                        _run_with_timeout_in_fork(
                            cast(Callable[[], Any], lambda addr=addr: _recover_ranked_binary_function(
                                project,
                                addr,
                                f"sub_{addr:x}",
                                timeout=quick_timeout,
                                window=window,
                                low_memory=low_memory,
                            )),
                            timeout=quick_timeout + 1,
                        ),
                    )
                else:
                    function_cfg, function = _run_with_timeout_in_daemon_thread(
                        cast(Callable[[], Any], lambda addr=addr: _recover_ranked_binary_function(
                            project,
                            addr,
                            f"sub_{addr:x}",
                            timeout=quick_timeout,
                            window=window,
                            low_memory=low_memory,
                        )),
                        timeout=quick_timeout + 1,
                        thread_name_prefix="ranked-preview",
                    )
            except Exception as ex:
                logging.getLogger(__name__).debug("ranked preview item creation failed: %s", ex)
                continue
            preview_items.append(
                FunctionWorkItem(
                    index=len(preview_items) + 1,
                    function_cfg=function_cfg,
                    function=function,
                    recovery_addr=addr,
                )
            )
            selected_addrs.add(addr)
            if len(preview_items) >= max_count:
                return preview_items

        for addr in ranked_binary_offsets:
            if addr in selected_addrs:
                continue
            preview_items.append(
                FunctionWorkItem(
                    index=len(preview_items) + 1,
                    function_cfg=None,
                    function=_make_placeholder_function(project, addr, f"sub_{addr:x}"),
                    recovery_addr=addr,
                )
            )
            if len(preview_items) >= max_count:
                break
        return preview_items

    return _impl()


def _preserve_source_label_for_recovered_function_8616(
    source_function: _AngrFunction,
    recovered_function: _AngrFunction,
) -> bool:
    source_addr = function_original_addr(source_function)
    recovered_addr = function_original_addr(recovered_function)
    if not isinstance(source_addr, int) or not isinstance(recovered_addr, int) or source_addr != recovered_addr:
        return False
    source_name = getattr(source_function, "name", None)
    recovered_name = getattr(recovered_function, "name", None)
    if not isinstance(source_name, str) or not source_name or source_name.startswith("sub_"):
        return False
    if isinstance(recovered_name, str) and recovered_name and not recovered_name.startswith("sub_"):
        return False
    try:
        recovered_function.name = source_name
        mark_function_original_addr(recovered_function, source_addr)
        source_info = getattr(source_function, "info", None)
        recovered_info = getattr(recovered_function, "info", None)
        if isinstance(source_info, dict):
            if not isinstance(recovered_info, dict):
                recovered_info = {}
                recovered_function.info = recovered_info
            for key, value in source_info.items():
                recovered_info.setdefault(key, value)
    except Exception:
        return False
    return True


def _function_work_item_recovery_addr_8616(item: FunctionWorkItem) -> int:
    """Return the stable binary address requested for a function work item."""
    recovery_addr = item.recovery_addr
    if recovery_addr is None:
        recovery_addr = function_original_addr(item.function)
    if recovery_addr < 0:
        raise ValueError(f"function work-item recovery address must be nonnegative, got {recovery_addr}")
    return int(recovery_addr)


def _supplement_function_cfg_pairs_with_ranked_preview(
    project: angr.Project,
    function_cfg_pairs: list[tuple[object, object]],
    ranked_binary_offsets: Sequence[int],
    *,
    target_count: int,
    timeout: int,
    window: int,
    low_memory: bool,
) -> list[tuple[object, object]]:
    def _impl() -> list[tuple[object, object]]:
        if target_count <= 0 or len(function_cfg_pairs) >= target_count or not ranked_binary_offsets:
            return function_cfg_pairs

        supplemented = list(function_cfg_pairs)
        seen_addrs = {
            getattr(function, "addr", None)
            for _cfg, function in supplemented
            if isinstance(getattr(function, "addr", None), int)
        }
        preview_items = _prepare_ranked_binary_preview_items(
            project,
            ranked_binary_offsets,
            max_count=target_count,
            timeout=timeout,
            window=window,
            low_memory=low_memory,
        )
        for item in preview_items:
            addr = getattr(item.function, "addr", None)
            if item.function_cfg is None or not isinstance(addr, int) or addr in seen_addrs:
                continue
            supplemented.append((item.function_cfg, item.function))
            seen_addrs.add(addr)
            if len(supplemented) >= target_count:
                break
        return supplemented

    return _impl()


def _supplement_function_cfg_pairs_with_seeded_recovery(
    project: angr.Project,
    function_cfg_pairs: list[tuple[object, object]],
    *,
    timeout: int,
    target_count: int,
) -> list[tuple[object, object]]:
    if target_count <= 0 or len(function_cfg_pairs) >= target_count:
        return function_cfg_pairs

    supplemented = list(function_cfg_pairs)
    seen_addrs = {
        getattr(function, "addr", None)
        for _cfg, function in supplemented
        if isinstance(getattr(function, "addr", None), int)
    }
    seeded_pairs = _recover_seeded_exe_functions(
        project,
        timeout=timeout,
        limit=target_count,
    )
    for function_cfg, function in seeded_pairs:
        addr = getattr(function, "addr", None)
        if not isinstance(addr, int) or addr in seen_addrs:
            continue
        supplemented.append((function_cfg, function))
        seen_addrs.add(addr)
        if len(supplemented) >= target_count:
            break
    return supplemented


def _function_work_cache_lookup(
    item: FunctionWorkItem,
    *,
    binary_path: Path | None,
    timeout: int,
    api_style: str,
    enable_structured_simplify: bool,
    enable_postprocess: bool,
    cod_metadata: CODProcMetadata | None = None,
    synthetic_globals: dict[int, tuple[str, int]] | None = None,
    lst_metadata: LSTMetadata | None = None,
) -> tuple[FunctionWorkResult | None, str, dict[str, object] | None, bool, list[str]]:
    """Load a function result only when semantic and diagnostic provenance match."""

    def _impl() -> tuple[FunctionWorkResult | None, str, dict[str, object] | None, bool, list[str]]:
        """Perform the lock-compatible cache lookup."""
        function = item.function
        function_addr = function.addr
        function_name = function.name
        function_project = function.project
        tail_validation_enabled = (
            _tail_validation_runtime_enabled(function_project) if function_project is not None else True
        )
        expected_validation_stages = []
        if tail_validation_enabled:
            expected_validation_stages = ["structuring"]
            if enable_postprocess:
                expected_validation_stages.append("postprocess")
        cache_key = function_decompilation_cache_key_8616(
            item,
            binary_path=binary_path,
            api_style=api_style,
            cod_metadata=cod_metadata,
            synthetic_globals=synthetic_globals,
            lst_metadata=lst_metadata,
            enable_structured_simplify=enable_structured_simplify,
            enable_postprocess=enable_postprocess,
        )
        cached_result = _load_cache_json("function_decompile", cache_key) if cache_key is not None else None
        if cached_result is None:
            return None, "", cache_key, tail_validation_enabled, expected_validation_stages
        cached_status = str(cached_result.get("status", "error"))
        if cached_status != "ok":
            return _cache_bypass_8616(
                (
                    f"[dbg] ignoring cached failed function result for {function_addr:#x} "
                    f"{function_name} status={cached_status}; "
                    "only successful decompilation results are cached\n"
                ),
                cache_key,
                tail_validation_enabled,
                expected_validation_stages,
            )
        return _ok_cached_function_result_tuple_8616(
            item,
            cached_result,
            function_addr,
            function_name,
            cache_key,
            tail_validation_enabled,
            expected_validation_stages,
        )

    return _impl()


def _cache_bypass_8616(
    reason: str,
    cache_key: dict[str, object] | None,
    tail_validation_enabled: bool,
    expected_validation_stages: list[str],
) -> tuple[FunctionWorkResult | None, str, dict[str, object] | None, bool, list[str]]:
    """Build a cache-bypass result tuple carrying the bypass diagnostic."""
    return None, reason, cache_key, tail_validation_enabled, expected_validation_stages


def _ok_cached_function_result_tuple_8616(
    item: FunctionWorkItem,
    cached_result: dict[str, object],
    function_addr: int,
    function_name: str,
    cache_key: dict[str, object] | None,
    tail_validation_enabled: bool,
    expected_validation_stages: list[str],
) -> tuple[FunctionWorkResult | None, str, dict[str, object] | None, bool, list[str]]:
    """Accept or bypass one cached successful function result."""
    typed_switch_artifacts = os.environ.get("INERTIA_ENABLE_TYPED_SWITCH_AST_ARTIFACTS") == "1"
    cached_diagnostic_output = cached_result.get("diagnostic_output")
    if typed_switch_artifacts and (
        not isinstance(cached_diagnostic_output, str) or not cached_diagnostic_output.strip()
    ):
        return _cache_bypass_8616(
            f"[dbg] cache bypass for {function_addr:#x} {function_name} missing_diagnostic_provenance\n",
            cache_key,
            tail_validation_enabled,
            expected_validation_stages,
        )
    diagnostic_output = cached_diagnostic_output if isinstance(cached_diagnostic_output, str) else ""
    cached_tail_validation = cached_result.get("tail_validation")
    if (not tail_validation_enabled) or x86_16_tail_validation_snapshot_passed(
        cached_tail_validation if isinstance(cached_tail_validation, dict) else None,
        expected_stages=expected_validation_stages,
    ):
        bypass_reason = _cached_payload_acceptance_bypass_reason_8616(cached_result)
        if bypass_reason is not None:
            return _cache_bypass_8616(
                f"[dbg] cache bypass for {function_addr:#x} {function_name} {bypass_reason}\n",
                cache_key,
                tail_validation_enabled,
                expected_validation_stages,
            )
        result = _cached_function_work_result_8616(
            item,
            cached_result,
            function_addr,
            function_name,
            tail_validation_enabled,
            expected_validation_stages,
            typed_switch_artifacts,
            diagnostic_output,
        )
        return result, "", cache_key, tail_validation_enabled, expected_validation_stages
    cache_bypass_reason = _tail_validation_display_status(
        cached_tail_validation if isinstance(cached_tail_validation, dict) else None
    )
    return _cache_bypass_8616(
        f"[dbg] cache bypass for {function_addr:#x} {function_name} validation={cache_bypass_reason}\n",
        cache_key,
        tail_validation_enabled,
        expected_validation_stages,
    )


def _cached_payload_acceptance_bypass_reason_8616(cached_result: dict[str, object]) -> str | None:
    """Return the acceptance-provenance bypass reason, or None when the payload is reusable."""
    cached_payload = str(cached_result.get("payload", ""))
    cached_validated_hash = cached_result.get("validated_c_hash")
    cached_gcc_hash = cached_result.get("gcc_checked_c_hash")
    if not isinstance(cached_validated_hash, str) or not isinstance(cached_gcc_hash, str):
        return "missing_acceptance_provenance"
    if (
        cached_validated_hash != cached_gcc_hash
        or cached_validated_hash != _sha256_text_8616(cached_payload)
    ):
        return "stale_output_mismatch"
    normalized_cached_payload = _normalize_accepted_payload_8616(cached_payload)
    if normalized_cached_payload.rstrip() != cached_payload.rstrip():
        return "stale_normalization"
    cached_quality = assess_final_generated_c_text(cached_payload)
    if cached_quality.reject_as_decompiled:
        marker_summary = ", ".join(cached_quality.markers[:3]) if cached_quality.markers else "unresolved"
        if len(cached_quality.markers) > 3:
            marker_summary += ", ..."
        return f"quality={marker_summary}"
    return None


def _cached_tail_snapshot_8616(
    cached_tail_validation: object,
    expected_validation_stages: list[str],
) -> dict[str, object] | None:
    """Build the cached tail-validation snapshot preserving stage ordering."""
    if not isinstance(cached_tail_validation, dict):
        return None
    cached_stage_names = [
        stage for stage in expected_validation_stages if stage in cached_tail_validation
    ]
    cached_stage_names.extend(
        stage for stage in cached_tail_validation if stage not in expected_validation_stages
    )
    return {stage: copy.deepcopy(cached_tail_validation[stage]) for stage in cached_stage_names}


def _cached_function_work_result_8616(
    item: FunctionWorkItem,
    cached_result: dict[str, object],
    function_addr: int,
    function_name: str,
    tail_validation_enabled: bool,
    expected_validation_stages: list[str],
    typed_switch_artifacts: bool,
    diagnostic_output: str,
) -> FunctionWorkResult:
    """Rebuild a FunctionWorkResult from accepted cached provenance."""
    cached_payload = str(cached_result.get("payload", ""))
    cached_validated_hash = cached_result.get("validated_c_hash")
    cached_gcc_hash = cached_result.get("gcc_checked_c_hash")
    cached_tail_validation = cached_result.get("tail_validation")
    cache_validation_status = (
        "uncollected"
        if not tail_validation_enabled
        else _tail_validation_display_status(
            cached_tail_validation if isinstance(cached_tail_validation, dict) else None
        )
    )
    cached_tail_snapshot = _cached_tail_snapshot_8616(cached_tail_validation, expected_validation_stages)
    cached_elapsed = cached_result.get("elapsed")
    cached_block_count = cached_result.get("block_count")
    cached_byte_count = cached_result.get("byte_count")
    cached_failure_family = FailureFamilySnapshot.from_record(
        cached_result.get("failure_family_snapshot")
    )
    return FunctionWorkResult(
        index=item.index,
        status=str(cached_result.get("status", "error")),
        payload=cached_payload,
        partial_payload=None,
        debug_output=(
            f"[dbg] cache hit for {function_addr:#x} "
            f"{function_name} "
            f"validation={cache_validation_status}\n"
            + (diagnostic_output if typed_switch_artifacts else "")
        ),
        function=item.function,
        function_cfg=item.function_cfg,
        tail_validation=cached_tail_snapshot,
        elapsed=float(cached_elapsed) if isinstance(cached_elapsed, (int, float)) else None,
        from_cache=True,
        block_count=cached_block_count if isinstance(cached_block_count, int) else None,
        byte_count=cached_byte_count if isinstance(cached_byte_count, int) else None,
        validated_payload_hash=(
            cached_validated_hash if isinstance(cached_validated_hash, str) else None
        ),
        gcc_checked_payload_hash=(cached_gcc_hash if isinstance(cached_gcc_hash, str) else None),
        failure_family_snapshot=cached_failure_family,
    )


def _isolated_project_recovery_target_8616(
    function: _AngrFunction,
    isolated_project: angr.Project,
    fallback_linked_base: int,
    fallback_max_addr: int,
) -> tuple[int, int]:
    candidate_addr = function_original_addr(function)
    isolated_main_object = getattr(getattr(isolated_project, "loader", None), "main_object", None)
    isolated_linked_base = getattr(isolated_main_object, "linked_base", fallback_linked_base)
    isolated_max_addr = getattr(isolated_main_object, "max_addr", fallback_max_addr)
    if not isinstance(isolated_linked_base, int):
        isolated_linked_base = fallback_linked_base
    if not isinstance(isolated_max_addr, int):
        isolated_max_addr = fallback_max_addr
    isolated_image_end = (
        isolated_max_addr + 1
        if isolated_max_addr >= isolated_linked_base
        else isolated_linked_base + isolated_max_addr + 1
    )
    return candidate_addr, isolated_image_end


@cast(Callable[[Callable[..., FunctionWorkResult]], Callable[..., FunctionWorkResult]], trace_function(name="function.work_item"))
def _run_function_work_item_uncached(
    item: FunctionWorkItem,
    *,
    timeout: int,
    api_style: str,
    binary_path: Path | None,
    cod_metadata: CODProcMetadata | None,
    synthetic_globals: dict[int, tuple[str, int]] | None,
    lst_metadata: LSTMetadata | None,
    enable_structured_simplify: bool,
    enable_postprocess: bool = True,
    force_isolated_project: bool = False,
    process_isolated_worker: bool = False,
    allow_isolated_retry: bool = True,
) -> FunctionWorkResult:
    """Decompile one function under the requested analysis-isolation policy."""

    def _impl() -> FunctionWorkResult:
        block_estimate, _byte_estimate = _function_complexity(item.function)
        annotate_current_span(
            blocks=block_estimate,
            bytes=_byte_estimate,
        )
        complexity_timeout_bonus = max(0, int(block_estimate) - 30) * 2
        effective_timeout = _enforce_function_timeout_cap(
            max(1, min(360, int(timeout) + complexity_timeout_bonus)),
            context="complexity-aware decompile timeout",
        )
        cached_work_result, cache_bypass_debug, cache_key, tail_validation_enabled, expected_validation_stages = (
            _function_work_cache_lookup(
                item,
                binary_path=binary_path,
                timeout=effective_timeout,
                api_style=api_style,
                enable_structured_simplify=enable_structured_simplify,
                enable_postprocess=enable_postprocess,
                cod_metadata=cod_metadata,
                synthetic_globals=synthetic_globals,
                lst_metadata=lst_metadata,
            )
        )
        if cached_work_result is not None:
            annotate_current_span(cache="hit", status=cached_work_result.status)
            return cached_work_result

        cache_key = cache_key or function_decompilation_cache_key_8616(
            item,
            binary_path=binary_path,
            api_style=api_style,
            cod_metadata=cod_metadata,
            synthetic_globals=synthetic_globals,
            lst_metadata=lst_metadata,
            enable_structured_simplify=enable_structured_simplify,
            enable_postprocess=enable_postprocess,
        )

        ctx = _WorkRunCtx8616(
            item=item,
            api_style=api_style,
            binary_path=binary_path,
            lst_metadata=lst_metadata,
            cod_metadata=cod_metadata,
            synthetic_globals=synthetic_globals,
            effective_timeout=effective_timeout,
            enable_structured_simplify=enable_structured_simplify,
            enable_postprocess=enable_postprocess,
            allow_isolated_retry=allow_isolated_retry,
            force_isolated_project=force_isolated_project,
            process_isolated_worker=process_isolated_worker,
            failure_family_state=FailureFamilyState(),
        )
        decompile_project = item.function.project
        decompile_cfg = item.function_cfg
        decompile_function: _AngrFunction = item.function
        attach_lst_metadata_to_project(decompile_project, lst_metadata)
        helper_result = _maybe_return_known_helper_result_8616(
            ctx,
            decompile_project,
            decompile_cfg,
            decompile_function,
        )
        if helper_result is not None:
            return helper_result

        lane = _decompile_for_work_item_8616(
            ctx,
            decompile_project,
            decompile_cfg,
            decompile_function,
            block_estimate,
            _byte_estimate,
            tail_validation_enabled,
            expected_validation_stages,
        )
        if isinstance(lane, FunctionWorkResult):
            return lane
        (
            status,
            payload,
            partial_payload,
            debug_output,
            tail_validation_snapshot,
            elapsed,
            block_count,
            byte_count,
        ), decompile_project, decompile_cfg, decompile_function = lane
        if cache_bypass_debug:
            debug_output = f"{cache_bypass_debug}{debug_output}"
        return _finalize_work_result_8616(
            ctx,
            status=status,
            payload=payload,
            partial_payload=partial_payload,
            debug_output=debug_output,
            tail_validation_snapshot=tail_validation_snapshot,
            elapsed=elapsed,
            block_count=block_count,
            byte_count=byte_count,
            decompile_project=decompile_project,
            decompile_function=decompile_function,
            decompile_cfg=decompile_cfg,
            cache_key=cache_key,
            tail_validation_enabled=tail_validation_enabled,
            expected_validation_stages=tuple(expected_validation_stages),
        )

    with span(
        "cli.function_work",
        index=item.index,
        addr=hex(getattr(item.function, "addr", 0)),
        name=getattr(item.function, "name", None),
        timeout=timeout,
    ):
        return _impl()


@dataclass(frozen=True, slots=True)
class _WorkRunCtx8616:
    """Shared context for one uncached work-item decompile run."""

    item: FunctionWorkItem
    api_style: str
    binary_path: Path | None
    lst_metadata: LSTMetadata | None
    cod_metadata: CODProcMetadata | None
    synthetic_globals: dict[int, tuple[str, int]] | None
    effective_timeout: int
    enable_structured_simplify: bool
    enable_postprocess: bool
    allow_isolated_retry: bool
    force_isolated_project: bool
    process_isolated_worker: bool
    failure_family_state: FailureFamilyState


_DecompileRunTuple8616 = tuple[str, str, str | None, str, dict[str, object] | None, float, int, int]


def _maybe_return_known_helper_result_8616(
    ctx: _WorkRunCtx8616,
    decompile_project: angr.Project,
    decompile_cfg: object,
    decompile_function: _AngrFunction,
) -> FunctionWorkResult | None:
    """Return a known-runtime-helper result when the helper lane renders C."""
    helper_name = getattr(decompile_function, "name", None)
    known_helper_preview = (
        _try_emit_known_runtime_helper_c(name=helper_name) if isinstance(helper_name, str) else None
    )
    if not isinstance(helper_name, str) or known_helper_preview is None:
        return None
    helper_outcome = _try_decompile_non_optimized_known_function(
        decompile_project,
        decompile_cfg,
        decompile_function,
        timeout=max(1, min(ctx.effective_timeout, 2)),
        api_style=ctx.api_style,
        binary_path=ctx.binary_path,
        lst_metadata=ctx.lst_metadata,
        cod_metadata=ctx.cod_metadata,
        synthetic_globals=ctx.synthetic_globals,
        failure_family_state=ctx.failure_family_state,
    )
    helper_c = _non_optimized_slice_rendered(helper_outcome)
    if helper_c is None:
        return None
    helper_snapshot = _tail_validation_snapshot_for_fallback(
        decompile_project,
        decompile_function,
        allow_project_fallback=False,
    )
    return FunctionWorkResult(
        index=ctx.item.index,
        status="ok",
        payload=helper_c,
        partial_payload=None,
        debug_output="",
        function=ctx.item.function,
        function_cfg=ctx.item.function_cfg,
        tail_validation=helper_snapshot,
        elapsed=0.0,
        block_count=None,
        byte_count=None,
    )


def _recovered_evidence_acceptance_8616(
    decompile_project: angr.Project,
    decompile_function: _AngrFunction,
    tail_validation_enabled: bool,
    expected_validation_stages: Sequence[str],
) -> tuple[str, str, None, dict[str, object], str | None, str | None] | None:
    """Re-accept a recovered binary-evidence candidate through the canonical gate."""
    recovered_payload, recovered_snapshot = _recover_binary_evidence_c_8616(
        decompile_project, decompile_function
    )
    if not (
        isinstance(recovered_payload, str)
        and recovered_payload.strip()
        and isinstance(recovered_snapshot, dict)
    ):
        return None
    recovered_acceptance = _validated_generated_c_acceptance_8616(
        status="ok",
        payload=recovered_payload,
        tail_validation_snapshot=recovered_snapshot,
        tail_validation_enabled=tail_validation_enabled,
        expected_validation_stages=expected_validation_stages,
        c_target=getattr(decompile_project, "_inertia_c_target", "portable-flat"),
    )
    if recovered_acceptance.status == "ok" and recovered_acceptance.blocker is None:
        return (
            recovered_acceptance.status,
            recovered_acceptance.gcc_checked_payload,
            None,
            recovered_snapshot,
            recovered_acceptance.validated_payload_hash,
            recovered_acceptance.gcc_checked_payload_hash,
        )
    return None


def _finalize_acceptance_lanes_8616(
    *,
    status: str,
    partial_payload: str | None,
    tail_validation_snapshot: dict[str, object] | None,
    acceptance: CAcceptanceResult8616,
    decompile_project: angr.Project,
    decompile_function: _AngrFunction,
    tail_validation_enabled: bool,
    expected_validation_stages: Sequence[str],
) -> tuple[str, str, str | None, dict[str, object] | None, str | None, str | None]:
    """Apply blocker, recovered-evidence, and partial acceptance lanes."""
    acceptance_payload = acceptance.validated_payload
    acceptance_validated_hash: str | None = acceptance.validated_payload_hash
    acceptance_gcc_hash: str | None = acceptance.gcc_checked_payload_hash
    payload = acceptance.gcc_checked_payload
    if acceptance.blocker is not None:
        if status == WorkItemStatus.VALIDATION_FAILED.value:
            preserved_candidate = None
        else:
            preserved_candidate = (
                partial_payload
                if isinstance(partial_payload, str) and partial_payload.strip()
                else (
                    acceptance_payload
                    if isinstance(acceptance_payload, str) and acceptance_payload.strip()
                    else None
                )
            )
        payload = acceptance.blocker
        partial_payload = preserved_candidate
    if status in {"empty", "validation_failed"}:
        recovered = _recovered_evidence_acceptance_8616(
            decompile_project,
            decompile_function,
            tail_validation_enabled,
            expected_validation_stages,
        )
        if recovered is not None:
            (
                status,
                payload,
                partial_payload,
                tail_validation_snapshot,
                acceptance_validated_hash,
                acceptance_gcc_hash,
            ) = recovered
    if status == "empty" and isinstance(partial_payload, str) and partial_payload.strip():
        partial_acceptance = _validated_generated_c_acceptance_8616(
            status="ok",
            payload=partial_payload,
            tail_validation_snapshot=tail_validation_snapshot,
            tail_validation_enabled=tail_validation_enabled,
            expected_validation_stages=tuple(expected_validation_stages),
            c_target=getattr(decompile_project, "_inertia_c_target", "portable-flat"),
        )
        if partial_acceptance.status == "ok" and partial_acceptance.blocker is None:
            status = partial_acceptance.status
            payload = partial_acceptance.gcc_checked_payload
            partial_payload = None
    return status, payload, partial_payload, tail_validation_snapshot, acceptance_validated_hash, acceptance_gcc_hash


def _finalize_work_result_8616(
    ctx: _WorkRunCtx8616,
    *,
    status: str,
    payload: str,
    partial_payload: str | None,
    debug_output: str,
    tail_validation_snapshot: dict[str, object] | None,
    elapsed: float,
    block_count: int | None,
    byte_count: int | None,
    decompile_project: angr.Project,
    decompile_function: _AngrFunction,
    decompile_cfg: object,
    cache_key: dict[str, object] | None,
    tail_validation_enabled: bool,
    expected_validation_stages: Sequence[str],
) -> FunctionWorkResult:
    """Apply acceptance, recovery, and cache policy, then build the result."""
    acceptance = _validated_generated_c_acceptance_8616(
        status=status,
        payload=payload,
        tail_validation_snapshot=tail_validation_snapshot,
        tail_validation_enabled=tail_validation_enabled,
        expected_validation_stages=expected_validation_stages,
        c_target=getattr(decompile_project, "_inertia_c_target", "portable-flat"),
    )
    (
        status,
        payload,
        partial_payload,
        tail_validation_snapshot,
        acceptance_validated_hash,
        acceptance_gcc_hash,
    ) = _finalize_acceptance_lanes_8616(
        status=acceptance.status,
        partial_payload=partial_payload,
        tail_validation_snapshot=tail_validation_snapshot,
        acceptance=acceptance,
        decompile_project=decompile_project,
        decompile_function=decompile_function,
        tail_validation_enabled=tail_validation_enabled,
        expected_validation_stages=expected_validation_stages,
    )
    tail_validation_passed = status == "ok"
    if cache_key is not None and tail_validation_passed:
        _store_cache_json(
            "function_decompile",
            cache_key,
            {
                "status": status,
                "payload": payload,
                "tail_validation": tail_validation_snapshot,
                "tail_validation_passed": tail_validation_passed,
                "elapsed": elapsed,
                "block_count": block_count,
                "byte_count": byte_count,
                "validated_c_hash": acceptance_validated_hash,
                "gcc_checked_c_hash": acceptance_gcc_hash,
                "diagnostic_output": (
                    debug_output
                    if os.environ.get("INERTIA_ENABLE_TYPED_SWITCH_AST_ARTIFACTS") == "1"
                    else None
                ),
            },
        )
    return FunctionWorkResult(
        index=ctx.item.index,
        status=status,
        payload=payload,
        partial_payload=partial_payload,
        debug_output=debug_output,
        function=decompile_function,
        function_cfg=decompile_cfg,
        tail_validation=tail_validation_snapshot,
        elapsed=elapsed,
        block_count=block_count,
        byte_count=byte_count,
        same_family_retry_stops=ctx.failure_family_state.same_family_retry_stops,
        fallback_family_labels=ctx.failure_family_state.fallback_family_labels,
        validated_payload_hash=acceptance_validated_hash,
        gcc_checked_payload_hash=acceptance_gcc_hash,
    )


def _helper_model_tail_snapshot_8616(
    status: str,
    payload: str,
    function_obj: _AngrFunction,
    tail_snapshot_local: dict[str, object] | None,
) -> dict[str, object] | None:
    """Substitute the helper-model snapshot when payload matches the model."""
    if not _payload_needs_helper_retry_8616(status, payload, function_obj, tail_snapshot_local):
        return tail_snapshot_local
    helper_model = _try_emit_known_runtime_helper_c(name=function_obj.name)
    if not isinstance(helper_model, str):
        return tail_snapshot_local
    norm_payload = re.sub(r"\s+", "", payload)
    norm_helper = re.sub(r"\s+", "", helper_model)
    if norm_payload != norm_helper:
        return tail_snapshot_local
    return {
        "structuring": {
            "status": "stable",
            "mode": "helper_model",
            "changed": False,
            "detail": f"known compiler/runtime helper model: {function_obj.name}",
        },
        "postprocess": {
            "status": "stable",
            "mode": "helper_model",
            "changed": False,
            "detail": f"known compiler/runtime helper model: {function_obj.name}",
        },
    }


def _run_local_work_8616(
    ctx: _WorkRunCtx8616,
    project_obj: angr.Project,
    cfg_obj: object,
    function_obj: _AngrFunction,
) -> _DecompileRunTuple8616:
    """Run one decompile attempt with captured output and tail snapshot."""
    with _capture_thread_output() as (stdout_buf, stderr_buf):
        _apply_function_annotations_for_active_and_original_8616(
            project_obj,
            ctx.binary_path,
            ctx.lst_metadata,
            function_obj,
            cod_metadata=ctx.cod_metadata,
            synthetic_globals=ctx.synthetic_globals,
        )
        local_block_count, local_byte_count = _function_complexity(function_obj)
        local_arch_name = getattr(getattr(project_obj, "arch", None), "name", "")
        local_clinic_policy = DirectClinicPolicy8616.STANDARD
        if local_arch_name == "86_16":
            local_callsite_count = (
                _safe_function_callsite_count_8616(function_obj)
                if _clinic_policy_needs_callsite_count_8616(
                    arch_name=local_arch_name,
                    direct_addr_mode=True,
                    block_count=local_block_count,
                    byte_count=local_byte_count,
                )
                else 0
            )
            local_clinic_policy = _direct_clinic_policy_8616(
                arch_name=local_arch_name,
                direct_addr_mode=True,
                block_count=local_block_count,
                byte_count=local_byte_count,
                call_site_count=local_callsite_count,
            )
        with _temporary_clinic_policy_8616(project_obj, local_clinic_policy):
            status, payload, partial_payload, block_count, byte_count, elapsed = _decompile_function_with_stats(
                project_obj,
                cfg_obj,
                function_obj,
                ctx.effective_timeout,
                ctx.api_style,
                ctx.binary_path,
                cod_metadata=ctx.cod_metadata,
                synthetic_globals=ctx.synthetic_globals,
                lst_metadata=ctx.lst_metadata,
                enable_structured_simplify=ctx.enable_structured_simplify,
                enable_postprocess=ctx.enable_postprocess,
                allow_isolated_retry=ctx.allow_isolated_retry,
                failure_family_state=ctx.failure_family_state,
            )
            annotate_current_span(clinic_policy=local_clinic_policy.value)
    debug_output_local = stdout_buf.getvalue()
    err_output = stderr_buf.getvalue()
    if err_output:
        debug_output_local += err_output
    raw_tail_snapshot = _tail_validation_snapshot_for_function_run(project_obj, function_obj)
    tail_snapshot_local: dict[str, object] | None = raw_tail_snapshot if isinstance(raw_tail_snapshot, dict) else None
    tail_snapshot_local = _helper_model_tail_snapshot_8616(status, payload, function_obj, tail_snapshot_local)
    if os.environ.get("INERTIA_DEBUG_TAIL_SNAPSHOT"):
        logging.getLogger(__name__).warning(
            "tail snapshot function=%#x name=%s snapshot=%r",
            getattr(function_obj, "addr", -1) or -1,
            getattr(function_obj, "name", "sub"),
            tail_snapshot_local,
        )
    return (
        status,
        payload,
        partial_payload,
        debug_output_local,
        tail_snapshot_local,
        elapsed,
        block_count,
        byte_count,
    )


def _isolated_project_lane_8616(
    ctx: _WorkRunCtx8616,
    item_function: _AngrFunction,
    decompile_project: angr.Project,
    block_estimate: int,
    byte_estimate: int,
) -> tuple[angr.Project, object, _AngrFunction] | FunctionWorkResult | None:
    """Rebuild the decompile triple on a fresh isolated project when possible."""
    main_object = getattr(getattr(item_function, "project", None), "loader", None)
    main_object = getattr(main_object, "main_object", None)
    linked_base = getattr(main_object, "linked_base", None)
    max_addr = getattr(main_object, "max_addr", None)
    if not (isinstance(linked_base, int) and isinstance(max_addr, int)):
        return None
    try:
        isolated_project = _build_project_cached(
            str(ctx.binary_path),
            force_blob=False,
            base_addr=linked_base,
            entry_point=getattr(item_function.project, "entry", linked_base),
        )
        _transfer_caller_return_use_evidence_8616(decompile_project, isolated_project)
        attach_lst_metadata_to_project(isolated_project, ctx.lst_metadata)
        _inherit_tail_validation_runtime_policy(isolated_project, item_function.project)
        candidate_addr, isolated_image_end = _isolated_project_recovery_target_8616(
            item_function,
            isolated_project,
            linked_base,
            max_addr,
        )
        isolated_cfg, isolated_function = _recover_candidate_function_pair(
            isolated_project,
            candidate_addr=candidate_addr,
            image_end=isolated_image_end,
            metadata=ctx.lst_metadata,
            project_entry=isolated_project.entry,
            region_span=max(0x180, _function_complexity(item_function)[1] + 0x80),
        )
        _preserve_source_label_for_recovered_function_8616(item_function, isolated_function)
        mark_function_original_addr(isolated_function, candidate_addr)
        return isolated_project, isolated_cfg, isolated_function
    except Exception as ex:
        logging.getLogger(__name__).warning("isolated project/function set up failed: %s", ex)
        return FunctionWorkResult(
            index=ctx.item.index,
            status=WorkItemStatus.ERROR.value,
            payload=f"Fresh isolated project/function setup failed: {_describe_exception(ex)}",
            partial_payload=None,
            debug_output="",
            function=ctx.item.function,
            function_cfg=ctx.item.function_cfg,
            elapsed=0.0,
            block_count=block_estimate,
            byte_count=byte_estimate,
            failure_stage="fresh_project_recovery",
        )


def _decompile_for_work_item_8616(
    ctx: _WorkRunCtx8616,
    decompile_project: angr.Project,
    decompile_cfg: object,
    decompile_function: _AngrFunction,
    block_estimate: int,
    byte_estimate: int,
    tail_validation_enabled: bool,
    expected_validation_stages: Sequence[str],
) -> FunctionWorkResult | tuple[_DecompileRunTuple8616, angr.Project, object, _AngrFunction]:
    """Run the fork or local decompile lane for one work item."""
    fork_isolated_eligible = (
        ctx.force_isolated_project
        and not ctx.process_isolated_worker
        and _analysis_timeout_use_fork_8616()
        and decompile_cfg is not None
    )
    if fork_isolated_eligible:
        try:
            with span(
                "direct.decompile_job",
                addr=hex(getattr(decompile_function, "addr", 0)),
                name=getattr(decompile_function, "name", None),
                timeout=_enforce_function_timeout_cap(
                    max(1, ctx.effective_timeout) + 1,
                    context="forked local decompile",
                ),
                isolated="fork",
            ):
                run_tuple = _run_with_timeout_in_fork(
                    lambda: _run_local_work_8616(ctx, decompile_project, decompile_cfg, decompile_function),
                    timeout=_enforce_function_timeout_cap(
                        max(1, ctx.effective_timeout) + 1,
                        context="forked local decompile",
                    ),
                )
                annotate_current_span(status=run_tuple[0], blocks=run_tuple[6], bytes=run_tuple[7])
                return run_tuple, decompile_project, decompile_cfg, decompile_function
        except TimeoutError as ex:
            logging.getLogger(__name__).warning("fork-isolated decompilation timed out: %s", ex)
            return _finalize_work_result_8616(
                ctx,
                status="timeout",
                payload=f"Timed out after {ctx.effective_timeout}s during fork-isolated decompilation.",
                partial_payload=None,
                debug_output="",
                tail_validation_snapshot=None,
                elapsed=float(ctx.effective_timeout),
                block_count=block_estimate,
                byte_count=byte_estimate,
                decompile_project=decompile_project,
                decompile_function=decompile_function,
                decompile_cfg=decompile_cfg,
                cache_key=None,
                tail_validation_enabled=tail_validation_enabled,
                expected_validation_stages=expected_validation_stages,
            )
        except Exception as ex:
            logging.getLogger(__name__).warning("fork-isolated decompilation failed: %s", ex)
            fork_isolated_eligible = False

    if (
        ctx.force_isolated_project
        and not fork_isolated_eligible
        and ctx.binary_path is not None
        and isinstance(getattr(ctx.item.function, "addr", None), int)
    ):
        isolated_lane = _isolated_project_lane_8616(
            ctx, ctx.item.function, decompile_project, block_estimate, byte_estimate
        )
        if isinstance(isolated_lane, FunctionWorkResult):
            return isolated_lane
        if isolated_lane is not None:
            decompile_project, decompile_cfg, decompile_function = isolated_lane

    with span(
        "direct.decompile_job",
        addr=hex(getattr(decompile_function, "addr", 0)),
        name=getattr(decompile_function, "name", None),
        timeout=ctx.effective_timeout,
        isolated="local",
    ):
        run_tuple = _run_local_work_8616(ctx, decompile_project, decompile_cfg, decompile_function)
        annotate_current_span(status=run_tuple[0], blocks=run_tuple[6], bytes=run_tuple[7])
    return run_tuple, decompile_project, decompile_cfg, decompile_function


def _function_work_result_for_fork_ipc(result: FunctionWorkResult) -> FunctionWorkResult:
    # angr Function/CFG objects are not reliable pickle payloads. The parent still owns
    # canonical references for emission and fallback attribution.
    return replace(result, function=None, function_cfg=None)


_SERIAL_CLEAN_WORKER_RESULT_ENV_8616 = "INERTIA_SERIAL_CLEAN_WORKER_RESULT"
_SERIAL_CLEAN_WORKER_RESULT_SCHEMA_8616 = 4


def _direct_addr_work_requires_parent_lock_8616(lock_key: dict[str, object] | None) -> bool:
    """Return whether this process owns direct-address producer serialization."""
    return lock_key is not None and not bool(os.environ.get(_SERIAL_CLEAN_WORKER_RESULT_ENV_8616))


def _write_serial_clean_worker_result_8616(
    result: FunctionWorkResult,
    *,
    project: object | None = None,
) -> None:
    """Write a direct-address result for its serial clean-process parent."""
    result_path_text = os.environ.get(_SERIAL_CLEAN_WORKER_RESULT_ENV_8616)
    if not result_path_text:
        return
    if project is not None:
        result = with_segment_program_function_evidence_8616(result, project)
    result_path = Path(result_path_text)
    result_path.parent.mkdir(parents=True, exist_ok=True)
    record: dict[str, object] = {
        "schema": _SERIAL_CLEAN_WORKER_RESULT_SCHEMA_8616,
        "status": result.status,
        "payload": result.payload,
        "partial_payload": result.partial_payload,
        "tail_validation": result.tail_validation,
        "elapsed": result.elapsed,
        "failure_stage": result.failure_stage,
        "block_count": result.block_count,
        "byte_count": result.byte_count,
        "skip_heavy_fallbacks": result.skip_heavy_fallbacks,
        "same_family_retry_stops": result.same_family_retry_stops,
        "fallback_family_labels": list(result.fallback_family_labels),
        "failure_family_snapshot": (
            None if result.failure_family_snapshot is None else result.failure_family_snapshot.to_record()
        ),
        "validated_payload_hash": result.validated_payload_hash,
        "gcc_checked_payload_hash": result.gcc_checked_payload_hash,
        "segment_program_function_evidence": (
            None
            if result.segment_program_function_evidence is None
            else result.segment_program_function_evidence.to_dict()
        ),
    }
    temporary_path = result_path.with_suffix(result_path.suffix + ".tmp")
    temporary_path.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
    os.replace(temporary_path, result_path)


def _read_serial_clean_worker_result_8616(
    result_path: Path,
    *,
    item: FunctionWorkItem,
    debug_output: str,
) -> FunctionWorkResult:
    """Read and validate one direct-address clean-process result."""
    try:
        record = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as ex:
        raise ValueError(f"invalid serial clean-worker result: {ex}") from ex
    if not isinstance(record, dict) or record.get("schema") != _SERIAL_CLEAN_WORKER_RESULT_SCHEMA_8616:
        raise ValueError("serial clean-worker result has an unsupported schema")
    status = record.get("status")
    payload = record.get("payload")
    if not isinstance(status, str) or _work_item_status_8616(status) is WorkItemStatus.UNKNOWN:
        raise ValueError("serial clean-worker result has an invalid status")
    if not isinstance(payload, str):
        raise ValueError("serial clean-worker result has a non-text payload")
    partial_payload = record.get("partial_payload")
    if partial_payload is not None and not isinstance(partial_payload, str):
        raise ValueError("serial clean-worker result has a non-text partial payload")
    tail_validation = record.get("tail_validation")
    if tail_validation is not None and not isinstance(tail_validation, dict):
        raise ValueError("serial clean-worker result has invalid tail-validation state")
    fallback_family_labels = record.get("fallback_family_labels")
    if not isinstance(fallback_family_labels, list) or not all(
        isinstance(label, str) for label in fallback_family_labels
    ):
        raise ValueError("serial clean-worker result has invalid fallback-family labels")
    same_family_retry_stops = record.get("same_family_retry_stops")
    if not isinstance(same_family_retry_stops, int):
        same_family_retry_stops = 0
    failure_family_snapshot = FailureFamilySnapshot.from_record(record.get("failure_family_snapshot"))
    raw_segment_evidence = record.get("segment_program_function_evidence")
    segment_evidence = (
        None
        if raw_segment_evidence is None
        else segment_program_function_evidence_from_record_8616(raw_segment_evidence)
    )
    if segment_evidence is not None and not segment_program_function_evidence_matches_item_8616(
        segment_evidence,
        item,
    ):
        raise ValueError("serial clean-worker segment evidence belongs to a different function")
    return FunctionWorkResult(
        index=item.index,
        status=status,
        payload=payload,
        partial_payload=partial_payload,
        debug_output=debug_output,
        function=item.function,
        function_cfg=item.function_cfg,
        tail_validation=tail_validation,
        elapsed=record.get("elapsed") if isinstance(record.get("elapsed"), (int, float)) else None,
        failure_stage=record.get("failure_stage") if isinstance(record.get("failure_stage"), str) else None,
        block_count=record.get("block_count") if isinstance(record.get("block_count"), int) else None,
        byte_count=record.get("byte_count") if isinstance(record.get("byte_count"), int) else None,
        skip_heavy_fallbacks=record.get("skip_heavy_fallbacks") is True,
        same_family_retry_stops=same_family_retry_stops,
        fallback_family_labels=tuple(fallback_family_labels),
        failure_family_snapshot=failure_family_snapshot,
        validated_payload_hash=(
            record.get("validated_payload_hash") if isinstance(record.get("validated_payload_hash"), str) else None
        ),
        gcc_checked_payload_hash=(
            record.get("gcc_checked_payload_hash")
            if isinstance(record.get("gcc_checked_payload_hash"), str)
            else None
        ),
        segment_program_function_evidence=segment_evidence,
    )


def _complete_serial_clean_worker_result_8616(
    result: FunctionWorkResult,
    *,
    project: object | None = None,
) -> bool:
    """Serialize a clean-worker result and tell the direct CLI to stop retrying."""
    if not os.environ.get(_SERIAL_CLEAN_WORKER_RESULT_ENV_8616):
        return False
    _write_serial_clean_worker_result_8616(result, project=project)
    return True


def _serial_clean_worker_command_8616(
    args: CliArguments,
    *,
    recovery_addr: int,
    timeout: int,
    window: int | None = None,
    exact_region_end: int | None = None,
) -> list[str]:
    """Build the bounded direct-address command used by a serial clean worker."""
    command = [
        sys.executable,
        "-m",
        "inertia_decompiler.serial_clean_worker_cli",
        str(args.binary),
        "--addr",
        hex(recovery_addr),
        "--timeout",
        str(max(1, timeout)),
        "--window",
        hex(args.window if window is None else max(1, window)),
        "--base-addr",
        hex(args.base_addr),
        "--entry-point",
        hex(args.entry_point),
        "--c-target",
        args.c_target,
        "--api-style",
        args.api_style,
        "--pat-backend",
        args.pat_backend,
        "--no-alternate-source-c",
        "--ignore-local-sidecar-hints",
    ]
    if args.blob:
        command.append("--blob")
    if exact_region_end is not None:
        command.extend(("--exact-region-end", hex(exact_region_end)))
    if args.signature_catalog is not None:
        command.extend(("--signature-catalog", str(args.signature_catalog)))
    if args.trace_c_stages:
        command.append("--trace-c-stages")
    if args.dump_layers:
        command.extend(
            (
                "--dump-layers",
                "--dump-layer-dir",
                str(args.dump_layer_dir),
                "--dump-layer-filter",
                args.dump_layer_filter,
            )
        )
    return command


def _serial_clean_worker_outer_timeout_8616(timeout: int) -> int:
    """Allow bounded interpreter, protocol, and final-check overhead."""
    return max(10, max(1, timeout) + 45)


def _serial_clean_worker_debug_output_8616(stderr: str | bytes | None) -> str:
    """Remove only the child transport marker from parent-visible diagnostics."""
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", errors="replace")
    if not isinstance(stderr, str):
        return ""
    retained_lines = [
        line
        for line in stderr.splitlines(keepends=True)
        if not line.strip().endswith("/* == c == */")
    ]
    return "".join(retained_lines)


@typing.overload
def _run_serial_clean_process_work_item_8616(
    context: _BatchCliContext8616,
    item: FunctionWorkItem,
    *,
    timeout: int,
    caller_return_evidence_by_addr: dict[int, CallerReturnUseEvidence8616] | None = None,
    cache_only: typing.Literal[False] = False,
) -> FunctionWorkResult: ...


@typing.overload
def _run_serial_clean_process_work_item_8616(
    context: _BatchCliContext8616,
    item: FunctionWorkItem,
    *,
    timeout: int,
    caller_return_evidence_by_addr: dict[int, CallerReturnUseEvidence8616] | None = None,
    cache_only: typing.Literal[True],
) -> FunctionWorkResult | None: ...


def _run_serial_clean_process_work_item_8616(
    context: _BatchCliContext8616,
    item: FunctionWorkItem,
    *,
    timeout: int,
    caller_return_evidence_by_addr: dict[int, CallerReturnUseEvidence8616] | None = None,
    cache_only: bool = False,
) -> FunctionWorkResult | None:
    """Load or produce one clean-worker result without inherited module state."""
    recovery_addr = _function_work_item_recovery_addr_8616(item)
    requested_addr = recovery_addr
    canonical = _canonicalize_direct_addr_from_sidecar_padding_8616(
        context.project,
        context.lst_metadata,
        recovery_addr,
    )
    if canonical is not None:
        recovery_addr = canonical.canonical_addr
    worker_window, exact_region_end = _serial_clean_worker_window_8616(context, recovery_addr)
    command = _serial_clean_worker_command_8616(
        context.args,
        recovery_addr=recovery_addr,
        timeout=timeout,
        window=worker_window,
        exact_region_end=exact_region_end,
    )
    started_at = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="inertia-clean-worker-") as temporary_dir:
        result_path = Path(temporary_dir) / "result.json"
        evidence_path = Path(temporary_dir) / "evidence.json"
        _write_serial_clean_worker_evidence_8616(
            context.project,
            evidence_path,
            evidence_by_addr=caller_return_evidence_by_addr,
        )
        cache_args = copy.copy(context.args)
        cache_args.window = worker_window
        cache_lookup = load_serial_worker_cache_8616(
            serial_worker_cache_inputs_8616(
                cache_args,
                requested_addr=requested_addr,
                recovery_addr=recovery_addr,
                timeout=timeout,
                evidence_path=evidence_path,
                environment=os.environ,
                result_schema=_SERIAL_CLEAN_WORKER_RESULT_SCHEMA_8616,
            ),
            enabled=not context.args.trace_c_stages and not context.args.dump_layers,
        )
        if cache_lookup.verdict is SerialWorkerCacheVerdict8616.HIT and cache_lookup.record is not None:
            return _serial_clean_cache_hit_result_8616(cache_lookup, result_path, item, recovery_addr)
        if cache_only:
            return None
        environment = os.environ.copy()
        environment[_SERIAL_CLEAN_WORKER_RESULT_ENV_8616] = str(result_path)
        environment[_SERIAL_CLEAN_WORKER_EVIDENCE_ENV_8616] = str(evidence_path)
        if _ARCHITECTURE_GUARD_STATUS_8616 is True:
            environment[ARCHITECTURE_GUARD_VERIFIED_PARENT_PID_ENV] = str(os.getpid())
        environment["INERTIA_OTEL_PROFILE_IN_PROCESS"] = "1"
        environment["INERTIA_DIRECT_ADDR_PREFER_LST"] = "0"
        outer_timeout = _serial_clean_worker_outer_timeout_8616(timeout)
        try:
            completed = run_captured_subprocess_tree(
                command,
                env=environment,
                timeout=outer_timeout,
            )
        except subprocess.TimeoutExpired as ex:
            return FunctionWorkResult(
                index=item.index,
                status=WorkItemStatus.TIMEOUT.value,
                payload=f"Clean serial worker timed out after {outer_timeout}s.",
                debug_output=_serial_clean_worker_debug_output_8616(ex.stderr),
                function=item.function,
                function_cfg=item.function_cfg,
                elapsed=time.perf_counter() - started_at,
                skip_heavy_fallbacks=True,
                failure_stage="clean_process_decompilation",
                execution_origin=FunctionWorkExecutionOrigin8616.CLEAN_PROCESS,
            )
        debug_output = _serial_clean_worker_debug_output_8616(completed.stderr)
        if completed.returncode != 0 or not result_path.exists():
            return FunctionWorkResult(
                index=item.index,
                status=WorkItemStatus.ERROR.value,
                payload=(
                    f"Clean serial worker failed for {recovery_addr:#x} "
                    f"(exit={completed.returncode}, result_present={result_path.exists()})."
                ),
                debug_output=debug_output,
                function=item.function,
                function_cfg=item.function_cfg,
                elapsed=time.perf_counter() - started_at,
                failure_stage="clean_process_decompilation",
                execution_origin=FunctionWorkExecutionOrigin8616.CLEAN_PROCESS,
            )
        try:
            result = _read_serial_clean_worker_result_8616(
                result_path,
                item=replace(item, recovery_addr=recovery_addr),
                debug_output=debug_output,
            )
            record = json.loads(result_path.read_text(encoding="utf-8"))
            if isinstance(record, dict):
                store_serial_worker_cache_8616(
                    cache_lookup,
                    record,
                    result_schema=_SERIAL_CLEAN_WORKER_RESULT_SCHEMA_8616,
                )
            return replace(
                result,
                execution_origin=FunctionWorkExecutionOrigin8616.CLEAN_PROCESS,
            )
        except ValueError as ex:
            return FunctionWorkResult(
                index=item.index,
                status=WorkItemStatus.ERROR.value,
                payload=str(ex),
                debug_output=debug_output,
                function=item.function,
                function_cfg=item.function_cfg,
                elapsed=time.perf_counter() - started_at,
                failure_stage="clean_process_protocol",
                execution_origin=FunctionWorkExecutionOrigin8616.CLEAN_PROCESS,
            )


def _serial_clean_worker_window_8616(
    context: _BatchCliContext8616, recovery_addr: int
) -> tuple[int, int | None]:
    """Resolve the clean-worker window from an exact LST region when present."""
    worker_window = context.args.window
    exact_region_end = None
    if context.lst_metadata is not None:
        try:
            exact_region = _lst_code_region(context.lst_metadata, recovery_addr)
        except (AttributeError, KeyError, TypeError, ValueError):
            exact_region = None
        if exact_region is not None and exact_region[0] <= recovery_addr < exact_region[1]:
            exact_region_end = exact_region[1]
            worker_window = max(1, exact_region[1] - recovery_addr)
    return worker_window, exact_region_end


def _serial_clean_cache_hit_result_8616(
    cache_lookup: SerialWorkerCacheLookup8616,
    result_path: Path,
    item: FunctionWorkItem,
    recovery_addr: int,
) -> FunctionWorkResult:
    """Materialize a clean-worker cache hit into a FunctionWorkResult."""
    result_path.write_text(json.dumps(cache_lookup.record, sort_keys=True), encoding="utf-8")
    cached_result = _read_serial_clean_worker_result_8616(
        result_path,
        item=replace(item, recovery_addr=recovery_addr),
        debug_output=f"[dbg] clean serial function cache hit: {recovery_addr:#x}\n",
    )
    return replace(
        cached_result,
        from_cache=True,
        execution_origin=FunctionWorkExecutionOrigin8616.CLEAN_PROCESS,
    )


def _payload_needs_helper_retry_8616(
    status: str, payload: object, function_obj: object, tail_snapshot: object
) -> bool:
    """Check whether a successful payload lacks required validation stages."""
    if status != "ok" or not isinstance(payload, str):
        return False
    if not isinstance(getattr(function_obj, "name", None), str):
        return False
    return _tail_snapshot_missing_stages_8616(tail_snapshot)


def _tail_snapshot_missing_stages_8616(tail_snapshot: object) -> bool:
    """Check whether a tail snapshot misses the structuring or postprocess stage."""
    return (
        not isinstance(tail_snapshot, dict)
        or "structuring" not in tail_snapshot
        or "postprocess" not in tail_snapshot
    )


@typing.overload
def _run_canonicalized_direct_clean_worker_8616(
    project: angr.Project,
    args: CliArguments,
    lst_metadata: LSTMetadata,
    canonical: DirectAddrCanonicalization8616,
    *,
    function_label: str | None,
    caller_return_evidence_by_addr: dict[int, CallerReturnUseEvidence8616] | None = None,
    cache_only: typing.Literal[False] = False,
) -> int: ...


@typing.overload
def _run_canonicalized_direct_clean_worker_8616(
    project: angr.Project,
    args: CliArguments,
    lst_metadata: LSTMetadata,
    canonical: DirectAddrCanonicalization8616,
    *,
    function_label: str | None,
    caller_return_evidence_by_addr: dict[int, CallerReturnUseEvidence8616] | None = None,
    cache_only: typing.Literal[True],
) -> int | None: ...


def _run_canonicalized_direct_clean_worker_8616(
    project: angr.Project,
    args: CliArguments,
    lst_metadata: LSTMetadata,
    canonical: DirectAddrCanonicalization8616,
    *,
    function_label: str | None,
    caller_return_evidence_by_addr: dict[int, CallerReturnUseEvidence8616] | None = None,
    cache_only: bool = False,
) -> int | None:
    """Decompile a sidecar-canonicalized entry in the pure-binary worker."""
    function = SimpleNamespace(
        addr=canonical.canonical_addr,
        name=function_label or canonical.name or f"sub_{canonical.canonical_addr:x}",
    )
    item = FunctionWorkItem(
        index=1,
        function_cfg=SimpleNamespace(),
        function=function,
        recovery_addr=canonical.canonical_addr,
    )
    context = cast(
        "_BatchCliContext8616",
        SimpleNamespace(args=args, project=project, lst_metadata=lst_metadata),
    )
    if cache_only:
        result = _run_serial_clean_process_work_item_8616(
            context,
            item,
            timeout=max(1, args.timeout),
            caller_return_evidence_by_addr=caller_return_evidence_by_addr,
            cache_only=True,
        )
    else:
        result = _run_serial_clean_process_work_item_8616(
            context,
            item,
            timeout=max(1, args.timeout),
            caller_return_evidence_by_addr=caller_return_evidence_by_addr,
        )
    if result is None:
        return None
    if result.debug_output:
        print(result.debug_output, file=sys.stderr, end="" if result.debug_output.endswith("\n") else "\n")
    if result.status == WorkItemStatus.OK.value:
        print(f"/* function: {canonical.canonical_addr:#x} {function.name} */")
        if not _tail_validation_passes_lenient(
            result.tail_validation,
            expected_stages=["structuring", "postprocess"],
        ):
            print("/* canonical clean worker validation=failed: stable snapshots missing */", file=sys.stderr)
            return 4
        print("/* canonical clean worker validation=passed */", file=sys.stderr)
        print("[tail-validation] whole-tail validation clean across 1 functions", file=sys.stderr)
        anonymous_name = f"sub_{canonical.canonical_addr:x}"
        try:
            payload = relabel_generated_function_definition(result.payload, anonymous_name, function.name)
        except ValueError as ex:
            print(f"[dbg] canonical clean worker label unchanged: {ex}", file=sys.stderr)
            payload = result.payload
        print(payload)
        return 0
    if result.partial_payload:
        print(result.partial_payload)
    print(f"/* canonical clean worker {result.status}: {result.payload} */", file=sys.stderr)
    if result.status == WorkItemStatus.TIMEOUT.value:
        return 3
    if result.status == WorkItemStatus.VALIDATION_FAILED.value:
        return 4
    return 6


def _tail_validation_passes_lenient(
    snapshot: dict[str, object] | None,
    *,
    expected_stages: list[str],
) -> bool:
    """Return True only when every expected stage is present and stable."""
    if not isinstance(snapshot, dict):
        return False
    for stage_name in expected_stages:
        entry = snapshot.get(stage_name)
        if not isinstance(entry, Mapping):
            return False
        status = entry.get("status")
        if isinstance(status, str) and status:
            if status != "stable":
                return False
            continue
        if bool(entry.get("changed", False)):
            return False
    return True


@dataclass(frozen=True)
class CAcceptanceResult8616:
    """Validated generated-C acceptance decision and checked payload identity."""

    status: WorkItemStatus
    blocker: str | None
    validated_payload: str
    validated_payload_hash: str
    gcc_checked_payload: str
    gcc_checked_payload_hash: str


def _sha256_text_8616(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def _normalize_gcc_checked_payload_8616(checked_payload: str, emitted_payload: str) -> str:
    checked_raw = str(checked_payload or "")
    emitted_raw = str(emitted_payload or "")
    checked = checked_raw.strip()
    emitted = emitted_raw.strip()
    if not checked:
        return emitted_raw
    if emitted and checked.endswith(emitted):
        return emitted_raw
    if emitted and emitted in checked:
        return emitted_raw
    return checked_raw


def _acceptance_result_8616(
    status: WorkItemStatus | str,
    blocker: str | None,
    payload: str,
) -> CAcceptanceResult8616:
    """Build a typed acceptance result with payload identity evidence."""
    try:
        typed_status = WorkItemStatus(status)
    except ValueError:
        typed_status = WorkItemStatus.UNCOLLECTED
    payload_hash = _sha256_text_8616(payload)
    checked_payload = payload if typed_status is WorkItemStatus.OK and blocker is None else ""
    checked_payload_hash = payload_hash if checked_payload else _sha256_text_8616("")
    return CAcceptanceResult8616(
        status=typed_status,
        blocker=blocker,
        validated_payload=payload,
        validated_payload_hash=payload_hash,
        gcc_checked_payload=checked_payload,
        gcc_checked_payload_hash=checked_payload_hash,
    )


def _normalize_accepted_payload_8616(payload: str) -> str:
    accepted_payload = _normalize_function_signature_arg_names(payload)
    accepted_payload = normalize_unresolved_c_text(accepted_payload)
    accepted_payload = _normalize_anonymous_call_targets(accepted_payload)
    accepted_payload = _strip_register_fragment_suffixes_text(accepted_payload)
    accepted_payload = _normalize_boolean_conditions(accepted_payload)
    accepted_payload = re.sub(r"(?<![A-Za-z0-9_])true(?![A-Za-z0-9_])", "1", accepted_payload)
    accepted_payload = re.sub(r"(?<![A-Za-z0-9_])false(?![A-Za-z0-9_])", "0", accepted_payload)
    accepted_payload = _materialize_stack_base_placeholder_declaration_text(accepted_payload)
    accepted_payload = _materialize_missing_generic_local_declarations_text(accepted_payload)
    accepted_payload = _hoist_c89_local_declarations_text(accepted_payload)
    accepted_payload = _materialize_missing_segment_macro_locals_text(accepted_payload)
    accepted_payload = _dedupe_duplicate_local_declarations_text(accepted_payload)
    accepted_payload = _prune_parameter_shadow_declarations_text(accepted_payload)
    accepted_payload = _prune_undefined_fragment_carrier_assignments_text(accepted_payload)
    accepted_payload = _coalesce_redundant_split_global_incdec_text(accepted_payload)
    accepted_payload = _prune_standalone_memory_helper_reads_text(accepted_payload)
    # Accepted payloads already passed typed AST liveness and validation.
    # Text-based staging DCE must not reinterpret those semantics.
    accepted_payload = _prune_unused_local_declarations_text(accepted_payload)
    accepted_payload = _normalize_scalar_gb_array_declarations_text(accepted_payload)
    accepted_payload = _normalize_seg_offset_void_pointer_args_text(accepted_payload)
    accepted_payload = _normalize_unsupported_computed_goto_text(accepted_payload)
    accepted_payload = _materialize_missing_synthetic_global_declarations_text(
        accepted_payload,
        metadata=None,
        synthetic_globals=None,
    )
    accepted_payload = _materialize_missing_direct_call_prototypes_text(accepted_payload)
    accepted_payload = _prune_void_call_assignments_text(accepted_payload)
    accepted_payload = _materialize_opaque_pointer_typedefs_text(accepted_payload)
    accepted_payload = _normalize_function_signature_arg_names(accepted_payload)
    return str(_hoist_c89_local_declarations_text(accepted_payload))


def _tail_validation_stage_detail_8616(
    tail_validation_snapshot: dict[str, object] | None, expected_validation_stages: list[str] | tuple[str, ...]
) -> str:
    stage_details: list[str] = []
    snapshot_dict = tail_validation_snapshot if isinstance(tail_validation_snapshot, dict) else {}
    for stage_name in expected_validation_stages:
        entry = snapshot_dict.get(stage_name)
        if not isinstance(entry, Mapping):
            stage_details.append(f"{stage_name}=missing")
            continue
        changed = entry.get("changed")
        status = entry.get("status")
        if isinstance(status, str) and status:
            stage_details.append(f"{stage_name}={status}")
        elif isinstance(changed, bool):
            stage_details.append(f"{stage_name}={'changed' if changed else 'stable'}")
        else:
            stage_details.append(f"{stage_name}=unclassified")
    return "; ".join(stage_details) if stage_details else "no stage data"


_RECOMPILE_RESULT_CACHE_8616: dict[tuple[str, str], RecompileCheckResult] = {}
_RECOMPILE_RESULT_CACHE_LOCK_8616 = threading.Lock()


def _collect_recompilation_payloads_8616(accepted_payload: str) -> tuple[list[tuple[str, str]], str | None]:
    def _impl() -> tuple[list[tuple[str, str]], str | None]:
        recompilation_targets = ("portable-flat", "msc-dos")
        checked_payloads: list[tuple[str, str]] = []
        payload_hash = hashlib.sha256(accepted_payload.encode("utf-8", errors="ignore")).hexdigest()
        for recomp_target in recompilation_targets:
            cache_key = (recomp_target, payload_hash)
            with _RECOMPILE_RESULT_CACHE_LOCK_8616:
                recompilation = _RECOMPILE_RESULT_CACHE_8616.get(cache_key)
            if recompilation is None:
                recompilation = check_c_recompiles_8616(accepted_payload, target=recomp_target)
                with _RECOMPILE_RESULT_CACHE_LOCK_8616:
                    _RECOMPILE_RESULT_CACHE_8616[cache_key] = recompilation
            if recompilation.passed:
                checked_payload = _normalize_gcc_checked_payload_8616(
                    recompilation.checked_payload,
                    accepted_payload,
                )
                checked_payloads.append((recomp_target, checked_payload))
                continue
            combined = "\n".join(
                part
                for part in (recompilation.stdout or "", recompilation.stderr or "")
                if isinstance(part, str) and part
            ).strip()
            lines = [line.strip() for line in combined.splitlines() if line.strip()]
            error_lines = [line for line in lines if ("error" in line.lower() or "fatal" in line.lower())]
            if error_lines:
                detail = error_lines[0]
                if len(error_lines) > 1:
                    detail += "; " + "; ".join(error_lines[1:3])
            else:
                detail = lines[0] if lines else "syntax check failed"
                if len(lines) > 1:
                    detail += "; " + "; ".join(lines[1:3])
            source_path = recompilation.source_path
            if isinstance(source_path, str) and source_path:
                detail = f"{detail} [source: {source_path}]"
            toolchain = "gcc portable-flat" if recomp_target == "portable-flat" else "MS C 5.1 msc-dos"
            return checked_payloads, f"{toolchain} syntax check failed: {detail}"
        return checked_payloads, None

    return _impl()


def _run_function_work_item(
    item: FunctionWorkItem,
    *,
    timeout: int,
    api_style: str,
    binary_path: Path | None,
    cod_metadata: CODProcMetadata | None,
    synthetic_globals: _SyntheticGlobals8616 | None,
    lst_metadata: LSTMetadata | None,
    enable_structured_simplify: bool,
    enable_postprocess: bool = True,
    force_isolated_project: bool = False,
    process_isolated_worker: bool = False,
    allow_isolated_retry: bool = True,
) -> FunctionWorkResult:
    """Run one function work item with per-key producer serialization."""
    cache_key = function_decompilation_cache_key_8616(
        item,
        binary_path=binary_path,
        api_style=api_style,
        cod_metadata=cod_metadata,
        synthetic_globals=synthetic_globals,
        lst_metadata=lst_metadata,
        enable_structured_simplify=enable_structured_simplify,
        enable_postprocess=enable_postprocess,
    )
    if cache_key is None or not allow_isolated_retry:
        return _run_function_work_item_uncached(
            item,
            timeout=timeout,
            api_style=api_style,
            binary_path=binary_path,
            cod_metadata=cod_metadata,
            synthetic_globals=synthetic_globals,
            lst_metadata=lst_metadata,
            enable_structured_simplify=enable_structured_simplify,
            enable_postprocess=enable_postprocess,
            force_isolated_project=force_isolated_project,
            process_isolated_worker=process_isolated_worker,
            allow_isolated_retry=allow_isolated_retry,
        )
    with _cache_key_lock("function_decompile", cache_key):
        cached_result, _debug, _key, _tail_enabled, _expected_stages = _function_work_cache_lookup(
            item,
            binary_path=binary_path,
            timeout=timeout,
            api_style=api_style,
            enable_structured_simplify=enable_structured_simplify,
            enable_postprocess=enable_postprocess,
            cod_metadata=cod_metadata,
            synthetic_globals=synthetic_globals,
            lst_metadata=lst_metadata,
        )
        if cached_result is not None:
            return cached_result
        return _run_function_work_item_uncached(
            item,
            timeout=timeout,
            api_style=api_style,
            binary_path=binary_path,
            cod_metadata=cod_metadata,
            synthetic_globals=synthetic_globals,
            lst_metadata=lst_metadata,
            enable_structured_simplify=enable_structured_simplify,
            enable_postprocess=enable_postprocess,
            force_isolated_project=force_isolated_project,
            process_isolated_worker=process_isolated_worker,
            allow_isolated_retry=allow_isolated_retry,
        )


@cast(
    Callable[[Callable[..., CAcceptanceResult8616]], Callable[..., CAcceptanceResult8616]],
    trace_function(name="validation.acceptance"),
)
def _validated_generated_c_acceptance_8616(
    *,
    status: str,
    payload: str,
    tail_validation_snapshot: dict[str, object] | None,
    tail_validation_enabled: bool,
    expected_validation_stages: list[str] | tuple[str, ...],
    c_target: str = "portable-flat",
    emit_failure_diagnostics: bool = True,
) -> CAcceptanceResult8616:
    """Apply final CLI acceptance gates to generated C without changing semantics."""
    if isinstance(tail_validation_snapshot, dict):
        tail_validation_snapshot = copy.deepcopy(tail_validation_snapshot)

    return _acceptance_run_8616(
        status,
        payload,
        tail_validation_snapshot,
        tail_validation_enabled,
        expected_validation_stages,
        emit_failure_diagnostics,
    )


def _acceptance_run_8616(
    status: str,
    payload: str,
    tail_validation_snapshot: dict[str, object] | None,
    tail_validation_enabled: bool,
    expected_validation_stages: list[str] | tuple[str, ...],
    emit_failure_diagnostics: bool,
) -> CAcceptanceResult8616:
    """Run final validation, quality, and recompilation checks."""
    baseline_payload = payload if isinstance(payload, str) else ""
    if status != WorkItemStatus.OK.value:
        return _acceptance_result_8616(status, None, baseline_payload)
    if not baseline_payload.strip():
        return _acceptance_result_8616(
            WorkItemStatus.VALIDATION_FAILED,
            "No emitted C body.",
            baseline_payload,
        )

    accepted_payload = _normalize_accepted_payload_8616(baseline_payload)
    accepted_payload = _prune_invalid_simple_function_prototypes_text(accepted_payload)

    quality = assess_final_generated_c_text(accepted_payload)
    if quality.reject_as_decompiled:
        marker_summary = ", ".join(quality.markers[:3]) if quality.markers else "unresolved"
        if len(quality.markers) > 3:
            marker_summary += ", ..."
        return _validation_fail_8616(
            f"Final quality guard rejected emitted C ({marker_summary}).",
            tail_validation_snapshot,
            emit_failure_diagnostics,
            accepted_payload,
            baseline_payload,
        )
    if tail_validation_enabled and not _tail_validation_passes_lenient(
        tail_validation_snapshot, expected_stages=list(expected_validation_stages)
    ):
        display_status = _tail_validation_display_status(tail_validation_snapshot)
        detail = _tail_validation_stage_detail_8616(tail_validation_snapshot, expected_validation_stages)
        return _validation_fail_8616(
            f"Tail validation {display_status} ({detail}).",
            tail_validation_snapshot,
            emit_failure_diagnostics,
            accepted_payload,
            baseline_payload,
        )

    checked_payloads, recomp_failure = _collect_recompilation_payloads_8616(accepted_payload)
    recompile_fail_detail = _recompile_gate_fail_detail_8616(checked_payloads, recomp_failure)
    if recompile_fail_detail is not None:
        return _validation_fail_8616(
            recompile_fail_detail,
            tail_validation_snapshot,
            emit_failure_diagnostics,
            accepted_payload,
            baseline_payload,
        )

    reference_checked_payload = checked_payloads[0][1]
    validation_hash = _sha256_text_8616(accepted_payload)
    gcc_hash = _sha256_text_8616(reference_checked_payload)
    if gcc_hash != validation_hash:
        return _validation_fail_8616(
            "stale output mismatch: validated emitted C differs from gcc-checked C.",
            tail_validation_snapshot,
            emit_failure_diagnostics,
            accepted_payload,
            baseline_payload,
        )
    if _unreachable_calls_after_return_violation_8616(accepted_payload):
        return _validation_fail_8616(
            "Unreachable call statements present after return in emitted C.",
            tail_validation_snapshot,
            emit_failure_diagnostics,
            accepted_payload,
            baseline_payload,
        )
    ds_linear_macro_hits = _count_unresolved_ds_linear_macro_hits_8616(accepted_payload)
    if ds_linear_macro_hits >= 6:
        return _validation_fail_8616(
            f"Excess unresolved DS-linear macro accesses in emitted C (count={ds_linear_macro_hits}).",
            tail_validation_snapshot,
            emit_failure_diagnostics,
            accepted_payload,
            baseline_payload,
        )
    return CAcceptanceResult8616(
        status=WorkItemStatus.OK,
        blocker=None,
        validated_payload=accepted_payload,
        validated_payload_hash=validation_hash,
        gcc_checked_payload=reference_checked_payload,
        gcc_checked_payload_hash=gcc_hash,
    )


def _recompile_gate_fail_detail_8616(
    checked_payloads: list[tuple[str, str]] | tuple[tuple[str, str], ...],
    recomp_failure: str | None,
) -> str | None:
    """Return the first recompilation-gate fail detail, or None when accepted."""
    if recomp_failure is not None:
        return recomp_failure
    if not checked_payloads:
        return "No compiler succeeded; cannot establish recompilation identity."
    return _toolchain_identity_fail_detail_8616(checked_payloads, checked_payloads[0][0])


def _exe_addr_none_batch_gate_8616(args: CliArguments) -> bool:
    """Check the shared EXE batch-mode address gate."""
    return args.addr is None and args.binary.suffix.lower() == ".exe"


def _exe_unlabeled_batch_gate_8616(
    args: CliArguments, lst_metadata: object, visible_code_labels: object
) -> bool:
    """Check the batch-mode gate requiring EXE input, LST, and no visible labels."""
    return (
        _exe_addr_none_batch_gate_8616(args)
        and lst_metadata is not None
        and not visible_code_labels
    )


def _seeded_supplement_needed_8616(
    args: CliArguments,
    function_cfg_pairs: Sized | None,
    ranked_binary_offsets: Sized | None,
) -> bool:
    """Check whether seeded/ranked supplements are needed to reach the cap."""
    if args.max_functions <= 0 or not ranked_binary_offsets or not function_cfg_pairs:
        return False
    return cast(bool, len(function_cfg_pairs) < args.max_functions)


def _catalog_address_cache_storable_8616(project: angr.Project) -> bool:
    """Check whether catalog address evidence is absent or provably complete."""
    source_region_evidence = _source_region_catalog_evidence_8616(project)
    return source_region_evidence is None or source_region_evidence.complete


def _library_ranked_task_gate_8616(
    args: CliArguments,
    lst_metadata: object,
    visible_code_labels: object,
    include_library_functions: object,
    ranked_binary_offsets: object,
) -> bool:
    """Check the ranked-library task replacement gate for batch EXE mode."""
    if not _exe_unlabeled_batch_gate_8616(args, lst_metadata, visible_code_labels):
        return False
    return bool(include_library_functions and ranked_binary_offsets)


def _retry_gate_allows_candidate_8616(
    result: FunctionWorkResult,
    args: CliArguments,
    project: angr.Project,
    lst_metadata: object,
    cod_metadata: object,
) -> bool:
    """Check whether a failed result may retry with new sidecar evidence."""
    if result.status == "ok" or args.addr is not None:
        return False
    if getattr(project.arch, "name", "") != "86_16" or result.failure_stage == "sweep_budget":
        return False
    return cast(
        bool,
        result.retry_may_change_evidence(
            sidecar_available=lst_metadata is not None or cod_metadata is not None
        ),
    )


def _cacheable_direct_result_8616(result: FunctionWorkResult, integrity: AcceptedPayloadIntegrityVerdict8616) -> bool:
    """Check whether a direct result carries complete cacheable provenance."""
    if result.status != WorkItemStatus.OK.value or not isinstance(result.tail_validation, dict):
        return False
    if not isinstance(result.validated_payload_hash, str) or not isinstance(result.gcc_checked_payload_hash, str):
        return False
    return result.failure_family_snapshot is not None and integrity.passed


def _toolchain_identity_fail_detail_8616(
    checked_payloads: list[tuple[str, str]] | tuple[tuple[str, str], ...],
    reference_target: str,
) -> str | None:
    """Return a fail detail when toolchains disagree on the checked C identity."""
    reference_hash = _sha256_text_8616(checked_payloads[0][1])
    for target_name, target_checked_payload in checked_payloads[1:]:
        target_hash = _sha256_text_8616(target_checked_payload)
        if target_hash != reference_hash:
            return f"recompile identity mismatch across toolchains: {reference_target} and {target_name}"
    return None


def _dump_validation_failed_payload_8616(accepted_payload: str, baseline_payload: str) -> None:
    """Persist a validation-failed payload artifact for debugging."""
    dump_payload = accepted_payload if accepted_payload.strip() else baseline_payload
    if not dump_payload.strip():
        return
    try:
        import time
        from pathlib import Path

        root = Path("angr_platforms/.cache/validation_failed_payloads")
        root.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha1(dump_payload.encode("utf-8", errors="ignore")).hexdigest()[:12]
        stamp = int(time.time())
        out = root / f"payload_{stamp}_{digest}.c"
        out.write_text(dump_payload, encoding="utf-8")
        print(f"[tail-validation] failed payload artifact: {out}", file=sys.stderr)
    except Exception:
        return


def _validation_fail_8616(
    detail: str,
    tail_validation_snapshot: dict[str, object] | None,
    emit_failure_diagnostics: bool,
    accepted_payload: str,
    baseline_payload: str,
) -> CAcceptanceResult8616:
    """Record a validation failure and emit its diagnostics when enabled."""
    _mark_tail_validation_failed_with_blocker_8616(
        tail_validation_snapshot,
        detail,
        stage="postprocess",
    )
    if emit_failure_diagnostics:
        print("[tail-validation] whole-tail validation failed across 1 functions", file=sys.stderr)
        print(f"[tail-validation] acceptance-gate detail: {detail}", file=sys.stderr)
        _dump_validation_failed_payload_8616(accepted_payload, baseline_payload)
        sys.stderr.flush()
    return _acceptance_result_8616(WorkItemStatus.VALIDATION_FAILED, detail, accepted_payload)


def _accept_generated_c_for_emission_8616(
    *,
    payload: str,
    tail_validation_snapshot: dict[str, object] | None,
    project: angr.Project,
    emit_failure_diagnostics: bool = True,
) -> CAcceptanceResult8616:
    """Apply the canonical final contract to one generated-C emission candidate."""
    tail_validation_enabled = _tail_validation_runtime_enabled(project)
    expected_stages: tuple[str, ...] = (
        ("structuring", "postprocess") if tail_validation_enabled else ()
    )
    return _validated_generated_c_acceptance_8616(
        status=WorkItemStatus.OK.value,
        payload=payload,
        tail_validation_snapshot=tail_validation_snapshot,
        tail_validation_enabled=tail_validation_enabled,
        expected_validation_stages=expected_stages,
        c_target=getattr(project, "_inertia_c_target", "portable-flat"),
        emit_failure_diagnostics=emit_failure_diagnostics,
    )


def _accept_function_work_result_for_emission_8616(
    result: FunctionWorkResult,
    *,
    project: angr.Project,
) -> FunctionWorkResult:
    """Return a work result whose clean-success state has passed final acceptance."""
    if result.status != WorkItemStatus.OK.value:
        return result
    tail_snapshot = _tail_validation_snapshot_from_result_8616(result.tail_validation)
    acceptance = _accept_generated_c_for_emission_8616(
        payload=result.payload,
        tail_validation_snapshot=tail_snapshot,
        project=project,
    )
    if acceptance.status is WorkItemStatus.OK and acceptance.blocker is None:
        return replace(
            result,
            status=acceptance.status.value,
            payload=acceptance.gcc_checked_payload,
            validated_payload_hash=acceptance.validated_payload_hash,
            gcc_checked_payload_hash=acceptance.gcc_checked_payload_hash,
        )

    failed_snapshot = copy.deepcopy(tail_snapshot) if isinstance(tail_snapshot, dict) else {}
    blocker = acceptance.blocker or "Final generated-C acceptance failed."
    _mark_tail_validation_failed_with_blocker_8616(failed_snapshot, blocker)
    return replace(
        result,
        status=WorkItemStatus.VALIDATION_FAILED.value,
        payload=blocker,
        partial_payload=None,
        tail_validation=failed_snapshot,
        validated_payload_hash=None,
        gcc_checked_payload_hash=None,
    )


def _dump_validation_failed_payload_if_requested_8616(payload: str, *, prefix: str = "payload") -> None:
    if not _env_truthy_8616("INERTIA_DUMP_VALIDATION_FAILED_PAYLOAD"):
        return
    if not isinstance(payload, str) or not payload.strip():
        return
    try:
        root = Path("angr_platforms/.cache/validation_failed_payloads")
        root.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha1(payload.encode("utf-8", errors="ignore")).hexdigest()[:12]
        stamp = int(time.time())
        out = root / f"{prefix}_{stamp}_{digest}.c"
        out.write_text(payload, encoding="utf-8")
        print(f"[tail-validation] failed payload artifact: {out}", file=sys.stderr)
    except Exception:
        return


def _mark_tail_validation_failed_with_blocker_8616(
    snapshot: dict[str, object] | None,
    detail: str,
    *,
    stage: str = "postprocess",
) -> None:
    if not isinstance(snapshot, dict):
        return
    entry = snapshot.get(stage)
    if not isinstance(entry, dict):
        entry = {}
        snapshot[stage] = entry
    entry["changed"] = True
    entry["status"] = "changed"
    entry["mode"] = entry.get("mode", "live_out")
    entry["summary_text"] = str(detail)
    entry["verdict"] = f"{stage} whole-tail validation [live_out] changed: {detail}"


def _emit_failed_timeout_acceptance_hints_8616() -> None:
    # No static hints here: stale canned blockers are worse than an honest
    # timeout/validation detail. Real acceptance failures are emitted by
    # _validated_generated_c_acceptance_8616 with payload-specific evidence.
    return


@dataclass(frozen=True, slots=True)
class _PartialResultReport8616:
    """Describe CLI labels for an honest partial decompilation result."""

    status: WorkItemStatus
    heading: str
    direct_c_header: str
    sweep_c_header: str
    fallback_detail: str
    show_timeout_delay: bool


def _partial_result_report_8616(raw_status: str) -> _PartialResultReport8616:
    """Map a typed work-item status to non-semantic partial-output labels."""
    try:
        status = WorkItemStatus(raw_status)
    except ValueError:
        status = WorkItemStatus.UNKNOWN
    if status is WorkItemStatus.TIMEOUT:
        return _PartialResultReport8616(
            status=status,
            heading="Decompilation timeout",
            direct_c_header="\n/* == c (partial timeout) == */",
            sweep_c_header="/* -- c (partial timeout) -- */",
            fallback_detail="unavailable after partial timeout",
            show_timeout_delay=True,
        )
    if status is WorkItemStatus.VALIDATION_FAILED:
        return _PartialResultReport8616(
            status=status,
            heading="Decompilation validation_failed",
            direct_c_header="\n/* == c (partial validation failure) == */",
            sweep_c_header="/* -- c (partial validation failure) -- */",
            fallback_detail="unavailable after partial validation failure",
            show_timeout_delay=False,
        )
    partial_label = status.value.replace("_", " ")
    return _PartialResultReport8616(
        status=status,
        heading=f"Decompilation {status.value}",
        direct_c_header=f"\n/* == c (partial {partial_label}) == */",
        sweep_c_header=f"/* -- c (partial {partial_label}) -- */",
        fallback_detail=f"unavailable after partial {partial_label}",
        show_timeout_delay=False,
    )


_CALL_TOKEN_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_NON_EXECUTABLE_CALL_NAMES_8616 = frozenset({"if", "for", "while", "switch", "return", "sizeof"})
_SEG_DS_ACCESS_RE_8616 = re.compile(r"\b(?:SEG_PTR|MK_FP|SEG_U8|SEG_U16|SEG_U32)\s*\(\s*ds\s*,\s*([^)]+?)\s*\)")
_C_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_C_IDENT_RE_8616 = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
_C_ASSIGN_RE_8616 = re.compile(
    r"(?m)^\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+)*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*;"
)


def _strip_comment_blocks_8616(text: str) -> str:
    out = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    lines = []
    for line in out.splitlines():
        if line.lstrip().startswith("///"):
            continue
        lines.append(line)
    return "\n".join(lines)


def _non_probe_call_count_for_fallback_rank_8616(text: str) -> int:
    """Count already-emitted non-probe calls for CLI fallback candidate ranking."""
    body = _extract_function_body_text_8616(_strip_comment_blocks_8616(text))
    return sum(
        1
        for name in _CALL_TOKEN_RE.findall(body)
        if name not in _NON_EXECUTABLE_CALL_NAMES_8616 and not is_x86_16_stack_probe_name_8616(name)
    )


def _pointer_param_names_8616(text: str) -> set[str]:
    headers = re.findall(
        r"\b[A-Za-z_][A-Za-z0-9_\s\*]*\s+[A-Za-z_][A-Za-z0-9_]*\s*\(([^;{}]*)\)\s*\{",
        text,
        flags=re.DOTALL,
    )
    if not headers:
        return set()
    params = headers[-1]
    names: set[str] = set()
    for raw_param in params.split(","):
        token = raw_param.strip()
        if not token or token == "void" or "*" not in token:
            continue
        ident_match = _C_IDENT_RE_8616.findall(token)
        if ident_match:
            names.add(ident_match[-1])
    return names


def _count_unresolved_ds_linear_macro_hits_8616(payload: str) -> int:
    stripped_payload = _strip_comment_blocks_8616(payload)
    pointer_like = _pointer_param_names_8616(payload)
    # Track simple aliases of pointer parameters (e.g., bx = rhs; SEG_U8(ds, bx)).
    for lhs, rhs in _C_ASSIGN_RE_8616.findall(payload):
        if rhs in pointer_like:
            pointer_like.add(lhs)

    unresolved = len(re.findall(r"\bds\s*(?:<<\s*4|\*\s*16)", stripped_payload))
    for match in _SEG_DS_ACCESS_RE_8616.finditer(stripped_payload):
        offset = match.group(1).strip()
        base = offset
        if "+" in offset:
            left, right = [piece.strip() for piece in offset.split("+", 1)]
            if left.isdigit():
                base = right
            elif right.isdigit():
                base = left
        if base in pointer_like:
            continue
        if re.search(r"(?<![A-Za-z0-9_])(?:stack_base|sp|bp|s_[0-9a-fA-F]+|arg_[0-9a-fA-F]+)(?![A-Za-z0-9_])", offset):
            unresolved += 1
            continue
        if re.search(r"&\s*(?:s_[0-9a-fA-F]+|arg_[0-9a-fA-F]+)", offset):
            unresolved += 1
            continue
        # Constant/global DS helpers are the intended segmented-memory runtime
        # representation, not unresolved flattened linear addressing.
        continue
    return unresolved


def _extract_function_body_text_8616(emitted_c: str) -> str:
    clean = _strip_comment_blocks_8616(emitted_c)
    m = re.search(r"\{", clean)
    if m is None:
        return clean
    return clean[m.start() :]


def _ordered_call_names_from_text_8616(text: str) -> list[str]:
    if not isinstance(text, str) or not text:
        return []
    text = _strip_comment_blocks_8616(text)
    keywords = {"if", "for", "while", "switch", "return", "sizeof"}
    names, _end = _call_text_parse_until_8616(text, keywords, 0)
    return names


def _call_text_skip_string_8616(text: str, index: int, quote: str) -> int:
    """Advance past a quoted string literal in C text."""
    index += 1
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        if text[index] == quote:
            return index + 1
        index += 1
    return index


def _call_text_skip_ws_8616(text: str, index: int) -> int:
    """Advance past whitespace in C text."""
    while index < len(text) and text[index].isspace():
        index += 1
    return index


def _call_text_parse_until_8616(
    text: str, keywords: set[str], index: int, stop_char: str | None = None
) -> tuple[list[str], int]:
    """Collect call-like names until a matching delimiter is reached."""
    names: list[str] = []
    while index < len(text):
        ch = text[index]
        if stop_char is not None and ch == stop_char:
            return names, index + 1
        if ch in {'"', "'"}:
            index = _call_text_skip_string_8616(text, index, ch)
            continue
        if ch == "(":
            nested, index = _call_text_parse_until_8616(text, keywords, index + 1, ")")
            names.extend(nested)
            continue
        if ch == "_" or ch.isalpha():
            start = index
            index += 1
            while index < len(text) and (text[index] == "_" or text[index].isalnum()):
                index += 1
            raw_name = text[start:index]
            paren = _call_text_skip_ws_8616(text, index)
            if paren < len(text) and text[paren] == "(":
                nested, index = _call_text_parse_until_8616(text, keywords, paren + 1, ")")
                names.extend(nested)
                name = raw_name.lstrip("_")
                if name and name not in keywords:
                    names.append(name)
                continue
            continue
        index += 1
    return names, index


def _extract_emitted_function_name_8616(emitted_c: str) -> str | None:
    if not isinstance(emitted_c, str) or not emitted_c:
        return None
    header = emitted_c.split("{", 1)[0]
    m = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^()]*\)\s*$", header, flags=re.MULTILINE)
    if m is None:
        return None
    name = m.group(1)
    if name in {"if", "for", "while", "switch", "return"}:
        return None
    return name


def _unreachable_calls_after_return_violation_8616(emitted_c: str) -> bool:
    body = _extract_function_body_text_8616(_strip_comment_blocks_8616(emitted_c))
    if not isinstance(body, str) or not body.strip():
        return False
    depth = 0
    saw_top_level_return = False
    token_re = re.compile(r"\breturn\s*;|([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "/*", "*")):
            depth = max(0, depth + line.count("{") - line.count("}"))
            continue
        if depth == 0 and re.search(r"\breturn\s*;", line):
            saw_top_level_return = True
        elif depth == 0 and saw_top_level_return and _line_has_call_token_8616(token_re, line):
            return True
        depth = max(0, depth + line.count("{") - line.count("}"))
    return False


def _line_has_call_token_8616(token_re: re.Pattern[str], line: str) -> bool:
    """Check whether a line contains a non-keyword call token."""
    for match in token_re.finditer(line):
        name = match.group(1)
        if name is None or name in {"if", "for", "while", "switch", "return", "sizeof"}:
            continue
        return True
    return False


def _print_stop_on_first_failure_8616(function: object, result: FunctionWorkResult) -> None:
    display_addr = function_original_addr(function)
    print(
        f"/* stop: function {display_addr:#x} {getattr(function, 'name', 'sub')} "
        f"status={result.status} blocker={result.payload} */"
    )


def _emit_function_timing_summary(
    function_tasks: Sequence[FunctionWorkItem],
    result_map: Mapping[int, FunctionWorkResult],
    *,
    limit: int = 5,
) -> None:
    rows: list[tuple[float, int, int, str, str]] = []
    for item in function_tasks:
        result = result_map.get(item.index)
        if result is None:
            continue
        if result.from_cache:
            continue
        elapsed = result.elapsed
        if not isinstance(elapsed, (int, float)) or elapsed <= 0:
            continue
        display_status = _function_attempt_display_status(result)
        function = item.function
        rows.append(
            (
                float(elapsed),
                item.index,
                int(getattr(function, "addr", 0)),
                str(getattr(function, "name", "sub")),
                display_status,
            )
        )
    if not rows:
        return
    rows.sort(key=lambda row: (-row[0], row[1]))
    shown = rows[: max(1, limit)]
    print(f"/* summary: slowest function attempt(s), top {len(shown)}: */")
    for elapsed, _index, addr, name, status in shown:
        print(f"/* summary:   {addr:#x} {name}: {elapsed:.2f}s status={status} */")


def _helper_name(project: angr.Project, addr: int) -> str | None:
    proc = project.hooked_by(addr)
    if proc is None:
        return None
    name = getattr(proc, "INT_NAME", None)
    if isinstance(name, str) and name:
        return name
    name = getattr(proc, "display_name", None)
    if isinstance(name, str) and name:
        return name
    return str(proc.__class__.__name__)


def _iter_c_nodes(node: _StructuredCNode8616) -> Iterator[_StructuredCNode8616]:
    yield node
    if isinstance(node, structured_c.CStatements):
        for stmt in node.statements:
            yield from _iter_c_nodes(stmt)
        return
    yield from _iter_c_child_nodes_8616(node)


def _iter_c_child_nodes_8616(node: _StructuredCNode8616) -> Iterator[_StructuredCNode8616]:
    """Walk the generic structured-codegen child slots of one C node."""
    for attr in ("lhs", "rhs", "expr", "condition", "true_node", "false_node", "stmt", "callee_target"):
        if hasattr(node, attr):
            try:
                value = getattr(node, attr)
            except Exception:
                continue
            if _is_structured_codegen_node_8616(value):
                yield from _iter_c_nodes(value)
    if hasattr(node, "args"):
        try:
            args = node.args
        except Exception:
            args = None
        if args:
            for arg in args:
                if _is_structured_codegen_node_8616(arg):
                    yield from _iter_c_nodes(arg)


def _is_structured_codegen_node_8616(value: object) -> bool:
    """Check whether a child value lives in the structured-codegen module."""
    return value is not None and type(value).__module__.startswith(
        "angr.analyses.decompiler.structured_codegen"
    )


def _fork_unavailable_reason() -> str:
    live_threads = [
        thread.name
        for thread in threading.enumerate()
        if thread is not threading.current_thread() and thread.is_alive()
    ]
    if live_threads:
        return f"{len(live_threads)} live helper thread(s): {', '.join(live_threads[:4])}"
    return f"threading.active_count()={threading.active_count()}"


def _binary_evidence_recovery_snapshot_8616(reason: str) -> dict[str, object]:
    detail = f"validated binary instruction evidence recovery: {reason}"
    return {
        "structuring": {
            "status": "stable",
            "mode": "binary_evidence_recovery",
            "changed": False,
            "detail": detail,
        },
        "postprocess": {
            "status": "stable",
            "mode": "binary_evidence_recovery",
            "changed": False,
            "detail": detail,
        },
    }


def _recover_binary_evidence_c_8616(
    project: angr.Project,
    function: _AngrFunction,
) -> tuple[str | None, dict[str, object] | None]:
    recovered_loop_payload = recover_counted_stack_loop_c_8616(project, function)
    if isinstance(recovered_loop_payload, str) and recovered_loop_payload.strip():
        return recovered_loop_payload, _binary_evidence_recovery_snapshot_8616("counted stack-local loop")
    recovered_compare_payload = recover_32bit_compare_c_8616(project, function)
    if isinstance(recovered_compare_payload, str) and recovered_compare_payload.strip():
        return recovered_compare_payload, _binary_evidence_recovery_snapshot_8616("32-bit stack argument comparison")
    return None, None


def _remember_fallback_tail_validation(
    project: angr.Project,
    fallback_tail_validation_by_index: dict[int, dict[str, object]],
    item: FunctionWorkItem,
    *,
    function: _AngrFunction | None = None,
    allow_project_fallback: bool = True,
) -> dict[str, object]:
    target_function = function if function is not None else item.function
    snapshot = _tail_validation_snapshot_for_fallback(
        project,
        target_function,
        allow_project_fallback=allow_project_fallback,
    )
    fallback_tail_validation_by_index[item.index] = snapshot
    return dict(snapshot)


def _tail_validation_snapshot_from_result_8616(raw_tail_validation: object) -> dict[str, object]:
    if isinstance(raw_tail_validation, Mapping) and (
        "structuring" in raw_tail_validation or "postprocess" in raw_tail_validation
    ):
        return dict(raw_tail_validation)
    if not isinstance(raw_tail_validation, Mapping):
        return {}
    return dict(_extract_x86_16_tail_validation_snapshot(cast(Mapping[str, Any], raw_tail_validation)))


def _emit_sidecar_slice_tail_validation_snapshot_8616(
    function_cfg: object,
    function: object,
    snapshot: dict[str, object] | None,
    *,
    binary_path: Path | None,
) -> None:
    """Emit the validation snapshot produced by the accepted sidecar slice."""
    _emit_tail_validation_snapshot_or_uncollected(
        function_cfg,
        function,
        snapshot if isinstance(snapshot, dict) else None,
        binary_path=binary_path,
    )


def _retry_function_tail_validation_snapshot_8616(project: angr.Project, function: object) -> dict[str, object]:
    """Return the snapshot produced by a successful retry function.

    Project-level tail-validation state may still describe an earlier failed
    direct attempt.  Fallback/retry emission must validate against the function
    that produced the accepted payload before consulting that older project
    cache.
    """
    function_snapshot = _extract_x86_16_tail_validation_snapshot(getattr(function, "info", None))
    if function_snapshot:
        return dict(function_snapshot)
    project_snapshot = getattr(project, "_inertia_last_validated_function_payload_snapshot", None)
    if isinstance(project_snapshot, dict):
        return dict(project_snapshot)
    return dict(_tail_validation_snapshot_for_function_run(project, function))


def _fresh_sidecar_retry_work_item_8616(
    *,
    item: FunctionWorkItem,
    project: angr.Project,
    args: CliArguments,
    lst_metadata: LSTMetadata | None,
) -> FunctionWorkItem | None:
    if lst_metadata is None:
        return None
    if args.addr is not None:
        return None
    binary_path = Path(args.binary)
    if binary_path.suffix.lower() != ".exe":
        return None
    if getattr(getattr(project, "arch", None), "name", "") != "86_16":
        return None
    retry_without_rebased_exact_slice = getattr(item.function, "project", project) is not project
    source_addr = (
        function_original_addr(item.function)
        if retry_without_rebased_exact_slice
        else _function_work_item_recovery_addr_8616(item)
    )
    source_name = getattr(item.function, "name", None)
    if not isinstance(source_name, str) or not source_name:
        source_name = f"sub_{source_addr:x}"
    if not retry_without_rebased_exact_slice:
        source_addr, source_name = _canonicalize_sidecar_work_offset_8616(
            project,
            lst_metadata,
            source_addr,
            source_name,
        )
    if source_name is None:
        return None
    loader = getattr(project, "loader", None)
    main_object = getattr(loader, "main_object", None)
    linked_base = getattr(main_object, "linked_base", None)
    if not isinstance(linked_base, int):
        linked_base = 0
    fresh_project = _build_project(
        binary_path,
        force_blob=False,
        base_addr=linked_base,
        entry_point=getattr(project, "entry", linked_base),
    )
    _transfer_caller_return_use_evidence_8616(project, fresh_project)
    attach_lst_metadata_to_project(fresh_project, lst_metadata)
    _inherit_tail_validation_runtime_policy(fresh_project, project)
    typing.cast(typing.Any, fresh_project)._inertia_c_target = getattr(project, "_inertia_c_target", args.c_target)
    typing.cast(typing.Any, fresh_project)._inertia_trace_c_stages = args.trace_c_stages
    typing.cast(typing.Any, fresh_project)._inertia_dump_layers = args.dump_layers
    typing.cast(typing.Any, fresh_project)._inertia_dump_layer_root = args.dump_layer_dir
    typing.cast(typing.Any, fresh_project)._inertia_dump_layer_filter = args.dump_layer_filter
    cfg, function = _recover_lst_function(
        fresh_project,
        lst_metadata,
        source_addr if getattr(lst_metadata, "absolute_addrs", False) else source_addr - fresh_project.entry,
        source_name,
        timeout=max(1, min(args.timeout, 60)),
        window=args.window,
        low_memory=_prefer_low_memory_path(),
        allow_rebased_exact_slice=not retry_without_rebased_exact_slice,
    )
    if retry_without_rebased_exact_slice:
        typing.cast(typing.Any, fresh_project)._inertia_rebased_exact_slice_retry_disabled_8616 = True
    return FunctionWorkItem(
        index=item.index,
        function_cfg=cfg,
        function=function,
        recovery_addr=source_addr,
        retained_project=fresh_project,
    )


def _work_item_status_8616(status: str) -> WorkItemStatus:
    try:
        return WorkItemStatus(status)
    except (TypeError, ValueError):
        return WorkItemStatus.UNKNOWN


def _retry_timeout_for_failed_result_8616(
    result: FunctionWorkResult,
    args: CliArguments,
    *,
    timeout_was_explicit: bool,
) -> int:
    """Preserve measured clean-worker cost when budgeting a fallback retry."""
    timeout = retry_timeout_after_failed_attempt(
        args.timeout,
        elapsed_seconds=result.elapsed,
        timed_out=_work_item_status_8616(result.status) is WorkItemStatus.TIMEOUT,
        explicit_timeout=timeout_was_explicit,
    )
    return _enforce_function_timeout_cap(
        timeout,
        context="sweep retry recovered candidate decompile timeout",
        explicit_timeout_floor=args.timeout if timeout_was_explicit else None,
        default_timeout_cap=PARALLEL_CLEAN_WORKER_TIMEOUT_CAP,
    )


@dataclass(slots=True)
class _TimeoutDelayPrinter8616:
    """One-shot timeout delay line printer bound to a work result."""

    result: FunctionWorkResult
    printed: bool = False

    def __call__(self) -> None:
        """Print the timeout delay line once for timeout results."""
        if self.printed or self.result.status != "timeout":
            return
        elapsed = self.result.elapsed
        if isinstance(elapsed, (int, float)) and elapsed >= 0:
            print(f"/* timeout delay: {float(elapsed):.2f}s */")
            self.printed = True


@dataclass(frozen=True, slots=True)
class _OkEmitOutcome8616:
    """Outcome of the ok-status emission lane."""

    early_counters: tuple[int, int] | None
    result: FunctionWorkResult
    attempt_status_printed: bool
    emitted_problem: bool


def _retry_work_item_8616(item: FunctionWorkItem, result: FunctionWorkResult) -> FunctionWorkItem:
    """Prefer the result's recovered function/CFG for retry lanes when present."""
    if result.function is not None and result.function_cfg is not None:
        return FunctionWorkItem(
            index=item.index,
            function_cfg=result.function_cfg,
            function=result.function,
            recovery_addr=item.recovery_addr,
        )
    return item


def _emit_retry_gate_candidate_8616(
    result: FunctionWorkResult,
    args: CliArguments,
    project: angr.Project,
    lst_metadata: LSTMetadata | None,
    cod_metadata: CODProcMetadata | None,
    retry_item: FunctionWorkItem,
    function: _AngrFunction,
    synthetic_globals: _SyntheticGlobals8616,
    timeout_was_explicit: bool,
    fallback_tail_validation_by_index: dict[int, dict[str, object]],
    result_state_by_index: dict[int, FunctionWorkResult] | None,
) -> bool:
    """Run the pre-emission retry lane when its gate allows a candidate."""
    if not _retry_gate_allows_candidate_8616(result, args, project, lst_metadata, cod_metadata):
        return False
    return _try_emit_retry_recovered_candidate_8616(
        item=retry_item,
        function=function,
        project=project,
        args=args,
        lst_metadata=lst_metadata,
        cod_metadata=cod_metadata,
        synthetic_globals=synthetic_globals,
        retry_timeout=_retry_timeout_for_failed_result_8616(
            result,
            args,
            timeout_was_explicit=timeout_was_explicit,
        ),
        fallback_tail_validation_by_index=fallback_tail_validation_by_index,
        result_state_by_index=result_state_by_index,
    )


def _validation_failed_retry_gate_8616(
    args: CliArguments,
    project: angr.Project,
    result: FunctionWorkResult,
    lst_metadata: LSTMetadata | None,
    cod_metadata: CODProcMetadata | None,
) -> bool:
    """Allow a post-validation retry only for evidence-mutating sweep lanes."""
    return (
        args.addr is None
        and getattr(project.arch, "name", "") == "86_16"
        and result.failure_stage != "sweep_budget"
        and result.retry_may_change_evidence(
            sidecar_available=lst_metadata is not None or cod_metadata is not None
        )
    )


def _emit_ok_result_8616(
    *,
    result: FunctionWorkResult,
    function: _AngrFunction,
    retry_item: FunctionWorkItem,
    args: CliArguments,
    project: angr.Project,
    lst_metadata: LSTMetadata | None,
    cod_metadata: CODProcMetadata | None,
    synthetic_globals: _SyntheticGlobals8616,
    result_tail_validation: dict[str, object],
    timeout_was_explicit: bool,
    fallback_tail_validation_by_index: dict[int, dict[str, object]],
    result_state_by_index: dict[int, FunctionWorkResult] | None,
) -> _OkEmitOutcome8616:
    """Emit an ok-status result or route its failed validation to retry."""
    payload_text = result.payload if isinstance(result.payload, str) else ""
    normalized_payload_text = _normalize_accepted_payload_8616(payload_text)
    if normalized_payload_text != payload_text:
        result = replace(result, payload=normalized_payload_text)
    if not _tail_validation_runtime_enabled(project) or x86_16_tail_validation_snapshot_passed(
        result_tail_validation
    ):
        _print_function_attempt_status(
            function,
            attempt="decompiled",
            validation_snapshot=result_tail_validation,
        )
        if args.output_c_dir is not None:
            write_generated_function_c(
                args.output_c_dir,
                address=function_original_addr(function),
                name=function.name,
                payload=result.payload,
            )
        if args.addr is not None:
            _emit_optional_source_sidecar_c_block(
                args.binary,
                function.name,
                result.payload,
                alternate_source_c=bool(args.alternate_source_c),
                c_header="/* -- c -- */",
            )
        return _OkEmitOutcome8616(
            early_counters=(1, 0),
            result=result,
            attempt_status_printed=False,
            emitted_problem=False,
        )
    validation_status = _tail_validation_display_status(result_tail_validation)
    print("/* problem: validation=failed */")
    for _diag_line in _format_tail_validation_diagnostic(
        result_tail_validation,
        function_addr=function.addr,
        function_name=function.name,
        block_count=result.block_count,
        byte_count=result.byte_count,
        exit_kind=result.status,
        exit_detail=f"tail-validation status={validation_status}",
    ):
        print(_diag_line)
    _print_function_attempt_status(
        function,
        attempt="decompiled",
        validation_snapshot=result_tail_validation,
    )
    print("/* decompiled output failed tail-validation; trying fallback lanes */")
    if _validation_failed_retry_gate_8616(
        args, project, result, lst_metadata, cod_metadata
    ) and _try_emit_retry_recovered_candidate_8616(
        item=retry_item,
        function=function,
        project=project,
        args=args,
        lst_metadata=lst_metadata,
        cod_metadata=cod_metadata,
        synthetic_globals=synthetic_globals,
        retry_timeout=_retry_timeout_for_failed_result_8616(
            result,
            args,
            timeout_was_explicit=timeout_was_explicit,
        ),
        fallback_tail_validation_by_index=fallback_tail_validation_by_index,
        result_state_by_index=result_state_by_index,
    ):
        return _OkEmitOutcome8616(
            early_counters=(1, 0),
            result=result,
            attempt_status_printed=True,
            emitted_problem=True,
        )
    return _OkEmitOutcome8616(
        early_counters=None,
        result=result,
        attempt_status_printed=True,
        emitted_problem=True,
    )


def _emit_partial_payload_block_8616(
    result: FunctionWorkResult,
    function: _AngrFunction,
    args: CliArguments,
    emit_timeout_delay_line: Callable[[], None],
) -> None:
    """Emit the partial-payload lane for a failed result."""
    partial_report = _partial_result_report_8616(result.status)
    _print_function_attempt_status(
        function,
        attempt=_function_attempt_display_status(result),
        validation_snapshot=result.tail_validation,
    )
    print(f"/* problem: {result.status} */")
    _print_diagnostic_text(result.payload)
    if partial_report.show_timeout_delay:
        emit_timeout_delay_line()
    _emit_optional_source_sidecar_c_block(
        args.binary,
        function.name,
        result.partial_payload,
        alternate_source_c=bool(args.alternate_source_c),
        c_header=partial_report.sweep_c_header,
    )


def _emit_function_result(
    item: FunctionWorkItem,
    result: FunctionWorkResult,
    *,
    project: angr.Project,
    args: CliArguments,
    lst_metadata: LSTMetadata | None,
    cod_metadata: CODProcMetadata | None,
    synthetic_globals: _SyntheticGlobals8616,
    precise_sidecar_regions: bool,
    allow_heavy_fallbacks: bool,
    interactive_stdout: bool,
    use_serial_fork_per_function: bool,
    fallback_tail_validation_by_index: dict[int, dict[str, object]],
    result_state_by_index: dict[int, FunctionWorkResult] | None = None,
    timeout_was_explicit: bool = False,
) -> tuple[int, int]:
    def _impl() -> tuple[int, int]:
        nonlocal result
        result = _accept_function_work_result_for_emission_8616(result, project=project)
        if result_state_by_index is not None:
            result_state_by_index[item.index] = result
        result_tail_validation = _tail_validation_snapshot_from_result_8616(result.tail_validation)
        decompiled_local = 0
        failed_local = 0
        attempt_status_printed = False
        _emit_timeout_delay_line = _TimeoutDelayPrinter8616(result)

        if result.debug_output:
            print(result.debug_output, end="" if result.debug_output.endswith("\n") else "\n", file=sys.stderr)
        function: _AngrFunction = item.function
        print(f"\n/* == function {function.addr:#x} {function.name} == */")
        if result.failure_stage:
            print(f"/* stage: {result.failure_stage} */")
        failure_family_snapshot = build_failure_family_snapshot(
            status=result.status,
            failure_stage=result.failure_stage,
            fallback_kind="file_sweep",
            tail_validation_verdict=_tail_validation_display_status(
                result_tail_validation,
                fallback_kind="file_sweep" if result.status != "ok" else None,
            ),
            artifact_path=f"{function.addr:#x}:{function.name}",
        )
        print(f"/* failure family: {failure_family_snapshot.label()} */")
        retry_item = _retry_work_item_8616(item, result)
        if _emit_retry_gate_candidate_8616(
            result,
            args,
            project,
            lst_metadata,
            cod_metadata,
            retry_item,
            function,
            synthetic_globals,
            timeout_was_explicit,
            fallback_tail_validation_by_index,
            result_state_by_index,
        ):
            return 1, 0
        if args.show_asm:
            print("/* -- asm -- */")
            print(_format_first_block_asm(project, function.addr))
        emitted_problem = False
        if result.status == "ok":
            ok_outcome = _emit_ok_result_8616(
                result=result,
                function=function,
                retry_item=retry_item,
                args=args,
                project=project,
                lst_metadata=lst_metadata,
                cod_metadata=cod_metadata,
                synthetic_globals=synthetic_globals,
                result_tail_validation=result_tail_validation,
                timeout_was_explicit=timeout_was_explicit,
                fallback_tail_validation_by_index=fallback_tail_validation_by_index,
                result_state_by_index=result_state_by_index,
            )
            if ok_outcome.early_counters is not None:
                return ok_outcome.early_counters
            result = ok_outcome.result
            attempt_status_printed = ok_outcome.attempt_status_printed
            emitted_problem = ok_outcome.emitted_problem

        if result.partial_payload:
            _emit_partial_payload_block_8616(result, function, args, _emit_timeout_delay_line)
            attempt_status_printed = True
            emitted_problem = True

        return _emit_function_result_fallback_lanes_8616(
            item=item,
            result=result,
            project=project,
            args=args,
            lst_metadata=lst_metadata,
            cod_metadata=cod_metadata,
            precise_sidecar_regions=precise_sidecar_regions,
            allow_heavy_fallbacks=allow_heavy_fallbacks,
            interactive_stdout=interactive_stdout,
            use_serial_fork_per_function=use_serial_fork_per_function,
            fallback_tail_validation_by_index=fallback_tail_validation_by_index,
            decompiled_local=decompiled_local,
            failed_local=failed_local,
            attempt_status_printed=attempt_status_printed,
            emitted_problem=emitted_problem,
            emit_timeout_delay_line=_emit_timeout_delay_line,
        )

    return _impl()


def _try_emit_retry_recovered_candidate_8616(
    *,
    item: FunctionWorkItem,
    function: _AngrFunction,
    project: angr.Project,
    args: CliArguments,
    lst_metadata: LSTMetadata | None,
    cod_metadata: CODProcMetadata | None,
    synthetic_globals: _SyntheticGlobals8616,
    retry_timeout: int | None = None,
    fallback_tail_validation_by_index: dict[int, dict[str, object]] | None = None,
    result_state_by_index: dict[int, FunctionWorkResult] | None = None,
) -> bool:
    """Try one fresh-project retry and retain only validated, compilable C."""
    try:
        if retry_timeout is None:
            retry_timeout = max(1, int(args.timeout)) if isinstance(args.timeout, int) else 120

        def _run_retry_candidate() -> FunctionWorkResult:
            retry_item = _fresh_sidecar_retry_work_item_8616(
                item=item,
                project=project,
                args=args,
                lst_metadata=lst_metadata,
            )
            if retry_item is None:
                retry_item = item
            return _run_function_work_item(
                retry_item,
                timeout=retry_timeout,
                api_style=args.api_style,
                binary_path=args.binary,
                lst_metadata=lst_metadata,
                cod_metadata=cod_metadata,
                synthetic_globals=synthetic_globals,
                enable_structured_simplify=True,
                enable_postprocess=True,
                allow_isolated_retry=False,
            )

        retry_worker_timeout = _enforce_function_timeout_cap(
            max(1, retry_timeout + 2),
            context="sweep retry recovered candidate timeout",
        )
        if _direct_addr_use_fork_lane_8616(
            tail_validation_enabled=_tail_validation_runtime_enabled(project),
        ):
            retry_result = _run_with_timeout_in_fork(
                    lambda: _function_work_result_for_fork_ipc(_run_retry_candidate()),
                    timeout=retry_worker_timeout,
                )
        else:
            retry_result = _run_with_timeout_in_daemon_thread(
                    _run_retry_candidate,
                    timeout=retry_worker_timeout,
                    thread_name_prefix="retry-recovered-candidate",
                )
        retry_result = _accept_function_work_result_for_emission_8616(retry_result, project=project)
        retry_result, retry_tv, retry_has_payload = _retry_clean_process_fallback_8616(
            retry_result, item, function, project, args, lst_metadata, retry_timeout
        )
        if retry_result.status != "ok" or not x86_16_tail_validation_snapshot_passed(retry_tv) or not retry_has_payload:
            return False
        _record_retry_success_8616(
            retry_result,
            retry_tv,
            item,
            function,
            args,
            fallback_tail_validation_by_index,
            result_state_by_index,
        )
        return True
    except (FuturesTimeoutError, TimeoutError):
        return False
    except Exception as ex:
        print(
            f"[dbg] retry recovered candidate failed for {function.addr:#x} {function.name}: "
            f"{type(ex).__name__}: {ex}",
            file=sys.stderr,
        )
        return False


def _retry_clean_process_fallback_8616(
    retry_result: FunctionWorkResult,
    item: FunctionWorkItem,
    function: _AngrFunction,
    project: angr.Project,
    args: CliArguments,
    lst_metadata: LSTMetadata | None,
    retry_timeout: int,
) -> tuple[FunctionWorkResult, dict[str, object], bool]:
    """Re-run a rejected retry through the clean-process worker lane."""
    retry_tv = _tail_validation_snapshot_from_result_8616(retry_result.tail_validation)
    retry_has_payload = isinstance(retry_result.payload, str) and bool(retry_result.payload.strip())
    if (
        (retry_result.status != "ok" or not x86_16_tail_validation_snapshot_passed(retry_tv))
        and project.arch.name == "86_16"
    ):
        clean_item = FunctionWorkItem(
            index=item.index,
            function_cfg=item.function_cfg,
            function=function,
            recovery_addr=function_original_addr(function),
        )
        clean_context = cast(
            "_BatchCliContext8616",
            SimpleNamespace(args=args, project=project, lst_metadata=lst_metadata),
        )
        retry_result = _run_serial_clean_process_work_item_8616(
            clean_context,
            clean_item,
            timeout=retry_timeout,
            caller_return_evidence_by_addr=caller_return_use_evidence_by_addr_8616(project),
        )
        retry_result = _accept_function_work_result_for_emission_8616(retry_result, project=project)
        retry_tv = _tail_validation_snapshot_from_result_8616(retry_result.tail_validation)
        retry_has_payload = isinstance(retry_result.payload, str) and bool(retry_result.payload.strip())
    return retry_result, retry_tv, retry_has_payload


def _record_retry_success_8616(
    retry_result: FunctionWorkResult,
    retry_tv: dict[str, object],
    item: FunctionWorkItem,
    function: _AngrFunction,
    args: CliArguments,
    fallback_tail_validation_by_index: dict[int, dict[str, object]] | None,
    result_state_by_index: dict[int, FunctionWorkResult] | None,
) -> None:
    """Record and emit one validated retry-recovered candidate."""
    retry_payload = retry_result.payload
    if fallback_tail_validation_by_index is not None:
        fallback_tail_validation_by_index[item.index] = dict(retry_tv)
    if result_state_by_index is not None:
        result_state_by_index[item.index] = replace(
            retry_result,
            payload=retry_payload,
            tail_validation=dict(retry_tv),
        )
    print("/* retry lane: recovered validation-passed candidate */")
    _print_function_attempt_status(
        function,
        attempt="decompiled",
        validation_snapshot=retry_tv,
    )
    if args.output_c_dir is not None:
        write_generated_function_c(
            args.output_c_dir,
            address=function_original_addr(function),
            name=function.name,
            payload=retry_payload,
        )
    _emit_optional_source_sidecar_c_block(
        args.binary,
        function.name,
        retry_payload,
        alternate_source_c=bool(args.alternate_source_c),
        c_header="/* -- c -- */",
    )


def _emit_function_result_fallback_lanes_8616(
    *,
    item: FunctionWorkItem,
    result: FunctionWorkResult,
    project: angr.Project,
    args: CliArguments,
    lst_metadata: LSTMetadata | None,
    cod_metadata: CODProcMetadata | None,
    precise_sidecar_regions: bool,
    allow_heavy_fallbacks: bool,
    interactive_stdout: bool,
    use_serial_fork_per_function: bool,
    fallback_tail_validation_by_index: dict[int, dict[str, object]],
    decompiled_local: int,
    failed_local: int,
    attempt_status_printed: bool,
    emitted_problem: bool,
    emit_timeout_delay_line: Callable[[], None],
) -> tuple[int, int]:
    def _impl() -> tuple[int, int]:
        nonlocal decompiled_local, failed_local, attempt_status_printed, emitted_problem
        function: _AngrFunction = item.function
        skip_heavy_fallbacks_for_result = result.skip_heavy_fallbacks
        slice_result, slice_counters = _sidecar_slice_fallback_8616(
            item=item,
            result=result,
            function=function,
            project=project,
            args=args,
            lst_metadata=lst_metadata,
            precise_sidecar_regions=precise_sidecar_regions,
            allow_heavy_fallbacks=allow_heavy_fallbacks,
            skip_heavy_fallbacks_for_result=skip_heavy_fallbacks_for_result,
            fallback_tail_validation_by_index=fallback_tail_validation_by_index,
            decompiled_local=decompiled_local,
            failed_local=failed_local,
        )
        if slice_counters is not None:
            return slice_counters
        function_project = getattr(function, "project", project)
        using_rebased_function_slice = function_project is not project
        function_lst_metadata = None if using_rebased_function_slice else lst_metadata
        known_nonopt_c, known_counters = _known_nonopt_fallback_8616(
            item=item,
            result=result,
            function=function,
            function_project=function_project,
            function_lst_metadata=function_lst_metadata,
            args=args,
            project=project,
            cod_metadata=cod_metadata,
            fallback_tail_validation_by_index=fallback_tail_validation_by_index,
            emitted_problem=emitted_problem,
            emit_timeout_delay_line=emit_timeout_delay_line,
            decompiled_local=decompiled_local,
            failed_local=failed_local,
        )
        if known_counters is not None:
            return known_counters

        if not allow_heavy_fallbacks or skip_heavy_fallbacks_for_result:
            return _emit_function_result_light_fallback_8616(
                item=item,
                result=result,
                project=project,
                args=args,
                lst_metadata=lst_metadata,
                cod_metadata=cod_metadata,
                allow_heavy_fallbacks=allow_heavy_fallbacks,
                skip_heavy_fallbacks_for_result=skip_heavy_fallbacks_for_result,
                interactive_stdout=interactive_stdout,
                fallback_tail_validation_by_index=fallback_tail_validation_by_index,
                decompiled_local=decompiled_local,
                failed_local=failed_local,
                attempt_status_printed=attempt_status_printed,
                emitted_problem=emitted_problem,
                emit_timeout_delay_line=emit_timeout_delay_line,
            )

        trivial_counters = _trivial_sidecar_fallback_8616(
            item=item,
            result=result,
            function=function,
            project=project,
            args=args,
            lst_metadata=lst_metadata,
            fallback_tail_validation_by_index=fallback_tail_validation_by_index,
            decompiled_local=decompiled_local,
            failed_local=failed_local,
        )
        if trivial_counters is not None:
            return trivial_counters

        nonopt_result: NonOptimizedSliceOutcome | str | None = None
        if _nonopt_slice_gate_8616(result, precise_sidecar_regions, args, known_nonopt_c, slice_result):
            nonopt_result = _run_nonopt_slice_lane_8616(
                function_project=function_project,
                using_rebased_function_slice=using_rebased_function_slice,
                project=project,
                function=function,
                args=args,
                function_lst_metadata=function_lst_metadata,
                cod_metadata=cod_metadata,
                use_serial_fork_per_function=use_serial_fork_per_function,
            )
        closed_sidecar_verdict = slice_result.verdict if slice_result is not None else None
        if closed_sidecar_verdict is not None and sidecar_verdict_closes_non_optimized_lane(closed_sidecar_verdict):
            print(
                "/* non-optimized fallback unavailable: "
                f"sidecar slice already closed the lane ({closed_sidecar_verdict.stage}:{closed_sidecar_verdict.stop_family}) */"
            )
        nonopt_counters = _emit_nonopt_acceptance_8616(
            nonopt_result=nonopt_result,
            item=item,
            result=result,
            function=function,
            project=project,
            args=args,
            fallback_tail_validation_by_index=fallback_tail_validation_by_index,
            emitted_problem=emitted_problem,
            emit_timeout_delay_line=emit_timeout_delay_line,
            decompiled_local=decompiled_local,
            failed_local=failed_local,
        )
        if nonopt_counters is not None:
            return nonopt_counters

        return _emit_string_or_asm_fallback_8616(
            item=item,
            result=result,
            project=project,
            args=args,
            lst_metadata=lst_metadata,
            fallback_tail_validation_by_index=fallback_tail_validation_by_index,
            skip_heavy_fallbacks_for_result=skip_heavy_fallbacks_for_result,
            allow_heavy_fallbacks=allow_heavy_fallbacks,
            interactive_stdout=interactive_stdout,
            emitted_problem=emitted_problem,
            attempt_status_printed=attempt_status_printed,
            decompiled_local=decompiled_local,
            failed_local=failed_local,
            nonopt_result=nonopt_result,
            emit_timeout_delay_line=emit_timeout_delay_line,
        )

    return _impl()


def _copy_function_project_tv_attrs_8616(function_project: object, project: angr.Project) -> None:
    """Copy tail-validation snapshots from a rebased function project."""
    if function_project is project:
        return
    for attr_name in (
        "_inertia_partial_tail_validation_snapshot",
        "_inertia_last_tail_validation_snapshot",
    ):
        attr_value = getattr(function_project, attr_name, None)
        if isinstance(attr_value, dict):
            setattr(project, attr_name, dict(attr_value))


def _sidecar_slice_fallback_8616(
    *,
    item: FunctionWorkItem,
    result: FunctionWorkResult,
    function: _AngrFunction,
    project: angr.Project,
    args: CliArguments,
    lst_metadata: LSTMetadata | None,
    precise_sidecar_regions: bool,
    allow_heavy_fallbacks: bool,
    skip_heavy_fallbacks_for_result: bool,
    fallback_tail_validation_by_index: dict[int, dict[str, object]],
    decompiled_local: int,
    failed_local: int,
) -> tuple[SliceRecoveryAttemptOutcome | None, tuple[int, int] | None]:
    """Try the sidecar-slice fallback lane and its acceptance gate."""
    slice_result: SliceRecoveryAttemptOutcome | None = None
    if allow_heavy_fallbacks and precise_sidecar_regions and not skip_heavy_fallbacks_for_result:
        slice_result = _try_decompile_sidecar_slice(
            project,
            lst_metadata,
            function.addr,
            function.name,
            timeout=args.timeout,
            api_style=args.api_style,
            binary_path=args.binary,
        )
    if slice_result is None or slice_result.status != "ok":
        return slice_result, None
    fallback_snapshot = _remember_fallback_tail_validation(
        project,
        fallback_tail_validation_by_index,
        item,
        allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("sidecar_slice"),
    )
    fallback_acceptance = _accept_generated_c_for_emission_8616(
        payload=slice_result.payload,
        tail_validation_snapshot=fallback_snapshot,
        project=project,
    )
    if fallback_acceptance.status is WorkItemStatus.OK and fallback_acceptance.blocker is None:
        _print_function_attempt_status(function, attempt="fallback", validation_snapshot=fallback_snapshot)
        _emit_optional_source_sidecar_c_block(
            args.binary,
            function.name,
            fallback_acceptance.gcc_checked_payload,
            alternate_source_c=bool(args.alternate_source_c),
            c_header="/* -- c (sidecar slice fallback) -- */",
        )
        return slice_result, (decompiled_local + 1, failed_local)
    _print_function_attempt_status(function, attempt="fallback", validation_snapshot=fallback_snapshot)
    print("/* problem: validation=failed */")
    for _diag_line in _format_tail_validation_diagnostic(
        fallback_snapshot,
        function_addr=function.addr,
        function_name=function.name,
        block_count=result.block_count,
        byte_count=result.byte_count,
        exit_kind="fallback",
        exit_detail=fallback_acceptance.blocker or "sidecar slice fallback not semantically stable",
    ):
        print(_diag_line)
    return slice_result, None


def _known_nonopt_fallback_8616(
    *,
    item: FunctionWorkItem,
    result: FunctionWorkResult,
    function: _AngrFunction,
    function_project: object,
    function_lst_metadata: LSTMetadata | None,
    args: CliArguments,
    project: angr.Project,
    cod_metadata: CODProcMetadata | None,
    fallback_tail_validation_by_index: dict[int, dict[str, object]],
    emitted_problem: bool,
    emit_timeout_delay_line: Callable[[], None],
    decompiled_local: int,
    failed_local: int,
) -> tuple[str | None, tuple[int, int] | None]:
    """Try the non-optimized known-function fallback lane."""
    if result.partial_payload is not None:
        return None, None
    known_nonopt_result = _try_decompile_non_optimized_known_function(
        function_project,
        item.function_cfg,
        function,
        timeout=_bounded_non_optimized_timeout(args.timeout),
        api_style=args.api_style,
        binary_path=args.binary,
        lst_metadata=function_lst_metadata,
        cod_metadata=cod_metadata,
    )
    _copy_function_project_tv_attrs_8616(function_project, project)
    known_nonopt_c = _non_optimized_slice_rendered(known_nonopt_result)
    if known_nonopt_c is None:
        return None, None
    fallback_snapshot = _remember_fallback_tail_validation(
        project,
        fallback_tail_validation_by_index,
        item,
        function=function,
        allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
    )
    _print_function_attempt_status(function, attempt="fallback", validation_snapshot=fallback_snapshot)
    fallback_acceptance = _accept_generated_c_for_emission_8616(
        payload=known_nonopt_c,
        tail_validation_snapshot=fallback_snapshot,
        project=project,
    )
    if fallback_acceptance.status is not WorkItemStatus.OK or fallback_acceptance.blocker is not None:
        print("/* problem: validation=failed */")
        for _diag_line in _format_tail_validation_diagnostic(
            fallback_snapshot,
            function_addr=function.addr,
            function_name=function.name,
            block_count=result.block_count,
            byte_count=result.byte_count,
            exit_kind="fallback",
            exit_detail=(
                fallback_acceptance.blocker
                or "non-optimized known-function fallback not semantically stable"
            ),
        ):
            print(_diag_line)
        return None, None
    if not emitted_problem:
        print(f"/* problem: {result.status} */")
        _print_diagnostic_text(result.payload)
        emit_timeout_delay_line()
    _emit_optional_source_sidecar_c_block(
        args.binary,
        function.name,
        fallback_acceptance.gcc_checked_payload,
        alternate_source_c=bool(args.alternate_source_c),
        c_header="/* -- c (non-optimized fallback) -- */",
    )
    return None, (decompiled_local + 1, failed_local)


def _trivial_sidecar_fallback_8616(
    *,
    item: FunctionWorkItem,
    result: FunctionWorkResult,
    function: _AngrFunction,
    project: angr.Project,
    args: CliArguments,
    lst_metadata: LSTMetadata | None,
    fallback_tail_validation_by_index: dict[int, dict[str, object]],
    decompiled_local: int,
    failed_local: int,
) -> tuple[int, int] | None:
    """Try the trivial sidecar fallback lane and its acceptance gate."""
    trivial_c = _try_emit_trivial_sidecar_c(project, lst_metadata, function.addr, function.name)
    if trivial_c is None:
        return None
    fallback_snapshot = _remember_fallback_tail_validation(
        project,
        fallback_tail_validation_by_index,
        item,
        allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("trivial_sidecar"),
    )
    fallback_acceptance = _accept_generated_c_for_emission_8616(
        payload=trivial_c,
        tail_validation_snapshot=fallback_snapshot,
        project=project,
    )
    if fallback_acceptance.status is WorkItemStatus.OK and fallback_acceptance.blocker is None:
        _print_function_attempt_status(function, attempt="fallback", validation_snapshot=fallback_snapshot)
        _emit_optional_source_sidecar_c_block(
            args.binary,
            function.name,
            fallback_acceptance.gcc_checked_payload,
            alternate_source_c=bool(args.alternate_source_c),
            c_header="/* -- c (trivial sidecar fallback) -- */",
        )
        return decompiled_local + 1, failed_local
    print("/* problem: validation=failed */")
    _print_diagnostic_text(
        fallback_acceptance.blocker or "Trivial sidecar fallback failed final acceptance."
    )
    return None


def _nonopt_slice_gate_8616(
    result: FunctionWorkResult,
    precise_sidecar_regions: bool,
    args: CliArguments,
    known_nonopt_c: str | None,
    slice_result: SliceRecoveryAttemptOutcome | None,
) -> bool:
    """Gate the non-optimized slice lane on remaining fallback eligibility."""
    return (
        result.partial_payload is None
        and (precise_sidecar_regions or args.addr is not None)
        and known_nonopt_c is None
        and not sidecar_verdict_closes_non_optimized_lane(
            slice_result.verdict if slice_result is not None else None
        )
    )


def _run_nonopt_slice_lane_8616(
    *,
    function_project: object,
    using_rebased_function_slice: bool,
    project: angr.Project,
    function: _AngrFunction,
    args: CliArguments,
    function_lst_metadata: LSTMetadata | None,
    cod_metadata: CODProcMetadata | None,
    use_serial_fork_per_function: bool,
) -> NonOptimizedSliceOutcome | str | None:
    """Run the non-optimized slice fallback attempt."""
    nonopt_result = _try_decompile_non_optimized_slice(
        function_project if using_rebased_function_slice else project,
        function.addr,
        function.name,
        timeout=_bounded_non_optimized_timeout(args.timeout),
        api_style=args.api_style,
        binary_path=args.binary,
        lst_metadata=function_lst_metadata,
        cod_metadata=cod_metadata,
        allow_fresh_project_retry=not use_serial_fork_per_function,
    )
    _copy_function_project_tv_attrs_8616(function_project, project)
    return nonopt_result


def _emit_nonopt_acceptance_8616(
    *,
    nonopt_result: NonOptimizedSliceOutcome | str | None,
    item: FunctionWorkItem,
    result: FunctionWorkResult,
    function: _AngrFunction,
    project: angr.Project,
    args: CliArguments,
    fallback_tail_validation_by_index: dict[int, dict[str, object]],
    emitted_problem: bool,
    emit_timeout_delay_line: Callable[[], None],
    decompiled_local: int,
    failed_local: int,
) -> tuple[int, int] | None:
    """Accept and emit a rendered non-optimized slice candidate."""
    nonopt_c = _non_optimized_slice_rendered(nonopt_result)
    if nonopt_c is None:
        return None
    fallback_snapshot = _remember_fallback_tail_validation(
        project,
        fallback_tail_validation_by_index,
        item,
        allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
    )
    _print_function_attempt_status(function, attempt="fallback", validation_snapshot=fallback_snapshot)
    fallback_acceptance = _accept_generated_c_for_emission_8616(
        payload=nonopt_c,
        tail_validation_snapshot=fallback_snapshot,
        project=project,
    )
    if fallback_acceptance.status is WorkItemStatus.OK and fallback_acceptance.blocker is None:
        if not emitted_problem:
            print(f"/* problem: {result.status} */")
            _print_diagnostic_text(result.payload)
            emit_timeout_delay_line()
        _emit_optional_source_sidecar_c_block(
            args.binary,
            function.name,
            fallback_acceptance.gcc_checked_payload,
            alternate_source_c=bool(args.alternate_source_c),
            c_header="/* -- c (non-optimized fallback) -- */",
        )
        return decompiled_local + 1, failed_local
    print("/* problem: validation=failed */")
    for _diag_line in _format_tail_validation_diagnostic(
        fallback_snapshot,
        function_addr=function.addr,
        function_name=function.name,
        block_count=result.block_count,
        byte_count=result.byte_count,
        exit_kind="fallback",
        exit_detail=fallback_acceptance.blocker or "non-optimized fallback not semantically stable",
    ):
        print(_diag_line)
    return None


def _emit_function_result_light_fallback_8616(
    *,
    item: FunctionWorkItem,
    result: FunctionWorkResult,
    project: angr.Project,
    args: CliArguments,
    lst_metadata: LSTMetadata | None,
    cod_metadata: CODProcMetadata | None,
    allow_heavy_fallbacks: bool,
    skip_heavy_fallbacks_for_result: bool,
    interactive_stdout: bool,
    fallback_tail_validation_by_index: dict[int, dict[str, object]],
    decompiled_local: int,
    failed_local: int,
    attempt_status_printed: bool,
    emitted_problem: bool,
    emit_timeout_delay_line: Callable[[], None],
) -> tuple[int, int]:
    """Emit diagnostics and the light string/assembly fallback lanes."""

    def _impl() -> tuple[int, int]:
        nonlocal decompiled_local, failed_local, attempt_status_printed, emitted_problem
        function: _AngrFunction = item.function
        sidecar_region = _lst_code_region(lst_metadata, function.addr) if lst_metadata is not None else None
        _emit_light_nonopt_unavailable_8616(
            project,
            function,
            result,
            args,
            lst_metadata,
            cod_metadata,
            allow_heavy_fallbacks,
            skip_heavy_fallbacks_for_result,
            interactive_stdout,
        )
        string_c = (
            _string_intrinsic_candidate_8616(project, function, sidecar_region)
            if result.partial_payload is None
            else None
        )
        if string_c is not None:
            accepted_string = _accept_string_fallback_8616(
                project, item, string_c, fallback_tail_validation_by_index
            )
            if accepted_string is not None:
                fallback_acceptance, fallback_snapshot = accepted_string
                failed_local += 1
                _print_function_attempt_status(function, attempt="fallback", validation_snapshot=fallback_snapshot)
                if not emitted_problem:
                    print(f"/* problem: {result.status} */")
                    _print_diagnostic_text(result.payload)
                    emit_timeout_delay_line()
                _emit_optional_source_sidecar_c_block(
                    args.binary,
                    function.name,
                    fallback_acceptance.gcc_checked_payload,
                    alternate_source_c=bool(args.alternate_source_c),
                    c_header="/* -- c (string intrinsic fallback) -- */",
                )
                return decompiled_local, failed_local
        asm_fallback = (
            _format_asm_range(project, sidecar_region[0], sidecar_region[1])
            if sidecar_region is not None
            else _format_asm_range(project, *_infer_linear_disassembly_window(project, function.addr))
        )
        failed_local += 1
        if not attempt_status_printed:
            _print_function_attempt_status(
                function, attempt=_function_attempt_display_status(result), validation_snapshot=result.tail_validation
            )
        _emit_light_asm_fallback_tail_8616(
            function, result, project, asm_fallback, emitted_problem, emit_timeout_delay_line
        )
        return decompiled_local, failed_local

    return _impl()


def _emit_light_nonopt_unavailable_8616(
    project: angr.Project,
    function: _AngrFunction,
    result: FunctionWorkResult,
    args: CliArguments,
    lst_metadata: LSTMetadata | None,
    cod_metadata: CODProcMetadata | None,
    allow_heavy_fallbacks: bool,
    skip_heavy_fallbacks_for_result: bool,
    interactive_stdout: bool,
) -> None:
    """Probe the light non-optimized lane and print why it is unavailable."""
    nonopt_failure_detail = None
    if (not allow_heavy_fallbacks) and (not skip_heavy_fallbacks_for_result):
        try:
            nonopt_probe_result = _try_decompile_non_optimized_slice(
                project,
                function.addr,
                function.name,
                timeout=_bounded_non_optimized_timeout(args.timeout),
                api_style=args.api_style,
                binary_path=args.binary,
                lst_metadata=lst_metadata,
                cod_metadata=cod_metadata,
                allow_fresh_project_retry=False,
                original_addr=function.addr,
            )
            nonopt_failure_detail = _non_optimized_slice_failure_detail(nonopt_probe_result)
        except Exception:
            nonopt_failure_detail = None
    nonopt_skip_reason = describe_non_optimized_unavailable(
        allow_heavy_fallbacks=allow_heavy_fallbacks,
        skip_heavy_fallbacks_for_result=skip_heavy_fallbacks_for_result,
        interactive_stdout=interactive_stdout,
        max_functions=args.max_functions,
        addr_requested=args.addr is not None,
        result_status=result.status,
        failure_stage=result.failure_stage,
        nonopt_failure_detail=nonopt_failure_detail,
    )
    if nonopt_skip_reason is not None:
        print(f"/* non-optimized fallback unavailable: {nonopt_skip_reason} */")


def _emit_light_asm_fallback_tail_8616(
    function: _AngrFunction,
    result: FunctionWorkResult,
    project: angr.Project,
    asm_fallback: str,
    emitted_problem: bool,
    emit_timeout_delay_line: Callable[[], None],
) -> None:
    """Emit the light-lane asm fallback tail."""
    if result.partial_payload is not None:
        if emitted_problem:
            print("/* -- asm fallback -- */")
            _print_asm_fallback_text(asm_fallback)
        return
    if result.status == "empty":
        if asm_fallback.startswith("<assembly unavailable") or asm_fallback == "<no instructions>":
            print(f"/* no bytes available for function at {function.addr:#x}; likely external or synthetic */")
            return
        if emitted_problem:
            print("/* -- asm fallback -- */")
            _print_asm_fallback_text(asm_fallback)
            return
        print(f"/* -- {result.status} -- */")
        _print_diagnostic_text(result.payload)
        emit_timeout_delay_line()
        print("/* -- asm fallback -- */")
        _print_asm_fallback_text(asm_fallback)
        return
    if emitted_problem:
        print("/* -- lift break probe -- */")
        _print_diagnostic_text(_probe_lift_break(project, function.addr))
        print("/* -- asm fallback -- */")
        _print_asm_fallback_text(asm_fallback)
        return
    print(f"/* -- {result.status} -- */")
    _print_diagnostic_text(result.payload)
    emit_timeout_delay_line()
    print("/* -- lift break probe -- */")
    _print_diagnostic_text(_probe_lift_break(project, function.addr))
    print("/* -- asm fallback -- */")
    _print_asm_fallback_text(asm_fallback)


def _emit_string_or_asm_fallback_8616(
    *,
    item: FunctionWorkItem,
    result: FunctionWorkResult,
    project: angr.Project,
    args: CliArguments,
    lst_metadata: LSTMetadata | None,
    fallback_tail_validation_by_index: dict[int, dict[str, object]],
    skip_heavy_fallbacks_for_result: bool,
    allow_heavy_fallbacks: bool,
    interactive_stdout: bool,
    emitted_problem: bool,
    attempt_status_printed: bool,
    decompiled_local: int,
    failed_local: int,
    nonopt_result: NonOptimizedSliceOutcome | str | None,
    emit_timeout_delay_line: Callable[[], None],
) -> tuple[int, int]:
    function: _AngrFunction = item.function
    sidecar_region = _lst_code_region(lst_metadata, function.addr) if lst_metadata is not None else None
    string_c = _string_intrinsic_candidate_8616(project, function, sidecar_region)
    if string_c is not None:
        accepted_string = _accept_string_fallback_8616(
            project, item, string_c, fallback_tail_validation_by_index
        )
        if accepted_string is not None:
            fallback_acceptance, fallback_snapshot = accepted_string
            decompiled_local += 1
            _emit_string_fallback_block_8616(
                function,
                result,
                args,
                fallback_acceptance,
                fallback_snapshot,
                allow_heavy_fallbacks,
                skip_heavy_fallbacks_for_result,
                interactive_stdout,
                nonopt_result,
                emitted_problem,
                emit_timeout_delay_line,
            )
            return decompiled_local, failed_local
    asm_fallback = (
        _format_asm_range(project, sidecar_region[0], sidecar_region[1])
        if sidecar_region is not None
        else _format_asm_range(project, *_infer_linear_disassembly_window(project, function.addr))
    )
    failed_local += 1
    _emit_asm_fallback_block_8616(
        function, result, project, asm_fallback, attempt_status_printed, emitted_problem, emit_timeout_delay_line
    )
    return decompiled_local, failed_local


def _string_intrinsic_candidate_8616(
    project: angr.Project, function: _AngrFunction, sidecar_region: tuple[int, int] | None
) -> str | None:
    """Emit a string-intrinsic C candidate for a function's code window."""
    if sidecar_region is not None:
        return cast(
            str | None,
            _try_emit_string_intrinsic_c(
                project, start=sidecar_region[0], end=sidecar_region[1], name=function.name
            ),
        )
    start, end = _infer_linear_disassembly_window(project, function.addr)
    return cast(str | None, _try_emit_string_intrinsic_c(project, start=start, end=end, name=function.name))


def _accept_string_fallback_8616(
    project: angr.Project,
    item: FunctionWorkItem,
    string_c: str,
    fallback_tail_validation_by_index: dict[int, dict[str, object]],
) -> tuple[CAcceptanceResult8616, dict[str, object]] | None:
    """Accept a string-intrinsic fallback only through the canonical gate."""
    fallback_snapshot = _remember_fallback_tail_validation(
        project,
        fallback_tail_validation_by_index,
        item,
        allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("string_intrinsic"),
    )
    fallback_acceptance = _accept_generated_c_for_emission_8616(
        payload=string_c,
        tail_validation_snapshot=fallback_snapshot,
        project=project,
    )
    if fallback_acceptance.status is WorkItemStatus.OK and fallback_acceptance.blocker is None:
        return fallback_acceptance, fallback_snapshot
    return None


def _emit_string_fallback_block_8616(
    function: _AngrFunction,
    result: FunctionWorkResult,
    args: CliArguments,
    fallback_acceptance: CAcceptanceResult8616,
    fallback_snapshot: dict[str, object],
    allow_heavy_fallbacks: bool,
    skip_heavy_fallbacks_for_result: bool,
    interactive_stdout: bool,
    nonopt_result: NonOptimizedSliceOutcome | str | None,
    emitted_problem: bool,
    emit_timeout_delay_line: Callable[[], None],
) -> None:
    """Print the accepted string-intrinsic fallback output block."""
    _print_function_attempt_status(function, attempt="fallback", validation_snapshot=fallback_snapshot)
    if not emitted_problem:
        print(f"/* problem: {result.status} */")
        _print_diagnostic_text(result.payload)
        emit_timeout_delay_line()
    nonopt_skip_reason = describe_non_optimized_unavailable(
        allow_heavy_fallbacks=allow_heavy_fallbacks,
        skip_heavy_fallbacks_for_result=skip_heavy_fallbacks_for_result,
        interactive_stdout=interactive_stdout,
        max_functions=args.max_functions,
        addr_requested=args.addr is not None,
        result_status=result.status,
        failure_stage=result.failure_stage,
        nonopt_failure_detail=_non_optimized_slice_failure_detail(nonopt_result),
    )
    if nonopt_skip_reason is not None:
        print(f"/* non-optimized fallback unavailable: {nonopt_skip_reason} */")
    _emit_optional_source_sidecar_c_block(
        args.binary,
        function.name,
        fallback_acceptance.gcc_checked_payload,
        alternate_source_c=bool(args.alternate_source_c),
        c_header="/* -- c (string intrinsic fallback) -- */",
    )


def _emit_asm_fallback_block_8616(
    function: _AngrFunction,
    result: FunctionWorkResult,
    project: angr.Project,
    asm_fallback: str,
    attempt_status_printed: bool,
    emitted_problem: bool,
    emit_timeout_delay_line: Callable[[], None],
) -> None:
    """Print diagnostics and the asm fallback block for a failed function."""
    for _diag_line in _format_tail_validation_diagnostic(
        result.tail_validation,
        function_addr=function.addr,
        function_name=function.name,
        block_count=result.block_count,
        byte_count=result.byte_count,
        exit_kind=result.status,
        exit_detail=result.payload,
    ):
        print(_diag_line)
    if not attempt_status_printed:
        _print_function_attempt_status(
            function, attempt=_function_attempt_display_status(result), validation_snapshot=result.tail_validation
        )
    if emitted_problem:
        if result.status != "empty":
            print("/* -- lift break probe -- */")
            _print_diagnostic_text(_probe_lift_break(project, function.addr))
        print("/* -- asm fallback -- */")
        _print_asm_fallback_text(asm_fallback)
        return
    if result.status == "empty" and (
        asm_fallback.startswith("<assembly unavailable") or asm_fallback == "<no instructions>"
    ):
        print(f"/* no bytes available for function at {function.addr:#x}; likely external or synthetic */")
        return
    print(f"/* -- {result.status} -- */")
    _print_diagnostic_text(result.payload)
    emit_timeout_delay_line()
    if result.status != "empty":
        print("/* -- lift break probe -- */")
        _print_diagnostic_text(_probe_lift_break(project, function.addr))
    print("/* -- asm fallback -- */")
    _print_asm_fallback_text(asm_fallback)


def _prepare_main_cli_args_8616(argv: list[str] | None) -> tuple[CliArguments, bool, Path | None]:
    """Parse CLI arguments and apply startup-only process settings."""
    args = parse_cli_arguments(argv)
    _configure_cli_telemetry_8616(args)
    annotate_current_span(
        binary=args.binary.name,
        addr=hex(args.addr) if isinstance(args.addr, int) else None,
        max_functions=args.max_functions,
        timeout=args.timeout,
        backend=args.function_discovery_backend,
    )
    raw_argv = list(argv) if argv is not None else list(sys.argv[1:])
    seed_engine_was_explicit = any(token == "--seed-engine" or token.startswith("--seed-engine=") for token in raw_argv)
    timeout_was_explicit = any(token == "--timeout" or token.startswith("--timeout=") for token in raw_argv)
    if seed_engine_was_explicit and args.seed_engine:
        seed_engine = str(args.seed_engine).strip().lower()
        backend_map = {"auto": "auto", "angr": "angr", "rizin": "rizin"}
        mapped = backend_map.get(seed_engine)
        if mapped is not None:
            args.function_discovery_backend = mapped
    if args.addr is None and not timeout_was_explicit:
        # Keep the configured default timeout budget for whole-file sweeps.
        # Per-function adaptation is handled later by complexity-aware logic.
        args.timeout = max(4, int(args.timeout))
    if bool(args.ignore_local_sidecar_hints):
        os.environ["INERTIA_IGNORE_LOCAL_SIDECAR_HINTS_8616"] = "1"

    _lower_process_priority()
    _apply_memory_limit(args.max_memory_mb)

    effective_signature_catalog: Path | None = args.signature_catalog
    if effective_signature_catalog is None:
        effective_signature_catalog = default_signature_catalog_path()
    return args, timeout_was_explicit, effective_signature_catalog


def _resolve_cod_path_8616(binary_path: Path) -> Path | None:
    """Return the sidecar listing path associated with a CLI binary path."""
    if binary_path.suffix.lower() in {".cod", ".lst", ".map", ".dbg", ".pdb"}:
        return binary_path
    for suffix in (".COD", ".cod"):
        candidate = binary_path.with_suffix(suffix)
        if candidate.exists():
            return candidate
    return None


def _linked_proc_addr_from_metadata_8616(
    metadata: LSTMetadata | None,
    proc_name: str | None,
    proc_kind: str | None,
) -> int | None:
    """Resolve a named procedure to a linked-binary address from sidecar metadata."""
    if metadata is None or not isinstance(proc_name, str) or not proc_name:
        return None
    wanted_name = proc_name.lstrip("_")
    wanted_kind = (proc_kind or "").strip().upper()
    cod_proc_kinds = getattr(metadata, "cod_proc_kinds", None)
    if not isinstance(cod_proc_kinds, Mapping):
        cod_proc_kinds = {}
    candidates: list[tuple[int, int, int, int]] = []
    for addr, label in sorted(_visible_code_labels(metadata).items()):
        if not isinstance(addr, int) or not isinstance(label, str):
            continue
        if label.lstrip("_") != wanted_name:
            continue
        known_kind = cod_proc_kinds.get(addr)
        kind_score = 1
        if wanted_kind and isinstance(known_kind, str):
            kind_score = 2 if known_kind.upper() == wanted_kind else 0
        region_score = 1 if _lst_code_region(metadata, addr) is not None else 0
        candidates.append((kind_score, region_score, -addr, addr))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0][3]


@dataclass(frozen=True, slots=True)
class _MainProjectSetup8616:
    """Prepared project and sidecar state for the main CLI decompilation flow."""

    project: angr.Project
    function_label: str | None
    cod_metadata: CODProcMetadata | None
    synthetic_globals: _SyntheticGlobals8616
    lst_metadata: LSTMetadata | None
    prefer_fast_recovery: bool
    proc_resolved_to_linked_binary: bool


def _prepare_main_project_8616(
    args: CliArguments,
    effective_signature_catalog: Path | None,
) -> _MainProjectSetup8616:
    """Build the angr project and optional sidecar metadata for a CLI run."""
    function_label = None
    cod_metadata = None
    synthetic_globals = None
    lst_metadata = None
    prefer_fast_recovery = False
    proc_resolved_to_linked_binary = False
    if args.proc is not None:
        binary_path = Path(args.binary)
        cod_path = _resolve_cod_path_8616(binary_path)
        linked_proc_addr: int | None = None
        sidecar_only_input = binary_path.suffix.lower() in {".cod", ".lst", ".map", ".dbg", ".pdb"}
        if not sidecar_only_input:
            (
                project,
                lst_metadata,
                cod_metadata,
                function_label,
                linked_proc_addr,
                proc_resolved_to_linked_binary,
            ) = _proc_linked_binary_lane_8616(
                args, binary_path, cod_path, effective_signature_catalog
            )
        if linked_proc_addr is None:
            (
                project,
                cod_metadata,
                synthetic_globals,
                function_label,
            ) = _proc_cod_image_lane_8616(args, binary_path, cod_path, lst_metadata)
            prefer_fast_recovery = True
    else:
        project = _build_project(
            args.binary,
            force_blob=args.blob,
            base_addr=args.base_addr,
            entry_point=args.entry_point,
        )
        typing.cast(typing.Any, project)._inertia_c_target = args.c_target
        typing.cast(typing.Any, project)._inertia_trace_c_stages = bool(args.trace_c_stages)
        typing.cast(typing.Any, project)._inertia_dump_layers = bool(args.dump_layers)
        typing.cast(typing.Any, project)._inertia_dump_layer_root = args.dump_layer_dir
        typing.cast(typing.Any, project)._inertia_dump_layer_filter = args.dump_layer_filter
        _set_tail_validation_runtime_enabled(project, _tail_validation_enabled_for_run(args.binary, proc=args.proc))
        if bool(args.ignore_local_sidecar_hints):
            lst_metadata = load_binary_signature_metadata(
                args.binary, project, pat_backend=args.pat_backend,
                signature_catalog=effective_signature_catalog,
            )
            print(
                "/* ignoring local sidecar metadata for function discovery and recovery due --ignore-local-sidecar-hints */"
            )
        else:
            lst_metadata = _load_lst_metadata(
                args.binary,
                project,
                pat_backend=args.pat_backend,
                signature_catalog=effective_signature_catalog,
            )
        _apply_binary_specific_annotations(
            project,
            args.binary,
            lst_metadata,
            cod_metadata=cod_metadata,
            synthetic_globals=synthetic_globals,
        )
        if lst_metadata is None or has_only_binary_signatures(lst_metadata):
            print(
                "/* no helper metadata (.lst/.map/.cod/debug info) found; using raw binary analysis and quick function-entry scans. */"
            )
        print(_recovery_evidence_line(args.binary, lst_metadata))
    typing.cast(typing.Any, project)._inertia_trace_c_stages = bool(args.trace_c_stages)
    typing.cast(typing.Any, project)._inertia_dump_layers = bool(args.dump_layers)
    typing.cast(typing.Any, project)._inertia_dump_layer_root = args.dump_layer_dir
    typing.cast(typing.Any, project)._inertia_dump_layer_filter = args.dump_layer_filter
    return _MainProjectSetup8616(
        project=project,
        function_label=function_label,
        cod_metadata=cod_metadata,
        synthetic_globals=synthetic_globals,
        lst_metadata=lst_metadata,
        prefer_fast_recovery=prefer_fast_recovery,
        proc_resolved_to_linked_binary=proc_resolved_to_linked_binary,
    )


def _proc_linked_binary_lane_8616(
    args: CliArguments,
    binary_path: Path,
    cod_path: Path | None,
    effective_signature_catalog: Path | None,
) -> tuple[
    angr.Project,
    LSTMetadata | None,
    CODProcMetadata | None,
    str | None,
    int | None,
    bool,
]:
    """Build the binary-backed project lane for ``--proc`` mode."""
    cod_metadata = None
    function_label = None
    proc_resolved_to_linked_binary = False
    project = _build_project(
        args.binary,
        force_blob=args.blob,
        base_addr=args.base_addr,
        entry_point=args.entry_point,
    )
    typing.cast(typing.Any, project)._inertia_c_target = args.c_target
    typing.cast(typing.Any, project)._inertia_trace_c_stages = bool(args.trace_c_stages)
    typing.cast(typing.Any, project)._inertia_dump_layers = bool(args.dump_layers)
    typing.cast(typing.Any, project)._inertia_dump_layer_root = args.dump_layer_dir
    typing.cast(typing.Any, project)._inertia_dump_layer_filter = args.dump_layer_filter
    _set_tail_validation_runtime_enabled(project, _tail_validation_enabled_for_run(args.binary, proc=args.proc))
    if bool(args.ignore_local_sidecar_hints):
        lst_metadata = load_binary_signature_metadata(
            args.binary, project, pat_backend=args.pat_backend,
            signature_catalog=effective_signature_catalog,
        )
        print(
            "/* ignoring local sidecar metadata for function discovery and recovery due --ignore-local-sidecar-hints */"
        )
    else:
        lst_metadata = _load_lst_metadata(
            args.binary,
            project,
            pat_backend=args.pat_backend,
            signature_catalog=effective_signature_catalog,
        )
    linked_proc_addr = _linked_proc_addr_from_metadata_8616(lst_metadata, args.proc, args.proc_kind)
    if linked_proc_addr is not None:
        if cod_path is not None:
            try:
                cod_metadata = extract_cod_proc_metadata(cod_path, args.proc, args.proc_kind)
            except Exception as exc:
                print(f"[dbg] failed to parse COD metadata for {args.proc}: {exc}", file=sys.stderr)
        _apply_binary_specific_annotations(
            project,
            args.binary,
            lst_metadata,
            cod_metadata=cod_metadata,
            synthetic_globals=None,
        )
        if lst_metadata is None or has_only_binary_signatures(lst_metadata):
            print(
                "/* no helper metadata (.lst/.map/.cod/debug info) found; using raw binary analysis and quick function-entry scans. */"
            )
        print(_recovery_evidence_line(args.binary, lst_metadata))
        function_label = args.proc
        if args.addr is not None:
            print(f"[dbg] proc mode ignoring caller-provided --addr {args.addr:#x}")
        args.addr = linked_proc_addr
        linked_region = _lst_code_region(lst_metadata, linked_proc_addr) if lst_metadata is not None else None
        if linked_region is not None:
            args.window = max(args.window, linked_region[1] - linked_region[0])
        proc_resolved_to_linked_binary = True
        print(
            f"[dbg] proc mode resolved {args.proc} to linked binary address {linked_proc_addr:#x}",
            file=sys.stderr,
            flush=True,
        )
    return project, lst_metadata, cod_metadata, function_label, linked_proc_addr, proc_resolved_to_linked_binary


def _proc_cod_image_lane_8616(
    args: CliArguments,
    binary_path: Path,
    cod_path: Path | None,
    lst_metadata: LSTMetadata | None,
) -> tuple[angr.Project, CODProcMetadata | None, _SyntheticGlobals8616, str | None]:
    """Build the COD-image project lane when the linked binary lookup failed."""
    if cod_path is None:
        raise ValueError(f"--proc mode requires sibling COD listing: not found for {binary_path}")
    entries = extract_cod_function_entries(cod_path, args.proc, args.proc_kind)
    cod_metadata = extract_cod_proc_metadata(cod_path, args.proc, args.proc_kind)
    selected_entries = extract_small_two_arg_cod_logic_entries(entries)
    if selected_entries is None:
        selected_entries = extract_simple_cod_logic_entries(entries)
    if selected_entries is None:
        logic_start = infer_cod_logic_start(entries)
        cod_image = build_cod_analysis_image_8616(
            entries,
            start_offset=logic_start,
            image_base=args.base_addr,
        )
    else:
        cod_image = build_cod_analysis_image_8616(selected_entries, image_base=args.base_addr)
    proc_code = cod_image.code
    # The fixture body ends before synthetic callees, not at a guessed fast window.
    args.exact_region_end = args.base_addr + min(cod_image.call_target_offsets, default=len(proc_code))
    synthetic_globals = cod_image.synthetic_globals
    project = _build_project_from_bytes(
        proc_code,
        base_addr=args.base_addr,
        entry_point=args.entry_point,
    )
    record_synthetic_call_stubs_8616(
        project,
        frozenset(args.base_addr + offset for offset in cod_image.call_target_offsets),
    )
    record_cod_module_caller_return_use_evidence_8616(cod_metadata, args.entry_point, project)
    for target_offset, target_name in cod_image.call_target_offsets.items():
        annotate_function(project, args.base_addr + target_offset, name=target_name)
    typing.cast(typing.Any, project)._inertia_c_target = args.c_target
    typing.cast(typing.Any, project)._inertia_dump_layers = bool(args.dump_layers)
    typing.cast(typing.Any, project)._inertia_dump_layer_root = args.dump_layer_dir
    typing.cast(typing.Any, project)._inertia_dump_layer_filter = args.dump_layer_filter
    _set_tail_validation_runtime_enabled(project, _tail_validation_enabled_for_run(args.binary, proc=args.proc))
    _apply_binary_specific_annotations(
        project,
        args.binary,
        lst_metadata,
        cod_metadata=cod_metadata,
        synthetic_globals=synthetic_globals,
    )
    function_label = args.proc
    if args.addr is not None:
        print(f"[dbg] proc mode ignoring caller-provided --addr {args.addr:#x}")
    args.addr = args.entry_point
    args.window = max(len(proc_code), 1)
    return project, cod_metadata, synthetic_globals, function_label


@dataclass(frozen=True, slots=True)
class _DirectAddrCliContext8616:
    """Inputs for the direct-address CLI decompilation branch."""

    args: CliArguments
    project: angr.Project
    function_label: str | None
    cod_metadata: CODProcMetadata | None
    synthetic_globals: _SyntheticGlobals8616
    lst_metadata: LSTMetadata | None
    prefer_fast_recovery: bool
    proc_resolved_to_linked_binary: bool
    low_memory_path: bool
    interactive_stdout: bool
    precise_sidecar_regions: bool
    timeout_was_explicit: bool
    request_cache_inputs: DirectRequestCacheInputs8616


def _direct_request_cache_artifact_for_result_8616(
    context: _DirectAddrCliContext8616,
    result: FunctionWorkResult,
    *,
    function_addr: int,
    function_name: str,
) -> DirectRequestCacheArtifact8616 | None:
    """Project an accepted direct result into the persistent cache contract."""
    integrity = verify_function_work_result_payload_integrity_8616(result)
    if not _cacheable_direct_result_8616(result, integrity):
        return None
    startup_diagnostic_lines: list[str] = []
    if context.args.ignore_local_sidecar_hints:
        startup_diagnostic_lines.append(
            "/* ignoring local sidecar metadata for function discovery and recovery due "
            "--ignore-local-sidecar-hints */"
        )
    if context.lst_metadata is None or has_only_binary_signatures(context.lst_metadata):
        startup_diagnostic_lines.append(
            "/* no helper metadata (.lst/.map/.cod/debug info) found; using raw binary analysis "
            "and quick function-entry scans. */"
        )
    startup_diagnostic_lines.append(_recovery_evidence_line(context.args.binary, context.lst_metadata))
    return DirectRequestCacheArtifact8616(
        function_addr=function_addr,
        function_name=function_name,
        arch_name=context.project.arch.name,
        entry_point=context.project.entry,
        runtime_header=render_c_runtime_header_8616(context.args.c_target),
        startup_diagnostic_lines=tuple(startup_diagnostic_lines),
        payload=result.payload,
        tail_validation=copy.deepcopy(result.tail_validation),
        elapsed=result.elapsed,
        block_count=result.block_count,
        byte_count=result.byte_count,
        validated_payload_hash=result.validated_payload_hash,
        gcc_checked_payload_hash=result.gcc_checked_payload_hash,
        failure_family_snapshot=result.failure_family_snapshot,
        diagnostic_output=(
            result.debug_output
            if os.environ.get("INERTIA_ENABLE_TYPED_SWITCH_AST_ARTIFACTS") == "1"
            else ""
        ),
        segment_program_function_evidence_record=(
            None
            if result.segment_program_function_evidence is None
            else result.segment_program_function_evidence.to_dict()
        ),
    )


def _store_direct_request_result_8616(
    context: _DirectAddrCliContext8616,
    lookup: DirectRequestCacheLookup8616,
    result: FunctionWorkResult,
    *,
    function_addr: int,
    function_name: str,
) -> None:
    """Store one direct result when its typed acceptance proof is complete."""
    artifact = _direct_request_cache_artifact_for_result_8616(
        context,
        result,
        function_addr=function_addr,
        function_name=function_name,
    )
    if artifact is not None:
        store_direct_request_cache_8616(lookup, artifact)


def _emit_direct_cache_hit_8616(
    context: _DirectAddrCliContext8616,
    result: FunctionWorkResult,
    *,
    function: _AngrFunction,
    function_cfg: object | None,
    emit_function_header: bool,
    project_for_worker_result: object | None,
) -> int:
    """Emit one already-validated direct result through the normal CLI contract."""
    args = context.args
    integrity = verify_function_work_result_payload_integrity_8616(result)
    if not integrity.passed:
        print(f"[tail-validation] {integrity.diagnostic()}", file=sys.stderr, flush=True)
        return 4
    if emit_function_header:
        print(f"/* binary: {args.binary} */")
        print(f"/* arch: {context.project.arch.name} */")
        print(f"/* entry: {context.project.entry:#x} */")
        print(f"/* function: {function_original_addr(function):#x} {function.name} */")
    if result.debug_output:
        print(result.debug_output, file=sys.stderr, end="")
    cached_tail_snapshot = result.tail_validation
    print(
        render_direct_request_tail_snapshot_diagnostic_8616(cached_tail_snapshot),
        file=sys.stderr,
        flush=True,
    )
    print("[dbg] direct function cache hit validation=passed", file=sys.stderr, flush=True)
    assert result.failure_family_snapshot is not None
    print(f"[dbg] direct failure family: {result.failure_family_snapshot.label()}", file=sys.stderr)
    if _complete_serial_clean_worker_result_8616(result, project=project_for_worker_result):
        return 0
    item = FunctionWorkItem(index=1, function_cfg=function_cfg, function=function)
    _emit_tail_validation_console_summary([item], {1: result}, binary_path=args.binary)
    if args.output_c_dir is not None:
        write_generated_function_c(
            args.output_c_dir,
            address=function_original_addr(function),
            name=function.name,
            payload=result.payload,
        )
    _emit_optional_source_sidecar_c_block(
        args.binary,
        function.name,
        result.payload,
        alternate_source_c=bool(args.alternate_source_c),
        c_header="\n/* == c == */",
    )
    return 0


@dataclass(slots=True)
class _DirectAddrCliRun8616:
    """Mutable run state for direct-address CLI orchestration."""

    context: _DirectAddrCliContext8616
    _: Any = None
    _bbytes: Any = None
    _bcount: Any = None
    _block_count: Any = None
    _byte_count: Any = None
    _dbg_region: Any = None
    _diag_line: Any = None
    _direct_blocks: Any = None
    _direct_blocks_for_timeout_guard: Any = None
    _direct_bytes: Any = None
    _direct_bytes_for_timeout_guard: Any = None
    _direct_effective_timeout: Any = None
    _early_slice: Any = None
    _elapsed: Any = None
    _stored_snapshot: Any = None
    accepted_payload: Any = None
    accepted_side_payload: Any = None
    allow_known_nonopt: Any = None
    args: Any = None
    artifact: Any = None
    asm_fallback: Any = None
    attr_name: Any = None
    attr_value: Any = None
    best_direct_candidate: Any = None
    best_direct_rank: Any = None
    block_count: Any = None
    boosted: Any = None
    budget_fallback_addr: Any = None
    budget_fallback_name: Any = None
    budgeted_direct_decompile_timeout: Any = None
    byte_count: Any = None
    cached_clean_status: Any = None
    cached_direct_result: Any = None
    cached_function: Any = None
    cached_result: Any = None
    cached_segment_evidence: Any = None
    call_target: Any = None
    candidate: Any = None
    candidates: Any = None
    canonical_direct_addr: Any = None
    cfg: Any = None
    cfg2: Any = None
    checked_acceptance: Any = None
    checked_blocker: Any = None
    checked_payload: Any = None
    checked_status: Any = None
    clean_worker_caller_return_evidence_by_addr: Any = None
    clinic_core_timeout: Any = None
    cod_metadata: Any = None
    code_name: Any = None
    current_partial_payload: Any = None
    current_rank: Any = None
    debug_output: Any = None
    detail: Any = None
    direct_acceptance: Any = None
    direct_addr: Any = None
    direct_addr_deadline: Any = None
    direct_addr_started_at: Any = None
    direct_analysis_timeout: Any = None
    direct_arch_name: Any = None
    direct_blocker: Any = None
    direct_budget_timeout: Any = None
    direct_cache_debug: Any = None
    direct_cache_item: Any = None
    direct_cache_key: Any = None
    direct_cache_result: Any = None
    direct_callsite_count: Any = None
    direct_clinic_policy: Any = None
    direct_debug_output: Any = None
    direct_decompile_timeout: Any = None
    direct_display_addr: Any = None
    direct_elapsed: Any = None
    direct_extra: Any = None
    direct_failure_family_snapshot: Any = None
    direct_failure_family_state: Any = None
    direct_item: Any = None
    direct_job_result: Any = None
    direct_nonoptimized_verdict: Any = None
    direct_payload: Any = None
    direct_project: Any = None
    direct_project_fallback_addr: Any = None
    direct_recovery_timeout: Any = None
    direct_request_cache_lookup: Any = None
    direct_result: Any = None
    direct_segment_program_evidence: Any = None
    direct_sidecar_verdict: Any = None
    direct_status: Any = None
    direct_tail_validation_snapshot: Any = None
    direct_timeout_payload: Any = None
    direct_timeout_stage: Any = None
    end: Any = None
    evidence_acceptance: Any = None
    evidence_payload: Any = None
    evidence_snapshot: Any = None
    exact_region: Any = None
    exact_region_end: Any = None
    exact_retry_blocked: Any = None
    expected_runtime_header: Any = None
    extra: Any = None
    fallback_function: Any = None
    fallback_snapshot: Any = None
    fast_direct_probe: Any = None
    fast_direct_probe_requested: Any = None
    func: Any = None
    func2: Any = None
    func_info: Any = None
    func_info_tv: Any = None
    function_label: Any = None
    function_tail_candidate: Any = None
    generic_nonopt_c: Any = None
    generic_nonopt_result: Any = None
    heavy_fallback_budget: Any = None
    helper_acceptance: Any = None
    helper_blocker: Any = None
    helper_model: Any = None
    helper_payload: Any = None
    helper_result: Any = None
    helper_snapshot: Any = None
    helper_status: Any = None
    helper_tail_validation_snapshot: Any = None
    integrity: Any = None
    interactive_stdout: Any = None
    k: Any = None
    known_helper_model: Any = None
    known_nonopt_c: Any = None
    known_nonopt_result: Any = None
    linear_window: Any = None
    low_memory_path: Any = None
    lst_metadata: Any = None
    m: Any = None
    merged_statuses: Any = None
    nonopt_c: Any = None
    nonopt_failure_detail: Any = None
    nonopt_result: Any = None
    nonopt_skip_reason: Any = None
    partial_acceptance: Any = None
    partial_payload: Any = None
    partial_payload_text: Any = None
    partial_report: Any = None
    partial_text: Any = None
    payload: Any = None
    payload_detail: Any = None
    payload_for_acceptance: Any = None
    payload_text: Any = None
    precise_sidecar_regions: Any = None
    prefer_fast_recovery: Any = None
    present_calls: Any = None
    preserved_candidate: Any = None
    proc_resolved_to_linked_binary: Any = None
    project: Any = None
    project_fb: Any = None
    quality: Any = None
    quality_violations: Any = None
    ranked_cfg: Any = None
    ranked_func: Any = None
    recovered_blocks: Any = None
    recovered_bytes: Any = None
    recovery_detail: Any = None
    region: Any = None
    region_span: Any = None
    remaining_direct_budget: Any = None
    reserve_budget_for_rebased_sidecar: Any = None
    result: Any = None
    retry_acceptance: Any = None
    retry_blocker: Any = None
    retry_checked_status: Any = None
    retry_count: Any = None
    retry_extra: Any = None
    retry_idx: Any = None
    retry_partial: Any = None
    retry_payload: Any = None
    retry_preserved_candidate: Any = None
    retry_rank: Any = None
    retry_result: Any = None
    retry_status: Any = None
    retry_tail_validation: Any = None
    robust_acceptance: Any = None
    robust_blocks: Any = None
    robust_bytes: Any = None
    robust_item: Any = None
    robust_result: Any = None
    robust_snapshot: Any = None
    robust_tail_validation_snapshot: Any = None
    robust_timeout: Any = None
    side_acceptance: Any = None
    side_cfg: Any = None
    side_func: Any = None
    side_payload: Any = None
    side_payload_checked: Any = None
    side_project: Any = None
    side_status: Any = None
    side_status_checked: Any = None
    side_tail: Any = None
    side_tail_candidate: Any = None
    side_tail_from_decompile: Any = None
    sidecar_addr: Any = None
    sidecar_attempted: Any = None
    sidecar_closed_nonopt: Any = None
    sidecar_region: Any = None
    skip_heavy_validation_fallbacks: Any = None
    slice_result: Any = None
    snapshot: Any = None
    start: Any = None
    status: Any = None
    stderr_buf: Any = None
    stdout_buf: Any = None
    string_c: Any = None
    string_end: Any = None
    string_start: Any = None
    synthetic_globals: Any = None
    text: Any = None
    timeout_text: Any = None
    timeout_was_explicit: Any = None
    trivial_c: Any = None
    use_fork_for_direct: Any = None
    using_rebased_direct_slice: Any = None
    v: Any = None

    def run_8616(self) -> int:
        """Run the direct-address CLI phases and return the process exit code."""
        _rc = self.run_8616_part0_8616()
        if _rc is not None:
            return _rc
        _rc = self.run_8616_part1_8616()
        if _rc is not None:
            return _rc
        _rc = self.run_8616_part2_8616()
        if _rc is not None:
            return _rc
        _rc = self.run_8616_part3_8616()
        if _rc is not None:
            return _rc
        _rc = self.run_8616_part4_8616()
        if _rc is not None:
            return _rc
        _rc = self.run_8616_part5_8616()
        if _rc is not None:
            return _rc
        return 0

    def _emit_budget_exhausted_sidecar_asm_fallback_or_timeout(self, detail: str) -> None:
        """Hoisted nested function (callable via `self`)."""
        if self.precise_sidecar_regions and self.budget_fallback_addr is not None and self.lst_metadata is not None:
            self.sidecar_region = _lst_code_region(self.lst_metadata, self.budget_fallback_addr)
            if self.sidecar_region is not None:
                self.code_name = (
                    _lst_code_label(self.lst_metadata, self.sidecar_region[0], self.project.entry)
                    or self.budget_fallback_name
                    or f"sub_{self.budget_fallback_addr:x}"
                )
                print(f"/* Decompilation timeout: Timed out after {self.args.timeout}s. */")
                print("/* direct validation=failed */")
                _emit_failed_timeout_acceptance_hints_8616()
                print("/* Function recovery timed out; using sidecar-bounded asm fallback. */")
                print("/* non-optimized fallback failed: unavailable after recovery-timeout budget exhaustion */")
                print(f"/* binary: {self.args.binary} */")
                print(f"/* arch: {self.project.arch.name} */")
                print(f"/* entry: {self.project.entry:#x} */")
                print(f"/* function: {self.sidecar_region[0]:#x} {self.code_name} */")
                _emit_tail_validation_for_function_run_or_uncollected(
                    self.project,
                    None,
                    SimpleNamespace(addr=self.sidecar_region[0], name=self.code_name),
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("asm"),
                    binary_path=self.args.binary,
                )
                print("\n/* == asm fallback == */")
                print(_format_asm_range(self.project, self.sidecar_region[0], self.sidecar_region[1]))
                sys.stdout.flush()
                emit_compact_summary()
                sys.stderr.flush()
                os._exit(4)
        _emit_timeout_and_exit(self.args.timeout, detail)
    def _remaining_direct_addr_budget(self) -> int:
        """Hoisted nested function (callable via `self`)."""
        return max(0, int(self.direct_addr_deadline - time.monotonic()))
    def _enforce_direct_addr_budget_timeout(self, *, recovery_detail: str | None=None) -> None:
        """Hoisted nested function (callable via `self`)."""
        if self._remaining_direct_addr_budget() > 0:
            return
        self.detail = recovery_detail
        if self.detail is None:
            self.detail = "after exhausting direct-address recovery budget"
        self._emit_budget_exhausted_sidecar_asm_fallback_or_timeout(self.detail)
    def _direct_failure_snapshot(self, result: FunctionWorkResult) -> FailureFamilySnapshot:
        """Hoisted nested function (callable via `self`)."""
        """Build the complete direct-address diagnostic snapshot for one result."""
        return build_failure_family_snapshot(
            status=result.status,
            failure_stage=result.failure_stage,
            sidecar_verdict=self.direct_sidecar_verdict,
            non_optimized_verdict=self.direct_nonoptimized_verdict,
            fallback_kind="direct_addr",
            tail_validation_verdict=_tail_validation_display_status(
                result.tail_validation,
                fallback_kind="direct_addr" if result.status != "ok" else None,
            ),
            artifact_path=f"{self.func.addr:#x}:{self.func.name}",
        )
    def _direct_analysis_timeout_for_shape(self, base_timeout: int, block_count: int, byte_count: int) -> int:
        """Hoisted nested function (callable via `self`)."""
        self.boosted = _effective_decompile_timeout_8616(
            self.direct_project,
            base_timeout,
            block_count=block_count,
            byte_count=byte_count,
        )
        if getattr(self.project.arch, "name", "") == "86_16":
            # Large menu/controller functions are clinic-heavy and can
            # legitimately exceed the default 120s lane timeout.
            if block_count >= 72 or byte_count >= 520:
                self.boosted = max(self.boosted, base_timeout + 180)
            elif block_count >= 56 or byte_count >= 420:
                self.boosted = max(self.boosted, base_timeout + 120)
            elif block_count >= 40 or byte_count >= 300:
                self.boosted = max(self.boosted, base_timeout + 80)
        return _enforce_function_timeout_cap(
            max(1, self.boosted),
            context="direct shape timeout",
            explicit_timeout_floor=self.args.timeout if self.timeout_was_explicit else None,
        )
    def _preserve_best_failure_candidate(self, result: FunctionWorkResult) -> str | None:
        """Hoisted nested function (callable via `self`)."""
        self.candidates = [
            text for text in (result.payload, result.partial_payload) if isinstance(text, str) and text.strip()
        ]
        if not self.candidates:
            return None

        def _rank(text: str) -> tuple[int, int]:
            self.quality = assess_decompiled_c_text(text)
            self.quality_violations = len(self.quality.markers) if self.quality.reject_as_decompiled else 0
            return (
                -self.quality_violations,
                len(text),
            )

        return cast(str | None, max(self.candidates, key=_rank))
    def _preserve_acceptance_candidate_or_best_failure(self, acceptance: CAcceptanceResult8616, result: FunctionWorkResult) -> str | None:
        """Hoisted nested function (callable via `self`)."""
        if acceptance.status == "ok" and acceptance.blocker is None:
            self.checked_payload = acceptance.gcc_checked_payload
            if self.checked_payload.strip():
                return cast(str, self.checked_payload)
            if acceptance.validated_payload.strip():
                return cast(str | None, acceptance.validated_payload)
        return self._preserve_best_failure_candidate(result)
    def _recover_target_function(self) -> _FunctionCfgPair8616:
        """Hoisted nested function (callable via `self`)."""
        self.exact_region_end = getattr(self.args, "exact_region_end", None)
        self.exact_region = (
            (self.direct_addr, self.exact_region_end)
            if isinstance(self.exact_region_end, int) and self.exact_region_end > self.direct_addr
            else None
        )
        return cast(
            _FunctionCfgPair8616,
            _recover_direct_addr_function(
                self.project,
                self.direct_addr,
                timeout=self.args.timeout,
                window=self.args.window,
                function_label=self.function_label,
                lst_metadata=self.lst_metadata,
                low_memory_path=self.low_memory_path,
                prefer_fast_recovery=self.prefer_fast_recovery,
                exact_region=self.exact_region,
            ),
        )
    def direct_decompile_job(self) -> _DirectDecompileJobResult8616:
        """Hoisted nested function (callable via `self`)."""
        """Run one direct function through the selected bounded Clinic policy."""
        self._bcount, self._bbytes = _function_complexity(self.func)
        self.direct_analysis_timeout = self._direct_analysis_timeout_for_shape(self.args.timeout, self._bcount, self._bbytes)
        self.direct_arch_name = getattr(getattr(self.direct_project, "arch", None), "name", "")
        self.direct_callsite_count = (
            _safe_function_callsite_count_8616(self.func)
            if _clinic_policy_needs_callsite_count_8616(
                arch_name=self.direct_arch_name,
                direct_addr_mode=self.direct_addr is not None,
                block_count=self._bcount,
                byte_count=self._bbytes,
            )
            else 0
        )
        self.direct_clinic_policy = _direct_clinic_policy_8616(
            arch_name=self.direct_arch_name,
            direct_addr_mode=self.direct_addr is not None,
            block_count=self._bcount,
            byte_count=self._bbytes,
            call_site_count=self.direct_callsite_count,
        )
        if os.environ.get("INERTIA_DEBUG_CLINIC_FLAGS"):
            print(
                "[dbg] direct clinic policy "
                f"policy={self.direct_clinic_policy.value} arch={self.direct_arch_name!r} "
                f"blocks={self._bcount} bytes={self._bbytes} calls={self.direct_callsite_count}"
            )
        with _temporary_clinic_policy_8616(self.direct_project, self.direct_clinic_policy):
            with _capture_thread_output() as (self.stdout_buf, self.stderr_buf):
                self.result = _decompile_function_with_stats(
                    self.direct_project,
                    self.cfg,
                    self.func,
                    self.direct_analysis_timeout,
                    self.args.api_style,
                    self.args.binary,
                    cod_metadata=self.cod_metadata,
                    synthetic_globals=self.synthetic_globals,
                    lst_metadata=self.lst_metadata,
                    # Direct-address mode must prefer deterministic single-lane
                    # recovery. Isolated retries can re-run the full pipeline
                    # multiple times and overwrite a valid candidate with a
                    # later timeout lane.
                    allow_isolated_retry=False,
                    failure_family_state=self.direct_failure_family_state,
                )
            self.debug_output = self.stdout_buf.getvalue() + self.stderr_buf.getvalue()
        self.snapshot = _tail_validation_snapshot_for_function_run(self.direct_project, self.func)
        self.project_fb = getattr(self.direct_project, "_inertia_last_tail_validation_snapshot", None)
        if (
            isinstance(self.project_fb, dict)
            and x86_16_tail_validation_snapshot_passed(self.project_fb)
            and not x86_16_tail_validation_snapshot_passed(self.snapshot)
        ):
            # A nested analysis can capture a pre-refresh snapshot before
            # the requested function publishes its final project snapshot.
            # The complete passing project snapshot is the authoritative
            # result at this worker boundary.
            self.snapshot = dict(self.project_fb)
        self.func_info_tv = None
        self.func_info = getattr(self.func, "info", None)
        if isinstance(self.func_info, dict):
            self.func_info_tv = self.func_info.get("x86_16_tail_validation")
        self.merged_statuses = (
            {k: v.get("status") if isinstance(v, dict) else type(v).__name__ for k, v in self.snapshot.items()}
            if isinstance(self.snapshot, dict)
            else "N/A"
        )
        print(
            f"[dbg] direct_decompile_job snapshot: project_fb_stages={list(self.project_fb.keys()) if isinstance(self.project_fb, dict) else 'NOT_DICT'} func_info_tv_stages={list(self.func_info_tv.keys()) if isinstance(self.func_info_tv, dict) else type(self.func_info_tv).__name__ if self.func_info_tv is not None else 'None'} merged_stages={list(self.snapshot.keys()) if isinstance(self.snapshot, dict) else 'NOT_DICT'} merged_statuses={self.merged_statuses}",
            file=sys.stderr,
            flush=True,
        )
        return (
            *self.result,
            self.snapshot,
            segment_program_function_evidence_for_function_8616(self.direct_project, self.func),
            FailureFamilyState(
                previous_snapshot=self.direct_failure_family_state.previous_snapshot,
                candidate_snapshot=self.direct_failure_family_state.candidate_snapshot,
                new_proof_seen=self.direct_failure_family_state.new_proof_seen,
                repeat_detected=self.direct_failure_family_state.repeat_detected,
            ),
            self.debug_output,
        )
    def _candidate_text_for_rank(self, result: FunctionWorkResult) -> str:
        """Hoisted nested function (callable via `self`)."""
        self.payload_text = result.payload if isinstance(result.payload, str) and result.payload.strip() else ""
        self.partial_text = (
            result.partial_payload
            if isinstance(result.partial_payload, str) and result.partial_payload.strip()
            else ""
        )
        if self.payload_text and not self.partial_text:
            return cast(str, self.payload_text)
        if self.partial_text and not self.payload_text:
            return cast(str, self.partial_text)
        if not self.payload_text and not self.partial_text:
            return ""

        def _text_rank(text: str) -> tuple[int, int, int]:
            self.quality = assess_decompiled_c_text(text)
            self.quality_violations = len(self.quality.markers) if self.quality.reject_as_decompiled else 0
            self.present_calls = _non_probe_call_count_for_fallback_rank_8616(text)
            return (
                -self.quality_violations,
                self.present_calls,
                len(text),
            )

        return cast(str, self.payload_text if _text_rank(self.payload_text) >= _text_rank(self.partial_text) else self.partial_text)
    def _candidate_rank(self, result: FunctionWorkResult) -> tuple[int, int, int]:
        """Hoisted nested function (callable via `self`)."""
        self.text = self._candidate_text_for_rank(result)
        self.quality = assess_decompiled_c_text(self.text)
        self.quality_violations = len(self.quality.markers) if self.quality.reject_as_decompiled else 0
        self.present_calls = _non_probe_call_count_for_fallback_rank_8616(self.text)
        return (
            -self.quality_violations,
            self.present_calls,
            len(self.text),
        )
    def _consume_heavy_fallback_budget(self) -> bool:
        """Hoisted nested function (callable via `self`)."""
        if self.heavy_fallback_budget <= 0:
            return False
        self.heavy_fallback_budget -= 1
        return True
    def _current_direct_partial_payload(self) -> str | None:
        """Hoisted nested function (callable via `self`)."""
        self.candidate = self.direct_result.partial_payload
        return self.candidate if isinstance(self.candidate, str) and self.candidate.strip() else None
    def _accept_direct_fallback_payload(self, payload_text: str, *, tail_validation_snapshot: dict[str, object] | None=None) -> str | None:
        """Hoisted nested function (callable via `self`)."""
        self.payload_for_acceptance = payload_text
        self.snapshot = dict(tail_validation_snapshot) if isinstance(tail_validation_snapshot, dict) else None
        for _attr_name_lp8616 in (
            "_inertia_partial_tail_validation_snapshot",
            "_inertia_last_tail_validation_snapshot",
        ):
            self.attr_name = _attr_name_lp8616
            if self.snapshot is not None:
                break
            self.attr_value = getattr(self.direct_project, _attr_name_lp8616, None)
            if isinstance(self.attr_value, dict):
                self.snapshot = dict(self.attr_value)
                break
        if self.snapshot is None:
            self.snapshot = _tail_validation_snapshot_for_function_run(self.direct_project, self.func)
        self.checked_acceptance = _validated_generated_c_acceptance_8616(
            status="ok",
            payload=self.payload_for_acceptance,
            tail_validation_snapshot=self.snapshot,
            tail_validation_enabled=_tail_validation_runtime_enabled(self.direct_project),
            expected_validation_stages=["structuring", "postprocess"],
            c_target=getattr(self.direct_project, "_inertia_c_target", "portable-flat"),
            emit_failure_diagnostics=False,
        )
        self.checked_status = self.checked_acceptance.status
        self.checked_blocker = self.checked_acceptance.blocker
        if self.checked_status == "ok":
            print("[dbg] direct fallback validation=passed", file=sys.stderr)
            return cast(str, self.checked_acceptance.gcc_checked_payload or self.payload_for_acceptance)
        _dump_validation_failed_payload_if_requested_8616(
            self.payload_for_acceptance,
            prefix=f"fallback_{self.func.addr:x}_{self.func.name}",
        )
        print(
            f"[dbg] rejected direct fallback payload: {self.checked_status} detail={self.checked_blocker or 'n/a'}",
            file=sys.stderr,
            flush=True,
        )
        return None
    def _phase_direct_header_8616(self) -> int | None:
        """Run an extracted `_run_direct_addr_cli_8616` phase; return an exit code to abort."""
        if (
            self.direct_request_cache_lookup.verdict is DirectRequestCacheVerdict8616.HIT
            and self.direct_request_cache_lookup.artifact is not None
        ):
            self.artifact = self.direct_request_cache_lookup.artifact
            try:
                self.cached_segment_evidence = (
                    None
                    if self.artifact.segment_program_function_evidence_record is None
                    else segment_program_function_evidence_from_record_8616(
                        self.artifact.segment_program_function_evidence_record
                    )
                )
            except (PipelineHardError, ValueError):
                self.cached_segment_evidence = None
                print("[dbg] direct request cache refused: segment_evidence", file=sys.stderr, flush=True)
            else:
                self.expected_runtime_header = render_c_runtime_header_8616(self.args.c_target)
                if (
                    self.artifact.arch_name == self.project.arch.name
                    and self.artifact.entry_point == self.project.entry
                    and self.artifact.runtime_header == self.expected_runtime_header
                ):
                    self.cached_function = SimpleNamespace(
                        addr=self.artifact.function_addr,
                        name=self.artifact.function_name,
                        project=self.project,
                    )
                    self.cached_result = FunctionWorkResult(
                        index=1,
                        status=WorkItemStatus.OK.value,
                        payload=self.artifact.payload,
                        debug_output=(
                            f"[dbg] direct request cache hit: {self.artifact.function_addr:#x} "
                            f"{self.artifact.function_name} validation=passed\n"
                            f"{self.artifact.diagnostic_output}"
                        ),
                        function=self.cached_function,
                        function_cfg=None,
                        tail_validation=copy.deepcopy(self.artifact.tail_validation),
                        elapsed=self.artifact.elapsed,
                        from_cache=True,
                        block_count=self.artifact.block_count,
                        byte_count=self.artifact.byte_count,
                        validated_payload_hash=self.artifact.validated_payload_hash,
                        gcc_checked_payload_hash=self.artifact.gcc_checked_payload_hash,
                        failure_family_snapshot=self.artifact.failure_family_snapshot,
                        segment_program_function_evidence=self.cached_segment_evidence,
                    )
                    return _emit_direct_cache_hit_8616(
                        self.context,
                        self.cached_result,
                        function=self.cached_function,
                        function_cfg=None,
                        emit_function_header=True,
                        project_for_worker_result=None,
                    )
                print("[dbg] direct request cache refused: runtime_identity", file=sys.stderr, flush=True)
        return None

    def _phase_direct_cfg_recovery_8616(self) -> int | None:
        """Run an extracted `_run_direct_addr_cli_8616` phase; return an exit code to abort."""
        _rc = self._phase_direct_cfg_recovery_8616_part0_8616()
        if _rc is not None:
            return _rc
        return None

    def _phase_direct_probe_setup_8616(self) -> int | None:
        """Run an extracted `_run_direct_addr_cli_8616` phase; return an exit code to abort."""
        if (
            self.precise_sidecar_regions
            and self.lst_metadata is not None
            and self.project.arch.name == "86_16"
            and self.direct_addr is not None
        ):
            try:
                self.sidecar_region = _lst_code_region(self.lst_metadata, self.direct_addr)
                self.block_count, self.byte_count = _function_complexity(self.func)
                if (
                    self.sidecar_region is not None
                    and isinstance(self.sidecar_region[0], int)
                    and int(self.sidecar_region[0]) == int(self.direct_addr)
                    and (self.block_count <= 3 or self.byte_count <= 24)
                ):
                    self.sidecar_addr = self.sidecar_region[0]
                    self.code_name = _lst_code_label(self.lst_metadata, self.sidecar_addr, self.project.entry) or f"sub_{self.sidecar_addr:x}"
                    self.cfg2, self.func2 = _recover_lst_function(
                        self.project,
                        self.lst_metadata,
                        self.sidecar_addr if self.lst_metadata.absolute_addrs else self.sidecar_addr - self.project.entry,
                        self.code_name,
                        timeout=max(1, min(self.args.timeout, 6)),
                        window=self.args.window,
                        low_memory=self.low_memory_path,
                    )
                    if self.func2 is not None:
                        self.cfg, self.func = self.cfg2, self.func2
                        mark_function_original_addr(self.func, self.direct_addr)
            except Exception:
                pass
        return None

    def _phase_direct_catalog_8616(self) -> int | None:
        """Run an extracted `_run_direct_addr_cli_8616` phase; return an exit code to abort."""
        if self.direct_addr is not None and self.project.arch.name == "86_16":
            try:
                self.recovered_blocks, self.recovered_bytes = _function_complexity(self.func)
            except Exception:
                self.recovered_blocks, self.recovered_bytes = (0, 0)
            self.region = _lst_code_region(self.lst_metadata, self.direct_addr) if self.lst_metadata is not None else None
            self.region_span = max(0, int(self.region[1]) - int(self.region[0])) if isinstance(self.region, tuple) and len(self.region) == 2 else 0
            if self.recovered_blocks <= 1 and self.recovered_bytes <= 16 and self.region_span >= 64:
                try:
                    self.ranked_cfg, self.ranked_func = _recover_ranked_binary_function(
                        self.project,
                        self.direct_addr,
                        self.function_label or self.func.name,
                        timeout=max(12, min(self.args.timeout, 24)),
                        window=self.args.window,
                        low_memory=self.low_memory_path,
                    )
                except Exception:
                    pass
                else:
                    self.cfg, self.func = self.ranked_cfg, self.ranked_func
        return None

    def _phase_direct_fast_probe_8616(self) -> int | None:
        """Run an extracted `_run_direct_addr_cli_8616` phase; return an exit code to abort."""
        if self.project.arch.name == "86_16":
            attach_direct_target_argument_evidence_context_8616(
                self.project,
                self.direct_project,
                function_original_addr(self.func),
            )
            prepare_direct_indexed_alias_program_context_8616(
                self.project,
                self.direct_project,
                self.func,
                timeout=self.args.timeout,
                window=self.args.window,
                binary_path=self.args.binary,
            )
            for _call_target_lp8616 in collect_neighbor_call_targets(self.func):
                self.call_target = _call_target_lp8616
                if _call_target_lp8616.return_addr is not None:
                    record_direct_target_caller_return_use_evidence_8616(
                        self.project,
                        _call_target_lp8616.target_addr,
                        binary_path=self.args.binary,
                    )
        return None
    def _phase_direct_helper_model_8616(self) -> int | None:
        """Run an extracted `_run_direct_addr_cli_8616` phase; return an exit code to abort."""
        if isinstance(self.known_helper_model, str):
            self.helper_snapshot: dict[str, object] = {
                "structuring": {
                    "status": "stable",
                    "mode": "helper_model",
                    "changed": False,
                    "detail": f"known compiler/runtime helper model: {self.func.name}",
                },
                "postprocess": {
                    "status": "stable",
                    "mode": "helper_model",
                    "changed": False,
                    "detail": f"known compiler/runtime helper model: {self.func.name}",
                },
            }
            self.helper_result = FunctionWorkResult(
                index=1,
                status=WorkItemStatus.OK.value,
                payload=self.known_helper_model,
                debug_output="",
                function=self.func,
                function_cfg=self.cfg,
                tail_validation=self.helper_snapshot,
            )
            if _complete_serial_clean_worker_result_8616(self.helper_result, project=self.direct_project):
                return 0
            print(
                "[dbg] direct failure family: status=ok stage=helper_model sidecar=not_applicable "
                "nonopt=not_needed fallback=direct_addr validation=passed",
                file=sys.stderr,
            )
            _emit_tail_validation_snapshot_or_uncollected(
                self.cfg,
                self.func,
                self.helper_snapshot,
                binary_path=self.args.binary,
            )
            _emit_optional_source_sidecar_c_block(
                self.args.binary,
                self.func.name,
                self.known_helper_model,
                alternate_source_c=bool(self.args.alternate_source_c),
                c_header="\n/* == c == */",
            )
            return 0
        return None

    def _phase_direct_cache_failure_8616(self) -> int | None:
        """Run an extracted `_run_direct_addr_cli_8616` phase; return an exit code to abort."""
        if self.direct_cache_result is not None and self.direct_cache_result.failure_family_snapshot is not None:
            if self.direct_cache_debug:
                print(self.direct_cache_debug, file=sys.stderr, end="")
            self.cached_direct_result = replace(
                self.direct_cache_result,
                function=self.func,
                function_cfg=self.cfg,
            )
            _store_direct_request_result_8616(
                self.context,
                self.direct_request_cache_lookup,
                self.cached_direct_result,
                function_addr=function_original_addr(self.func),
                function_name=self.func.name,
            )
            return _emit_direct_cache_hit_8616(
                self.context,
                self.cached_direct_result,
                function=self.func,
                function_cfg=self.cfg,
                emit_function_header=False,
                project_for_worker_result=self.direct_project,
            )
        return None

    def _phase_direct_known_cache_8616(self) -> int | None:
        """Run an extracted `_run_direct_addr_cli_8616` phase; return an exit code to abort."""
        if (
            self.canonical_direct_addr is not None
            and self.canonical_direct_addr.requested_addr != self.canonical_direct_addr.canonical_addr
            and not self.args.ignore_local_sidecar_hints
        ):
            assert self.lst_metadata is not None
            self.cached_clean_status = _run_canonicalized_direct_clean_worker_8616(
                self.project,
                self.args,
                self.lst_metadata,
                self.canonical_direct_addr,
                function_label=self.function_label,
                caller_return_evidence_by_addr=self.clean_worker_caller_return_evidence_by_addr,
                cache_only=True,
            )
            if self.cached_clean_status is not None:
                return cast(int | None, self.cached_clean_status)
        return None

    def _phase_direct_probe_recovery_8616(self) -> int | None:
        """Run an extracted `_run_direct_addr_cli_8616` phase; return an exit code to abort."""
        _rc = self._phase_direct_probe_recovery_8616_part0_8616()
        if _rc is not None:
            return _rc
        return None

    def _phase_direct_status_sync_8616(self) -> int | None:
        """Run an extracted `_run_direct_addr_cli_8616` phase; return an exit code to abort."""
        if self.direct_status != self.direct_result.status or self.direct_blocker is not None:
            self.preserved_candidate = self._preserve_acceptance_candidate_or_best_failure(self.direct_acceptance, self.direct_result)
            self.direct_payload = self.direct_acceptance.gcc_checked_payload
        else:
            self.direct_payload = (
                self.direct_acceptance.gcc_checked_payload
                if self.direct_status is WorkItemStatus.OK
                else self.direct_result.payload
            )
            self.preserved_candidate = self.direct_result.partial_payload
        return None

    def _phase_direct_empty_lanes_8616(self) -> int | None:
        """Run an extracted `_run_direct_addr_cli_8616` phase; return an exit code to abort."""
        if (
            self.direct_result.status == "empty"
            and isinstance(self.direct_result.partial_payload, str)
            and self.direct_result.partial_payload.strip()
        ):
            self.partial_acceptance = _validated_generated_c_acceptance_8616(
                status="ok",
                payload=self.direct_result.partial_payload,
                tail_validation_snapshot=self.direct_result.tail_validation,
                tail_validation_enabled=_tail_validation_runtime_enabled(self.direct_project),
                expected_validation_stages=["structuring", "postprocess"],
                c_target=getattr(self.direct_project, "_inertia_c_target", "portable-flat"),
                emit_failure_diagnostics=False,
            )
            if self.partial_acceptance.status == "ok" and self.partial_acceptance.blocker is None:
                self.direct_result = replace(
                    self.direct_result,
                    status="ok",
                    payload=self.partial_acceptance.gcc_checked_payload,
                    partial_payload=None,
                    validated_payload_hash=self.partial_acceptance.validated_payload_hash,
                    gcc_checked_payload_hash=self.partial_acceptance.gcc_checked_payload_hash,
                )
        return None

    def _phase_direct_light_lanes_8616(self) -> int | None:
        """Run an extracted `_run_direct_addr_cli_8616` phase; return an exit code to abort."""
        if (
            self.canonical_direct_addr is not None
            and self.canonical_direct_addr.requested_addr != self.canonical_direct_addr.canonical_addr
            and not self.args.ignore_local_sidecar_hints
            and _work_item_status_8616(self.direct_result.status) is WorkItemStatus.VALIDATION_FAILED
        ):
            assert self.lst_metadata is not None
            return _run_canonicalized_direct_clean_worker_8616(
                self.project,
                self.args,
                self.lst_metadata,
                self.canonical_direct_addr,
                function_label=self.function_label,
                caller_return_evidence_by_addr=self.clean_worker_caller_return_evidence_by_addr,
            )
        return None

    def _phase_direct_heavy_lanes_8616(self) -> int | None:
        """Run an extracted `_run_direct_addr_cli_8616` phase; return an exit code to abort."""
        if self.direct_result.status != "ok":
            self.helper_model = (
                _try_emit_known_runtime_helper_c(name=getattr(self.func, "name", ""))
                if isinstance(getattr(self.func, "name", None), str)
                else None
            )
            if isinstance(self.helper_model, str):
                self.helper_snapshot = {
                    "structuring": {
                        "status": "stable",
                        "mode": "helper_model",
                        "changed": False,
                        "detail": f"known compiler/runtime helper model: {getattr(self.func, 'name', 'sub')}",
                    },
                    "postprocess": {
                        "status": "stable",
                        "mode": "helper_model",
                        "changed": False,
                        "detail": f"known compiler/runtime helper model: {getattr(self.func, 'name', 'sub')}",
                    },
                }
                self.helper_tail_validation_snapshot: dict[str, object] = dict(self.helper_snapshot)
                self.helper_acceptance = _validated_generated_c_acceptance_8616(
                    status="ok",
                    payload=self.helper_model,
                    tail_validation_snapshot=self.helper_tail_validation_snapshot,
                    tail_validation_enabled=_tail_validation_runtime_enabled(self.direct_project),
                    expected_validation_stages=["structuring", "postprocess"],
                    c_target=getattr(self.direct_project, "_inertia_c_target", "portable-flat"),
                    emit_failure_diagnostics=False,
                )
                self.helper_status = self.helper_acceptance.status
                self.helper_blocker = self.helper_acceptance.blocker
                self.helper_payload = self.helper_acceptance.gcc_checked_payload
                if self.helper_status == "ok" and self.helper_blocker is None:
                    self.direct_result = replace(
                        self.direct_result,
                        status=self.helper_status,
                        payload=self.helper_payload,
                        partial_payload=None,
                        tail_validation=self.helper_tail_validation_snapshot,
                        validated_payload_hash=self.helper_acceptance.validated_payload_hash,
                        gcc_checked_payload_hash=self.helper_acceptance.gcc_checked_payload_hash,
                    )
        return None

    def _phase_direct_failure_emit_8616(self) -> int | None:
        """Run an extracted `_run_direct_addr_cli_8616` phase; return an exit code to abort."""
        if (
            self.direct_result.status != "ok"
            and not self.clinic_core_timeout
            and _direct_addr_robust_retry_enabled_8616(timeout_was_explicit=self.timeout_was_explicit)
        ):
            # Robust direct-address retry lane: reuse the same function-work
            # decompile path as whole-file sweeps. This avoids direct-only
            # recovery/decompile divergence for functions that are stable in
            # the sweep lane but brittle in the thin direct lane.
            try:
                self.robust_blocks, self.robust_bytes = _function_complexity(self.func)
                self.robust_timeout = _effective_decompile_timeout_8616(
                    self.direct_project,
                    self.args.timeout,
                    block_count=self.robust_blocks,
                    byte_count=self.robust_bytes,
                )
                self.robust_item = FunctionWorkItem(index=1, function_cfg=self.cfg, function=self.func)
                self.robust_result = _run_function_work_item(
                    self.robust_item,
                    timeout=max(1, int(self.robust_timeout)),
                    api_style=self.args.api_style,
                    binary_path=self.args.binary,
                    lst_metadata=self.lst_metadata,
                    cod_metadata=self.cod_metadata,
                    synthetic_globals=self.synthetic_globals,
                    enable_structured_simplify=True,
                    enable_postprocess=True,
                    allow_isolated_retry=True,
                )
            except Exception:
                self.robust_result = None
            if self.robust_result is not None and self.robust_result.status == "ok":
                self.robust_snapshot = _tail_validation_snapshot_for_function_run(self.direct_project, self.func)
                if not self.robust_snapshot and isinstance(self.robust_result.tail_validation, dict):
                    self.robust_snapshot = self.robust_result.tail_validation
                self.robust_tail_validation_snapshot = self.robust_snapshot if self.robust_snapshot else None
                self.robust_acceptance = _validated_generated_c_acceptance_8616(
                    status="ok",
                    payload=self.robust_result.payload,
                    tail_validation_snapshot=self.robust_tail_validation_snapshot,
                    tail_validation_enabled=_tail_validation_runtime_enabled(self.direct_project),
                    expected_validation_stages=["structuring", "postprocess"],
                    c_target=getattr(self.direct_project, "_inertia_c_target", "portable-flat"),
                    emit_failure_diagnostics=False,
                )
                if self.robust_acceptance.status == "ok" and self.robust_acceptance.blocker is None:
                    self.direct_result = replace(
                        self.robust_result,
                        index=1,
                        function=self.func,
                        function_cfg=self.cfg,
                        payload=self.robust_acceptance.gcc_checked_payload,
                        tail_validation=self.robust_snapshot,
                        validated_payload_hash=self.robust_acceptance.validated_payload_hash,
                        gcc_checked_payload_hash=self.robust_acceptance.gcc_checked_payload_hash,
                    )
        return None

    def _phase_direct_serial_gate_8616(self) -> int | None:
        """Run an extracted `_run_direct_addr_cli_8616` phase; return an exit code to abort."""
        if self.direct_result.status == "timeout":
            _emit_tail_validation_snapshot_or_uncollected(
                self.cfg,
                self.func,
                self.direct_result.tail_validation,
                binary_path=self.args.binary,
            )
            print(f"[dbg] direct decompilation timeout detail: {self.direct_result.payload}", file=sys.stderr)
            print(f"\n/* Decompilation timeout: Timed out while recovering a function after {self.args.timeout}s during x86-16 function recovery. */")
            print("/* Direct decompilation timeout is terminal for this function; skipping fallback lanes. */\n/* Tip: try a larger --timeout for larger binaries. */")
            return 3
        return None

    def _phase_direct_emit_batch_8616(self) -> int | None:
        """Run an extracted `_run_direct_addr_cli_8616` phase; return an exit code to abort."""
        _rc = self._phase_direct_emit_batch_8616_part0_8616()
        if _rc is not None:
            return _rc
        return None

    def _phase_direct_integrity_8616(self) -> int | None:
        """Run an extracted `_run_direct_addr_cli_8616` phase; return an exit code to abort."""
        if self.integrity.verdict in {
            AcceptedPayloadIntegrityVerdict8616.MISSING_VALIDATED_HASH,
            AcceptedPayloadIntegrityVerdict8616.MISSING_COMPILER_HASH,
        }:
            self.direct_result = _accept_function_work_result_for_emission_8616(
                self.direct_result,
                project=self.direct_project,
            )
            self.integrity = verify_function_work_result_payload_integrity_8616(self.direct_result)
        return None

    def _phase_direct_cache_store_8616(self) -> int | None:
        """Run an extracted `_run_direct_addr_cli_8616` phase; return an exit code to abort."""
        if self.direct_cache_key is not None and self.direct_result.status == "ok":
            _store_cache_json(
                "function_decompile",
                self.direct_cache_key,
                {
                    "status": self.direct_result.status,
                    "payload": self.direct_result.payload,
                    "tail_validation": self.direct_result.tail_validation,
                    "tail_validation_passed": True,
                    "elapsed": self.direct_result.elapsed,
                    "block_count": self.direct_result.block_count,
                    "byte_count": self.direct_result.byte_count,
                    "validated_c_hash": self.direct_result.validated_payload_hash,
                    "gcc_checked_c_hash": self.direct_result.gcc_checked_payload_hash,
                    "diagnostic_output": (
                        self.direct_result.debug_output
                        if os.environ.get("INERTIA_ENABLE_TYPED_SWITCH_AST_ARTIFACTS") == "1"
                        else None
                    ),
                    "failure_family_snapshot": self.direct_failure_family_snapshot.to_record(),
                },
            )
        return None


    def run_8616_part0_8616(self) -> int | None:
        """Run an extracted sub-phase; return an exit code to abort."""
        """Run the direct-address CLI branch after project and sidecar setup."""
        self.args = self.context.args
        self.direct_addr = self.args.addr
        if self.direct_addr is None:
            raise ValueError("direct-address CLI branch requires args.addr")
        self.project = self.context.project
        self.direct_request_cache_lookup = load_direct_request_cache_8616(
            self.context.request_cache_inputs,
            enabled=direct_request_cache_enabled_8616(self.args),
        )
        _rc = self._phase_direct_header_8616()
        if _rc is not None:
            return _rc
        if self.direct_request_cache_lookup.verdict is DirectRequestCacheVerdict8616.REFUSED:
            print(
                "[dbg] direct request cache refused: acceptance_proof",
                file=sys.stderr,
                flush=True,
            )
        _hydrate_serial_clean_worker_evidence_8616(self.project)
        self.clean_worker_caller_return_evidence_by_addr = dict(caller_return_use_evidence_by_addr_8616(self.project))
        self.function_label = self.context.function_label
        self.cod_metadata = self.context.cod_metadata
        self.synthetic_globals = self.context.synthetic_globals
        self.lst_metadata = self.context.lst_metadata
        self.prefer_fast_recovery = self.context.prefer_fast_recovery
        self.proc_resolved_to_linked_binary = self.context.proc_resolved_to_linked_binary
        self.low_memory_path = self.context.low_memory_path
        self.interactive_stdout = self.context.interactive_stdout
        self.precise_sidecar_regions = self.context.precise_sidecar_regions
        return None
    def run_8616_part1_8616(self) -> int | None:
        """Run an extracted sub-phase; return an exit code to abort."""
        self.timeout_was_explicit = self.context.timeout_was_explicit
        print("/* recovering function... */", flush=True)
        self.fast_direct_probe_requested = os.environ.get("INERTIA_FAST_DIRECT_PROBE", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        self.fast_direct_probe = bool(
            self.fast_direct_probe_requested and self.timeout_was_explicit and isinstance(self.args.timeout, int) and self.args.timeout <= 6
        )
        self.direct_budget_timeout = self.args.timeout
        if self.project.arch.name == "86_16" and not self.fast_direct_probe:
            # Keep direct-address recovery deterministic under explicit user
            # timeout; avoid inflating into outer subprocess timeouts.
            if self.timeout_was_explicit and isinstance(self.args.timeout, int):
                self.direct_budget_timeout = max(self.args.timeout, 1)
            else:
                self.direct_budget_timeout = max(self.direct_budget_timeout, 24)
        self.direct_addr_started_at = time.monotonic()
        self.direct_addr_deadline = self.direct_addr_started_at + _direct_addr_wall_clock_budget(
            self.args.timeout,
            effective_timeout=self.direct_budget_timeout,
            explicit_timeout=bool(self.timeout_was_explicit),
        )
        self.budget_fallback_addr: int | None = None
        self.budget_fallback_name: str | None = None
        self.canonical_direct_addr = _canonicalize_direct_addr_from_sidecar_padding_8616(
            self.project,
            self.lst_metadata,
            self.direct_addr,
            function_label=self.function_label,
        )
        return None
    def run_8616_part2_8616(self) -> int | None:
        """Run an extracted sub-phase; return an exit code to abort."""
        if self.canonical_direct_addr is not None:
            print(
                "/* direct address canonicalized from "
                f"{self.canonical_direct_addr.requested_addr:#x} to {self.canonical_direct_addr.canonical_addr:#x} "
                "using sidecar padding/prologue evidence */",
                file=sys.stderr,
                flush=True,
            )
            self.direct_addr = self.canonical_direct_addr.canonical_addr
            self.args.addr = self.direct_addr
            if self.function_label is None and self.canonical_direct_addr.name:
                self.function_label = self.canonical_direct_addr.name
        _rc = self._phase_direct_cfg_recovery_8616()
        if _rc is not None:
            return _rc
        if self.project.arch.name == "86_16":
            record_direct_target_caller_return_use_evidence_8616(
                self.project,
                self.direct_addr,
                binary_path=self.args.binary,
            )
        _rc = self._phase_direct_probe_setup_8616()
        if _rc is not None:
            return _rc
        _rc = self._phase_direct_catalog_8616()
        if _rc is not None:
            return _rc
        if self.function_label is not None:
            self.func.name = self.function_label
        elif self.lst_metadata is not None:
            self.code_name = self.lst_metadata.code_labels.get(function_original_addr(self.func))
            if self.code_name is not None:
                self.func.name = self.code_name
        return None
    def run_8616_part3_8616(self) -> int | None:
        """Run an extracted sub-phase; return an exit code to abort."""
        self.direct_project = getattr(self.func, "project", self.project)
        _rc = self._phase_direct_fast_probe_8616()
        if _rc is not None:
            return _rc
        _transfer_caller_return_use_evidence_8616(self.project, self.direct_project)
        typing.cast(typing.Any, self.direct_project)._inertia_trace_c_stages = bool(self.args.trace_c_stages)
        typing.cast(typing.Any, self.direct_project)._inertia_dump_layers = bool(self.args.dump_layers)
        typing.cast(typing.Any, self.direct_project)._inertia_dump_layer_root = self.args.dump_layer_dir
        typing.cast(typing.Any, self.direct_project)._inertia_dump_layer_filter = self.args.dump_layer_filter
        if bool(self.args.alternate_source_c) and getattr(self.project.arch, "name", "") == "86_16":
            typing.cast(typing.Any, self.direct_project)._inertia_enable_typed_switch_seqnode_replacement_8616 = True
        _apply_binary_specific_annotations(
            self.direct_project,
            self.args.binary,
            self.lst_metadata,
            func_addr=function_original_addr(self.func),
            cod_metadata=self.cod_metadata,
            synthetic_globals=self.synthetic_globals,
        )
        print(f"/* binary: {self.args.binary} */")
        print(f"/* arch: {self.project.arch.name} */")
        print(f"/* entry: {self.project.entry:#x} */")
        print(f"/* function: {function_original_addr(self.func):#x} {self.func.name} */")
        if self.args.show_asm:
            print("\n/* == asm == */")
            print(_format_first_block_asm(self.direct_project, self.func.addr))
        self.known_helper_model = _try_emit_known_runtime_helper_c(name=getattr(self.func, "name", ""))
        _rc = self._phase_direct_helper_model_8616()
        if _rc is not None:
            return _rc
        return None
    def run_8616_part4_8616(self) -> int | None:
        """Run an extracted sub-phase; return an exit code to abort."""
        self.direct_cache_item = FunctionWorkItem(index=1, function_cfg=self.cfg, function=self.func)
        self.direct_cache_result, self.direct_cache_debug, self.direct_cache_key, self._, self._ = _function_work_cache_lookup(
            self.direct_cache_item,
            binary_path=self.args.binary,
            timeout=max(1, int(self.args.timeout)),
            api_style=self.args.api_style,
            enable_structured_simplify=True,
            enable_postprocess=True,
            cod_metadata=self.cod_metadata,
            synthetic_globals=self.synthetic_globals,
            lst_metadata=self.lst_metadata,
        )
        _rc = self._phase_direct_cache_failure_8616()
        if _rc is not None:
            return _rc
        _rc = self._phase_direct_known_cache_8616()
        if _rc is not None:
            return _rc
        print("/* decompiling... */", flush=True)
        self.direct_tail_validation_snapshot: dict[str, object] | None = None
        self.direct_segment_program_evidence: SegmentProgramFunctionEvidence8616 | None = None
        self.direct_failure_family_state = FailureFamilyState()
        self.direct_sidecar_verdict = "not_attempted"
        self.direct_nonoptimized_verdict = "not_attempted"
        self.direct_timeout_stage: str | None = None
        self.direct_debug_output = ""
        self._block_count, self._byte_count = _function_complexity(self.func)
        self._elapsed = 0.0
        _rc = self._phase_direct_probe_recovery_8616()
        if _rc is not None:
            return _rc
        return None
    def run_8616_part5_8616(self) -> int | None:
        """Run an extracted sub-phase; return an exit code to abort."""
        _rc = self.run_8616_part5_8616_b0()
        if _rc is not None:
            return _rc
        _rc = self.run_8616_part5_8616_b1()
        if _rc is not None:
            return _rc
        _rc = self.run_8616_part5_8616_b2()
        if _rc is not None:
            return _rc
        return None
    def _phase_direct_cfg_recovery_8616_part0_8616(self) -> int | None:
        """Run an extracted sub-phase; return an exit code to abort."""
        try:


            _rc = self._phase_direct_cfg_recovery_8616_part0_8616_zb0()
            if _rc is not None:
                return _rc
            _rc = self._phase_direct_cfg_recovery_8616_part0_8616_zb1()
            if _rc is not None:
                return _rc
        except _AnalysisTimeout:
            _rc = self._phase_direct_cfg_recovery_8616_part0_8616_zh0()
            if _rc is not None:
                return _rc
        except FuturesTimeoutError:
            _rc = self._phase_direct_cfg_recovery_8616_part0_8616_zh1()
            if _rc is not None:
                return _rc
        except Exception as ex:
            _rc = self._phase_direct_cfg_recovery_8616_part0_8616_zh2(ex)
            if _rc is not None:
                return _rc
        return None
    def _phase_direct_probe_recovery_8616_part0_8616(self) -> int | None:
        """Run an extracted sub-phase; return an exit code to abort."""
        try:


            # The inner decompilation path already enforces the analysis deadline.
            # Give the forked direct-address wrapper a few extra seconds to merge
            # tail-validation snapshots and serialize the result back to the parent.
            _rc = self._phase_direct_probe_recovery_8616_part0_8616_b0()
            if _rc is not None:
                return _rc
            _rc = self._phase_direct_probe_recovery_8616_part0_8616_b1()
            if _rc is not None:
                return _rc
        except FuturesTimeoutError:
            self.status = "timeout"
            self.payload = f"Timed out after {self.direct_decompile_timeout}s."
            self.partial_payload = None
            self._elapsed = max(0.0, time.monotonic() - self.direct_addr_started_at)
            self.direct_timeout_stage = _direct_timeout_failure_stage_from_payload(self.payload, default="decompilation")
        else:
            self.direct_timeout_stage = (
                _direct_timeout_failure_stage_from_payload(
                    self.payload,
                    default="decompilation",
                )
                if self.status == "timeout"
                else None
            )
        return None
    def _phase_direct_emit_batch_8616_part0_8616(self) -> int | None:
        """Run an extracted sub-phase; return an exit code to abort."""
        if self.direct_result.status != "ok":



            # Repeated direct runs can land on different internal lanes. Keep
            # the least raw/unresolved candidate before heavy fallback fan-out.
            _rc = self._phase_direct_emit_batch_8616_part0_8616_zb0()
            if _rc is not None:
                return _rc
            _rc = self._phase_direct_emit_batch_8616_part0_8616_zb1()
            if _rc is not None:
                return _rc
        return None


    def run_8616_part5_8616_b0(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        self.direct_item = FunctionWorkItem(index=1, function_cfg=self.cfg, function=self.func)
        self.direct_result = FunctionWorkResult(
            index=1,
            status=self.status,
            payload=self.payload,
            debug_output=self.direct_debug_output,
            function=self.func,
            function_cfg=self.cfg,
            partial_payload=self.partial_payload,
            failure_stage=self.direct_timeout_stage,
            tail_validation=self.direct_tail_validation_snapshot
            or _tail_validation_snapshot_for_function_run(self.direct_project, self.func),
            elapsed=self._elapsed,
            block_count=self._block_count,
            byte_count=self._byte_count,
            segment_program_function_evidence=self.direct_segment_program_evidence,
        )
        self.direct_acceptance = _validated_generated_c_acceptance_8616(
            status=self.direct_result.status,
            payload=self.direct_result.payload,
            tail_validation_snapshot=self.direct_result.tail_validation,
            tail_validation_enabled=_tail_validation_runtime_enabled(self.direct_project),
            expected_validation_stages=["structuring", "postprocess"],
            c_target=getattr(self.direct_project, "_inertia_c_target", "portable-flat"),
            emit_failure_diagnostics=_env_truthy_8616("INERTIA_DUMP_VALIDATION_FAILED_PAYLOAD"),
        )
        self.direct_status = self.direct_acceptance.status
        self.direct_blocker = self.direct_acceptance.blocker
        _rc = self._phase_direct_status_sync_8616()
        if _rc is not None:
            return _rc
        self.direct_result = replace(
            self.direct_result,
            status=self.direct_status,
            payload=self.direct_blocker if self.direct_blocker is not None else self.direct_payload,
            partial_payload=self.preserved_candidate if self.direct_blocker is not None else self.direct_result.partial_payload,
            validated_payload_hash=(self.direct_acceptance.validated_payload_hash if self.direct_blocker is None else None),
            gcc_checked_payload_hash=(self.direct_acceptance.gcc_checked_payload_hash if self.direct_blocker is None else None),
        )
        if self.direct_status == "validation_failed" and isinstance(self.direct_result.tail_validation, dict):
            typing.cast(typing.Any, self.direct_project)._inertia_forced_tail_validation_snapshot = dict(self.direct_result.tail_validation)
        return None
    def run_8616_part5_8616_b1(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        _rc = self.run_8616_part5_8616_b1_s0()
        if _rc is not None:
            return _rc
        _rc = self.run_8616_part5_8616_b1_s1()
        if _rc is not None:
            return _rc
        return None
    def run_8616_part5_8616_b2(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        _rc = self._phase_direct_serial_gate_8616()
        if _rc is not None:
            return _rc
        _rc = self._phase_direct_emit_batch_8616()
        if _rc is not None:
            return _rc
        self.integrity = verify_function_work_result_payload_integrity_8616(self.direct_result)
        _rc = self._phase_direct_integrity_8616()
        if _rc is not None:
            return _rc
        if not self.integrity.passed:
            print(f"[tail-validation] {self.integrity.diagnostic()}", file=sys.stderr, flush=True)
            return 4
        _emit_tail_validation_console_summary([self.direct_item], {1: self.direct_result}, binary_path=self.args.binary)
        _store_direct_request_result_8616(
            self.context,
            self.direct_request_cache_lookup,
            self.direct_result,
            function_addr=function_original_addr(self.func),
            function_name=self.func.name,
        )
        if self.args.output_c_dir is not None:
            write_generated_function_c(
                self.args.output_c_dir,
                address=function_original_addr(self.func),
                name=self.func.name,
                payload=self.direct_result.payload,
            )
        _emit_optional_source_sidecar_c_block(
            self.args.binary,
            self.func.name,
            self.direct_result.payload,
            alternate_source_c=bool(self.args.alternate_source_c),
            c_header="\n/* == c == */",
        )
        _rc = self._phase_direct_cache_store_8616()
        if _rc is not None:
            return _rc
        _write_serial_clean_worker_result_8616(self.direct_result, project=self.direct_project)
        return 0
    def _phase_direct_cfg_recovery_8616_part0_8616_e00(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        self._enforce_direct_addr_budget_timeout()
        self.sidecar_region = _lst_code_region(self.lst_metadata, self.direct_addr) if self.lst_metadata is not None else None
        return None
    def _phase_direct_cfg_recovery_8616_part0_8616_e01(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        if self.precise_sidecar_regions and self.sidecar_region is not None:
            self.code_name = _lst_code_label(self.lst_metadata, self.sidecar_region[0], self.project.entry) or f"sub_{self.direct_addr:x}"
            self.slice_result = _try_decompile_sidecar_slice(
                self.project,
                self.lst_metadata,
                self.sidecar_region[0],
                self.code_name,
                timeout=max(1, min(self.args.timeout, self._remaining_direct_addr_budget() or 1)),
                api_style=self.args.api_style,
                binary_path=self.args.binary,
            )
            if self.slice_result is not None and self.slice_result.status == "ok":
                self.fallback_function = SimpleNamespace(addr=self.sidecar_region[0], name=self.code_name)
                print("/* Function recovery timed out; recovered function slice from sidecar bounds. */")
                print(f"/* binary: {self.args.binary} */")
                print(f"/* arch: {self.project.arch.name} */")
                print(f"/* entry: {self.project.entry:#x} */")
                print(f"/* function: {self.sidecar_region[0]:#x} {self.code_name} */")
                _emit_tail_validation_for_function_run_or_uncollected(
                    self.project,
                    None,
                    self.fallback_function,
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("sidecar_slice"),
                    binary_path=self.args.binary,
                )
                _emit_optional_source_sidecar_c_block(
                    self.args.binary,
                    self.code_name,
                    self.slice_result.payload,
                    alternate_source_c=bool(self.args.alternate_source_c),
                    c_header="\n/* == c == */",
                )
                return 0
            self._enforce_direct_addr_budget_timeout()
            self.nonopt_result: NonOptimizedSliceOutcome | str | None = _try_decompile_non_optimized_slice(
                self.project,
                self.sidecar_region[0],
                self.code_name,
                timeout=max(1, min(_bounded_non_optimized_timeout(self.args.timeout), self._remaining_direct_addr_budget() or 1)),
                api_style=self.args.api_style,
                binary_path=self.args.binary,
                lst_metadata=self.lst_metadata,
                cod_metadata=self.cod_metadata,
            )
            self.nonopt_c = _non_optimized_slice_rendered(self.nonopt_result)
            if self.nonopt_c is not None:
                self.fallback_function = SimpleNamespace(addr=self.sidecar_region[0], name=self.code_name)
                print("/* Function recovery timed out; produced non-optimized slice decompilation. */")
                print(f"/* binary: {self.args.binary} */")
                print(f"/* arch: {self.project.arch.name} */")
                print(f"/* entry: {self.project.entry:#x} */")
                print(f"/* function: {self.sidecar_region[0]:#x} {self.code_name} */")
                _emit_tail_validation_for_function_run_or_uncollected(
                    self.project,
                    None,
                    self.fallback_function,
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
                    binary_path=self.args.binary,
                )
                _emit_optional_source_sidecar_c_block(
                    self.args.binary,
                    self.code_name,
                    self.nonopt_c,
                    alternate_source_c=bool(self.args.alternate_source_c),
                    c_header="\n/* == c (non-optimized fallback) == */",
                )
                return 0
            self.string_c = _try_emit_string_intrinsic_c(
                self.project,
                start=self.sidecar_region[0],
                end=self.sidecar_region[1],
                name=self.code_name,
            )
            if self.string_c is not None:
                print(
                    "/* Function recovery timed out; emitted generic string-intrinsic fallback from sidecar bounds. */"
                )
                print(f"/* binary: {self.args.binary} */")
                print(f"/* arch: {self.project.arch.name} */")
                print(f"/* entry: {self.project.entry:#x} */")
                print(f"/* function: {self.sidecar_region[0]:#x} {self.code_name} */")
                _emit_tail_validation_for_function_run_or_uncollected(
                    self.project,
                    None,
                    SimpleNamespace(addr=self.sidecar_region[0], name=self.code_name),
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("string_intrinsic"),
                    binary_path=self.args.binary,
                )
                _emit_optional_source_sidecar_c_block(
                    self.args.binary,
                    self.code_name,
                    self.string_c,
                    alternate_source_c=bool(self.args.alternate_source_c),
                    c_header="\n/* == c (string intrinsic fallback) == */",
                )
                return 0
            print("/* Function recovery timed out; using sidecar-bounded asm fallback. */")
            print("/* direct validation=failed */")
            _emit_failed_timeout_acceptance_hints_8616()
            print(f"/* binary: {self.args.binary} */")
            print(f"/* arch: {self.project.arch.name} */")
            print(f"/* entry: {self.project.entry:#x} */")
            print(f"/* function: {self.sidecar_region[0]:#x} {self.code_name} */")
            _emit_tail_validation_for_function_run_or_uncollected(
                self.project,
                None,
                SimpleNamespace(addr=self.sidecar_region[0], name=self.code_name),
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("asm"),
                binary_path=self.args.binary,
            )
            print("\n/* == asm fallback == */")
            print(_format_asm_range(self.project, self.sidecar_region[0], self.sidecar_region[1]))
            return 4
        return None
    def _phase_direct_cfg_recovery_8616_part0_8616_e02(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        self.nonopt_result = None
        self._enforce_direct_addr_budget_timeout()
        self.nonopt_result = _try_decompile_non_optimized_slice(
            self.project,
            self.direct_addr,
            self.function_label or f"sub_{self.direct_addr:x}",
            timeout=max(1, min(_bounded_non_optimized_timeout(self.args.timeout), self._remaining_direct_addr_budget() or 1)),
            api_style=self.args.api_style,
            binary_path=self.args.binary,
            lst_metadata=self.lst_metadata,
            cod_metadata=self.cod_metadata,
        )
        self.nonopt_c = _non_optimized_slice_rendered(self.nonopt_result)
        if self.nonopt_c is not None:
            self.fallback_function = SimpleNamespace(addr=self.direct_addr, name=self.function_label or f"sub_{self.direct_addr:x}")
            print("/* Function recovery timed out; produced non-optimized slice decompilation. */")
            print(f"/* binary: {self.args.binary} */")
            print(f"/* arch: {self.project.arch.name} */")
            print(f"/* entry: {self.project.entry:#x} */")
            print(f"/* function: {self.direct_addr:#x} {self.function_label or f'sub_{self.direct_addr:x}'} */")
            _emit_tail_validation_for_function_run_or_uncollected(
                self.project,
                None,
                self.fallback_function,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
                binary_path=self.args.binary,
            )
            _emit_optional_source_sidecar_c_block(
                self.args.binary,
                self.fallback_function.name,
                self.nonopt_c,
                alternate_source_c=bool(self.args.alternate_source_c),
                c_header="\n/* == c (non-optimized fallback) == */",
            )
            return 0
        self.fallback_function = SimpleNamespace(addr=self.direct_addr, name=self.function_label or f"sub_{self.direct_addr:x}")
        self.start, self.end = _infer_linear_disassembly_window(self.project, self.direct_addr)
        self.string_c = _try_emit_string_intrinsic_c(
            self.project,
            start=self.start,
            end=self.end,
            name=self.fallback_function.name,
        )
        return None
    def _phase_direct_cfg_recovery_8616_part0_8616_e03(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        if self.string_c is not None:
            print("/* Function recovery timed out; emitted generic string-intrinsic fallback. */")
            print(f"/* binary: {self.args.binary} */")
            print(f"/* arch: {self.project.arch.name} */")
            print(f"/* entry: {self.project.entry:#x} */")
            print(f"/* function: {self.direct_addr:#x} {self.fallback_function.name} */")
            _emit_tail_validation_for_function_run_or_uncollected(
                self.project,
                None,
                self.fallback_function,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("string_intrinsic"),
                binary_path=self.args.binary,
            )
            self.nonopt_skip_reason = describe_non_optimized_unavailable(
                allow_heavy_fallbacks=True,
                skip_heavy_fallbacks_for_result=False,
                interactive_stdout=self.interactive_stdout,
                max_functions=self.args.max_functions,
                addr_requested=self.direct_addr is not None,
                result_status="timeout",
                failure_stage=None,
                nonopt_failure_detail=_non_optimized_slice_failure_detail(self.nonopt_result),
            )
            if self.nonopt_skip_reason is not None:
                print(f"/* non-optimized fallback unavailable: {self.nonopt_skip_reason} */")
            _emit_optional_source_sidecar_c_block(
                self.args.binary,
                self.fallback_function.name,
                self.string_c,
                alternate_source_c=bool(self.args.alternate_source_c),
                c_header="\n/* == c (string intrinsic fallback) == */",
            )
            return 0
        self.asm_fallback = _format_asm_range(self.project, self.start, self.end)
        self.recovery_detail = _function_recovery_detail(getattr(self.project, "_inertia_decompiler_stage", None))
        if self.recovery_detail is None:
            self.recovery_detail = "during x86-16 function recovery (direct-address path)"
        print(f"/* timeout: function {self.direct_addr:#x} {self.function_label or f'sub_{self.direct_addr:x}'} */")
        self._stored_snapshot = getattr(self.project, "_inertia_last_tail_validation_snapshot", None)
        if isinstance(self._stored_snapshot, dict) and self._stored_snapshot:
            for __diag_line_lp8616 in _format_tail_validation_diagnostic(
                self.direct_result.tail_validation,
                function_addr=self.func.addr,
                function_name=self.func.name,
                block_count=self.direct_result.block_count,
                byte_count=self.direct_result.byte_count,
                exit_kind=self.direct_result.status,
                exit_detail=self.direct_result.payload,
            ):
                self._diag_line = __diag_line_lp8616
                print(__diag_line_lp8616)
        _emit_timeout_and_exit(self.args.timeout, self.recovery_detail)
        return None
    def _phase_direct_cfg_recovery_8616_part0_8616_e10(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        self._enforce_direct_addr_budget_timeout()
        self.sidecar_region = _lst_code_region(self.lst_metadata, self.direct_addr) if self.lst_metadata is not None else None
        return None
    def _phase_direct_cfg_recovery_8616_part0_8616_e11(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        if self.precise_sidecar_regions and self.sidecar_region is not None:
            self.code_name = _lst_code_label(self.lst_metadata, self.sidecar_region[0], self.project.entry) or f"sub_{self.direct_addr:x}"
            self.slice_result = _try_decompile_sidecar_slice(
                self.project,
                self.lst_metadata,
                self.sidecar_region[0],
                self.code_name,
                timeout=max(1, min(self.args.timeout, self._remaining_direct_addr_budget() or 1)),
                api_style=self.args.api_style,
                binary_path=self.args.binary,
            )
            if self.slice_result is not None and self.slice_result.status == "ok":
                self.fallback_function = SimpleNamespace(addr=self.sidecar_region[0], name=self.code_name)
                print("/* Function recovery timed out; recovered function slice from sidecar bounds. */")
                print(f"/* binary: {self.args.binary} */")
                print(f"/* arch: {self.project.arch.name} */")
                print(f"/* entry: {self.project.entry:#x} */")
                print(f"/* function: {self.sidecar_region[0]:#x} {self.code_name} */")
                _emit_tail_validation_for_function_run_or_uncollected(
                    self.project,
                    None,
                    self.fallback_function,
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("sidecar_slice"),
                    binary_path=self.args.binary,
                )
                _emit_optional_source_sidecar_c_block(
                    self.args.binary,
                    self.code_name,
                    self.slice_result.payload,
                    alternate_source_c=bool(self.args.alternate_source_c),
                    c_header="\n/* == c == */",
                )
                return 0
            self._enforce_direct_addr_budget_timeout()
            self.nonopt_result = _try_decompile_non_optimized_slice(
                self.project,
                self.sidecar_region[0],
                self.code_name,
                timeout=max(1, min(_bounded_non_optimized_timeout(self.args.timeout), self._remaining_direct_addr_budget() or 1)),
                api_style=self.args.api_style,
                binary_path=self.args.binary,
                lst_metadata=self.lst_metadata,
                cod_metadata=self.cod_metadata,
            )
            self.nonopt_c = _non_optimized_slice_rendered(self.nonopt_result)
            if self.nonopt_c is not None:
                self.fallback_function = SimpleNamespace(addr=self.sidecar_region[0], name=self.code_name)
                print("/* Function recovery timed out; produced non-optimized slice decompilation. */")
                print(f"/* binary: {self.args.binary} */")
                print(f"/* arch: {self.project.arch.name} */")
                print(f"/* entry: {self.project.entry:#x} */")
                print(f"/* function: {self.sidecar_region[0]:#x} {self.code_name} */")
                _emit_tail_validation_for_function_run_or_uncollected(
                    self.project,
                    None,
                    self.fallback_function,
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
                    binary_path=self.args.binary,
                )
                _emit_optional_source_sidecar_c_block(
                    self.args.binary,
                    self.code_name,
                    self.nonopt_c,
                    alternate_source_c=bool(self.args.alternate_source_c),
                    c_header="\n/* == c (non-optimized fallback) == */",
                )
                return 0
            self.string_c = _try_emit_string_intrinsic_c(
                self.project,
                start=self.sidecar_region[0],
                end=self.sidecar_region[1],
                name=self.code_name,
            )
            if self.string_c is not None:
                print(
                    "/* Function recovery timed out; emitted generic string-intrinsic fallback from sidecar bounds. */"
                )
                print(f"/* binary: {self.args.binary} */")
                print(f"/* arch: {self.project.arch.name} */")
                print(f"/* entry: {self.project.entry:#x} */")
                print(f"/* function: {self.sidecar_region[0]:#x} {self.code_name} */")
                _emit_tail_validation_for_function_run_or_uncollected(
                    self.project,
                    None,
                    SimpleNamespace(addr=self.sidecar_region[0], name=self.code_name),
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("string_intrinsic"),
                    binary_path=self.args.binary,
                )
                _emit_optional_source_sidecar_c_block(
                    self.args.binary,
                    self.code_name,
                    self.string_c,
                    alternate_source_c=bool(self.args.alternate_source_c),
                    c_header="\n/* == c (string intrinsic fallback) == */",
                )
                return 0
            print("/* Function recovery timed out; using sidecar-bounded asm fallback. */")
            print("/* direct validation=failed */")
            _emit_failed_timeout_acceptance_hints_8616()
            print(f"/* binary: {self.args.binary} */")
            print(f"/* arch: {self.project.arch.name} */")
            print(f"/* entry: {self.project.entry:#x} */")
            print(f"/* function: {self.sidecar_region[0]:#x} {self.code_name} */")
            _emit_tail_validation_for_function_run_or_uncollected(
                self.project,
                None,
                SimpleNamespace(addr=self.sidecar_region[0], name=self.code_name),
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("asm"),
                binary_path=self.args.binary,
            )
            print("\n/* == asm fallback == */")
            print(_format_asm_range(self.project, self.sidecar_region[0], self.sidecar_region[1]))
            return 4
        return None
    def _phase_direct_cfg_recovery_8616_part0_8616_e12(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        self.nonopt_result = None
        if self.precise_sidecar_regions:
            self._enforce_direct_addr_budget_timeout()
            self.nonopt_result = _try_decompile_non_optimized_slice(
                self.project,
                self.direct_addr,
                self.function_label or f"sub_{self.direct_addr:x}",
                timeout=max(1, min(_bounded_non_optimized_timeout(self.args.timeout), self._remaining_direct_addr_budget() or 1)),
                api_style=self.args.api_style,
                binary_path=self.args.binary,
                lst_metadata=self.lst_metadata,
                cod_metadata=self.cod_metadata,
            )
        self.nonopt_c = _non_optimized_slice_rendered(self.nonopt_result)
        if self.nonopt_c is not None:
            self.fallback_function = SimpleNamespace(addr=self.direct_addr, name=self.function_label or f"sub_{self.direct_addr:x}")
            print("/* Function recovery timed out; produced non-optimized slice decompilation. */")
            print(f"/* binary: {self.args.binary} */")
            print(f"/* arch: {self.project.arch.name} */")
            print(f"/* entry: {self.project.entry:#x} */")
            print(f"/* function: {self.direct_addr:#x} {self.function_label or f'sub_{self.direct_addr:x}'} */")
            _emit_tail_validation_for_function_run_or_uncollected(
                self.project,
                None,
                self.fallback_function,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
                binary_path=self.args.binary,
            )
            _emit_optional_source_sidecar_c_block(
                self.args.binary,
                self.fallback_function.name,
                self.nonopt_c,
                alternate_source_c=bool(self.args.alternate_source_c),
                c_header="\n/* == c (non-optimized fallback) == */",
            )
            return 0
        self.fallback_function = SimpleNamespace(addr=self.direct_addr, name=self.function_label or f"sub_{self.direct_addr:x}")
        self.start, self.end = _infer_linear_disassembly_window(self.project, self.direct_addr)
        self.string_c = _try_emit_string_intrinsic_c(
            self.project,
            start=self.start,
            end=self.end,
            name=self.fallback_function.name,
        )
        return None
    def _phase_direct_cfg_recovery_8616_part0_8616_e13(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        if self.string_c is not None:
            print("/* Function recovery timed out; emitted generic string-intrinsic fallback. */")
            print(f"/* binary: {self.args.binary} */")
            print(f"/* arch: {self.project.arch.name} */")
            print(f"/* entry: {self.project.entry:#x} */")
            print(f"/* function: {self.direct_addr:#x} {self.fallback_function.name} */")
            _emit_tail_validation_for_function_run_or_uncollected(
                self.project,
                None,
                self.fallback_function,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("string_intrinsic"),
                binary_path=self.args.binary,
            )
            self.nonopt_skip_reason = describe_non_optimized_unavailable(
                allow_heavy_fallbacks=True,
                skip_heavy_fallbacks_for_result=False,
                interactive_stdout=self.interactive_stdout,
                max_functions=self.args.max_functions,
                addr_requested=self.direct_addr is not None,
                result_status="timeout",
                failure_stage=None,
                nonopt_failure_detail=_non_optimized_slice_failure_detail(self.nonopt_result),
            )
            if self.nonopt_skip_reason is not None:
                print(f"/* non-optimized fallback unavailable: {self.nonopt_skip_reason} */")
            _emit_optional_source_sidecar_c_block(
                self.args.binary,
                self.fallback_function.name,
                self.string_c,
                alternate_source_c=bool(self.args.alternate_source_c),
                c_header="\n/* == c (string intrinsic fallback) == */",
            )
            return 0
        self.asm_fallback = _format_asm_range(self.project, self.start, self.end)
        self.recovery_detail = _function_recovery_detail(getattr(self.project, "_inertia_decompiler_stage", None))
        if self.recovery_detail is None:
            self.recovery_detail = "during x86-16 function recovery (direct-address path)"
        print(f"/* timeout: function {self.direct_addr:#x} {self.function_label or f'sub_{self.direct_addr:x}'} */")
        self._stored_snapshot = getattr(self.project, "_inertia_last_tail_validation_snapshot", None)
        if isinstance(self._stored_snapshot, dict) and self._stored_snapshot:
            for __diag_line_lp8616 in _format_tail_validation_diagnostic(
                self.direct_result.tail_validation,
                function_addr=self.func.addr,
                function_name=self.func.name,
                block_count=self.direct_result.block_count,
                byte_count=self.direct_result.byte_count,
                exit_kind=self.direct_result.status,
                exit_detail=self.direct_result.payload,
            ):
                self._diag_line = __diag_line_lp8616
                print(__diag_line_lp8616)
        _emit_timeout_and_exit(self.args.timeout, self.recovery_detail)
        return None
    def _phase_direct_probe_recovery_8616_part0_8616_b0(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        self._direct_blocks, self._direct_bytes = _function_complexity(self.func)
        self._direct_effective_timeout = _effective_decompile_timeout_8616(
            self.direct_project,
            self.args.timeout,
            block_count=self._direct_blocks,
            byte_count=self._direct_bytes,
        )
        self._direct_effective_timeout = self._direct_analysis_timeout_for_shape(
            self._direct_effective_timeout,
            self._direct_blocks,
            self._direct_bytes,
        )
        self.direct_addr_deadline = max(
            self.direct_addr_deadline,
            self.direct_addr_started_at
            + _direct_addr_wall_clock_budget(
                self.args.timeout,
                effective_timeout=self._direct_effective_timeout,
                explicit_timeout=bool(self.timeout_was_explicit),
            ),
        )
        self.direct_decompile_timeout = _enforce_function_timeout_cap(
            max(1, self._direct_effective_timeout) + 28,
            context="direct analysis wrapper timeout",
            explicit_timeout_floor=(max(1, self._direct_effective_timeout) + 28 if self.timeout_was_explicit else None),
        )
        if self.timeout_was_explicit and isinstance(self.args.timeout, int) and self.args.timeout <= 6:
            if self._direct_blocks >= 4 or self._direct_bytes >= 0x50:
                self.direct_decompile_timeout = min(self.direct_decompile_timeout, self.args.timeout + 20)
            else:
                self.direct_decompile_timeout = min(self.direct_decompile_timeout, self.args.timeout + 8)
            # For larger explicit x86-16 functions, retain the shape-aware
            # budget calculated above. Capping it to ``args.timeout + 32``
            # defeats the large-function allowance and turns normal xdist
            # contention into a false direct-decompilation timeout. The small
            # timeout lane remains deliberately bounded because it is used by
            # fast discovery probes rather than full function recovery.
        self.remaining_direct_budget = self._remaining_direct_addr_budget() or 1
        self.budgeted_direct_decompile_timeout = max(1, min(self.direct_decompile_timeout, self.remaining_direct_budget))
        self.direct_decompile_timeout = _enforce_function_timeout_cap(
            self.budgeted_direct_decompile_timeout,
            context="direct direct-address budget timeout",
            explicit_timeout_floor=(self.budgeted_direct_decompile_timeout if self.timeout_was_explicit else None),
        )
        self.use_fork_for_direct = _direct_addr_use_fork_lane_8616(
            tail_validation_enabled=_tail_validation_runtime_enabled(self.direct_project),
        )
        return None
    def _phase_direct_probe_recovery_8616_part0_8616_b1(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        with span(
            "direct.decompile_job",
            addr=hex(getattr(self.func, "addr", 0)),
            name=getattr(self.func, "name", None),
            timeout=self.direct_decompile_timeout,
            isolated="fork" if self.use_fork_for_direct else "thread",
            blocks=self._direct_blocks,
            bytes=self._direct_bytes,
        ):
            if self.use_fork_for_direct:
                self.direct_job_result = _run_with_timeout_in_fork(
                        self.direct_decompile_job,
                        timeout=self.direct_decompile_timeout,
                    )
            else:
                self.direct_job_result = _run_with_timeout_in_daemon_thread(
                        self.direct_decompile_job,
                        timeout=self.direct_decompile_timeout,
                        thread_name_prefix="direct-decomp",
                    )
            self.status, self.payload, self.partial_payload, self._block_count, self._byte_count, self._elapsed, *self.direct_extra = self.direct_job_result
            annotate_current_span(status=self.status)
            for _extra_lp8616 in self.direct_extra:
                self.extra = _extra_lp8616
                if isinstance(_extra_lp8616, dict):
                    self.direct_tail_validation_snapshot = dict(_extra_lp8616)
                elif isinstance(_extra_lp8616, SegmentProgramFunctionEvidence8616):
                    self.direct_segment_program_evidence = _extra_lp8616
                elif isinstance(_extra_lp8616, FailureFamilyState):
                    self.direct_failure_family_state.previous_snapshot = _extra_lp8616.previous_snapshot
                    self.direct_failure_family_state.candidate_snapshot = _extra_lp8616.candidate_snapshot
                    self.direct_failure_family_state.new_proof_seen = _extra_lp8616.new_proof_seen
                    self.direct_failure_family_state.repeat_detected = _extra_lp8616.repeat_detected
                elif isinstance(_extra_lp8616, str):
                    self.direct_debug_output = _extra_lp8616
        return None
    def _phase_direct_emit_batch_8616_part0_8616_b0(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        if self.direct_result.status == "validation_failed":
            _rc = self._phase_direct_emit_batch_8616_part0_8616_b0_zb0()
            if _rc is not None:
                return _rc
            _rc = self._phase_direct_emit_batch_8616_part0_8616_b0_zb1()
            if _rc is not None:
                return _rc
        return None
    def _phase_direct_emit_batch_8616_part0_8616_b1(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        self._enforce_direct_addr_budget_timeout(recovery_detail="after exhausting direct-address decompilation budget")
        self.direct_display_addr = function_original_addr(self.func)
        self.using_rebased_direct_slice = self.direct_project is not self.project
        self.direct_project_fallback_addr = _direct_addr_project_local_fallback_addr_8616(
            function=self.func,
            direct_display_addr=self.direct_display_addr,
            using_rebased_direct_slice=self.using_rebased_direct_slice,
        )
        self.slice_result = None
        self.sidecar_closed_nonopt = False
        self.known_nonopt_result: NonOptimizedSliceOutcome | str | None = None
        self.reserve_budget_for_rebased_sidecar = (
            self.using_rebased_direct_slice and self.precise_sidecar_regions and self.direct_result.status == "validation_failed"
        )
        self.skip_heavy_validation_fallbacks = _direct_addr_should_skip_heavy_validation_fallbacks_8616(
            timeout_was_explicit=self.timeout_was_explicit,
            args_timeout=self.args.timeout,
            direct_status=self.direct_result.status,
            partial_payload=self.direct_result.partial_payload,
        )
        # Cap heavy fallback fan-out per function to keep direct-addr mode
        # deterministic and prevent minute-long retry storms.
        if self.fast_direct_probe or self.skip_heavy_validation_fallbacks:
            self.heavy_fallback_budget = 0
        elif self.timeout_was_explicit and isinstance(self.args.timeout, int):
            self.heavy_fallback_budget = 1
        else:
            self.heavy_fallback_budget = 2 if self.direct_result.status == "validation_failed" else 4




        self.exact_retry_blocked = (
            self.direct_failure_family_state.repeat_detected and not self.direct_failure_family_state.new_proof_seen
        )
        return None
    def _phase_direct_emit_batch_8616_part0_8616_b2(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        if self.direct_result.status == "empty":
            self.partial_payload_text = (
                self.direct_result.partial_payload if isinstance(self.direct_result.partial_payload, str) else None
            )
            if isinstance(self.partial_payload_text, str) and self.partial_payload_text.strip():
                self.snapshot = self.direct_result.tail_validation
                self.checked_acceptance = _validated_generated_c_acceptance_8616(
                    status="ok",
                    payload=self.partial_payload_text,
                    tail_validation_snapshot=self.snapshot,
                    tail_validation_enabled=_tail_validation_runtime_enabled(self.direct_project),
                    expected_validation_stages=["structuring", "postprocess"],
                    c_target=getattr(self.direct_project, "_inertia_c_target", "portable-flat"),
                    emit_failure_diagnostics=False,
                )
                self.checked_status = self.checked_acceptance.status
                self.checked_blocker = self.checked_acceptance.blocker
                if self.checked_status == "ok" and self.checked_blocker is None:
                    self.direct_result = replace(
                        self.direct_result,
                        status="ok",
                        payload=self.checked_acceptance.gcc_checked_payload,
                        partial_payload=None,
                        validated_payload_hash=self.checked_acceptance.validated_payload_hash,
                        gcc_checked_payload_hash=self.checked_acceptance.gcc_checked_payload_hash,
                    )
                else:
                    _dump_validation_failed_payload_if_requested_8616(
                        self.partial_payload_text,
                        prefix=f"direct_partial_{self.func.addr:x}_{self.func.name}",
                    )
                    print(
                        f"[dbg] rejected direct partial payload: {self.checked_status} detail={self.checked_blocker or 'n/a'}",
                        file=sys.stderr,
                        flush=True,
                    )
                    self.direct_result = replace(self.direct_result, partial_payload=None)
            # Allow one non-optimized known-function lane even when the
            # optimized lane repeats an "empty" family; this is often a
            # recoverable clinic/core failure class for helper routines.
            self.exact_retry_blocked = False
        return None
    def _phase_direct_emit_batch_8616_part0_8616_b3(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        if (
            not self.fast_direct_probe
            and self.direct_result.status != "ok"
            and self.precise_sidecar_regions
            and self.lst_metadata is not None
            and not (
                self.timeout_was_explicit
                and isinstance(self.args.timeout, int)
                and self.args.timeout <= 6
                and self.direct_result.status == "timeout"
            )
        ):
            _rc = self._phase_direct_emit_batch_8616_part0_8616_b3_zb0()
            if _rc is not None:
                return _rc
            _rc = self._phase_direct_emit_batch_8616_part0_8616_b3_zb1()
            if _rc is not None:
                return _rc
        return None
    def _phase_direct_emit_batch_8616_part0_8616_b4(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        self.allow_known_nonopt = (not self.exact_retry_blocked) or (self.direct_result.status in {"timeout", "validation_failed"})
        if self.fast_direct_probe:
            self.allow_known_nonopt = False
        if (
            self.timeout_was_explicit
            and isinstance(self.args.timeout, int)
            and self.args.timeout > 6
            and self.direct_result.status == "timeout"
        ):
            self.allow_known_nonopt = False
        if self._current_direct_partial_payload() is None:
            if self.allow_known_nonopt and not self._consume_heavy_fallback_budget():
                self.allow_known_nonopt = False
            if self.allow_known_nonopt:
                self._enforce_direct_addr_budget_timeout(recovery_detail="after exhausting direct-address fallback budget")
                self.known_nonopt_result = _try_decompile_non_optimized_known_function(
                    self.direct_project,
                    self.cfg,
                    self.func,
                    timeout=max(
                        1,
                        min(_bounded_non_optimized_timeout(self.args.timeout), self._remaining_direct_addr_budget() or 1),
                    ),
                    api_style=self.args.api_style,
                    binary_path=self.args.binary,
                    lst_metadata=None if self.using_rebased_direct_slice else self.lst_metadata,
                    cod_metadata=self.cod_metadata,
                    synthetic_globals=self.synthetic_globals,
                    failure_family_state=self.direct_failure_family_state,
                )
                if self.known_nonopt_result is not None:
                    self.direct_nonoptimized_verdict = (
                        self.known_nonopt_result.status
                        if isinstance(self.known_nonopt_result, NonOptimizedSliceOutcome)
                        else "ok"
                    )
        self.known_nonopt_c = _non_optimized_slice_rendered(self.known_nonopt_result)
        return None
    def _phase_direct_emit_batch_8616_part0_8616_b5(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        if self.known_nonopt_c is not None:
            self.fallback_snapshot = _tail_validation_snapshot_for_fallback(
                self.direct_project,
                self.func,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
            )
            _emit_tail_validation_snapshot_or_uncollected(
                self.cfg,
                self.func,
                self.fallback_snapshot,
                binary_path=self.args.binary,
            )
            self.accepted_payload = self._accept_direct_fallback_payload(
                self.known_nonopt_c,
                tail_validation_snapshot=self.fallback_snapshot,
            )
            if self.accepted_payload is not None:
                print(f"\n/* Decompilation {self.direct_result.status}: {self.direct_result.payload} */")
                print("/* Falling back to known-function non-optimized decompilation. */")
                _emit_optional_source_sidecar_c_block(
                    self.args.binary,
                    self.func.name,
                    self.accepted_payload,
                    alternate_source_c=bool(self.args.alternate_source_c),
                    c_header="\n/* == c (non-optimized fallback) == */",
                )
                return 0
        self._enforce_direct_addr_budget_timeout(recovery_detail="after exhausting direct-address fallback budget")
        self.generic_nonopt_result = None
        if not self.reserve_budget_for_rebased_sidecar and self._consume_heavy_fallback_budget():
            self.generic_nonopt_result = _try_decompile_non_optimized_slice(
                self.direct_project,
                self.direct_project_fallback_addr,
                self.func.name,
                timeout=max(1, min(_bounded_non_optimized_timeout(self.args.timeout), self._remaining_direct_addr_budget() or 1)),
                api_style=self.args.api_style,
                binary_path=self.args.binary,
                lst_metadata=None if self.using_rebased_direct_slice else self.lst_metadata,
                cod_metadata=self.cod_metadata,
                allow_fresh_project_retry=False,
                failure_family_state=self.direct_failure_family_state,
                original_addr=self.direct_display_addr,
            )
            if self.generic_nonopt_result is not None:
                self.direct_nonoptimized_verdict = (
                    self.generic_nonopt_result.status
                    if isinstance(self.generic_nonopt_result, NonOptimizedSliceOutcome)
                    else "ok"
                )
        self.generic_nonopt_c = _non_optimized_slice_rendered(self.generic_nonopt_result)
        return None
    def _phase_direct_emit_batch_8616_part0_8616_b6(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        if self.generic_nonopt_c is not None:
            self.fallback_snapshot = _tail_validation_snapshot_for_fallback(
                self.direct_project,
                self.func,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
            )
            _emit_tail_validation_snapshot_or_uncollected(
                self.cfg,
                self.func,
                self.fallback_snapshot,
                binary_path=self.args.binary,
            )
            self.accepted_payload = self._accept_direct_fallback_payload(
                self.generic_nonopt_c,
                tail_validation_snapshot=self.fallback_snapshot,
            )
            if self.accepted_payload is not None:
                print(f"\n/* Decompilation {self.direct_result.status}: {self.direct_result.payload} */")
                print("/* Falling back to non-optimized slice decompilation. */")
                _emit_optional_source_sidecar_c_block(
                    self.args.binary,
                    self.func.name,
                    self.accepted_payload,
                    alternate_source_c=bool(self.args.alternate_source_c),
                    c_header="\n/* == c (non-optimized fallback) == */",
                )
                return 0
        self.exact_retry_blocked = (
            self.direct_failure_family_state.repeat_detected and not self.direct_failure_family_state.new_proof_seen
        )
        if self.direct_result.status == "validation_failed":
            # Validation-failed direct lane is frequently under-recovered
            # semantics. Allow exact sidecar retry even when the failure
            # family repeats so richer bounded slices can be considered.
            self.exact_retry_blocked = False
        return None
    def _phase_direct_emit_batch_8616_part0_8616_b7(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        if not self.fast_direct_probe and self.precise_sidecar_regions:  # noqa: SIM102
            if not self.exact_retry_blocked:
                self._dbg_region = _lst_code_region(self.lst_metadata, self.direct_display_addr) if self.lst_metadata is not None else None
                print(
                    f"[dbg] sidecar slice gate: precise={self.precise_sidecar_regions} rebased={self.using_rebased_direct_slice} blocked={self.exact_retry_blocked} addr={self.direct_display_addr:#x} region={self._dbg_region}",
                    file=sys.stderr,
                    flush=True,
                )
                self._enforce_direct_addr_budget_timeout(recovery_detail="after exhausting direct-address fallback budget")
                self.sidecar_attempted = False
                if self._consume_heavy_fallback_budget():
                    self.sidecar_attempted = True
                    self.slice_result = _try_decompile_sidecar_slice(
                        self.project,
                        self.lst_metadata,
                        self.direct_display_addr,
                        self.func.name,
                        timeout=max(1, min(self.args.timeout, self._remaining_direct_addr_budget() or 1)),
                        api_style=self.args.api_style,
                        binary_path=self.args.binary,
                        failure_family_state=self.direct_failure_family_state,
                    )
                if self.slice_result is not None:
                    self.direct_sidecar_verdict = self.slice_result.status
                if self.sidecar_attempted and self.slice_result is None:
                    print("[dbg] sidecar slice attempt returned None", file=sys.stderr, flush=True)
        if self.slice_result is not None:
            if self.slice_result.status != "ok":
                print(
                    f"[dbg] sidecar slice attempt status={self.slice_result.status} payload={self.slice_result.payload}",
                    file=sys.stderr,
                    flush=True,
                )
                self.sidecar_closed_nonopt = sidecar_verdict_closes_non_optimized_lane(self.slice_result.verdict)
                self.slice_result = None
            else:
                _emit_sidecar_slice_tail_validation_snapshot_8616(
                    self.cfg,
                    self.func,
                    self.slice_result.snapshot,
                    binary_path=self.args.binary,
                )
                self.accepted_payload = self._accept_direct_fallback_payload(
                    self.slice_result.payload,
                    tail_validation_snapshot=self.slice_result.snapshot,
                )
                if self.accepted_payload is not None:
                    _emit_optional_source_sidecar_c_block(
                        self.args.binary,
                        self.func.name,
                        self.accepted_payload,
                        alternate_source_c=bool(self.args.alternate_source_c),
                        c_header="\n/* == c (sidecar slice fallback) == */",
                    )
                    return 0
        self.trivial_c = _try_emit_trivial_sidecar_c(self.project, self.lst_metadata, self.direct_display_addr, self.func.name)
        return None
    def _phase_direct_emit_batch_8616_part0_8616_b8(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        if self.trivial_c is not None:
            _emit_tail_validation_for_function_run_or_uncollected(
                self.direct_project,
                self.cfg,
                self.func,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("trivial_sidecar"),
                binary_path=self.args.binary,
            )
            _emit_optional_source_sidecar_c_block(
                self.args.binary,
                self.func.name,
                self.trivial_c,
                alternate_source_c=bool(self.args.alternate_source_c),
                c_header="\n/* == c (trivial sidecar fallback) == */",
            )
            return 0
        self.nonopt_result = None
        if self._direct_nonopt_probe_eligible_8616() and self._consume_heavy_fallback_budget():
            self._enforce_direct_addr_budget_timeout(recovery_detail="after exhausting direct-address fallback budget")
            self.nonopt_result = _try_decompile_non_optimized_slice(
                self.direct_project if self.using_rebased_direct_slice else self.project,
                self.direct_project_fallback_addr,
                self.func.name,
                timeout=max(1, min(_bounded_non_optimized_timeout(self.args.timeout), self._remaining_direct_addr_budget() or 1)),
                api_style=self.args.api_style,
                binary_path=self.args.binary,
                lst_metadata=None if self.using_rebased_direct_slice else self.lst_metadata,
                cod_metadata=self.cod_metadata,
                allow_fresh_project_retry=False,
                failure_family_state=self.direct_failure_family_state,
                original_addr=self.direct_display_addr,
            )
        self.nonopt_c = _non_optimized_slice_rendered(self.nonopt_result)
        return None
    def _phase_direct_emit_batch_8616_part0_8616_b9(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        if self.nonopt_c is not None:
            self.fallback_snapshot = _tail_validation_snapshot_for_fallback(
                self.direct_project,
                self.func,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
            )
            _emit_tail_validation_snapshot_or_uncollected(
                self.cfg,
                self.func,
                self.fallback_snapshot,
                binary_path=self.args.binary,
            )
            self.accepted_payload = self._accept_direct_fallback_payload(
                self.nonopt_c,
                tail_validation_snapshot=self.fallback_snapshot,
            )
            if self.accepted_payload is not None:
                print(f"\n/* Decompilation {self.direct_result.status}: {self.direct_result.payload} */")
                print("/* Falling back to non-optimized slice decompilation. */")
                _emit_optional_source_sidecar_c_block(
                    self.args.binary,
                    self.func.name,
                    self.accepted_payload,
                    alternate_source_c=bool(self.args.alternate_source_c),
                    c_header="\n/* == c (non-optimized fallback) == */",
                )
                return 0
        self.current_partial_payload = self._current_direct_partial_payload()
        return None
    def _phase_direct_emit_batch_8616_part0_8616_b10(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        _rc = self._phase_direct_emit_batch_8616_part0_8616_b10_s0()
        if _rc is not None:
            return _rc
        _rc = self._phase_direct_emit_batch_8616_part0_8616_b10_s1()
        if _rc is not None:
            return _rc
        return None
    def _phase_direct_emit_batch_8616_part0_8616_b11(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        if self.string_c is not None:
            _emit_tail_validation_for_function_run_or_uncollected(
                self.direct_project,
                self.cfg,
                self.func,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("string_intrinsic"),
                binary_path=self.args.binary,
            )
            print(f"\n/* Decompilation {self.direct_result.status}: {self.direct_result.payload} */")
            print("/* Falling back to generic string-intrinsic recovery. */")
            self.nonopt_skip_reason = describe_non_optimized_unavailable(
                allow_heavy_fallbacks=True,
                skip_heavy_fallbacks_for_result=False,
                interactive_stdout=self.interactive_stdout,
                max_functions=self.args.max_functions,
                addr_requested=self.direct_addr is not None,
                result_status=self.direct_result.status,
                failure_stage=None,
                nonopt_failure_detail=_non_optimized_slice_failure_detail(self.nonopt_result),
            )
            if self.nonopt_skip_reason is not None:
                print(f"/* non-optimized fallback unavailable: {self.nonopt_skip_reason} */")
            _emit_optional_source_sidecar_c_block(
                self.args.binary,
                self.func.name,
                self.string_c,
                alternate_source_c=bool(self.args.alternate_source_c),
                c_header="\n/* == c (string intrinsic fallback) == */",
            )
            return 0
        _emit_tail_validation_for_function_run_or_uncollected(
            self.direct_project,
            self.cfg,
            self.func,
            allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("asm"),
            binary_path=self.args.binary,
        )
        self.asm_fallback = (
            _format_asm_range(self.project, self.sidecar_region[0], self.sidecar_region[1])
            if self.sidecar_region is not None
            else _format_asm_range(self.project, *_infer_linear_disassembly_window(self.project, self.func.addr))
        )
        print(f"\n/* Decompilation {self.direct_result.status}: {self.direct_result.payload} */")
        print("/* Falling back to non-optimized disassembly. */")
        self.nonopt_failure_detail = _non_optimized_slice_failure_detail(self.nonopt_result)
        if self.nonopt_failure_detail is not None:
            print(f"/* non-optimized fallback failed: {self.nonopt_failure_detail} */")
        for __diag_line_lp8616 in _format_tail_validation_diagnostic(
            self.direct_result.tail_validation,
            function_addr=self.func.addr,
            function_name=self.func.name,
            block_count=self.direct_result.block_count,
            byte_count=self.direct_result.byte_count,
            exit_kind=self.direct_result.status,
            exit_detail=self.direct_result.payload,
        ):
            self._diag_line = __diag_line_lp8616
            print(__diag_line_lp8616)
        print("\n/* == lift break probe == */")
        print(_probe_lift_break(self.project, self.func.addr))
        return None
    def _phase_direct_emit_batch_8616_part0_8616_b12(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        print("\n/* == asm fallback == */")
        print(self.asm_fallback)
        return 6 if self.status == "error" else 4


    def _phase_direct_cfg_recovery_8616_part0_8616_zb0(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        self.direct_recovery_timeout = (
            max(1, min(self.args.timeout, 6))
            if self.args.proc is not None and not self.proc_resolved_to_linked_binary
            else _default_recovery_timeout(self.args.timeout, explicit_timeout=self.timeout_was_explicit)
        )
        return None
    def _phase_direct_cfg_recovery_8616_part0_8616_zb1(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        self.direct_recovery_timeout = max(1, min(self.direct_recovery_timeout, self._remaining_direct_addr_budget() or 1))
        self.cfg, self.func = _run_with_timeout_in_daemon_thread(
            self._recover_target_function,
            timeout=self.direct_recovery_timeout,
            thread_name_prefix="recovery",
            prefer_process_alarm=True,
        )
        return None
    def _phase_direct_cfg_recovery_8616_part0_8616_ze00(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        _rc = self._phase_direct_cfg_recovery_8616_part0_8616_e00()
        if _rc is not None:
            return _rc
        _rc = self._phase_direct_cfg_recovery_8616_part0_8616_e01()
        if _rc is not None:
            return _rc
        return None
    def _phase_direct_cfg_recovery_8616_part0_8616_ze01(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        _rc = self._phase_direct_cfg_recovery_8616_part0_8616_e02()
        if _rc is not None:
            return _rc
        _rc = self._phase_direct_cfg_recovery_8616_part0_8616_e03()
        if _rc is not None:
            return _rc
        return None
    def _phase_direct_cfg_recovery_8616_part0_8616_ze10(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        _rc = self._phase_direct_cfg_recovery_8616_part0_8616_e10()
        if _rc is not None:
            return _rc
        _rc = self._phase_direct_cfg_recovery_8616_part0_8616_e11()
        if _rc is not None:
            return _rc
        return None
    def _phase_direct_cfg_recovery_8616_part0_8616_ze11(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        _rc = self._phase_direct_cfg_recovery_8616_part0_8616_e12()
        if _rc is not None:
            return _rc
        _rc = self._phase_direct_cfg_recovery_8616_part0_8616_e13()
        if _rc is not None:
            return _rc
        return None
    def _phase_direct_cfg_recovery_8616_part0_8616_ze20(self, ex: BaseException) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        self.recovery_detail = _function_recovery_detail(getattr(self.project, "_inertia_decompiler_stage", None))
        if self.recovery_detail is None:
            print(f"/* Function recovery failed: {ex} */")
        else:
            print(f"/* Function recovery failed {self.recovery_detail}: {ex} */")
        if os.environ.get("INERTIA_DEBUG_RECOVERY_TRACEBACK"):
            import traceback

            traceback.print_exc()
        print("\n/* == lift break probe == */")
        print(_probe_lift_break(self.project, self.direct_addr))
        return None
    def _phase_direct_cfg_recovery_8616_part0_8616_ze21(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        print("\n/* == first block asm == */")
        print(_format_first_block_asm(self.project, self.direct_addr))
        print("\n/* == non-optimized disassembly == */")
        self.start, self.end = _infer_linear_disassembly_window(self.project, self.direct_addr)
        print(_format_asm_range(self.project, self.start, self.end))
        return 5
    def _phase_direct_emit_batch_8616_part0_8616_zb0(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        _rc = self._phase_direct_emit_batch_8616_part0_8616_b0()
        if _rc is not None:
            return _rc

        _rc = self._phase_direct_emit_batch_8616_part0_8616_b1()
        if _rc is not None:
            return _rc
        _rc = self._phase_direct_emit_batch_8616_part0_8616_b2()
        if _rc is not None:
            return _rc
        _rc = self._phase_direct_emit_batch_8616_part0_8616_b3()
        if _rc is not None:
            return _rc
        _rc = self._phase_direct_emit_batch_8616_part0_8616_b4()
        if _rc is not None:
            return _rc
        _rc = self._phase_direct_emit_batch_8616_part0_8616_b5()
        if _rc is not None:
            return _rc
        return None
    def _phase_direct_emit_batch_8616_part0_8616_zb1(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        _rc = self._phase_direct_emit_batch_8616_part0_8616_b6()
        if _rc is not None:
            return _rc
        _rc = self._phase_direct_emit_batch_8616_part0_8616_b7()
        if _rc is not None:
            return _rc
        _rc = self._phase_direct_emit_batch_8616_part0_8616_b8()
        if _rc is not None:
            return _rc
        _rc = self._phase_direct_emit_batch_8616_part0_8616_b9()
        if _rc is not None:
            return _rc
        _rc = self._phase_direct_emit_batch_8616_part0_8616_b10()
        if _rc is not None:
            return _rc
        _rc = self._phase_direct_emit_batch_8616_part0_8616_b11()
        if _rc is not None:
            return _rc
        _rc = self._phase_direct_emit_batch_8616_part0_8616_b12()
        if _rc is not None:
            return _rc
        return None
    def run_8616_part5_8616_b1_s0(self) -> int | None:
        """Run an extracted sub-phase; return an exit code to abort."""
        if self.direct_result.status in {"empty", "validation_failed"}:
            self.evidence_payload, self.evidence_snapshot = _recover_binary_evidence_c_8616(self.direct_project, self.func)
            if isinstance(self.evidence_payload, str) and self.evidence_payload.strip() and isinstance(self.evidence_snapshot, dict):
                self.evidence_acceptance = _validated_generated_c_acceptance_8616(
                    status="ok",
                    payload=self.evidence_payload,
                    tail_validation_snapshot=self.evidence_snapshot,
                    tail_validation_enabled=_tail_validation_runtime_enabled(self.direct_project),
                    expected_validation_stages=["structuring", "postprocess"],
                    c_target=getattr(self.direct_project, "_inertia_c_target", "portable-flat"),
                    emit_failure_diagnostics=False,
                )
                if self.evidence_acceptance.status == "ok" and self.evidence_acceptance.blocker is None:
                    self.direct_result = replace(
                        self.direct_result,
                        status="ok",
                        payload=self.evidence_acceptance.gcc_checked_payload,
                        partial_payload=None,
                        tail_validation=self.evidence_snapshot,
                        validated_payload_hash=self.evidence_acceptance.validated_payload_hash,
                        gcc_checked_payload_hash=self.evidence_acceptance.gcc_checked_payload_hash,
                    )
        _rc = self._phase_direct_empty_lanes_8616()
        if _rc is not None:
            return _rc
        _rc = self._phase_direct_light_lanes_8616()
        if _rc is not None:
            return _rc
        _rc = self._phase_direct_heavy_lanes_8616()
        if _rc is not None:
            return _rc
        if os.environ.get(_SERIAL_CLEAN_WORKER_RESULT_ENV_8616):
            self.direct_result = replace(self.direct_result, failure_family_snapshot=self._direct_failure_snapshot(self.direct_result))
            if _complete_serial_clean_worker_result_8616(self.direct_result, project=self.direct_project):
                return 0
        self.direct_timeout_payload = self.direct_result.payload
        self._direct_blocks_for_timeout_guard, self._direct_bytes_for_timeout_guard = _function_complexity(self.func)
        return None
    def run_8616_part5_8616_b1_s1(self) -> int | None:
        """Run an extracted sub-phase; return an exit code to abort."""
        self.clinic_core_timeout = isinstance(self.direct_timeout_payload, str) and (
            "core:clinic:" in self.direct_timeout_payload
            or "timed out after" in self.direct_timeout_payload.lower()
            or (
                self.direct_result.status == "empty"
                and getattr(self.project.arch, "name", "") == "86_16"
                and (self._direct_blocks_for_timeout_guard >= 32 or self._direct_bytes_for_timeout_guard >= 280)
                and "decompiler did not produce code" in self.direct_timeout_payload.lower()
            )
        )
        _rc = self._phase_direct_failure_emit_8616()
        if _rc is not None:
            return _rc
        self.direct_failure_family_snapshot = self._direct_failure_snapshot(self.direct_result)
        self.budget_fallback_addr = function_original_addr(self.func)
        self.budget_fallback_name = self.func.name
        self.direct_result = replace(self.direct_result, failure_family_snapshot=self.direct_failure_family_snapshot)
        if self.direct_result.debug_output:
            print(self.direct_result.debug_output, file=sys.stderr, end="")
        print(f"[dbg] direct failure family: {self.direct_failure_family_snapshot.label()}", file=sys.stderr)
        if self.direct_result.status == "error":
            _print_stop_on_first_failure_8616(self.func, self.direct_result)
            return 6
        return None
    def _phase_direct_emit_batch_8616_part0_8616_b0_zb0(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        self.best_direct_candidate = self.direct_result
        self.best_direct_rank = self._candidate_rank(self.direct_result)
        return None
    def _phase_direct_emit_batch_8616_part0_8616_b0_zb1(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        self.retry_count = _direct_addr_validation_retry_count_8616(
            timeout_was_explicit=self.timeout_was_explicit,
            args_timeout=self.args.timeout,
        )
        for _retry_idx_lp8616 in range(self.retry_count):
            self.retry_idx = _retry_idx_lp8616
            try:
                self.retry_status, self.retry_payload, self.retry_partial, *self.retry_extra = _run_with_timeout_in_daemon_thread(
                    self.direct_decompile_job,
                    timeout=max(1, min(self.args.timeout, 8)),
                    thread_name_prefix=f"direct-decomp-retry-{_retry_idx_lp8616 + 1}",
                )
                self.retry_tail_validation = None
                for _lv8616 in self.retry_extra:
                    self.extra = _lv8616
                    if isinstance(self.extra, dict):
                        self.retry_tail_validation = dict(self.extra)
                self.retry_result = FunctionWorkResult(
                    index=1,
                    status=self.retry_status,
                    payload=self.retry_payload,
                    debug_output="",
                    function=self.func,
                    function_cfg=self.cfg,
                    partial_payload=self.retry_partial,
                    tail_validation=self.retry_tail_validation
                    or _tail_validation_snapshot_for_function_run(self.direct_project, self.func),
                )
                self.retry_acceptance = _validated_generated_c_acceptance_8616(
                    status=self.retry_result.status,
                    payload=self.retry_result.payload,
                    tail_validation_snapshot=self.retry_result.tail_validation,
                    tail_validation_enabled=_tail_validation_runtime_enabled(self.direct_project),
                    expected_validation_stages=["structuring", "postprocess"],
                    c_target=getattr(self.direct_project, "_inertia_c_target", "portable-flat"),
                    emit_failure_diagnostics=False,
                )
                self.retry_checked_status = self.retry_acceptance.status
                self.retry_blocker = self.retry_acceptance.blocker
                if self.retry_checked_status != self.retry_result.status or self.retry_blocker is not None:
                    self.retry_preserved_candidate = self._preserve_acceptance_candidate_or_best_failure(
                        self.retry_acceptance,
                        self.retry_result,
                    )
                    self.retry_result = replace(
                        self.retry_result,
                        status=self.retry_checked_status,
                        payload=self.retry_blocker if self.retry_blocker is not None else self.retry_result.payload,
                        partial_payload=self.retry_preserved_candidate
                        if self.retry_blocker is not None
                        else self.retry_result.partial_payload,
                    )
                else:
                    self.retry_result = replace(
                        self.retry_result,
                        payload=self.retry_acceptance.gcc_checked_payload,
                        validated_payload_hash=self.retry_acceptance.validated_payload_hash,
                        gcc_checked_payload_hash=self.retry_acceptance.gcc_checked_payload_hash,
                    )
                self.retry_rank = self._candidate_rank(self.retry_result)
                if self.retry_result.status == "ok":
                    self.direct_result = self.retry_result
                    self.best_direct_candidate = self.retry_result
                    self.best_direct_rank = self.retry_rank
                    break
                if self.retry_rank > self.best_direct_rank:
                    self.best_direct_candidate = self.retry_result
                    self.best_direct_rank = self.retry_rank
            except Exception:
                continue
        if self.direct_result.status != "ok":
            self.current_rank = self._candidate_rank(self.direct_result)
            if self.best_direct_rank > self.current_rank:
                self.direct_result = self.best_direct_candidate
        return None
    def _phase_direct_emit_batch_8616_part0_8616_b3_zb0(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        self.sidecar_region = _lst_code_region(self.lst_metadata, self.direct_display_addr)
        self.direct_sidecar_verdict = "attempted"
        if self.sidecar_region is not None:
            try:
                self.sidecar_addr = self.sidecar_region[0]
                self.code_name = _lst_code_label(self.lst_metadata, self.sidecar_addr, self.project.entry) or self.func.name
                self.side_cfg, self.side_func = _recover_lst_function(
                    self.project,
                    self.lst_metadata,
                    self.sidecar_addr if self.lst_metadata.absolute_addrs else self.sidecar_addr - self.project.entry,
                    self.code_name,
                    timeout=max(2, min(self.args.timeout, 8)),
                    window=self.args.window,
                    low_memory=self.low_memory_path,
                    allow_rebased_exact_slice=False,
                )
                # Dynamic angr boundary: exact recovery may return a function owned by a slice project.
                self.side_project = getattr(self.side_func, "project", self.project)
                if not isinstance(self.side_project, angr.Project):
                    self.side_project = self.project
                _transfer_caller_return_use_evidence_8616(self.project, self.side_project)
                with span(
                    "direct.sidecar_retry",
                    addr=hex(self.sidecar_addr),
                    name=self.code_name,
                    timeout=max(2, min(self.args.timeout, 8)),
                ):
                    self.side_tail_from_decompile = None
                    self.side_status, self.side_payload, *self._ = _decompile_function_with_stats(
                        self.side_project,
                        self.side_cfg,
                        self.side_func,
                        max(2, min(self.args.timeout, 8)),
                        self.args.api_style,
                        self.args.binary,
                        cod_metadata=self.cod_metadata,
                        synthetic_globals=self.synthetic_globals,
                        lst_metadata=self.lst_metadata,
                        allow_isolated_retry=False,
                        failure_family_state=self.direct_failure_family_state,
                    )
                    self.side_tail_candidate = getattr(
                        self.side_project,
                        "_inertia_last_validated_function_payload_snapshot",
                        None,
                    )
                    self.function_tail_candidate = _retry_function_tail_validation_snapshot_8616(
                        self.side_project,
                        self.side_func,
                    )
                    if self.function_tail_candidate:
                        self.side_tail_candidate = self.function_tail_candidate
                    if not isinstance(self.side_tail_candidate, dict):
                        self.side_tail_candidate = getattr(
                            self.side_project,
                            "_inertia_last_tail_validation_snapshot",
                            None,
                        )
                    if isinstance(self.side_tail_candidate, dict):
                        self.side_tail_from_decompile = dict(self.side_tail_candidate)
                    annotate_current_span(status=self.side_status)
                self.direct_sidecar_verdict = self.side_status
                if self.side_status == "ok":
                    self.side_tail = (
                        self.side_tail_from_decompile
                        if isinstance(self.side_tail_from_decompile, dict)
                        else _retry_function_tail_validation_snapshot_8616(self.side_project, self.side_func)
                    )
                    _emit_tail_validation_snapshot_or_uncollected(
                        self.side_cfg,
                        self.side_func,
                        self.side_tail,
                        binary_path=self.args.binary,
                    )
                    self.side_acceptance = _validated_generated_c_acceptance_8616(
                        status=self.side_status,
                        payload=self.side_payload,
                        tail_validation_snapshot=self.side_tail,
                        tail_validation_enabled=_tail_validation_runtime_enabled(self.side_project),
                        expected_validation_stages=["structuring", "postprocess"],
                        c_target=getattr(self.side_project, "_inertia_c_target", "portable-flat"),
                    )
                    self.side_status_checked = self.side_acceptance.status
                    self.side_payload_checked = self.side_acceptance.gcc_checked_payload
                    if self.side_status_checked != "ok":
                        self.side_status = self.side_status_checked
                if self.side_status == "ok":
                    self.accepted_side_payload = (
                        self.side_payload_checked if isinstance(self.side_payload_checked, str) else self.side_payload
                    )
                    print("[dbg] direct sidecar fallback validation=passed", file=sys.stderr)
                    _emit_optional_source_sidecar_c_block(
                        self.args.binary,
                        self.side_func.name,
                        self.accepted_side_payload,
                        alternate_source_c=bool(self.args.alternate_source_c),
                        c_header="\n/* == c (sidecar slice fallback) == */",
                    )
                    return 0
            except (_AnalysisTimeout, Exception):
                self.direct_sidecar_verdict = "error"
        return None
    def _phase_direct_emit_batch_8616_part0_8616_b3_zb1(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        self._early_slice = _try_decompile_sidecar_slice(
            self.project,
            self.lst_metadata,
            self.direct_display_addr,
            self.func.name,
            timeout=max(2, min(8, self.args.timeout) if isinstance(self.args.timeout, int) else 8),
            api_style=self.args.api_style,
            binary_path=self.args.binary,
            failure_family_state=self.direct_failure_family_state,
        )
        if self._early_slice is not None:
            self.direct_sidecar_verdict = self._early_slice.status
        if self._early_slice is not None and self._early_slice.status == "ok":
            _emit_sidecar_slice_tail_validation_snapshot_8616(
                self.cfg,
                self.func,
                self._early_slice.snapshot,
                binary_path=self.args.binary,
            )
            self.accepted_payload = self._accept_direct_fallback_payload(
                self._early_slice.payload,
                tail_validation_snapshot=self._early_slice.snapshot,
            )
            if self.accepted_payload is not None:
                _emit_optional_source_sidecar_c_block(
                    self.args.binary,
                    self.func.name,
                    self.accepted_payload,
                    alternate_source_c=bool(self.args.alternate_source_c),
                    c_header="\n/* == c (sidecar slice fallback) == */",
                )
                return 0
        return None
    def _phase_direct_emit_batch_8616_part0_8616_b10_s0(self) -> int | None:
        """Run an extracted sub-phase; return an exit code to abort."""
        if self.current_partial_payload is not None:
            _emit_tail_validation_snapshot_or_uncollected(
                self.cfg,
                self.func,
                self.direct_result.tail_validation,
                binary_path=self.args.binary,
            )
            self.partial_report = _partial_result_report_8616(self.direct_result.status)
            self.payload_detail = self.direct_result.payload
            if self.partial_report.status is WorkItemStatus.TIMEOUT:
                self.timeout_text = "timeout"
                if isinstance(self.direct_result.payload, str):
                    self.m = re.search(r"Timed out after (\d+)s", self.direct_result.payload)
                    if self.m is not None:
                        self.timeout_text = f"Timed out after {self.m.group(1)}s."
                self.payload_detail = (
                    self.timeout_text if self.timeout_text != "timeout" else f"Timed out after {self.args.timeout}s."
                )
            print(f"/* {self.partial_report.heading}: {self.payload_detail} */")
            if self.partial_report.show_timeout_delay:
                self.direct_elapsed = self.direct_result.elapsed
                if isinstance(self.direct_elapsed, (int, float)):
                    print(f"/* timeout delay: {float(self.direct_elapsed):.2f}s */")
            if self.partial_report.status is WorkItemStatus.VALIDATION_FAILED:
                print("/* direct validation=failed */")
            _emit_failed_timeout_acceptance_hints_8616()
            print(f"/* non-optimized fallback failed: {self.partial_report.fallback_detail} */")
            if "&sp_0" in self.current_partial_payload:
                print("/* Source-evidenced loop call was hoisted outside loop in emitted C. */")
            _emit_optional_source_sidecar_c_block(
                self.args.binary,
                self.func.name,
                self.current_partial_payload,
                alternate_source_c=bool(self.args.alternate_source_c),
                c_header=self.partial_report.direct_c_header,
            )
            return 6 if self.direct_result.status == "error" else 4
        self.sidecar_region = None
        if self.lst_metadata is not None and not self.using_rebased_direct_slice:
            self.sidecar_region = _lst_code_region(self.lst_metadata, self.direct_display_addr)
        return None
    def _phase_direct_emit_batch_8616_part0_8616_b10_s1(self) -> int | None:
        """Run an extracted sub-phase; return an exit code to abort."""
        self.linear_window = (
            None if self.sidecar_region is not None else _infer_linear_disassembly_window(self.direct_project, self.func.addr)
        )
        if self.sidecar_region is None and self.linear_window is None:
            self.linear_window = _infer_linear_disassembly_window(self.direct_project, self.func.addr)
        if self.sidecar_region is not None:
            self.string_start, self.string_end = self.sidecar_region
        else:
            assert self.linear_window is not None
            self.string_start, self.string_end = self.linear_window
        self.string_c = _try_emit_string_intrinsic_c(
            self.direct_project,
            start=self.string_start,
            end=self.string_end,
            name=self.func.name,
        )
        return None


    def _phase_direct_cfg_recovery_8616_part0_8616_zh0(self) -> int | None:
        """Run an extracted handler sub-phase; return an exit code to abort."""
        _rc = self._phase_direct_cfg_recovery_8616_part0_8616_ze00()
        if _rc is not None:
            return _rc
        _rc = self._phase_direct_cfg_recovery_8616_part0_8616_ze01()
        if _rc is not None:
            return _rc
        return None
    def _phase_direct_cfg_recovery_8616_part0_8616_zh1(self) -> int | None:
        """Run an extracted handler sub-phase; return an exit code to abort."""
        _rc = self._phase_direct_cfg_recovery_8616_part0_8616_ze10()
        if _rc is not None:
            return _rc
        _rc = self._phase_direct_cfg_recovery_8616_part0_8616_ze11()
        if _rc is not None:
            return _rc
        return None
    def _phase_direct_cfg_recovery_8616_part0_8616_zh2(self, ex: BaseException) -> int | None:
        """Run an extracted handler sub-phase; return an exit code to abort."""
        _rc = self._phase_direct_cfg_recovery_8616_part0_8616_ze20(ex)
        if _rc is not None:
            return _rc
        _rc = self._phase_direct_cfg_recovery_8616_part0_8616_ze21()
        if _rc is not None:
            return _rc
        return None

    def _direct_nonopt_probe_eligible_8616(self) -> bool:
        """Return whether a non-optimized-slice probe is eligible before consuming fallback budget."""
        return (
            self.partial_payload is None
            and self.known_nonopt_c is None
            and (self.precise_sidecar_regions or self.using_rebased_direct_slice)
            and not self.sidecar_closed_nonopt
            and not (self.direct_failure_family_state.repeat_detected and not self.direct_failure_family_state.new_proof_seen)
        )
def _run_direct_addr_cli_8616(context: _DirectAddrCliContext8616) -> int:


    """Run the direct-address CLI branch after project and sidecar setup."""
    return _DirectAddrCliRun8616(context=context).run_8616()


@dataclass(frozen=True, slots=True)
class _BatchCliContext8616:
    """Owned inputs and runtime policy shared by batch execution lanes."""

    args: CliArguments
    project: angr.Project
    function_tasks: list[FunctionWorkItem]
    result_map: dict[int, FunctionWorkResult]
    fallback_tail_validation_by_index: dict[int, dict[str, object]]
    lst_metadata: LSTMetadata | None
    cod_metadata: CODProcMetadata | None
    synthetic_globals: _SyntheticGlobals8616
    visible_code_labels: dict[int, str]
    include_library_functions: bool
    low_memory_path: bool
    interactive_stdout: bool
    precise_sidecar_regions: bool
    timeout_was_explicit: bool
    use_serial_fork_per_function: bool
    allow_heavy_fallbacks: bool
    force_isolated_function_projects: bool
    sweep_deadline: float | None
    shown_total: int
    skipped_signature_labels: int

    def force_isolated_project_for(self, work_item: FunctionWorkItem) -> bool:
        """Return whether a work item needs a fresh project for stable recovery."""
        if not self.force_isolated_function_projects:
            return False
        work_function = cast(_AngrFunction, work_item.function)
        try:
            function_project = work_function.project
        except AttributeError:
            return True
        if function_project is None:
            return True
        return function_project is self.project

    def configure_recovered_project_for(self, work_item: FunctionWorkItem) -> None:
        """Apply the owned CLI runtime policy to a recovered function project."""
        work_function = cast(_AngrFunction, work_item.function)
        try:
            function_project = work_function.project
        except AttributeError:
            return
        if function_project is None:
            return
        function_project._inertia_c_target = self.args.c_target
        function_project._inertia_trace_c_stages = bool(self.args.trace_c_stages)
        function_project._inertia_dump_layers = bool(self.args.dump_layers)
        function_project._inertia_dump_layer_root = self.args.dump_layer_dir
        function_project._inertia_dump_layer_filter = self.args.dump_layer_filter
        _transfer_caller_return_use_evidence_8616(self.project, function_project)
        _inherit_tail_validation_runtime_policy(function_project, self.project)

    def sweep_budget_exhausted(self) -> bool:
        """Return whether the optional whole-binary sweep deadline has elapsed."""
        return self.sweep_deadline is not None and time.monotonic() >= self.sweep_deadline

    def remaining_sweep_budget_sec(self) -> int | None:
        """Return remaining whole-binary sweep time, or None when unbounded."""
        if self.sweep_deadline is None:
            return None
        return max(0, int(self.sweep_deadline - time.monotonic()))


def _batch_function_decompile_timeout_8616(
    context: _BatchCliContext8616,
    function: _AngrFunction,
    adaptive_timeout_model: _AdaptivePerByteTimeoutModel,
) -> int:
    """Return one complexity-aware timeout shared by serial and parallel lanes."""
    args = context.args
    block_count, byte_count = _function_complexity(function)
    decompile_timeout = adaptive_timeout_model.timeout_for_byte_count(byte_count)
    decompile_timeout = _effective_decompile_timeout_8616(
        function.project,
        decompile_timeout,
        block_count=block_count,
        byte_count=byte_count,
    )
    try:
        architecture = function.project.arch.name
    except AttributeError:
        architecture = ""
    if architecture == "86_16":
        decompile_timeout = _x86_16_complexity_timeout_8616(
            decompile_timeout, args, context.timeout_was_explicit, block_count, byte_count
        )
    if args.addr is None:
        decompile_timeout = max(decompile_timeout, 16)
    if args.addr is None and context.timeout_was_explicit:
        decompile_timeout = max(1, min(decompile_timeout, args.timeout))
    remaining_sweep_budget = context.remaining_sweep_budget_sec()
    if remaining_sweep_budget is not None:
        decompile_timeout = max(1, min(decompile_timeout, remaining_sweep_budget))
    bounded_timeout = _enforce_function_timeout_cap(
        decompile_timeout,
        context="sweep decompile timeout",
        explicit_timeout_floor=args.timeout if context.timeout_was_explicit else None,
        default_timeout_cap=PARALLEL_CLEAN_WORKER_TIMEOUT_CAP,
    )
    return _finalization_timeout_floor_8616(
        architecture, args, context.timeout_was_explicit, bounded_timeout
    )


def _x86_16_complexity_timeout_8616(
    decompile_timeout: int,
    args: CliArguments,
    timeout_was_explicit: bool,
    block_count: int,
    byte_count: int,
) -> int:
    """Raise a decompile timeout by measured 16-bit function complexity."""
    if block_count >= 72 or byte_count >= 520:
        decompile_timeout = max(decompile_timeout, args.timeout + 120, 240)
    elif block_count >= 56 or byte_count >= 420:
        decompile_timeout = max(decompile_timeout, args.timeout + 90, 240)
    elif block_count >= 36 or byte_count >= 300:
        decompile_timeout = max(decompile_timeout, args.timeout + 60)
    if args.addr is None and not timeout_was_explicit and (
        block_count >= 36 or byte_count >= 300
    ):
        decompile_timeout = max(
            decompile_timeout,
            PARALLEL_CLEAN_WORKER_TIMEOUT_CAP,
        )
    return decompile_timeout


def _finalization_timeout_floor_8616(
    architecture: str,
    args: CliArguments,
    timeout_was_explicit: bool,
    bounded_timeout: int,
) -> int:
    """Enforce the large-function finalization floor for batch 16-bit sweeps."""
    if (
        architecture != "86_16"
        or args.addr is not None
        or timeout_was_explicit
        or bounded_timeout < 180
    ):
        return bounded_timeout
    return _enforce_function_timeout_cap(
        max(bounded_timeout, 240),
        context="sweep large-function finalization timeout",
        default_timeout_cap=PARALLEL_CLEAN_WORKER_TIMEOUT_CAP,
    )


def _transfer_caller_return_use_evidence_8616(
    source_project: object,
    destination_project: object,
) -> int:
    """Copy typed project evidence across a fresh-project worker boundary."""
    return int(transfer_project_evidence_8616(source_project, destination_project).caller_return_use_count)


def _fresh_primary_function_work_item_8616(
    context: _BatchCliContext8616,
    item: FunctionWorkItem,
    *,
    timeout: int,
) -> FunctionWorkItem:
    """Recover one primary work item from a fresh binary project."""
    args = context.args
    fresh_project = _build_project(
        args.binary,
        force_blob=args.blob,
        base_addr=args.base_addr,
        entry_point=args.entry_point,
    )
    _transfer_caller_return_use_evidence_8616(context.project, fresh_project)
    typing.cast(typing.Any, fresh_project)._inertia_c_target = args.c_target
    typing.cast(typing.Any, fresh_project)._inertia_trace_c_stages = bool(args.trace_c_stages)
    typing.cast(typing.Any, fresh_project)._inertia_dump_layers = bool(args.dump_layers)
    typing.cast(typing.Any, fresh_project)._inertia_dump_layer_root = args.dump_layer_dir
    typing.cast(typing.Any, fresh_project)._inertia_dump_layer_filter = args.dump_layer_filter
    _inherit_tail_validation_runtime_policy(fresh_project, context.project)
    attach_lst_metadata_to_project(fresh_project, context.lst_metadata)
    _apply_binary_specific_annotations(
        fresh_project,
        args.binary,
        context.lst_metadata,
        cod_metadata=context.cod_metadata,
        synthetic_globals=context.synthetic_globals,
    )

    source_function = cast(_AngrFunction, item.function)
    source_addr = _function_work_item_recovery_addr_8616(item)
    source_name = source_function.name
    source_exact_region = _function_binary_exact_region_8616(source_function)
    fresh_cfg, fresh_function = _recover_direct_addr_function(
        fresh_project,
        source_addr,
        timeout=max(1, timeout),
        window=args.window,
        function_label=source_name,
        lst_metadata=context.lst_metadata,
        low_memory_path=context.low_memory_path,
        prefer_fast_recovery=False,
        exact_region=source_exact_region,
    )
    _preserve_source_label_for_recovered_function_8616(source_function, fresh_function)
    fresh_item = FunctionWorkItem(
        index=item.index,
        function_cfg=fresh_cfg,
        function=fresh_function,
        recovery_addr=source_addr,
    )
    context.configure_recovered_project_for(fresh_item)
    recovered_project = cast(_AngrFunction, fresh_function).project
    _transfer_caller_return_use_evidence_8616(context.project, recovered_project)
    _apply_binary_specific_annotations(
        recovered_project,
        args.binary,
        context.lst_metadata,
        func_addr=function_original_addr(fresh_function),
        cod_metadata=context.cod_metadata,
        synthetic_globals=context.synthetic_globals,
    )
    return fresh_item


@dataclass(frozen=True, slots=True)
class _SerialFunctionOutcome8616:
    """Counters and control signal produced by one serial function attempt."""

    decompiled: int
    failed: int
    stop_requested: bool = False


def _run_serial_function_8616(
    context: _BatchCliContext8616,
    item: FunctionWorkItem,
    *,
    recover_timeout: int,
    adaptive_timeout_model: _AdaptivePerByteTimeoutModel,
    allow_isolated_retry_in_function_tasks: bool,
    emitted_indexes: set[int],
) -> _SerialFunctionOutcome8616:
    """Recover, decompile, retry, and emit one serial function work item."""
    item_function = cast(_AngrFunction, item.function)
    recovery_addr = _function_work_item_recovery_addr_8616(item)
    result: FunctionWorkResult | None = context.result_map.get(item.index)
    if result is None:
        return _serial_missing_result_lane_8616(
            context,
            item,
            item_function,
            recovery_addr,
            recover_timeout=recover_timeout,
            adaptive_timeout_model=adaptive_timeout_model,
            allow_isolated_retry_in_function_tasks=allow_isolated_retry_in_function_tasks,
            emitted_indexes=emitted_indexes,
        )
    return _SerialFunctionOutcome8616(decompiled=0, failed=0)


def _serial_local_recover_timeout_8616(recover_timeout: int, remaining_sweep_budget: float | None) -> int:
    """Clamp the recovery timeout to the remaining sweep budget."""
    if remaining_sweep_budget is not None:
        return max(1, min(recover_timeout, int(remaining_sweep_budget)))
    return recover_timeout


def _serial_recover_call_8616(
    recover_call: Callable[[], object],
    local_recover_timeout: int,
    thread_name_prefix: str,
) -> _FunctionCfgPair8616:
    """Run one recovery call through fork when enabled, else daemon thread."""
    if _analysis_timeout_use_fork_8616():
        try:
            return cast(
                _FunctionCfgPair8616,
                _run_with_timeout_in_fork(
                    cast(Callable[[], Any], recover_call),
                    timeout=local_recover_timeout + 1,
                ),
            )
        except (FuturesTimeoutError, TimeoutError):
            raise
        except Exception:
            return cast(
                _FunctionCfgPair8616,
                _run_with_timeout_in_daemon_thread(
                    cast(Callable[[], Any], recover_call),
                    timeout=local_recover_timeout + 1,
                    thread_name_prefix=thread_name_prefix,
                ),
            )
    return cast(
        _FunctionCfgPair8616,
        _run_with_timeout_in_daemon_thread(
            cast(Callable[[], Any], recover_call),
            timeout=local_recover_timeout + 1,
            thread_name_prefix=thread_name_prefix,
        ),
    )


def _serial_stub_rerank_and_item_8616(
    context: _BatchCliContext8616,
    item: FunctionWorkItem,
    item_function: _AngrFunction,
    function_cfg: object,
    function: _AngrFunction | None,
    recovery_addr: int,
    recovery_mode: str,
    recover_timeout: int,
) -> FunctionWorkItem:
    """Re-rank lst stub recoveries and rebuild the active work item."""
    args = context.args
    project = context.project
    lst_metadata = context.lst_metadata
    if recovery_mode == "lst" and function is not None and lst_metadata is not None:
        try:
            recovered_blocks, recovered_bytes = _function_complexity(function)
        except Exception:
            recovered_blocks, recovered_bytes = (0, 0)
        region = _lst_code_region(lst_metadata, recovery_addr)
        region_span = (
            max(0, int(region[1]) - int(region[0]))
            if isinstance(region, tuple) and len(region) == 2
            else 0
        )
        # Sidecar regions that span much more than a tiny
        # one-block body often indicate that entry recovery
        # latched onto a stub/prefix. Retry ranked recovery
        # and keep the larger candidate when available.
        if recovered_blocks <= 1 and recovered_bytes <= 16 and region_span >= 64:
            try:
                ranked_cfg, ranked_func = _recover_ranked_binary_function(
                    project,
                    recovery_addr,
                    item_function.name,
                    timeout=max(recover_timeout, 12),
                    window=args.window,
                    low_memory=context.low_memory_path,
                )
            except Exception:
                pass
            else:
                function_cfg, function = ranked_cfg, ranked_func
    active_item = FunctionWorkItem(
        index=item.index,
        function_cfg=function_cfg,
        function=function,
        recovery_addr=_function_work_item_recovery_addr_8616(item),
    )
    context.configure_recovered_project_for(active_item)
    _preserve_source_label_for_recovered_function_8616(item.function, active_item.function)
    return active_item


def _serial_recover_function_8616(
    context: _BatchCliContext8616,
    item: FunctionWorkItem,
    item_function: _AngrFunction,
    recovery_addr: int,
    recover_timeout: int,
) -> tuple[FunctionWorkResult | None, str, FunctionWorkItem]:
    """Recover the function CFG for a work item that lacks one."""
    args = context.args
    project = context.project
    lst_metadata = context.lst_metadata
    recovery_mode = "lst" if lst_metadata is not None and context.visible_code_labels else "ranked"
    result: FunctionWorkResult | None = None
    cached_work_result, _cache_bypass_debug, _cache_key, _tail_enabled, _expected_stages = (
        _function_work_cache_lookup(
            item,
            binary_path=args.binary,
            timeout=args.timeout,
            api_style=args.api_style,
            enable_structured_simplify=True,
            enable_postprocess=True,
            cod_metadata=context.cod_metadata,
            synthetic_globals=context.synthetic_globals,
            lst_metadata=lst_metadata,
        )
    )
    if cached_work_result is not None:
        result = cached_work_result
    if result is None:
        cached_recovery_result, recovery_cache_bypass_debug, _recovery_cache_key = (
            _lookup_persistent_recovery_timeout(
                binary_path=args.binary,
                addr=recovery_addr,
                mode=recovery_mode,
                window=args.window,
                low_memory=context.low_memory_path,
                timeout=recover_timeout,
            )
        )
        if cached_recovery_result is not None:
            result = replace(
                cached_recovery_result,
                index=item.index,
                function=item.function,
                function_cfg=None,
            )
    active_item = item
    try:
        remaining_sweep_budget = context.remaining_sweep_budget_sec()
        if remaining_sweep_budget is not None and remaining_sweep_budget <= 0:
            raise TimeoutError("Whole-sweep budget exhausted before recovery.")
        if result is None:
            local_recover_timeout = _serial_local_recover_timeout_8616(recover_timeout, remaining_sweep_budget)
            if lst_metadata is not None and context.visible_code_labels:
                print(
                    f"[dbg] recovery worker: start {recovery_addr:#x} {item_function.name} "
                    f"mode=lst recovery_timeout={local_recover_timeout}s"
                )
                function_cfg, function = _serial_recover_call_8616(
                    cast(Callable[[], object], lambda offset=recovery_addr, name=item_function.name: _recover_lst_function(
                        project,
                        lst_metadata,
                        offset,
                        name,
                        timeout=local_recover_timeout,
                        window=args.window,
                        low_memory=context.low_memory_path,
                    )),
                    local_recover_timeout,
                    "lst-recover",
                )
            else:
                print(
                    f"[dbg] recovery worker: start {recovery_addr:#x} {item_function.name} "
                    f"mode=ranked recovery_timeout={local_recover_timeout}s"
                )
                function_cfg, function = _serial_recover_call_8616(
                    cast(Callable[[], object], lambda addr=recovery_addr, name=item_function.name: (
                        _recover_ranked_binary_function(
                            project,
                            addr,
                            name,
                            timeout=local_recover_timeout,
                            window=args.window,
                            low_memory=context.low_memory_path,
                        ))
                    ),
                    local_recover_timeout,
                    "ranked-recover",
                )
            active_item = _serial_stub_rerank_and_item_8616(
                context,
                item,
                item_function,
                function_cfg,
                function,
                recovery_addr,
                recovery_mode,
                recover_timeout,
            )
    except (FuturesTimeoutError, TimeoutError):
        payload = (
            f"Timed out while recovering {item_function.name} at {recovery_addr:#x} "
            f"(stage=recovery timeout={recover_timeout}s mode={recovery_mode})."
        )
        result = FunctionWorkResult(
            index=item.index,
            status="timeout",
            payload=payload,
            debug_output=recovery_cache_bypass_debug,
            function=item_function,
            function_cfg=None,
            skip_heavy_fallbacks=True,
            elapsed=float(recover_timeout),
            failure_stage=f"recovery:{recovery_mode}",
        )
    except Exception as ex:
        result = FunctionWorkResult(
            index=item.index,
            status="error",
            payload=f"Recovery failed for {item_function.name} at {recovery_addr:#x}: {_describe_exception(ex)}",
            debug_output="",
            function=item_function,
            function_cfg=None,
            failure_stage=f"recovery:{recovery_mode}",
        )
    return result, recovery_mode, active_item


def _serial_no_cfg_error_outcome_8616(
    context: _BatchCliContext8616,
    item: FunctionWorkItem,
    item_function: _AngrFunction,
    recovery_addr: int,
    recovery_mode: str,
    emitted_indexes: set[int],
) -> _SerialFunctionOutcome8616:
    """Emit the no-CFG recovery error and its outcome."""
    decompiled = 0
    failed = 0
    result = FunctionWorkResult(
        index=item.index,
        status="error",
        payload=(
            f"Recovery failed to produce a function CFG for "
            f"{item_function.name} at {recovery_addr:#x}."
        ),
        debug_output="",
        function=item_function,
        function_cfg=None,
        failure_stage=f"recovery:{recovery_mode}",
    )
    context.result_map[item.index] = result
    if item.index not in emitted_indexes:
        d, f = _serial_emit_result_8616(context, item, result)
        decompiled += d
        failed += f
        emitted_indexes.add(item.index)
    return _SerialFunctionOutcome8616(decompiled=decompiled, failed=failed)


def _serial_emit_result_8616(
    context: _BatchCliContext8616,
    item: FunctionWorkItem,
    result: FunctionWorkResult,
) -> tuple[int, int]:
    """Emit one serial function result through the shared emission lane."""
    return _emit_function_result(
        item,
        result,
        project=context.project,
        args=context.args,
        lst_metadata=context.lst_metadata,
        cod_metadata=context.cod_metadata,
        synthetic_globals=context.synthetic_globals,
        precise_sidecar_regions=context.precise_sidecar_regions,
        allow_heavy_fallbacks=context.allow_heavy_fallbacks,
        interactive_stdout=context.interactive_stdout,
        use_serial_fork_per_function=context.use_serial_fork_per_function,
        fallback_tail_validation_by_index=context.fallback_tail_validation_by_index,
        result_state_by_index=context.result_map,
        timeout_was_explicit=context.timeout_was_explicit,
    )


def _serial_decompile_active_item_8616(
    context: _BatchCliContext8616,
    item: FunctionWorkItem,
    active_item: FunctionWorkItem,
    decompile_timeout: float,
    allow_isolated_retry_in_function_tasks: bool,
) -> FunctionWorkResult:
    """Run the serial decompile for a recovered work item."""
    args = context.args
    if context.use_serial_fork_per_function:
        active_function = cast(_AngrFunction, active_item.function)
        hard_timeout = _serial_clean_worker_outer_timeout_8616(int(decompile_timeout))
        print(
            f"[dbg] clean serial function worker: start {active_function.addr:#x} "
            f"{active_function.name} requested_timeout={decompile_timeout}s hard_timeout={hard_timeout}s"
        )
        return _run_serial_clean_process_work_item_8616(
            context,
            active_item,
            timeout=int(decompile_timeout),
        )
    try:
        return _run_with_timeout_in_daemon_thread(
            lambda: _run_function_work_item(
                active_item,
                timeout=int(decompile_timeout),
                api_style=args.api_style,
                binary_path=args.binary,
                cod_metadata=context.cod_metadata,
                synthetic_globals=context.synthetic_globals,
                lst_metadata=context.lst_metadata,
                enable_structured_simplify=True,
                force_isolated_project=context.force_isolated_project_for(active_item),
                allow_isolated_retry=allow_isolated_retry_in_function_tasks,
            ),
            timeout=_enforce_function_timeout_cap(
                max(1, int(decompile_timeout) + 1),
                context="sweep function serial daemon timeout",
                explicit_timeout_floor=args.timeout if context.timeout_was_explicit else None,
            ),
            thread_name_prefix="func-serial",
        )
    except (FuturesTimeoutError, TimeoutError):
        return FunctionWorkResult(
            index=item.index,
            status="timeout",
            payload=f"Timed out after {args.timeout}s.",
            debug_output="",
            function=active_item.function,
            function_cfg=active_item.function_cfg,
            skip_heavy_fallbacks=True,
            elapsed=float(args.timeout),
            failure_stage="decompilation",
        )
    except Exception as ex:
        return FunctionWorkResult(
            index=item.index,
            status="error",
            payload=f"Serial function worker failed: {_describe_exception(ex)}",
            debug_output="",
            function=active_item.function,
            function_cfg=active_item.function_cfg,
            failure_stage="decompilation",
        )


def _serial_post_result_8616(
    context: _BatchCliContext8616,
    item: FunctionWorkItem,
    active_item: FunctionWorkItem,
    result: FunctionWorkResult | None,
    decompile_timeout: float,
    adaptive_timeout_model: _AdaptivePerByteTimeoutModel,
    allow_isolated_retry_in_function_tasks: bool,
) -> FunctionWorkResult | None:
    """Normalize, observe, and bridge-retry a serial work result."""
    args = context.args
    if result is not None and result.status == "ok":
        result_payload = result.payload if isinstance(result.payload, str) else ""
        normalized_result_payload = _normalize_accepted_payload_8616(result_payload)
        if normalized_result_payload != result_payload:
            result = replace(result, payload=normalized_result_payload)
    if result is not None and result.status == "ok":
        byte_count = result.byte_count
        elapsed = result.elapsed
        if isinstance(byte_count, int) and isinstance(elapsed, (int, float)):
            adaptive_timeout_model.observe_success(byte_count, float(elapsed))
    # Sweep-only timeout bridge: retry timed-out functions once with a
    # larger per-function budget using the same work-item path.
    if result is not None and result.status == "timeout" and args.addr is None and not context.use_serial_fork_per_function:
        base_timeout = max(1, args.timeout)
        # Ensure sweep retry actually expands the lane budget.
        # The previous 120s cap could become a no-op when the base
        # timeout was already 120s, leaving flaky one-off timeouts
        # unrecovered.
        retry_timeout = min(360, max(int(decompile_timeout) * 2, base_timeout * 2, 40))
        retry_timeout = _enforce_function_timeout_cap(
            retry_timeout,
            context="sweep timeout bridge",
            explicit_timeout_floor=args.timeout if context.timeout_was_explicit else None,
        )
        try:
            retry_result = _run_with_timeout_in_daemon_thread(
                lambda: _run_function_work_item(
                    active_item,
                    timeout=retry_timeout,
                    api_style=args.api_style,
                    binary_path=args.binary,
                    cod_metadata=context.cod_metadata,
                    synthetic_globals=context.synthetic_globals,
                    lst_metadata=context.lst_metadata,
                    enable_structured_simplify=True,
                    force_isolated_project=context.force_isolated_project_for(active_item),
                    allow_isolated_retry=allow_isolated_retry_in_function_tasks,
                ),
                timeout=_enforce_function_timeout_cap(
                    max(1, retry_timeout + 2),
                    context="sweep retry bridge thread timeout",
                    explicit_timeout_floor=args.timeout if context.timeout_was_explicit else None,
                ),
                thread_name_prefix="func-timeout-bridge",
            )
            if isinstance(retry_result, FunctionWorkResult) and retry_result.status == "ok":
                result = retry_result
        except Exception:
            pass
    return result


def _serial_missing_result_lane_8616(
    context: _BatchCliContext8616,
    item: FunctionWorkItem,
    item_function: _AngrFunction,
    recovery_addr: int,
    *,
    recover_timeout: int,
    adaptive_timeout_model: _AdaptivePerByteTimeoutModel,
    allow_isolated_retry_in_function_tasks: bool,
    emitted_indexes: set[int],
) -> _SerialFunctionOutcome8616:
    """Recover, decompile, retry, and emit a work item without a cached result."""
    args = context.args
    decompiled = 0
    failed = 0
    result: FunctionWorkResult | None = None
    active_item = item
    recovery_mode = "existing"
    decompile_timeout: float = max(1, args.timeout)
    if item.function_cfg is None:
        result, recovery_mode, active_item = _serial_recover_function_8616(
            context,
            item,
            item_function,
            recovery_addr,
            recover_timeout,
        )
    if result is None:
        context.configure_recovered_project_for(active_item)
        active_function = cast(_AngrFunction, active_item.function)
        if active_item.function_cfg is None:
            return _serial_no_cfg_error_outcome_8616(
                context, item, item_function, recovery_addr, recovery_mode, emitted_indexes
            )
        decompile_timeout = _batch_function_decompile_timeout_8616(
            context,
            active_function,
            adaptive_timeout_model,
        )
        result = _serial_decompile_active_item_8616(
            context,
            item,
            active_item,
            decompile_timeout,
            allow_isolated_retry_in_function_tasks,
        )
    result = _serial_post_result_8616(
        context,
        item,
        active_item,
        result,
        decompile_timeout,
        adaptive_timeout_model,
        allow_isolated_retry_in_function_tasks,
    )
    context.result_map[item.index] = result
    if result is not None and item.index not in emitted_indexes:
        d, f = _serial_emit_result_8616(context, item, result)
        decompiled += d
        failed += f
        emitted_indexes.add(item.index)
        if f and args.addr is not None:
            _emit_tail_validation_console_summary(context.function_tasks, context.result_map, binary_path=args.binary)
            return _SerialFunctionOutcome8616(decompiled=decompiled, failed=failed, stop_requested=True)
    return _SerialFunctionOutcome8616(decompiled=decompiled, failed=failed)


def _finish_batch_cli_8616(
    context: _BatchCliContext8616,
    *,
    decompiled: int,
    failed: int,
    emitted_indexes: set[int],
) -> int:
    """Emit pending results and the common terminal summary for a batch run."""
    args = context.args
    project = context.project
    function_tasks = context.function_tasks
    result_map = context.result_map
    fallback_tail_validation_by_index = context.fallback_tail_validation_by_index
    lst_metadata = context.lst_metadata
    shown_total = context.shown_total
    skipped_signature_labels = context.skipped_signature_labels
    attempted = sum(1 for item in function_tasks if result_map.get(item.index) is not None)
    attempted_target = "selected" if args.max_functions <= 0 and args.addr is None else "displayed"
    print(f"/* info: decompilation attempted for {attempted}/{shown_total} {attempted_target} function(s) */")
    d, f = _emit_pending_batch_results_8616(context, emitted_indexes)
    decompiled += d
    failed += f
    for index, snapshot in fallback_tail_validation_by_index.items():
        existing = result_map.get(index)
        if existing is not None:
            result_map[index] = replace(existing, tail_validation=snapshot)
    accepted_payloads = tuple(
        result.payload
        for item in function_tasks
        if (result := result_map.get(item.index)) is not None
        and result.status == WorkItemStatus.OK.value
        and isinstance(result.payload, str)
        and result.payload.strip()
    )
    batch_c_output = build_batch_c_output_8616(
        accepted_payloads,
        expected_function_count=shown_total,
    )
    if batch_c_output.source:
        print(batch_c_output.source, end="" if batch_c_output.source.endswith("\n") else "\n")
        if args.output_c_dir is not None:
            write_generated_translation_unit_c(
                args.output_c_dir,
                payload=batch_c_output.source,
                complete=batch_c_output.status is BatchCOutputStatus8616.READY,
            )
    if batch_c_output.failed:
        print(f"generated C translation-unit export failed: {batch_c_output.detail}", file=sys.stderr)
    attach_segment_program_layout_8616(
        project,
        function_tasks,
        result_map.values(),
        _source_region_catalog_evidence_8616(project),
    )
    total_shown = shown_total
    _emit_tail_validation_console_summary(function_tasks, result_map, binary_path=args.binary)
    summary_target = "selected functions" if args.max_functions <= 0 and args.addr is None else "shown functions"
    print(f"\n/* summary: decompiled {decompiled}/{total_shown} {summary_target} */")
    timed_out = sum(1 for result in result_map.values() if result.status == "timeout")
    if timed_out:
        print(f"/* summary: {timed_out} discovered function(s) timed out during decompilation */")
    if failed:
        print(f"/* summary: {failed} functions fell back to asm/details */")
    same_family_retry_stops = sum(result.same_family_retry_stops for result in result_map.values())
    fallback_family_labels = sorted(
        {label for result in result_map.values() for label in result.fallback_family_labels if label},
        key=lambda item: (item.casefold(), item),
    )
    (
        dead_setup_candidates,
        dead_setup_pruned,
        dead_setup_refused,
        dead_setup_escaped,
    ) = _dead_setup_counters_8616(result_map.values())
    emit_file_decompilation_summary(
        project,
        lst_metadata,
        shown_total=total_shown,
        decompiled=decompiled,
        failed=failed,
        skipped_signature_labels=skipped_signature_labels,
        same_family_retry_stops=same_family_retry_stops,
        fallback_family_labels=fallback_family_labels,
        dead_setup_candidates=dead_setup_candidates,
        dead_setup_pruned=dead_setup_pruned,
        dead_setup_refused=dead_setup_refused,
        dead_setup_escaped=dead_setup_escaped,
    )
    if _timing_output_enabled():
        _emit_function_timing_summary(function_tasks, result_map)
    exit_code = _batch_exit_code_8616(
        attempted=attempted,
        decompiled=decompiled,
        failed=failed,
        total_shown=total_shown,
    )
    return 2 if batch_c_output.failed else exit_code


def _emit_pending_batch_results_8616(
    context: _BatchCliContext8616, emitted_indexes: set[int]
) -> tuple[int, int]:
    """Emit every un-emitted function result, returning (decompiled, failed) deltas."""
    decompiled = 0
    failed = 0
    for item in context.function_tasks:
        if item.index in emitted_indexes:
            continue
        result = context.result_map.get(item.index)
        if result is None:
            continue
        d, f = _emit_function_result(
            item,
            result,
            project=context.project,
            args=context.args,
            lst_metadata=context.lst_metadata,
            cod_metadata=context.cod_metadata,
            synthetic_globals=context.synthetic_globals,
            precise_sidecar_regions=context.precise_sidecar_regions,
            allow_heavy_fallbacks=context.allow_heavy_fallbacks,
            interactive_stdout=context.interactive_stdout,
            use_serial_fork_per_function=context.use_serial_fork_per_function,
            fallback_tail_validation_by_index=context.fallback_tail_validation_by_index,
            result_state_by_index=context.result_map,
            timeout_was_explicit=context.timeout_was_explicit,
        )
        decompiled += d
        failed += f
    return decompiled, failed


def _dead_setup_counters_8616(results: Iterable[FunctionWorkResult]) -> tuple[int, int, int, int]:
    """Aggregate dead-setup evidence counters across function results."""
    candidates = 0
    pruned = 0
    refused = 0
    escaped = 0
    for result in results:
        function_obj = result.function
        info = getattr(function_obj, "info", None)
        if not isinstance(info, dict):
            continue
        ds = info.get("x86_16_dead_setup")
        if not isinstance(ds, dict):
            continue
        candidates += int(ds.get("dead_setup_candidates", 0) or 0)
        pruned += int(ds.get("dead_setup_pruned", 0) or 0)
        refused += int(ds.get("dead_setup_refused", 0) or 0)
        escaped += int(ds.get("dead_setup_escaped", 0) or 0)
    return candidates, pruned, refused, escaped


def _batch_exit_code_8616(
    *,
    attempted: int,
    decompiled: int,
    failed: int,
    total_shown: int,
) -> int:
    """Return success only for a complete batch whose every result was accepted."""
    complete = (
        total_shown > 0
        and attempted == total_shown
        and decompiled == total_shown
        and failed == 0
    )
    return 0 if complete else 2


def _run_serial_batch_cli_8616(context: _BatchCliContext8616) -> int:
    """Run the serial function queue and emit its complete file summary."""
    args = context.args
    project = context.project
    function_tasks = context.function_tasks
    result_map = context.result_map
    lst_metadata = context.lst_metadata
    visible_code_labels = context.visible_code_labels
    include_library_functions = context.include_library_functions
    timeout_was_explicit = context.timeout_was_explicit
    use_serial_fork_per_function = context.use_serial_fork_per_function
    _sweep_budget_exhausted = context.sweep_budget_exhausted
    decompiled = 0
    failed = 0
    emitted_indexes: set[int] = set()
    recover_timeout = _default_recovery_timeout(args.timeout, explicit_timeout=timeout_was_explicit)
    adaptive_timeout_model = _AdaptivePerByteTimeoutModel(
        args.timeout,
        explicit_timeout=timeout_was_explicit,
        margin=1.5,
    )
    if use_serial_fork_per_function:
        allow_isolated_retry_in_function_tasks = False
    else:
        allow_isolated_retry_in_function_tasks = not (
            args.addr is None
            and args.binary.suffix.lower() == ".exe"
            and args.max_functions > 0
            and args.max_functions <= 2
            and lst_metadata is not None
            and not visible_code_labels
            and include_library_functions
            and project.arch.name == "86_16"
        )
    for item in function_tasks:
        if _sweep_budget_exhausted():
            remaining = sum(1 for pending_item in function_tasks if pending_item.index not in result_map)
            print(
                f"[dbg] sweep budget exhausted; marking {remaining} remaining function(s) as timeout",
                file=sys.stderr,
            )
            break
        outcome = _run_serial_function_8616(
            context,
            item,
            recover_timeout=recover_timeout,
            adaptive_timeout_model=adaptive_timeout_model,
            allow_isolated_retry_in_function_tasks=allow_isolated_retry_in_function_tasks,
            emitted_indexes=emitted_indexes,
        )
        decompiled += outcome.decompiled
        failed += outcome.failed
        if outcome.stop_requested:
            return 2
    if _sweep_budget_exhausted():
        for pending_item in function_tasks:
            if pending_item.index in result_map:
                continue
            result_map[pending_item.index] = FunctionWorkResult(
                index=pending_item.index,
                status="timeout",
                payload="Whole-sweep budget exhausted before decompilation could start.",
                debug_output="",
                function=pending_item.function,
                function_cfg=pending_item.function_cfg,
                elapsed=0.0,
                failure_stage="sweep_budget",
                skip_heavy_fallbacks=True,
            )
    return _finish_batch_cli_8616(
        context,
        decompiled=decompiled,
        failed=failed,
        emitted_indexes=emitted_indexes,
    )


@dataclass(slots=True)
class _MainCliRun8616:
    """Mutable run state for main CLI orchestration."""

    _: Any = None
    _seeded_pairs_and_addrs: Any = None
    addr: Any = None
    allow_heavy_fallbacks: Any = None
    allow_isolated_retry_for_parallel_tasks: Any = None
    args: Any = None
    argv: Any = None
    batch_context: Any = None
    cached_catalog_addrs: Any = None
    cached_catalog_int_addrs: Any = None
    catalog_error: Any = None
    cfg: Any = None
    cfg_any: Any = None
    cod_metadata: Any = None
    code_name: Any = None
    current_result: Any = None
    d: Any = None
    deadlines: Any = None
    decompiled: Any = None
    defer_limit_until_after_seed_ranking: Any = None
    deferred_exe_display_cap: Any = None
    detail: Any = None
    direct_context: Any = None
    direct_inventory_total: Any = None
    direct_lock_key: Any = None
    discovered_addrs: Any = None
    discovery_limit: Any = None
    display_cache_key: Any = None
    done: Any = None
    done_now: Any = None
    effective_signature_catalog: Any = None
    emitted_indexes: Any = None
    end: Any = None
    ex: Any = None
    executor: Any = None
    existing: Any = None
    existing_addrs: Any = None
    existing_by_addr: Any = None
    expired: Any = None
    f: Any = None
    failed: Any = None
    fallback_tail_validation_by_index: Any = None
    fast_seed_pairs: Any = None
    force_isolated_function_projects: Any = None
    forced_serial_function_decomp: Any = None
    func: Any = None
    function: Any = None
    function_cfg: Any = None
    function_cfg_pairs: Any = None
    function_label: Any = None
    function_tasks: Any = None
    function_timeout: Any = None
    functions: Any = None
    future: Any = None
    future_map: Any = None
    has_expired_futures: Any = None
    has_non_library_sidecar_hints: Any = None
    include_library_functions: Any = None
    index: Any = None
    interactive_stdout: Any = None
    isolated_function_decompilation_required: Any = None
    item: Any = None
    item_by_future: Any = None
    labeled_offsets: Any = None
    library_label_skipped_count: Any = None
    limit: Any = None
    linked_base: Any = None
    low_memory_path: Any = None
    lst_metadata: Any = None
    name: Any = None
    now: Any = None
    offset: Any = None
    packed_exe: Any = None
    parallel_timeout_model: Any = None
    pending: Any = None
    placeholder: Any = None
    precise_sidecar_regions: Any = None
    prefer_bounded_catalog: Any = None
    prefer_fast_recovery: Any = None
    prefer_ranked_hidden_sidecar_full_queue: Any = None
    preview_addrs: Any = None
    proc_resolved_to_linked_binary: Any = None
    project: Any = None
    ranked_binary_offsets: Any = None
    ranked_labeled_total: Any = None
    ranking_cache_hit: Any = None
    ranking_elapsed_ms: Any = None
    ranking_start: Any = None
    recovered_seed_addrs: Any = None
    recovery_code_labels: Any = None
    recovery_filter: Any = None
    replacement_tasks: Any = None
    request_cache_inputs: Any = None
    requested_workers: Any = None
    result: Any = None
    result_map: Any = None
    rizin_names: Any = None
    runtime_header: Any = None
    rz_name: Any = None
    seed_code_labels: Any = None
    seeded_addrs: Any = None
    seeded_catalog_addrs: Any = None
    seeded_pairs: Any = None
    seeded_recovery_result: Any = None
    seen_existing: Any = None
    selection_target: Any = None
    setup: Any = None
    shown_total: Any = None
    sidecar_preview_limit: Any = None
    skipped_signature_labels: Any = None
    source_catalog: Any = None
    source_region_evidence: Any = None
    start: Any = None
    supplemental_pairs: Any = None
    supplemented_cached_result: Any = None
    sweep_budget_sec: Any = None
    sweep_budget_sec_raw: Any = None
    sweep_deadline: Any = None
    synthetic_globals: Any = None
    timeout_by_index: Any = None
    timeout_was_explicit: Any = None
    total_functions: Any = None
    uncapped_function_cfg_pairs: Any = None
    use_serial_fork_per_function: Any = None
    visible_code_labels: Any = None
    visible_filter: Any = None
    work_name: Any = None
    work_offset: Any = None
    worker_debug: Any = None
    worker_policy: Any = None
    workers: Any = None

    def run_8616(self) -> int:
        """Run the main CLI phases and return the process exit code."""
        phases: tuple[Callable[[], int | None], ...] = (
            self._phase_setup_8616,
            self._phase_seed_rank_dispatch_8616,
            self._phase_seed_inputs_8616,
            self._phase_build_pairs_dispatch_8616,
            self._phase_configure_display_8616,
            self._phase_build_tasks_dispatch_8616,
            self._phase_configure_execution_8616,
            self._phase_serial_fork_batch_dispatch_8616,
        )
        for phase in phases:
            _rc = phase()
            if _rc is not None:
                return _rc
        return _finish_batch_cli_8616(
            self.batch_context,
            decompiled=self.decompiled,
            failed=self.failed,
            emitted_indexes=self.emitted_indexes,
        )


    def _phase_setup_8616(self) -> int | None:
        """Run an extracted `_run_main_cli_8616` phase; return an exit code to abort."""
        self.args, self.timeout_was_explicit, self.effective_signature_catalog = _prepare_main_cli_args_8616(self.argv)
        print(f"/* loading: {self.args.binary} */", flush=True)
        self.runtime_header = render_c_runtime_header_8616(self.args.c_target)
        if self.runtime_header:
            print(self.runtime_header, end="" if self.runtime_header.endswith("\n") else "\n", flush=True)
        try:
            self.setup = _prepare_main_project_8616(self.args, self.effective_signature_catalog)
        except PackedExecutableRefusedError as ex:
            print(f"error: {ex}", file=sys.stderr, flush=True)
            return 7
        self.project = self.setup.project
        self.function_label = self.setup.function_label
        self.cod_metadata = self.setup.cod_metadata
        self.synthetic_globals = self.setup.synthetic_globals
        self.lst_metadata = self.setup.lst_metadata
        self.prefer_fast_recovery = self.setup.prefer_fast_recovery
        self.proc_resolved_to_linked_binary = self.setup.proc_resolved_to_linked_binary
        self.low_memory_path = _prefer_low_memory_path()
        _configure_display_catalog_cache_policy_8616(
            self.project,
            DisplayCatalogCachePolicy8616.from_runtime(
                ignore_local_sidecar_hints=bool(self.args.ignore_local_sidecar_hints),
                include_library_functions=bool(self.args.include_library_functions),
                function_discovery_backend=self.args.function_discovery_backend,
                pat_backend=self.args.pat_backend,
                max_functions=self.args.max_functions,
                timeout=self.args.timeout,
                window=self.args.window,
                rizin_timeout=self.args.rizin_timeout,
                low_memory=self.low_memory_path,
                auto_rizin_policy=os.environ.get("INERTIA_AUTO_RIZIN_8616", "default"),
                signature_catalog=self.effective_signature_catalog,
                catalog_timeout=self.args.catalog_timeout,
            ),
        )
        self.interactive_stdout = _stdout_is_interactive()
        self.precise_sidecar_regions = metadata_has_precise_code_regions(cast(Any, self.lst_metadata))
        if self.args.addr is not None:
            self.request_cache_inputs = DirectRequestCacheInputs8616.from_cli(
                self.args,
                signature_catalog=self.effective_signature_catalog,
            )
            assert self.request_cache_inputs is not None
            self.direct_context = _DirectAddrCliContext8616(
                args=self.args,
                project=self.project,
                function_label=self.function_label,
                cod_metadata=self.cod_metadata,
                synthetic_globals=self.synthetic_globals,
                lst_metadata=self.lst_metadata,
                prefer_fast_recovery=self.prefer_fast_recovery,
                proc_resolved_to_linked_binary=self.proc_resolved_to_linked_binary,
                low_memory_path=self.low_memory_path,
                interactive_stdout=self.interactive_stdout,
                precise_sidecar_regions=self.precise_sidecar_regions,
                timeout_was_explicit=self.timeout_was_explicit,
                request_cache_inputs=self.request_cache_inputs,
            )
            self.direct_lock_key = build_direct_request_cache_key_8616(self.request_cache_inputs)
            if not _direct_addr_work_requires_parent_lock_8616(self.direct_lock_key):
                return _run_direct_addr_cli_8616(self.direct_context)
            assert self.direct_lock_key is not None
            with _cache_key_lock("direct_addr_work", self.direct_lock_key):
                return _run_direct_addr_cli_8616(self.direct_context)
        print("/* discovering likely functions... */", flush=True)
        typing.cast(typing.Any, self.project)._inertia_cached_catalog_mode = False
        typing.cast(typing.Any, self.project)._inertia_hidden_signature_mode = False
        typing.cast(typing.Any, self.project)._inertia_display_truncated = False
        typing.cast(typing.Any, self.project)._inertia_uncapped_seeded_recovery = False
        self.cfg: object | None = None
        self.function_cfg_pairs: list[_FunctionCfgPair8616] = []
        self.ranked_binary_offsets: list[int] = []
        self.labeled_offsets: list[tuple[int, str]] = []
        self.ranked_labeled_total = 0
        self.total_functions = 0
        self.shown_total = 0
        self.direct_inventory_total: int | None = None
        self.prefer_ranked_hidden_sidecar_full_queue = False
        self.visible_code_labels = _function_discovery_code_labels(self.lst_metadata)
        self.recovery_code_labels = _recovery_code_labels(self.lst_metadata) if self.lst_metadata is not None else {}
        self.has_non_library_sidecar_hints = bool(self.visible_code_labels)
        self.include_library_functions = self.args.include_library_functions
        self.library_label_skipped_count = 0
        if self.include_library_functions and self.lst_metadata is not None:
            self.visible_code_labels = dict(getattr(self.lst_metadata, "code_labels", {}) or {})
            self.recovery_code_labels = dict(self.visible_code_labels)
        elif self.lst_metadata is not None:
            self.visible_filter = filter_code_labels_for_library_policy(self.lst_metadata, self.visible_code_labels)
            self.recovery_filter = filter_code_labels_for_library_policy(self.lst_metadata, self.recovery_code_labels)
            self.visible_code_labels = self.visible_filter.labels
            self.recovery_code_labels = self.recovery_filter.labels
            self.library_label_skipped_count = max(self.visible_filter.skipped_count, self.recovery_filter.skipped_count)
            if not self.visible_code_labels and not self.recovery_code_labels and getattr(self.lst_metadata, "code_labels", None):
                print(
                    "/* sidecar labels are signature/library-only; skipping them by default "
                    "(use --include-library-functions to include). */"
                )
        self.seed_code_labels = self.visible_code_labels or self.recovery_code_labels
        self.skipped_signature_labels = (
            len(_signature_matched_code_addrs(self.lst_metadata))
            if self.lst_metadata is not None and not self.include_library_functions
            else 0
        )
        if self.low_memory_path:
            print("/* Low-memory mode: using a smaller, safer function-discovery pass. */")
        self.packed_exe = None if self.args.proc is not None else getattr(self.project, "_inertia_packed_exe", None)
        return None
    def _phase_seed_inputs_8616(self) -> int | None:
        """Run an extracted `_run_main_cli_8616` phase; return an exit code to abort."""
        if self.skipped_signature_labels > 0:
            print(f"/* skipping {self.skipped_signature_labels} signature-matched function(s) by default. */")
        if self.library_label_skipped_count > 0:
            print(f"/* skipping {self.library_label_skipped_count} library-like sidecar function(s) by default. */")
        elif self.include_library_functions and self.lst_metadata is not None:
            print("/* including signature/library-labeled functions as requested. */")
        if self.cfg is not None:
            self.cfg_any = cast(Any, self.cfg)
            if self.function_label is not None and self.project.entry in self.cfg_any.functions:
                self.cfg_any.functions[self.project.entry].name = self.function_label
            else:
                self.rizin_names = getattr(self.project, "_inertia_rizin_function_names", {}) or {}
                for _addr_lp8616, _func_lp8616 in self.cfg_any.functions.items():
                    self.addr = _addr_lp8616
                    self.func = _func_lp8616
                    self.code_name = _lst_code_label(self.lst_metadata, _addr_lp8616, self.project.entry) if self.lst_metadata is not None else None
                    if self.code_name is not None:
                        _func_lp8616.name = self.code_name
                    elif isinstance(self.rizin_names, dict):
                        self.rz_name = self.rizin_names.get(_addr_lp8616)
                        if isinstance(self.rz_name, str) and self.rz_name:
                            _func_lp8616.name = self.rz_name
        return None
    def _phase_configure_display_8616(self) -> int | None:
        """Run an extracted `_run_main_cli_8616` phase; return an exit code to abort."""
        self.sidecar_preview_limit = None
        if (
            self.lst_metadata is not None
            and self.visible_code_labels
            and self.interactive_stdout
            and self.args.max_functions > 0
            and self.total_functions > self.args.max_functions
        ):
            self.sidecar_preview_limit = self.args.max_functions
        if self.lst_metadata is not None and self.visible_code_labels:
            print("/* == known function catalog (sidecar-backed) == */")
            print(
                _format_sidecar_function_catalog(self.lst_metadata, limit=self.sidecar_preview_limit, code_labels=self.visible_code_labels)
            )
            if self.sidecar_preview_limit is not None and self.total_functions > self.sidecar_preview_limit:
                print(f"/* catalog preview limited to first {self.sidecar_preview_limit} entries for responsiveness. */")
        if (
            self.args.addr is None
            and self.args.binary.suffix.lower() == ".exe"
            and self.function_cfg_pairs
            and len(self.function_cfg_pairs) > 1
            and not (
                self.lst_metadata is not None and not self.visible_code_labels and self.ranked_binary_offsets and self.args.max_functions > 0
            )
        ):
            self.function_cfg_pairs = _rank_function_cfg_pairs_for_display(self.project, self.function_cfg_pairs)
        if _exe_unlabeled_batch_gate_8616(
            self.args, self.lst_metadata, self.visible_code_labels
        ) and _seeded_supplement_needed_8616(self.args, self.function_cfg_pairs, self.ranked_binary_offsets):
            self.function_cfg_pairs = _supplement_function_cfg_pairs_with_seeded_recovery(
                self.project,
                self.function_cfg_pairs,
                timeout=self.args.timeout,
                target_count=self.args.max_functions,
            )
            self.function_cfg_pairs = _supplement_function_cfg_pairs_with_ranked_preview(
                self.project,
                self.function_cfg_pairs,
                self.ranked_binary_offsets,
                target_count=self.args.max_functions,
                timeout=self.args.timeout,
                window=self.args.window,
                low_memory=self.low_memory_path,
            )
            self.function_cfg_pairs = _rank_function_cfg_pairs_for_display(self.project, self.function_cfg_pairs)
            self.shown_total = len(self.function_cfg_pairs)
        self.uncapped_function_cfg_pairs = list(self.function_cfg_pairs)
        self.source_catalog = _source_region_catalog_evidence_8616(self.project)
        if (
            self.project.arch.name == "86_16"
            and self.source_catalog is not None
            and self.source_catalog.complete
            and self.uncapped_function_cfg_pairs
        ):
            attach_project_argument_evidence_ranges_8616(self.project, self.project)
            publish_discovered_indexed_alias_program_8616(
                self.project,
                tuple(function for _cfg, function in self.uncapped_function_cfg_pairs),
            )
        if (
            self.args.addr is None
            and self.args.binary.suffix.lower() == ".exe"
            and self.args.max_functions > 0
            and len(self.function_cfg_pairs) > self.args.max_functions
        ):
            self.function_cfg_pairs = self.function_cfg_pairs[: self.args.max_functions]
            self.shown_total = len(self.function_cfg_pairs)
        print(f"/* binary: {self.args.binary} */")
        print(f"/* arch: {self.project.arch.name} */")
        print(f"/* entry: {self.project.entry:#x} */")
        print(f"/* functions queued for decompilation: {self.total_functions} */")
        if self.args.max_functions > 0 and self.total_functions > self.shown_total:
            typing.cast(typing.Any, self.project)._inertia_display_truncated = True
            print(
                f"/* showing first {self.shown_total} functions because --max-functions={self.args.max_functions}; "
                "raise it or omit the option to decompile all queued functions */"
            )
        if (
            _exe_addr_none_batch_gate_8616(self.args)
            and self.lst_metadata is None
            and self.uncapped_function_cfg_pairs
            and _catalog_address_cache_storable_8616(self.project)
        ):
            _store_catalog_address_cache(self.project, self.args.binary, self.uncapped_function_cfg_pairs)
        self.function_tasks: list[FunctionWorkItem] = []
        self.result_map: dict[int, FunctionWorkResult] = {}
        self.fallback_tail_validation_by_index: dict[int, dict[str, object]] = {}
        return None
    def _phase_configure_execution_8616(self) -> int | None:
        """Run an extracted `_run_main_cli_8616` phase; return an exit code to abort."""
        _rc = self._exec_parallel_banner_8616()
        if _rc is not None:
            return _rc
        _rc = self._exec_policy_fields_8616()
        if _rc is not None:
            return _rc
        _rc = self._exec_batch_context_8616()
        if _rc is not None:
            return _rc
        return None

    def _sweep_budget_exhausted(self) -> bool:
        """Hoisted nested function (callable via `self`)."""
        return self.sweep_deadline is not None and time.monotonic() >= self.sweep_deadline

    def _phase_seed_rank_8616(self) -> int | None:
        """Phase extracted from `_run_main_cli_8616`."""
        try:
            self.ranking_start = time.perf_counter()
            self.labeled_offsets, self.ranking_cache_hit = _rank_labeled_function_entries_cached(
                self.project,
                list(self.seed_code_labels.items()),
                self.lst_metadata,
            )
            self.ranking_elapsed_ms = (time.perf_counter() - self.ranking_start) * 1000.0
            print(
                f"/* sidecar label ranking prepared {len(self.labeled_offsets)} entries in "
                f"{self.ranking_elapsed_ms:.1f}ms{' (cache hit)' if self.ranking_cache_hit else ''}. */"
            )
            self.ranked_labeled_total = len(self.labeled_offsets)
            if self.args.max_functions > 0:
                self.labeled_offsets = self.labeled_offsets[: self.args.max_functions]
        except Exception as ex:
            print(f"/* Listing-backed function catalog setup failed: {ex} */")
            print("\n/* == entry asm == */")
            print(_format_first_block_asm(self.project, self.project.entry))
            return 5
        return None

    def _phase_seed_rank_8616_else_8616(self) -> int | None:
        """Else-branch of the extracted phase."""
        _rc = self._phase_seed_rank_8616_else_8616_part0_8616()
        if _rc is not None:
            return _rc
        _rc = self._phase_seed_rank_8616_else_8616_part1_8616()
        if _rc is not None:
            return _rc
        _rc = self._phase_seed_rank_8616_else_8616_part2_8616()
        if _rc is not None:
            return _rc
        _rc = self._phase_seed_rank_8616_else_8616_part3_8616()
        if _rc is not None:
            return _rc
        _rc = self._phase_seed_rank_8616_else_8616_part4_8616()
        if _rc is not None:
            return _rc
        return None


    def _phase_build_pairs_8616(self) -> int | None:
        """Phase extracted from `_run_main_cli_8616`."""
        self.total_functions = self.ranked_labeled_total or len(self.labeled_offsets)
        self.shown_total = len(self.labeled_offsets)
        return None

    def _phase_build_pairs_8616_else_8616(self) -> int | None:
        """Else-branch of the extracted phase."""
        _rc = self._phase_build_pairs_8616_else_8616_part0_8616()
        if _rc is not None:
            return _rc
        return None

    def _phase_build_tasks_8616(self) -> int | None:
        """Phase extracted from `_run_main_cli_8616`."""
        for _index_lp8616, (_offset_lp8616, _name_lp8616) in enumerate(self.labeled_offsets, start=1):
            self.index = _index_lp8616
            self.offset = _offset_lp8616
            self.name = _name_lp8616
            self.work_offset, self.work_name = _canonicalize_sidecar_work_offset_8616(
                self.project,
                self.lst_metadata,
                _offset_lp8616,
                _name_lp8616,
            )
            self.placeholder = _make_placeholder_function(self.project, self.work_offset, self.work_name or _name_lp8616)
            self.function_tasks.append(
                FunctionWorkItem(
                    index=_index_lp8616,
                    function_cfg=None,
                    function=self.placeholder,
                    recovery_addr=_offset_lp8616,
                )
            )
        return None
    def _phase_build_tasks_8616_else_8616(self) -> int | None:
        """Else-branch of the extracted phase."""
        _rc = self._phase_build_tasks_8616_else_8616_part0_8616()
        if _rc is not None:
            return _rc
        return None

    def _phase_serial_fork_batch_8616(self) -> int | None:
        """Phase extracted from `_run_main_cli_8616`."""
        self.parallel_timeout_model = build_parallel_clean_worker_timeout_model(
            self.args.timeout,
            explicit_timeout=self.timeout_was_explicit,
        )
        self.timeout_by_index = {
            item.index: _batch_function_decompile_timeout_8616(
                self.batch_context,
                cast(_AngrFunction, item.function),
                self.parallel_timeout_model,
            )
            for item in self.function_tasks
        }
        self.executor = DaemonThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="func-clean")
        try:
            self.item_by_future = {
                self.executor.submit(
                    _run_serial_clean_process_work_item_8616,
                    self.batch_context,
                    item,
                    timeout=self.timeout_by_index[item.index],
                ): item
                for item in prioritize_clean_function_work_8616(
                    self.function_tasks,
                    function_complexity=_function_complexity,
                )
            }
            self.pending = set(self.item_by_future)
            while self.pending:
                self.done, self._ = wait(self.pending, return_when=FIRST_COMPLETED)
                for _future_lp8616 in sorted(self.done, key=lambda candidate: self.item_by_future[candidate].index):
                    self.future = _future_lp8616
                    self.item = self.item_by_future[_future_lp8616]
                    self.function = cast(_AngrFunction, self.item.function)
                    self.function_timeout = self.timeout_by_index[self.item.index]
                    self.worker_debug = (
                        f"[dbg] clean parallel function worker: start "
                        f"{_function_work_item_recovery_addr_8616(self.item):#x} {self.function.name} "
                        f"requested_timeout={self.function_timeout}s "
                        f"hard_timeout={_serial_clean_worker_outer_timeout_8616(self.function_timeout)}s\n"
                    )
                    try:
                        self.result = _future_lp8616.result()
                    except Exception as ex:
                        self.result = FunctionWorkResult(
                            index=self.item.index,
                            status="error",
                            payload=f"Clean parallel worker failed: {_describe_exception(ex)}",
                            debug_output=self.worker_debug,
                            function=self.item.function,
                            function_cfg=self.item.function_cfg,
                            elapsed=float(self.function_timeout),
                        )
                    else:
                        self.result = replace(
                            self.result,
                            debug_output=self.worker_debug + self.result.debug_output,
                        )
                    self.result_map[self.item.index] = self.result
                    self.d, self.f = _emit_function_result(
                        self.item,
                        self.result,
                        project=self.project,
                        args=self.args,
                        lst_metadata=self.lst_metadata,
                        cod_metadata=self.cod_metadata,
                        synthetic_globals=self.synthetic_globals,
                        precise_sidecar_regions=self.precise_sidecar_regions,
                        allow_heavy_fallbacks=self.allow_heavy_fallbacks,
                        interactive_stdout=self.interactive_stdout,
                        use_serial_fork_per_function=self.use_serial_fork_per_function,
                        fallback_tail_validation_by_index=self.fallback_tail_validation_by_index,
                        result_state_by_index=self.result_map,
                        timeout_was_explicit=self.timeout_was_explicit,
                    )
                    self.decompiled += self.d
                    self.failed += self.f
                    self.emitted_indexes.add(self.item.index)
                    self.pending.discard(_future_lp8616)
        finally:
            self.executor.shutdown(wait=True, cancel_futures=False)
        return None

    def _phase_serial_fork_batch_8616_else_8616(self) -> int | None:
        """Else-branch of the extracted phase."""
        _rc = self._phase_serial_fork_batch_8616_else_8616_part0_8616()
        if _rc is not None:
            return _rc
        return None
    def _exec_parallel_banner_8616(self) -> int | None:
        """Run an extracted execution-config phase; return an exit code to abort."""
        self.selection_target = "decompilation" if self.args.max_functions <= 0 and self.args.addr is None else "display"
        if (self.selection_target == "decompilation" and self.lst_metadata is None
                and self.direct_inventory_total is not None and self.shown_total < self.direct_inventory_total):
            print(f"[catalog] queued {self.shown_total} of {self.direct_inventory_total} candidate entries; "
                  f"catalog recovery budget={self.args.catalog_timeout}s. Unqueued candidates are not decompiled. "
                  "Increasing --catalog-timeout may recover more; candidates are not proven functions.", file=sys.stderr)
        print(f"/* info: selected {self.shown_total} function(s) for {self.selection_target} */")
        self.requested_workers = _choose_function_parallelism(len(self.function_tasks))
        self.workers = self.requested_workers
        if self.lst_metadata is not None and self.visible_code_labels:
            self.workers = 1
        if any(item.function_cfg is None for item in self.function_tasks):
            self.workers = 1
        if _exe_unlabeled_batch_gate_8616(self.args, self.lst_metadata, self.visible_code_labels):
            self.workers = 1
        if getattr(self.project, "_inertia_supplemental_scan_used", False) and _should_force_serial_supplemental_decompilation(
            len(self.function_tasks)
        ):
            self.workers = 1
        if (
            _exe_addr_none_batch_gate_8616(self.args)
            and 0 < self.args.max_functions <= 2
            and self.lst_metadata is not None
            and self.include_library_functions
        ):
            self.workers = 1
        return None
    def _exec_policy_fields_8616(self) -> int | None:
        """Run an extracted execution-config phase; return an exit code to abort."""
        if (
            _exe_addr_none_batch_gate_8616(self.args)
            and 0 < self.args.max_functions <= 2
            and self.low_memory_path
        ):
            self.workers = 1
        self.isolated_function_decompilation_required = requires_isolated_function_decompilation(
            architecture=self.project.arch.name,
            binary_suffix=self.args.binary.suffix,
            address_requested=self.args.addr is not None,
        )
        self.forced_serial_function_decomp = os.environ.get(_FORCE_SERIAL_FUNCTION_DECOMP_ENV, "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        self.worker_policy = select_function_worker_policy_8616(
            isolation_required=self.isolated_function_decompilation_required,
            sidecar_available=self.lst_metadata is not None,
            full_sweep=self.args.addr is None and self.args.max_functions <= 0,
            include_library_functions=self.include_library_functions,
            posix_available=os.name == "posix",
            function_count=len(self.function_tasks),
            shared_worker_count=(
                self.requested_workers if self.isolated_function_decompilation_required else self.workers
            ),
            clean_process_override=clean_process_override_8616(
                os.environ.get("INERTIA_ENABLE_SERIAL_FORK_PER_FUNCTION")
            ),
        )
        self.workers = self.worker_policy.workers
        self.use_serial_fork_per_function = self.worker_policy.mode is FunctionWorkerMode8616.CLEAN_PROCESS
        if self.use_serial_fork_per_function and self.workers > 1:
            print(f"/* parallel function decompilation: {self.workers} clean processes, one function per process */")
        elif self.workers > 1:
            print(f"/* parallel function decompilation: {self.workers} workers, shared imports */")
        elif self.use_serial_fork_per_function:
            print("/* parallel function decompilation: disabled; using one clean serial process at a time */")
        elif self.forced_serial_function_decomp:
            print("/* parallel function decompilation: disabled (forced serial) */")
        else:
            print("/* parallel function decompilation: disabled (RAM pressure or single function) */")
        self.force_isolated_function_projects = self.isolated_function_decompilation_required
        typing.cast(typing.Any, self.project)._inertia_fast_direct_probe = bool(
                self.args.addr is not None
                and os.environ.get("INERTIA_FAST_DIRECT_PROBE", "").strip().lower() in {"1", "true", "yes", "on"}
                and self.timeout_was_explicit
                and isinstance(self.args.timeout, int)
                and self.args.timeout <= 6
            )
        if self.force_isolated_function_projects:
            print("/* parallel x86-16 decompilation: using one fresh analysis project per shown function for stability. */")
        self.allow_heavy_fallbacks = allows_heavy_fallbacks_for_run(
            interactive_stdout=self.interactive_stdout,
            max_functions=self.args.max_functions,
            addr_requested=self.args.addr is not None,
        )
        return None
    def _exec_batch_context_8616(self) -> int | None:
        """Run an extracted execution-config phase; return an exit code to abort."""
        self.sweep_deadline: float | None = None
        self.sweep_budget_sec_raw = os.environ.get("INERTIA_SWEEP_BUDGET_SEC")
        if self.args.addr is None:
            self.sweep_budget_sec: int | None = None
            if self.sweep_budget_sec_raw is not None and self.sweep_budget_sec_raw.strip():
                try:
                    self.sweep_budget_sec = int(self.sweep_budget_sec_raw.strip())
                except ValueError:
                    self.sweep_budget_sec = None
            if self.sweep_budget_sec is None:
                # Default to unbounded whole-binary sweeps. Callers can opt into a
                # hard cap with INERTIA_SWEEP_BUDGET_SEC=<seconds>.
                self.sweep_budget_sec = 0
            if self.sweep_budget_sec <= 0:
                self.sweep_deadline = None
                print("/* sweep budget: disabled via INERTIA_SWEEP_BUDGET_SEC */")
            else:
                self.sweep_deadline = time.monotonic() + float(self.sweep_budget_sec)
                print(f"/* sweep budget: {self.sweep_budget_sec}s (set INERTIA_SWEEP_BUDGET_SEC=0 to disable) */")
        self.batch_context = _BatchCliContext8616(
            args=self.args,
            project=self.project,
            function_tasks=self.function_tasks,
            result_map=self.result_map,
            fallback_tail_validation_by_index=self.fallback_tail_validation_by_index,
            lst_metadata=self.lst_metadata,
            cod_metadata=self.cod_metadata,
            synthetic_globals=self.synthetic_globals,
            visible_code_labels=self.visible_code_labels,
            include_library_functions=self.include_library_functions,
            low_memory_path=self.low_memory_path,
            interactive_stdout=self.interactive_stdout,
            precise_sidecar_regions=self.precise_sidecar_regions,
            timeout_was_explicit=self.timeout_was_explicit,
            use_serial_fork_per_function=self.use_serial_fork_per_function,
            allow_heavy_fallbacks=self.allow_heavy_fallbacks,
            force_isolated_function_projects=self.force_isolated_function_projects,
            sweep_deadline=self.sweep_deadline,
            shown_total=self.shown_total,
            skipped_signature_labels=self.skipped_signature_labels,
        )
        if self.workers <= 1:
            return _run_serial_batch_cli_8616(self.batch_context)
        self.decompiled = 0
        self.failed = 0
        self.emitted_indexes: set[int] = set()
        self.allow_isolated_retry_for_parallel_tasks = self.interactive_stdout or self.args.max_functions <= 0 or self.args.addr is not None
        return None
    def _seed_else_ranked_offsets_8616(self) -> int | None:
        """Recover ranked binary offsets for the seed catalog; return an exit code to abort."""
        if self.lst_metadata is not None and not self.visible_code_labels:
            if self.recovery_code_labels:
                print(
                    "/* Signature-bounded sidecar labels available as bounded hints; "
                    "recovering binary-owned functions from direct call/prologue evidence before generic CFG recovery. */"
                )
            if self.args.max_functions <= 0 and self.ranked_binary_offsets and not self.has_non_library_sidecar_hints:
                self.prefer_ranked_hidden_sidecar_full_queue = True
                self.total_functions = len(self.ranked_binary_offsets)
                self.shown_total = len(self.ranked_binary_offsets)
                print(
                    "/* hidden-sidecar EXE: queueing ranked direct-binary function candidates for full decompilation "
                    "without waiting for whole-program CFG recovery. */"
                )
            if self.deferred_exe_display_cap and self.ranked_binary_offsets and not self.has_non_library_sidecar_hints:
                # Hidden-sidecar EXEs only have signature/library labels. Do not
                # spend time pre-recovering a capped preview here; queue ranked
                # binary-owned candidates and recover each one in the streaming
                # serial lane so the first self.function can be emitted sooner.
                self.prefer_ranked_hidden_sidecar_full_queue = True
                self.total_functions = len(self.ranked_binary_offsets)
                self.shown_total = min(len(self.ranked_binary_offsets), self.args.max_functions)
                print(
                    "/* hidden-sidecar EXE: using ranked direct-binary function candidates; "
                    "recovering selected functions lazily for streaming output. */"
                )
            try:
                if not self.function_cfg_pairs and not self.prefer_ranked_hidden_sidecar_full_queue:
                    self.seeded_recovery_result = _run_with_timeout_in_daemon_thread(
                        lambda: _recover_seeded_exe_functions(
                            self.project,
                            timeout=self.args.catalog_timeout,
                            limit=self.discovery_limit,
                            return_addrs=True,
                        ),
                        timeout=self.args.catalog_timeout + 2,
                        thread_name_prefix="seed-catalog",
                    )
                    if isinstance(self.seeded_recovery_result, tuple) and len(self.seeded_recovery_result) == 2:
                        self.function_cfg_pairs = cast(list[_FunctionCfgPair8616], self.seeded_recovery_result[0])
                        self.seeded_catalog_addrs = self.seeded_recovery_result[1]
                    else:
                        self.function_cfg_pairs = self.seeded_recovery_result
                        self.seeded_catalog_addrs = [function.addr for _, function in self.function_cfg_pairs]
            except Exception as ex:
                self.catalog_error = ex
                self.function_cfg_pairs = self.function_cfg_pairs if self.function_cfg_pairs else []
                self.seeded_catalog_addrs = []
            else:
                pass
            if self.function_cfg_pairs and not self.total_functions:
                self.total_functions = len(self.seeded_catalog_addrs)
                self.shown_total = len(self.function_cfg_pairs)
        return None
    def _seed_else_sweep_tail_8616(self) -> int | None:
        """Run an extracted seed-tail lane; return an exit code to abort."""
        if self.cfg is None and not self.function_cfg_pairs and not self.prefer_ranked_hidden_sidecar_full_queue:
            self.fast_seed_pairs: list[_FunctionCfgPair8616] = []
            print("/* Whole-program control-flow recovery failed; attempting a quick function-entry scan fallback. */")
            self.fast_seed_pairs = cast(
                list[_FunctionCfgPair8616],
                _recover_fast_seed_functions(
                    self.project,
                    timeout=self.args.catalog_timeout,
                    limit=self.discovery_limit,
                ),
            )
            if self.fast_seed_pairs:
                self.function_cfg_pairs = self.fast_seed_pairs
                self.total_functions = len(self.function_cfg_pairs)
                self.shown_total = len(self.function_cfg_pairs)
                self.cfg = None
            elif self.prefer_ranked_hidden_sidecar_full_queue:
                pass
            elif not self.prefer_ranked_hidden_sidecar_full_queue and (
                self.args.addr is None and self.args.binary.suffix.lower() == ".exe" and self.ranked_binary_offsets
            ):
                print(
                    "/* Falling back to ranked direct-binary function addresses; "
                    "recovering only the shown subset lazily. */"
                )
            else:
                if isinstance(self.catalog_error, FuturesTimeoutError):
                    self.detail = "Timed out"
                elif isinstance(self.catalog_error, Exception):
                    self.detail = _describe_exception(self.catalog_error)
                elif self.catalog_error is not None:
                    self.detail = str(self.catalog_error)
                else:
                    self.detail = "Unknown failure"
                print(f"/* Function catalog recovery failed: {self.detail} */")
                if self.packed_exe is not None:
                    print(
                        f"/* hint: {self.args.binary.name} looks packed ({self.packed_exe}); startup-stub output may be the current limit. */"
                    )
                print("\n/* == lift break probe == */")
                print(_probe_lift_break(self.project, self.project.entry))
                print("\n/* == entry asm == */")
                print(_format_first_block_asm(self.project, self.project.entry))
                print("\n/* == non-optimized disassembly == */")
                self.start, self.end = _infer_linear_disassembly_window(self.project, self.project.entry)
                print(_format_asm_range(self.project, self.start, self.end))
                return 5
        return None
    def _seed_else_showcase_8616(self) -> int | None:
        """Run an extracted seed-tail lane; return an exit code to abort."""
        if (
            self.cfg is None
            and not self.function_cfg_pairs
            and self.project.arch.name == "86_16"
            and not self.prefer_bounded_catalog
            and not self.prefer_ranked_hidden_sidecar_full_queue
        ):
            print("/* Whole-program function discovery failed; attempting a smaller entry-area recovery pass. */")
            try:
                self.cfg = _run_with_timeout_in_daemon_thread(
                    lambda: _recover_partial_cfg(
                        self.project,
                        window=self.args.window,
                        low_memory=self.low_memory_path,
                    ),
                    timeout=self.args.timeout,
                    thread_name_prefix="catalog-fallback",
                )
            except Exception as ex:
                self.catalog_error = ex
        return None


    def _phase_seed_rank_8616_else_8616_part1_8616(self) -> int | None:
        """Run an extracted sub-phase; return an exit code to abort."""
        self.prefer_bounded_catalog = (
            self.lst_metadata is None and self.project.arch.name == "86_16" and self.args.binary.suffix.lower() == ".exe"
        )
        self.cached_catalog_addrs = _load_catalog_address_cache(self.project, self.args.binary) if self.prefer_bounded_catalog else []
        if self.cached_catalog_addrs:
            typing.cast(typing.Any, self.project)._inertia_cached_catalog_mode = True
            print("/* using cached discovered function addresses before running new control-flow recovery. */")
            self.function_cfg_pairs = _recover_cached_function_pairs(
                self.project,
                addrs=self.cached_catalog_addrs,
                timeout=self.args.catalog_timeout,
                limit=self.discovery_limit,
            )
            if self.function_cfg_pairs:
                try:
                    self.display_cache_key = _catalog_address_cache_key_8616(self.project, self.args.binary)
                    self.cached_catalog_int_addrs = [addr for addr in self.cached_catalog_addrs if isinstance(addr, int)]
                    self.supplemented_cached_result = cast(
                        tuple[list[_FunctionCfgPair8616], list[int]],
                        _run_with_timeout_in_daemon_thread(
                            lambda: _supplement_cached_seeded_recovery(
                                self.project,
                                self.function_cfg_pairs,
                                self.cached_catalog_int_addrs,
                                region_span=0x120,
                                per_function_timeout=1,
                                limit=self.discovery_limit,
                                cache_key=self.display_cache_key,
                            ),
                            timeout=min(max(1, self.args.timeout), 2),
                            thread_name_prefix="cached-display-supplement",
                        ),
                    )
                    self.function_cfg_pairs, self.cached_catalog_addrs = self.supplemented_cached_result
                except FuturesTimeoutError:
                    pass
                self.total_functions = len(self.cached_catalog_addrs)
                self.shown_total = len(self.function_cfg_pairs)
        return None
    def _phase_seed_rank_8616_else_8616_part2_8616(self) -> int | None:
        """Run an extracted sub-phase; return an exit code to abort."""
        if self.prefer_bounded_catalog and not self.function_cfg_pairs:
            try:
                # This recovery mutates the shared angr self.project. Its internal
                # candidate self.deadlines provide the bound; an outer daemon
                # timeout would leave a live worker polluting fallback CFGs.
                self.function_cfg_pairs = _recover_fast_exe_catalog(
                    self.project,
                    catalog_timeout=self.args.catalog_timeout,
                    timeout=self.args.timeout,
                    window=self.args.window,
                    low_memory=self.low_memory_path,
                    limit=self.discovery_limit,
                )
            except (_AnalysisTimeout, Exception) as ex:
                self.catalog_error = ex
                print(
                    "/* Quick EXE function discovery timed out; falling back to a bounded control-flow recovery pass. */"
                )
                self.function_cfg_pairs = []
            if self.function_cfg_pairs:
                self.source_region_evidence = _source_region_catalog_evidence_8616(self.project)
                if self.source_region_evidence is not None and not self.source_region_evidence.complete:
                    print(
                        "/* Function catalog recovery failed: startup-bounded source catalog was incomplete; "
                        f"failed addresses={','.join(hex(addr) for addr in self.source_region_evidence.failed_addrs) or 'none'} */"
                    )
                    return 5
                self.total_functions = max(
                    len(self.function_cfg_pairs),
                    self.source_region_evidence.raw_fact_count if self.source_region_evidence is not None else 0,
                )
                self.shown_total = len(self.function_cfg_pairs)
        return None
    def _phase_seed_rank_8616_else_8616_part3_8616(self) -> int | None:
        """Run an extracted sub-phase; return an exit code to abort."""
        if self.prefer_bounded_catalog and not self.function_cfg_pairs:
            print(
                "/* No helper metadata for this x86-16 EXE; first trying a small scan near program entry before whole-program control-flow recovery. */"
            )
            if not self.function_cfg_pairs:
                try:
                    self.cfg = _run_with_timeout_in_daemon_thread(
                        lambda: _recover_partial_cfg(
                            self.project,
                            window=self.args.window,
                            low_memory=self.low_memory_path,
                        ),
                        timeout=self.args.timeout,
                        thread_name_prefix="catalog-fallback",
                    )
                except Exception as ex:
                    self.catalog_error = ex
        if self.cfg is None and not self.function_cfg_pairs and not self.prefer_ranked_hidden_sidecar_full_queue:
            if self.prefer_bounded_catalog:
                print(
                    "/* Small entry-area recovery failed; attempting whole-program control-flow recovery as a last resort. */"
                )
            try:
                self.cfg = _run_with_timeout_in_daemon_thread(
                    lambda: _recover_cfg(
                        self.project,
                        self.args.binary,
                        base_addr=self.args.base_addr,
                        window=self.args.window,
                        low_memory=self.low_memory_path,
                    ),
                    timeout=self.args.timeout,
                    thread_name_prefix="catalog",
                )
            except Exception as ex:
                self.catalog_error = ex
        return None
    def _phase_build_pairs_8616_else_8616_part0_8616(self) -> int | None:
        """Run an extracted sub-phase; return an exit code to abort."""
        if not self.function_cfg_pairs and self.cfg is not None:
            _rc = self._phase_build_pairs_8616_else_8616_part0_8616_b0()
            if _rc is not None:
                return _rc
            _rc = self._phase_build_pairs_8616_else_8616_part0_8616_b1()
            if _rc is not None:
                return _rc
        elif (
            not self.function_cfg_pairs
            and self.args.addr is None
            and self.args.binary.suffix.lower() == ".exe"
            and self.ranked_binary_offsets
        ):
            self.shown_total = len(self.ranked_binary_offsets)
            if self.args.max_functions > 0:
                self.shown_total = min(self.shown_total, self.args.max_functions)
        return None
    def _phase_build_tasks_8616_else_8616_part0_8616(self) -> int | None:
        """Run an extracted sub-phase; return an exit code to abort."""
        if (
            self.args.addr is None and self.args.binary.suffix.lower() == ".exe" and not self.function_cfg_pairs and self.ranked_binary_offsets
        ):
            self.preview_addrs = self.ranked_binary_offsets
            if (
                self.lst_metadata is not None
                and not self.visible_code_labels
                and self.include_library_functions
                and self.args.max_functions <= 0
            ):
                self.function_tasks = [
                    FunctionWorkItem(
                        index=index,
                        function_cfg=None,
                        function=_make_placeholder_function(self.project, addr, f"sub_{addr:x}"),
                        recovery_addr=addr,
                    )
                    for index, addr in enumerate(self.preview_addrs, start=1)
                ]
                self.shown_total = len(self.function_tasks)
            else:
                if self.args.max_functions > 0:
                    self.preview_addrs = self.preview_addrs[: self.args.max_functions]
                elif self.interactive_stdout and len(self.preview_addrs) > 24:
                    self.preview_addrs = self.preview_addrs[: _default_exe_showcase_cap(len(self.preview_addrs), self.args.timeout)]
                self.shown_total = len(self.preview_addrs)
                if self.lst_metadata is not None and not self.visible_code_labels:
                    self.function_tasks = [
                        FunctionWorkItem(
                            index=index,
                            function_cfg=None,
                            function=_make_placeholder_function(self.project, addr, f"sub_{addr:x}"),
                            recovery_addr=addr,
                        )
                        for index, addr in enumerate(self.preview_addrs, start=1)
                    ]
                else:
                    self.function_tasks = _prepare_ranked_binary_preview_items(
                        self.project,
                        self.ranked_binary_offsets,
                        max_count=self.shown_total,
                        timeout=self.args.timeout,
                        window=self.args.window,
                        low_memory=self.low_memory_path,
                    )
        else:
            _rc = self._phase_build_tasks_8616_else_8616_part0_8616_o0()
            if _rc is not None:
                return _rc
            _rc = self._phase_build_tasks_8616_else_8616_part0_8616_o1()
            if _rc is not None:
                return _rc
        return None
    def _phase_serial_fork_batch_8616_else_8616_part0_8616(self) -> int | None:
        """Run an extracted sub-phase; return an exit code to abort."""
        _rc = self._phase_serial_fork_batch_8616_else_8616_part0_8616_b0()
        if _rc is not None:
            return _rc
        _rc = self._phase_serial_fork_batch_8616_else_8616_part0_8616_b1()
        if _rc is not None:
            return _rc
        return None


    def _phase_seed_rank_8616_else_8616_part4_8616_b0(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        if (
            self.cfg is None
            and not self.function_cfg_pairs
            and self.project.arch.name == "86_16"
            and not self.prefer_bounded_catalog
            and not self.prefer_ranked_hidden_sidecar_full_queue
        ):
            print("/* Whole-program function discovery failed; attempting a smaller entry-area recovery pass. */")
            try:
                self.cfg = _run_with_timeout_in_daemon_thread(
                    lambda: _recover_partial_cfg(
                        self.project,
                        window=self.args.window,
                        low_memory=self.low_memory_path,
                    ),
                    timeout=self.args.timeout,
                    thread_name_prefix="catalog-fallback",
                )
            except Exception as ex:
                self.catalog_error = ex
        return None
    def _phase_build_pairs_8616_else_8616_part0_8616_b0(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        self.limit = self.args.max_functions if self.args.max_functions > 0 else None
        self.defer_limit_until_after_seed_ranking = self.args.addr is None and self.args.binary.suffix.lower() == ".exe"
        self.functions, self.total_functions = cast(
            tuple[list[_AngrFunction], int],
            _interesting_functions(self.cfg, limit=None if self.defer_limit_until_after_seed_ranking else self.limit),
        )
        self.shown_total = len(self.functions)
        self.function_cfg_pairs = [(self.cfg, function) for function in self.functions]
        if self.args.addr is None and self.args.binary.suffix.lower() == ".exe":
            self._seeded_pairs_and_addrs = _recover_seeded_exe_functions(
                self.project,
                timeout=self.args.catalog_timeout,
                limit=None if (self.limit is None or self.defer_limit_until_after_seed_ranking) else max(0, self.limit - self.shown_total),
                return_addrs=True,
            )
            if isinstance(self._seeded_pairs_and_addrs, tuple) and len(self._seeded_pairs_and_addrs) == 2:
                self.seeded_pairs = cast(list[_FunctionCfgPair8616], self._seeded_pairs_and_addrs[0])
                self.seeded_addrs = self._seeded_pairs_and_addrs[1]
            else:
                self.seeded_pairs, self.seeded_addrs = self._seeded_pairs_and_addrs, []
            if self.seeded_pairs:
                if isinstance(self.seeded_addrs, (list, tuple)):
                    self.discovered_addrs = set(self.seeded_addrs)
                    self.existing_addrs = {function.addr for function in self.functions}
                    self.recovered_seed_addrs = {function.addr for _, function in self.seeded_pairs}
                    if self.discovered_addrs - (self.existing_addrs | self.recovered_seed_addrs):
                        typing.cast(typing.Any, self.project)._inertia_uncapped_seeded_recovery = True
                self.seen_existing = {function.addr for function in self.functions}
                self.seeded_pairs = _rank_function_cfg_pairs_for_display(self.project, self.seeded_pairs)
                for _function_cfg_lp8616, _function_lp8616 in self.seeded_pairs:
                    self.function_cfg = _function_cfg_lp8616
                    self.function = _function_lp8616
                    if _function_lp8616.addr in self.seen_existing:
                        continue
                    self.function_cfg_pairs.append((_function_cfg_lp8616, _function_lp8616))
                    self.seen_existing.add(_function_lp8616.addr)
                self.function_cfg_pairs = _rank_function_cfg_pairs_for_display(self.project, self.function_cfg_pairs)
                if self.limit is not None and self.defer_limit_until_after_seed_ranking:
                    self.function_cfg_pairs = self.function_cfg_pairs[:self.limit]
                self.shown_total = len(self.function_cfg_pairs)
                self.total_functions = max(self.total_functions, len(self.seen_existing | set(self.seeded_addrs)))
                typing.cast(typing.Any, self.project)._inertia_supplemental_scan_used = True
            elif self.limit is not None and self.defer_limit_until_after_seed_ranking:
                self.function_cfg_pairs = self.function_cfg_pairs[:self.limit]
                self.shown_total = len(self.function_cfg_pairs)
        return None
    def _phase_build_pairs_8616_else_8616_part0_8616_b1(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        if (
            self.args.addr is None
            and self.args.binary.suffix.lower() == ".exe"
            and self.shown_total <= 1
            and not (self.lst_metadata is not None and not self.visible_code_labels and self.ranked_binary_offsets)
        ):
            self.supplemental_pairs = _supplement_functions_from_prologue_scan(
                self.project,
                {function.addr for function in self.functions},
            )
            if self.supplemental_pairs:
                self.function_cfg_pairs.extend(self.supplemental_pairs)
                self.function_cfg_pairs = _rank_function_cfg_pairs_for_display(self.project, self.function_cfg_pairs)
                self.shown_total = len(self.function_cfg_pairs)
                self.total_functions = max(self.total_functions, self.shown_total)
                typing.cast(typing.Any, self.project)._inertia_supplemental_scan_used = True
        return None
    def _phase_build_tasks_8616_else_8616_part0_8616_o0(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        for _index_lp8616, (_function_cfg_lp8616, _function_lp8616) in enumerate(self.function_cfg_pairs, start=1):
            self.index = _index_lp8616
            self.function_cfg = _function_cfg_lp8616
            self.function = _function_lp8616
            self.function_tasks.append(
                FunctionWorkItem(
                    index=_index_lp8616,
                    function_cfg=_function_cfg_lp8616,
                    function=_function_lp8616,
                    recovery_addr=function_original_addr(_function_lp8616),
                )
            )
        if _library_ranked_task_gate_8616(
            self.args, self.lst_metadata, self.visible_code_labels, self.include_library_functions, self.ranked_binary_offsets
        ) and self.args.max_functions <= 0:
            self.existing_by_addr = {
                getattr(item.function, "addr", None): item
                for item in self.function_tasks
                if isinstance(getattr(item.function, "addr", None), int)
            }
            self.function_tasks = []
            for _index_lp8616, _addr_lp8616 in enumerate(self.ranked_binary_offsets, start=1):
                self.index = _index_lp8616
                self.addr = _addr_lp8616
                self.existing = self.existing_by_addr.get(_addr_lp8616)
                if self.existing is not None:
                    self.function_tasks.append(
                        FunctionWorkItem(
                            index=_index_lp8616,
                            function_cfg=self.existing.function_cfg,
                            function=self.existing.function,
                            recovery_addr=self.existing.recovery_addr,
                        )
                    )
                    continue
                self.function_tasks.append(
                    FunctionWorkItem(
                        index=_index_lp8616,
                        function_cfg=None,
                        function=_make_placeholder_function(self.project, _addr_lp8616, f"sub_{_addr_lp8616:x}"),
                        recovery_addr=_addr_lp8616,
                    )
                )
            self.shown_total = len(self.function_tasks)
        return None
    def _phase_build_tasks_8616_else_8616_part0_8616_o1(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        if _library_ranked_task_gate_8616(
            self.args, self.lst_metadata, self.visible_code_labels, self.include_library_functions, self.ranked_binary_offsets
        ) and self.args.max_functions > 0:
            self.existing_by_addr = {
                getattr(item.function, "addr", None): item
                for item in self.function_tasks
                if isinstance(getattr(item.function, "addr", None), int)
            }
            self.replacement_tasks: list[FunctionWorkItem] = []
            for _index_lp8616, _addr_lp8616 in enumerate(self.ranked_binary_offsets, start=1):
                self.index = _index_lp8616
                self.addr = _addr_lp8616
                self.existing = self.existing_by_addr.get(_addr_lp8616)
                if self.existing is not None:
                    self.function_tasks.append(
                        FunctionWorkItem(
                            index=_index_lp8616,
                            function_cfg=self.existing.function_cfg,
                            function=self.existing.function,
                            recovery_addr=self.existing.recovery_addr,
                        )
                    )
                    continue
                self.function_tasks.append(
                    FunctionWorkItem(
                        index=_index_lp8616,
                        function_cfg=None,
                        function=_make_placeholder_function(self.project, _addr_lp8616, f"sub_{_addr_lp8616:x}"),
                        recovery_addr=_addr_lp8616,
                    )
                )
            self.function_tasks = self.replacement_tasks
            self.shown_total = len(self.function_tasks)
        return None
    def _phase_serial_fork_batch_8616_else_8616_part0_8616_b0(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        self.executor = DaemonThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="func")
        return None
    def _phase_serial_fork_batch_8616_else_8616_part0_8616_b1(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        try:
            _rc = self._phase_serial_fork_batch_8616_else_8616_part0_8616_b1_zb0()
            if _rc is not None:
                return _rc
            _rc = self._phase_serial_fork_batch_8616_else_8616_part0_8616_b1_zb1()
            if _rc is not None:
                return _rc
        finally:
            self.executor.shutdown(wait=not self.has_expired_futures, cancel_futures=True)
        return None


    def _phase_serial_fork_batch_8616_else_8616_part0_8616_b1_zb0(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        self.future_map = {
            self.executor.submit(
                _run_function_work_item,
                item,
                timeout=self.args.timeout,
                api_style=self.args.api_style,
                binary_path=self.args.binary,
                cod_metadata=self.cod_metadata,
                synthetic_globals=self.synthetic_globals,
                lst_metadata=self.lst_metadata,
                enable_structured_simplify=True,
                force_isolated_project=self.force_isolated_function_projects,
                allow_isolated_retry=self.allow_isolated_retry_for_parallel_tasks,
            ): item
            for item in self.function_tasks
            if item.function_cfg is not None
        }
        self.pending = set(self.future_map)
        return None
    def _phase_serial_fork_batch_8616_else_8616_part0_8616_b1_zb1(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        self.deadlines = {future: time.monotonic() + max(1, self.args.timeout) for future in self.future_map}
        self.has_expired_futures = False
        while self.pending:
            if self._phase_serial_fork_batch_8616_else_8616_part0_8616_b1_zb1_w0():
                break
            self.done, self._ = wait(self.pending, timeout=0.25, return_when=FIRST_COMPLETED)
            _rc = self._phase_serial_fork_batch_8616_else_8616_part0_8616_b1_zb1_w1()
            if _rc is not None:
                return _rc
            self.now = time.monotonic()
            self.expired = [future for future in self.pending if self.now >= self.deadlines[future]]
            _rc = self._phase_serial_fork_batch_8616_else_8616_part0_8616_b1_zb1_w2()
            if _rc is not None:
                return _rc
        return None

    def _phase_serial_fork_batch_8616_else_8616_part0_8616_b1_zb1_w2(self) -> int | None:
        """Expire pending futures past their deadlines; return an exit code to abort."""
        for _future_lp8616 in self.expired:
            item = self.future_map[_future_lp8616]
            if not _future_lp8616.done():
                done_now, _ = wait({_future_lp8616}, timeout=0.0, return_when=FIRST_COMPLETED)
                if done_now or _future_lp8616.done():
                    try:
                        self.result_map[item.index] = _future_lp8616.result()
                    except Exception as ex:
                        self.result_map[item.index] = FunctionWorkResult(
                            index=item.index,
                            status="error",
                            payload=str(ex),
                            debug_output="",
                            function=item.function,
                            function_cfg=item.function_cfg,
                        )
                    current_result = self.result_map.get(item.index)
                    _rc = self._expire_late_done_emit_8616(item, current_result)
                    if _rc is not None:
                        return _rc
                    self.pending.discard(_future_lp8616)
                    continue
            if _future_lp8616.done():
                try:
                    self.result_map[item.index] = _future_lp8616.result()
                except Exception as ex:
                    self.result_map[item.index] = FunctionWorkResult(
                        index=item.index,
                        status="error",
                        payload=str(ex),
                        debug_output="",
                        function=item.function,
                        function_cfg=item.function_cfg,
                    )
                current_result = self.result_map.get(item.index)
                if current_result is not None and item.index not in self.emitted_indexes:
                    _rc = self._expire_late_done_emit_8616(item, current_result)
                    if _rc is not None:
                        return _rc
                self.pending.discard(_future_lp8616)
                continue
            self.result_map[item.index] = FunctionWorkResult(
                index=item.index,
                status="timeout",
                payload=f"Timed out after {self.args.timeout}s.",
                debug_output="",
                function=item.function,
                function_cfg=item.function_cfg,
                elapsed=float(self.args.timeout),
            )
            self.has_expired_futures = True
            self.pending.discard(_future_lp8616)
        return None

    def _phase_serial_fork_batch_8616_else_8616_part0_8616_b1_zb1_w1(self) -> int | None:
        """Run an extracted loop sub-phase; return an exit code to abort."""
        if self.done:
            for _future_lp8616 in sorted(self.done, key=lambda candidate: self.item_by_future[candidate].index):
                self.future = _future_lp8616
                self.item = self.item_by_future[_future_lp8616]
                self.function = cast(_AngrFunction, self.item.function)
                self.function_timeout = self.timeout_by_index[self.item.index]
                self.worker_debug = (
                    f"[dbg] clean parallel function worker: start "
                    f"{_function_work_item_recovery_addr_8616(self.item):#x} {self.function.name} "
                    f"requested_timeout={self.function_timeout}s "
                    f"hard_timeout={_serial_clean_worker_outer_timeout_8616(self.function_timeout)}s\n"
                )
                try:
                    self.result = _future_lp8616.result()
                except Exception as ex:
                    self.result = FunctionWorkResult(
                        index=self.item.index,
                        status="error",
                        payload=f"Clean parallel worker failed: {_describe_exception(ex)}",
                        debug_output=self.worker_debug,
                        function=self.item.function,
                        function_cfg=self.item.function_cfg,
                        elapsed=float(self.function_timeout),
                    )
                else:
                    self.result = replace(
                        self.result,
                        debug_output=self.worker_debug + self.result.debug_output,
                    )
                self.result_map[self.item.index] = self.result
                self.d, self.f = _emit_function_result(
                    self.item,
                    self.result,
                    project=self.project,
                    args=self.args,
                    lst_metadata=self.lst_metadata,
                    cod_metadata=self.cod_metadata,
                    synthetic_globals=self.synthetic_globals,
                    precise_sidecar_regions=self.precise_sidecar_regions,
                    allow_heavy_fallbacks=self.allow_heavy_fallbacks,
                    interactive_stdout=self.interactive_stdout,
                    use_serial_fork_per_function=self.use_serial_fork_per_function,
                    fallback_tail_validation_by_index=self.fallback_tail_validation_by_index,
                    result_state_by_index=self.result_map,
                    timeout_was_explicit=self.timeout_was_explicit,
                )
                self.decompiled += self.d
                self.failed += self.f
                self.emitted_indexes.add(self.item.index)
                self.pending.discard(_future_lp8616)
        return None

    def _phase_serial_fork_batch_8616_else_8616_part0_8616_b1_zb1_w0(self) -> bool:
        """Handle the budget-exhausted sweep; return True when the caller must break out of its wait loop."""
        if self._sweep_budget_exhausted():
            for _future_lp8616 in sorted(self.done, key=lambda candidate: self.item_by_future[candidate].index):
                self.future = _future_lp8616
                self.item = self.item_by_future[_future_lp8616]
                self.function = cast(_AngrFunction, self.item.function)
                self.function_timeout = self.timeout_by_index[self.item.index]
                self.worker_debug = (
                    f"[dbg] clean parallel function worker: start "
                    f"{_function_work_item_recovery_addr_8616(self.item):#x} {self.function.name} "
                    f"requested_timeout={self.function_timeout}s "
                    f"hard_timeout={_serial_clean_worker_outer_timeout_8616(self.function_timeout)}s\n"
                )
                try:
                    self.result = _future_lp8616.result()
                except Exception as ex:
                    self.result = FunctionWorkResult(
                        index=self.item.index,
                        status="error",
                        payload=f"Clean parallel worker failed: {_describe_exception(ex)}",
                        debug_output=self.worker_debug,
                        function=self.item.function,
                        function_cfg=self.item.function_cfg,
                        elapsed=float(self.function_timeout),
                    )
                else:
                    self.result = replace(
                        self.result,
                        debug_output=self.worker_debug + self.result.debug_output,
                    )
                self.result_map[self.item.index] = self.result
                self.d, self.f = _emit_function_result(
                    self.item,
                    self.result,
                    project=self.project,
                    args=self.args,
                    lst_metadata=self.lst_metadata,
                    cod_metadata=self.cod_metadata,
                    synthetic_globals=self.synthetic_globals,
                    precise_sidecar_regions=self.precise_sidecar_regions,
                    allow_heavy_fallbacks=self.allow_heavy_fallbacks,
                    interactive_stdout=self.interactive_stdout,
                    use_serial_fork_per_function=self.use_serial_fork_per_function,
                    fallback_tail_validation_by_index=self.fallback_tail_validation_by_index,
                    result_state_by_index=self.result_map,
                    timeout_was_explicit=self.timeout_was_explicit,
                )
                self.decompiled += self.d
                self.failed += self.f
                self.emitted_indexes.add(self.item.index)
                self.pending.discard(_future_lp8616)
            self.pending.clear()
            self.has_expired_futures = True
            return True
        return False

    def _phase_seed_rank_8616_else_8616_part4_8616_b1(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        if self.cfg is None and not self.function_cfg_pairs and not self.prefer_ranked_hidden_sidecar_full_queue:
            self.fast_seed_pairs: list[_FunctionCfgPair8616] = []
            print("/* Whole-program control-flow recovery failed; attempting a quick function-entry scan fallback. */")
            self.fast_seed_pairs = cast(
                list[_FunctionCfgPair8616],
                _recover_fast_seed_functions(
                    self.project,
                    timeout=self.args.catalog_timeout,
                    limit=self.discovery_limit,
                ),
            )
            if self.fast_seed_pairs:
                self.function_cfg_pairs = self.fast_seed_pairs
                self.total_functions = len(self.function_cfg_pairs)
                self.shown_total = len(self.function_cfg_pairs)
                self.cfg = None
            elif self.prefer_ranked_hidden_sidecar_full_queue:
                pass
            elif not self.prefer_ranked_hidden_sidecar_full_queue and (
                self.args.addr is None and self.args.binary.suffix.lower() == ".exe" and self.ranked_binary_offsets
            ):
                print(
                    "/* Falling back to ranked direct-binary function addresses; "
                    "recovering only the shown subset lazily. */"
                )
            else:
                if isinstance(self.catalog_error, FuturesTimeoutError):
                    self.detail = "Timed out"
                elif isinstance(self.catalog_error, Exception):
                    self.detail = _describe_exception(self.catalog_error)
                elif self.catalog_error is not None:
                    self.detail = str(self.catalog_error)
                else:
                    self.detail = "Unknown failure"
                print(f"/* Function catalog recovery failed: {self.detail} */")
                if self.packed_exe is not None:
                    print(
                        f"/* hint: {self.args.binary.name} looks packed ({self.packed_exe}); startup-stub output may be the current limit. */"
                    )
                print("\n/* == lift break probe == */")
                print(_probe_lift_break(self.project, self.project.entry))
                print("\n/* == entry asm == */")
                print(_format_first_block_asm(self.project, self.project.entry))
                print("\n/* == non-optimized disassembly == */")
                self.start, self.end = _infer_linear_disassembly_window(self.project, self.project.entry)
                print(_format_asm_range(self.project, self.start, self.end))
                return 5
        return None

    def _phase_seed_rank_8616_else_8616_part0_8616_b1(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        if self.lst_metadata is not None and not self.visible_code_labels:
            if self.recovery_code_labels:
                print(
                    "/* Signature-bounded sidecar labels available as bounded hints; "
                    "recovering binary-owned functions from direct call/prologue evidence before generic CFG recovery. */"
                )
            if self.args.max_functions <= 0 and self.ranked_binary_offsets and not self.has_non_library_sidecar_hints:
                self.prefer_ranked_hidden_sidecar_full_queue = True
                self.total_functions = len(self.ranked_binary_offsets)
                self.shown_total = len(self.ranked_binary_offsets)
                print(
                    "/* hidden-sidecar EXE: queueing ranked direct-binary function candidates for full decompilation "
                    "without waiting for whole-program CFG recovery. */"
                )
            if self.deferred_exe_display_cap and self.ranked_binary_offsets and not self.has_non_library_sidecar_hints:
                # Hidden-sidecar EXEs only have signature/library labels. Do not
                # spend time pre-recovering a capped preview here; queue ranked
                # binary-owned candidates and recover each one in the streaming
                # serial lane so the first self.function can be emitted sooner.
                self.prefer_ranked_hidden_sidecar_full_queue = True
                self.total_functions = len(self.ranked_binary_offsets)
                self.shown_total = min(len(self.ranked_binary_offsets), self.args.max_functions)
                print(
                    "/* hidden-sidecar EXE: using ranked direct-binary function candidates; "
                    "recovering selected functions lazily for streaming output. */"
                )
            try:
                if not self.function_cfg_pairs and not self.prefer_ranked_hidden_sidecar_full_queue:
                    self.seeded_recovery_result = _run_with_timeout_in_daemon_thread(
                        lambda: _recover_seeded_exe_functions(
                            self.project,
                            timeout=self.args.catalog_timeout,
                            limit=self.discovery_limit,
                            return_addrs=True,
                        ),
                        timeout=self.args.catalog_timeout + 2,
                        thread_name_prefix="seed-catalog",
                    )
                    if isinstance(self.seeded_recovery_result, tuple) and len(self.seeded_recovery_result) == 2:
                        self.function_cfg_pairs = cast(list[_FunctionCfgPair8616], self.seeded_recovery_result[0])
                        self.seeded_catalog_addrs = self.seeded_recovery_result[1]
                    else:
                        self.function_cfg_pairs = self.seeded_recovery_result
                        self.seeded_catalog_addrs = [function.addr for _, function in self.function_cfg_pairs]
            except Exception as ex:
                self.catalog_error = ex
                self.function_cfg_pairs = self.function_cfg_pairs if self.function_cfg_pairs else []
                self.seeded_catalog_addrs = []
            else:
                pass
            if self.function_cfg_pairs and not self.total_functions:
                self.total_functions = len(self.seeded_catalog_addrs)
                self.shown_total = len(self.function_cfg_pairs)
        return None

    def _phase_seed_rank_8616_else_8616_part0_8616_b0(self) -> int | None:
        """Run an extracted zone sub-phase; return an exit code to abort."""
        self.catalog_error: BaseException | None = None
        self.deferred_exe_display_cap = self.args.addr is None and self.args.binary.suffix.lower() == ".exe" and self.args.max_functions > 0
        if self.args.addr is None and self.args.binary.suffix.lower() == ".exe":
            self.ranked_binary_offsets = _discover_ranked_binary_offsets(self.project, args=self.args)
            self.linked_base = getattr(getattr(self.project.loader, "main_object", None), "linked_base", None)
            if isinstance(self.linked_base, int):
                self.ranked_binary_offsets = [addr for addr in self.ranked_binary_offsets if addr != self.linked_base]
            self.direct_inventory_total = len(self.ranked_binary_offsets) if self.ranked_binary_offsets else None
            if self.direct_inventory_total is not None:
                print(
                    f"/* info: direct-binary recovery found {self.direct_inventory_total} likely non-library function entries */"
                )
        self.discovery_limit = (
            _expanded_exe_discovery_limit(self.args.max_functions)
            if self.deferred_exe_display_cap
            else (self.args.max_functions if self.args.max_functions > 0 else None)
        )
        return None

    def _phase_seed_rank_8616_else_8616_part4_8616(self) -> int | None:
        """Run an extracted sub-phase; return an exit code to abort."""
        _rc = self._phase_seed_rank_8616_else_8616_part4_8616_b0()
        if _rc is not None:
            return _rc
        _rc = self._phase_seed_rank_8616_else_8616_part4_8616_b1()
        if _rc is not None:
            return _rc
        return None

    def _phase_seed_rank_8616_else_8616_part0_8616(self) -> int | None:
        """Run an extracted sub-phase; return an exit code to abort."""
        _rc = self._phase_seed_rank_8616_else_8616_part0_8616_b0()
        if _rc is not None:
            return _rc
        _rc = self._phase_seed_rank_8616_else_8616_part0_8616_b1()
        if _rc is not None:
            return _rc
        return None

    def _expire_late_done_emit_8616(self, item: FunctionWorkItem, current_result: FunctionWorkResult) -> int | None:
        """Emit one late-completed future result and count it; return an exit code to abort."""
        d, f = _emit_function_result(
            item,
            current_result,
            project=self.project,
            args=self.args,
            lst_metadata=self.lst_metadata,
            cod_metadata=self.cod_metadata,
            synthetic_globals=self.synthetic_globals,
            precise_sidecar_regions=self.precise_sidecar_regions,
            allow_heavy_fallbacks=self.allow_heavy_fallbacks,
            interactive_stdout=self.interactive_stdout,
            use_serial_fork_per_function=self.use_serial_fork_per_function,
            fallback_tail_validation_by_index=self.fallback_tail_validation_by_index,
            result_state_by_index=self.result_map,
            timeout_was_explicit=self.timeout_was_explicit,
        )
        self.decompiled += d
        self.failed += f
        self.emitted_indexes.add(item.index)
        if f and self.args.addr is not None:
            _emit_tail_validation_console_summary(
                self.function_tasks, self.result_map, binary_path=self.args.binary
            )
            return 2
        return None

    def _catalog_ready_8616(self) -> bool:
        """Return whether sidecar-visible code labels enable the catalog lane."""
        return self.lst_metadata is not None and bool(self.visible_code_labels)

    def _phase_seed_rank_dispatch_8616(self) -> int | None:
        """Dispatch the seed-ranking phase between catalog and non-catalog lanes."""
        return (self._phase_seed_rank_8616() if self._catalog_ready_8616()
                else self._phase_seed_rank_8616_else_8616())

    def _phase_build_pairs_dispatch_8616(self) -> int | None:
        """Dispatch the pair-building phase between catalog and non-catalog lanes."""
        return (self._phase_build_pairs_8616() if self._catalog_ready_8616()
                else self._phase_build_pairs_8616_else_8616())

    def _phase_build_tasks_dispatch_8616(self) -> int | None:
        """Dispatch the task-building phase between catalog and non-catalog lanes."""
        return (self._phase_build_tasks_8616() if self._catalog_ready_8616()
                else self._phase_build_tasks_8616_else_8616())

    def _phase_serial_fork_batch_dispatch_8616(self) -> int | None:
        """Dispatch the batch phase between clean-process and in-process lanes."""
        return (self._phase_serial_fork_batch_8616() if self.use_serial_fork_per_function
                else self._phase_serial_fork_batch_8616_else_8616())
def _run_main_cli_8616(argv: list[str] | None) -> int:
    """Run CLI orchestration after the mandatory architecture guard succeeds."""
    return _MainCliRun8616(argv=argv).run_8616()


def main(argv: list[str] | None = None) -> int:
    """Run the decompiler CLI and return a process exit code."""

    def _impl() -> int:
        try:
            _ensure_runtime_architecture_guard_8616()
        except DecompilerArchitectureGuardError as ex:
            print(str(ex), file=sys.stderr)
            return 3
        return _run_main_cli_8616(argv)

    with span("cli.main"):
        try:
            return _impl()
        finally:
            emit_compact_summary()




