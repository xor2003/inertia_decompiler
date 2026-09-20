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
from collections.abc import Callable, Iterator, Mapping, Sequence
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
from inertia_decompiler.rizin_discovery import RizinDiscoveryStatus, discover_rizin_function_entries
from inertia_decompiler.rizin_evidence import RizinEvidenceStatus, collect_rizin_evidence
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


def _discover_ranked_binary_offsets(
    project: angr.Project,
    *,
    args: CliArguments,
) -> list[int]:
    binary_path = args.binary
    include_library_functions = args.include_library_functions
    typing.cast(typing.Any, project)._inertia_include_library_functions = include_library_functions

    def _collect_rizin_library_offsets_8616(evidence: object | None) -> set[int]:
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

    def _has_local_sidecar_evidence(binary_path: Path) -> bool:
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

    def _auto_rizin_enabled_for_current_binary() -> bool:
        # For non-86_16 keep auto as hybrid-friendly behavior.
        if str(getattr(project.arch, "name", "") or "") != "86_16":
            return True
        env = os.environ.get("INERTIA_AUTO_RIZIN_8616", "").strip().lower()
        if env in {"1", "true", "yes", "on"}:
            return True
        if env in {"0", "false", "no", "off"}:
            return False
        # Default: rizin-first when local sidecar hints are not available.
        return not _has_local_sidecar_evidence(binary_path)

    backend = args.function_discovery_backend.strip().lower()
    if backend == "auto":
        legacy_seed_engine = args.seed_engine.strip().lower()
        if legacy_seed_engine in {"angr", "rizin"}:
            backend = legacy_seed_engine
    rizin_timeout = max(1, args.rizin_timeout)
    angr_offsets: list[int] | None = None
    wants_rizin = False
    if args.binary.suffix.lower() == ".exe":
        if backend in {"rizin", "hybrid"}:
            wants_rizin = True
        elif backend == "auto":
            wants_rizin = _auto_rizin_enabled_for_current_binary()
    rz_evidence = collect_rizin_evidence(binary_path, timeout_sec=rizin_timeout) if wants_rizin else None
    if rz_evidence is not None:
        typing.cast(typing.Any, project)._inertia_rizin_evidence = rz_evidence
        typing.cast(typing.Any, project)._inertia_rizin_function_names = rz_evidence.function_name_by_addr
    rz = discover_rizin_function_entries(args.binary, timeout_sec=rizin_timeout) if wants_rizin else None
    rizin_library_offsets = _collect_rizin_library_offsets_8616(rz_evidence)
    if rz_evidence is not None and rz_evidence.status is RizinEvidenceStatus.OK and rz_evidence.functions:
        rizin_offsets = list(rz_evidence.function_offsets)
        elapsed_ms = rz_evidence.elapsed_ms
        status_value = rz_evidence.status.value
    elif rz is not None and rz.status is RizinDiscoveryStatus.OK:
        rizin_offsets = list(rz.offsets)
        elapsed_ms = rz.elapsed_ms
        status_value = rz.status.value
    else:
        rizin_offsets = []
        elapsed_ms = 0.0
        status_value = "error"
    if rizin_offsets:
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
    if angr_offsets is None:
        angr_offsets = _rank_exe_function_seeds(
            project,
            include_library_functions=include_library_functions,
        )
    return angr_offsets


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
        if cached_result is not None:
            cached_status = str(cached_result.get("status", "error"))
            cached_tail_validation = cached_result.get("tail_validation")
            if cached_status != "ok":
                return (
                    None,
                    (
                        f"[dbg] ignoring cached failed function result for {function_addr:#x} "
                        f"{function_name} status={cached_status}; "
                        "only successful decompilation results are cached\n"
                    ),
                    cache_key,
                    tail_validation_enabled,
                    expected_validation_stages,
                )
            typed_switch_artifacts = os.environ.get("INERTIA_ENABLE_TYPED_SWITCH_AST_ARTIFACTS") == "1"
            cached_diagnostic_output = cached_result.get("diagnostic_output")
            if typed_switch_artifacts and (
                not isinstance(cached_diagnostic_output, str) or not cached_diagnostic_output.strip()
            ):
                return (
                    None,
                    f"[dbg] cache bypass for {function_addr:#x} {function_name} missing_diagnostic_provenance\n",
                    cache_key,
                    tail_validation_enabled,
                    expected_validation_stages,
                )
            diagnostic_output = cached_diagnostic_output if isinstance(cached_diagnostic_output, str) else ""
            if (not tail_validation_enabled) or x86_16_tail_validation_snapshot_passed(
                cached_tail_validation if isinstance(cached_tail_validation, dict) else None,
                expected_stages=expected_validation_stages,
            ):
                cached_payload = str(cached_result.get("payload", ""))
                cached_validated_hash = cached_result.get("validated_c_hash")
                cached_gcc_hash = cached_result.get("gcc_checked_c_hash")
                if not isinstance(cached_validated_hash, str) or not isinstance(cached_gcc_hash, str):
                    return (
                        None,
                        (
                            f"[dbg] cache bypass for {function_addr:#x} "
                            f"{function_name} missing_acceptance_provenance\n"
                        ),
                        cache_key,
                        tail_validation_enabled,
                        expected_validation_stages,
                    )
                if (
                    cached_validated_hash != cached_gcc_hash
                    or cached_validated_hash != _sha256_text_8616(cached_payload)
                ):
                    return (
                        None,
                        (
                            f"[dbg] cache bypass for {function_addr:#x} "
                            f"{function_name} stale_output_mismatch\n"
                        ),
                        cache_key,
                        tail_validation_enabled,
                        expected_validation_stages,
                    )
                normalized_cached_payload = _normalize_accepted_payload_8616(cached_payload)
                if normalized_cached_payload.rstrip() != cached_payload.rstrip():
                    return (
                        None,
                        (
                            f"[dbg] cache bypass for {function_addr:#x} "
                            f"{function_name} stale_normalization\n"
                        ),
                        cache_key,
                        tail_validation_enabled,
                        expected_validation_stages,
                    )
                cached_quality = assess_final_generated_c_text(cached_payload)
                if cached_quality.reject_as_decompiled:
                    marker_summary = ", ".join(cached_quality.markers[:3]) if cached_quality.markers else "unresolved"
                    if len(cached_quality.markers) > 3:
                        marker_summary += ", ..."
                    return (
                        None,
                        (
                            f"[dbg] cache bypass for {function_addr:#x} "
                            f"{function_name} quality={marker_summary}\n"
                        ),
                        cache_key,
                        tail_validation_enabled,
                        expected_validation_stages,
                    )
                cache_validation_status = (
                    "uncollected"
                    if not tail_validation_enabled
                    else _tail_validation_display_status(
                        cached_tail_validation if isinstance(cached_tail_validation, dict) else None
                    )
                )
                cached_tail_snapshot: dict[str, object] | None = None
                if isinstance(cached_tail_validation, dict):
                    cached_stage_names = [
                        stage for stage in expected_validation_stages if stage in cached_tail_validation
                    ]
                    cached_stage_names.extend(
                        stage for stage in cached_tail_validation if stage not in expected_validation_stages
                    )
                    cached_tail_snapshot = {
                        stage: copy.deepcopy(cached_tail_validation[stage]) for stage in cached_stage_names
                    }
                cached_elapsed = cached_result.get("elapsed")
                cached_block_count = cached_result.get("block_count")
                cached_byte_count = cached_result.get("byte_count")
                cached_failure_family = FailureFamilySnapshot.from_record(
                    cached_result.get("failure_family_snapshot")
                )
                return (
                    FunctionWorkResult(
                        index=item.index,
                        status=cached_status,
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
                    ),
                    "",
                    cache_key,
                    tail_validation_enabled,
                    expected_validation_stages,
                )
            cache_bypass_reason = _tail_validation_display_status(
                cached_tail_validation if isinstance(cached_tail_validation, dict) else None
            )
            return (
                None,
                (
                    f"[dbg] cache bypass for {function_addr:#x} "
                    f"{function_name} validation={cache_bypass_reason}\n"
                ),
                cache_key,
                tail_validation_enabled,
                expected_validation_stages,
            )
        return None, "", cache_key, tail_validation_enabled, expected_validation_stages

    return _impl()


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
        def _maybe_return_known_helper_result(
            decompile_project: angr.Project,
            decompile_cfg: object,
            decompile_function: object,
            effective_timeout: int,
            failure_family_state: FailureFamilyState,
        ) -> FunctionWorkResult | None:
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
                timeout=max(1, min(effective_timeout, 2)),
                api_style=api_style,
                binary_path=binary_path,
                lst_metadata=lst_metadata,
                cod_metadata=cod_metadata,
                synthetic_globals=synthetic_globals,
                failure_family_state=failure_family_state,
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
                index=item.index,
                status="ok",
                payload=helper_c,
                partial_payload=None,
                debug_output="",
                function=item.function,
                function_cfg=item.function_cfg,
                tail_validation=helper_snapshot,
                elapsed=0.0,
                block_count=None,
                byte_count=None,
            )

        def _finalize_work_result(
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
            failure_family_state: FailureFamilyState,
            cache_key: dict[str, object] | None,
            tail_validation_enabled: bool,
            expected_validation_stages: tuple[str, ...],
        ) -> FunctionWorkResult:
            acceptance = _validated_generated_c_acceptance_8616(
                status=status,
                payload=payload,
                tail_validation_snapshot=tail_validation_snapshot,
                tail_validation_enabled=tail_validation_enabled,
                expected_validation_stages=expected_validation_stages,
                c_target=getattr(decompile_project, "_inertia_c_target", "portable-flat"),
            )
            status = acceptance.status
            acceptance_blocker = acceptance.blocker
            acceptance_payload = acceptance.validated_payload
            acceptance_validated_hash = acceptance.validated_payload_hash
            acceptance_gcc_hash = acceptance.gcc_checked_payload_hash
            payload = acceptance.gcc_checked_payload
            if acceptance_blocker is not None:
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
                payload = acceptance_blocker
                partial_payload = preserved_candidate
            if status in {"empty", "validation_failed"}:
                recovered_payload, recovered_snapshot = _recover_binary_evidence_c_8616(
                    decompile_project, decompile_function
                )
                if (
                    isinstance(recovered_payload, str)
                    and recovered_payload.strip()
                    and isinstance(recovered_snapshot, dict)
                ):
                    recovered_acceptance = _validated_generated_c_acceptance_8616(
                        status="ok",
                        payload=recovered_payload,
                        tail_validation_snapshot=recovered_snapshot,
                        tail_validation_enabled=tail_validation_enabled,
                        expected_validation_stages=expected_validation_stages,
                        c_target=getattr(decompile_project, "_inertia_c_target", "portable-flat"),
                    )
                    if recovered_acceptance.status == "ok" and recovered_acceptance.blocker is None:
                        status = recovered_acceptance.status
                        payload = recovered_acceptance.gcc_checked_payload
                        partial_payload = None
                        tail_validation_snapshot = recovered_snapshot
                        acceptance_validated_hash = recovered_acceptance.validated_payload_hash
                        acceptance_gcc_hash = recovered_acceptance.gcc_checked_payload_hash
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
                index=item.index,
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
                same_family_retry_stops=failure_family_state.same_family_retry_stops,
                fallback_family_labels=failure_family_state.fallback_family_labels,
                validated_payload_hash=acceptance_validated_hash,
                gcc_checked_payload_hash=acceptance_gcc_hash,
            )

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

        item_function: _AngrFunction = item.function
        decompile_project = item_function.project
        decompile_cfg = item.function_cfg
        decompile_function: _AngrFunction = item_function
        attach_lst_metadata_to_project(decompile_project, lst_metadata)
        failure_family_state = FailureFamilyState()
        helper_result = _maybe_return_known_helper_result(
            decompile_project,
            decompile_cfg,
            decompile_function,
            effective_timeout,
            failure_family_state,
        )
        if helper_result is not None:
            return helper_result

        def _run_local(
            project_obj: angr.Project, cfg_obj: object, function_obj: _AngrFunction
        ) -> tuple[str, str, str | None, str, dict[str, object] | None, float, int, int]:
            with _capture_thread_output() as (stdout_buf, stderr_buf):
                _apply_function_annotations_for_active_and_original_8616(
                    project_obj,
                    binary_path,
                    lst_metadata,
                    function_obj,
                    cod_metadata=cod_metadata,
                    synthetic_globals=synthetic_globals,
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
                        effective_timeout,
                        api_style,
                        binary_path,
                        cod_metadata=cod_metadata,
                        synthetic_globals=synthetic_globals,
                        lst_metadata=lst_metadata,
                        enable_structured_simplify=enable_structured_simplify,
                        enable_postprocess=enable_postprocess,
                        allow_isolated_retry=allow_isolated_retry,
                        failure_family_state=failure_family_state,
                    )
                    annotate_current_span(clinic_policy=local_clinic_policy.value)
            debug_output_local = stdout_buf.getvalue()
            err_output = stderr_buf.getvalue()
            if err_output:
                debug_output_local += err_output
            raw_tail_snapshot = _tail_validation_snapshot_for_function_run(project_obj, function_obj)
            tail_snapshot_local: dict[str, object] | None = raw_tail_snapshot if isinstance(raw_tail_snapshot, dict) else None
            if (
                status == "ok"
                and isinstance(payload, str)
                and isinstance(getattr(function_obj, "name", None), str)
                and (
                    not isinstance(tail_snapshot_local, dict)
                    or "structuring" not in tail_snapshot_local
                    or "postprocess" not in tail_snapshot_local
                )
            ):
                helper_model = _try_emit_known_runtime_helper_c(name=function_obj.name)
                if isinstance(helper_model, str):
                    norm_payload = re.sub(r"\s+", "", payload)
                    norm_helper = re.sub(r"\s+", "", helper_model)
                    if norm_payload == norm_helper:
                        tail_snapshot_local = {
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

        fork_isolated_eligible = (
            force_isolated_project
            and not process_isolated_worker
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
                        max(1, effective_timeout) + 1,
                        context="forked local decompile",
                    ),
                    isolated="fork",
                ):
                    (
                        status,
                        payload,
                        partial_payload,
                        debug_output,
                        tail_validation_snapshot,
                        elapsed,
                        block_count,
                        byte_count,
                    ) = _run_with_timeout_in_fork(
                            lambda: _run_local(decompile_project, decompile_cfg, decompile_function),
                            timeout=_enforce_function_timeout_cap(
                                max(1, effective_timeout) + 1,
                                context="forked local decompile",
                            ),
                        )
                    annotate_current_span(status=status, blocks=block_count, bytes=byte_count)
            except TimeoutError as ex:
                logging.getLogger(__name__).warning("fork-isolated decompilation timed out: %s", ex)
                return _finalize_work_result(
                    status="timeout",
                    payload=f"Timed out after {effective_timeout}s during fork-isolated decompilation.",
                    partial_payload=None,
                    debug_output="",
                    tail_validation_snapshot=None,
                    elapsed=float(effective_timeout),
                    block_count=block_estimate,
                    byte_count=_byte_estimate,
                    decompile_project=decompile_project,
                    failure_family_state=failure_family_state,
                    cache_key=None,
                    tail_validation_enabled=tail_validation_enabled,
                    expected_validation_stages=tuple(expected_validation_stages),
                )
            except Exception as ex:
                logging.getLogger(__name__).warning("fork-isolated decompilation failed: %s", ex)
                fork_isolated_eligible = False

        if (
            force_isolated_project
            and not fork_isolated_eligible
            and binary_path is not None
            and isinstance(getattr(item.function, "addr", None), int)
        ):
            main_object = getattr(getattr(item.function, "project", None), "loader", None)
            main_object = getattr(main_object, "main_object", None)
            linked_base = getattr(main_object, "linked_base", None)
            max_addr = getattr(main_object, "max_addr", None)
            if isinstance(linked_base, int) and isinstance(max_addr, int):
                try:
                    isolated_project = _build_project_cached(
                        str(binary_path),
                        force_blob=False,
                        base_addr=linked_base,
                        entry_point=getattr(item_function.project, "entry", linked_base),
                    )
                    _transfer_caller_return_use_evidence_8616(decompile_project, isolated_project)
                    attach_lst_metadata_to_project(isolated_project, lst_metadata)
                    _inherit_tail_validation_runtime_policy(isolated_project, item_function.project)
                    candidate_addr, isolated_image_end = _isolated_project_recovery_target_8616(
                        item.function,
                        isolated_project,
                        linked_base,
                        max_addr,
                    )
                    isolated_cfg, isolated_function = _recover_candidate_function_pair(
                        isolated_project,
                        candidate_addr=candidate_addr,
                        image_end=isolated_image_end,
                        metadata=lst_metadata,
                        project_entry=isolated_project.entry,
                        region_span=max(0x180, _function_complexity(item.function)[1] + 0x80),
                    )
                    _preserve_source_label_for_recovered_function_8616(item.function, isolated_function)
                    mark_function_original_addr(isolated_function, candidate_addr)
                    decompile_project = isolated_project
                    decompile_cfg = isolated_cfg
                    decompile_function = isolated_function
                except Exception as ex:
                    logging.getLogger(__name__).warning("isolated project/function set up failed: %s", ex)
                    return FunctionWorkResult(
                        index=item.index,
                        status=WorkItemStatus.ERROR.value,
                        payload=f"Fresh isolated project/function setup failed: {_describe_exception(ex)}",
                        partial_payload=None,
                        debug_output="",
                        function=item.function,
                        function_cfg=item.function_cfg,
                        elapsed=0.0,
                        block_count=block_estimate,
                        byte_count=_byte_estimate,
                        failure_stage="fresh_project_recovery",
                    )

        if not fork_isolated_eligible:
            with span(
                "direct.decompile_job",
                addr=hex(getattr(decompile_function, "addr", 0)),
                name=getattr(decompile_function, "name", None),
                timeout=effective_timeout,
                isolated="local",
            ):
                (
                    status,
                    payload,
                    partial_payload,
                    debug_output,
                    tail_validation_snapshot,
                    elapsed,
                    block_count,
                    byte_count,
                ) = _run_local(
                    decompile_project,
                    decompile_cfg,
                    decompile_function,
                )
                annotate_current_span(status=status, blocks=block_count, bytes=byte_count)
        if cache_bypass_debug:
            debug_output = f"{cache_bypass_debug}{debug_output}"
        return _finalize_work_result(
            status=status,
            payload=payload,
            partial_payload=partial_payload,
            debug_output=debug_output,
            tail_validation_snapshot=tail_validation_snapshot,
            elapsed=elapsed,
            block_count=block_count,
            byte_count=byte_count,
            decompile_project=decompile_project,
            failure_family_state=failure_family_state,
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

    def _impl() -> CAcceptanceResult8616:
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

        accepted_payload = baseline_payload

        def _dump_validation_failed_payload(detail: str) -> None:
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

        def _validation_fail(detail: str) -> CAcceptanceResult8616:
            _mark_tail_validation_failed_with_blocker_8616(
                tail_validation_snapshot,
                detail,
                stage="postprocess",
            )
            if emit_failure_diagnostics:
                print("[tail-validation] whole-tail validation failed across 1 functions", file=sys.stderr)
                print(f"[tail-validation] acceptance-gate detail: {detail}", file=sys.stderr)
                _dump_validation_failed_payload(detail)
                sys.stderr.flush()
            return _acceptance_result_8616(WorkItemStatus.VALIDATION_FAILED, detail, accepted_payload)

        accepted_payload = _normalize_accepted_payload_8616(accepted_payload)
        accepted_payload = _prune_invalid_simple_function_prototypes_text(accepted_payload)

        quality = assess_final_generated_c_text(accepted_payload)
        if quality.reject_as_decompiled:
            marker_summary = ", ".join(quality.markers[:3]) if quality.markers else "unresolved"
            if len(quality.markers) > 3:
                marker_summary += ", ..."
            return _validation_fail(f"Final quality guard rejected emitted C ({marker_summary}).")
        if tail_validation_enabled and not _tail_validation_passes_lenient(
            tail_validation_snapshot, expected_stages=list(expected_validation_stages)
        ):
            display_status = _tail_validation_display_status(tail_validation_snapshot)
            detail = _tail_validation_stage_detail_8616(tail_validation_snapshot, expected_validation_stages)
            return _validation_fail(f"Tail validation {display_status} ({detail}).")

        checked_payloads, recomp_failure = _collect_recompilation_payloads_8616(accepted_payload)
        if recomp_failure is not None:
            return _validation_fail(recomp_failure)

        if not checked_payloads:
            return _validation_fail("No compiler succeeded; cannot establish recompilation identity.")

        reference_target, reference_checked_payload = checked_payloads[0]
        reference_hash = _sha256_text_8616(reference_checked_payload)
        for target_name, target_checked_payload in checked_payloads[1:]:
            target_hash = _sha256_text_8616(target_checked_payload)
            if target_hash != reference_hash:
                return _validation_fail(
                    f"recompile identity mismatch across toolchains: {reference_target} and {target_name}"
                )

        validation_hash = _sha256_text_8616(accepted_payload)
        gcc_hash = reference_hash
        if gcc_hash != validation_hash:
            return _validation_fail("stale output mismatch: validated emitted C differs from gcc-checked C.")
        if _unreachable_calls_after_return_violation_8616(accepted_payload):
            return _validation_fail("Unreachable call statements present after return in emitted C.")
        ds_linear_macro_hits = _count_unresolved_ds_linear_macro_hits_8616(accepted_payload)
        if ds_linear_macro_hits >= 6:
            return _validation_fail(
                f"Excess unresolved DS-linear macro accesses in emitted C (count={ds_linear_macro_hits})."
            )
        return CAcceptanceResult8616(
            status=WorkItemStatus.OK,
            blocker=None,
            validated_payload=accepted_payload,
            validated_payload_hash=validation_hash,
            gcc_checked_payload=reference_checked_payload,
            gcc_checked_payload_hash=gcc_hash,
        )

    return _impl()


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

    def skip_string(index: int, quote: str) -> int:
        index += 1
        while index < len(text):
            if text[index] == "\\":
                index += 2
                continue
            if text[index] == quote:
                return index + 1
            index += 1
        return index

    def skip_ws(index: int) -> int:
        while index < len(text) and text[index].isspace():
            index += 1
        return index

    def parse_until(index: int, stop_char: str | None = None) -> tuple[list[str], int]:
        """Collect call-like names until a matching delimiter is reached."""
        names: list[str] = []
        while index < len(text):
            ch = text[index]
            if stop_char is not None and ch == stop_char:
                return names, index + 1
            if ch in {'"', "'"}:
                index = skip_string(index, ch)
                continue
            if ch == "(":
                nested, index = parse_until(index + 1, ")")
                names.extend(nested)
                continue
            if ch == "_" or ch.isalpha():
                start = index
                index += 1
                while index < len(text) and (text[index] == "_" or text[index].isalnum()):
                    index += 1
                raw_name = text[start:index]
                paren = skip_ws(index)
                if paren < len(text) and text[paren] == "(":
                    nested, index = parse_until(paren + 1, ")")
                    names.extend(nested)
                    name = raw_name.lstrip("_")
                    if name and name not in keywords:
                        names.append(name)
                    continue
                continue
            index += 1
        return names, index

    names, _end = parse_until(0)
    return names


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
    def _impl() -> bool:
        body = _extract_function_body_text_8616(_strip_comment_blocks_8616(emitted_c))
        if not isinstance(body, str) or not body.strip():
            return False
        depth = 0
        saw_top_level_return = False
        token_re = re.compile(r"\breturn\s*;|([A-Za-z_][A-Za-z0-9_]*)\s*\(")
        for line in body.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(("//", "/*", "*")):
                depth += line.count("{") - line.count("}")
                if depth < 0:
                    depth = 0
                continue
            if depth == 0 and re.search(r"\breturn\s*;", line):
                saw_top_level_return = True
            elif depth == 0 and saw_top_level_return:
                for match in token_re.finditer(line):
                    name = match.group(1)
                    if name is None:
                        continue
                    if name in {"if", "for", "while", "switch", "return", "sizeof"}:
                        continue
                    return True
            depth += line.count("{") - line.count("}")
            if depth < 0:
                depth = 0
        return False

    return _impl()


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
    def _impl() -> Iterator[_StructuredCNode8616]:
        yield node
        if isinstance(node, structured_c.CStatements):
            for stmt in node.statements:
                yield from _iter_c_nodes(stmt)
            return
        for attr in ("lhs", "rhs", "expr", "condition", "true_node", "false_node", "stmt", "callee_target"):
            if hasattr(node, attr):
                try:
                    value = getattr(node, attr)
                except Exception:
                    continue
                if value is not None and type(value).__module__.startswith(
                    "angr.analyses.decompiler.structured_codegen"
                ):
                    yield from _iter_c_nodes(value)
        if hasattr(node, "args"):
            try:
                args = node.args
            except Exception:
                args = None
            if args:
                for arg in args:
                    if type(arg).__module__.startswith("angr.analyses.decompiler.structured_codegen"):
                        yield from _iter_c_nodes(arg)

    return _impl()


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
        timeout_delay_printed = False

        def _emit_timeout_delay_line() -> None:
            nonlocal timeout_delay_printed
            if timeout_delay_printed or result.status != "timeout":
                return
            elapsed = result.elapsed
            if isinstance(elapsed, (int, float)) and elapsed >= 0:
                print(f"/* timeout delay: {float(elapsed):.2f}s */")
                timeout_delay_printed = True

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
        retry_item = item
        if result.function is not None and result.function_cfg is not None:
            retry_item = FunctionWorkItem(
                index=item.index,
                function_cfg=result.function_cfg,
                function=result.function,
                recovery_addr=item.recovery_addr,
            )
        if (
            result.status != "ok"
            and args.addr is None
            and getattr(project.arch, "name", "") == "86_16"
            and result.failure_stage != "sweep_budget"
            and result.retry_may_change_evidence(
                sidecar_available=lst_metadata is not None or cod_metadata is not None
            )
            and _try_emit_retry_recovered_candidate_8616(
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
        ):
            decompiled_local += 1
            return decompiled_local, failed_local
        if args.show_asm:
            print("/* -- asm -- */")
            print(_format_first_block_asm(project, function.addr))
        emitted_problem = False
        if result.status == "ok":
            payload_text = result.payload if isinstance(result.payload, str) else ""
            normalized_payload_text = _normalize_accepted_payload_8616(payload_text)
            if normalized_payload_text != payload_text:
                result = replace(result, payload=normalized_payload_text)
                payload_text = normalized_payload_text
            if result.status == "ok" and (
                not _tail_validation_runtime_enabled(project)
                or x86_16_tail_validation_snapshot_passed(result_tail_validation)
            ):
                decompiled_local += 1
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
                return decompiled_local, failed_local
            if result.status == "ok":
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
                attempt_status_printed = True
                emitted_problem = True
                if (
                    args.addr is None
                    and getattr(project.arch, "name", "") == "86_16"
                    and result.failure_stage != "sweep_budget"
                    and result.retry_may_change_evidence(
                        sidecar_available=lst_metadata is not None or cod_metadata is not None
                    )
                    and _try_emit_retry_recovered_candidate_8616(
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
                ):
                    decompiled_local += 1
                    return decompiled_local, failed_local

        if result.partial_payload:
            partial_report = _partial_result_report_8616(result.status)
            _print_function_attempt_status(
                function,
                attempt=_function_attempt_display_status(result),
                validation_snapshot=result.tail_validation,
            )
            attempt_status_printed = True
            print(f"/* problem: {result.status} */")
            _print_diagnostic_text(result.payload)
            if partial_report.show_timeout_delay:
                _emit_timeout_delay_line()
            _emit_optional_source_sidecar_c_block(
                args.binary,
                function.name,
                result.partial_payload,
                alternate_source_c=bool(args.alternate_source_c),
                c_header=partial_report.sweep_c_header,
            )
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
        if retry_result.status != "ok" or not x86_16_tail_validation_snapshot_passed(retry_tv) or not retry_has_payload:
            return False
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
        if slice_result is not None and slice_result.status == "ok":
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
                decompiled_local += 1
                _print_function_attempt_status(function, attempt="fallback", validation_snapshot=fallback_snapshot)
                _emit_optional_source_sidecar_c_block(
                    args.binary,
                    function.name,
                    fallback_acceptance.gcc_checked_payload,
                    alternate_source_c=bool(args.alternate_source_c),
                    c_header="/* -- c (sidecar slice fallback) -- */",
                )
                return decompiled_local, failed_local
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

        nonopt_result: NonOptimizedSliceOutcome | str | None = None
        known_nonopt_result: NonOptimizedSliceOutcome | str | None = None
        function_project = getattr(function, "project", project)
        using_rebased_function_slice = function_project is not project
        function_lst_metadata = None if using_rebased_function_slice else lst_metadata
        if result.partial_payload is None:
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
            if function_project is not project:
                for attr_name in (
                    "_inertia_partial_tail_validation_snapshot",
                    "_inertia_last_tail_validation_snapshot",
                ):
                    attr_value = getattr(function_project, attr_name, None)
                    if isinstance(attr_value, dict):
                        setattr(project, attr_name, dict(attr_value))
        known_nonopt_c = _non_optimized_slice_rendered(known_nonopt_result)
        if known_nonopt_c is not None:
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
                known_nonopt_c = None
            else:
                decompiled_local += 1
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
                return decompiled_local, failed_local

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

        trivial_c = _try_emit_trivial_sidecar_c(project, lst_metadata, function.addr, function.name)
        if trivial_c is not None:
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
                decompiled_local += 1
                _print_function_attempt_status(function, attempt="fallback", validation_snapshot=fallback_snapshot)
                _emit_optional_source_sidecar_c_block(
                    args.binary,
                    function.name,
                    fallback_acceptance.gcc_checked_payload,
                    alternate_source_c=bool(args.alternate_source_c),
                    c_header="/* -- c (trivial sidecar fallback) -- */",
                )
                return decompiled_local, failed_local
            print("/* problem: validation=failed */")
            _print_diagnostic_text(
                fallback_acceptance.blocker or "Trivial sidecar fallback failed final acceptance."
            )

        if (
            result.partial_payload is None
            and (precise_sidecar_regions or args.addr is not None)
            and known_nonopt_c is None
            and not sidecar_verdict_closes_non_optimized_lane(
                slice_result.verdict if slice_result is not None else None
            )
        ):
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
            if function_project is not project:
                for attr_name in (
                    "_inertia_partial_tail_validation_snapshot",
                    "_inertia_last_tail_validation_snapshot",
                ):
                    attr_value = getattr(function_project, attr_name, None)
                    if isinstance(attr_value, dict):
                        setattr(project, attr_name, dict(attr_value))
        closed_sidecar_verdict = slice_result.verdict if slice_result is not None else None
        if closed_sidecar_verdict is not None and sidecar_verdict_closes_non_optimized_lane(closed_sidecar_verdict):
            print(
                "/* non-optimized fallback unavailable: "
                f"sidecar slice already closed the lane ({closed_sidecar_verdict.stage}:{closed_sidecar_verdict.stop_family}) */"
            )
        nonopt_c = _non_optimized_slice_rendered(nonopt_result)
        if nonopt_c is not None:
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
                decompiled_local += 1
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
                return decompiled_local, failed_local
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
        string_c = None
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
        if result.partial_payload is None:
            if sidecar_region is not None:
                string_c = _try_emit_string_intrinsic_c(
                    project, start=sidecar_region[0], end=sidecar_region[1], name=function.name
                )
            else:
                start, end = _infer_linear_disassembly_window(project, function.addr)
                string_c = _try_emit_string_intrinsic_c(project, start=start, end=end, name=function.name)
        if string_c is not None:
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
        if result.partial_payload is not None:
            if emitted_problem:
                print("/* -- asm fallback -- */")
                _print_asm_fallback_text(asm_fallback)
            return decompiled_local, failed_local
        if result.status == "empty":
            if asm_fallback.startswith("<assembly unavailable") or asm_fallback == "<no instructions>":
                print(f"/* no bytes available for function at {function.addr:#x}; likely external or synthetic */")
            else:
                if emitted_problem:
                    print("/* -- asm fallback -- */")
                    _print_asm_fallback_text(asm_fallback)
                    return decompiled_local, failed_local
                print(f"/* -- {result.status} -- */")
                _print_diagnostic_text(result.payload)
                emit_timeout_delay_line()
                print("/* -- asm fallback -- */")
                _print_asm_fallback_text(asm_fallback)
            return decompiled_local, failed_local
        if emitted_problem:
            print("/* -- lift break probe -- */")
            _print_diagnostic_text(_probe_lift_break(project, function.addr))
            print("/* -- asm fallback -- */")
            _print_asm_fallback_text(asm_fallback)
            return decompiled_local, failed_local
        print(f"/* -- {result.status} -- */")
        _print_diagnostic_text(result.payload)
        emit_timeout_delay_line()
        print("/* -- lift break probe -- */")
        _print_diagnostic_text(_probe_lift_break(project, function.addr))
        print("/* -- asm fallback -- */")
        _print_asm_fallback_text(asm_fallback)
        return decompiled_local, failed_local

    return _impl()


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
    def _impl() -> tuple[int, int]:
        nonlocal decompiled_local, failed_local, attempt_status_printed, emitted_problem
        function: _AngrFunction = item.function
        sidecar_region = _lst_code_region(lst_metadata, function.addr) if lst_metadata is not None else None
        string_c = None
        if sidecar_region is not None:
            string_c = _try_emit_string_intrinsic_c(
                project, start=sidecar_region[0], end=sidecar_region[1], name=function.name
            )
        else:
            start, end = _infer_linear_disassembly_window(project, function.addr)
            string_c = _try_emit_string_intrinsic_c(project, start=start, end=end, name=function.name)
        if string_c is not None:
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
                decompiled_local += 1
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
                return decompiled_local, failed_local
        asm_fallback = (
            _format_asm_range(project, sidecar_region[0], sidecar_region[1])
            if sidecar_region is not None
            else _format_asm_range(project, *_infer_linear_disassembly_window(project, function.addr))
        )
        failed_local += 1
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
        if result.status == "empty":
            if asm_fallback.startswith("<assembly unavailable") or asm_fallback == "<no instructions>":
                print(f"/* no bytes available for function at {function.addr:#x}; likely external or synthetic */")
            else:
                if emitted_problem:
                    print("/* -- asm fallback -- */")
                    _print_asm_fallback_text(asm_fallback)
                    return decompiled_local, failed_local
                print(f"/* -- {result.status} -- */")
                _print_diagnostic_text(result.payload)
                emit_timeout_delay_line()
                print("/* -- asm fallback -- */")
                _print_asm_fallback_text(asm_fallback)
        else:
            if emitted_problem:
                print("/* -- lift break probe -- */")
                _print_diagnostic_text(_probe_lift_break(project, function.addr))
                print("/* -- asm fallback -- */")
                _print_asm_fallback_text(asm_fallback)
                return decompiled_local, failed_local
            print(f"/* -- {result.status} -- */")
            _print_diagnostic_text(result.payload)
            emit_timeout_delay_line()
            print("/* -- lift break probe -- */")
            _print_diagnostic_text(_probe_lift_break(project, function.addr))
            print("/* -- asm fallback -- */")
            _print_asm_fallback_text(asm_fallback)
        return decompiled_local, failed_local

    return _impl()


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
                    synthetic_globals=synthetic_globals,
                )
                if lst_metadata is None:
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
        if linked_proc_addr is None:
            if cod_path is None:
                raise ValueError(f"--proc mode requires sibling COD listing: not found for {binary_path}")
            entries = extract_cod_function_entries(cod_path, args.proc, args.proc_kind)
            cod_metadata = extract_cod_proc_metadata(cod_path, args.proc, args.proc_kind)
            prefer_fast_recovery = True
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
        if lst_metadata is None:
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
    if (
        result.status != WorkItemStatus.OK.value
        or not isinstance(result.tail_validation, dict)
        or not isinstance(result.validated_payload_hash, str)
        or not isinstance(result.gcc_checked_payload_hash, str)
        or result.failure_family_snapshot is None
        or not integrity.passed
    ):
        return None
    startup_diagnostic_lines: list[str] = []
    if context.args.ignore_local_sidecar_hints:
        startup_diagnostic_lines.append(
            "/* ignoring local sidecar metadata for function discovery and recovery due "
            "--ignore-local-sidecar-hints */"
        )
    if context.lst_metadata is None:
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


def _run_direct_addr_cli_8616(context: _DirectAddrCliContext8616) -> int:
    """Run the direct-address CLI branch after project and sidecar setup."""
    args = context.args
    direct_addr = args.addr
    if direct_addr is None:
        raise ValueError("direct-address CLI branch requires args.addr")
    project = context.project
    direct_request_cache_lookup = load_direct_request_cache_8616(
        context.request_cache_inputs,
        enabled=direct_request_cache_enabled_8616(args),
    )
    if (
        direct_request_cache_lookup.verdict is DirectRequestCacheVerdict8616.HIT
        and direct_request_cache_lookup.artifact is not None
    ):
        artifact = direct_request_cache_lookup.artifact
        try:
            cached_segment_evidence = (
                None
                if artifact.segment_program_function_evidence_record is None
                else segment_program_function_evidence_from_record_8616(
                    artifact.segment_program_function_evidence_record
                )
            )
        except (PipelineHardError, ValueError):
            cached_segment_evidence = None
            print("[dbg] direct request cache refused: segment_evidence", file=sys.stderr, flush=True)
        else:
            expected_runtime_header = render_c_runtime_header_8616(args.c_target)
            if (
                artifact.arch_name == project.arch.name
                and artifact.entry_point == project.entry
                and artifact.runtime_header == expected_runtime_header
            ):
                cached_function = SimpleNamespace(
                    addr=artifact.function_addr,
                    name=artifact.function_name,
                    project=project,
                )
                cached_result = FunctionWorkResult(
                    index=1,
                    status=WorkItemStatus.OK.value,
                    payload=artifact.payload,
                    debug_output=(
                        f"[dbg] direct request cache hit: {artifact.function_addr:#x} "
                        f"{artifact.function_name} validation=passed\n"
                        f"{artifact.diagnostic_output}"
                    ),
                    function=cached_function,
                    function_cfg=None,
                    tail_validation=copy.deepcopy(artifact.tail_validation),
                    elapsed=artifact.elapsed,
                    from_cache=True,
                    block_count=artifact.block_count,
                    byte_count=artifact.byte_count,
                    validated_payload_hash=artifact.validated_payload_hash,
                    gcc_checked_payload_hash=artifact.gcc_checked_payload_hash,
                    failure_family_snapshot=artifact.failure_family_snapshot,
                    segment_program_function_evidence=cached_segment_evidence,
                )
                return _emit_direct_cache_hit_8616(
                    context,
                    cached_result,
                    function=cached_function,
                    function_cfg=None,
                    emit_function_header=True,
                    project_for_worker_result=None,
                )
            print("[dbg] direct request cache refused: runtime_identity", file=sys.stderr, flush=True)
    if direct_request_cache_lookup.verdict is DirectRequestCacheVerdict8616.REFUSED:
        print(
            "[dbg] direct request cache refused: acceptance_proof",
            file=sys.stderr,
            flush=True,
        )
    _hydrate_serial_clean_worker_evidence_8616(project)
    clean_worker_caller_return_evidence_by_addr = dict(caller_return_use_evidence_by_addr_8616(project))
    function_label = context.function_label
    cod_metadata = context.cod_metadata
    synthetic_globals = context.synthetic_globals
    lst_metadata = context.lst_metadata
    prefer_fast_recovery = context.prefer_fast_recovery
    proc_resolved_to_linked_binary = context.proc_resolved_to_linked_binary
    low_memory_path = context.low_memory_path
    interactive_stdout = context.interactive_stdout
    precise_sidecar_regions = context.precise_sidecar_regions
    timeout_was_explicit = context.timeout_was_explicit
    print("/* recovering function... */", flush=True)
    fast_direct_probe_requested = os.environ.get("INERTIA_FAST_DIRECT_PROBE", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    fast_direct_probe = bool(
        fast_direct_probe_requested and timeout_was_explicit and isinstance(args.timeout, int) and args.timeout <= 6
    )
    direct_budget_timeout = args.timeout
    if project.arch.name == "86_16" and not fast_direct_probe:
        # Keep direct-address recovery deterministic under explicit user
        # timeout; avoid inflating into outer subprocess timeouts.
        if timeout_was_explicit and isinstance(args.timeout, int):
            direct_budget_timeout = max(args.timeout, 1)
        else:
            direct_budget_timeout = max(direct_budget_timeout, 24)
    direct_addr_started_at = time.monotonic()
    direct_addr_deadline = direct_addr_started_at + _direct_addr_wall_clock_budget(
        args.timeout,
        effective_timeout=direct_budget_timeout,
        explicit_timeout=bool(timeout_was_explicit),
    )
    budget_fallback_addr: int | None = None
    budget_fallback_name: str | None = None

    def _emit_budget_exhausted_sidecar_asm_fallback_or_timeout(detail: str) -> None:
        if precise_sidecar_regions and budget_fallback_addr is not None and lst_metadata is not None:
            sidecar_region = _lst_code_region(lst_metadata, budget_fallback_addr)
            if sidecar_region is not None:
                code_name = (
                    _lst_code_label(lst_metadata, sidecar_region[0], project.entry)
                    or budget_fallback_name
                    or f"sub_{budget_fallback_addr:x}"
                )
                print(f"/* Decompilation timeout: Timed out after {args.timeout}s. */")
                print("/* direct validation=failed */")
                _emit_failed_timeout_acceptance_hints_8616()
                print("/* Function recovery timed out; using sidecar-bounded asm fallback. */")
                print("/* non-optimized fallback failed: unavailable after recovery-timeout budget exhaustion */")
                print(f"/* binary: {args.binary} */")
                print(f"/* arch: {project.arch.name} */")
                print(f"/* entry: {project.entry:#x} */")
                print(f"/* function: {sidecar_region[0]:#x} {code_name} */")
                _emit_tail_validation_for_function_run_or_uncollected(
                    project,
                    None,
                    SimpleNamespace(addr=sidecar_region[0], name=code_name),
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("asm"),
                    binary_path=args.binary,
                )
                print("\n/* == asm fallback == */")
                print(_format_asm_range(project, sidecar_region[0], sidecar_region[1]))
                sys.stdout.flush()
                emit_compact_summary()
                sys.stderr.flush()
                os._exit(4)
        _emit_timeout_and_exit(args.timeout, detail)

    def _remaining_direct_addr_budget() -> int:
        return max(0, int(direct_addr_deadline - time.monotonic()))

    def _enforce_direct_addr_budget_timeout(*, recovery_detail: str | None = None) -> None:
        if _remaining_direct_addr_budget() > 0:
            return
        detail = recovery_detail
        if detail is None:
            detail = "after exhausting direct-address recovery budget"
        _emit_budget_exhausted_sidecar_asm_fallback_or_timeout(detail)

    canonical_direct_addr = _canonicalize_direct_addr_from_sidecar_padding_8616(
        project,
        lst_metadata,
        direct_addr,
        function_label=function_label,
    )
    if canonical_direct_addr is not None:
        print(
            "/* direct address canonicalized from "
            f"{canonical_direct_addr.requested_addr:#x} to {canonical_direct_addr.canonical_addr:#x} "
            "using sidecar padding/prologue evidence */",
            file=sys.stderr,
            flush=True,
        )
        direct_addr = canonical_direct_addr.canonical_addr
        args.addr = direct_addr
        if function_label is None and canonical_direct_addr.name:
            function_label = canonical_direct_addr.name

    try:

        def _recover_target_function() -> _FunctionCfgPair8616:
            exact_region_end = getattr(args, "exact_region_end", None)
            exact_region = (
                (direct_addr, exact_region_end)
                if isinstance(exact_region_end, int) and exact_region_end > direct_addr
                else None
            )
            return cast(
                _FunctionCfgPair8616,
                _recover_direct_addr_function(
                    project,
                    direct_addr,
                    timeout=args.timeout,
                    window=args.window,
                    function_label=function_label,
                    lst_metadata=lst_metadata,
                    low_memory_path=low_memory_path,
                    prefer_fast_recovery=prefer_fast_recovery,
                    exact_region=exact_region,
                ),
            )

        direct_recovery_timeout = (
            max(1, min(args.timeout, 6))
            if args.proc is not None and not proc_resolved_to_linked_binary
            else _default_recovery_timeout(args.timeout, explicit_timeout=timeout_was_explicit)
        )
        direct_recovery_timeout = max(1, min(direct_recovery_timeout, _remaining_direct_addr_budget() or 1))
        cfg, func = _run_with_timeout_in_daemon_thread(
            _recover_target_function,
            timeout=direct_recovery_timeout,
            thread_name_prefix="recovery",
            prefer_process_alarm=True,
        )
    except _AnalysisTimeout:
        _enforce_direct_addr_budget_timeout()
        sidecar_region = _lst_code_region(lst_metadata, direct_addr) if lst_metadata is not None else None
        if precise_sidecar_regions and sidecar_region is not None:
            code_name = _lst_code_label(lst_metadata, sidecar_region[0], project.entry) or f"sub_{direct_addr:x}"
            slice_result = _try_decompile_sidecar_slice(
                project,
                lst_metadata,
                sidecar_region[0],
                code_name,
                timeout=max(1, min(args.timeout, _remaining_direct_addr_budget() or 1)),
                api_style=args.api_style,
                binary_path=args.binary,
            )
            if slice_result is not None and slice_result.status == "ok":
                fallback_function = SimpleNamespace(addr=sidecar_region[0], name=code_name)
                print("/* Function recovery timed out; recovered function slice from sidecar bounds. */")
                print(f"/* binary: {args.binary} */")
                print(f"/* arch: {project.arch.name} */")
                print(f"/* entry: {project.entry:#x} */")
                print(f"/* function: {sidecar_region[0]:#x} {code_name} */")
                _emit_tail_validation_for_function_run_or_uncollected(
                    project,
                    None,
                    fallback_function,
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("sidecar_slice"),
                    binary_path=args.binary,
                )
                _emit_optional_source_sidecar_c_block(
                    args.binary,
                    code_name,
                    slice_result.payload,
                    alternate_source_c=bool(args.alternate_source_c),
                    c_header="\n/* == c == */",
                )
                return 0
            _enforce_direct_addr_budget_timeout()
            nonopt_result: NonOptimizedSliceOutcome | str | None = _try_decompile_non_optimized_slice(
                project,
                sidecar_region[0],
                code_name,
                timeout=max(1, min(_bounded_non_optimized_timeout(args.timeout), _remaining_direct_addr_budget() or 1)),
                api_style=args.api_style,
                binary_path=args.binary,
                lst_metadata=lst_metadata,
                cod_metadata=cod_metadata,
            )
            nonopt_c = _non_optimized_slice_rendered(nonopt_result)
            if nonopt_c is not None:
                fallback_function = SimpleNamespace(addr=sidecar_region[0], name=code_name)
                print("/* Function recovery timed out; produced non-optimized slice decompilation. */")
                print(f"/* binary: {args.binary} */")
                print(f"/* arch: {project.arch.name} */")
                print(f"/* entry: {project.entry:#x} */")
                print(f"/* function: {sidecar_region[0]:#x} {code_name} */")
                _emit_tail_validation_for_function_run_or_uncollected(
                    project,
                    None,
                    fallback_function,
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
                    binary_path=args.binary,
                )
                _emit_optional_source_sidecar_c_block(
                    args.binary,
                    code_name,
                    nonopt_c,
                    alternate_source_c=bool(args.alternate_source_c),
                    c_header="\n/* == c (non-optimized fallback) == */",
                )
                return 0
            string_c = _try_emit_string_intrinsic_c(
                project,
                start=sidecar_region[0],
                end=sidecar_region[1],
                name=code_name,
            )
            if string_c is not None:
                print(
                    "/* Function recovery timed out; emitted generic string-intrinsic fallback from sidecar bounds. */"
                )
                print(f"/* binary: {args.binary} */")
                print(f"/* arch: {project.arch.name} */")
                print(f"/* entry: {project.entry:#x} */")
                print(f"/* function: {sidecar_region[0]:#x} {code_name} */")
                _emit_tail_validation_for_function_run_or_uncollected(
                    project,
                    None,
                    SimpleNamespace(addr=sidecar_region[0], name=code_name),
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("string_intrinsic"),
                    binary_path=args.binary,
                )
                _emit_optional_source_sidecar_c_block(
                    args.binary,
                    code_name,
                    string_c,
                    alternate_source_c=bool(args.alternate_source_c),
                    c_header="\n/* == c (string intrinsic fallback) == */",
                )
                return 0
            print("/* Function recovery timed out; using sidecar-bounded asm fallback. */")
            print("/* direct validation=failed */")
            _emit_failed_timeout_acceptance_hints_8616()
            print(f"/* binary: {args.binary} */")
            print(f"/* arch: {project.arch.name} */")
            print(f"/* entry: {project.entry:#x} */")
            print(f"/* function: {sidecar_region[0]:#x} {code_name} */")
            _emit_tail_validation_for_function_run_or_uncollected(
                project,
                None,
                SimpleNamespace(addr=sidecar_region[0], name=code_name),
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("asm"),
                binary_path=args.binary,
            )
            print("\n/* == asm fallback == */")
            print(_format_asm_range(project, sidecar_region[0], sidecar_region[1]))
            return 4
        nonopt_result = None
        _enforce_direct_addr_budget_timeout()
        nonopt_result = _try_decompile_non_optimized_slice(
            project,
            direct_addr,
            function_label or f"sub_{direct_addr:x}",
            timeout=max(1, min(_bounded_non_optimized_timeout(args.timeout), _remaining_direct_addr_budget() or 1)),
            api_style=args.api_style,
            binary_path=args.binary,
            lst_metadata=lst_metadata,
            cod_metadata=cod_metadata,
        )
        nonopt_c = _non_optimized_slice_rendered(nonopt_result)
        if nonopt_c is not None:
            fallback_function = SimpleNamespace(addr=direct_addr, name=function_label or f"sub_{direct_addr:x}")
            print("/* Function recovery timed out; produced non-optimized slice decompilation. */")
            print(f"/* binary: {args.binary} */")
            print(f"/* arch: {project.arch.name} */")
            print(f"/* entry: {project.entry:#x} */")
            print(f"/* function: {direct_addr:#x} {function_label or f'sub_{direct_addr:x}'} */")
            _emit_tail_validation_for_function_run_or_uncollected(
                project,
                None,
                fallback_function,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
                binary_path=args.binary,
            )
            _emit_optional_source_sidecar_c_block(
                args.binary,
                fallback_function.name,
                nonopt_c,
                alternate_source_c=bool(args.alternate_source_c),
                c_header="\n/* == c (non-optimized fallback) == */",
            )
            return 0
        fallback_function = SimpleNamespace(addr=direct_addr, name=function_label or f"sub_{direct_addr:x}")
        start, end = _infer_linear_disassembly_window(project, direct_addr)
        string_c = _try_emit_string_intrinsic_c(
            project,
            start=start,
            end=end,
            name=fallback_function.name,
        )
        if string_c is not None:
            print("/* Function recovery timed out; emitted generic string-intrinsic fallback. */")
            print(f"/* binary: {args.binary} */")
            print(f"/* arch: {project.arch.name} */")
            print(f"/* entry: {project.entry:#x} */")
            print(f"/* function: {direct_addr:#x} {fallback_function.name} */")
            _emit_tail_validation_for_function_run_or_uncollected(
                project,
                None,
                fallback_function,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("string_intrinsic"),
                binary_path=args.binary,
            )
            nonopt_skip_reason = describe_non_optimized_unavailable(
                allow_heavy_fallbacks=True,
                skip_heavy_fallbacks_for_result=False,
                interactive_stdout=interactive_stdout,
                max_functions=args.max_functions,
                addr_requested=direct_addr is not None,
                result_status="timeout",
                failure_stage=None,
                nonopt_failure_detail=_non_optimized_slice_failure_detail(nonopt_result),
            )
            if nonopt_skip_reason is not None:
                print(f"/* non-optimized fallback unavailable: {nonopt_skip_reason} */")
            _emit_optional_source_sidecar_c_block(
                args.binary,
                fallback_function.name,
                string_c,
                alternate_source_c=bool(args.alternate_source_c),
                c_header="\n/* == c (string intrinsic fallback) == */",
            )
            return 0
        asm_fallback = _format_asm_range(project, start, end)
        recovery_detail = _function_recovery_detail(getattr(project, "_inertia_decompiler_stage", None))
        if recovery_detail is None:
            recovery_detail = "during x86-16 function recovery (direct-address path)"
        print(f"/* timeout: function {direct_addr:#x} {function_label or f'sub_{direct_addr:x}'} */")
        _stored_snapshot = getattr(project, "_inertia_last_tail_validation_snapshot", None)
        if isinstance(_stored_snapshot, dict) and _stored_snapshot:
            for _diag_line in _format_tail_validation_diagnostic(
                _stored_snapshot,
                function_addr=direct_addr,
                function_name=function_label or f"sub_{direct_addr:x}",
                exit_kind="timeout",
                exit_detail=recovery_detail,
            ):
                print(_diag_line)
        _emit_timeout_and_exit(args.timeout, recovery_detail)
    except FuturesTimeoutError:
        _enforce_direct_addr_budget_timeout()
        sidecar_region = _lst_code_region(lst_metadata, direct_addr) if lst_metadata is not None else None
        if precise_sidecar_regions and sidecar_region is not None:
            code_name = _lst_code_label(lst_metadata, sidecar_region[0], project.entry) or f"sub_{direct_addr:x}"
            slice_result = _try_decompile_sidecar_slice(
                project,
                lst_metadata,
                sidecar_region[0],
                code_name,
                timeout=max(1, min(args.timeout, _remaining_direct_addr_budget() or 1)),
                api_style=args.api_style,
                binary_path=args.binary,
            )
            if slice_result is not None and slice_result.status == "ok":
                fallback_function = SimpleNamespace(addr=sidecar_region[0], name=code_name)
                print("/* Function recovery timed out; recovered function slice from sidecar bounds. */")
                print(f"/* binary: {args.binary} */")
                print(f"/* arch: {project.arch.name} */")
                print(f"/* entry: {project.entry:#x} */")
                print(f"/* function: {sidecar_region[0]:#x} {code_name} */")
                _emit_tail_validation_for_function_run_or_uncollected(
                    project,
                    None,
                    fallback_function,
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("sidecar_slice"),
                    binary_path=args.binary,
                )
                _emit_optional_source_sidecar_c_block(
                    args.binary,
                    code_name,
                    slice_result.payload,
                    alternate_source_c=bool(args.alternate_source_c),
                    c_header="\n/* == c == */",
                )
                return 0
            _enforce_direct_addr_budget_timeout()
            nonopt_result = _try_decompile_non_optimized_slice(
                project,
                sidecar_region[0],
                code_name,
                timeout=max(1, min(_bounded_non_optimized_timeout(args.timeout), _remaining_direct_addr_budget() or 1)),
                api_style=args.api_style,
                binary_path=args.binary,
                lst_metadata=lst_metadata,
                cod_metadata=cod_metadata,
            )
            nonopt_c = _non_optimized_slice_rendered(nonopt_result)
            if nonopt_c is not None:
                fallback_function = SimpleNamespace(addr=sidecar_region[0], name=code_name)
                print("/* Function recovery timed out; produced non-optimized slice decompilation. */")
                print(f"/* binary: {args.binary} */")
                print(f"/* arch: {project.arch.name} */")
                print(f"/* entry: {project.entry:#x} */")
                print(f"/* function: {sidecar_region[0]:#x} {code_name} */")
                _emit_tail_validation_for_function_run_or_uncollected(
                    project,
                    None,
                    fallback_function,
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
                    binary_path=args.binary,
                )
                _emit_optional_source_sidecar_c_block(
                    args.binary,
                    code_name,
                    nonopt_c,
                    alternate_source_c=bool(args.alternate_source_c),
                    c_header="\n/* == c (non-optimized fallback) == */",
                )
                return 0
            string_c = _try_emit_string_intrinsic_c(
                project,
                start=sidecar_region[0],
                end=sidecar_region[1],
                name=code_name,
            )
            if string_c is not None:
                print(
                    "/* Function recovery timed out; emitted generic string-intrinsic fallback from sidecar bounds. */"
                )
                print(f"/* binary: {args.binary} */")
                print(f"/* arch: {project.arch.name} */")
                print(f"/* entry: {project.entry:#x} */")
                print(f"/* function: {sidecar_region[0]:#x} {code_name} */")
                _emit_tail_validation_for_function_run_or_uncollected(
                    project,
                    None,
                    SimpleNamespace(addr=sidecar_region[0], name=code_name),
                    allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("string_intrinsic"),
                    binary_path=args.binary,
                )
                _emit_optional_source_sidecar_c_block(
                    args.binary,
                    code_name,
                    string_c,
                    alternate_source_c=bool(args.alternate_source_c),
                    c_header="\n/* == c (string intrinsic fallback) == */",
                )
                return 0
            print("/* Function recovery timed out; using sidecar-bounded asm fallback. */")
            print("/* direct validation=failed */")
            _emit_failed_timeout_acceptance_hints_8616()
            print(f"/* binary: {args.binary} */")
            print(f"/* arch: {project.arch.name} */")
            print(f"/* entry: {project.entry:#x} */")
            print(f"/* function: {sidecar_region[0]:#x} {code_name} */")
            _emit_tail_validation_for_function_run_or_uncollected(
                project,
                None,
                SimpleNamespace(addr=sidecar_region[0], name=code_name),
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("asm"),
                binary_path=args.binary,
            )
            print("\n/* == asm fallback == */")
            print(_format_asm_range(project, sidecar_region[0], sidecar_region[1]))
            return 4
        nonopt_result = None
        if precise_sidecar_regions:
            _enforce_direct_addr_budget_timeout()
            nonopt_result = _try_decompile_non_optimized_slice(
                project,
                direct_addr,
                function_label or f"sub_{direct_addr:x}",
                timeout=max(1, min(_bounded_non_optimized_timeout(args.timeout), _remaining_direct_addr_budget() or 1)),
                api_style=args.api_style,
                binary_path=args.binary,
                lst_metadata=lst_metadata,
                cod_metadata=cod_metadata,
            )
        nonopt_c = _non_optimized_slice_rendered(nonopt_result)
        if nonopt_c is not None:
            fallback_function = SimpleNamespace(addr=direct_addr, name=function_label or f"sub_{direct_addr:x}")
            print("/* Function recovery timed out; produced non-optimized slice decompilation. */")
            print(f"/* binary: {args.binary} */")
            print(f"/* arch: {project.arch.name} */")
            print(f"/* entry: {project.entry:#x} */")
            print(f"/* function: {direct_addr:#x} {function_label or f'sub_{direct_addr:x}'} */")
            _emit_tail_validation_for_function_run_or_uncollected(
                project,
                None,
                fallback_function,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
                binary_path=args.binary,
            )
            _emit_optional_source_sidecar_c_block(
                args.binary,
                fallback_function.name,
                nonopt_c,
                alternate_source_c=bool(args.alternate_source_c),
                c_header="\n/* == c (non-optimized fallback) == */",
            )
            return 0
        fallback_function = SimpleNamespace(addr=direct_addr, name=function_label or f"sub_{direct_addr:x}")
        start, end = _infer_linear_disassembly_window(project, direct_addr)
        string_c = _try_emit_string_intrinsic_c(
            project,
            start=start,
            end=end,
            name=fallback_function.name,
        )
        if string_c is not None:
            print("/* Function recovery timed out; emitted generic string-intrinsic fallback. */")
            print(f"/* binary: {args.binary} */")
            print(f"/* arch: {project.arch.name} */")
            print(f"/* entry: {project.entry:#x} */")
            print(f"/* function: {direct_addr:#x} {fallback_function.name} */")
            _emit_tail_validation_for_function_run_or_uncollected(
                project,
                None,
                fallback_function,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("string_intrinsic"),
                binary_path=args.binary,
            )
            nonopt_skip_reason = describe_non_optimized_unavailable(
                allow_heavy_fallbacks=True,
                skip_heavy_fallbacks_for_result=False,
                interactive_stdout=interactive_stdout,
                max_functions=args.max_functions,
                addr_requested=direct_addr is not None,
                result_status="timeout",
                failure_stage=None,
                nonopt_failure_detail=_non_optimized_slice_failure_detail(nonopt_result),
            )
            if nonopt_skip_reason is not None:
                print(f"/* non-optimized fallback unavailable: {nonopt_skip_reason} */")
            _emit_optional_source_sidecar_c_block(
                args.binary,
                fallback_function.name,
                string_c,
                alternate_source_c=bool(args.alternate_source_c),
                c_header="\n/* == c (string intrinsic fallback) == */",
            )
            return 0
        asm_fallback = _format_asm_range(project, start, end)
        recovery_detail = _function_recovery_detail(getattr(project, "_inertia_decompiler_stage", None))
        if recovery_detail is None:
            recovery_detail = "during x86-16 function recovery (direct-address path)"
        print(f"/* timeout: function {direct_addr:#x} {function_label or f'sub_{direct_addr:x}'} */")
        _stored_snapshot = getattr(project, "_inertia_last_tail_validation_snapshot", None)
        if isinstance(_stored_snapshot, dict) and _stored_snapshot:
            for _diag_line in _format_tail_validation_diagnostic(
                _stored_snapshot,
                function_addr=direct_addr,
                function_name=function_label or f"sub_{direct_addr:x}",
                exit_kind="timeout",
                exit_detail=recovery_detail,
            ):
                print(_diag_line)
        _emit_timeout_and_exit(args.timeout, recovery_detail)
    except Exception as ex:
        recovery_detail = _function_recovery_detail(getattr(project, "_inertia_decompiler_stage", None))
        if recovery_detail is None:
            print(f"/* Function recovery failed: {ex} */")
        else:
            print(f"/* Function recovery failed {recovery_detail}: {ex} */")
        if os.environ.get("INERTIA_DEBUG_RECOVERY_TRACEBACK"):
            import traceback

            traceback.print_exc()
        print("\n/* == lift break probe == */")
        print(_probe_lift_break(project, direct_addr))
        print("\n/* == first block asm == */")
        print(_format_first_block_asm(project, direct_addr))
        print("\n/* == non-optimized disassembly == */")
        start, end = _infer_linear_disassembly_window(project, direct_addr)
        print(_format_asm_range(project, start, end))
        return 5

    if project.arch.name == "86_16":
        record_direct_target_caller_return_use_evidence_8616(
            project,
            direct_addr,
            binary_path=args.binary,
        )

    if (
        precise_sidecar_regions
        and lst_metadata is not None
        and project.arch.name == "86_16"
        and direct_addr is not None
    ):
        try:
            sidecar_region = _lst_code_region(lst_metadata, direct_addr)
            block_count, byte_count = _function_complexity(func)
            if (
                sidecar_region is not None
                and isinstance(sidecar_region[0], int)
                and int(sidecar_region[0]) == int(direct_addr)
                and (block_count <= 3 or byte_count <= 24)
            ):
                sidecar_addr = sidecar_region[0]
                code_name = _lst_code_label(lst_metadata, sidecar_addr, project.entry) or f"sub_{sidecar_addr:x}"
                cfg2, func2 = _recover_lst_function(
                    project,
                    lst_metadata,
                    sidecar_addr if lst_metadata.absolute_addrs else sidecar_addr - project.entry,
                    code_name,
                    timeout=max(1, min(args.timeout, 6)),
                    window=args.window,
                    low_memory=low_memory_path,
                )
                if func2 is not None:
                    cfg, func = cfg2, func2
                    mark_function_original_addr(func, direct_addr)
        except Exception:
            pass

    if direct_addr is not None and project.arch.name == "86_16":
        try:
            recovered_blocks, recovered_bytes = _function_complexity(func)
        except Exception:
            recovered_blocks, recovered_bytes = (0, 0)
        region = _lst_code_region(lst_metadata, direct_addr) if lst_metadata is not None else None
        region_span = max(0, int(region[1]) - int(region[0])) if isinstance(region, tuple) and len(region) == 2 else 0
        if recovered_blocks <= 1 and recovered_bytes <= 16 and region_span >= 64:
            try:
                ranked_cfg, ranked_func = _recover_ranked_binary_function(
                    project,
                    direct_addr,
                    function_label or func.name,
                    timeout=max(12, min(args.timeout, 24)),
                    window=args.window,
                    low_memory=low_memory_path,
                )
            except Exception:
                pass
            else:
                cfg, func = ranked_cfg, ranked_func

    if function_label is not None:
        func.name = function_label
    elif lst_metadata is not None:
        code_name = lst_metadata.code_labels.get(function_original_addr(func))
        if code_name is not None:
            func.name = code_name
    direct_project = getattr(func, "project", project)
    if project.arch.name == "86_16":
        attach_direct_target_argument_evidence_context_8616(
            project,
            direct_project,
            function_original_addr(func),
        )
        prepare_direct_indexed_alias_program_context_8616(
            project,
            direct_project,
            func,
            timeout=args.timeout,
            window=args.window,
            binary_path=args.binary,
        )
        for call_target in collect_neighbor_call_targets(func):
            if call_target.return_addr is not None:
                record_direct_target_caller_return_use_evidence_8616(
                    project,
                    call_target.target_addr,
                    binary_path=args.binary,
                )
    _transfer_caller_return_use_evidence_8616(project, direct_project)
    typing.cast(typing.Any, direct_project)._inertia_trace_c_stages = bool(args.trace_c_stages)
    typing.cast(typing.Any, direct_project)._inertia_dump_layers = bool(args.dump_layers)
    typing.cast(typing.Any, direct_project)._inertia_dump_layer_root = args.dump_layer_dir
    typing.cast(typing.Any, direct_project)._inertia_dump_layer_filter = args.dump_layer_filter
    if bool(args.alternate_source_c) and getattr(project.arch, "name", "") == "86_16":
        typing.cast(typing.Any, direct_project)._inertia_enable_typed_switch_seqnode_replacement_8616 = True
    _apply_binary_specific_annotations(
        direct_project,
        args.binary,
        lst_metadata,
        func_addr=function_original_addr(func),
        cod_metadata=cod_metadata,
        synthetic_globals=synthetic_globals,
    )

    print(f"/* binary: {args.binary} */")
    print(f"/* arch: {project.arch.name} */")
    print(f"/* entry: {project.entry:#x} */")
    print(f"/* function: {function_original_addr(func):#x} {func.name} */")

    if args.show_asm:
        print("\n/* == asm == */")
        print(_format_first_block_asm(direct_project, func.addr))

    known_helper_model = _try_emit_known_runtime_helper_c(name=getattr(func, "name", ""))
    if isinstance(known_helper_model, str):
        helper_snapshot: dict[str, object] = {
            "structuring": {
                "status": "stable",
                "mode": "helper_model",
                "changed": False,
                "detail": f"known compiler/runtime helper model: {func.name}",
            },
            "postprocess": {
                "status": "stable",
                "mode": "helper_model",
                "changed": False,
                "detail": f"known compiler/runtime helper model: {func.name}",
            },
        }
        helper_result = FunctionWorkResult(
            index=1,
            status=WorkItemStatus.OK.value,
            payload=known_helper_model,
            debug_output="",
            function=func,
            function_cfg=cfg,
            tail_validation=helper_snapshot,
        )
        if _complete_serial_clean_worker_result_8616(helper_result, project=direct_project):
            return 0
        print(
            "[dbg] direct failure family: status=ok stage=helper_model sidecar=not_applicable "
            "nonopt=not_needed fallback=direct_addr validation=passed",
            file=sys.stderr,
        )
        _emit_tail_validation_snapshot_or_uncollected(
            cfg,
            func,
            helper_snapshot,
            binary_path=args.binary,
        )
        _emit_optional_source_sidecar_c_block(
            args.binary,
            func.name,
            known_helper_model,
            alternate_source_c=bool(args.alternate_source_c),
            c_header="\n/* == c == */",
        )
        return 0

    direct_cache_item = FunctionWorkItem(index=1, function_cfg=cfg, function=func)
    direct_cache_result, direct_cache_debug, direct_cache_key, _, _ = _function_work_cache_lookup(
        direct_cache_item,
        binary_path=args.binary,
        timeout=max(1, int(args.timeout)),
        api_style=args.api_style,
        enable_structured_simplify=True,
        enable_postprocess=True,
        cod_metadata=cod_metadata,
        synthetic_globals=synthetic_globals,
        lst_metadata=lst_metadata,
    )
    if direct_cache_result is not None and direct_cache_result.failure_family_snapshot is not None:
        if direct_cache_debug:
            print(direct_cache_debug, file=sys.stderr, end="")
        cached_direct_result = replace(
            direct_cache_result,
            function=func,
            function_cfg=cfg,
        )
        _store_direct_request_result_8616(
            context,
            direct_request_cache_lookup,
            cached_direct_result,
            function_addr=function_original_addr(func),
            function_name=func.name,
        )
        return _emit_direct_cache_hit_8616(
            context,
            cached_direct_result,
            function=func,
            function_cfg=cfg,
            emit_function_header=False,
            project_for_worker_result=direct_project,
        )

    if (
        canonical_direct_addr is not None
        and canonical_direct_addr.requested_addr != canonical_direct_addr.canonical_addr
        and not args.ignore_local_sidecar_hints
    ):
        assert lst_metadata is not None
        cached_clean_status = _run_canonicalized_direct_clean_worker_8616(
            project,
            args,
            lst_metadata,
            canonical_direct_addr,
            function_label=function_label,
            caller_return_evidence_by_addr=clean_worker_caller_return_evidence_by_addr,
            cache_only=True,
        )
        if cached_clean_status is not None:
            return cached_clean_status

    print("/* decompiling... */", flush=True)
    direct_tail_validation_snapshot: dict[str, object] | None = None
    direct_segment_program_evidence: SegmentProgramFunctionEvidence8616 | None = None
    direct_failure_family_state = FailureFamilyState()
    direct_sidecar_verdict = "not_attempted"
    direct_nonoptimized_verdict = "not_attempted"
    direct_timeout_stage: str | None = None
    direct_debug_output = ""
    _block_count, _byte_count = _function_complexity(func)
    _elapsed = 0.0

    def _direct_failure_snapshot(result: FunctionWorkResult) -> FailureFamilySnapshot:
        """Build the complete direct-address diagnostic snapshot for one result."""
        return build_failure_family_snapshot(
            status=result.status,
            failure_stage=result.failure_stage,
            sidecar_verdict=direct_sidecar_verdict,
            non_optimized_verdict=direct_nonoptimized_verdict,
            fallback_kind="direct_addr",
            tail_validation_verdict=_tail_validation_display_status(
                result.tail_validation,
                fallback_kind="direct_addr" if result.status != "ok" else None,
            ),
            artifact_path=f"{func.addr:#x}:{func.name}",
        )

    def _direct_analysis_timeout_for_shape(base_timeout: int, block_count: int, byte_count: int) -> int:
        boosted = _effective_decompile_timeout_8616(
            direct_project,
            base_timeout,
            block_count=block_count,
            byte_count=byte_count,
        )
        if getattr(project.arch, "name", "") == "86_16":
            # Large menu/controller functions are clinic-heavy and can
            # legitimately exceed the default 120s lane timeout.
            if block_count >= 72 or byte_count >= 520:
                boosted = max(boosted, base_timeout + 180)
            elif block_count >= 56 or byte_count >= 420:
                boosted = max(boosted, base_timeout + 120)
            elif block_count >= 40 or byte_count >= 300:
                boosted = max(boosted, base_timeout + 80)
        return _enforce_function_timeout_cap(
            max(1, boosted),
            context="direct shape timeout",
            explicit_timeout_floor=args.timeout if timeout_was_explicit else None,
        )

    try:

        def direct_decompile_job() -> _DirectDecompileJobResult8616:
            """Run one direct function through the selected bounded Clinic policy."""
            _bcount, _bbytes = _function_complexity(func)
            direct_analysis_timeout = _direct_analysis_timeout_for_shape(args.timeout, _bcount, _bbytes)
            direct_arch_name = getattr(getattr(direct_project, "arch", None), "name", "")
            direct_callsite_count = (
                _safe_function_callsite_count_8616(func)
                if _clinic_policy_needs_callsite_count_8616(
                    arch_name=direct_arch_name,
                    direct_addr_mode=direct_addr is not None,
                    block_count=_bcount,
                    byte_count=_bbytes,
                )
                else 0
            )
            direct_clinic_policy = _direct_clinic_policy_8616(
                arch_name=direct_arch_name,
                direct_addr_mode=direct_addr is not None,
                block_count=_bcount,
                byte_count=_bbytes,
                call_site_count=direct_callsite_count,
            )
            if os.environ.get("INERTIA_DEBUG_CLINIC_FLAGS"):
                print(
                    "[dbg] direct clinic policy "
                    f"policy={direct_clinic_policy.value} arch={direct_arch_name!r} "
                    f"blocks={_bcount} bytes={_bbytes} calls={direct_callsite_count}"
                )
            with _temporary_clinic_policy_8616(direct_project, direct_clinic_policy):
                with _capture_thread_output() as (stdout_buf, stderr_buf):
                    result = _decompile_function_with_stats(
                        direct_project,
                        cfg,
                        func,
                        direct_analysis_timeout,
                        args.api_style,
                        args.binary,
                        cod_metadata=cod_metadata,
                        synthetic_globals=synthetic_globals,
                        lst_metadata=lst_metadata,
                        # Direct-address mode must prefer deterministic single-lane
                        # recovery. Isolated retries can re-run the full pipeline
                        # multiple times and overwrite a valid candidate with a
                        # later timeout lane.
                        allow_isolated_retry=False,
                        failure_family_state=direct_failure_family_state,
                    )
                debug_output = stdout_buf.getvalue() + stderr_buf.getvalue()
            snapshot = _tail_validation_snapshot_for_function_run(direct_project, func)
            project_fb = getattr(direct_project, "_inertia_last_tail_validation_snapshot", None)
            if (
                isinstance(project_fb, dict)
                and x86_16_tail_validation_snapshot_passed(project_fb)
                and not x86_16_tail_validation_snapshot_passed(snapshot)
            ):
                # A nested analysis can capture a pre-refresh snapshot before
                # the requested function publishes its final project snapshot.
                # The complete passing project snapshot is the authoritative
                # result at this worker boundary.
                snapshot = dict(project_fb)
            func_info_tv = None
            func_info = getattr(func, "info", None)
            if isinstance(func_info, dict):
                func_info_tv = func_info.get("x86_16_tail_validation")
            merged_statuses = (
                {k: v.get("status") if isinstance(v, dict) else type(v).__name__ for k, v in snapshot.items()}
                if isinstance(snapshot, dict)
                else "N/A"
            )
            print(
                f"[dbg] direct_decompile_job snapshot: project_fb_stages={list(project_fb.keys()) if isinstance(project_fb, dict) else 'NOT_DICT'} func_info_tv_stages={list(func_info_tv.keys()) if isinstance(func_info_tv, dict) else type(func_info_tv).__name__ if func_info_tv is not None else 'None'} merged_stages={list(snapshot.keys()) if isinstance(snapshot, dict) else 'NOT_DICT'} merged_statuses={merged_statuses}",
                file=sys.stderr,
                flush=True,
            )
            return (
                *result,
                snapshot,
                segment_program_function_evidence_for_function_8616(direct_project, func),
                FailureFamilyState(
                    previous_snapshot=direct_failure_family_state.previous_snapshot,
                    candidate_snapshot=direct_failure_family_state.candidate_snapshot,
                    new_proof_seen=direct_failure_family_state.new_proof_seen,
                    repeat_detected=direct_failure_family_state.repeat_detected,
                ),
                debug_output,
            )

        # The inner decompilation path already enforces the analysis deadline.
        # Give the forked direct-address wrapper a few extra seconds to merge
        # tail-validation snapshots and serialize the result back to the parent.
        _direct_blocks, _direct_bytes = _function_complexity(func)
        _direct_effective_timeout = _effective_decompile_timeout_8616(
            direct_project,
            args.timeout,
            block_count=_direct_blocks,
            byte_count=_direct_bytes,
        )
        _direct_effective_timeout = _direct_analysis_timeout_for_shape(
            _direct_effective_timeout,
            _direct_blocks,
            _direct_bytes,
        )
        direct_addr_deadline = max(
            direct_addr_deadline,
            direct_addr_started_at
            + _direct_addr_wall_clock_budget(
                args.timeout,
                effective_timeout=_direct_effective_timeout,
                explicit_timeout=bool(timeout_was_explicit),
            ),
        )
        direct_decompile_timeout = _enforce_function_timeout_cap(
            max(1, _direct_effective_timeout) + 28,
            context="direct analysis wrapper timeout",
            explicit_timeout_floor=(max(1, _direct_effective_timeout) + 28 if timeout_was_explicit else None),
        )
        if timeout_was_explicit and isinstance(args.timeout, int) and args.timeout <= 6:
            if _direct_blocks >= 4 or _direct_bytes >= 0x50:
                direct_decompile_timeout = min(direct_decompile_timeout, args.timeout + 20)
            else:
                direct_decompile_timeout = min(direct_decompile_timeout, args.timeout + 8)
            # For larger explicit x86-16 functions, retain the shape-aware
            # budget calculated above. Capping it to ``args.timeout + 32``
            # defeats the large-function allowance and turns normal xdist
            # contention into a false direct-decompilation timeout. The small
            # timeout lane remains deliberately bounded because it is used by
            # fast discovery probes rather than full function recovery.
        remaining_direct_budget = _remaining_direct_addr_budget() or 1
        budgeted_direct_decompile_timeout = max(1, min(direct_decompile_timeout, remaining_direct_budget))
        direct_decompile_timeout = _enforce_function_timeout_cap(
            budgeted_direct_decompile_timeout,
            context="direct direct-address budget timeout",
            explicit_timeout_floor=(budgeted_direct_decompile_timeout if timeout_was_explicit else None),
        )
        use_fork_for_direct = _direct_addr_use_fork_lane_8616(
            tail_validation_enabled=_tail_validation_runtime_enabled(direct_project),
        )
        with span(
            "direct.decompile_job",
            addr=hex(getattr(func, "addr", 0)),
            name=getattr(func, "name", None),
            timeout=direct_decompile_timeout,
            isolated="fork" if use_fork_for_direct else "thread",
            blocks=_direct_blocks,
            bytes=_direct_bytes,
        ):
            if use_fork_for_direct:
                direct_job_result = _run_with_timeout_in_fork(
                        direct_decompile_job,
                        timeout=direct_decompile_timeout,
                    )
            else:
                direct_job_result = _run_with_timeout_in_daemon_thread(
                        direct_decompile_job,
                        timeout=direct_decompile_timeout,
                        thread_name_prefix="direct-decomp",
                    )
            status, payload, partial_payload, _block_count, _byte_count, _elapsed, *direct_extra = direct_job_result
            annotate_current_span(status=status)
            for extra in direct_extra:
                if isinstance(extra, dict):
                    direct_tail_validation_snapshot = dict(extra)
                elif isinstance(extra, SegmentProgramFunctionEvidence8616):
                    direct_segment_program_evidence = extra
                elif isinstance(extra, FailureFamilyState):
                    direct_failure_family_state.previous_snapshot = extra.previous_snapshot
                    direct_failure_family_state.candidate_snapshot = extra.candidate_snapshot
                    direct_failure_family_state.new_proof_seen = extra.new_proof_seen
                    direct_failure_family_state.repeat_detected = extra.repeat_detected
                elif isinstance(extra, str):
                    direct_debug_output = extra
    except FuturesTimeoutError:
        status = "timeout"
        payload = f"Timed out after {direct_decompile_timeout}s."
        partial_payload = None
        _elapsed = max(0.0, time.monotonic() - direct_addr_started_at)
        direct_timeout_stage = _direct_timeout_failure_stage_from_payload(payload, default="decompilation")
    else:
        direct_timeout_stage = (
            _direct_timeout_failure_stage_from_payload(
                payload,
                default="decompilation",
            )
            if status == "timeout"
            else None
        )
    direct_item = FunctionWorkItem(index=1, function_cfg=cfg, function=func)
    direct_result = FunctionWorkResult(
        index=1,
        status=status,
        payload=payload,
        debug_output=direct_debug_output,
        function=func,
        function_cfg=cfg,
        partial_payload=partial_payload,
        failure_stage=direct_timeout_stage,
        tail_validation=direct_tail_validation_snapshot
        or _tail_validation_snapshot_for_function_run(direct_project, func),
        elapsed=_elapsed,
        block_count=_block_count,
        byte_count=_byte_count,
        segment_program_function_evidence=direct_segment_program_evidence,
    )
    direct_acceptance = _validated_generated_c_acceptance_8616(
        status=direct_result.status,
        payload=direct_result.payload,
        tail_validation_snapshot=direct_result.tail_validation,
        tail_validation_enabled=_tail_validation_runtime_enabled(direct_project),
        expected_validation_stages=["structuring", "postprocess"],
        c_target=getattr(direct_project, "_inertia_c_target", "portable-flat"),
        emit_failure_diagnostics=_env_truthy_8616("INERTIA_DUMP_VALIDATION_FAILED_PAYLOAD"),
    )
    direct_status = direct_acceptance.status
    direct_blocker = direct_acceptance.blocker

    def _preserve_best_failure_candidate(result: FunctionWorkResult) -> str | None:
        candidates = [
            text for text in (result.payload, result.partial_payload) if isinstance(text, str) and text.strip()
        ]
        if not candidates:
            return None

        def _rank(text: str) -> tuple[int, int]:
            quality = assess_decompiled_c_text(text)
            quality_violations = len(quality.markers) if quality.reject_as_decompiled else 0
            return (
                -quality_violations,
                len(text),
            )

        return max(candidates, key=_rank)

    def _preserve_acceptance_candidate_or_best_failure(
        acceptance: CAcceptanceResult8616,
        result: FunctionWorkResult,
    ) -> str | None:
        if acceptance.status == "ok" and acceptance.blocker is None:
            checked_payload = acceptance.gcc_checked_payload
            if checked_payload.strip():
                return checked_payload
            if acceptance.validated_payload.strip():
                return acceptance.validated_payload
        return _preserve_best_failure_candidate(result)

    if direct_status != direct_result.status or direct_blocker is not None:
        preserved_candidate = _preserve_acceptance_candidate_or_best_failure(direct_acceptance, direct_result)
        direct_payload = direct_acceptance.gcc_checked_payload
    else:
        direct_payload = (
            direct_acceptance.gcc_checked_payload
            if direct_status is WorkItemStatus.OK
            else direct_result.payload
        )
        preserved_candidate = direct_result.partial_payload
    direct_result = replace(
        direct_result,
        status=direct_status,
        payload=direct_blocker if direct_blocker is not None else direct_payload,
        partial_payload=preserved_candidate if direct_blocker is not None else direct_result.partial_payload,
        validated_payload_hash=(direct_acceptance.validated_payload_hash if direct_blocker is None else None),
        gcc_checked_payload_hash=(direct_acceptance.gcc_checked_payload_hash if direct_blocker is None else None),
    )
    if direct_status == "validation_failed" and isinstance(direct_result.tail_validation, dict):
        typing.cast(typing.Any, direct_project)._inertia_forced_tail_validation_snapshot = dict(direct_result.tail_validation)
    if direct_result.status in {"empty", "validation_failed"}:
        evidence_payload, evidence_snapshot = _recover_binary_evidence_c_8616(direct_project, func)
        if isinstance(evidence_payload, str) and evidence_payload.strip() and isinstance(evidence_snapshot, dict):
            evidence_acceptance = _validated_generated_c_acceptance_8616(
                status="ok",
                payload=evidence_payload,
                tail_validation_snapshot=evidence_snapshot,
                tail_validation_enabled=_tail_validation_runtime_enabled(direct_project),
                expected_validation_stages=["structuring", "postprocess"],
                c_target=getattr(direct_project, "_inertia_c_target", "portable-flat"),
                emit_failure_diagnostics=False,
            )
            if evidence_acceptance.status == "ok" and evidence_acceptance.blocker is None:
                direct_result = replace(
                    direct_result,
                    status="ok",
                    payload=evidence_acceptance.gcc_checked_payload,
                    partial_payload=None,
                    tail_validation=evidence_snapshot,
                    validated_payload_hash=evidence_acceptance.validated_payload_hash,
                    gcc_checked_payload_hash=evidence_acceptance.gcc_checked_payload_hash,
                )
    if (
        direct_result.status == "empty"
        and isinstance(direct_result.partial_payload, str)
        and direct_result.partial_payload.strip()
    ):
        partial_acceptance = _validated_generated_c_acceptance_8616(
            status="ok",
            payload=direct_result.partial_payload,
            tail_validation_snapshot=direct_result.tail_validation,
            tail_validation_enabled=_tail_validation_runtime_enabled(direct_project),
            expected_validation_stages=["structuring", "postprocess"],
            c_target=getattr(direct_project, "_inertia_c_target", "portable-flat"),
            emit_failure_diagnostics=False,
        )
        if partial_acceptance.status == "ok" and partial_acceptance.blocker is None:
            direct_result = replace(
                direct_result,
                status="ok",
                payload=partial_acceptance.gcc_checked_payload,
                partial_payload=None,
                validated_payload_hash=partial_acceptance.validated_payload_hash,
                gcc_checked_payload_hash=partial_acceptance.gcc_checked_payload_hash,
            )
    if (
        canonical_direct_addr is not None
        and canonical_direct_addr.requested_addr != canonical_direct_addr.canonical_addr
        and not args.ignore_local_sidecar_hints
        and _work_item_status_8616(direct_result.status) is WorkItemStatus.VALIDATION_FAILED
    ):
        assert lst_metadata is not None
        return _run_canonicalized_direct_clean_worker_8616(
            project,
            args,
            lst_metadata,
            canonical_direct_addr,
            function_label=function_label,
            caller_return_evidence_by_addr=clean_worker_caller_return_evidence_by_addr,
        )
    if direct_result.status != "ok":
        helper_model = (
            _try_emit_known_runtime_helper_c(name=getattr(func, "name", ""))
            if isinstance(getattr(func, "name", None), str)
            else None
        )
        if isinstance(helper_model, str):
            helper_snapshot = {
                "structuring": {
                    "status": "stable",
                    "mode": "helper_model",
                    "changed": False,
                    "detail": f"known compiler/runtime helper model: {getattr(func, 'name', 'sub')}",
                },
                "postprocess": {
                    "status": "stable",
                    "mode": "helper_model",
                    "changed": False,
                    "detail": f"known compiler/runtime helper model: {getattr(func, 'name', 'sub')}",
                },
            }
            helper_tail_validation_snapshot: dict[str, object] = dict(helper_snapshot)
            helper_acceptance = _validated_generated_c_acceptance_8616(
                status="ok",
                payload=helper_model,
                tail_validation_snapshot=helper_tail_validation_snapshot,
                tail_validation_enabled=_tail_validation_runtime_enabled(direct_project),
                expected_validation_stages=["structuring", "postprocess"],
                c_target=getattr(direct_project, "_inertia_c_target", "portable-flat"),
                emit_failure_diagnostics=False,
            )
            helper_status = helper_acceptance.status
            helper_blocker = helper_acceptance.blocker
            helper_payload = helper_acceptance.gcc_checked_payload
            if helper_status == "ok" and helper_blocker is None:
                direct_result = replace(
                    direct_result,
                    status=helper_status,
                    payload=helper_payload,
                    partial_payload=None,
                    tail_validation=helper_tail_validation_snapshot,
                    validated_payload_hash=helper_acceptance.validated_payload_hash,
                    gcc_checked_payload_hash=helper_acceptance.gcc_checked_payload_hash,
                )
    if os.environ.get(_SERIAL_CLEAN_WORKER_RESULT_ENV_8616):
        direct_result = replace(direct_result, failure_family_snapshot=_direct_failure_snapshot(direct_result))
        if _complete_serial_clean_worker_result_8616(direct_result, project=direct_project):
            return 0
    direct_timeout_payload = direct_result.payload
    _direct_blocks_for_timeout_guard, _direct_bytes_for_timeout_guard = _function_complexity(func)
    clinic_core_timeout = isinstance(direct_timeout_payload, str) and (
        "core:clinic:" in direct_timeout_payload
        or "timed out after" in direct_timeout_payload.lower()
        or (
            direct_result.status == "empty"
            and getattr(project.arch, "name", "") == "86_16"
            and (_direct_blocks_for_timeout_guard >= 32 or _direct_bytes_for_timeout_guard >= 280)
            and "decompiler did not produce code" in direct_timeout_payload.lower()
        )
    )
    if (
        direct_result.status != "ok"
        and not clinic_core_timeout
        and _direct_addr_robust_retry_enabled_8616(timeout_was_explicit=timeout_was_explicit)
    ):
        # Robust direct-address retry lane: reuse the same function-work
        # decompile path as whole-file sweeps. This avoids direct-only
        # recovery/decompile divergence for functions that are stable in
        # the sweep lane but brittle in the thin direct lane.
        try:
            robust_blocks, robust_bytes = _function_complexity(func)
            robust_timeout = _effective_decompile_timeout_8616(
                direct_project,
                args.timeout,
                block_count=robust_blocks,
                byte_count=robust_bytes,
            )
            robust_item = FunctionWorkItem(index=1, function_cfg=cfg, function=func)
            robust_result = _run_function_work_item(
                robust_item,
                timeout=max(1, int(robust_timeout)),
                api_style=args.api_style,
                binary_path=args.binary,
                lst_metadata=lst_metadata,
                cod_metadata=cod_metadata,
                synthetic_globals=synthetic_globals,
                enable_structured_simplify=True,
                enable_postprocess=True,
                allow_isolated_retry=True,
            )
        except Exception:
            robust_result = None
        if robust_result is not None and robust_result.status == "ok":
            robust_snapshot = _tail_validation_snapshot_for_function_run(direct_project, func)
            if not robust_snapshot and isinstance(robust_result.tail_validation, dict):
                robust_snapshot = robust_result.tail_validation
            robust_tail_validation_snapshot = robust_snapshot if robust_snapshot else None
            robust_acceptance = _validated_generated_c_acceptance_8616(
                status="ok",
                payload=robust_result.payload,
                tail_validation_snapshot=robust_tail_validation_snapshot,
                tail_validation_enabled=_tail_validation_runtime_enabled(direct_project),
                expected_validation_stages=["structuring", "postprocess"],
                c_target=getattr(direct_project, "_inertia_c_target", "portable-flat"),
                emit_failure_diagnostics=False,
            )
            if robust_acceptance.status == "ok" and robust_acceptance.blocker is None:
                direct_result = replace(
                    robust_result,
                    index=1,
                    function=func,
                    function_cfg=cfg,
                    payload=robust_acceptance.gcc_checked_payload,
                    tail_validation=robust_snapshot,
                    validated_payload_hash=robust_acceptance.validated_payload_hash,
                    gcc_checked_payload_hash=robust_acceptance.gcc_checked_payload_hash,
                )
    direct_failure_family_snapshot = _direct_failure_snapshot(direct_result)
    budget_fallback_addr = function_original_addr(func)
    budget_fallback_name = func.name
    direct_result = replace(direct_result, failure_family_snapshot=direct_failure_family_snapshot)
    if direct_result.debug_output:
        print(direct_result.debug_output, file=sys.stderr, end="")
    print(f"[dbg] direct failure family: {direct_failure_family_snapshot.label()}", file=sys.stderr)
    if direct_result.status == "error":
        _print_stop_on_first_failure_8616(func, direct_result)
        return 6
    if direct_result.status == "timeout":
        _emit_tail_validation_snapshot_or_uncollected(
            cfg,
            func,
            direct_result.tail_validation,
            binary_path=args.binary,
        )
        print(f"[dbg] direct decompilation timeout detail: {direct_result.payload}", file=sys.stderr)
        print(f"\n/* Decompilation timeout: Timed out while recovering a function after {args.timeout}s during x86-16 function recovery. */")
        print("/* Direct decompilation timeout is terminal for this function; skipping fallback lanes. */\n/* Tip: try a larger --timeout for larger binaries. */")
        return 3
    if direct_result.status != "ok":

        def _candidate_text_for_rank(result: FunctionWorkResult) -> str:
            payload_text = result.payload if isinstance(result.payload, str) and result.payload.strip() else ""
            partial_text = (
                result.partial_payload
                if isinstance(result.partial_payload, str) and result.partial_payload.strip()
                else ""
            )
            if payload_text and not partial_text:
                return payload_text
            if partial_text and not payload_text:
                return partial_text
            if not payload_text and not partial_text:
                return ""

            def _text_rank(text: str) -> tuple[int, int, int]:
                quality = assess_decompiled_c_text(text)
                quality_violations = len(quality.markers) if quality.reject_as_decompiled else 0
                present_calls = _non_probe_call_count_for_fallback_rank_8616(text)
                return (
                    -quality_violations,
                    present_calls,
                    len(text),
                )

            return payload_text if _text_rank(payload_text) >= _text_rank(partial_text) else partial_text

        def _candidate_rank(result: FunctionWorkResult) -> tuple[int, int, int]:
            text = _candidate_text_for_rank(result)
            quality = assess_decompiled_c_text(text)
            quality_violations = len(quality.markers) if quality.reject_as_decompiled else 0
            present_calls = _non_probe_call_count_for_fallback_rank_8616(text)
            return (
                -quality_violations,
                present_calls,
                len(text),
            )

        # Repeated direct runs can land on different internal lanes. Keep
        # the least raw/unresolved candidate before heavy fallback fan-out.
        if direct_result.status == "validation_failed":
            best_direct_candidate = direct_result
            best_direct_rank = _candidate_rank(direct_result)
            retry_count = _direct_addr_validation_retry_count_8616(
                timeout_was_explicit=timeout_was_explicit,
                args_timeout=args.timeout,
            )
            for retry_idx in range(retry_count):
                try:
                    retry_status, retry_payload, retry_partial, *retry_extra = _run_with_timeout_in_daemon_thread(
                        direct_decompile_job,
                        timeout=max(1, min(args.timeout, 8)),
                        thread_name_prefix=f"direct-decomp-retry-{retry_idx + 1}",
                    )
                    retry_tail_validation = None
                    for extra in retry_extra:
                        if isinstance(extra, dict):
                            retry_tail_validation = dict(extra)
                    retry_result = FunctionWorkResult(
                        index=1,
                        status=retry_status,
                        payload=retry_payload,
                        debug_output="",
                        function=func,
                        function_cfg=cfg,
                        partial_payload=retry_partial,
                        tail_validation=retry_tail_validation
                        or _tail_validation_snapshot_for_function_run(direct_project, func),
                    )
                    retry_acceptance = _validated_generated_c_acceptance_8616(
                        status=retry_result.status,
                        payload=retry_result.payload,
                        tail_validation_snapshot=retry_result.tail_validation,
                        tail_validation_enabled=_tail_validation_runtime_enabled(direct_project),
                        expected_validation_stages=["structuring", "postprocess"],
                        c_target=getattr(direct_project, "_inertia_c_target", "portable-flat"),
                        emit_failure_diagnostics=False,
                    )
                    retry_checked_status = retry_acceptance.status
                    retry_blocker = retry_acceptance.blocker
                    if retry_checked_status != retry_result.status or retry_blocker is not None:
                        retry_preserved_candidate = _preserve_acceptance_candidate_or_best_failure(
                            retry_acceptance,
                            retry_result,
                        )
                        retry_result = replace(
                            retry_result,
                            status=retry_checked_status,
                            payload=retry_blocker if retry_blocker is not None else retry_result.payload,
                            partial_payload=retry_preserved_candidate
                            if retry_blocker is not None
                            else retry_result.partial_payload,
                        )
                    else:
                        retry_result = replace(
                            retry_result,
                            payload=retry_acceptance.gcc_checked_payload,
                            validated_payload_hash=retry_acceptance.validated_payload_hash,
                            gcc_checked_payload_hash=retry_acceptance.gcc_checked_payload_hash,
                        )
                    retry_rank = _candidate_rank(retry_result)
                    if retry_result.status == "ok":
                        direct_result = retry_result
                        best_direct_candidate = retry_result
                        best_direct_rank = retry_rank
                        break
                    if retry_rank > best_direct_rank:
                        best_direct_candidate = retry_result
                        best_direct_rank = retry_rank
                except Exception:
                    continue
            if direct_result.status != "ok":
                current_rank = _candidate_rank(direct_result)
                if best_direct_rank > current_rank:
                    direct_result = best_direct_candidate

        _enforce_direct_addr_budget_timeout(recovery_detail="after exhausting direct-address decompilation budget")
        direct_display_addr = function_original_addr(func)
        using_rebased_direct_slice = direct_project is not project
        direct_project_fallback_addr = _direct_addr_project_local_fallback_addr_8616(
            function=func,
            direct_display_addr=direct_display_addr,
            using_rebased_direct_slice=using_rebased_direct_slice,
        )
        slice_result = None
        sidecar_closed_nonopt = False
        known_nonopt_result: NonOptimizedSliceOutcome | str | None = None
        reserve_budget_for_rebased_sidecar = (
            using_rebased_direct_slice and precise_sidecar_regions and direct_result.status == "validation_failed"
        )
        skip_heavy_validation_fallbacks = _direct_addr_should_skip_heavy_validation_fallbacks_8616(
            timeout_was_explicit=timeout_was_explicit,
            args_timeout=args.timeout,
            direct_status=direct_result.status,
            partial_payload=direct_result.partial_payload,
        )
        # Cap heavy fallback fan-out per function to keep direct-addr mode
        # deterministic and prevent minute-long retry storms.
        if fast_direct_probe or skip_heavy_validation_fallbacks:
            heavy_fallback_budget = 0
        elif timeout_was_explicit and isinstance(args.timeout, int):
            heavy_fallback_budget = 1
        else:
            heavy_fallback_budget = 2 if direct_result.status == "validation_failed" else 4

        def _consume_heavy_fallback_budget() -> bool:
            nonlocal heavy_fallback_budget
            if heavy_fallback_budget <= 0:
                return False
            heavy_fallback_budget -= 1
            return True

        def _current_direct_partial_payload() -> str | None:
            candidate = direct_result.partial_payload
            return candidate if isinstance(candidate, str) and candidate.strip() else None

        def _accept_direct_fallback_payload(
            payload_text: str,
            *,
            tail_validation_snapshot: dict[str, object] | None = None,
        ) -> str | None:
            payload_for_acceptance = payload_text
            snapshot = dict(tail_validation_snapshot) if isinstance(tail_validation_snapshot, dict) else None
            for attr_name in (
                "_inertia_partial_tail_validation_snapshot",
                "_inertia_last_tail_validation_snapshot",
            ):
                if snapshot is not None:
                    break
                attr_value = getattr(direct_project, attr_name, None)
                if isinstance(attr_value, dict):
                    snapshot = dict(attr_value)
                    break
            if snapshot is None:
                snapshot = _tail_validation_snapshot_for_function_run(direct_project, func)
            checked_acceptance = _validated_generated_c_acceptance_8616(
                status="ok",
                payload=payload_for_acceptance,
                tail_validation_snapshot=snapshot,
                tail_validation_enabled=_tail_validation_runtime_enabled(direct_project),
                expected_validation_stages=["structuring", "postprocess"],
                c_target=getattr(direct_project, "_inertia_c_target", "portable-flat"),
                emit_failure_diagnostics=False,
            )
            checked_status = checked_acceptance.status
            checked_blocker = checked_acceptance.blocker
            if checked_status == "ok":
                print("[dbg] direct fallback validation=passed", file=sys.stderr)
                return checked_acceptance.gcc_checked_payload or payload_for_acceptance
            _dump_validation_failed_payload_if_requested_8616(
                payload_for_acceptance,
                prefix=f"fallback_{func.addr:x}_{func.name}",
            )
            print(
                f"[dbg] rejected direct fallback payload: {checked_status} detail={checked_blocker or 'n/a'}",
                file=sys.stderr,
                flush=True,
            )
            return None

        exact_retry_blocked = (
            direct_failure_family_state.repeat_detected and not direct_failure_family_state.new_proof_seen
        )
        if direct_result.status == "empty":
            partial_payload_text = (
                direct_result.partial_payload if isinstance(direct_result.partial_payload, str) else None
            )
            if isinstance(partial_payload_text, str) and partial_payload_text.strip():
                snapshot = direct_result.tail_validation
                checked_acceptance = _validated_generated_c_acceptance_8616(
                    status="ok",
                    payload=partial_payload_text,
                    tail_validation_snapshot=snapshot,
                    tail_validation_enabled=_tail_validation_runtime_enabled(direct_project),
                    expected_validation_stages=["structuring", "postprocess"],
                    c_target=getattr(direct_project, "_inertia_c_target", "portable-flat"),
                    emit_failure_diagnostics=False,
                )
                checked_status = checked_acceptance.status
                checked_blocker = checked_acceptance.blocker
                if checked_status == "ok" and checked_blocker is None:
                    direct_result = replace(
                        direct_result,
                        status="ok",
                        payload=checked_acceptance.gcc_checked_payload,
                        partial_payload=None,
                        validated_payload_hash=checked_acceptance.validated_payload_hash,
                        gcc_checked_payload_hash=checked_acceptance.gcc_checked_payload_hash,
                    )
                else:
                    _dump_validation_failed_payload_if_requested_8616(
                        partial_payload_text,
                        prefix=f"direct_partial_{func.addr:x}_{func.name}",
                    )
                    print(
                        f"[dbg] rejected direct partial payload: {checked_status} detail={checked_blocker or 'n/a'}",
                        file=sys.stderr,
                        flush=True,
                    )
                    direct_result = replace(direct_result, partial_payload=None)
            # Allow one non-optimized known-function lane even when the
            # optimized lane repeats an "empty" family; this is often a
            # recoverable clinic/core failure class for helper routines.
            exact_retry_blocked = False
        if (
            not fast_direct_probe
            and direct_result.status != "ok"
            and precise_sidecar_regions
            and lst_metadata is not None
            and not (
                timeout_was_explicit
                and isinstance(args.timeout, int)
                and args.timeout <= 6
                and direct_result.status == "timeout"
            )
        ):
            sidecar_region = _lst_code_region(lst_metadata, direct_display_addr)
            direct_sidecar_verdict = "attempted"
            if sidecar_region is not None:
                try:
                    sidecar_addr = sidecar_region[0]
                    code_name = _lst_code_label(lst_metadata, sidecar_addr, project.entry) or func.name
                    side_cfg, side_func = _recover_lst_function(
                        project,
                        lst_metadata,
                        sidecar_addr if lst_metadata.absolute_addrs else sidecar_addr - project.entry,
                        code_name,
                        timeout=max(2, min(args.timeout, 8)),
                        window=args.window,
                        low_memory=low_memory_path,
                        allow_rebased_exact_slice=False,
                    )
                    # Dynamic angr boundary: exact recovery may return a function owned by a slice project.
                    side_project = getattr(side_func, "project", project)
                    if not isinstance(side_project, angr.Project):
                        side_project = project
                    _transfer_caller_return_use_evidence_8616(project, side_project)
                    with span(
                        "direct.sidecar_retry",
                        addr=hex(sidecar_addr),
                        name=code_name,
                        timeout=max(2, min(args.timeout, 8)),
                    ):
                        side_tail_from_decompile = None
                        side_status, side_payload, *_ = _decompile_function_with_stats(
                            side_project,
                            side_cfg,
                            side_func,
                            max(2, min(args.timeout, 8)),
                            args.api_style,
                            args.binary,
                            cod_metadata=cod_metadata,
                            synthetic_globals=synthetic_globals,
                            lst_metadata=lst_metadata,
                            allow_isolated_retry=False,
                            failure_family_state=direct_failure_family_state,
                        )
                        side_tail_candidate = getattr(
                            side_project,
                            "_inertia_last_validated_function_payload_snapshot",
                            None,
                        )
                        function_tail_candidate = _retry_function_tail_validation_snapshot_8616(
                            side_project,
                            side_func,
                        )
                        if function_tail_candidate:
                            side_tail_candidate = function_tail_candidate
                        if not isinstance(side_tail_candidate, dict):
                            side_tail_candidate = getattr(
                                side_project,
                                "_inertia_last_tail_validation_snapshot",
                                None,
                            )
                        if isinstance(side_tail_candidate, dict):
                            side_tail_from_decompile = dict(side_tail_candidate)
                        annotate_current_span(status=side_status)
                    direct_sidecar_verdict = side_status
                    if side_status == "ok":
                        side_tail = (
                            side_tail_from_decompile
                            if isinstance(side_tail_from_decompile, dict)
                            else _retry_function_tail_validation_snapshot_8616(side_project, side_func)
                        )
                        _emit_tail_validation_snapshot_or_uncollected(
                            side_cfg,
                            side_func,
                            side_tail,
                            binary_path=args.binary,
                        )
                        side_acceptance = _validated_generated_c_acceptance_8616(
                            status=side_status,
                            payload=side_payload,
                            tail_validation_snapshot=side_tail,
                            tail_validation_enabled=_tail_validation_runtime_enabled(side_project),
                            expected_validation_stages=["structuring", "postprocess"],
                            c_target=getattr(side_project, "_inertia_c_target", "portable-flat"),
                        )
                        side_status_checked = side_acceptance.status
                        side_payload_checked = side_acceptance.gcc_checked_payload
                        if side_status_checked != "ok":
                            side_status = side_status_checked
                    if side_status == "ok":
                        accepted_side_payload = (
                            side_payload_checked if isinstance(side_payload_checked, str) else side_payload
                        )
                        print("[dbg] direct sidecar fallback validation=passed", file=sys.stderr)
                        _emit_optional_source_sidecar_c_block(
                            args.binary,
                            side_func.name,
                            accepted_side_payload,
                            alternate_source_c=bool(args.alternate_source_c),
                            c_header="\n/* == c (sidecar slice fallback) == */",
                        )
                        return 0
                except (_AnalysisTimeout, Exception):
                    direct_sidecar_verdict = "error"
            _early_slice = _try_decompile_sidecar_slice(
                project,
                lst_metadata,
                direct_display_addr,
                func.name,
                timeout=max(2, min(8, args.timeout) if isinstance(args.timeout, int) else 8),
                api_style=args.api_style,
                binary_path=args.binary,
                failure_family_state=direct_failure_family_state,
            )
            if _early_slice is not None:
                direct_sidecar_verdict = _early_slice.status
            if _early_slice is not None and _early_slice.status == "ok":
                _emit_sidecar_slice_tail_validation_snapshot_8616(
                    cfg,
                    func,
                    _early_slice.snapshot,
                    binary_path=args.binary,
                )
                accepted_payload = _accept_direct_fallback_payload(
                    _early_slice.payload,
                    tail_validation_snapshot=_early_slice.snapshot,
                )
                if accepted_payload is not None:
                    _emit_optional_source_sidecar_c_block(
                        args.binary,
                        func.name,
                        accepted_payload,
                        alternate_source_c=bool(args.alternate_source_c),
                        c_header="\n/* == c (sidecar slice fallback) == */",
                    )
                    return 0
        allow_known_nonopt = (not exact_retry_blocked) or (direct_result.status in {"timeout", "validation_failed"})
        if fast_direct_probe:
            allow_known_nonopt = False
        if (
            timeout_was_explicit
            and isinstance(args.timeout, int)
            and args.timeout > 6
            and direct_result.status == "timeout"
        ):
            allow_known_nonopt = False
        if _current_direct_partial_payload() is None:
            if allow_known_nonopt and not _consume_heavy_fallback_budget():
                allow_known_nonopt = False
            if allow_known_nonopt:
                _enforce_direct_addr_budget_timeout(recovery_detail="after exhausting direct-address fallback budget")
                known_nonopt_result = _try_decompile_non_optimized_known_function(
                    direct_project,
                    cfg,
                    func,
                    timeout=max(
                        1,
                        min(_bounded_non_optimized_timeout(args.timeout), _remaining_direct_addr_budget() or 1),
                    ),
                    api_style=args.api_style,
                    binary_path=args.binary,
                    lst_metadata=None if using_rebased_direct_slice else lst_metadata,
                    cod_metadata=cod_metadata,
                    synthetic_globals=synthetic_globals,
                    failure_family_state=direct_failure_family_state,
                )
                if known_nonopt_result is not None:
                    direct_nonoptimized_verdict = (
                        known_nonopt_result.status
                        if isinstance(known_nonopt_result, NonOptimizedSliceOutcome)
                        else "ok"
                    )
        known_nonopt_c = _non_optimized_slice_rendered(known_nonopt_result)
        if known_nonopt_c is not None:
            fallback_snapshot = _tail_validation_snapshot_for_fallback(
                direct_project,
                func,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
            )
            _emit_tail_validation_snapshot_or_uncollected(
                cfg,
                func,
                fallback_snapshot,
                binary_path=args.binary,
            )
            accepted_payload = _accept_direct_fallback_payload(
                known_nonopt_c,
                tail_validation_snapshot=fallback_snapshot,
            )
            if accepted_payload is not None:
                print(f"\n/* Decompilation {direct_result.status}: {direct_result.payload} */")
                print("/* Falling back to known-function non-optimized decompilation. */")
                _emit_optional_source_sidecar_c_block(
                    args.binary,
                    func.name,
                    accepted_payload,
                    alternate_source_c=bool(args.alternate_source_c),
                    c_header="\n/* == c (non-optimized fallback) == */",
                )
                return 0
        _enforce_direct_addr_budget_timeout(recovery_detail="after exhausting direct-address fallback budget")
        generic_nonopt_result = None
        if not reserve_budget_for_rebased_sidecar and _consume_heavy_fallback_budget():
            generic_nonopt_result = _try_decompile_non_optimized_slice(
                direct_project,
                direct_project_fallback_addr,
                func.name,
                timeout=max(1, min(_bounded_non_optimized_timeout(args.timeout), _remaining_direct_addr_budget() or 1)),
                api_style=args.api_style,
                binary_path=args.binary,
                lst_metadata=None if using_rebased_direct_slice else lst_metadata,
                cod_metadata=cod_metadata,
                allow_fresh_project_retry=False,
                failure_family_state=direct_failure_family_state,
                original_addr=direct_display_addr,
            )
            if generic_nonopt_result is not None:
                direct_nonoptimized_verdict = (
                    generic_nonopt_result.status
                    if isinstance(generic_nonopt_result, NonOptimizedSliceOutcome)
                    else "ok"
                )
        generic_nonopt_c = _non_optimized_slice_rendered(generic_nonopt_result)
        if generic_nonopt_c is not None:
            fallback_snapshot = _tail_validation_snapshot_for_fallback(
                direct_project,
                func,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
            )
            _emit_tail_validation_snapshot_or_uncollected(
                cfg,
                func,
                fallback_snapshot,
                binary_path=args.binary,
            )
            accepted_payload = _accept_direct_fallback_payload(
                generic_nonopt_c,
                tail_validation_snapshot=fallback_snapshot,
            )
            if accepted_payload is not None:
                print(f"\n/* Decompilation {direct_result.status}: {direct_result.payload} */")
                print("/* Falling back to non-optimized slice decompilation. */")
                _emit_optional_source_sidecar_c_block(
                    args.binary,
                    func.name,
                    accepted_payload,
                    alternate_source_c=bool(args.alternate_source_c),
                    c_header="\n/* == c (non-optimized fallback) == */",
                )
                return 0
        exact_retry_blocked = (
            direct_failure_family_state.repeat_detected and not direct_failure_family_state.new_proof_seen
        )
        if direct_result.status == "validation_failed":
            # Validation-failed direct lane is frequently under-recovered
            # semantics. Allow exact sidecar retry even when the failure
            # family repeats so richer bounded slices can be considered.
            exact_retry_blocked = False
        if not fast_direct_probe and precise_sidecar_regions:  # noqa: SIM102
            if not exact_retry_blocked:
                _dbg_region = _lst_code_region(lst_metadata, direct_display_addr) if lst_metadata is not None else None
                print(
                    f"[dbg] sidecar slice gate: precise={precise_sidecar_regions} rebased={using_rebased_direct_slice} blocked={exact_retry_blocked} addr={direct_display_addr:#x} region={_dbg_region}",
                    file=sys.stderr,
                    flush=True,
                )
                _enforce_direct_addr_budget_timeout(recovery_detail="after exhausting direct-address fallback budget")
                sidecar_attempted = False
                if _consume_heavy_fallback_budget():
                    sidecar_attempted = True
                    slice_result = _try_decompile_sidecar_slice(
                        project,
                        lst_metadata,
                        direct_display_addr,
                        func.name,
                        timeout=max(1, min(args.timeout, _remaining_direct_addr_budget() or 1)),
                        api_style=args.api_style,
                        binary_path=args.binary,
                        failure_family_state=direct_failure_family_state,
                    )
                if slice_result is not None:
                    direct_sidecar_verdict = slice_result.status
                if sidecar_attempted and slice_result is None:
                    print("[dbg] sidecar slice attempt returned None", file=sys.stderr, flush=True)
        if slice_result is not None:
            if slice_result.status != "ok":
                print(
                    f"[dbg] sidecar slice attempt status={slice_result.status} payload={slice_result.payload}",
                    file=sys.stderr,
                    flush=True,
                )
                sidecar_closed_nonopt = sidecar_verdict_closes_non_optimized_lane(slice_result.verdict)
                slice_result = None
            else:
                _emit_sidecar_slice_tail_validation_snapshot_8616(
                    cfg,
                    func,
                    slice_result.snapshot,
                    binary_path=args.binary,
                )
                accepted_payload = _accept_direct_fallback_payload(
                    slice_result.payload,
                    tail_validation_snapshot=slice_result.snapshot,
                )
                if accepted_payload is not None:
                    _emit_optional_source_sidecar_c_block(
                        args.binary,
                        func.name,
                        accepted_payload,
                        alternate_source_c=bool(args.alternate_source_c),
                        c_header="\n/* == c (sidecar slice fallback) == */",
                    )
                    return 0
        trivial_c = _try_emit_trivial_sidecar_c(project, lst_metadata, direct_display_addr, func.name)
        if trivial_c is not None:
            _emit_tail_validation_for_function_run_or_uncollected(
                direct_project,
                cfg,
                func,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("trivial_sidecar"),
                binary_path=args.binary,
            )
            _emit_optional_source_sidecar_c_block(
                args.binary,
                func.name,
                trivial_c,
                alternate_source_c=bool(args.alternate_source_c),
                c_header="\n/* == c (trivial sidecar fallback) == */",
            )
            return 0
        nonopt_result = None
        if (
            partial_payload is None
            and known_nonopt_c is None
            and (precise_sidecar_regions or using_rebased_direct_slice)
            and not sidecar_closed_nonopt
            and not (direct_failure_family_state.repeat_detected and not direct_failure_family_state.new_proof_seen)
            and _consume_heavy_fallback_budget()
        ):
            _enforce_direct_addr_budget_timeout(recovery_detail="after exhausting direct-address fallback budget")
            nonopt_result = _try_decompile_non_optimized_slice(
                direct_project if using_rebased_direct_slice else project,
                direct_project_fallback_addr,
                func.name,
                timeout=max(1, min(_bounded_non_optimized_timeout(args.timeout), _remaining_direct_addr_budget() or 1)),
                api_style=args.api_style,
                binary_path=args.binary,
                lst_metadata=None if using_rebased_direct_slice else lst_metadata,
                cod_metadata=cod_metadata,
                allow_fresh_project_retry=False,
                failure_family_state=direct_failure_family_state,
                original_addr=direct_display_addr,
            )
        nonopt_c = _non_optimized_slice_rendered(nonopt_result)
        if nonopt_c is not None:
            fallback_snapshot = _tail_validation_snapshot_for_fallback(
                direct_project,
                func,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("non_optimized"),
            )
            _emit_tail_validation_snapshot_or_uncollected(
                cfg,
                func,
                fallback_snapshot,
                binary_path=args.binary,
            )
            accepted_payload = _accept_direct_fallback_payload(
                nonopt_c,
                tail_validation_snapshot=fallback_snapshot,
            )
            if accepted_payload is not None:
                print(f"\n/* Decompilation {direct_result.status}: {direct_result.payload} */")
                print("/* Falling back to non-optimized slice decompilation. */")
                _emit_optional_source_sidecar_c_block(
                    args.binary,
                    func.name,
                    accepted_payload,
                    alternate_source_c=bool(args.alternate_source_c),
                    c_header="\n/* == c (non-optimized fallback) == */",
                )
                return 0
        current_partial_payload = _current_direct_partial_payload()
        if current_partial_payload is not None:
            _emit_tail_validation_snapshot_or_uncollected(
                cfg,
                func,
                direct_result.tail_validation,
                binary_path=args.binary,
            )
            partial_report = _partial_result_report_8616(direct_result.status)
            payload_detail = direct_result.payload
            if partial_report.status is WorkItemStatus.TIMEOUT:
                timeout_text = "timeout"
                if isinstance(direct_result.payload, str):
                    m = re.search(r"Timed out after (\d+)s", direct_result.payload)
                    if m is not None:
                        timeout_text = f"Timed out after {m.group(1)}s."
                payload_detail = (
                    timeout_text if timeout_text != "timeout" else f"Timed out after {args.timeout}s."
                )
            print(f"/* {partial_report.heading}: {payload_detail} */")
            if partial_report.show_timeout_delay:
                direct_elapsed = direct_result.elapsed
                if isinstance(direct_elapsed, (int, float)):
                    print(f"/* timeout delay: {float(direct_elapsed):.2f}s */")
            if partial_report.status is WorkItemStatus.VALIDATION_FAILED:
                print("/* direct validation=failed */")
            _emit_failed_timeout_acceptance_hints_8616()
            print(f"/* non-optimized fallback failed: {partial_report.fallback_detail} */")
            if "&sp_0" in current_partial_payload:
                print("/* Source-evidenced loop call was hoisted outside loop in emitted C. */")
            _emit_optional_source_sidecar_c_block(
                args.binary,
                func.name,
                current_partial_payload,
                alternate_source_c=bool(args.alternate_source_c),
                c_header=partial_report.direct_c_header,
            )
            return 6 if direct_result.status == "error" else 4
        sidecar_region = None
        if lst_metadata is not None and not using_rebased_direct_slice:
            sidecar_region = _lst_code_region(lst_metadata, direct_display_addr)
        linear_window = (
            None if sidecar_region is not None else _infer_linear_disassembly_window(direct_project, func.addr)
        )
        if sidecar_region is None and linear_window is None:
            linear_window = _infer_linear_disassembly_window(direct_project, func.addr)
        if sidecar_region is not None:
            string_start, string_end = sidecar_region
        else:
            assert linear_window is not None
            string_start, string_end = linear_window
        string_c = _try_emit_string_intrinsic_c(
            direct_project,
            start=string_start,
            end=string_end,
            name=func.name,
        )
        if string_c is not None:
            _emit_tail_validation_for_function_run_or_uncollected(
                direct_project,
                cfg,
                func,
                allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("string_intrinsic"),
                binary_path=args.binary,
            )
            print(f"\n/* Decompilation {direct_result.status}: {direct_result.payload} */")
            print("/* Falling back to generic string-intrinsic recovery. */")
            nonopt_skip_reason = describe_non_optimized_unavailable(
                allow_heavy_fallbacks=True,
                skip_heavy_fallbacks_for_result=False,
                interactive_stdout=interactive_stdout,
                max_functions=args.max_functions,
                addr_requested=direct_addr is not None,
                result_status=direct_result.status,
                failure_stage=None,
                nonopt_failure_detail=_non_optimized_slice_failure_detail(nonopt_result),
            )
            if nonopt_skip_reason is not None:
                print(f"/* non-optimized fallback unavailable: {nonopt_skip_reason} */")
            _emit_optional_source_sidecar_c_block(
                args.binary,
                func.name,
                string_c,
                alternate_source_c=bool(args.alternate_source_c),
                c_header="\n/* == c (string intrinsic fallback) == */",
            )
            return 0
        _emit_tail_validation_for_function_run_or_uncollected(
            direct_project,
            cfg,
            func,
            allow_project_fallback=_tail_validation_fallback_allows_project_snapshot("asm"),
            binary_path=args.binary,
        )
        asm_fallback = (
            _format_asm_range(project, sidecar_region[0], sidecar_region[1])
            if sidecar_region is not None
            else _format_asm_range(project, *_infer_linear_disassembly_window(project, func.addr))
        )
        print(f"\n/* Decompilation {direct_result.status}: {direct_result.payload} */")
        print("/* Falling back to non-optimized disassembly. */")
        nonopt_failure_detail = _non_optimized_slice_failure_detail(nonopt_result)
        if nonopt_failure_detail is not None:
            print(f"/* non-optimized fallback failed: {nonopt_failure_detail} */")
        for _diag_line in _format_tail_validation_diagnostic(
            direct_result.tail_validation,
            function_addr=func.addr,
            function_name=func.name,
            block_count=direct_result.block_count,
            byte_count=direct_result.byte_count,
            exit_kind=direct_result.status,
            exit_detail=direct_result.payload,
        ):
            print(_diag_line)
        print("\n/* == lift break probe == */")
        print(_probe_lift_break(project, func.addr))
        print("\n/* == asm fallback == */")
        print(asm_fallback)
        return 6 if status == "error" else 4

    integrity = verify_function_work_result_payload_integrity_8616(direct_result)
    if integrity.verdict in {
        AcceptedPayloadIntegrityVerdict8616.MISSING_VALIDATED_HASH,
        AcceptedPayloadIntegrityVerdict8616.MISSING_COMPILER_HASH,
    }:
        direct_result = _accept_function_work_result_for_emission_8616(
            direct_result,
            project=direct_project,
        )
        integrity = verify_function_work_result_payload_integrity_8616(direct_result)
    if not integrity.passed:
        print(f"[tail-validation] {integrity.diagnostic()}", file=sys.stderr, flush=True)
        return 4
    _emit_tail_validation_console_summary([direct_item], {1: direct_result}, binary_path=args.binary)
    _store_direct_request_result_8616(
        context,
        direct_request_cache_lookup,
        direct_result,
        function_addr=function_original_addr(func),
        function_name=func.name,
    )
    if args.output_c_dir is not None:
        write_generated_function_c(
            args.output_c_dir,
            address=function_original_addr(func),
            name=func.name,
            payload=direct_result.payload,
        )
    _emit_optional_source_sidecar_c_block(
        args.binary,
        func.name,
        direct_result.payload,
        alternate_source_c=bool(args.alternate_source_c),
        c_header="\n/* == c == */",
    )
    if direct_cache_key is not None and direct_result.status == "ok":
        _store_cache_json(
            "function_decompile",
            direct_cache_key,
            {
                "status": direct_result.status,
                "payload": direct_result.payload,
                "tail_validation": direct_result.tail_validation,
                "tail_validation_passed": True,
                "elapsed": direct_result.elapsed,
                "block_count": direct_result.block_count,
                "byte_count": direct_result.byte_count,
                "validated_c_hash": direct_result.validated_payload_hash,
                "gcc_checked_c_hash": direct_result.gcc_checked_payload_hash,
                "diagnostic_output": (
                    direct_result.debug_output
                    if os.environ.get("INERTIA_ENABLE_TYPED_SWITCH_AST_ARTIFACTS") == "1"
                    else None
                ),
                "failure_family_snapshot": direct_failure_family_snapshot.to_record(),
            },
        )
    _write_serial_clean_worker_result_8616(direct_result, project=direct_project)
    return 0


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
        if block_count >= 72 or byte_count >= 520:
            decompile_timeout = max(decompile_timeout, args.timeout + 120, 240)
        elif block_count >= 56 or byte_count >= 420:
            decompile_timeout = max(decompile_timeout, args.timeout + 90, 240)
        elif block_count >= 36 or byte_count >= 300:
            decompile_timeout = max(decompile_timeout, args.timeout + 60)
        if args.addr is None and not context.timeout_was_explicit and (
            block_count >= 36 or byte_count >= 300
        ):
            decompile_timeout = max(
                decompile_timeout,
                PARALLEL_CLEAN_WORKER_TIMEOUT_CAP,
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
    if (
        architecture == "86_16"
        and args.addr is None
        and not context.timeout_was_explicit
        and bounded_timeout >= 180
    ):
        return _enforce_function_timeout_cap(
            max(bounded_timeout, 240),
            context="sweep large-function finalization timeout",
            default_timeout_cap=PARALLEL_CLEAN_WORKER_TIMEOUT_CAP,
        )
    return bounded_timeout


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
    args = context.args
    project = context.project
    function_tasks = context.function_tasks
    result_map = context.result_map
    fallback_tail_validation_by_index = context.fallback_tail_validation_by_index
    lst_metadata = context.lst_metadata
    cod_metadata = context.cod_metadata
    synthetic_globals = context.synthetic_globals
    visible_code_labels = context.visible_code_labels
    low_memory_path = context.low_memory_path
    interactive_stdout = context.interactive_stdout
    precise_sidecar_regions = context.precise_sidecar_regions
    timeout_was_explicit = context.timeout_was_explicit
    use_serial_fork_per_function = context.use_serial_fork_per_function
    allow_heavy_fallbacks = context.allow_heavy_fallbacks
    _force_isolated_project_for_work_item = context.force_isolated_project_for
    _configure_recovered_work_item_project_8616 = context.configure_recovered_project_for
    _remaining_sweep_budget_sec = context.remaining_sweep_budget_sec
    decompiled = 0
    failed = 0
    item_function = cast(_AngrFunction, item.function)
    recovery_addr = _function_work_item_recovery_addr_8616(item)
    result: FunctionWorkResult | None = result_map.get(item.index)
    recovery_mode = "existing"
    decompile_timeout = max(1, args.timeout)
    if result is None:
        active_item = item
        active_function = item_function
        if item.function_cfg is None:
            recovery_mode = "lst" if lst_metadata is not None and visible_code_labels else "ranked"
            cached_work_result, _cache_bypass_debug, _cache_key, _tail_enabled, _expected_stages = (
                _function_work_cache_lookup(
                    item,
                    binary_path=args.binary,
                    timeout=args.timeout,
                    api_style=args.api_style,
                    enable_structured_simplify=True,
                    enable_postprocess=True,
                    cod_metadata=cod_metadata,
                    synthetic_globals=synthetic_globals,
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
                        low_memory=low_memory_path,
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
            try:
                remaining_sweep_budget = _remaining_sweep_budget_sec()
                if remaining_sweep_budget is not None and remaining_sweep_budget <= 0:
                    raise TimeoutError("Whole-sweep budget exhausted before recovery.")
                if result is not None:
                    pass
                elif lst_metadata is not None and visible_code_labels:
                    local_recover_timeout = recover_timeout
                    if remaining_sweep_budget is not None:
                        local_recover_timeout = max(1, min(local_recover_timeout, remaining_sweep_budget))
                    print(
                        f"[dbg] recovery worker: start {recovery_addr:#x} {item_function.name} "
                        f"mode=lst recovery_timeout={local_recover_timeout}s"
                    )
                    if _analysis_timeout_use_fork_8616():
                        try:
                            function_cfg, function = cast(
                                _FunctionCfgPair8616,
                                _run_with_timeout_in_fork(
                                    cast(Callable[[], Any], lambda offset=recovery_addr, name=item_function.name: _recover_lst_function(
                                        project,
                                        lst_metadata,
                                        offset,
                                        name,
                                        timeout=local_recover_timeout,
                                        window=args.window,
                                        low_memory=low_memory_path,
                                    )),
                                    timeout=local_recover_timeout + 1,
                                ),
                            )
                        except (FuturesTimeoutError, TimeoutError):
                            raise
                        except Exception:
                            function_cfg, function = cast(
                                _FunctionCfgPair8616,
                                _run_with_timeout_in_daemon_thread(
                                    cast(Callable[[], Any], lambda offset=recovery_addr, name=item_function.name: _recover_lst_function(
                                        project,
                                        lst_metadata,
                                        offset,
                                        name,
                                        timeout=local_recover_timeout,
                                        window=args.window,
                                        low_memory=low_memory_path,
                                    )),
                                    timeout=local_recover_timeout + 1,
                                    thread_name_prefix="lst-recover",
                                ),
                            )
                    else:
                        function_cfg, function = cast(
                            _FunctionCfgPair8616,
                            _run_with_timeout_in_daemon_thread(
                                cast(Callable[[], Any], lambda offset=recovery_addr, name=item_function.name: _recover_lst_function(
                                    project,
                                    lst_metadata,
                                    offset,
                                    name,
                                    timeout=local_recover_timeout,
                                    window=args.window,
                                    low_memory=low_memory_path,
                                )),
                                timeout=local_recover_timeout + 1,
                                thread_name_prefix="lst-recover",
                            ),
                        )
                else:
                    local_recover_timeout = recover_timeout
                    if remaining_sweep_budget is not None:
                        local_recover_timeout = max(1, min(local_recover_timeout, remaining_sweep_budget))
                    print(
                        f"[dbg] recovery worker: start {recovery_addr:#x} {item_function.name} "
                        f"mode=ranked recovery_timeout={local_recover_timeout}s"
                    )
                    if _analysis_timeout_use_fork_8616():
                        try:
                            function_cfg, function = cast(
                                _FunctionCfgPair8616,
                                _run_with_timeout_in_fork(
                                    cast(Callable[[], Any], lambda addr=recovery_addr, name=item_function.name: (
                                        _recover_ranked_binary_function(
                                            project,
                                            addr,
                                            name,
                                            timeout=local_recover_timeout,
                                            window=args.window,
                                            low_memory=low_memory_path,
                                        )
                                    )),
                                    timeout=local_recover_timeout + 1,
                                ),
                            )
                        except (FuturesTimeoutError, TimeoutError):
                            raise
                        except Exception:
                            function_cfg, function = cast(
                                _FunctionCfgPair8616,
                                _run_with_timeout_in_daemon_thread(
                                    cast(Callable[[], Any], lambda addr=recovery_addr, name=item_function.name: (
                                        _recover_ranked_binary_function(
                                            project,
                                            addr,
                                            name,
                                            timeout=local_recover_timeout,
                                            window=args.window,
                                            low_memory=low_memory_path,
                                        )
                                    )),
                                    timeout=local_recover_timeout + 1,
                                    thread_name_prefix="ranked-recover",
                                ),
                            )
                    else:
                        function_cfg, function = cast(
                            _FunctionCfgPair8616,
                            _run_with_timeout_in_daemon_thread(
                                cast(Callable[[], Any], lambda addr=recovery_addr, name=item_function.name: (
                                    _recover_ranked_binary_function(
                                        project,
                                        addr,
                                        name,
                                        timeout=local_recover_timeout,
                                        window=args.window,
                                        low_memory=low_memory_path,
                                    )
                                )),
                                timeout=local_recover_timeout + 1,
                                thread_name_prefix="ranked-recover",
                            ),
                        )
                if result is None:
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
                                    low_memory=low_memory_path,
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
                    _configure_recovered_work_item_project_8616(active_item)
                    _preserve_source_label_for_recovered_function_8616(item.function, active_item.function)
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
        if result is None:
            _configure_recovered_work_item_project_8616(active_item)
            active_function = cast(_AngrFunction, active_item.function)
            if active_item.function_cfg is None:
                result_map[item.index] = FunctionWorkResult(
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
                result = result_map[item.index]
                if item.index not in emitted_indexes:
                    d, f = _emit_function_result(
                        item,
                        result,
                        project=project,
                        args=args,
                        lst_metadata=lst_metadata,
                        cod_metadata=cod_metadata,
                        synthetic_globals=synthetic_globals,
                        precise_sidecar_regions=precise_sidecar_regions,
                        allow_heavy_fallbacks=allow_heavy_fallbacks,
                        interactive_stdout=interactive_stdout,
                        use_serial_fork_per_function=use_serial_fork_per_function,
                        fallback_tail_validation_by_index=fallback_tail_validation_by_index,
                        result_state_by_index=result_map,
                        timeout_was_explicit=timeout_was_explicit,
                    )
                    decompiled += d
                    failed += f
                    emitted_indexes.add(item.index)
                return _SerialFunctionOutcome8616(decompiled=decompiled, failed=failed)
            decompile_timeout = _batch_function_decompile_timeout_8616(
                context,
                active_function,
                adaptive_timeout_model,
            )
            if use_serial_fork_per_function:
                hard_timeout = _serial_clean_worker_outer_timeout_8616(decompile_timeout)
                print(
                    f"[dbg] clean serial function worker: start {active_function.addr:#x} "
                    f"{active_function.name} requested_timeout={decompile_timeout}s hard_timeout={hard_timeout}s"
                )
                result = _run_serial_clean_process_work_item_8616(
                    context,
                    active_item,
                    timeout=decompile_timeout,
                )
            else:
                try:
                    result = _run_with_timeout_in_daemon_thread(
                        lambda: _run_function_work_item(
                            active_item,
                            timeout=decompile_timeout,
                            api_style=args.api_style,
                            binary_path=args.binary,
                            cod_metadata=cod_metadata,
                            synthetic_globals=synthetic_globals,
                            lst_metadata=lst_metadata,
                            enable_structured_simplify=True,
                            force_isolated_project=_force_isolated_project_for_work_item(active_item),
                            allow_isolated_retry=allow_isolated_retry_in_function_tasks,
                        ),
                        timeout=_enforce_function_timeout_cap(
                            max(1, decompile_timeout + 1),
                            context="sweep function serial daemon timeout",
                            explicit_timeout_floor=args.timeout if timeout_was_explicit else None,
                        ),
                        thread_name_prefix="func-serial",
                    )
                except (FuturesTimeoutError, TimeoutError):
                    result = FunctionWorkResult(
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
                    result = FunctionWorkResult(
                        index=item.index,
                        status="error",
                        payload=f"Serial function worker failed: {_describe_exception(ex)}",
                        debug_output="",
                        function=active_item.function,
                        function_cfg=active_item.function_cfg,
                        failure_stage="decompilation",
                    )
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
        if result is not None and result.status == "timeout" and args.addr is None and not use_serial_fork_per_function:
            base_timeout = max(1, args.timeout)
            # Ensure sweep retry actually expands the lane budget.
            # The previous 120s cap could become a no-op when the base
            # timeout was already 120s, leaving flaky one-off timeouts
            # unrecovered.
            retry_timeout = min(360, max(int(decompile_timeout) * 2, base_timeout * 2, 40))
            retry_timeout = _enforce_function_timeout_cap(
                retry_timeout,
                context="sweep timeout bridge",
                explicit_timeout_floor=args.timeout if timeout_was_explicit else None,
            )
            try:
                retry_result = _run_with_timeout_in_daemon_thread(
                    lambda: _run_function_work_item(
                        active_item,
                        timeout=retry_timeout,
                        api_style=args.api_style,
                        binary_path=args.binary,
                        cod_metadata=cod_metadata,
                        synthetic_globals=synthetic_globals,
                        lst_metadata=lst_metadata,
                        enable_structured_simplify=True,
                        force_isolated_project=_force_isolated_project_for_work_item(active_item),
                        allow_isolated_retry=allow_isolated_retry_in_function_tasks,
                    ),
                    timeout=_enforce_function_timeout_cap(
                        max(1, retry_timeout + 2),
                        context="sweep retry bridge thread timeout",
                        explicit_timeout_floor=args.timeout if timeout_was_explicit else None,
                    ),
                    thread_name_prefix="func-timeout-bridge",
                )
                if isinstance(retry_result, FunctionWorkResult) and retry_result.status == "ok":
                    result = retry_result
            except Exception:
                pass
        result_map[item.index] = result
        if result is not None and item.index not in emitted_indexes:
            d, f = _emit_function_result(
                item,
                result,
                project=project,
                args=args,
                lst_metadata=lst_metadata,
                cod_metadata=cod_metadata,
                synthetic_globals=synthetic_globals,
                precise_sidecar_regions=precise_sidecar_regions,
                allow_heavy_fallbacks=allow_heavy_fallbacks,
                interactive_stdout=interactive_stdout,
                use_serial_fork_per_function=use_serial_fork_per_function,
                fallback_tail_validation_by_index=fallback_tail_validation_by_index,
                result_state_by_index=result_map,
                timeout_was_explicit=timeout_was_explicit,
            )
            decompiled += d
            failed += f
            emitted_indexes.add(item.index)
            if f and args.addr is not None:
                _emit_tail_validation_console_summary(function_tasks, result_map, binary_path=args.binary)
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
    cod_metadata = context.cod_metadata
    synthetic_globals = context.synthetic_globals
    precise_sidecar_regions = context.precise_sidecar_regions
    allow_heavy_fallbacks = context.allow_heavy_fallbacks
    interactive_stdout = context.interactive_stdout
    use_serial_fork_per_function = context.use_serial_fork_per_function
    shown_total = context.shown_total
    skipped_signature_labels = context.skipped_signature_labels
    attempted = sum(1 for item in function_tasks if result_map.get(item.index) is not None)
    attempted_target = "selected" if args.max_functions <= 0 and args.addr is None else "displayed"
    print(f"/* info: decompilation attempted for {attempted}/{shown_total} {attempted_target} function(s) */")
    for item in function_tasks:
        if item.index in emitted_indexes:
            continue
        result = result_map.get(item.index)
        if result is None:
            continue
        d, f = _emit_function_result(
            item,
            result,
            project=project,
            args=args,
            lst_metadata=lst_metadata,
            cod_metadata=cod_metadata,
            synthetic_globals=synthetic_globals,
            precise_sidecar_regions=precise_sidecar_regions,
            allow_heavy_fallbacks=allow_heavy_fallbacks,
            interactive_stdout=interactive_stdout,
            use_serial_fork_per_function=use_serial_fork_per_function,
            fallback_tail_validation_by_index=fallback_tail_validation_by_index,
            result_state_by_index=result_map,
            timeout_was_explicit=context.timeout_was_explicit,
        )
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
    dead_setup_candidates = 0
    dead_setup_pruned = 0
    dead_setup_refused = 0
    dead_setup_escaped = 0
    for result in result_map.values():
        function_obj = result.function
        info = getattr(function_obj, "info", None)
        if not isinstance(info, dict):
            continue
        ds = info.get("x86_16_dead_setup")
        if not isinstance(ds, dict):
            continue
        dead_setup_candidates += int(ds.get("dead_setup_candidates", 0) or 0)
        dead_setup_pruned += int(ds.get("dead_setup_pruned", 0) or 0)
        dead_setup_refused += int(ds.get("dead_setup_refused", 0) or 0)
        dead_setup_escaped += int(ds.get("dead_setup_escaped", 0) or 0)
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


def _run_main_cli_8616(argv: list[str] | None) -> int:
    """Run CLI orchestration after the mandatory architecture guard succeeds."""
    args, timeout_was_explicit, effective_signature_catalog = _prepare_main_cli_args_8616(argv)

    print(f"/* loading: {args.binary} */", flush=True)
    runtime_header = render_c_runtime_header_8616(args.c_target)
    if runtime_header:
        print(runtime_header, end="" if runtime_header.endswith("\n") else "\n", flush=True)
    try:
        setup = _prepare_main_project_8616(args, effective_signature_catalog)
    except PackedExecutableRefusedError as ex:
        print(f"error: {ex}", file=sys.stderr, flush=True)
        return 7
    project = setup.project
    function_label = setup.function_label
    cod_metadata = setup.cod_metadata
    synthetic_globals = setup.synthetic_globals
    lst_metadata = setup.lst_metadata
    prefer_fast_recovery = setup.prefer_fast_recovery
    proc_resolved_to_linked_binary = setup.proc_resolved_to_linked_binary
    low_memory_path = _prefer_low_memory_path()
    _configure_display_catalog_cache_policy_8616(
        project,
        DisplayCatalogCachePolicy8616.from_runtime(
            ignore_local_sidecar_hints=bool(args.ignore_local_sidecar_hints),
            include_library_functions=bool(args.include_library_functions),
            function_discovery_backend=args.function_discovery_backend,
            pat_backend=args.pat_backend,
            max_functions=args.max_functions,
            timeout=args.timeout,
            window=args.window,
            rizin_timeout=args.rizin_timeout,
            low_memory=low_memory_path,
            auto_rizin_policy=os.environ.get("INERTIA_AUTO_RIZIN_8616", "default"),
            signature_catalog=effective_signature_catalog,
            catalog_timeout=args.catalog_timeout,
        ),
    )
    interactive_stdout = _stdout_is_interactive()
    precise_sidecar_regions = metadata_has_precise_code_regions(cast(Any, lst_metadata))
    if args.addr is not None:
        request_cache_inputs = DirectRequestCacheInputs8616.from_cli(
            args,
            signature_catalog=effective_signature_catalog,
        )
        assert request_cache_inputs is not None
        direct_context = _DirectAddrCliContext8616(
            args=args,
            project=project,
            function_label=function_label,
            cod_metadata=cod_metadata,
            synthetic_globals=synthetic_globals,
            lst_metadata=lst_metadata,
            prefer_fast_recovery=prefer_fast_recovery,
            proc_resolved_to_linked_binary=proc_resolved_to_linked_binary,
            low_memory_path=low_memory_path,
            interactive_stdout=interactive_stdout,
            precise_sidecar_regions=precise_sidecar_regions,
            timeout_was_explicit=timeout_was_explicit,
            request_cache_inputs=request_cache_inputs,
        )
        direct_lock_key = build_direct_request_cache_key_8616(request_cache_inputs)
        if not _direct_addr_work_requires_parent_lock_8616(direct_lock_key):
            return _run_direct_addr_cli_8616(direct_context)
        assert direct_lock_key is not None
        with _cache_key_lock("direct_addr_work", direct_lock_key):
            return _run_direct_addr_cli_8616(direct_context)

    print("/* discovering likely functions... */", flush=True)
    typing.cast(typing.Any, project)._inertia_cached_catalog_mode = False
    typing.cast(typing.Any, project)._inertia_hidden_signature_mode = False
    typing.cast(typing.Any, project)._inertia_display_truncated = False
    typing.cast(typing.Any, project)._inertia_uncapped_seeded_recovery = False
    cfg: object | None = None
    function_cfg_pairs: list[_FunctionCfgPair8616] = []
    ranked_binary_offsets: list[int] = []
    labeled_offsets: list[tuple[int, str]] = []
    ranked_labeled_total = 0
    total_functions = 0
    shown_total = 0
    direct_inventory_total: int | None = None
    prefer_ranked_hidden_sidecar_full_queue = False
    visible_code_labels = _function_discovery_code_labels(lst_metadata)
    recovery_code_labels = _recovery_code_labels(lst_metadata) if lst_metadata is not None else {}
    has_non_library_sidecar_hints = bool(visible_code_labels)
    include_library_functions = args.include_library_functions
    library_label_skipped_count = 0
    if include_library_functions and lst_metadata is not None:
        visible_code_labels = dict(getattr(lst_metadata, "code_labels", {}) or {})
        recovery_code_labels = dict(visible_code_labels)
    elif lst_metadata is not None:
        visible_filter = filter_code_labels_for_library_policy(lst_metadata, visible_code_labels)
        recovery_filter = filter_code_labels_for_library_policy(lst_metadata, recovery_code_labels)
        visible_code_labels = visible_filter.labels
        recovery_code_labels = recovery_filter.labels
        library_label_skipped_count = max(visible_filter.skipped_count, recovery_filter.skipped_count)
        if not visible_code_labels and not recovery_code_labels and getattr(lst_metadata, "code_labels", None):
            print(
                "/* sidecar labels are signature/library-only; skipping them by default "
                "(use --include-library-functions to include). */"
            )
    seed_code_labels = visible_code_labels or recovery_code_labels
    skipped_signature_labels = (
        len(_signature_matched_code_addrs(lst_metadata))
        if lst_metadata is not None and not include_library_functions
        else 0
    )
    if low_memory_path:
        print("/* Low-memory mode: using a smaller, safer function-discovery pass. */")
    packed_exe = None if args.proc is not None else getattr(project, "_inertia_packed_exe", None)
    if lst_metadata is not None and visible_code_labels:
        try:
            ranking_start = time.perf_counter()
            labeled_offsets, ranking_cache_hit = _rank_labeled_function_entries_cached(
                project,
                list(seed_code_labels.items()),
                lst_metadata,
            )
            ranking_elapsed_ms = (time.perf_counter() - ranking_start) * 1000.0
            print(
                f"/* sidecar label ranking prepared {len(labeled_offsets)} entries in "
                f"{ranking_elapsed_ms:.1f}ms{' (cache hit)' if ranking_cache_hit else ''}. */"
            )
            ranked_labeled_total = len(labeled_offsets)
            if args.max_functions > 0:
                labeled_offsets = labeled_offsets[: args.max_functions]
        except Exception as ex:
            print(f"/* Listing-backed function catalog setup failed: {ex} */")
            print("\n/* == entry asm == */")
            print(_format_first_block_asm(project, project.entry))
            return 5
    else:
        catalog_error: BaseException | None = None
        deferred_exe_display_cap = args.addr is None and args.binary.suffix.lower() == ".exe" and args.max_functions > 0
        if args.addr is None and args.binary.suffix.lower() == ".exe":
            ranked_binary_offsets = _discover_ranked_binary_offsets(project, args=args)
            linked_base = getattr(getattr(project.loader, "main_object", None), "linked_base", None)
            if isinstance(linked_base, int):
                ranked_binary_offsets = [addr for addr in ranked_binary_offsets if addr != linked_base]
            direct_inventory_total = len(ranked_binary_offsets) if ranked_binary_offsets else None
            if direct_inventory_total is not None:
                print(
                    f"/* info: direct-binary recovery found {direct_inventory_total} likely non-library function entries */"
                )
        discovery_limit = (
            _expanded_exe_discovery_limit(args.max_functions)
            if deferred_exe_display_cap
            else (args.max_functions if args.max_functions > 0 else None)
        )
        if lst_metadata is not None and not visible_code_labels:
            if recovery_code_labels:
                print(
                    "/* Signature-bounded sidecar labels available as bounded hints; "
                    "recovering binary-owned functions from direct call/prologue evidence before generic CFG recovery. */"
                )
            if args.max_functions <= 0 and ranked_binary_offsets and not has_non_library_sidecar_hints:
                prefer_ranked_hidden_sidecar_full_queue = True
                total_functions = len(ranked_binary_offsets)
                shown_total = len(ranked_binary_offsets)
                print(
                    "/* hidden-sidecar EXE: queueing ranked direct-binary function candidates for full decompilation "
                    "without waiting for whole-program CFG recovery. */"
                )
            if deferred_exe_display_cap and ranked_binary_offsets and not has_non_library_sidecar_hints:
                # Hidden-sidecar EXEs only have signature/library labels. Do not
                # spend time pre-recovering a capped preview here; queue ranked
                # binary-owned candidates and recover each one in the streaming
                # serial lane so the first function can be emitted sooner.
                prefer_ranked_hidden_sidecar_full_queue = True
                total_functions = len(ranked_binary_offsets)
                shown_total = min(len(ranked_binary_offsets), args.max_functions)
                print(
                    "/* hidden-sidecar EXE: using ranked direct-binary function candidates; "
                    "recovering selected functions lazily for streaming output. */"
                )
            try:
                if not function_cfg_pairs and not prefer_ranked_hidden_sidecar_full_queue:
                    seeded_recovery_result = _run_with_timeout_in_daemon_thread(
                        lambda: _recover_seeded_exe_functions(
                            project,
                            timeout=args.catalog_timeout,
                            limit=discovery_limit,
                            return_addrs=True,
                        ),
                        timeout=args.catalog_timeout + 2,
                        thread_name_prefix="seed-catalog",
                    )
                    if isinstance(seeded_recovery_result, tuple) and len(seeded_recovery_result) == 2:
                        function_cfg_pairs = cast(list[_FunctionCfgPair8616], seeded_recovery_result[0])
                        seeded_catalog_addrs = seeded_recovery_result[1]
                    else:
                        function_cfg_pairs = seeded_recovery_result
                        seeded_catalog_addrs = [function.addr for _, function in function_cfg_pairs]
            except Exception as ex:
                catalog_error = ex
                function_cfg_pairs = function_cfg_pairs if function_cfg_pairs else []
                seeded_catalog_addrs = []
            else:
                pass
            if function_cfg_pairs and not total_functions:
                total_functions = len(seeded_catalog_addrs)
                shown_total = len(function_cfg_pairs)

        prefer_bounded_catalog = (
            lst_metadata is None and project.arch.name == "86_16" and args.binary.suffix.lower() == ".exe"
        )
        cached_catalog_addrs = _load_catalog_address_cache(project, args.binary) if prefer_bounded_catalog else []
        if cached_catalog_addrs:
            typing.cast(typing.Any, project)._inertia_cached_catalog_mode = True
            print("/* using cached discovered function addresses before running new control-flow recovery. */")
            function_cfg_pairs = _recover_cached_function_pairs(
                project,
                addrs=cached_catalog_addrs,
                timeout=args.catalog_timeout,
                limit=discovery_limit,
            )
            if function_cfg_pairs:
                try:
                    display_cache_key = _catalog_address_cache_key_8616(project, args.binary)
                    cached_catalog_int_addrs = [addr for addr in cached_catalog_addrs if isinstance(addr, int)]
                    supplemented_cached_result = cast(
                        tuple[list[_FunctionCfgPair8616], list[int]],
                        _run_with_timeout_in_daemon_thread(
                            lambda: _supplement_cached_seeded_recovery(
                                project,
                                function_cfg_pairs,
                                cached_catalog_int_addrs,
                                region_span=0x120,
                                per_function_timeout=1,
                                limit=discovery_limit,
                                cache_key=display_cache_key,
                            ),
                            timeout=min(max(1, args.timeout), 2),
                            thread_name_prefix="cached-display-supplement",
                        ),
                    )
                    function_cfg_pairs, cached_catalog_addrs = supplemented_cached_result
                except FuturesTimeoutError:
                    pass
                total_functions = len(cached_catalog_addrs)
                shown_total = len(function_cfg_pairs)

        if prefer_bounded_catalog and not function_cfg_pairs:
            try:
                # This recovery mutates the shared angr project. Its internal
                # candidate deadlines provide the bound; an outer daemon
                # timeout would leave a live worker polluting fallback CFGs.
                function_cfg_pairs = _recover_fast_exe_catalog(
                    project,
                    catalog_timeout=args.catalog_timeout,
                    timeout=args.timeout,
                    window=args.window,
                    low_memory=low_memory_path,
                    limit=discovery_limit,
                )
            except (_AnalysisTimeout, Exception) as ex:
                catalog_error = ex
                print(
                    "/* Quick EXE function discovery timed out; falling back to a bounded control-flow recovery pass. */"
                )
                function_cfg_pairs = []
            if function_cfg_pairs:
                source_region_evidence = _source_region_catalog_evidence_8616(project)
                if source_region_evidence is not None and not source_region_evidence.complete:
                    print(
                        "/* Function catalog recovery failed: startup-bounded source catalog was incomplete; "
                        f"failed addresses={','.join(hex(addr) for addr in source_region_evidence.failed_addrs) or 'none'} */"
                    )
                    return 5
                total_functions = max(
                    len(function_cfg_pairs),
                    source_region_evidence.raw_fact_count if source_region_evidence is not None else 0,
                )
                shown_total = len(function_cfg_pairs)

        if prefer_bounded_catalog and not function_cfg_pairs:
            print(
                "/* No helper metadata for this x86-16 EXE; first trying a small scan near program entry before whole-program control-flow recovery. */"
            )
            if not function_cfg_pairs:
                try:
                    cfg = _run_with_timeout_in_daemon_thread(
                        lambda: _recover_partial_cfg(
                            project,
                            window=args.window,
                            low_memory=low_memory_path,
                        ),
                        timeout=args.timeout,
                        thread_name_prefix="catalog-fallback",
                    )
                except Exception as ex:
                    catalog_error = ex

        if cfg is None and not function_cfg_pairs and not prefer_ranked_hidden_sidecar_full_queue:
            if prefer_bounded_catalog:
                print(
                    "/* Small entry-area recovery failed; attempting whole-program control-flow recovery as a last resort. */"
                )
            try:
                cfg = _run_with_timeout_in_daemon_thread(
                    lambda: _recover_cfg(
                        project,
                        args.binary,
                        base_addr=args.base_addr,
                        window=args.window,
                        low_memory=low_memory_path,
                    ),
                    timeout=args.timeout,
                    thread_name_prefix="catalog",
                )
            except Exception as ex:
                catalog_error = ex

        if (
            cfg is None
            and not function_cfg_pairs
            and project.arch.name == "86_16"
            and not prefer_bounded_catalog
            and not prefer_ranked_hidden_sidecar_full_queue
        ):
            print("/* Whole-program function discovery failed; attempting a smaller entry-area recovery pass. */")
            try:
                cfg = _run_with_timeout_in_daemon_thread(
                    lambda: _recover_partial_cfg(
                        project,
                        window=args.window,
                        low_memory=low_memory_path,
                    ),
                    timeout=args.timeout,
                    thread_name_prefix="catalog-fallback",
                )
            except Exception as ex:
                catalog_error = ex

        if cfg is None and not function_cfg_pairs and not prefer_ranked_hidden_sidecar_full_queue:
            fast_seed_pairs: list[_FunctionCfgPair8616] = []
            print("/* Whole-program control-flow recovery failed; attempting a quick function-entry scan fallback. */")
            fast_seed_pairs = cast(
                list[_FunctionCfgPair8616],
                _recover_fast_seed_functions(
                    project,
                    timeout=args.catalog_timeout,
                    limit=discovery_limit,
                ),
            )
            if fast_seed_pairs:
                function_cfg_pairs = fast_seed_pairs
                total_functions = len(function_cfg_pairs)
                shown_total = len(function_cfg_pairs)
                cfg = None
            elif prefer_ranked_hidden_sidecar_full_queue:
                pass
            elif not prefer_ranked_hidden_sidecar_full_queue and (
                args.addr is None and args.binary.suffix.lower() == ".exe" and ranked_binary_offsets
            ):
                print(
                    "/* Falling back to ranked direct-binary function addresses; "
                    "recovering only the shown subset lazily. */"
                )
            else:
                if isinstance(catalog_error, FuturesTimeoutError):
                    detail = "Timed out"
                elif isinstance(catalog_error, Exception):
                    detail = _describe_exception(catalog_error)
                elif catalog_error is not None:
                    detail = str(catalog_error)
                else:
                    detail = "Unknown failure"
                print(f"/* Function catalog recovery failed: {detail} */")
                if packed_exe is not None:
                    print(
                        f"/* hint: {args.binary.name} looks packed ({packed_exe}); startup-stub output may be the current limit. */"
                    )
                print("\n/* == lift break probe == */")
                print(_probe_lift_break(project, project.entry))
                print("\n/* == entry asm == */")
                print(_format_first_block_asm(project, project.entry))
                print("\n/* == non-optimized disassembly == */")
                start, end = _infer_linear_disassembly_window(project, project.entry)
                print(_format_asm_range(project, start, end))
                return 5

    if skipped_signature_labels > 0:
        print(f"/* skipping {skipped_signature_labels} signature-matched function(s) by default. */")
    if library_label_skipped_count > 0:
        print(f"/* skipping {library_label_skipped_count} library-like sidecar function(s) by default. */")
    elif include_library_functions and lst_metadata is not None:
        print("/* including signature/library-labeled functions as requested. */")

    if cfg is not None:
        cfg_any = cast(Any, cfg)
        if function_label is not None and project.entry in cfg_any.functions:
            cfg_any.functions[project.entry].name = function_label
        else:
            rizin_names = getattr(project, "_inertia_rizin_function_names", {}) or {}
            for addr, func in cfg_any.functions.items():
                code_name = _lst_code_label(lst_metadata, addr, project.entry) if lst_metadata is not None else None
                if code_name is not None:
                    func.name = code_name
                elif isinstance(rizin_names, dict):
                    rz_name = rizin_names.get(addr)
                    if isinstance(rz_name, str) and rz_name:
                        func.name = rz_name

    if lst_metadata is not None and visible_code_labels:
        total_functions = ranked_labeled_total or len(labeled_offsets)
        shown_total = len(labeled_offsets)
    elif not function_cfg_pairs and cfg is not None:
        limit = args.max_functions if args.max_functions > 0 else None
        defer_limit_until_after_seed_ranking = args.addr is None and args.binary.suffix.lower() == ".exe"
        functions, total_functions = cast(
            tuple[list[_AngrFunction], int],
            _interesting_functions(cfg, limit=None if defer_limit_until_after_seed_ranking else limit),
        )
        shown_total = len(functions)
        function_cfg_pairs = [(cfg, function) for function in functions]
        if args.addr is None and args.binary.suffix.lower() == ".exe":
            _seeded_pairs_and_addrs = _recover_seeded_exe_functions(
                project,
                timeout=args.catalog_timeout,
                limit=None if (limit is None or defer_limit_until_after_seed_ranking) else max(0, limit - shown_total),
                return_addrs=True,
            )
            if isinstance(_seeded_pairs_and_addrs, tuple) and len(_seeded_pairs_and_addrs) == 2:
                seeded_pairs = cast(list[_FunctionCfgPair8616], _seeded_pairs_and_addrs[0])
                seeded_addrs = _seeded_pairs_and_addrs[1]
            else:
                seeded_pairs, seeded_addrs = _seeded_pairs_and_addrs, []
            if seeded_pairs:
                if isinstance(seeded_addrs, (list, tuple)):
                    discovered_addrs = set(seeded_addrs)
                    existing_addrs = {function.addr for function in functions}
                    recovered_seed_addrs = {function.addr for _, function in seeded_pairs}
                    if discovered_addrs - (existing_addrs | recovered_seed_addrs):
                        typing.cast(typing.Any, project)._inertia_uncapped_seeded_recovery = True
                seen_existing = {function.addr for function in functions}
                seeded_pairs = _rank_function_cfg_pairs_for_display(project, seeded_pairs)
                for function_cfg, function in seeded_pairs:
                    if function.addr in seen_existing:
                        continue
                    function_cfg_pairs.append((function_cfg, function))
                    seen_existing.add(function.addr)
                function_cfg_pairs = _rank_function_cfg_pairs_for_display(project, function_cfg_pairs)
                if limit is not None and defer_limit_until_after_seed_ranking:
                    function_cfg_pairs = function_cfg_pairs[:limit]
                shown_total = len(function_cfg_pairs)
                total_functions = max(total_functions, len(seen_existing | set(seeded_addrs)))
                typing.cast(typing.Any, project)._inertia_supplemental_scan_used = True
            elif limit is not None and defer_limit_until_after_seed_ranking:
                function_cfg_pairs = function_cfg_pairs[:limit]
                shown_total = len(function_cfg_pairs)
        if (
            args.addr is None
            and args.binary.suffix.lower() == ".exe"
            and shown_total <= 1
            and not (lst_metadata is not None and not visible_code_labels and ranked_binary_offsets)
        ):
            supplemental_pairs = _supplement_functions_from_prologue_scan(
                project,
                {function.addr for function in functions},
            )
            if supplemental_pairs:
                function_cfg_pairs.extend(supplemental_pairs)
                function_cfg_pairs = _rank_function_cfg_pairs_for_display(project, function_cfg_pairs)
                shown_total = len(function_cfg_pairs)
                total_functions = max(total_functions, shown_total)
                typing.cast(typing.Any, project)._inertia_supplemental_scan_used = True
    elif (
        not function_cfg_pairs
        and args.addr is None
        and args.binary.suffix.lower() == ".exe"
        and ranked_binary_offsets
    ):
        shown_total = len(ranked_binary_offsets)
        if args.max_functions > 0:
            shown_total = min(shown_total, args.max_functions)

    sidecar_preview_limit = None
    if (
        lst_metadata is not None
        and visible_code_labels
        and interactive_stdout
        and args.max_functions > 0
        and total_functions > args.max_functions
    ):
        sidecar_preview_limit = args.max_functions
    if lst_metadata is not None and visible_code_labels:
        print("/* == known function catalog (sidecar-backed) == */")
        print(
            _format_sidecar_function_catalog(lst_metadata, limit=sidecar_preview_limit, code_labels=visible_code_labels)
        )
        if sidecar_preview_limit is not None and total_functions > sidecar_preview_limit:
            print(f"/* catalog preview limited to first {sidecar_preview_limit} entries for responsiveness. */")

    if (
        args.addr is None
        and args.binary.suffix.lower() == ".exe"
        and function_cfg_pairs
        and len(function_cfg_pairs) > 1
        and not (
            lst_metadata is not None and not visible_code_labels and ranked_binary_offsets and args.max_functions > 0
        )
    ):
        function_cfg_pairs = _rank_function_cfg_pairs_for_display(project, function_cfg_pairs)

    if (
        args.addr is None
        and args.binary.suffix.lower() == ".exe"
        and lst_metadata is not None
        and not visible_code_labels
        and args.max_functions > 0
        and function_cfg_pairs
        and len(function_cfg_pairs) < args.max_functions
        and ranked_binary_offsets
    ):
        function_cfg_pairs = _supplement_function_cfg_pairs_with_seeded_recovery(
            project,
            function_cfg_pairs,
            timeout=args.timeout,
            target_count=args.max_functions,
        )
        function_cfg_pairs = _supplement_function_cfg_pairs_with_ranked_preview(
            project,
            function_cfg_pairs,
            ranked_binary_offsets,
            target_count=args.max_functions,
            timeout=args.timeout,
            window=args.window,
            low_memory=low_memory_path,
        )
        function_cfg_pairs = _rank_function_cfg_pairs_for_display(project, function_cfg_pairs)
        shown_total = len(function_cfg_pairs)
    uncapped_function_cfg_pairs = list(function_cfg_pairs)
    source_catalog = _source_region_catalog_evidence_8616(project)
    if (
        project.arch.name == "86_16"
        and source_catalog is not None
        and source_catalog.complete
        and uncapped_function_cfg_pairs
    ):
        attach_project_argument_evidence_ranges_8616(project, project)
        publish_discovered_indexed_alias_program_8616(
            project,
            tuple(function for _cfg, function in uncapped_function_cfg_pairs),
        )
    if (
        args.addr is None
        and args.binary.suffix.lower() == ".exe"
        and args.max_functions > 0
        and len(function_cfg_pairs) > args.max_functions
    ):
        function_cfg_pairs = function_cfg_pairs[: args.max_functions]
        shown_total = len(function_cfg_pairs)

    print(f"/* binary: {args.binary} */")
    print(f"/* arch: {project.arch.name} */")
    print(f"/* entry: {project.entry:#x} */")
    print(f"/* functions queued for decompilation: {total_functions} */")

    if args.max_functions > 0 and total_functions > shown_total:
        typing.cast(typing.Any, project)._inertia_display_truncated = True
        print(
            f"/* showing first {shown_total} functions because --max-functions={args.max_functions}; "
            "raise it or omit the option to decompile all queued functions */"
        )

    if (
        args.addr is None
        and args.binary.suffix.lower() == ".exe"
        and lst_metadata is None
        and uncapped_function_cfg_pairs
        and (
            (source_region_evidence := _source_region_catalog_evidence_8616(project)) is None
            or source_region_evidence.complete
        )
    ):
        _store_catalog_address_cache(project, args.binary, uncapped_function_cfg_pairs)

    function_tasks: list[FunctionWorkItem] = []
    result_map: dict[int, FunctionWorkResult] = {}
    fallback_tail_validation_by_index: dict[int, dict[str, object]] = {}
    if lst_metadata is not None and visible_code_labels:
        for index, (offset, name) in enumerate(labeled_offsets, start=1):
            work_offset, work_name = _canonicalize_sidecar_work_offset_8616(
                project,
                lst_metadata,
                offset,
                name,
            )
            placeholder = _make_placeholder_function(project, work_offset, work_name or name)
            function_tasks.append(
                FunctionWorkItem(
                    index=index,
                    function_cfg=None,
                    function=placeholder,
                    recovery_addr=offset,
                )
            )
    elif (
        args.addr is None and args.binary.suffix.lower() == ".exe" and not function_cfg_pairs and ranked_binary_offsets
    ):
        preview_addrs = ranked_binary_offsets
        if (
            lst_metadata is not None
            and not visible_code_labels
            and include_library_functions
            and args.max_functions <= 0
        ):
            function_tasks = [
                FunctionWorkItem(
                    index=index,
                    function_cfg=None,
                    function=_make_placeholder_function(project, addr, f"sub_{addr:x}"),
                    recovery_addr=addr,
                )
                for index, addr in enumerate(preview_addrs, start=1)
            ]
            shown_total = len(function_tasks)
        else:
            if args.max_functions > 0:
                preview_addrs = preview_addrs[: args.max_functions]
            elif interactive_stdout and len(preview_addrs) > 24:
                preview_addrs = preview_addrs[: _default_exe_showcase_cap(len(preview_addrs), args.timeout)]
            shown_total = len(preview_addrs)
            if lst_metadata is not None and not visible_code_labels:
                function_tasks = [
                    FunctionWorkItem(
                        index=index,
                        function_cfg=None,
                        function=_make_placeholder_function(project, addr, f"sub_{addr:x}"),
                        recovery_addr=addr,
                    )
                    for index, addr in enumerate(preview_addrs, start=1)
                ]
            else:
                function_tasks = _prepare_ranked_binary_preview_items(
                    project,
                    ranked_binary_offsets,
                    max_count=shown_total,
                    timeout=args.timeout,
                    window=args.window,
                    low_memory=low_memory_path,
                )
    else:
        for index, (function_cfg, function) in enumerate(function_cfg_pairs, start=1):
            function_tasks.append(
                FunctionWorkItem(
                    index=index,
                    function_cfg=function_cfg,
                    function=function,
                    recovery_addr=function_original_addr(function),
                )
            )
        if (
            args.addr is None
            and args.binary.suffix.lower() == ".exe"
            and lst_metadata is not None
            and not visible_code_labels
            and include_library_functions
            and ranked_binary_offsets
            and args.max_functions <= 0
        ):
            existing_by_addr = {
                getattr(item.function, "addr", None): item
                for item in function_tasks
                if isinstance(getattr(item.function, "addr", None), int)
            }
            function_tasks = []
            for index, addr in enumerate(ranked_binary_offsets, start=1):
                existing = existing_by_addr.get(addr)
                if existing is not None:
                    function_tasks.append(
                        FunctionWorkItem(
                            index=index,
                            function_cfg=existing.function_cfg,
                            function=existing.function,
                            recovery_addr=existing.recovery_addr,
                        )
                    )
                    continue
                function_tasks.append(
                    FunctionWorkItem(
                        index=index,
                        function_cfg=None,
                        function=_make_placeholder_function(project, addr, f"sub_{addr:x}"),
                        recovery_addr=addr,
                    )
                )
            shown_total = len(function_tasks)
        if (
            args.addr is None
            and args.binary.suffix.lower() == ".exe"
            and lst_metadata is not None
            and not visible_code_labels
            and include_library_functions
            and ranked_binary_offsets
            and args.max_functions > 0
        ):
            existing_by_addr = {
                getattr(item.function, "addr", None): item
                for item in function_tasks
                if isinstance(getattr(item.function, "addr", None), int)
            }
            replacement_tasks: list[FunctionWorkItem] = []
            for index, addr in enumerate(ranked_binary_offsets[: args.max_functions], start=1):
                existing = existing_by_addr.get(addr)
                if existing is not None:
                    replacement_tasks.append(
                        FunctionWorkItem(
                            index=index,
                            function_cfg=existing.function_cfg,
                            function=existing.function,
                            recovery_addr=existing.recovery_addr,
                        )
                    )
                    continue
                replacement_tasks.append(
                    FunctionWorkItem(
                        index=index,
                        function_cfg=None,
                        function=_make_placeholder_function(project, addr, f"sub_{addr:x}"),
                        recovery_addr=addr,
                    )
                )
            function_tasks = replacement_tasks
            shown_total = len(function_tasks)

    selection_target = "decompilation" if args.max_functions <= 0 and args.addr is None else "display"
    if (selection_target == "decompilation" and lst_metadata is None
            and direct_inventory_total is not None and shown_total < direct_inventory_total):
        print(f"[catalog] queued {shown_total} of {direct_inventory_total} candidate entries; "
              f"catalog recovery budget={args.catalog_timeout}s. Unqueued candidates are not decompiled. "
              "Increasing --catalog-timeout may recover more; candidates are not proven functions.", file=sys.stderr)
    print(f"/* info: selected {shown_total} function(s) for {selection_target} */")

    requested_workers = _choose_function_parallelism(len(function_tasks))
    workers = requested_workers
    if lst_metadata is not None and visible_code_labels:
        workers = 1
    if any(item.function_cfg is None for item in function_tasks):
        workers = 1
    if (
        args.addr is None
        and args.binary.suffix.lower() == ".exe"
        and lst_metadata is not None
        and not visible_code_labels
    ):
        workers = 1
    if getattr(project, "_inertia_supplemental_scan_used", False) and _should_force_serial_supplemental_decompilation(
        len(function_tasks)
    ):
        workers = 1
    if (
        args.addr is None
        and args.binary.suffix.lower() == ".exe"
        and args.max_functions > 0
        and args.max_functions <= 2
        and lst_metadata is not None
        and include_library_functions
    ):
        workers = 1
    if (
        args.addr is None
        and args.binary.suffix.lower() == ".exe"
        and args.max_functions > 0
        and args.max_functions <= 2
        and low_memory_path
    ):
        workers = 1
    isolated_function_decompilation_required = requires_isolated_function_decompilation(
        architecture=project.arch.name,
        binary_suffix=args.binary.suffix,
        address_requested=args.addr is not None,
    )
    forced_serial_function_decomp = os.environ.get(_FORCE_SERIAL_FUNCTION_DECOMP_ENV, "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    worker_policy = select_function_worker_policy_8616(
        isolation_required=isolated_function_decompilation_required,
        sidecar_available=lst_metadata is not None,
        full_sweep=args.addr is None and args.max_functions <= 0,
        include_library_functions=include_library_functions,
        posix_available=os.name == "posix",
        function_count=len(function_tasks),
        shared_worker_count=(
            requested_workers if isolated_function_decompilation_required else workers
        ),
        clean_process_override=clean_process_override_8616(
            os.environ.get("INERTIA_ENABLE_SERIAL_FORK_PER_FUNCTION")
        ),
    )
    workers = worker_policy.workers
    use_serial_fork_per_function = worker_policy.mode is FunctionWorkerMode8616.CLEAN_PROCESS
    if use_serial_fork_per_function and workers > 1:
        print(f"/* parallel function decompilation: {workers} clean processes, one function per process */")
    elif workers > 1:
        print(f"/* parallel function decompilation: {workers} workers, shared imports */")
    elif use_serial_fork_per_function:
        print("/* parallel function decompilation: disabled; using one clean serial process at a time */")
    elif forced_serial_function_decomp:
        print("/* parallel function decompilation: disabled (forced serial) */")
    else:
        print("/* parallel function decompilation: disabled (RAM pressure or single function) */")
    force_isolated_function_projects = isolated_function_decompilation_required
    typing.cast(typing.Any, project)._inertia_fast_direct_probe = bool(
            args.addr is not None
            and os.environ.get("INERTIA_FAST_DIRECT_PROBE", "").strip().lower() in {"1", "true", "yes", "on"}
            and timeout_was_explicit
            and isinstance(args.timeout, int)
            and args.timeout <= 6
        )

    if force_isolated_function_projects:
        print("/* parallel x86-16 decompilation: using one fresh analysis project per shown function for stability. */")

    allow_heavy_fallbacks = allows_heavy_fallbacks_for_run(
        interactive_stdout=interactive_stdout,
        max_functions=args.max_functions,
        addr_requested=args.addr is not None,
    )

    sweep_deadline: float | None = None
    sweep_budget_sec_raw = os.environ.get("INERTIA_SWEEP_BUDGET_SEC")
    if args.addr is None:
        sweep_budget_sec: int | None = None
        if sweep_budget_sec_raw is not None and sweep_budget_sec_raw.strip():
            try:
                sweep_budget_sec = int(sweep_budget_sec_raw.strip())
            except ValueError:
                sweep_budget_sec = None
        if sweep_budget_sec is None:
            # Default to unbounded whole-binary sweeps. Callers can opt into a
            # hard cap with INERTIA_SWEEP_BUDGET_SEC=<seconds>.
            sweep_budget_sec = 0
        if sweep_budget_sec <= 0:
            sweep_deadline = None
            print("/* sweep budget: disabled via INERTIA_SWEEP_BUDGET_SEC */")
        else:
            sweep_deadline = time.monotonic() + float(sweep_budget_sec)
            print(f"/* sweep budget: {sweep_budget_sec}s (set INERTIA_SWEEP_BUDGET_SEC=0 to disable) */")

    def _sweep_budget_exhausted() -> bool:
        return sweep_deadline is not None and time.monotonic() >= sweep_deadline

    batch_context = _BatchCliContext8616(
        args=args,
        project=project,
        function_tasks=function_tasks,
        result_map=result_map,
        fallback_tail_validation_by_index=fallback_tail_validation_by_index,
        lst_metadata=lst_metadata,
        cod_metadata=cod_metadata,
        synthetic_globals=synthetic_globals,
        visible_code_labels=visible_code_labels,
        include_library_functions=include_library_functions,
        low_memory_path=low_memory_path,
        interactive_stdout=interactive_stdout,
        precise_sidecar_regions=precise_sidecar_regions,
        timeout_was_explicit=timeout_was_explicit,
        use_serial_fork_per_function=use_serial_fork_per_function,
        allow_heavy_fallbacks=allow_heavy_fallbacks,
        force_isolated_function_projects=force_isolated_function_projects,
        sweep_deadline=sweep_deadline,
        shown_total=shown_total,
        skipped_signature_labels=skipped_signature_labels,
    )
    if workers <= 1:
        return _run_serial_batch_cli_8616(batch_context)
    decompiled = 0
    failed = 0
    emitted_indexes: set[int] = set()
    allow_isolated_retry_for_parallel_tasks = interactive_stdout or args.max_functions <= 0 or args.addr is not None
    if use_serial_fork_per_function:
        parallel_timeout_model = build_parallel_clean_worker_timeout_model(
            args.timeout,
            explicit_timeout=timeout_was_explicit,
        )
        timeout_by_index = {
            item.index: _batch_function_decompile_timeout_8616(
                batch_context,
                cast(_AngrFunction, item.function),
                parallel_timeout_model,
            )
            for item in function_tasks
        }
        executor = DaemonThreadPoolExecutor(max_workers=workers, thread_name_prefix="func-clean")
        try:
            item_by_future = {
                executor.submit(
                    _run_serial_clean_process_work_item_8616,
                    batch_context,
                    item,
                    timeout=timeout_by_index[item.index],
                ): item
                for item in prioritize_clean_function_work_8616(
                    function_tasks,
                    function_complexity=_function_complexity,
                )
            }
            pending = set(item_by_future)
            while pending:
                done, _ = wait(pending, return_when=FIRST_COMPLETED)
                for future in sorted(done, key=lambda candidate: item_by_future[candidate].index):
                    item = item_by_future[future]
                    function = cast(_AngrFunction, item.function)
                    function_timeout = timeout_by_index[item.index]
                    worker_debug = (
                        f"[dbg] clean parallel function worker: start "
                        f"{_function_work_item_recovery_addr_8616(item):#x} {function.name} "
                        f"requested_timeout={function_timeout}s "
                        f"hard_timeout={_serial_clean_worker_outer_timeout_8616(function_timeout)}s\n"
                    )
                    try:
                        result = future.result()
                    except Exception as ex:
                        result = FunctionWorkResult(
                            index=item.index,
                            status="error",
                            payload=f"Clean parallel worker failed: {_describe_exception(ex)}",
                            debug_output=worker_debug,
                            function=item.function,
                            function_cfg=item.function_cfg,
                            elapsed=float(function_timeout),
                        )
                    else:
                        result = replace(
                            result,
                            debug_output=worker_debug + result.debug_output,
                        )
                    result_map[item.index] = result
                    d, f = _emit_function_result(
                        item,
                        result,
                        project=project,
                        args=args,
                        lst_metadata=lst_metadata,
                        cod_metadata=cod_metadata,
                        synthetic_globals=synthetic_globals,
                        precise_sidecar_regions=precise_sidecar_regions,
                        allow_heavy_fallbacks=allow_heavy_fallbacks,
                        interactive_stdout=interactive_stdout,
                        use_serial_fork_per_function=use_serial_fork_per_function,
                        fallback_tail_validation_by_index=fallback_tail_validation_by_index,
                        result_state_by_index=result_map,
                        timeout_was_explicit=timeout_was_explicit,
                    )
                    decompiled += d
                    failed += f
                    emitted_indexes.add(item.index)
                    pending.discard(future)
        finally:
            executor.shutdown(wait=True, cancel_futures=False)
    else:
        executor = DaemonThreadPoolExecutor(max_workers=workers, thread_name_prefix="func")
        try:
            future_map = {
                executor.submit(
                    _run_function_work_item,
                    item,
                    timeout=args.timeout,
                    api_style=args.api_style,
                    binary_path=args.binary,
                    cod_metadata=cod_metadata,
                    synthetic_globals=synthetic_globals,
                    lst_metadata=lst_metadata,
                    enable_structured_simplify=True,
                    force_isolated_project=force_isolated_function_projects,
                    allow_isolated_retry=allow_isolated_retry_for_parallel_tasks,
                ): item
                for item in function_tasks
                if item.function_cfg is not None
            }
            pending = set(future_map)
            deadlines = {future: time.monotonic() + max(1, args.timeout) for future in future_map}
            has_expired_futures = False
            while pending:
                if _sweep_budget_exhausted():
                    for future in list(pending):
                        item = future_map[future]
                        result_map[item.index] = FunctionWorkResult(
                            index=item.index,
                            status="timeout",
                            payload="Whole-sweep budget exhausted before decompilation completed.",
                            debug_output="",
                            function=item.function,
                            function_cfg=item.function_cfg,
                            elapsed=0.0,
                            failure_stage="sweep_budget",
                            skip_heavy_fallbacks=True,
                        )
                    pending.clear()
                    has_expired_futures = True
                    break
                done, _ = wait(pending, timeout=0.25, return_when=FIRST_COMPLETED)
                if done:
                    for future in done:
                        item = future_map[future]
                        try:
                            result_map[item.index] = future.result()
                        except Exception as ex:
                            result_map[item.index] = FunctionWorkResult(
                                index=item.index,
                                status="error",
                                payload=str(ex),
                                debug_output="",
                                function=item.function,
                                function_cfg=item.function_cfg,
                            )
                        current_result = result_map.get(item.index)
                        if current_result is not None and item.index not in emitted_indexes:
                            d, f = _emit_function_result(
                                item,
                                current_result,
                                project=project,
                                args=args,
                                lst_metadata=lst_metadata,
                                cod_metadata=cod_metadata,
                                synthetic_globals=synthetic_globals,
                                precise_sidecar_regions=precise_sidecar_regions,
                                allow_heavy_fallbacks=allow_heavy_fallbacks,
                                interactive_stdout=interactive_stdout,
                                use_serial_fork_per_function=use_serial_fork_per_function,
                                fallback_tail_validation_by_index=fallback_tail_validation_by_index,
                                result_state_by_index=result_map,
                                timeout_was_explicit=timeout_was_explicit,
                            )
                            decompiled += d
                            failed += f
                            emitted_indexes.add(item.index)
                            if f and args.addr is not None:
                                _emit_tail_validation_console_summary(
                                    function_tasks, result_map, binary_path=args.binary
                                )
                                return 2
                        pending.discard(future)
                now = time.monotonic()
                expired = [future for future in pending if now >= deadlines[future]]
                for future in expired:
                    item = future_map[future]
                    if not future.done():
                        done_now, _ = wait({future}, timeout=0.0, return_when=FIRST_COMPLETED)
                        if done_now or future.done():
                            try:
                                result_map[item.index] = future.result()
                            except Exception as ex:
                                result_map[item.index] = FunctionWorkResult(
                                    index=item.index,
                                    status="error",
                                    payload=str(ex),
                                    debug_output="",
                                    function=item.function,
                                    function_cfg=item.function_cfg,
                                )
                            current_result = result_map.get(item.index)
                            if current_result is not None and item.index not in emitted_indexes:
                                d, f = _emit_function_result(
                                    item,
                                    current_result,
                                    project=project,
                                    args=args,
                                    lst_metadata=lst_metadata,
                                    cod_metadata=cod_metadata,
                                    synthetic_globals=synthetic_globals,
                                    precise_sidecar_regions=precise_sidecar_regions,
                                    allow_heavy_fallbacks=allow_heavy_fallbacks,
                                    interactive_stdout=interactive_stdout,
                                    use_serial_fork_per_function=use_serial_fork_per_function,
                                    fallback_tail_validation_by_index=fallback_tail_validation_by_index,
                                    result_state_by_index=result_map,
                                    timeout_was_explicit=timeout_was_explicit,
                                )
                                decompiled += d
                                failed += f
                                emitted_indexes.add(item.index)
                                if f and args.addr is not None:
                                    _emit_tail_validation_console_summary(
                                        function_tasks, result_map, binary_path=args.binary
                                    )
                                    return 2
                            pending.discard(future)
                            continue
                    if future.done():
                        try:
                            result_map[item.index] = future.result()
                        except Exception as ex:
                            result_map[item.index] = FunctionWorkResult(
                                index=item.index,
                                status="error",
                                payload=str(ex),
                                debug_output="",
                                function=item.function,
                                function_cfg=item.function_cfg,
                            )
                        current_result = result_map.get(item.index)
                        if current_result is not None and item.index not in emitted_indexes:
                            d, f = _emit_function_result(
                                item,
                                current_result,
                                project=project,
                                args=args,
                                lst_metadata=lst_metadata,
                                cod_metadata=cod_metadata,
                                synthetic_globals=synthetic_globals,
                                precise_sidecar_regions=precise_sidecar_regions,
                                allow_heavy_fallbacks=allow_heavy_fallbacks,
                                interactive_stdout=interactive_stdout,
                                use_serial_fork_per_function=use_serial_fork_per_function,
                                fallback_tail_validation_by_index=fallback_tail_validation_by_index,
                                result_state_by_index=result_map,
                                timeout_was_explicit=timeout_was_explicit,
                            )
                            decompiled += d
                            failed += f
                            emitted_indexes.add(item.index)
                            if f and args.addr is not None:
                                _emit_tail_validation_console_summary(
                                    function_tasks, result_map, binary_path=args.binary
                                )
                                return 2
                        pending.discard(future)
                        continue
                    result_map[item.index] = FunctionWorkResult(
                        index=item.index,
                        status="timeout",
                        payload=f"Timed out after {args.timeout}s.",
                        debug_output="",
                        function=item.function,
                        function_cfg=item.function_cfg,
                        elapsed=float(args.timeout),
                    )
                    has_expired_futures = True
                    pending.discard(future)
        finally:
            executor.shutdown(wait=not has_expired_futures, cancel_futures=True)

    return _finish_batch_cli_8616(
        batch_context,
        decompiled=decompiled,
        failed=failed,
        emitted_indexes=emitted_indexes,
    )


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
