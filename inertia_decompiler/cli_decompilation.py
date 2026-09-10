# AUTO-GENERATED split from cli_runtime_shared.py
"""Layer: CLI/fallback/reporting.

Responsibility: sequence decompilation passes, diagnostics, timeouts, and validated fallbacks.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
Guard: this CLI boundary must not become the owner of decompiler semantics.
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
import sys
import threading
import time
import traceback
import typing
import weakref
from collections import Counter
from collections.abc import Callable, Iterator, Mapping, MutableMapping
from dataclasses import dataclass
from enum import Enum, StrEnum
from pathlib import Path
from typing import Any, TypedDict, cast

import angr
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeBottom, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.analysis_helpers import (
    sanitize_direct_call_sites_8616,
    seed_calling_conventions,
    seed_wide_stack_prototype_from_binary_address_8616,
)
from angr_platforms.X86_16.annotations import (
    _apply_known_helper_signatures,
    annotate_function,
    apply_x86_16_metadata_annotations,
)
from angr_platforms.X86_16.c_ast_utils import _c_ast_cycle_path_8616
from angr_platforms.X86_16.callee_name_normalization import normalize_callee_name_8616
from angr_platforms.X86_16.cod_extract import CODProcMetadata, extract_cod_proc_metadata
from angr_platforms.X86_16.cod_known_objects import known_cod_object_spec
from angr_platforms.X86_16.codegen_metadata import (
    GlobalDeclarationArrayExtent8616,
    get_codegen_sequence_attr,
    snapshot_stack_local_candidates_8616,
)
from angr_platforms.X86_16.compiler_helpers import (
    CompilerHelperEvidenceKind8616,
    hook_x86_16_compiler_helper_at_8616,
    identify_x86_16_compiler_helper_at_8616,
    is_x86_16_stack_probe_name_8616,
)
from angr_platforms.X86_16.decompiler_postprocess_calls import (
    _replay_bound_callsite_argument_consumer_8616,
    replay_callsite_stack_arguments_after_regeneration_8616,
)
from angr_platforms.X86_16.decompiler_postprocess_simplify import _simplify_structured_expressions_8616
from angr_platforms.X86_16.decompiler_postprocess_stage import (
    _dead_code_elimination_after_flag_prune_8616,
    _materialize_missing_terminal_ax_return_8616,
    _repair_missing_cnode_codegen_metadata_8616,
    finalize_late_ast_cleanup_8616,
    finalize_post_switch_cleanup_after_seqnode_replacement_8616,
    run_callsite_stack_fact_materialization_8616,
)
from angr_platforms.X86_16.decompiler_postprocess_utils import _iter_c_nodes_deep_8616
from angr_platforms.X86_16.decompiler_structuring_stage import (
    active_structuring_function_8616,
    finalize_seqnode_switch_replay_after_replacement_8616,
    finalize_shared_call_occurrences_8616,
    finalize_typed_edge_switch_replacement_if_enabled_8616,
    prune_redundant_loop_break_carriers_after_lowering_8616,
    record_typed_edge_switch_replacement_diagnostics_8616,
    recover_structuring_canonical_for_loops_8616,
    run_direct_instruction_materialization_8616,
    seqnode_switch_replacement_changed_for_codegen_8616,
)
from angr_platforms.X86_16.ir.status_flag_lift_context import active_status_flag_lift_context_8616
from angr_platforms.X86_16.lowering.callsite_prototype_declarations import (
    materialize_callsite_prototype_declarations_8616,
)
from angr_platforms.X86_16.lowering.callsite_prototype_seeding import (
    CallsitePrototypeSeedDecision8616,
    seed_physical_callsite_prototype_8616,
)
from angr_platforms.X86_16.lowering.fact_transfer import transfer_semantic_alias_facts_to_codegen_8616
from angr_platforms.X86_16.lowering.function_pointer_parameters import (
    materialize_function_pointer_parameters_8616,
)
from angr_platforms.X86_16.lowering.real_mode_linear import (
    DirectStackMoveSourceKind8616,
    lower_stable_ss_linear_stack_dereferences_8616,
    materialize_direct_stack_mov_instructions_8616,
)
from angr_platforms.X86_16.lowering.segment_global_materialization import (
    run_segment_global_materialization_8616,
)
from angr_platforms.X86_16.lowering.segmented_global_loads import (
    SegmentedGlobalLoadStats8616,
    materialize_compare_register_global_carriers_8616,
    materialize_direct_global_symbol_stores_8616,
    materialize_indexed_segmented_global_loads_8616,
    materialize_named_segmented_global_loads_8616,
    reapply_proven_named_global_aggregate_types_8616,
    reapply_proven_stack_aggregate_field_projections_8616,
    reapply_proven_stack_aggregate_types_8616,
    reconcile_registered_named_global_aggregate_declarations_8616,
)
from angr_platforms.X86_16.lowering.segmented_memory_lowering import apply_runtime_segment_lowering_8616
from angr_platforms.X86_16.lowering.stack_aggregate_objects import (
    reapply_stack_aggregate_object_facts_8616,
)
from angr_platforms.X86_16.lowering.stack_lowering import run_stack_lowering_pass_8616
from angr_platforms.X86_16.lowering.stack_lowering_from_facts import (
    attach_cod_stack_alias_annotations_8616,
    lower_stack_accesses_from_alias_facts_8616,
)
from angr_platforms.X86_16.lowering.stack_probe_return_facts import build_typed_stack_probe_return_facts_8616
from angr_platforms.X86_16.lowering.stack_prototype_materialization import (
    reconcile_exact_stack_argument_prototype_8616,
)
from angr_platforms.X86_16.lowering.terminal_register_return_types import (
    materialize_terminal_register_return_type_8616,
)
from angr_platforms.X86_16.lst_extract import LSTMetadata
from angr_platforms.X86_16.pipeline.architecture_guard import (
    assert_final_c_quality_8616,
    final_c_has_unreachable_call_after_return_8616,
)
from angr_platforms.X86_16.pipeline.contracts import assert_pipeline_contracts_8616
from angr_platforms.X86_16.pipeline.errors import PipelineHardError
from angr_platforms.X86_16.pipeline.recovery_coverage_guard import assert_exact_instruction_coverage_8616
from angr_platforms.X86_16.pipeline.render_authority import (
    CodegenRenderAuthority8616,
    codegen_render_authority_8616,
    require_codegen_render_integrity_8616,
)
from angr_platforms.X86_16.postprocess.optimization.dce import _dead_code_elimination_8616
from angr_platforms.X86_16.recovery_instruction_coverage import collect_exact_instruction_coverage_8616
from angr_platforms.X86_16.render_compat import repair_cfunctioncall_render_targets_8616
from angr_platforms.X86_16.segmented_memory_reasoning import apply_x86_16_segmented_memory_reasoning
from angr_platforms.X86_16.stack_probe_fact_trace import (
    callsite_stack_probe_evidence_8616,
    format_stack_probe_fact_stats_8616,
)
from angr_platforms.X86_16.structuring.clinic_option_policy import enforce_x86_16_clinic_options_8616
from angr_platforms.X86_16.structuring.compare32_recovery import recover_32bit_compare_c_8616
from angr_platforms.X86_16.structuring.condition_provenance import (
    replay_codegen_structured_condition_segment_provenance_8616,
)
from angr_platforms.X86_16.structuring.loop_body_repair import repair_empty_counted_loop_body_from_evidence_8616
from angr_platforms.X86_16.structuring.simple_loop_recovery import recover_counted_stack_loop_c_8616
from angr_platforms.X86_16.tail_validation import (
    X86_16TailValidationSummary,
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
    refresh_x86_16_final_semantic_validation_8616,
    x86_16_tail_validation_result_passed,
    x86_16_tail_validation_snapshot_passed,
)

from inertia_decompiler.c_text_cleanup import normalize_unresolved_c_text
from inertia_decompiler.cli_output import (
    _timestamped_print,
)
from inertia_decompiler.cli_semantic_rollback import (
    TrustedCoreSnapshot8616,
    rollback_final_semantic_drift_8616,
    snapshot_trusted_cfunc_8616,
)
from inertia_decompiler.decompilation_quality import assess_decompiled_c_text
from inertia_decompiler.project_loading import (
    _build_project_cached,
    _describe_exception,
)
from inertia_decompiler.recompile_check import check_c_recompiles_8616
from inertia_decompiler.runtime_support import (
    DECOMPILATION_PREP_LOCK,
)
from inertia_decompiler.runtime_support import (
    AnalysisTimeout as _AnalysisTimeout,
)
from inertia_decompiler.runtime_support import (
    analysis_timeout as _analysis_timeout,
)
from inertia_decompiler.runtime_support import (
    guard_angr_ail_narrowing as _guard_angr_ail_narrowing,
)
from inertia_decompiler.runtime_support import (
    guard_angr_basepointeroffset_codegen_support as _guard_angr_basepointeroffset_codegen_support,
)
from inertia_decompiler.runtime_support import (
    guard_angr_clinic_stage_markers as _guard_angr_clinic_stage_markers,
)
from inertia_decompiler.runtime_support import (
    guard_angr_fast_post_ssa_8616 as _guard_angr_fast_post_ssa_8616,
)
from inertia_decompiler.runtime_support import (
    guard_angr_peephole_expr_bitwidth_assertion as _guard_angr_peephole_expr_bitwidth_assertion,
)
from inertia_decompiler.runtime_support import (
    guard_angr_pre_codegen_seqnode_probe as _guard_angr_pre_codegen_seqnode_probe,
)
from inertia_decompiler.runtime_support import (
    guard_angr_structurer_codegen_timing as _guard_angr_structurer_codegen_timing,
)
from inertia_decompiler.runtime_support import (
    guard_angr_structuring_codegen_internal_timing as _guard_angr_structuring_codegen_internal_timing,
)
from inertia_decompiler.runtime_support import (
    guard_angr_structuring_seqnode_stage_probe as _guard_angr_structuring_seqnode_stage_probe,
)
from inertia_decompiler.runtime_support import (
    guard_angr_tail_validation_collection_timing as _guard_angr_tail_validation_collection_timing,
)
from inertia_decompiler.runtime_support import (
    guard_angr_variable_recovery_binop_sub_size_mismatch as _guard_angr_variable_recovery_binop_sub_size_mismatch,
)
from inertia_decompiler.runtime_support import (
    run_with_timeout_in_fork as _run_with_timeout_in_fork,
)
from inertia_decompiler.runtime_support import (
    timing_output_enabled as _timing_output_enabled,
)
from inertia_decompiler.sidecar_metadata import (
    _lst_code_region,
    attach_lst_metadata_to_project,
)
from inertia_decompiler.tail_validation import (
    inherit_tail_validation_runtime_policy as _inherit_tail_validation_runtime_policy,
)
from inertia_decompiler.tail_validation import (
    tail_validation_runtime_enabled as _tail_validation_runtime_enabled,
)
from inertia_decompiler.tail_validation import (
    tail_validation_snapshot_for_function_run as _tail_validation_snapshot_for_function_run,
)
from inertia_decompiler.telemetry import annotate_current_span, span, trace_function
from inertia_decompiler.x86_16_exact_slice import (
    function_original_addr,
    mark_function_original_addr,
)

from .cli_c_ast_rewrites import (
    _attach_access_trait_field_names,
    _attach_cod_global_declaration_names,
    _attach_cod_global_declaration_types,
    _attach_cod_global_names,
    _attach_cod_variable_names,
    _attach_lst_data_names,
    _attach_pointer_member_names,
    _attach_register_names,
    _attach_segment_register_names,
    _attach_ss_stack_variables,
    _canonicalize_stack_cvars,
    _coalesce_cod_word_global_loads,
    _coalesce_cod_word_global_statements,
    _coalesce_far_pointer_stack_expressions,
    _coalesce_linear_recurrence_statements,
    _coalesce_segmented_word_load_expressions,
    _collect_access_traits,
    _dedupe_codegen_variable_names_8616,
    _elide_redundant_segment_pointer_dereferences,
    _iter_c_nodes_deep,
    _materialize_missing_register_local_declarations,
    _materialize_missing_stack_local_declarations,
    _normalize_scalar_byte_register_types,
    _prune_dead_local_assignments,
    _prune_tiny_wrapper_staging_locals,
    _prune_unused_local_declarations,
    _prune_unused_unnamed_memory_declarations,
    _prune_void_function_return_values,
    _rewrite_ss_stack_byte_offsets,
    _run_typed_widening_pass,
    _simplify_basic_algebraic_identities,
    _simplify_nested_mk_fp_calls,
    _simplify_structured_c_expressions,
)
from .cli_c_text_postprocess import (
    _annotate_cod_proc_output,
    _collapse_annotated_stack_aliases_text,
    _collapse_duplicate_type_keywords_text,
    _dedupe_adjacent_prototype_lines,
    _dedupe_conflicting_extern_variable_declarations_text,
    _dedupe_duplicate_local_declarations_text,
    _format_known_helper_calls,
    _hoist_c89_local_declarations_text,
    _materialize_annotated_cod_declarations_text,
    _materialize_missing_direct_call_prototypes_text,
    _materialize_missing_g_hex_externs_text,
    _materialize_missing_generic_local_declarations_text,
    _materialize_missing_segment_macro_locals_text,
    _materialize_missing_synthetic_global_declarations_text,
    _materialize_opaque_pointer_typedefs_text,
    _materialize_stack_base_placeholder_declaration_text,
    _normalize_anonymous_call_targets,
    _normalize_boolean_conditions,
    _normalize_concat_zero_text,
    _normalize_function_signature_arg_names,
    _normalize_integer_dereference_stores_text,
    _normalize_msc_signed_int_function_signature_text,
    _normalize_portable_flat_main_signature_text,
    _normalize_scalar_assigned_extern_arrays_text,
    _normalize_scalar_gb_array_declarations_text,
    _normalize_seg_offset_void_pointer_args_text,
    _normalize_shift_add_precedence_in_assignments,
    _normalize_signed_char_function_signature_text,
    _normalize_spurious_duplicate_local_suffixes,
    _normalize_unary_not_shift_precedence_text,
    _prune_dead_stack_base_assignments_text,
    _prune_invalid_simple_function_prototypes_text,
    _prune_non_lvalue_arithmetic_assignments,
    _prune_parameter_shadow_declarations_text,
    _prune_standalone_stack_probe_calls_text,
    _prune_trailing_generic_return_text,
    _prune_undefined_fragment_carrier_assignments_text,
    _prune_unused_local_declarations_text,
    _prune_unused_staging_assignments,
    _prune_void_call_assignments_text,
    _prune_void_function_return_values_text,
    _prune_weaker_conflicting_prototypes_text,
    _rewrite_known_helper_signature_text,
    _sanitize_mangled_autonames_text,
    _simplify_x86_16_stack_byte_pointers,
    _strip_register_fragment_suffixes_text,
)
from .cli_function_discovery import (
    _addr_in_ranges,
    _function_covered_ranges,
    _recover_candidate_function_pair,
)
from .cli_interrupt_modeling import (
    _attach_dos_pseudo_callees,
    _attach_interrupt_wrapper_callees,
    _lower_interrupt_wrapper_result_reads,
)
from .direct_addr_failure_family import (
    FailureFamilyState,
    advance_failure_family_state,
    build_failure_family_snapshot,
    record_failure_family_retry_stop,
    remember_failure_family_candidate,
)
from .direct_addr_stage_bundle import DirectAddrStageBundleInput, write_direct_addr_stage_bundle
from .disassembly_helpers import _format_asm_range, _infer_linear_disassembly_window
from .msc51_local_hash import emit_msc51_diagnostic

print: Callable[..., None] = _timestamped_print
__all__ = [
    "_apply_binary_specific_annotations",
    "_apply_function_annotations_for_active_and_original_8616",
    "_apply_known_cod_object_annotations",
    "_decompile_function",
    "_decompile_function_with_stats",
    "_direct_call_stub_filter_regions",
    "_emit_optional_source_sidecar_c_block",
    "_format_minimal_codegen_output",
    "_function_complexity",
    "_function_decompilation_profile",
    "_preferred_decompiler_options",
    "_preferred_expr_collapse_depth",
    "_prepare_function_for_decompilation",
    "_regenerate_codegen_text_safely",
    "_register_direct_call_target_function_stubs",
    "_sidecar_cod_metadata_for_function",
    "_snapshot_codegen_text",
]


def _normalize_text_payload_8616(payload: object) -> str:
    """Coerce arbitrary codegen payloads into stable text for emission."""
    if payload is None:
        return ""
    if isinstance(payload, tuple) and payload:
        return _normalize_text_payload_8616(payload[0])
    if isinstance(payload, bytes):
        text = payload.decode("utf-8", errors="ignore")
    elif isinstance(payload, str):
        text = payload
    else:
        text = str(payload)
    if "\x00" in text:
        text = text.replace("\x00", "")
    return text


def _effective_decompile_timeout_8616(
    project: angr.Project,
    timeout: int,
    *,
    block_count: int,
    byte_count: int,
) -> int:
    effective_timeout = int(timeout)
    if getattr(getattr(project, "arch", None), "name", "") == "86_16":
        if byte_count >= 320 or block_count >= 48:
            effective_timeout = max(effective_timeout, 40)
        elif byte_count >= 160 or block_count >= 24:
            effective_timeout = max(effective_timeout, 24)
        elif byte_count >= 64 or block_count >= 8:
            # Mid-sized 16-bit procedures frequently need more than 14s once
            # structuring + postprocess + validation are all enabled.
            effective_timeout = max(effective_timeout, 24)
    return effective_timeout


def _forced_corpus_templates_enabled() -> bool:
    return False


def _forced_function_template(
    function_name: str | None, binary_path: Path | None = None, api_style: str | None = None
) -> str | None:
    return None

def _apply_binary_specific_annotations(
    project: angr.Project,
    binary_path: Path | None,
    lst_metadata: LSTMetadata | None,
    *,
    func_addr: int | None = None,
    cod_metadata: CODProcMetadata | None = None,
    synthetic_globals: dict[int, tuple[str, int]] | None = None,
) -> bool:
    changed = False
    if func_addr is None:
        if cod_metadata is not None:
            changed |= _apply_known_helper_signatures(project, cod_metadata)
        return changed

    if cod_metadata is not None:
        # Dynamic angr/codegen compatibility boundary.
        metadata_by_addr = getattr(project, "_inertia_cod_metadata_by_func_addr_8616", None)
        if not isinstance(metadata_by_addr, dict):
            metadata_by_addr = {}
            # Dynamic angr/codegen compatibility boundary.
            typing.cast(typing.Any, project)._inertia_cod_metadata_by_func_addr_8616 = metadata_by_addr
        metadata_by_addr[func_addr] = cod_metadata

    if lst_metadata is not None or cod_metadata is not None or synthetic_globals:
        changed = apply_x86_16_metadata_annotations(
            project,
            func_addr=func_addr,
            cod_metadata=cod_metadata,
            lst_metadata=lst_metadata,
            synthetic_globals=synthetic_globals,
        )
    return bool(changed)


def _apply_function_annotations_for_active_and_original_8616(
    project: angr.Project,
    binary_path: Path | None,
    lst_metadata: LSTMetadata | None,
    function: object,
    *,
    cod_metadata: CODProcMetadata | None = None,
    synthetic_globals: dict[int, tuple[str, int]] | None = None,
) -> bool:
    original_addr = function_original_addr(function)
    if os.environ.get("INERTIA_DEBUG_X87_PROTO") == "1":
        print(
            "[dbg-x87-proto] "
            f"apply_function_annotations active={getattr(function, 'addr', None)!r} "
            f"original={original_addr!r} "
            f"name={getattr(function, 'name', None)!r} "
            f"project_id={id(project)} "
            f"function_project_id={id(getattr(function, 'project', None)) if getattr(function, 'project', None) is not None else None} "
            f"cod_source_lines={len(tuple(getattr(cod_metadata, 'source_lines', ()) or ())) if cod_metadata is not None else 0}",
            file=sys.stderr,
            flush=True,
        )
    if cod_metadata is not None:
        metadata_by_addr = getattr(project, "_inertia_cod_metadata_by_func_addr_8616", None)
        if not isinstance(metadata_by_addr, dict):
            metadata_by_addr = {}
            typing.cast(typing.Any, project)._inertia_cod_metadata_by_func_addr_8616 = metadata_by_addr
        metadata_by_addr[original_addr] = cod_metadata
        attach_cod_stack_alias_annotations_8616(project, original_addr, cod_metadata)
        active_addr = getattr(function, "addr", None)
        if isinstance(active_addr, int):
            metadata_by_addr[active_addr] = cod_metadata
            attach_cod_stack_alias_annotations_8616(project, active_addr, cod_metadata)
    changed = bool(
        _apply_binary_specific_annotations(
            project,
            binary_path,
            lst_metadata,
            func_addr=original_addr,
            cod_metadata=cod_metadata,
            synthetic_globals=synthetic_globals,
        )
    )
    active_addr = getattr(function, "addr", None)
    if isinstance(active_addr, int) and active_addr != original_addr:
        changed = bool(changed) | bool(
            _apply_binary_specific_annotations(
                project,
                binary_path,
                lst_metadata,
                func_addr=active_addr,
                cod_metadata=cod_metadata,
                synthetic_globals=synthetic_globals,
            )
        )
    if os.environ.get("INERTIA_DEBUG_X87_PROTO") == "1":
        functions = getattr(getattr(project, "kb", None), "functions", None)
        for label, addr in (("original", original_addr), ("active", active_addr)):
            if not isinstance(addr, int) or functions is None:
                continue
            try:
                func = functions.function(addr=addr, create=False)
            except Exception:
                func = None
            info = getattr(func, "info", None)
            annotations = info.get("x86_16_annotations") if isinstance(info, MutableMapping) else None
            print(
                "[dbg-x87-proto] "
                f"annotation_state {label}={addr!r} "
                f"func_id={id(func) if func is not None else None} "
                f"source_lines={len(tuple(annotations.get('source_lines', ()) or ())) if isinstance(annotations, dict) else 0} "
                f"stack_offsets={sorted(k for k in annotations.get('stack_vars', {}) if isinstance(k, int)) if isinstance(annotations, dict) else []}",
                file=sys.stderr,
                flush=True,
            )
    return bool(changed)


def _sync_recovered_function_metadata_from_kb_8616(project: angr.Project, function: object) -> bool:
    """Bounded CFG recovery can hand the decompiler a Function object that is not
    the same object as project.kb.functions[addr].  Metadata annotations are
    applied to the KB function, so copy that evidence onto the recovered object
    before angr consumes the function type.
    """
    function_dynamic = cast(Any, function)
    addr = getattr(function_dynamic, "addr", None)
    if not isinstance(addr, int):
        return False
    functions = getattr(getattr(project, "kb", None), "functions", None)
    if functions is None:
        return False
    try:
        source = functions.function(addr=addr, create=False)
    except Exception:
        return False
    if source is None or source is function:
        return False

    changed = False
    stats = getattr(project, "_inertia_function_metadata_sync_stats", None)
    if not isinstance(stats, dict):
        stats = {
            "candidates": 0,
            "name_synced": 0,
            "info_synced": 0,
        }
        typing.cast(typing.Any, project)._inertia_function_metadata_sync_stats = stats
    stats["candidates"] = int(stats.get("candidates", 0) or 0) + 1

    source_name = getattr(source, "name", None)
    current_name = getattr(function, "name", None)
    if isinstance(source_name, str) and source_name and source_name != current_name:
        current_is_generic = not isinstance(current_name, str) or not current_name or current_name.startswith("sub_")
        if current_is_generic:
            function_dynamic.name = source_name
            stats["name_synced"] = int(stats.get("name_synced", 0) or 0) + 1
            changed = True

    source_info = getattr(source, "info", None)
    if isinstance(source_info, MutableMapping) and source_info:
        target_info = getattr(function, "info", None)
        if not isinstance(target_info, MutableMapping):
            function_dynamic.info = copy.deepcopy(source_info)
            stats["info_synced"] = int(stats.get("info_synced", 0) or 0) + 1
            changed = True
        else:
            before = copy.deepcopy(target_info)
            for key, value in source_info.items():
                if key not in target_info:
                    target_info[key] = copy.deepcopy(value)
                elif key == "x86_16_annotations" and isinstance(target_info.get(key), dict) and isinstance(value, dict):
                    target_annotations = target_info[key]
                    incoming_annotations = copy.deepcopy(value)
                    for annotation_key, annotation_value in incoming_annotations.items():
                        if annotation_key in {"source_lines", "source_return_lines"}:
                            if annotation_value or annotation_key not in target_annotations:
                                target_annotations[annotation_key] = annotation_value
                            continue
                        if (
                            annotation_key in {"stack_vars", "global_vars"}
                            and isinstance(target_annotations.get(annotation_key), dict)
                            and isinstance(annotation_value, dict)
                        ):
                            target_annotations[annotation_key].update(annotation_value)
                            continue
                        target_annotations[annotation_key] = annotation_value
            if target_info != before:
                stats["info_synced"] = int(stats.get("info_synced", 0) or 0) + 1
                changed = True

    return changed


def _sidecar_cod_metadata_for_function(
    project: angr.Project,
    function: object,
    binary_path: Path | None,
    lst_metadata: LSTMetadata | None,
) -> CODProcMetadata | None:
    def _impl() -> CODProcMetadata | None:
        metadata_by_addr = getattr(project, "_inertia_cod_metadata_by_func_addr_8616", None)
        if isinstance(metadata_by_addr, Mapping):
            for addr in (function_original_addr(function), getattr(function, "addr", None)):
                if isinstance(addr, int):
                    cached_metadata = metadata_by_addr.get(addr)
                    if isinstance(cached_metadata, CODProcMetadata):
                        return cached_metadata

        active_lst_metadata = lst_metadata
        if active_lst_metadata is None:
            candidate_metadata = getattr(project, "_inertia_lst_metadata", None)
            if getattr(candidate_metadata, "cod_path", None):
                active_lst_metadata = candidate_metadata
        if binary_path is None or active_lst_metadata is None or not active_lst_metadata.cod_path:
            return None
        cod_proc_kinds = getattr(active_lst_metadata, "cod_proc_kinds", {}) or {}
        proc_kind = (
            cod_proc_kinds.get(function_original_addr(function))
            or cod_proc_kinds.get(getattr(function, "addr", None))
            or "NEAR"
        ).upper()
        name_candidates = []
        function_name = getattr(function, "name", "") or ""
        if function_name:
            name_candidates.append(function_name)
            if not function_name.startswith("_"):
                name_candidates.append(f"_{function_name}")
            else:
                name_candidates.append(function_name.lstrip("_"))
        cod_path = Path(active_lst_metadata.cod_path)
        cache = getattr(project, "_inertia_sidecar_cod_metadata_cache", None)
        if not isinstance(cache, dict):
            cache = {}
            typing.cast(typing.Any, project)._inertia_sidecar_cod_metadata_cache = cache
        for candidate in name_candidates:
            cache_key = (str(cod_path), candidate, proc_kind)
            if cache_key in cache:
                return cache[cache_key]
            try:
                metadata = extract_cod_proc_metadata(cod_path, candidate, proc_kind)
            except Exception as ex:
                logging.getLogger(__name__).debug(
                    "COD metadata extraction failed path=%s candidate=%s kind=%s: %s",
                    cod_path,
                    candidate,
                    proc_kind,
                    ex,
                )
                continue
            cache[cache_key] = metadata
            return metadata
        return None

    return _impl()


def _snapshot_codegen_text(codegen: object) -> str:
    codegen_dynamic = cast(Any, codegen)
    try:
        return _normalize_text_payload_8616(codegen_dynamic.text)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Codegen text snapshot failed at function=%#x stage=snapshot-text: %s",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            ex,
        )
        return ""


def _function_header_arg_count_8616(c_text: str) -> int | None:
    """Return the first function header argument count from generated C text."""
    match = re.search(r"^\s*[A-Za-z_][\w\s\*]*\s+[A-Za-z_]\w*\s*\((?P<args>[^)]*)\)", c_text, re.MULTILINE)
    if match is None:
        return None
    args = match.group("args").strip()
    if not args or args == "void":
        return 0
    return len([part for part in args.split(",") if part.strip()])


def _has_synthetic_split_signature_args_8616(c_text: str) -> bool:
    """Return true when a rendered function header exposes split word arguments."""
    match = re.search(r"^\s*[A-Za-z_][\w\s\*]*\s+[A-Za-z_]\w*\s*\((?P<args>[^)]*)\)", c_text, re.MULTILINE)
    if match is None:
        return False
    return re.search(r"\b[A-Za-z_]\w*_\d+(?:_\d+)?\b", match.group("args")) is not None


def _evidence_recovery_has_better_source_abi_8616(formatted: str, evidence_recovered_c: str) -> bool:
    """Return true when binary-evidence recovery has a simpler source ABI."""
    formatted_count = _function_header_arg_count_8616(formatted)
    evidence_count = _function_header_arg_count_8616(evidence_recovered_c)
    if formatted_count is None or evidence_count is None:
        return False
    return evidence_count < formatted_count and _has_synthetic_split_signature_args_8616(formatted)


def _select_evidence_recovered_c_8616(
    formatted: str,
    evidence_recovered_c: str | None,
    *,
    prefer_proven_evidence: bool = False,
) -> str:
    """Select proven source-shaped recovery when the structured output is incomplete."""
    if not isinstance(evidence_recovered_c, str) or not evidence_recovered_c.strip():
        return formatted
    if not isinstance(formatted, str) or not formatted.strip():
        return evidence_recovered_c
    quality = assess_decompiled_c_text(formatted)
    if quality.reject_as_decompiled:
        return evidence_recovered_c
    if prefer_proven_evidence:
        return evidence_recovered_c
    if _evidence_recovery_has_better_source_abi_8616(formatted, evidence_recovered_c):
        return evidence_recovered_c
    return formatted


def _bind_codegen_render_variable_types_8616(codegen: object) -> None:
    def _impl() -> None:
        project = getattr(codegen, "project", None)
        arch = getattr(project, "arch", None)
        cfunc = getattr(codegen, "cfunc", None)
        if arch is None or cfunc is None:
            return

        def _bind_type(type_: object) -> object:
            if type(type_) is SimTypeBottom:
                try:
                    return SimTypeShort(False).with_arch(arch)
                except Exception:
                    return SimTypeShort(False)
            if type_ is None or getattr(type_, "_arch", None) is not None or not hasattr(type_, "with_arch"):
                return type_
            try:
                return cast(Any, type_).with_arch(arch)
            except Exception:
                return type_

        variables_in_use = getattr(cfunc, "variables_in_use", None)
        if isinstance(variables_in_use, dict):
            for cvar in variables_in_use.values():
                bound = _bind_type(getattr(cvar, "variable_type", None))
                if bound is not getattr(cvar, "variable_type", None):
                    cvar.variable_type = bound

        unified_locals = getattr(cfunc, "unified_local_vars", None)
        if isinstance(unified_locals, dict):
            for variable, entries in list(unified_locals.items()):
                if not isinstance(entries, set):
                    continue
                rebuilt = set()
                changed = False
                for cvar, vartype in entries:
                    bound = _bind_type(vartype)
                    changed = changed or (bound is not vartype)
                    if bound is not getattr(cvar, "variable_type", None):
                        cvar.variable_type = bound
                    rebuilt.add((cvar, bound))
                if changed:
                    unified_locals[variable] = rebuilt

    return _impl()


_LAYER_DUMP_MUTEX = threading.Lock()

_LAYER_DUMP_STATE_ATTR = "_inertia_layer_dump_states"


class _LayerDumpStatus(StrEnum):
    skipped = "skipped"
    written = "written"
    failed = "failed"


class _LayerDumpState(TypedDict):
    """Typed state shared by opt-in per-layer diagnostic snapshots."""

    attempt: int
    function_addr: int
    function_name: str
    root: Path
    manifest: Path
    index: int


def _layer_dump_enabled(project: angr.Project) -> bool:
    enabled = bool(getattr(project, "_inertia_dump_layers", False))
    if not enabled:
        enabled = os.environ.get("INERTIA_DUMP_LAYERS", "").strip().lower() in {"1", "true", "yes", "on"}
    return bool(enabled)


def _layer_dump_root(project: angr.Project) -> Path:
    raw_root = getattr(project, "_inertia_dump_layer_root", None)
    if isinstance(raw_root, Path):
        return raw_root
    if isinstance(raw_root, str) and raw_root:
        return Path(raw_root)
    return Path("angr_platforms/.cache/decompilation_layers")


def _layer_dump_filter(project: angr.Project) -> tuple[str, ...]:
    raw = getattr(project, "_inertia_dump_layer_filter", None)
    if raw is None:
        raw = os.environ.get("INERTIA_DUMP_LAYER_FILTER", "")
    if not isinstance(raw, str):
        return ()
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def _layer_dump_accepts_label(project: angr.Project, label: str) -> bool:
    filter_layers = _layer_dump_filter(project)
    if not filter_layers:
        return True
    return label in filter_layers


def _safe_path_component(text: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]", "_", str(text))
    cleaned = cleaned.strip("._-")
    return cleaned or "x"


def _get_layer_dump_state(project: angr.Project, function: object) -> _LayerDumpState | None:
    if not _layer_dump_enabled(project):
        return None
    with _LAYER_DUMP_MUTEX:
        states = getattr(project, _LAYER_DUMP_STATE_ATTR, None)
        if not isinstance(states, dict):
            states = cast(dict[int, _LayerDumpState], {})
            setattr(project, _LAYER_DUMP_STATE_ATTR, states)
        states = cast(dict[int, _LayerDumpState], states)

        attempts = getattr(project, "_inertia_dump_layer_attempts", None)
        if not isinstance(attempts, dict):
            attempts = cast(dict[int, int], {})
            typing.cast(typing.Any, project)._inertia_dump_layer_attempts = attempts
        attempts = cast(dict[int, int], attempts)

        display_addr = function_original_addr(function)
        key = int(display_addr)
        attempts[key] = int(attempts.get(key, 0)) + 1
        attempt = attempts[key]

        root = _layer_dump_root(project).expanduser().resolve()
        root.mkdir(parents=True, exist_ok=True)

        display_name = _safe_path_component(getattr(function, "name", "sub"))
        fn_root = root / f"{display_addr:#x}_{display_name}_{attempt:02d}"
        if fn_root.exists():
            while True:
                attempts[key] = int(attempts.get(key, 0)) + 1
                attempt = attempts[key]
                fn_root = root / f"{display_addr:#x}_{display_name}_{attempt:02d}"
                if not fn_root.exists():
                    break

        fn_root.mkdir(parents=True, exist_ok=True)

        state: _LayerDumpState = {
            "attempt": attempt,
            "function_addr": key,
            "function_name": display_name,
            "root": fn_root,
            "manifest": fn_root / "manifest.jsonl",
            "index": 0,
        }
        states[key] = state
        return state


def _record_layer_dump(
    project: angr.Project,
    function: object,
    stage_name: str,
    text: str,
    *,
    layer_dump_state: _LayerDumpState | None = None,
) -> None:
    if not _layer_dump_enabled(project):
        return
    if layer_dump_state is None:
        return
    if not _layer_dump_accepts_label(project, stage_name):
        return

    stage_index = int(layer_dump_state.get("index", 0)) + 1
    layer_dump_state["index"] = stage_index
    stage_path = Path(layer_dump_state["root"]) / f"{stage_index:04d}_{_safe_path_component(stage_name)}.c"
    manifest_path = Path(layer_dump_state["manifest"])

    entry = {
        "status": _LayerDumpStatus.skipped.value,
        "index": stage_index,
        "layer": stage_name,
        "attempt": int(layer_dump_state.get("attempt", 0)),
        "function_addr": layer_dump_state.get("function_addr", function_original_addr(function)),
        "function_name": layer_dump_state.get("function_name", _safe_path_component(getattr(function, "name", "sub"))),
        "path": str(stage_path),
        "bytes": 0,
    }
    text = _normalize_text_payload_8616(text)
    if not text.strip():
        try:
            with manifest_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(entry, sort_keys=True) + "\n")
        except Exception:
            pass
        return

    payload = text if text.endswith("\n") else text + "\n"
    try:
        stage_path.write_text(payload, encoding="utf-8")
        entry.update(
            {
                "status": _LayerDumpStatus.written.value,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest(),
            }
        )
    except Exception as ex:
        entry["status"] = _LayerDumpStatus.failed.value
        entry["error"] = str(ex)

    try:
        with manifest_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(entry, sort_keys=True) + "\n")
    except Exception:
        pass


def _latest_layer_dump_text_8616(
    layer_dump_state: _LayerDumpState | None,
    labels: tuple[str, ...],
) -> str | None:
    if not layer_dump_state or not labels:
        return None
    manifest_path = Path(layer_dump_state.get("manifest", ""))
    if not manifest_path.exists():
        return None
    try:
        entries = [json.loads(line) for line in manifest_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except Exception:
        return None
    label_set = set(labels)
    for entry in reversed(entries):
        if entry.get("layer") not in label_set or entry.get("status") != _LayerDumpStatus.written.value:
            continue
        path = Path(str(entry.get("path", "")))
        if not path.exists():
            continue
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return None
    return None


def _cod_window_for_stage_bundle_8616(cod_metadata: CODProcMetadata | None) -> str | None:
    if cod_metadata is None:
        return None
    lines: tuple[object, ...] = tuple(cod_metadata.source_lines)
    if lines:
        return "\n".join(str(line) for line in lines) + "\n"
    raw_entries: tuple[object, ...] = tuple(cod_metadata.cod_raw_entries)
    if raw_entries:
        rendered: list[str] = []
        for entry in raw_entries:
            if not isinstance(entry, Mapping):
                continue
            offset = entry.get("offset")
            text = entry.get("text")
            rendered.append(f"{offset!r}: {text!s}")
        if rendered:
            return "\n".join(rendered) + "\n"
    return None


def _raw_asm_for_stage_bundle_8616(
    project: angr.Project,
    function: object,
    lst_metadata: LSTMetadata | None,
) -> str | None:
    display_addr = function_original_addr(function)
    region = _lst_code_region(lst_metadata, display_addr) if lst_metadata is not None else None
    try:
        if region is not None:
            return str(_format_asm_range(project, region[0], region[1]))
        # Dynamic angr/codegen compatibility boundary.
        start, end = _infer_linear_disassembly_window(project, getattr(function, "addr", display_addr))
        return str(_format_asm_range(project, start, end))
    except Exception:
        return None


def _emit_direct_addr_stage_bundle_8616(
    project: angr.Project,
    function: object,
    *,
    binary_path: Path | None,
    cod_metadata: CODProcMetadata | None,
    lst_metadata: LSTMetadata | None,
    family_label: str,
    lane: str,
    detail: str,
    repeat_reason: str | None,
    layer_dump_state: _LayerDumpState | None,
    messages: tuple[str, ...] = (),
) -> None:
    if repeat_reason is None:
        return
    request = DirectAddrStageBundleInput(
        binary_path=binary_path,
        function_addr=function_original_addr(function),
        # Dynamic angr/codegen compatibility boundary.
        function_name=str(getattr(function, "name", "sub")),
        family_label=family_label,
        raw_asm=_raw_asm_for_stage_bundle_8616(project, function, lst_metadata),
        cod_window=_cod_window_for_stage_bundle_8616(cod_metadata),
        raw_codegen=_latest_layer_dump_text_8616(layer_dump_state, ("post-structured-codegen",)),
        post_callsite=_latest_layer_dump_text_8616(
            layer_dump_state,
            ("post-cod-annotation", "post-helper-call-format", "post-helper-signature-rewrite"),
        ),
        post_stack_lowering=_latest_layer_dump_text_8616(
            layer_dump_state,
            (
                "post-stack-lowering",
                "post-stack-rewrite",
                "post-fact-backed-stack-rewrite",
                "post-structured-codegen",
            ),
        ),
        final_stdout=f"[dbg] stop: {repeat_reason}; lane={lane}\n{detail}\n",
        final_stderr="\n".join(messages) + ("\n" if messages else ""),
    )
    try:
        result = write_direct_addr_stage_bundle(request)
    except Exception as ex:
        print(f"[dbg] direct stage bundle failed: {ex}", file=sys.stderr, flush=True)
        return
    # Dynamic angr/codegen compatibility boundary.
    printed = getattr(project, "_inertia_direct_stage_bundle_printed", None)
    if not isinstance(printed, set):
        printed = set()
        # Dynamic angr/codegen compatibility boundary.
        typing.cast(typing.Any, project)._inertia_direct_stage_bundle_printed = printed
    path_text = str(result.path)
    if path_text in printed:
        return
    printed.add(path_text)
    reused = " reused" if result.reused else ""
    print(f"[dbg] direct stage bundle{reused}: {result.path}", flush=True)


def _emit_c_stage_trace(
    project: angr.Project,
    function: object,
    label: str,
    c_text: str,
    *,
    layer_dump_state: _LayerDumpState | None = None,
) -> None:
    """Emit opt-in C snapshot headers to stderr.

    Full per-stage C bodies are disabled by default to avoid noisy
    duplication. Set INERTIA_TRACE_C_STAGES_FULL=1 to enable them.
    """
    c_text = _normalize_text_payload_8616(c_text)
    if not bool(getattr(project, "_inertia_trace_c_stages", False)):
        _record_layer_dump(project, function, label, c_text, layer_dump_state=layer_dump_state)
        return
    if not c_text.strip():
        _record_layer_dump(project, function, f"{label}:skipped", c_text, layer_dump_state=layer_dump_state)
        return
    display_addr = function_original_addr(function)
    print(
        f"/* -- c trace: {display_addr:#x} {getattr(function, 'name', 'sub')} :: {label} -- */",
        file=sys.stderr,
    )
    if bool(int(os.environ.get("INERTIA_TRACE_C_STAGES_FULL", "0"))):
        print(c_text if c_text.endswith("\n") else c_text + "\n", file=sys.stderr)
    _record_layer_dump(project, function, label, c_text, layer_dump_state=layer_dump_state)
    sys.stderr.flush()


def _emit_typed_edge_switch_replacement_safety_stats_8616(codegen: object) -> None:
    """Report latest switch outcomes and ordered history without aggregating attempts."""
    if os.environ.get("INERTIA_ENABLE_TYPED_SWITCH_AST_ARTIFACTS") != "1":
        return
    with contextlib.suppress(Exception):
        record_typed_edge_switch_replacement_diagnostics_8616(codegen)
    print(
        "[structuring-pass-status] "
        + json.dumps(
            {
                # Dynamic angr/codegen compatibility boundary.
                "failed": bool(getattr(codegen, "_inertia_structuring_failed", False)),
                # Dynamic angr/codegen compatibility boundary.
                "failure_error": getattr(codegen, "_inertia_structuring_failure_error", None),
                # Dynamic angr/codegen compatibility boundary.
                "failure_pass": getattr(codegen, "_inertia_structuring_failure_pass", None),
                # Dynamic angr/codegen compatibility boundary.
                "grouped_error": getattr(codegen, "_inertia_grouped_structuring_error_8616", None),
                # Dynamic angr/codegen compatibility boundary.
                "has_clinic": bool(getattr(codegen, "_clinic", None) is not None),
                # Dynamic angr/codegen compatibility boundary.
                "passes": list(getattr(codegen, "_inertia_structuring_passes", ()) or ()),
            },
            sort_keys=True,
        ),
        file=sys.stderr,
        flush=True,
    )
    # Dynamic angr/codegen compatibility boundary.
    grouped_stats = getattr(codegen, "_inertia_grouped_structuring_stats_8616", None)
    if isinstance(grouped_stats, Mapping):
        initial_graph_summary = grouped_stats.get("initial_graph_summary", {})
        final_graph_summary = grouped_stats.get("final_graph_summary", {})
        if not isinstance(initial_graph_summary, Mapping):
            initial_graph_summary = {}
        if not isinstance(final_graph_summary, Mapping):
            final_graph_summary = {}
        print(
            "[grouped-structuring-stats] "
            + json.dumps(
                {
                    "edge_guard_switches_detected": int(
                        grouped_stats.get("edge_guard_switches_detected", 0) or 0
                    ),
                    "final_node_count": int(grouped_stats.get("final_node_count", 0) or 0),
                    "initial_eq_guarded_regions": int(initial_graph_summary.get("eq_guarded_regions", 0) or 0),
                    "initial_guarded_regions": int(initial_graph_summary.get("guarded_regions", 0) or 0),
                    "initial_two_way_heads_with_eq_guarded_successor": int(
                        initial_graph_summary.get("two_way_heads_with_eq_guarded_successor", 0) or 0
                    ),
                    "final_eq_guarded_regions": int(final_graph_summary.get("eq_guarded_regions", 0) or 0),
                    "final_guarded_regions": int(final_graph_summary.get("guarded_regions", 0) or 0),
                    "regions_reduced": int(grouped_stats.get("regions_reduced", 0) or 0),
                    "sequences_created": int(grouped_stats.get("sequences_created", 0) or 0),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
            flush=True,
        )
        if os.environ.get("INERTIA_DEBUG_TYPED_SWITCH_GRAPH") == "1":
            print(
                "[grouped-structuring-sample] "
                + json.dumps(
                    {
                        "candidate_heads": list(initial_graph_summary.get("candidate_heads", ()) or ()),
                        "initial": list(initial_graph_summary.get("sample_regions", ()) or ()),
                        "final": list(final_graph_summary.get("sample_regions", ()) or ()),
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
                flush=True,
            )
    # Dynamic angr/codegen compatibility boundary.
    project = getattr(codegen, "project", None)
    # Dynamic angr/codegen compatibility boundary.
    pre_codegen_records = getattr(project, "_inertia_pre_codegen_seqnode_probe_8616", None)
    if isinstance(pre_codegen_records, list) and pre_codegen_records:
        latest_probe = pre_codegen_records[-1]
        if isinstance(latest_probe, Mapping):
            stage_mapping_summaries = []
            for record in list(latest_probe.get("pre_codegen_structuring_stage_mappings", ()) or ())[:6]:
                if not isinstance(record, Mapping):
                    continue
                mappings = list(record.get("grouped_switch_artifact_mappings", ()) or ())
                first_mapping = mappings[0] if mappings and isinstance(mappings[0], Mapping) else {}
                stage_mapping_summaries.append(
                    {
                        "expanded_root_body_mapping_status": first_mapping.get("expanded_root_body_mapping_status"),
                        "expanded_root_body_shape_status": first_mapping.get("expanded_root_body_shape_status"),
                        "expanded_root_common_parent_path": list(
                            first_mapping.get("expanded_root_common_parent_path", ()) or ()
                        ),
                        "expanded_root_direct_sibling_span": bool(
                            first_mapping.get("expanded_root_direct_sibling_span", False)
                        ),
                        "expanded_root_external_default_owner_path": list(
                            record.get("expanded_root_external_default_owner_path", ()) or ()
                        ),
                        "expanded_root_ladder_owner_path": list(
                            record.get("expanded_root_ladder_owner_path", ()) or ()
                        ),
                        "expanded_root_loop_internal_body_mapping_status": record.get(
                            "expanded_root_loop_internal_body_mapping_status"
                        ),
                        "expanded_root_loop_internal_body_shape_status": record.get(
                            "expanded_root_loop_internal_body_shape_status"
                        ),
                        "expanded_root_loop_exit_default_relation": dict(
                            record.get("expanded_root_loop_exit_default_relation", {}) or {}
                        ),
                        "expanded_root_loop_preserving_materialization_plan": dict(
                            record.get("expanded_root_loop_preserving_materialization_plan", {}) or {}
                        ),
                        "expanded_root_loop_internal_external_default_owner_path": list(
                            record.get("expanded_root_loop_internal_external_default_owner_path", ()) or ()
                        ),
                        "expanded_root_loop_internal_ladder_owner_path": list(
                            record.get("expanded_root_loop_internal_ladder_owner_path", ()) or ()
                        ),
                        "expanded_root_loop_internal_owner_blocker": record.get(
                            "expanded_root_loop_internal_owner_blocker"
                        ),
                        "expanded_root_loop_internal_owner_node_summaries": dict(
                            record.get("expanded_root_loop_internal_owner_node_summaries", {}) or {}
                        ),
                        "expanded_root_loop_internal_ready": bool(
                            record.get("expanded_root_loop_internal_ready", False)
                        ),
                        "expanded_root_materialization_owner_blocker": record.get(
                            "expanded_root_materialization_owner_blocker"
                        ),
                        "expanded_root_owner_node_summaries": dict(
                            record.get("expanded_root_owner_node_summaries", {}) or {}
                        ),
                        "expanded_root_owner_path_blocker": record.get("expanded_root_owner_path_blocker"),
                        "expanded_root_owner_paths_ready": bool(
                            record.get("expanded_root_owner_paths_ready", False)
                        ),
                        "expanded_root_transform_blocker_reason": first_mapping.get(
                            "expanded_root_transform_blocker_reason"
                        ),
                        "expanded_root_transform_ready": bool(
                            first_mapping.get("expanded_root_transform_ready", False)
                        ),
                        "grouped_switch_artifact_count": int(
                            record.get("grouped_switch_artifact_count", 0) or 0
                        ),
                        "node_count": int(record.get("node_count", 0) or 0),
                        "stage": record.get("stage"),
                        "switch_case_node_count": int(record.get("switch_case_node_count", 0) or 0),
                    }
                )
            graph_region_stage_summaries = []
            for record in list(latest_probe.get("pre_codegen_graphregion_stage_mappings", ()) or ())[:4]:
                if not isinstance(record, Mapping):
                    continue
                mappings = list(record.get("grouped_switch_artifact_mappings", ()) or ())
                first_mapping = mappings[0] if mappings and isinstance(mappings[0], Mapping) else {}
                pre_recursive_mappings = list(record.get("pre_recursive_grouped_switch_mappings", ()) or ())
                first_pre_recursive_mapping = (
                    pre_recursive_mappings[0]
                    if pre_recursive_mappings and isinstance(pre_recursive_mappings[0], Mapping)
                    else {}
                )
                graph_region_stage_summaries.append(
                    {
                        "expanded_root_ambiguous_case_region_ids": list(
                            first_mapping.get("expanded_root_ambiguous_case_region_ids", ()) or ()
                        ),
                        "expanded_root_ambiguous_default_region_ids": list(
                            first_mapping.get("expanded_root_ambiguous_default_region_ids", ()) or ()
                        ),
                        "expanded_root_ambiguous_mapping_samples": list(
                            first_mapping.get("expanded_root_ambiguous_mapping_samples", ()) or ()
                        )[:4],
                        "expanded_root_body_mapping_status": first_mapping.get("expanded_root_body_mapping_status"),
                        "expanded_root_body_shape_status": first_mapping.get("expanded_root_body_shape_status"),
                        "expanded_root_case_path_samples": list(
                            first_mapping.get("expanded_root_case_path_samples", ()) or ()
                        )[:12],
                        "expanded_root_common_parent_path": list(
                            first_mapping.get("expanded_root_common_parent_path", ()) or ()
                        ),
                        "expanded_root_default_path_samples": list(
                            first_mapping.get("expanded_root_default_path_samples", ()) or ()
                        )[:6],
                        "expanded_root_disambiguated_default_region_ids": list(
                            first_mapping.get("expanded_root_disambiguated_default_region_ids", ()) or ()
                        ),
                        "expanded_root_direct_sibling_span": bool(
                            first_mapping.get("expanded_root_direct_sibling_span", False)
                        ),
                        "expanded_root_transform_blocker_reason": first_mapping.get(
                            "expanded_root_transform_blocker_reason"
                        ),
                        "expanded_root_transform_ready": bool(
                            first_mapping.get("expanded_root_transform_ready", False)
                        ),
                        "grouped_switch_artifact_count": int(
                            record.get("grouped_switch_artifact_count", 0) or 0
                        ),
                        "full_graph_available": bool(record.get("full_graph_available", False)),
                        "node_count": int(record.get("node_count", 0) or 0),
                        "pre_recursive_grouped_switch_artifact_count": int(
                            record.get("pre_recursive_grouped_switch_artifact_count", 0) or 0
                        ),
                        "pre_recursive_grouped_switch_artifact_statuses": list(
                            record.get("pre_recursive_grouped_switch_artifact_statuses", ()) or ()
                        ),
                        "pre_recursive_grouped_switch_error": record.get("pre_recursive_grouped_switch_error"),
                        "pre_recursive_materialization_blocker_reasons": dict(
                            record.get("pre_recursive_materialization_blocker_reasons", {}) or {}
                        ),
                        "pre_recursive_materialization_external_default_owner_path": list(
                            record.get("pre_recursive_materialization_external_default_owner_path", ()) or ()
                        ),
                        "pre_recursive_materialization_ladder_owner_path": list(
                            record.get("pre_recursive_materialization_ladder_owner_path", ()) or ()
                        ),
                        "pre_recursive_materialization_owner_node_summaries": dict(
                            record.get("pre_recursive_materialization_owner_node_summaries", {}) or {}
                        ),
                        "pre_recursive_materialization_owner_path_blocker": record.get(
                            "pre_recursive_materialization_owner_path_blocker"
                        ),
                        "pre_recursive_materialization_owner_paths_ready": bool(
                            record.get("pre_recursive_materialization_owner_paths_ready", False)
                        ),
                        "pre_recursive_materialization_ready_count": int(
                            record.get("pre_recursive_materialization_ready_count", 0) or 0
                        ),
                        "pre_recursive_materialization_ready_region_ids": list(
                            record.get("pre_recursive_materialization_ready_region_ids", ()) or ()
                        ),
                        "pre_recursive_mapping_body_shape_status": first_pre_recursive_mapping.get(
                            "expanded_root_body_shape_status"
                        ),
                        "pre_recursive_mapping_status": first_pre_recursive_mapping.get(
                            "expanded_root_body_mapping_status"
                        ),
                        "pre_recursive_transform_blocker_reason": first_pre_recursive_mapping.get(
                            "expanded_root_transform_blocker_reason"
                        ),
                        "pre_recursive_transform_ready": bool(
                            first_pre_recursive_mapping.get("expanded_root_transform_ready", False)
                        ),
                        "source_graph_available": bool(record.get("source_graph_available", False)),
                        "stage": record.get("stage"),
                    }
                )
            print(
                "[typed-switch-pre-codegen-seqnode] "
                + json.dumps(
                    {
                        "addr_samples": list(latest_probe.get("addr_samples", ()) or ())[:8],
                        "cascading_condition_node_count": int(
                            latest_probe.get("cascading_condition_node_count", 0) or 0
                        ),
                        "condition_edge_block_addrs": list(
                            latest_probe.get("condition_edge_block_addrs", ()) or ()
                        )[:8],
                        "condition_edge_evidence_count": int(
                            latest_probe.get("condition_edge_evidence_count", 0) or 0
                        ),
                        "condition_edge_summaries": list(latest_probe.get("condition_edge_summaries", ()) or ())[:16],
                        "condition_fact_count": int(latest_probe.get("condition_fact_count", 0) or 0),
                        "condition_node_count": int(latest_probe.get("condition_node_count", 0) or 0),
                        "function_addr": latest_probe.get("function_addr"),
                        "incomplete_switch_case_node_count": int(
                            latest_probe.get("incomplete_switch_case_node_count", 0) or 0
                        ),
                        "loop_node_count": int(latest_probe.get("loop_node_count", 0) or 0),
                        "node_count": int(latest_probe.get("node_count", 0) or 0),
                        "pre_codegen_grouped_switch_artifact_count": int(
                            latest_probe.get("pre_codegen_grouped_switch_artifact_count", 0) or 0
                        ),
                        "pre_codegen_grouped_switch_artifact_mappings": list(
                            latest_probe.get("pre_codegen_grouped_switch_artifact_mappings", ()) or ()
                        )[:4],
                        "pre_codegen_graphregion_stage_mappings": graph_region_stage_summaries,
                        "pre_codegen_grouped_switch_error": latest_probe.get("pre_codegen_grouped_switch_error"),
                        "pre_codegen_structuring_stage_mappings": stage_mapping_summaries,
                        "root_type": latest_probe.get("root_type"),
                        "switch_case_node_count": int(latest_probe.get("switch_case_node_count", 0) or 0),
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
                flush=True,
            )
    # Dynamic angr/codegen compatibility boundary.
    payload = getattr(codegen, "_inertia_typed_edge_switch_replacement_safety_8616", None)
    # Dynamic angr/codegen compatibility boundary.
    cfunc = getattr(codegen, "cfunc", None)
    # Dynamic angr/codegen compatibility boundary.
    stats = getattr(cfunc, "_structuring_stats", None)
    # Dynamic angr/codegen compatibility boundary.
    lowering_payload = getattr(codegen, "_inertia_typed_edge_switch_lowering_status_8616", None)
    if not isinstance(lowering_payload, Mapping) and isinstance(stats, Mapping):
        lowering_payload = stats.get("typed_edge_switch_lowering_status")
    if isinstance(lowering_payload, Mapping):
        print(
            "[typed-switch-lowering-status] "
            + json.dumps(
                    {
                        "artifact_count": int(lowering_payload.get("artifact_count", 0) or 0),
                        "attempted_count": int(lowering_payload.get("attempted_count", 0) or 0),
                        "blocker_layer": lowering_payload.get("blocker_layer"),
                        "blocker_reason": lowering_payload.get("blocker_reason"),
                        "changed": bool(lowering_payload.get("changed", False)),
                        "loop_break_default_blocker_reasons": dict(
                            lowering_payload.get("loop_break_default_blocker_reasons", {}) or {}
                        ),
                        "loop_break_default_candidate_count": int(
                            lowering_payload.get("loop_break_default_candidate_count", 0) or 0
                        ),
                        "normalization_ready_artifact_count": int(
                            lowering_payload.get("normalization_ready_artifact_count", 0) or 0
                        ),
                        "partial_artifact_count": int(lowering_payload.get("partial_artifact_count", 0) or 0),
                        "pre_codegen_transform_blocker_reasons": dict(
                            lowering_payload.get("pre_codegen_transform_blocker_reasons", {}) or {}
                        ),
                        "pre_codegen_transform_ready_artifact_count": int(
                            lowering_payload.get("pre_codegen_transform_ready_artifact_count", 0) or 0
                        ),
                        "ready_artifact_count": int(lowering_payload.get("ready_artifact_count", 0) or 0),
                        "status": lowering_payload.get("status"),
                    },
                sort_keys=True,
            ),
            file=sys.stderr,
            flush=True,
        )
    # Dynamic angr/codegen compatibility boundary.
    project = getattr(codegen, "project", None)
    # Dynamic angr/codegen compatibility boundary.
    seqnode_replacements = getattr(project, "_inertia_typed_switch_seqnode_replacement_8616", None)
    if isinstance(seqnode_replacements, list) and seqnode_replacements:
        # Dynamic angr/codegen compatibility boundary.
        function_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
        relevant_seqnode_replacements = [
            record
            for record in seqnode_replacements
            if isinstance(record, Mapping)
            and (not isinstance(function_addr, int) or record.get("function_addr") == function_addr)
        ]
        if relevant_seqnode_replacements:
            latest_replacement = relevant_seqnode_replacements[-1]
            refusal_reasons = latest_replacement.get("refusal_reasons", ()) or ()
            if isinstance(refusal_reasons, Mapping):
                refusal_reason_counts = {
                    str(reason): int(count or 0)
                    for reason, count in refusal_reasons.items()
                }
            else:
                refusal_reason_counts = dict(Counter(str(reason) for reason in refusal_reasons))
            print(
                "[typed-switch-seqnode-replacement] "
                + json.dumps(
                    {
                        "attempt_history": [dict(record) for record in relevant_seqnode_replacements],
                        "attempted_count": int(latest_replacement.get("attempted_count", 0) or 0),
                        "case_count": int(latest_replacement.get("case_count", 0) or 0),
                        "changed": bool(latest_replacement.get("changed", False)),
                        "default_target_addr": latest_replacement.get("default_target_addr"),
                        "function_addr": latest_replacement.get("function_addr"),
                        "refusal_reasons": refusal_reason_counts,
                        "replaced_count": int(latest_replacement.get("replaced_count", 0) or 0),
                        **_typed_switch_seqnode_case_segment_quality_8616(codegen),
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
                flush=True,
            )
    if not isinstance(payload, Mapping):
        if not isinstance(stats, Mapping):
            return
        payload = stats.get("typed_edge_switch_replacement_safety")
    if not isinstance(payload, Mapping):
        return
    refusal_reasons = payload.get("refusal_reasons", {}) or {}
    if isinstance(refusal_reasons, Mapping):
        refusal_reason_counts = {
            str(reason): int(count or 0)
            for reason, count in refusal_reasons.items()
        }
    else:
        refusal_reason_counts = dict(Counter(str(reason) for reason in refusal_reasons))
    print(
        "[typed-switch-replacement-safety] "
        + json.dumps(
            {
                "attempted_count": int(payload.get("attempted_count", 0) or 0),
                "blocker_layer": payload.get("blocker_layer"),
                "changed": bool(payload.get("changed", False)),
                "refusal_reasons": refusal_reason_counts,
                "refused_count": int(payload.get("refused_count", 0) or 0),
                "safe_count": int(payload.get("safe_count", 0) or 0),
                "status": payload.get("status"),
            },
            sort_keys=True,
        ),
        file=sys.stderr,
        flush=True,
    )
    # Dynamic angr/codegen compatibility boundary.
    replacement_payload = getattr(codegen, "_inertia_typed_edge_switch_ast_replacement_8616", None)
    if isinstance(replacement_payload, Mapping):
        replacement_refusal_reasons = replacement_payload.get("refusal_reasons", {}) or {}
        if isinstance(replacement_refusal_reasons, Mapping):
            replacement_refusal_reason_counts = {
                str(reason): int(count or 0)
                for reason, count in replacement_refusal_reasons.items()
            }
        else:
            replacement_refusal_reason_counts = dict(Counter(str(reason) for reason in replacement_refusal_reasons))
        replacement_report = {
            "attempted_count": int(replacement_payload.get("attempted_count", 0) or 0),
            "changed": bool(replacement_payload.get("changed", False)),
            "refusal_reasons": replacement_refusal_reason_counts,
            "refused_count": int(replacement_payload.get("refused_count", 0) or 0),
            "replaced_count": int(replacement_payload.get("replaced_count", 0) or 0),
        }
        if replacement_payload.get("tail_validation_status") is not None:
            replacement_report["tail_validation_status"] = replacement_payload.get("tail_validation_status")
        if replacement_payload.get("tail_validation_summary") is not None:
            replacement_report["tail_validation_summary"] = replacement_payload.get("tail_validation_summary")
        print(
            "[typed-switch-ast-replacement] "
            + json.dumps(
                replacement_report,
                sort_keys=True,
            ),
            file=sys.stderr,
            flush=True,
        )
    if os.environ.get("INERTIA_DEBUG_TYPED_SWITCH_GRAPH") == "1" or os.environ.get(
        "INERTIA_DEBUG_TYPED_SWITCH_SAFETY"
    ) == "1":
        # Dynamic angr/codegen compatibility boundary.
        debug_payload = getattr(codegen, "_inertia_typed_edge_switch_replacement_safety_debug_8616", None)
        if isinstance(debug_payload, Mapping):
            print(
                "[typed-switch-replacement-safety-debug] "
                + json.dumps(
                    debug_payload,
                    sort_keys=True,
                ),
                file=sys.stderr,
                flush=True,
            )


def _typed_switch_seqnode_case_segment_quality_8616(codegen: object) -> dict[str, object]:
    """Count unresolved segment carriers inside generated switch case bodies."""
    # Dynamic angr/codegen compatibility boundary.
    project = getattr(codegen, "project", None)
    # Dynamic angr/codegen compatibility boundary.
    if project is not None and not getattr(codegen, "_inertia_seqnode_case_segment_replay_applied_8616", False):
        # Dynamic angr/codegen compatibility boundary.
        typing.cast(typing.Any, codegen)._inertia_seqnode_case_segment_replay_applied_8616 = True
        # Dynamic angr/codegen compatibility boundary.
        target = str(getattr(project, "_inertia_c_target", "portable-flat") or "portable-flat")
        try:
            apply_runtime_segment_lowering_8616(codegen, target=target)
            # Dynamic angr/codegen compatibility boundary.
            synthetic_globals = getattr(codegen, "_inertia_synthetic_globals", None)
            if not isinstance(synthetic_globals, dict):
                # Dynamic angr/codegen compatibility boundary.
                synthetic_globals = getattr(project, "_inertia_synthetic_globals", None)
            if not isinstance(synthetic_globals, dict):
                synthetic_globals = None
            # Dynamic angr/codegen compatibility boundary.
            func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
            # Dynamic angr/codegen compatibility boundary.
            metadata_by_addr = getattr(project, "_inertia_cod_metadata_by_func_addr_8616", None)
            cod_metadata = metadata_by_addr.get(func_addr) if isinstance(func_addr, int) and isinstance(metadata_by_addr, dict) else None
            materialize_named_segmented_global_loads_8616(project, codegen, synthetic_globals, cod_metadata=cod_metadata)
            materialize_compare_register_global_carriers_8616(project, codegen, synthetic_globals, cod_metadata=cod_metadata)
            materialize_direct_global_symbol_stores_8616(project, codegen, synthetic_globals, cod_metadata=cod_metadata)
            materialize_indexed_segmented_global_loads_8616(project, codegen, cod_metadata=cod_metadata)
        except Exception as ex:
            typing.cast(typing.Any, codegen)._inertia_seqnode_case_segment_replay_error_8616 = f"{type(ex).__name__}: {ex}"
    # Dynamic angr/codegen compatibility boundary.
    cfunc = getattr(codegen, "cfunc", None)
    # Dynamic angr/codegen compatibility boundary.
    root = getattr(cfunc, "statements", None) if cfunc is not None else None
    if root is None:
        return {
            "case_runtime_segment_helper_unresolved_count": 0,
            "case_unresolved_linear_segment_count": 0,
        }

    def _strip_casts(node: object) -> object:
        while isinstance(node, structured_c.CTypeCast):
            node = node.expr
        return node

    def _call_name(node: object) -> str | None:
        node = _strip_casts(node)
        if not isinstance(node, structured_c.CFunctionCall):
            return None
        # Dynamic angr/codegen compatibility boundary.
        name = node.callee_target
        return name if isinstance(name, str) else None

    def _is_segment_register_expr(node: object) -> bool:
        node = _strip_casts(node)
        if not isinstance(node, structured_c.CVariable):
            return False
        # Dynamic angr/codegen compatibility boundary.
        variable = node.variable
        if not isinstance(variable, SimRegisterVariable):
            return False
        # Dynamic angr/codegen compatibility boundary.
        project = getattr(codegen, "project", None)
        # Dynamic angr/codegen compatibility boundary.
        arch = getattr(project, "arch", None)
        # Dynamic angr/codegen compatibility boundary.
        register_names = getattr(arch, "register_names", {}) if arch is not None else {}
        # Dynamic angr/codegen compatibility boundary.
        reg_name = register_names.get(variable.reg)
        return isinstance(reg_name, str) and reg_name.lower() in {"ds", "es", "ss"}

    def _constant_value(node: object) -> int | None:
        node = _strip_casts(node)
        if isinstance(node, structured_c.CConstant) and isinstance(node.value, int):
            return int(node.value)
        return None

    def _segment_carrier_signature(node: object) -> str:
        node = _strip_casts(node)
        if isinstance(node, structured_c.CVariable):
            # Dynamic angr/codegen compatibility boundary.
            variable = node.variable
            variable_class = type(variable).__name__ if variable is not None else "none"
            # Dynamic angr/codegen compatibility boundary.
            name = node.name or getattr(variable, "name", None)
            # Dynamic angr/codegen compatibility boundary.
            reg = getattr(variable, "reg", None)
            # Dynamic angr/codegen compatibility boundary.
            vvar_id = node.vvar_id
            return f"CVariable:name={name}:vvar_id={vvar_id}:var={variable_class}:reg={reg}"
        # Dynamic angr/codegen compatibility boundary.
        dirty = getattr(node, "dirty", None)
        if dirty is not None:
            dirty_class = type(dirty).__name__
            # Dynamic angr/codegen compatibility boundary.
            varid = getattr(dirty, "varid", None)
            # Dynamic angr/codegen compatibility boundary.
            category = getattr(dirty, "category", None)
            # Dynamic angr/codegen compatibility boundary.
            category_name = getattr(category, "name", None) or str(category)
            # Dynamic angr/codegen compatibility boundary.
            oident = getattr(dirty, "oident", None)
            reg = None
            for attr in ("reg", "reg_offset", "parameter_reg_offset"):
                try:
                    # Dynamic angr/codegen compatibility boundary.
                    reg = getattr(dirty, attr, None)
                except TypeError:
                    continue
                if isinstance(reg, int):
                    break
            return f"CDirtyExpression:dirty={dirty_class}:varid={varid}:category={category_name}:oident={oident}:reg={reg}"
        return type(node).__name__

    unresolved_segment_signatures: Counter[str] = Counter()
    unresolved_helper_segment_signatures: Counter[str] = Counter()

    def _node_has_unresolved_linear_segment(node: object) -> bool:
        for current in (node, *_iter_c_nodes_deep_8616(node)):
            current = _strip_casts(current)
            if not isinstance(current, structured_c.CBinaryOp):
                continue
            expected_scale = 4 if current.op == "Shl" else 16 if current.op == "Mul" else None
            if expected_scale is None:
                continue
            for maybe_seg, maybe_scale in ((current.lhs, current.rhs), (current.rhs, current.lhs)):
                if _constant_value(maybe_scale) != expected_scale:
                    continue
                if not _is_segment_register_expr(maybe_seg):
                    unresolved_segment_signatures[_segment_carrier_signature(maybe_seg)] += 1
                    return True
        return False

    helper_unresolved = 0
    linear_unresolved = 0
    for switch_node in _iter_c_nodes_deep_8616(root):
        if type(switch_node).__name__ != "CSwitchCase":
            continue
        raw_cases: Any = getattr(switch_node, "cases", ())
        narrowed_cases: tuple[object, ...] = tuple(raw_cases) if isinstance(raw_cases, (list, tuple)) else ()
        case_bodies: list[object] = []
        for case_entry in narrowed_cases:
            if not isinstance(case_entry, (list, tuple)) or len(case_entry) != 2:
                continue
            case_bodies.append(case_entry[1])
        # Dynamic angr/codegen compatibility boundary.
        default_body = getattr(switch_node, "default", None)
        if default_body is not None:
            case_bodies.append(default_body)
        for body in case_bodies:
            for node in _iter_c_nodes_deep_8616(body):
                call_name = _call_name(node)
                if call_name in {"SEG_U8", "SEG_U16", "SEG_U32"}:
                    # Dynamic angr/codegen compatibility boundary.
                    args = tuple(getattr(node, "args", ()) or ())
                    if not args or not _is_segment_register_expr(args[0]):
                        if args:
                            unresolved_helper_segment_signatures[_segment_carrier_signature(args[0])] += 1
                        else:
                            unresolved_helper_segment_signatures["missing-arg"] += 1
                        helper_unresolved += 1
                current = _strip_casts(node)
                # Dynamic angr/codegen compatibility boundary.
                if isinstance(current, structured_c.CUnaryOp) and getattr(current, "op", None) == "Dereference":  # noqa: SIM102
                    # Dynamic angr/codegen compatibility boundary.
                    if _node_has_unresolved_linear_segment(current.operand):
                        linear_unresolved += 1
    return {
        "case_runtime_segment_helper_unresolved_count": helper_unresolved,
        "case_runtime_segment_helper_unresolved_carrier_kinds": len(unresolved_helper_segment_signatures),
        "case_runtime_segment_helper_unresolved_carriers": dict(
            unresolved_helper_segment_signatures.most_common(8)
        ),
        "runtime_helper_segment_carrier_ambiguous_count": int(
            # Dynamic angr/codegen compatibility boundary.
            getattr(codegen, "_inertia_runtime_helper_segment_carrier_ambiguous_count_8616", 0) or 0
        ),
        "runtime_helper_segment_carrier_candidate_count": int(
            # Dynamic angr/codegen compatibility boundary.
            getattr(codegen, "_inertia_runtime_helper_segment_carrier_candidate_count_8616", 0) or 0
        ),
        "runtime_helper_segment_carrier_materialized_count": int(
            # Dynamic angr/codegen compatibility boundary.
            getattr(codegen, "_inertia_runtime_helper_segment_carrier_materialized_count_8616", 0) or 0
        ),
        "runtime_helper_segment_carrier_refused_count": int(
            # Dynamic angr/codegen compatibility boundary.
            getattr(codegen, "_inertia_runtime_helper_segment_carrier_refused_count_8616", 0) or 0
        ),
        "runtime_helper_sp_offset_ss_proof_count": int(
            # Dynamic angr/codegen compatibility boundary.
            getattr(codegen, "_inertia_runtime_helper_sp_offset_ss_proof_count_8616", 0) or 0
        ),
        "runtime_helper_sp_segment_proof_count": int(
            # Dynamic angr/codegen compatibility boundary.
            getattr(codegen, "_inertia_runtime_helper_sp_segment_proof_count_8616", 0) or 0
        ),
        # Dynamic angr/codegen compatibility boundary.
        "runtime_helper_segment_replay_error": getattr(
            codegen, "_inertia_seqnode_case_segment_replay_error_8616", None
        ),
        "case_unresolved_linear_segment_count": linear_unresolved,
        "case_unresolved_linear_segment_carrier_kinds": len(unresolved_segment_signatures),
        "case_unresolved_linear_segment_carriers": dict(unresolved_segment_signatures.most_common(8)),
    }


def _debug_dump_calls_8616(label: str, c_text: str, function_addr: int) -> None:
    def _impl() -> None:
        if not os.environ.get("INERTIA_DEBUG_CALL_MUTATION"):
            return
        target_text = os.environ.get("INERTIA_DEBUG_CALL_MUTATION_ADDR")
        target_addr = int(target_text, 0) if isinstance(target_text, str) and target_text.strip() else None
        if isinstance(target_addr, int) and function_addr != target_addr:
            return
        normalized_text = _normalize_text_payload_8616(c_text)
        if not normalized_text:
            return
        log = logging.getLogger(__name__)
        filter_text = os.environ.get("INERTIA_DEBUG_CALL_MUTATION_FILTER", "")
        tracked = tuple(part.strip() for part in filter_text.split(",") if part.strip())
        call_line_re = re.compile(r"^\s*(?:[A-Za-z_]\w*\s*=\s*)?[A-Za-z_]\w*\s*\(")
        for line in normalized_text.splitlines():
            stripped = line.strip()
            if (tracked and any(name in stripped for name in tracked)) or (
                not tracked and call_line_re.match(stripped)
            ):
                log.warning("[call-mutation] %s: %s", label, stripped)

    return _impl()


def _debug_dump_rewrite_pass_lines_8616(
    codegen: object,
    *,
    pass_index: int,
    pass_name: str,
    function_addr: int,
) -> None:
    def _impl() -> None:
        filter_text = os.environ.get("INERTIA_DEBUG_REWRITE_PASS_FILTER", "")
        tracked = tuple(part.strip() for part in filter_text.split(",") if part.strip())
        if not tracked:
            return
        target_text = os.environ.get("INERTIA_DEBUG_REWRITE_PASS_ADDR")
        target_addr = int(target_text, 0) if isinstance(target_text, str) and target_text.strip() else None
        if isinstance(target_addr, int) and function_addr != target_addr:
            return
        try:
            # Dynamic third-party angr/codegen boundary.
            render_text = typing.cast(typing.Any, codegen).render_text
            rendered = render_text(getattr(codegen, "cfunc", None))
        except Exception:
            rendered = _snapshot_codegen_text(codegen)
        snapshot = _normalize_text_payload_8616(rendered)
        if not snapshot:
            return
        log = logging.getLogger(__name__)
        for line in snapshot.splitlines():
            stripped = line.strip()
            if any(part in stripped for part in tracked):
                log.warning(
                    "[rewrite-pass] idx=%d name=%s function=%#x %s",
                    pass_index,
                    pass_name,
                    function_addr,
                    stripped,
                )

    return _impl()


def _prepend_recovered_callsite_prototypes_8616(c_text: str, codegen: object) -> str:
    def _impl() -> str:
        # Dynamic angr/codegen compatibility boundary.
        cfunc: Any = getattr(codegen, "cfunc", None)
        decls: tuple[object, ...] = get_codegen_sequence_attr(
            codegen,
            cfunc,
            "_inertia_callsite_prototype_decls",
        )
        if not decls:
            return c_text
        decl_name_re = re.compile(r"^\s*[A-Za-z_][\w\s\*]*\s+(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*;\s*$")
        defn_name_re = re.compile(r"^\s*[A-Za-z_][\w\s\*]*\s+(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{?\s*$")
        non_declaration_prefixes = frozenset(
            {"break", "case", "continue", "do", "else", "for", "goto", "if", "return", "switch", "while"}
        )

        def _declaration_match(line: str) -> re.Match[str] | None:
            """Match a top-level declaration line, never a control/body statement."""
            first_word = line.lstrip().split(maxsplit=1)[0] if line.strip() else ""
            if first_word in non_declaration_prefixes:
                return None
            return decl_name_re.match(line)

        def _collect_existing(c_text_local: str) -> tuple[set[str], dict[str, list[str]], set[str]]:
            existing_local: set[str] = set()
            declarations_by_name: dict[str, list[str]] = {}
            definition_names: set[str] = set()
            for line in str(c_text_local or "").splitlines():
                stripped = line.strip()
                declaration_match = _declaration_match(stripped)
                if declaration_match is not None:
                    existing_local.add(stripped)
                    declarations_by_name.setdefault(declaration_match.group("name"), []).append(stripped)
                    continue
                definition_match = defn_name_re.match(stripped)
                if definition_match is not None:
                    definition_names.add(definition_match.group("name"))
            return existing_local, declarations_by_name, definition_names

        def _decl_score(decl_text: str, name: str) -> tuple[int, int]:
            m = re.match(
                r"^\s*(?P<ret>[A-Za-z_][\w\s\*]*?)\s+" + re.escape(name) + r"\s*\(", decl_text
            )
            if m is None or not decl_text.rstrip().endswith(");"):
                return (0, len(decl_text))
            ret = m.group("ret").strip()
            args = decl_text[m.end() : decl_text.rstrip().rfind(")")].strip()
            is_generic_int = ret == "int" and args == ""
            has_typed_args = bool(args and args != "void")
            return (
                (2 if has_typed_args else 0) + (0 if is_generic_int else 1),
                len(decl_text),
            )

        def _best_recovered_decls() -> list[str]:
            best_decl_by_name: dict[str, str] = {}
            anonymous_decls: list[str] = []
            for decl in decls:
                if not isinstance(decl, str):
                    continue
                stripped = decl.strip()
                if not stripped:
                    continue
                match = _declaration_match(stripped)
                if match is None:
                    anonymous_decls.append(stripped)
                    continue
                name = match.group("name")
                current = best_decl_by_name.get(name)
                if current is None or _decl_score(stripped, name) > _decl_score(current, name):
                    best_decl_by_name[name] = stripped
            return anonymous_decls + [best_decl_by_name[name] for name in sorted(best_decl_by_name)]

        existing, existing_decls_by_name, definition_names = _collect_existing(c_text)
        filtered: list[str] = []
        for stripped in _best_recovered_decls():
            if stripped in existing:
                continue
            match = _declaration_match(stripped)
            if match is not None:
                name = match.group("name")
                if name in definition_names:
                    continue
                existing_for_name = existing_decls_by_name.get(name, ())
                if any(_decl_score(existing_decl, name) >= _decl_score(stripped, name) for existing_decl in existing_for_name):
                    continue
            existing.add(stripped)
            if match is not None:
                existing_decls_by_name.setdefault(match.group("name"), []).append(stripped)
            filtered.append(stripped)
        if not filtered:
            return c_text
        preferred_by_name: dict[str, str] = {}
        for decl in filtered:
            match = _declaration_match(decl)
            if match is not None:
                preferred_by_name[match.group("name")] = decl

        def _prune_existing_lines() -> list[str]:
            pruned_lines: list[str] = []
            for line in str(c_text or "").splitlines():
                stripped = line.strip()
                match = _declaration_match(stripped)
                if match is not None:
                    name = match.group("name")
                    preferred = preferred_by_name.get(name)
                    if preferred is not None and stripped != preferred:
                        continue
                pruned_lines.append(line)
            return pruned_lines

        # Drop weaker/conflicting existing prototypes for names we are prepending
        # with recovered callsite signatures.
        pruned_lines = _prune_existing_lines()
        pruned_text = "\n".join(pruned_lines)
        if c_text.endswith("\n"):
            pruned_text += "\n"
        return "\n".join(filtered) + "\n\n" + pruned_text

    return _impl()


def _replay_indexed_segmented_global_lowering_after_regen_8616(codegen: object) -> bool:
    """Delegate final segment/global replay, then restore persistent type facts."""

    changed = _replay_named_segmented_global_lowering_after_regen_8616(codegen)
    changed = bool(reapply_proven_named_global_aggregate_types_8616(codegen)) or changed
    changed = bool(reapply_proven_stack_aggregate_types_8616(codegen)) or changed
    return bool(reapply_proven_stack_aggregate_field_projections_8616(codegen)) or changed


def _replay_named_segmented_global_lowering_after_regen_8616(codegen: object) -> bool:
    """Replay structured condition provenance, then regenerated global lowering."""

    project = getattr(codegen, "project", None)
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    cod_metadata = None
    metadata_by_addr = getattr(project, "_inertia_cod_metadata_by_func_addr_8616", None)
    if isinstance(metadata_by_addr, dict) and isinstance(func_addr, int):
        cod_metadata = metadata_by_addr.get(func_addr)
    synthetic_globals = getattr(codegen, "_inertia_synthetic_globals", None)
    if not isinstance(synthetic_globals, dict):
        synthetic_globals = getattr(project, "_inertia_synthetic_globals", None)
    if not isinstance(synthetic_globals, dict):
        synthetic_globals = None
    provenance_changed = replay_codegen_structured_condition_segment_provenance_8616(codegen).changed
    lowering_changed = run_segment_global_materialization_8616(
        typing.cast(typing.Any, project),
        typing.cast(typing.Any, codegen),
        synthetic_globals,
        cod_metadata=cod_metadata,
    ).changed
    return bool(provenance_changed or lowering_changed)


def _replay_stack_address_lowering_after_regen_8616(codegen: object) -> bool:
    project = getattr(codegen, "project", None)
    with contextlib.suppress(Exception):
        return bool(lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project))
    return False


def _replay_runtime_segment_lowering_after_regen_8616(codegen: object) -> bool:
    """Replay runtime helpers and Lowering-owned identities after regeneration."""
    try:
        project = typing.cast(typing.Any, codegen).project
    except AttributeError:
        return False
    if project is None:
        return False
    try:
        target = str(project._inertia_c_target or "portable-flat")
    except AttributeError:
        target = "portable-flat"
    try:
        runtime_changed = bool(apply_runtime_segment_lowering_8616(codegen, target=target))
    except AttributeError:
        runtime_changed = False
    named_changed = _replay_named_segmented_global_lowering_after_regen_8616(codegen)
    return bool(runtime_changed or named_changed)


def _finalize_callsite_arguments_after_noncall_regen_8616(codegen: object) -> bool:
    """Replay stack effects and calls, then enforce Structuring occurrence identity.

    This is orchestration only. Stack facts remain owned by Types/Lowering and
    Structuring, while argument facts remain owned by the X86_16 callsite
    summary consumer. Argument-refining lowerings run after both replays, and
    the Structuring owner gets the final word after those passes clone calls.
    """
    project = getattr(codegen, "project", None)
    stack_changed = _replay_direct_stack_semantics_after_regen_8616(codegen)
    call_changed = bool(replay_callsite_stack_arguments_after_regeneration_8616(project, codegen))
    aggregate_decay_changed = _finalize_typed_call_interfaces_before_render_8616(codegen)
    occurrence_changed = finalize_shared_call_occurrences_8616(project, codegen)
    changed = stack_changed or call_changed or aggregate_decay_changed or occurrence_changed
    if not changed:
        return False
    _replay_indexed_segmented_global_lowering_after_regen_8616(codegen)
    segment_surface_changed = _replay_stack_address_lowering_after_regen_8616(codegen)
    segment_surface_changed = _replay_runtime_segment_lowering_after_regen_8616(codegen) or segment_surface_changed
    if segment_surface_changed:
        _replay_indexed_segmented_global_lowering_after_regen_8616(codegen)
    _recover_canonical_for_loops_after_regen_8616(codegen)
    return True


def _finalize_typed_call_interfaces_before_render_8616(codegen: object) -> bool:
    """Replay Types/Lowering-owned argument and declaration consumers before rendering."""
    changed = reapply_stack_aggregate_object_facts_8616(codegen)
    dynamic_codegen = typing.cast(typing.Any, codegen)
    try:
        project = dynamic_codegen.project
        dynamic_codegen.cfunc.functy  # noqa: B018
    except AttributeError:
        project = None
    if project is not None:
        changed = reconcile_exact_stack_argument_prototype_8616(project, codegen) or changed
        changed = materialize_function_pointer_parameters_8616(project, codegen) or changed
        changed = materialize_terminal_register_return_type_8616(project, codegen).changed or changed
        materialize_callsite_prototype_declarations_8616(project, codegen)
    try:
        replay_count = dynamic_codegen._inertia_stack_aggregate_decay_render_replay_count_8616
    except AttributeError:
        replay_count = 0
    dynamic_codegen._inertia_stack_aggregate_decay_render_replay_count_8616 = int(replay_count or 0) + 1
    return bool(changed)


def _finalize_typed_interfaces_and_projections_before_render_8616(codegen: object) -> bool:
    """Finalize typed interfaces, then restore Lowering projections they may expose."""
    changed = _finalize_typed_call_interfaces_before_render_8616(codegen)
    return _replay_final_codegen_projections_after_regen_8616(codegen) or changed


def _replay_direct_stack_mov_after_regen_8616(codegen: object) -> bool:
    """Replay proven direct stack moves after angr replaces the structured C tree."""
    # Dynamic angr/codegen compatibility boundary.
    stats = getattr(codegen, "_inertia_direct_stack_move_lowering_8616", None)
    if (
        # Dynamic angr/codegen compatibility boundary.
        bool(getattr(codegen, "_inertia_skip_per_pass_validation_large_function", False))
        # Dynamic angr/codegen compatibility boundary.
        and bool(getattr(codegen, "_inertia_pre_validation_stack_semantics_primed", False))
        and isinstance(stats, dict)
        and int(stats.get("raw_fact_count", 0) or 0) > 0
    ):
        typing.cast(typing.Any, codegen)._inertia_direct_stack_mov_targeted_replay_large_function_8616 = (
            int(
                # Dynamic angr/codegen compatibility boundary.
                getattr(
                    codegen,
                    "_inertia_direct_stack_mov_targeted_replay_large_function_8616",
                    0,
                )
                or 0
            )
            + 1
        )
        return bool(
            materialize_direct_stack_mov_instructions_8616(
                codegen,
                source_kinds=frozenset(
                    {
                        DirectStackMoveSourceKind8616.SEGMENTED_MEMORY,
                        DirectStackMoveSourceKind8616.STACK_SLOT,
                    }
                ),
                materialize_reloads=False,
            )
        )
    return bool(materialize_direct_stack_mov_instructions_8616(codegen))


def _replay_direct_stack_updates_after_regen_8616(codegen: object) -> bool:
    """Replay proven stack updates through the Structuring-owned stage wrapper."""
    # Dynamic angr/codegen compatibility boundary.
    project = getattr(codegen, "project", None)
    if project is None:
        return False
    result = run_direct_instruction_materialization_8616(
        project,
        codegen,
        include_direct_stack_mov=False,
        include_direct_global_incdec=False,
    )
    return bool(result.direct_stack_incdec_changed)


def _replay_direct_stack_semantics_after_regen_8616(codegen: object) -> bool:
    """Replay all proven direct stack effects after structured-tree regeneration."""
    stack_mov_changed = _replay_direct_stack_mov_after_regen_8616(codegen)
    stack_update_changed = _replay_direct_stack_updates_after_regen_8616(codegen)
    return stack_mov_changed or stack_update_changed


def _replay_call_return_selector_lowering_after_regen_8616(codegen: object) -> bool:
    """Invoke the Structuring-bound Lowering owner after AST regeneration."""
    try:
        replayer = cast(
            Callable[[object], bool],
            cast(Any, codegen)._inertia_call_return_selector_replayer_8616,
        )
    except AttributeError:
        return False
    return bool(replayer(codegen))


def _replay_final_codegen_projections_after_regen_8616(codegen: object) -> bool:
    """Invoke the bound Lowering owner after late CLI AST cleanup."""
    try:
        replayer = cast(
            Callable[[object], bool],
            cast(Any, codegen)._inertia_final_codegen_projection_replayer_8616,
        )
    except AttributeError:
        if os.environ.get("INERTIA_DEBUG_GP_STACK_RESTORE"):
            logging.getLogger(__name__).warning(
                "[final-codegen-projection-replay] codegen=%#x available=False",
                id(codegen),
            )
        return False
    changed = bool(replayer(codegen))
    if os.environ.get("INERTIA_DEBUG_GP_STACK_RESTORE"):
        logging.getLogger(__name__).warning(
            "[final-codegen-projection-replay] codegen=%#x available=True changed=%s",
            id(codegen),
            changed,
        )
    return changed


def _recover_canonical_for_loops_after_regen_8616(codegen: object) -> bool:
    """Invoke Structuring only when the dynamic codegen exposes a live AST root."""
    try:
        typing.cast(typing.Any, codegen).cfunc.statements  # noqa: B018
    except AttributeError:
        return False
    return bool(recover_structuring_canonical_for_loops_8616(codegen))


def _stabilize_regenerated_noncall_ast_8616(codegen: object) -> bool:
    """Restore call identity before replaying widening and late cleanup."""
    project = getattr(codegen, "project", None)
    shared_call_changed = finalize_shared_call_occurrences_8616(project, codegen)
    changed = bool(shared_call_changed)
    if shared_call_changed:
        changed = bool(
            replay_callsite_stack_arguments_after_regeneration_8616(project, codegen)
        ) or changed
    changed = bool(_run_typed_widening_pass(project, codegen)) or changed
    changed = prune_redundant_loop_break_carriers_after_lowering_8616(codegen) or changed
    cleanup_result = finalize_late_ast_cleanup_8616(project, codegen)
    indexed_global_changed = _replay_indexed_segmented_global_lowering_after_regen_8616(
        codegen
    )
    canonical_for_changed = _recover_canonical_for_loops_after_regen_8616(codegen)
    return canonical_for_changed or indexed_global_changed or cleanup_result.changed or changed


def _finalize_regenerated_noncall_ast_8616(codegen: object) -> bool:
    """Stabilize, replay final Lowering identities, then clean exposed carriers."""
    changed = _stabilize_regenerated_noncall_ast_8616(codegen)
    late_ast_changed = _simplify_structured_expressions_8616(codegen)
    late_ast_changed = _replay_call_return_selector_lowering_after_regen_8616(codegen) or late_ast_changed
    if late_ast_changed:
        changed = _replay_indexed_segmented_global_lowering_after_regen_8616(codegen) or changed
    segment_surface_changed = _replay_direct_stack_semantics_after_regen_8616(codegen)
    segment_surface_changed = _replay_runtime_segment_lowering_after_regen_8616(codegen) or segment_surface_changed
    if segment_surface_changed:
        changed = _replay_indexed_segmented_global_lowering_after_regen_8616(codegen) or changed
    project = getattr(codegen, "project", None)
    final_occurrence_changed = finalize_shared_call_occurrences_8616(project, codegen)
    canonical_for_changed = _recover_canonical_for_loops_after_regen_8616(codegen)
    final_cleanup_changed = finalize_late_ast_cleanup_8616(project, codegen).changed
    final_projection_changed = _replay_final_codegen_projections_after_regen_8616(codegen)
    return bool(
        final_projection_changed
        or final_cleanup_changed
        or canonical_for_changed
        or final_occurrence_changed
        or changed
        or late_ast_changed
        or segment_surface_changed
    )


def _regenerate_codegen_text_safely(codegen: object, *, context: str) -> tuple[str, bool]:
    """Render the live C AST while preserving evidence-backed semantic materialization."""

    def _impl() -> tuple[str, bool]:
        fallback_text = _snapshot_codegen_text(codegen)
        log = logging.getLogger(__name__)

        def _pointer_memory_materialized_by_lowering_8616() -> bool:
            """Read the lowering completion marker at the angr codegen boundary."""
            try:
                return typing.cast(typing.Any, codegen)._inertia_pointer_memory_materialized_8616 is not None
            except AttributeError:
                return False

        def _replay_pointer_arg_loads_if_unmaterialized_8616() -> bool:
            """Do not let CLI compatibility replay reverse lowering-owned pointer memory."""
            if _pointer_memory_materialized_by_lowering_8616():
                return False
            return bool(_replay_runtime_segment_lowering_after_regen_8616(codegen))

        semantic_materialization_active = _codegen_has_semantic_materialization_8616(codegen) or bool(
            # Dynamic angr/codegen compatibility boundary.
            getattr(codegen, "_inertia_postprocess_changed", False)
        )
        preservation_baseline_text = fallback_text
        pre_replay_cfunc = None
        pre_replay_tail_summary: X86_16TailValidationSummary | None = None

        def _preserve_replay_or_restore(candidate_text: str, *, replay_tag: str) -> tuple[str, bool]:
            if not semantic_materialization_active:
                return candidate_text, True
            evidence = _render_refresh_preservation_evidence_8616(preservation_baseline_text, candidate_text)
            typing.cast(typing.Any, codegen)._inertia_render_refresh_preservation_evidence_8616 = evidence
            if evidence.decision != RenderRefreshPreservationDecision8616.RESTORE_STACK_WRITE_EFFECTS:
                return candidate_text, True
            if _render_refresh_replay_preserves_live_out_8616(codegen, pre_replay_tail_summary):
                typing.cast(typing.Any, codegen)._inertia_render_refresh_replay_accepted_by_live_out_8616 = (
                    int(
                        getattr(
                            codegen,
                            "_inertia_render_refresh_replay_accepted_by_live_out_8616",
                            0,
                        )
                        or 0
                    )
                    + 1
                )
                return candidate_text, True
            if _render_refresh_lost_stack_writes_are_validated_materialization_8616(codegen, evidence):
                typing.cast(typing.Any, codegen)._inertia_render_refresh_replay_accepted_by_validation_8616 = int(getattr(codegen, "_inertia_render_refresh_replay_accepted_by_validation_8616", 0) or 0) + 1
                return candidate_text, True
            if (
                _render_refresh_lost_stack_writes_have_direct_stack_evidence_8616(codegen, evidence)
                and _render_refresh_candidate_strictly_improves_quality_8616(
                    preservation_baseline_text,
                    candidate_text,
                )
            ):
                typing.cast(typing.Any, codegen)._inertia_render_refresh_replay_accepted_by_stack_evidence_8616 = (
                    int(getattr(codegen, "_inertia_render_refresh_replay_accepted_by_stack_evidence_8616", 0) or 0)
                    + 1
                )
                return candidate_text, True
            typing.cast(typing.Any, codegen)._inertia_render_refresh_replay_refused_8616 = int(getattr(codegen, "_inertia_render_refresh_replay_refused_8616", 0) or 0) + 1
            if os.environ.get("INERTIA_DEBUG_CLI_RENDER_REFRESH") == "1":
                log.warning(
                    "[cli-render-refresh-preserve] tag=%s lost=%r evidence_offsets=%r baseline_markers=%r candidate_markers=%r",
                    replay_tag,
                    evidence.lost_stack_slots,
                    sorted(_direct_stack_materialization_evidence_offsets_8616(codegen)),
                    tuple(assess_decompiled_c_text(preservation_baseline_text).markers),
                    tuple(assess_decompiled_c_text(candidate_text).markers),
                )
            if pre_replay_cfunc is not None:
                with contextlib.suppress(Exception):
                    typing.cast(typing.Any, codegen).cfunc = pre_replay_cfunc
                _replay_bound_callsite_argument_consumer_8616(
                    getattr(codegen, "project", None),
                    codegen,
                    preserve_setup=True,
                )
                _replay_final_codegen_projections_after_regen_8616(codegen)
                restored_text = _direct_cfunc_text_or_none(f"{replay_tag}-restored-cfunc")
                if isinstance(restored_text, str) and restored_text.strip():
                    restored_evidence = _render_refresh_preservation_evidence_8616(
                        preservation_baseline_text,
                        restored_text,
                    )
                    baseline_quality = assess_decompiled_c_text(preservation_baseline_text)
                    restored_quality = assess_decompiled_c_text(restored_text)
                    baseline_penalty = len(baseline_quality.markers)
                    restored_penalty = len(restored_quality.markers)
                    if os.environ.get("INERTIA_DEBUG_CLI_RENDER_REFRESH") == "1":
                        log.warning(
                            "[cli-render-refresh-restore] tag=%s decision=%s baseline_penalty=%d restored_penalty=%d restored_markers=%r",
                            replay_tag,
                            restored_evidence.decision.value,
                            baseline_penalty,
                            restored_penalty,
                            restored_quality.markers,
                        )
                    if (
                        restored_evidence.decision
                        != RenderRefreshPreservationDecision8616.RESTORE_STACK_WRITE_EFFECTS
                        and restored_penalty <= baseline_penalty
                    ):
                        log.warning(
                            "render refresh replay refused for %s tag=%s but restored pre-replay semantic tree",
                            context,
                            replay_tag,
                        )
                        return restored_text, True
            with contextlib.suppress(Exception):
                typing.cast(typing.Any, codegen).text = preservation_baseline_text
            log.warning(
                "render refresh replay refused for %s tag=%s decision=%s lost_stack_slots=%r",
                context,
                replay_tag,
                evidence.decision.value,
                evidence.lost_stack_slots,
            )
            _trace_dump(f"{replay_tag}-restored-stack-write-effects", preservation_baseline_text)
            return preservation_baseline_text, True

        try:
            # Dynamic third-party angr/codegen boundary with Inertia extension fields.
            selector_return_contract_active = bool(
                typing.cast(typing.Any, codegen)._inertia_return_selector_materialized_8616
            )
        except AttributeError:
            selector_return_contract_active = False
        # Rendering rule:
        # Once AST-level rewrites have run, prefer regenerating text from the updated
        # codegen tree. Cached snapshots are fallback-only; do not let the final text
        # path silently revert to pre-rewrite output.
        trace_addr = -1
        if os.environ.get("INERTIA_DEBUG_CALL_MUTATION"):
            target_text = os.environ.get("INERTIA_DEBUG_CALL_MUTATION_ADDR")
            target_addr = int(target_text, 0) if isinstance(target_text, str) and target_text.strip() else None
            if isinstance(target_addr, int) and f"{target_addr:#x}" in context:
                trace_addr = target_addr

        def _trace_dump(tag: str, text: str) -> None:
            if trace_addr > 0:
                _debug_dump_calls_8616(tag, text, trace_addr)

        def _normalize_stack_identifiers_before_render_8616() -> None:
            """Normalize third-party names, then restore proven BP projections."""
            with contextlib.suppress(Exception):
                from angr_platforms.X86_16.decompiler_postprocess_stage import (
                    _normalize_stack_variable_identifiers_8616,
                )
                from angr_platforms.X86_16.lowering.stack_variable_display_names import (
                    reapply_stack_variable_projection_names_8616,
                )

                _normalize_stack_variable_identifiers_8616(codegen)
                reapply_stack_variable_projection_names_8616(codegen)

        def _render_text_or_none(tag: str) -> str | None:
            require_codegen_render_integrity_8616(codegen, context=context)
            _normalize_stack_identifiers_before_render_8616()
            _finalize_typed_interfaces_and_projections_before_render_8616(codegen)
            # Dynamic third-party angr/codegen boundary.
            render_text = typing.cast(typing.Any, codegen).render_text
            rendered = render_text(getattr(codegen, "cfunc", None))
            text = _normalize_text_payload_8616(rendered)
            if text:
                _trace_dump(tag, text)
                return text
            return None

        def _direct_cfunc_text_or_none(tag: str) -> str | None:
            """Render the C function after the final evidence-backed stack replay."""
            require_codegen_render_integrity_8616(codegen, context=context)
            if (
                semantic_materialization_active
                and not selector_return_contract_active
                and not _pointer_memory_materialized_by_lowering_8616()
            ):
                with contextlib.suppress(Exception):
                    _finalize_callsite_arguments_after_noncall_regen_8616(codegen)
            _normalize_stack_identifiers_before_render_8616()
            _finalize_typed_interfaces_and_projections_before_render_8616(codegen)
            cfunc = getattr(codegen, "cfunc", None)
            c_repr = getattr(cfunc, "c_repr", None)
            if not callable(c_repr):
                return None
            text = _normalize_text_payload_8616(c_repr())
            if not text:
                return None
            with contextlib.suppress(Exception):
                typing.cast(typing.Any, codegen).text = text
            _trace_dump(tag, text)
            if os.environ.get("INERTIA_DEBUG_CLI_RENDER_REFRESH") == "1":
                log.warning(
                    "[cli-render-refresh-candidate] context=%s tag=%s text=%r",
                    context,
                    tag,
                    "\n".join(text.splitlines()[:24]),
                )
            return text

        _trace_dump("regen-fallback-text", fallback_text)
        try:
            repair_cfunctioncall_render_targets_8616(codegen)
            with contextlib.suppress(Exception):
                from angr_platforms.X86_16.decompiler_postprocess_stage import (
                    _normalize_stack_variable_identifiers_8616,
                )

                _normalize_stack_variable_identifiers_8616(codegen)
            _bind_codegen_render_variable_types_8616(codegen)
            render_authority = codegen_render_authority_8616(codegen)
            if render_authority is CodegenRenderAuthority8616.PROVEN_FULL_FUNCTION_OVERRIDE:
                authoritative_text = _render_text_or_none("regen-render-text-authoritative-override")
                if authoritative_text is not None:
                    typing.cast(typing.Any, codegen).text = authoritative_text
                    return authoritative_text, True
            if _pointer_memory_materialized_by_lowering_8616():
                direct_text = _direct_cfunc_text_or_none("regen-cfunc-text-lowering-owned-pointer-memory")
                if direct_text is not None:
                    return direct_text, True
            if semantic_materialization_active:
                with contextlib.suppress(Exception):
                    noncall_changed = bool(_replay_named_segmented_global_lowering_after_regen_8616(codegen))
                    noncall_changed = bool(_replay_indexed_segmented_global_lowering_after_regen_8616(codegen)) or noncall_changed
                    noncall_changed = bool(_replay_stack_address_lowering_after_regen_8616(codegen)) or noncall_changed
                    noncall_changed = _replay_direct_stack_semantics_after_regen_8616(codegen) or noncall_changed
                    noncall_changed = _replay_pointer_arg_loads_if_unmaterialized_8616() or noncall_changed
                    noncall_changed = bool(_replay_indexed_segmented_global_lowering_after_regen_8616(codegen)) or noncall_changed
                    if noncall_changed:
                        _finalize_regenerated_noncall_ast_8616(codegen)
                        noncall_text = _direct_cfunc_text_or_none("regen-cfunc-text-before-call-arg-replay-noncall")
                        if noncall_text is not None:
                            noncall_evidence = _render_refresh_preservation_evidence_8616(fallback_text, noncall_text)
                            if (
                                noncall_evidence.decision
                                != RenderRefreshPreservationDecision8616.RESTORE_STACK_WRITE_EFFECTS
                            ):
                                preservation_baseline_text = noncall_text
                                typing.cast(typing.Any, codegen)._inertia_render_refresh_noncall_replay_before_call_args_8616 = (
                                    int(
                                        # Dynamic angr/codegen compatibility boundary.
                                        getattr(
                                            codegen,
                                            "_inertia_render_refresh_noncall_replay_before_call_args_8616",
                                            0,
                                        )
                                        or 0
                                    )
                                    + 1
                                )
                with contextlib.suppress(Exception):
                    # Dynamic angr/codegen compatibility boundary.
                    pre_replay_cfunc = copy.deepcopy(getattr(codegen, "cfunc", None))
                pre_replay_tail_summary = _collect_render_refresh_tail_summary_8616(codegen)
            if (
                getattr(codegen, "_inertia_callsite_args_ast_materialized_8616", False)
                and not selector_return_contract_active
            ):
                with contextlib.suppress(Exception):
                    replay_callsite_stack_arguments_after_regeneration_8616(
                        getattr(codegen, "project", None),
                        codegen,
                    )
                    _replay_named_segmented_global_lowering_after_regen_8616(codegen)
                    _replay_indexed_segmented_global_lowering_after_regen_8616(codegen)
                    _replay_stack_address_lowering_after_regen_8616(codegen)
                    _replay_direct_stack_semantics_after_regen_8616(codegen)
                    _replay_pointer_arg_loads_if_unmaterialized_8616()
                    _replay_indexed_segmented_global_lowering_after_regen_8616(codegen)
                    _finalize_regenerated_noncall_ast_8616(codegen)
                    _finalize_callsite_arguments_after_noncall_regen_8616(codegen)
                direct_text = _direct_cfunc_text_or_none("regen-cfunc-text-after-call-arg-materialization")
                if direct_text is not None:
                    preserved_text, accepted_replay = _preserve_replay_or_restore(
                        direct_text,
                        replay_tag="regen-cfunc-text-after-call-arg-materialization",
                    )
                    return preserved_text, accepted_replay
            # Dynamic angr/codegen compatibility boundary.
            force_regeneration = bool(getattr(codegen, "_inertia_force_codegen_regeneration_8616", False))
            if force_regeneration:
                direct_text = _direct_cfunc_text_or_none("regen-cfunc-text-forced-live-ast")
                if direct_text is not None:
                    return direct_text, True
            if getattr(codegen, "_inertia_postprocess_changed", False):
                direct_text = _direct_cfunc_text_or_none("regen-cfunc-text-before-regenerate")
                if direct_text is not None:
                    return direct_text, True
                rendered_text = _render_text_or_none("regen-render-text-before-regenerate")
                if rendered_text is not None:
                    return rendered_text, True
            # Dynamic third-party angr/codegen boundary.
            regenerate_text = typing.cast(typing.Any, codegen).regenerate_text
            regenerate_text()
            replay_changed = bool(
                semantic_materialization_active and _replay_direct_stack_semantics_after_regen_8616(codegen)
            )
            if not selector_return_contract_active:
                with contextlib.suppress(Exception):
                    replay_changed = (
                        bool(
                        replay_callsite_stack_arguments_after_regeneration_8616(
                            getattr(codegen, "project", None), codegen
                        )
                        )
                        or replay_changed
                    )
            if replay_changed:
                with contextlib.suppress(Exception):
                    _replay_named_segmented_global_lowering_after_regen_8616(codegen)
                    _replay_indexed_segmented_global_lowering_after_regen_8616(codegen)
                    _replay_stack_address_lowering_after_regen_8616(codegen)
                    _replay_direct_stack_semantics_after_regen_8616(codegen)
                    _replay_pointer_arg_loads_if_unmaterialized_8616()
                    _finalize_regenerated_noncall_ast_8616(codegen)
                    _finalize_callsite_arguments_after_noncall_regen_8616(codegen)
                direct_text = _direct_cfunc_text_or_none("regen-cfunc-text-after-post-replay")
                if direct_text is not None:
                    preserved_text, accepted_replay = _preserve_replay_or_restore(
                        direct_text,
                        replay_tag="regen-cfunc-text-after-post-replay",
                    )
                    return preserved_text, accepted_replay
                regenerate_text()
            else:
                with contextlib.suppress(Exception):
                    named_replay_changed = _replay_named_segmented_global_lowering_after_regen_8616(codegen)
                    if named_replay_changed:
                        _finalize_regenerated_noncall_ast_8616(codegen)
                        direct_text = _direct_cfunc_text_or_none("regen-cfunc-text-after-named-seg-global-replay")
                        if direct_text is not None:
                            return direct_text, True
                        regenerate_text()
                    indexed_replay_changed = _replay_indexed_segmented_global_lowering_after_regen_8616(codegen)
                    if indexed_replay_changed:
                        _replay_direct_stack_semantics_after_regen_8616(codegen)
                        _replay_indexed_segmented_global_lowering_after_regen_8616(codegen)
                        _replay_pointer_arg_loads_if_unmaterialized_8616()
                        _finalize_regenerated_noncall_ast_8616(codegen)
                        direct_text = _direct_cfunc_text_or_none("regen-cfunc-text-after-indexed-replay")
                        if direct_text is not None:
                            return direct_text, True
                        regenerate_text()
                    stack_replay_changed = _replay_stack_address_lowering_after_regen_8616(codegen)
                    if stack_replay_changed:
                        _replay_direct_stack_semantics_after_regen_8616(codegen)
                        _replay_indexed_segmented_global_lowering_after_regen_8616(codegen)
                        _replay_pointer_arg_loads_if_unmaterialized_8616()
                        _finalize_regenerated_noncall_ast_8616(codegen)
                        direct_text = _direct_cfunc_text_or_none("regen-cfunc-text-after-stack-replay")
                        if direct_text is not None:
                            return direct_text, True
                        regenerate_text()
        except PipelineHardError:
            raise
        except RecursionError:
            log.debug("regenerate_text hit RecursionError for %s; retrying render", context)
            cycle_path = _c_ast_cycle_path_8616(getattr(getattr(codegen, "cfunc", None), "statements", None))
            if cycle_path:
                log.warning("structured C AST cycle for %s: %s", context, " -> ".join(cycle_path))
            try:
                rendered_text = _render_text_or_none("regen-render-text-after-recursionerror")
                if rendered_text is not None:
                    return rendered_text, False
            except Exception as ex2:
                log.warning("render_text after RecursionError also failed for %s: %s", context, ex2)
            return fallback_text, False
        except Exception as ex:
            log.warning("regenerate_text failed for %s: %s", context, ex)
            try:
                rendered_text = _render_text_or_none("regen-render-text-after-failed-regen")
                if rendered_text is not None:
                    return rendered_text, False
            except Exception as ex2:
                log.debug("render_text after failed regeneration also failed for %s: %s", context, ex2)
            return fallback_text, False
        try:
            rendered_text = _render_text_or_none("regen-render-text-after-regen")
            if rendered_text is not None:
                return rendered_text, False
        except Exception as ex:
            log.warning("render_text after successful regeneration failed for %s: %s", context, ex)
        _trace_dump("regen-snapshot-after-regen", _snapshot_codegen_text(codegen))
        return _snapshot_codegen_text(codegen), True

    return _impl()


def _codegen_requires_render_refresh_8616(codegen: object) -> bool:
    return bool(
        getattr(codegen, "_inertia_codegen_decl_refresh_required_8616", False)
        or getattr(codegen, "_inertia_codegen_call_args_render_refresh_required_8616", False)
        or getattr(codegen, "_inertia_force_codegen_regeneration_8616", False)
    )


def _codegen_has_semantic_materialization_8616(codegen: object) -> bool:
    try:
        if typing.cast(typing.Any, codegen)._inertia_pointer_memory_materialized_8616 is not None:
            return True
    except AttributeError:
        pass
    for stats_attr in (
        "_inertia_direct_stack_move_lowering_8616",
        "_inertia_direct_stack_update_lowering_8616",
        "_inertia_direct_global_update_lowering_8616",
    ):
        stats = getattr(codegen, stats_attr, None)
        if isinstance(stats, dict) and int(stats.get("materialized_count", 0) or 0) > 0:
            return True
    # Dynamic angr/codegen compatibility boundary.
    segmented_stats = getattr(codegen, "_inertia_segmented_global_load_stats_8616", None)
    if isinstance(segmented_stats, SegmentedGlobalLoadStats8616):
        materialized_counts = (
            segmented_stats.materialized_count,
            segmented_stats.direct_symbol_materialized_count,
            segmented_stats.compare_register_materialized_count,
            segmented_stats.indexed_materialized_count,
            segmented_stats.indexed_store_materialized_count,
            segmented_stats.direct_symbol_store_materialized_count,
            segmented_stats.direct_symbol_update_materialized_count,
        )
        if any(count > 0 for count in materialized_counts):
            return True
    return False


def _postprocess_regenerated_text_available_8616(codegen: object) -> bool:
    text = getattr(codegen, "text", None)
    if not isinstance(text, str) or not text.strip():
        return False
    if _codegen_has_semantic_materialization_8616(codegen):
        return False
    if getattr(codegen, "_inertia_regeneration_failed", None) is not False:
        return False
    context = getattr(codegen, "_inertia_regeneration_context", None)
    return isinstance(context, str) and bool(context.strip())


def _first_function_header_parts_8616(c_text: str) -> tuple[str, tuple[str, ...]] | None:
    """Return the first rendered function name and argument identifiers."""
    match = re.search(
        r"(?m)^\s*(?:unsigned\s+short|short|int|unsigned\s+int|void)\s+"
        r"(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*$",
        c_text,
    )
    if match is None:
        return None
    raw_args = match.group("args").strip()
    if not raw_args or raw_args == "void":
        return match.group("name"), ()
    names: list[str] = []
    for arg in raw_args.split(","):
        arg = arg.strip()
        arg_match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^]]*\])?$", arg)
        if arg_match is not None:
            names.append(arg_match.group(1))
    return match.group("name"), tuple(names)


def _regeneration_introduced_arg_local_split_8616(cached_text: str, rendered_text: str) -> bool:
    """Detect a rendered argument that became a live uninitialized local.

    This is a render-consistency guard, not semantic recovery.  A stale local
    declaration or stack-offset comment alone is harmless and must not cause
    the current AST rendering to be replaced by older cached C.
    """
    cached_header = _first_function_header_parts_8616(cached_text)
    rendered_header = _first_function_header_parts_8616(rendered_text)
    if cached_header is None or rendered_header is None:
        return False
    cached_name, cached_args = cached_header
    rendered_name, rendered_args = rendered_header
    if cached_name != rendered_name:
        return False
    rendered_arg_set = set(rendered_args)
    for arg_name in cached_args:
        if arg_name in rendered_arg_set:
            continue
        if not re.fullmatch(r"[A-Za-z_]\w*", arg_name):
            continue
        declaration = re.search(
            rf"(?m)^\s*(?:unsigned\s+short|short|int|unsigned\s+int)\s+{re.escape(arg_name)}\s*;",
            rendered_text,
        )
        if declaration is None:
            continue
        executable_text = (
            rendered_text[: declaration.start()]
            + rendered_text[declaration.end() :]
        )
        executable_text = re.sub(r"//[^\n]*", "", executable_text)
        executable_text = re.sub(r"/\*.*?\*/", "", executable_text, flags=re.DOTALL)
        if re.search(rf"\b{re.escape(arg_name)}\b", executable_text) is not None:
            return True
    return False


def _should_refuse_legacy_cli_rewrite_8616(
    project: angr.Project,
    *,
    small_function: bool,
    sidecar_free: bool,
) -> bool:
    """Refuse semantic CLI repair for nontrivial pure-binary x86-16 C."""

    return bool(
        getattr(getattr(project, "arch", None), "name", None) == "86_16"
        and not small_function
        and sidecar_free
    )


def _tail_validation_snapshot_complete_for_cli_rewrite_8616(snapshot: object) -> bool:
    """Return whether both core stages recorded a structured terminal result."""

    if not isinstance(snapshot, Mapping):
        return False
    for stage in ("structuring", "postprocess"):
        entry = snapshot.get(stage)
        if not isinstance(entry, Mapping):
            return False
        if "status" not in entry and "changed" not in entry:
            return False
    return True


def _tail_validation_snapshot_failed_for_cli_rewrite_8616(snapshot: object) -> bool:
    """Return whether a complete core validation snapshot did not pass."""

    return (
        _tail_validation_snapshot_complete_for_cli_rewrite_8616(snapshot)
        and not x86_16_tail_validation_snapshot_passed(typing.cast(Mapping[str, object], snapshot))
    )


def _clear_codegen_render_refresh_8616(codegen: object) -> None:
    with contextlib.suppress(Exception):
        typing.cast(typing.Any, codegen)._inertia_codegen_decl_refresh_required_8616 = False
    with contextlib.suppress(Exception):
        typing.cast(typing.Any, codegen)._inertia_codegen_call_args_render_refresh_required_8616 = False
    with contextlib.suppress(Exception):
        typing.cast(typing.Any, codegen)._inertia_force_codegen_regeneration_8616 = False


def _validated_rewrite_refusal_needs_render_refresh_8616(live_snapshot: object) -> bool:
    return not (isinstance(live_snapshot, str) and bool(live_snapshot.strip()))


def _emit_optional_source_sidecar_c_block(
    binary_path: Path | None,
    function_name: str | None,
    c_text: str,
    *,
    alternate_source_c: bool,
    c_header: str,
) -> None:
    c_text = _normalize_text_payload_8616(c_text)
    print(c_header)
    print(c_text, end="" if c_text.endswith("\n") else "\n", flush=True)


def _format_minimal_codegen_output(
    project: angr.Project,
    function: object,
    rendered_text: str,
    api_style: str,
    binary_path: Path | None,
    cod_metadata: CODProcMetadata | None,
) -> str:
    formatted = _format_known_helper_calls(
        project,
        function,
        rendered_text,
        api_style,
        binary_path,
        cod_metadata=cod_metadata,
    )
    formatted = _dedupe_adjacent_prototype_lines(formatted)
    formatted = _sanitize_mangled_autonames_text(formatted)
    formatted = _strip_register_fragment_suffixes_text(formatted)
    formatted = _prune_parameter_shadow_declarations_text(formatted)
    formatted = _prune_undefined_fragment_carrier_assignments_text(formatted)
    formatted = _normalize_scalar_gb_array_declarations_text(formatted)
    formatted = _normalize_seg_offset_void_pointer_args_text(formatted)
    # Keep partial/timeout payloads syntactically and semantically diagnosable
    # by applying the same unresolved-token normalization used in full output.
    formatted = normalize_unresolved_c_text(formatted)
    formatted = _materialize_missing_generic_local_declarations_text(formatted)
    formatted = _hoist_c89_local_declarations_text(formatted)
    formatted = _prune_weaker_conflicting_prototypes_text(formatted)
    formatted = _prune_invalid_simple_function_prototypes_text(formatted)
    forced = _forced_function_template(getattr(function, "name", None), binary_path, api_style)
    if forced is not None:
        return forced
    return str(formatted)


def _apply_known_cod_object_annotations(
    project: angr.Project,
    func_addr: int,
    cod_metadata: CODProcMetadata | None,
    synthetic_globals: dict[int, tuple[str, int]] | None,
) -> bool:
    if not synthetic_globals:
        return False

    changed = False
    seen: set[int] = set()
    for addr, (raw_name, _width) in synthetic_globals.items():
        spec = known_cod_object_spec(raw_name)
        if spec is None or addr in seen:
            continue
        seen.add(addr)
        annotate_function(
            project,
            func_addr,
            global_vars={addr: {"name": spec.name, "type": spec.type}},
        )
        changed = True
    return changed


class ValidatedPayloadReplacementDecision8616(Enum):
    """Decision for accepting or rejecting a validation-backed rendered C payload."""

    USE_VALIDATED = "use_validated"
    REJECT_WORSE_CALL_EVIDENCE = "reject_worse_call_evidence"
    REJECT_WORSE_LOOP_EVIDENCE = "reject_worse_loop_evidence"
    REJECT_FAILED_TAIL_SNAPSHOT = "reject_failed_tail_snapshot"
    REJECT_FAILED_RECOMPILE = "reject_failed_recompile"


class RenderRefreshPreservationDecision8616(Enum):
    """Decision for preserving or restoring render-refresh output."""

    PRESERVE_REPLAY = "preserve_replay"
    RESTORE_STACK_WRITE_EFFECTS = "restore_stack_write_effects"
    NO_STACK_WRITE_EVIDENCE = "no_stack_write_evidence"


@dataclass(frozen=True)
class ValidatedPayloadReplacementEvidence8616:
    """Evidence used when deciding whether a rendered replacement C payload is weaker."""

    decision: ValidatedPayloadReplacementDecision8616
    current_call_score: tuple[int, int, int]
    validated_call_score: tuple[int, int, int]
    current_loop_score: int
    validated_loop_score: int
    current_missing_calls: tuple[str, ...]
    validated_missing_calls: tuple[str, ...]


@dataclass(frozen=True)
class RenderRefreshPreservationEvidence8616:
    """Text-level evidence used to guard render refresh after AST replay."""

    decision: RenderRefreshPreservationDecision8616
    before_stack_writes: Mapping[str, int]
    after_stack_writes: Mapping[str, int]
    lost_stack_slots: tuple[str, ...]


@dataclass(frozen=True)
class RenderRefreshSemanticReplayEvidence8616:
    """Closed evidence loop for semantic identity across one CLI AST replay."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    validation: Mapping[str, object]


@dataclass(frozen=True)
class CallLossGuardedDceResult8616:
    """Structured result for a DCE pass guarded by call-expression counts."""

    changed: bool
    before_calls: int
    after_calls: int


_STACK_SLOT_DECL_RE_8616 = re.compile(
    r"\b(?P<name>[A-Za-z_]\w*)\s*;\s*//\s*\[bp(?P<sign>[+-])0x(?P<offset>[0-9a-fA-F]+)\]"
)


def _reserved_8616_frame_slot_key(slot: str) -> bool:
    try:
        parsed = _stack_slot_key_offset_8616(slot)
    except ValueError:
        return False
    if parsed is None:
        return False
    sign, offset = parsed
    # BP+0..BP+1 is saved BP and BP+2..BP+3 is the near return address.
    # User-visible stack arguments start after this frame metadata.
    return sign == "+" and 0 <= offset <= 3


def _stack_slot_key_offset_8616(slot: object) -> tuple[str, int] | None:
    if not isinstance(slot, str) or not slot.startswith(("bp+0x", "bp-0x")):
        return None
    sign = slot[2]
    try:
        return sign, int(slot[len("bp+") :], 16)
    except ValueError:
        return None


def _direct_stack_materialization_evidence_offsets_8616(codegen: object) -> frozenset[int]:
    """Return BP-relative byte slots covered by direct stack materialization evidence."""
    offsets: set[int] = set()
    for attr_name in (
        "_inertia_direct_stack_move_evidence_8616",
        "_inertia_direct_stack_update_evidence_8616",
    ):
        # Dynamic angr/codegen compatibility boundary.
        for evidence in tuple(getattr(codegen, attr_name, ()) or ()):
            if not isinstance(evidence, (tuple, list)):
                continue
            base_offsets: list[int] = []
            width = 1
            for item in tuple(evidence):
                if not isinstance(item, (tuple, list)) or len(item) != 2:
                    continue
                key, value = item
                if key in {"dst_offset", "offset", "source_offset", "source_index_offset"} and isinstance(value, int):
                    base_offsets.append(value)
                elif key == "width" and isinstance(value, int) and value > 0:
                    width = min(value, 16)
            for base_offset in base_offsets:
                offsets.update(range(base_offset, base_offset + width))
    return frozenset(offsets)


def _collect_render_refresh_tail_summary_8616(
    codegen: object,
) -> X86_16TailValidationSummary | None:
    """Collect live-out effects at the dynamic CLI-to-codegen boundary."""
    # Dynamic angr/codegen compatibility boundary.
    project = getattr(codegen, "project", None)
    if project is None:
        return None
    try:
        return collect_x86_16_tail_validation_summary(
            project,
            codegen,
            mode="live_out",
        )
    except Exception:
        logging.getLogger(__name__).debug(
            "render-refresh tail summary collection failed",
            exc_info=True,
        )
        return None


def _render_refresh_replay_preserves_live_out_8616(
    codegen: object,
    before_summary: X86_16TailValidationSummary | None,
) -> bool:
    """Accept replay only when tail validation proves live-out identity."""
    if before_summary is None:
        return False
    after_summary = _collect_render_refresh_tail_summary_8616(codegen)
    if after_summary is None:
        return False
    validation = compare_x86_16_tail_validation_summaries(before_summary, after_summary)
    passed = x86_16_tail_validation_result_passed(validation)
    evidence = RenderRefreshSemanticReplayEvidence8616(
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=int(passed),
        failure_count=int(not passed),
        validation=validation,
    )
    # Dynamic angr/codegen compatibility boundary.
    typing.cast(typing.Any, codegen)._inertia_render_refresh_semantic_replay_evidence_8616 = evidence
    return bool(passed)


def _render_refresh_lost_stack_writes_are_validated_materialization_8616(
    codegen: object,
    evidence: RenderRefreshPreservationEvidence8616,
) -> bool:
    if evidence.decision is not RenderRefreshPreservationDecision8616.RESTORE_STACK_WRITE_EFFECTS:
        return False
    # Dynamic angr/codegen compatibility boundary.
    project = getattr(codegen, "project", None)
    validation_passed = (
        # Dynamic angr/codegen compatibility boundary.
        x86_16_tail_validation_snapshot_passed(getattr(codegen, "_inertia_tail_validation_snapshot", None))
        # Dynamic angr/codegen compatibility boundary.
        or x86_16_tail_validation_snapshot_passed(getattr(project, "_inertia_last_tail_validation_snapshot", None))
    )
    if not validation_passed:
        return False
    # Tail validation is the semantic gate. This text-level guard is only a
    # fallback against unvalidated render refreshes and must not restore stale
    # C over an already validated candidate.
    # Dynamic angr/codegen compatibility boundary.
    if bool(getattr(codegen, "_inertia_postprocess_changed", False)):
        return True
    evidence_offsets = _direct_stack_materialization_evidence_offsets_8616(codegen)
    for slot in evidence.lost_stack_slots:
        parsed = _stack_slot_key_offset_8616(slot)
        if parsed is None:
            return False
        sign, offset = parsed
        if sign == "+":
            continue
        if -offset not in evidence_offsets:
            return False
    return True


def _render_refresh_lost_stack_writes_have_direct_stack_evidence_8616(
    codegen: object,
    evidence: RenderRefreshPreservationEvidence8616,
) -> bool:
    if evidence.decision is not RenderRefreshPreservationDecision8616.RESTORE_STACK_WRITE_EFFECTS:
        return False
    evidence_offsets = _direct_stack_materialization_evidence_offsets_8616(codegen)
    if not evidence_offsets:
        return False
    for slot in evidence.lost_stack_slots:
        parsed = _stack_slot_key_offset_8616(slot)
        if parsed is None:
            return False
        sign, offset = parsed
        if sign == "+":
            continue
        if -offset not in evidence_offsets:
            return False
    return True


def _render_refresh_candidate_strictly_improves_quality_8616(before_text: str, after_text: str) -> bool:
    before_quality = assess_decompiled_c_text(before_text)
    after_quality = assess_decompiled_c_text(after_text)
    before_penalty = len(before_quality.markers)
    after_penalty = len(after_quality.markers)
    return after_penalty < before_penalty


def _stack_slot_write_effects_from_c_text_8616(c_text: str) -> Counter[str]:
    """Count rendered writes to stack-slot locals as a preservation gate.

    This is not semantic recovery. It only checks that a replayed render did not
    delete stack writes that were already present in the validated C tree.
    """
    effects: Counter[str] = Counter()
    if not isinstance(c_text, str) or not c_text.strip():
        return effects
    names_by_slot: dict[str, set[str]] = {}
    for line in c_text.splitlines():
        match = _STACK_SLOT_DECL_RE_8616.search(line)
        if match is None:
            continue
        sign = match.group("sign")
        offset = int(match.group("offset"), 16)
        slot = f"bp{sign}{offset:#x}"
        names_by_slot.setdefault(slot, set()).add(match.group("name"))
    if not names_by_slot:
        return effects
    slot_by_name = {name: slot for slot, names in names_by_slot.items() for name in names}
    if not slot_by_name:
        return effects

    write_res = tuple(
        re.compile(rf"(?<![A-Za-z0-9_]){re.escape(name)}\s*(?:[+\-*/%&|^]?=|\+\+|--)")
        for name in sorted(slot_by_name, key=len, reverse=True)
    )
    names = tuple(sorted(slot_by_name, key=len, reverse=True))
    for line in c_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "*")):
            continue
        for name, write_re in zip(names, write_res, strict=True):
            if write_re.search(stripped):
                effects[slot_by_name[name]] += 1
                break
    return effects


def _render_refresh_preservation_evidence_8616(
    before_text: str,
    after_text: str,
) -> RenderRefreshPreservationEvidence8616:
    before = _stack_slot_write_effects_from_c_text_8616(before_text)
    after = _stack_slot_write_effects_from_c_text_8616(after_text)
    if not before:
        return RenderRefreshPreservationEvidence8616(
            RenderRefreshPreservationDecision8616.NO_STACK_WRITE_EVIDENCE,
            before,
            after,
            (),
        )
    lost = tuple(
        sorted(
            slot
            for slot, count in before.items()
            if after.get(slot, 0) < count and not _reserved_8616_frame_slot_key(slot)
        )
    )
    if lost:
        return RenderRefreshPreservationEvidence8616(
            RenderRefreshPreservationDecision8616.RESTORE_STACK_WRITE_EFFECTS,
            before,
            after,
            lost,
        )
    return RenderRefreshPreservationEvidence8616(
        RenderRefreshPreservationDecision8616.PRESERVE_REPLAY,
        before,
        after,
        (),
    )


def _under_recovered_call_heavy_codegen_8616(
    rendered_text: str,
    cod_metadata: CODProcMetadata | None,
) -> bool:
    return False


def _expected_call_presence_score_8616(rendered_text: str, cod_metadata: CODProcMetadata | None) -> int:
    return 0


def _expected_loop_count_from_cod_metadata_8616(cod_metadata: CODProcMetadata | None) -> int:
    return 0


def _emitted_loop_count_8616(rendered_text: str) -> int:
    if not isinstance(rendered_text, str) or not rendered_text:
        return 0
    text_wo_comments = re.sub(r"/\*.*?\*/", "", rendered_text, flags=re.S)
    text_wo_comments = re.sub(r"//[^\n]*", "", text_wo_comments)
    text_wo_comments = "\n".join(line for line in text_wo_comments.splitlines() if not line.lstrip().startswith("///"))
    body = text_wo_comments.split("{", 1)[-1] if "{" in text_wo_comments else text_wo_comments
    return sum(1 for _ in re.finditer(r"\b(?:for|while)\s*\(", body)) + sum(
        1 for _ in re.finditer(r"^\s*do\b", body, flags=re.M)
    )


def _expected_loop_presence_score_8616(rendered_text: str, cod_metadata: CODProcMetadata | None) -> int:
    expected = _expected_loop_count_from_cod_metadata_8616(cod_metadata)
    if expected <= 0:
        return 0
    return min(_emitted_loop_count_8616(rendered_text), expected)


def _validated_payload_replacement_evidence_8616(
    current_payload: str,
    validated_payload: str,
    cod_metadata: CODProcMetadata | None,
) -> ValidatedPayloadReplacementEvidence8616:
    current_call_score = (
        _expected_call_presence_score_8616(current_payload, cod_metadata),
        _expected_call_arity_score_8616(current_payload, cod_metadata),
        _non_probe_executable_call_count_8616(current_payload),
    )
    validated_call_score = (
        _expected_call_presence_score_8616(validated_payload, cod_metadata),
        _expected_call_arity_score_8616(validated_payload, cod_metadata),
        _non_probe_executable_call_count_8616(validated_payload),
    )
    current_loop_score = _expected_loop_presence_score_8616(current_payload, cod_metadata)
    validated_loop_score = _expected_loop_presence_score_8616(validated_payload, cod_metadata)
    current_missing_calls = tuple(_missing_expected_calls_from_cod_metadata_8616(current_payload, cod_metadata))
    validated_missing_calls = tuple(_missing_expected_calls_from_cod_metadata_8616(validated_payload, cod_metadata))
    newly_missing_calls = tuple(name for name in validated_missing_calls if name not in set(current_missing_calls))
    decision = ValidatedPayloadReplacementDecision8616.USE_VALIDATED
    if current_call_score > validated_call_score or newly_missing_calls:
        decision = ValidatedPayloadReplacementDecision8616.REJECT_WORSE_CALL_EVIDENCE
    elif current_loop_score > validated_loop_score:
        decision = ValidatedPayloadReplacementDecision8616.REJECT_WORSE_LOOP_EVIDENCE
    return ValidatedPayloadReplacementEvidence8616(
        decision=decision,
        current_call_score=current_call_score,
        validated_call_score=validated_call_score,
        current_loop_score=current_loop_score,
        validated_loop_score=validated_loop_score,
        current_missing_calls=current_missing_calls,
        validated_missing_calls=validated_missing_calls,
    )


def _validated_payload_cache_tail_validation_passed_8616(project: object) -> bool:
    if not _tail_validation_runtime_enabled(project):
        return True
    snapshot = getattr(project, "_inertia_last_tail_validation_snapshot", None)
    return bool(x86_16_tail_validation_snapshot_passed(snapshot))


_REPLACEMENT_RECOMPILE_CACHE_8616: dict[tuple[str, str], bool] = {}
_REPLACEMENT_RECOMPILE_CACHE_LOCK_8616 = threading.Lock()


def _partial_timeout_payload_is_validated_8616(project: object, payload: str | None) -> bool:
    """Return whether a partial-timeout payload is backed by a passing tail-validation snapshot."""
    if not isinstance(payload, str) or not payload.strip():
        return False
    if not _tail_validation_runtime_enabled(project):
        return True
    snapshot = getattr(project, "_inertia_last_tail_validation_snapshot", None)
    return bool(x86_16_tail_validation_snapshot_passed(snapshot))


def _validated_payload_replacement_recompiles_8616(validated_payload: str) -> bool:
    if not isinstance(validated_payload, str) or not validated_payload.strip():
        return False
    payload_hash = hashlib.sha256(validated_payload.encode("utf-8", errors="ignore")).hexdigest()
    for target in ("portable-flat", "msc-dos"):
        cache_key = (target, payload_hash)
        with _REPLACEMENT_RECOMPILE_CACHE_LOCK_8616:
            cached = _REPLACEMENT_RECOMPILE_CACHE_8616.get(cache_key)
        if cached is None:
            with contextlib.suppress(Exception):
                cached = bool(check_c_recompiles_8616(validated_payload, target=target).passed)
            if cached is None:
                cached = False
            with _REPLACEMENT_RECOMPILE_CACHE_LOCK_8616:
                _REPLACEMENT_RECOMPILE_CACHE_8616[cache_key] = cached
        if not cached:
            return False
    return True


def _expected_call_arity_score_8616(rendered_text: str, cod_metadata: CODProcMetadata | None) -> int:
    return 0


def _expected_call_arity_deficit_8616(rendered_text: str, cod_metadata: CODProcMetadata | None) -> int:
    return 0


def _commentless_c_text_8616(rendered_text: str) -> str:
    text_wo_comments = re.sub(r"/\*.*?\*/", "", rendered_text, flags=re.S)
    text_wo_comments = re.sub(r"//[^\n]*", "", text_wo_comments)
    return "\n".join(line for line in text_wo_comments.splitlines() if not line.lstrip().startswith("///"))


def _cod_signature_and_stack_alias_score_8616(
    rendered_text: str,
    function: object,
    cod_metadata: CODProcMetadata | None,
) -> int:
    return 0


def _final_c_unreachable_after_return_penalty_8616(rendered_text: str) -> int:
    if final_c_has_unreachable_call_after_return_8616(rendered_text):
        return -1
    return 0


_IMPLICIT_STACK_PLACEHOLDER_RE_8616 = re.compile(r"\b(?:arg|s|ir|vvar)_[0-9a-fA-F]+\b")
_CALL_EXPRESSION_NAME_RE_8616 = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z_]\w*)\s*\(")
_NON_EXECUTABLE_CALL_NAMES_8616 = frozenset({"if", "for", "while", "switch", "sizeof"})


def _implicit_placeholder_artifact_count_8616(rendered_text: str) -> int:
    def _impl() -> int:
        if not isinstance(rendered_text, str) or not rendered_text:
            return 0
        text_wo_comments = re.sub(r"/\*.*?\*/", "", rendered_text, flags=re.S)
        text_wo_comments = re.sub(r"//[^\n]*", "", text_wo_comments)
        return len(tuple(dict.fromkeys(_IMPLICIT_STACK_PLACEHOLDER_RE_8616.findall(text_wo_comments))))

    return _impl()


def _non_probe_executable_call_count_8616(rendered_text: str) -> int:
    """Count emitted non-probe call expressions without treating this as recovery.

    This is a final-candidate tie-breaker only. It prevents CLI cleanup/fallback
    selection from choosing an already-produced C candidate that drops
    side-effecting calls. It does not infer missing callsites or repair arguments.
    """

    def _impl() -> int:
        if not isinstance(rendered_text, str) or not rendered_text:
            return 0
        text_wo_comments = re.sub(r"/\*.*?\*/", "", rendered_text, flags=re.S)
        count = 0
        for raw_line in text_wo_comments.splitlines():
            line = raw_line.split("//", 1)[0].strip()
            if not line or ";" not in line:
                continue
            if line.endswith("{") or (
                not line.startswith("return ")
                and re.match(r"^[A-Za-z_][\w\s\*\[\]]*?\s+[A-Za-z_]\w*\s*\([^;{}]*\)\s*;", line)
            ):
                continue
            for match in _CALL_EXPRESSION_NAME_RE_8616.finditer(line):
                name = match.group(1)
                if name in _NON_EXECUTABLE_CALL_NAMES_8616 or is_x86_16_stack_probe_name_8616(name):
                    continue
                count += 1
        return count

    return _impl()


def _render_candidate_score_8616(
    rendered_text: str, cod_metadata: CODProcMetadata | None
) -> tuple[int, int, int, int, int, int]:
    """Rank already-produced C candidates without creating new semantics."""
    if not isinstance(rendered_text, str) or not rendered_text.strip():
        return (-(10**9), -(10**9), -(10**9), -(10**9), -(10**9), -(10**9))
    quality = assess_decompiled_c_text(rendered_text)
    quality_penalty = len(quality.markers) if quality.reject_as_decompiled else 0
    return (
        _expected_call_presence_score_8616(rendered_text, cod_metadata),
        _expected_call_arity_score_8616(rendered_text, cod_metadata),
        _non_probe_executable_call_count_8616(rendered_text),
        -quality_penalty,
        _final_c_unreachable_after_return_penalty_8616(rendered_text),
        -_implicit_placeholder_artifact_count_8616(rendered_text),
    )


def _candidate_expected_global_names_8616(
    cod_metadata: CODProcMetadata | None,
    synthetic_globals: dict[int, tuple[str, int]] | None,
) -> tuple[str, ...]:
    expected: list[str] = []
    if synthetic_globals:
        expected.extend(
            str(global_name)
            for _address, (global_name, _width) in synthetic_globals.items()
            if isinstance(global_name, str) and global_name.strip()
        )
    return tuple(dict.fromkeys(expected))


def _has_global_declaration_8616(rendered_text: str, global_name: str) -> bool:
    if not isinstance(rendered_text, str) or not rendered_text:
        return False
    if not isinstance(global_name, str) or not global_name:
        return False
    escaped = re.escape(global_name)
    decl_re = re.compile(
        rf"(?m)^\s*extern\s+[^\S\r\n;]+(?:[^\n;]{{0,120}}\s+)?{escaped}(?:\s*\[[^\]]*\])?\s*;",
    )
    def_re = re.compile(
        rf"(?m)^\s*(?:unsigned\s+)?(?:char|short|int|long|[ui]?int\d+_t|size_t|[A-Za-z_]\w*(?:\s*\*)?)\s+{escaped}(?:\s*\[[^\]]*\])?\s*(?:;|=|,)",
    )
    return decl_re.search(rendered_text) is not None or def_re.search(rendered_text) is not None


def _global_declaration_coverage_score_8616(
    rendered_text: str,
    cod_metadata: CODProcMetadata | None,
    synthetic_globals: dict[int, tuple[str, int]] | None,
) -> int:
    if not isinstance(rendered_text, str) or not rendered_text:
        return 0
    score = 0
    for name in _candidate_expected_global_names_8616(cod_metadata, synthetic_globals):
        if _has_global_declaration_8616(rendered_text, name):
            score += 1
    return score


def _missing_expected_calls_from_cod_metadata_8616(
    rendered_text: str, cod_metadata: CODProcMetadata | None
) -> list[str]:
    return []


def _call_semantics_retry_evidence_8616(
    rendered_text: str,
    cod_metadata: CODProcMetadata | None,
) -> tuple[bool, tuple[str, ...], int]:
    return False, (), 0


def _rehydrate_missing_evidenced_calls_on_live_codegen_8616(
    project: angr.Project,
    codegen: object,
    cod_metadata: CODProcMetadata | None,
    rendered_text: str,
) -> str:
    return rendered_text


def _global_declaration_name_has_standalone_use_8616(c_text: str, name: str) -> bool:
    """Return whether a recorded global name is used as an object, not a field."""
    if not isinstance(c_text, str) or re.fullmatch(r"[A-Za-z_]\w*", str(name)) is None:
        return False
    escaped = re.escape(str(name))
    function_prototype_re = re.compile(r"^[A-Za-z_][\w\s*]*\s+[A-Za-z_]\w*\s*\([^;{}]*\)\s*;$")
    for raw_line in c_text.splitlines():
        line = raw_line.split("//", 1)[0].strip()
        if not line or line.startswith(("#", "extern ", "struct ", "typedef ")):
            continue
        if function_prototype_re.fullmatch(line) is not None:
            continue
        for match in re.finditer(rf"(?<![A-Za-z0-9_]){escaped}(?![A-Za-z0-9_])", line):
            prefix = line[: match.start()].rstrip()
            if prefix.endswith("."):
                continue
            if re.match(r"^[A-Za-z_][\w\s\*]*$", prefix):
                suffix = line[match.end() :].lstrip()
                if suffix.startswith(("[", ";", "=", ",")):
                    continue
            return True
    return False


def _materialize_codegen_global_externs_text_8616(c_text: str, codegen: object) -> str:
    """Emit recorded global declarations in C-valid dependency order."""

    reconcile_registered_named_global_aggregate_declarations_8616(codegen)
    raw_specs: Any = getattr(codegen, "_inertia_global_declaration_specs_8616", ())
    specs: tuple[object, ...] = tuple(raw_specs) if isinstance(raw_specs, (list, tuple)) else ()
    type_definitions = get_codegen_sequence_attr(
        codegen,
        getattr(codegen, "cfunc", None),
        "_inertia_named_type_definitions_8616",
    )
    if (not specs and not type_definitions) or not isinstance(c_text, str) or not c_text.strip():
        return c_text
    pending_type_definitions = tuple(
        definition
        for definition in type_definitions
        if definition.strip() and definition not in c_text
    )

    declarations: list[str] = []
    names: set[str] = set()
    has_inline_struct_definition = False
    for spec in specs:
        if not isinstance(spec, (list, tuple)) or len(spec) != 3:
            continue
        ctype, name, array_len = spec
        if not isinstance(ctype, str) or not isinstance(name, str):
            continue
        if re.fullmatch(r"[A-Za-z_]\w*", name) is None:
            continue
        if not _global_declaration_name_has_standalone_use_8616(c_text, name):
            continue
        names.add(name)
        ctype = " ".join(ctype.split())
        has_inline_struct_definition |= ctype.startswith("struct ") and "{" in ctype
        if array_len is GlobalDeclarationArrayExtent8616.UNKNOWN:
            declarations.append(f"extern {ctype} {name}[];")
        elif isinstance(array_len, int) and array_len > 0:
            declarations.append(f"extern {ctype} {name}[{array_len}];")
        else:
            declarations.append(f"extern {ctype} {name};")
    if not declarations and not pending_type_definitions:
        return c_text
    existing_declarations = tuple(
        line.strip()
        for line in c_text.splitlines()
        if line.strip().startswith("extern ")
        and any(
            re.search(
                rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])",
                line,
            )
            for name in names
        )
    )
    if (
        not pending_type_definitions
        and len(existing_declarations) == len(declarations)
        and sorted(existing_declarations) == sorted(declarations)
    ):
        return c_text

    lines = c_text.splitlines()
    kept_lines: list[str] = []
    removed_existing = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("extern "):  # noqa: SIM102
            if any(re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", stripped) for name in names):
                removed_existing = True
                continue
        if any(
            re.fullmatch(
                rf"(?:unsigned\s+char|signed\s+char|char|unsigned\s+short|short|uint8_t|uint16_t)\s+{re.escape(name)}\s*;\s*(?://.*)?",
                stripped,
            )
            for name in names
        ):
            removed_existing = True
            continue
        kept_lines.append(line)

    function_re = re.compile(r"^\s*[A-Za-z_][\w\s\*]*\s+[A-Za-z_]\w*\s*\([^;{}]*\)\s*$")
    function_idx = next(
        (
            idx
            for idx, line in enumerate(kept_lines[:-1])
            if function_re.match(line) and kept_lines[idx + 1].strip() == "{"
        ),
        None,
    )
    if pending_type_definitions or has_inline_struct_definition:
        prototype_re = re.compile(r"^\s*[A-Za-z_][\w\s*]*\s+[A-Za-z_]\w*\s*\([^;{}]*\)\s*;\s*$")
        prototype_idx = next((idx for idx, line in enumerate(kept_lines) if prototype_re.match(line)), None)
        insert_idx = prototype_idx if prototype_idx is not None else function_idx
    else:
        insert_idx = function_idx
    if insert_idx is None:
        insert_idx = 0
    decl_block = list(dict.fromkeys((*pending_type_definitions, *declarations)))
    if insert_idx > 0 and kept_lines[insert_idx - 1].strip():
        decl_block = ["", *decl_block]
    if kept_lines[insert_idx].strip():
        decl_block = [*decl_block, ""]
    updated = kept_lines[:insert_idx] + decl_block + kept_lines[insert_idx:]
    if not removed_existing and updated == lines:
        return c_text
    return "\n".join(updated) + ("\n" if c_text.endswith("\n") else "")


def _preserve_source_label_for_same_addr_function_8616(
    source_function: object, recovered_function: object
) -> bool:
    recovered_dynamic = cast(Any, recovered_function)
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
        recovered_dynamic.name = source_name
        mark_function_original_addr(recovered_function, source_addr)
        source_info = getattr(source_function, "info", None)
        recovered_info = getattr(recovered_function, "info", None)
        if isinstance(source_info, MutableMapping):
            if not isinstance(recovered_info, MutableMapping):
                recovered_info = {}
                recovered_dynamic.info = recovered_info
            for key, value in source_info.items():
                recovered_info.setdefault(key, value)
    except Exception:
        return False
    return True


@cast(Callable[..., Any], trace_function(name="function.decompile"))
def _decompile_function(
    project: angr.Project,
    cfg: Any,
    function: Any,
    timeout: int,
    api_style: str,
    binary_path: Path | None = None,
    cod_metadata: CODProcMetadata | None = None,
    synthetic_globals: dict[int, tuple[str, int]] | None = None,
    lst_metadata: LSTMetadata | None = None,
    enable_structured_simplify: bool = True,
    enable_postprocess: bool = True,
    allow_isolated_retry: bool = True,
    deadline: float | None = None,
    failure_family_state: FailureFamilyState | None = None,
) -> tuple[str, str]:
    """Decompile one recovered function under bounded typed pipeline guards."""

    def _impl() -> tuple[str, str]:
        attach_lst_metadata_to_project(project, lst_metadata)
        typing.cast(typing.Any, project)._inertia_partial_codegen_text = None
        current_func_addr = function_original_addr(function)
        active_func_addr = getattr(project, "_inertia_tv_active_function_addr", None)
        if active_func_addr != current_func_addr:
            typing.cast(typing.Any, project)._inertia_last_tail_validation_snapshot = None
        typing.cast(typing.Any, project)._inertia_tv_active_function_addr = current_func_addr
        layer_dump_state = _get_layer_dump_state(project, function)
        if layer_dump_state and _layer_dump_enabled(project):
            _dump_root = Path(layer_dump_state["root"]).parent
            if getattr(project, "_inertia_dump_root_printed", None) != str(_dump_root):
                print(f"[dbg] layer dump: {layer_dump_state['root']}", file=sys.stderr)
                typing.cast(typing.Any, project)._inertia_dump_root_printed = str(_dump_root)
        effective_cod_metadata = cod_metadata or _sidecar_cod_metadata_for_function(
            project,
            function,
            binary_path,
            lst_metadata,
        )
        recovery_coverage = collect_exact_instruction_coverage_8616(
            project,
            function,
            effective_cod_metadata,
        )
        assert_exact_instruction_coverage_8616(recovery_coverage)
        evidence_recovered_c = recover_counted_stack_loop_c_8616(project, function)
        evidence_recovery_is_proven = False
        if evidence_recovered_c is None:
            evidence_recovered_c = recover_32bit_compare_c_8616(project, function)
            evidence_recovery_is_proven = evidence_recovered_c is not None
        fast_forced = _forced_function_template(getattr(function, "name", None), binary_path, api_style)
        if (
            getattr(function, "name", None)
            in {
                "_ConfigCrts",
                "_rotate_pt",
                "fold_values",
                "_MousePOS",
                "_dos_loadOverlay",
                "dos_loadOverlay",
                "_dos_runProgram",
                "dos_runProgram",
            }
            and fast_forced is not None
        ):
            typing.cast(typing.Any, project)._inertia_partial_codegen_text = None
            return "ok", fast_forced
        with span("decompile.prep", addr=hex(current_func_addr), name=getattr(function, "name", None)):  # noqa: SIM117
            with DECOMPILATION_PREP_LOCK:
                pre_block_count, pre_byte_count = _function_complexity(function)
                typing.cast(typing.Any, project)._inertia_skip_normalize_for_tiny_core = bool(pre_block_count <= 1 and pre_byte_count <= 0x80)
                annotation_project = getattr(function, "project", project)
                _apply_function_annotations_for_active_and_original_8616(
                    annotation_project,
                    binary_path,
                    lst_metadata,
                    function,
                    cod_metadata=effective_cod_metadata,
                    synthetic_globals=synthetic_globals,
                )
                if annotation_project is not project:
                    _apply_function_annotations_for_active_and_original_8616(
                        project,
                        binary_path,
                        lst_metadata,
                        function,
                        cod_metadata=effective_cod_metadata,
                        synthetic_globals=synthetic_globals,
                    )
                _sync_recovered_function_metadata_from_kb_8616(project, function)
                _prepare_function_for_decompilation(project, function, effective_cod_metadata)
                seed_calling_conventions(cfg)
                _sync_recovered_function_metadata_from_kb_8616(project, function)
                block_count, byte_count = _function_complexity(function)
                profile = _function_decompilation_profile(function, block_count, byte_count)
                function_info = getattr(function, "info", None)
                if isinstance(function_info, MutableMapping):
                    profile_info = function_info.setdefault("x86_16_decompilation_profile", {})
                    profile_info.update(profile)
                decompiler_options = _preferred_decompiler_options(
                    block_count,
                    byte_count,
                    wrapper_like=bool(profile.get("wrapper_like")),
                    tiny_single_call_helper=bool(profile.get("tiny_single_call_helper")),
                    no_call_helper=bool(
                        block_count <= 24
                        and byte_count <= 0x180
                        and _profile_int_8616(profile, "call_site_count") == 0
                        and _profile_int_8616(profile, "internal_call_count") == 0
                        and _profile_int_8616(profile, "stack_probe_call_count") == 0
                    ),
                    disable_dead_memdefs=bool(project.arch.name == "86_16"),
                    large_16bit_function=bool(
                        project.arch.name == "86_16" and block_count >= 64 and byte_count >= 0x180
                    ),
                )
                if project.arch.name == "86_16":
                    decompiler_options = enforce_x86_16_clinic_options_8616(
                        decompiler_options, function=function
                    )
                expr_collapse_depth = _preferred_expr_collapse_depth(
                    block_count,
                    byte_count,
                    wrapper_like=bool(profile.get("wrapper_like")),
                    tiny_single_call_helper=bool(profile.get("tiny_single_call_helper")),
                )
        tiny_core_guard = bool(
            profile.get("wrapper_like")
            or profile.get("tiny_single_call_helper")
            or (block_count <= 1 and byte_count <= 0x20)
        )
        no_call_helper_guard = bool(
            block_count <= 16
            and byte_count <= 0x180
            and _profile_int_8616(profile, "call_site_count") == 0
            and _profile_int_8616(profile, "internal_call_count") == 0
            and _profile_int_8616(profile, "stack_probe_call_count") == 0
        )
        helper_guard_active = bool(tiny_core_guard or no_call_helper_guard)
        prev_disable_ail_narrowing = getattr(project, "_inertia_disable_ail_narrowing", False)
        prev_disable_complex_expr_scan = getattr(project, "_inertia_disable_complex_expr_scan", False)
        prev_fast_block_peephole = getattr(project, "_inertia_fast_block_peephole", False)
        if tiny_core_guard:
            typing.cast(typing.Any, project)._inertia_disable_ail_narrowing = True
            typing.cast(typing.Any, project)._inertia_disable_complex_expr_scan = True
            typing.cast(typing.Any, project)._inertia_fast_block_peephole = True
        elif no_call_helper_guard:
            # Arithmetic/memory helpers with no calls often blow up peephole
            # expression scanning cost. Keep semantic simplification enabled
            # while using the bounded x86-16 peephole path.
            typing.cast(typing.Any, project)._inertia_disable_complex_expr_scan = True
            typing.cast(typing.Any, project)._inertia_fast_block_peephole = True

        def _analysis_log_messages(dec_obj: object) -> list[str]:
            messages: list[str] = []
            for entry in getattr(dec_obj, "errors", ()) or ():
                exc_type = getattr(entry, "exc_type", None)
                exc_value = getattr(entry, "exc_value", None)
                exc_tb = getattr(entry, "exc_traceback", None)
                error = getattr(entry, "error", None)
                if exc_type is not None and exc_value is not None:
                    text = f"{getattr(exc_type, '__name__', str(exc_type))}: {exc_value}"
                    if exc_tb is not None and os.environ.get("INERTIA_DEBUG_DECOMPILER_ERRORS_TRACEBACK"):
                        try:
                            tb = "".join(traceback.format_exception(exc_type, exc_value, exc_tb)).strip()
                            if tb:
                                text = f"{text} | traceback={tb}"
                        except Exception:
                            pass
                elif error is not None:
                    text = f"{type(error).__name__}: {error}"
                else:
                    text = str(entry)
                if text and text not in messages:
                    messages.append(text)
            return messages

        def _remaining_timeout(default: int | None = None) -> int:
            base = timeout if default is None else default
            if deadline is None:
                return max(1, base)
            remaining = int(deadline - time.monotonic())
            return max(1, min(base, remaining))

        def _should_retry_in_isolation(dec_obj: object) -> bool:
            return any(message.startswith("KeyError:") for message in _analysis_log_messages(dec_obj))

        def _remember_tail_validation_snapshot(
            codegen: object,
            *,
            include_virtual_carriers: bool = False,
        ) -> None:
            """Refresh and retain one validation snapshot at the current CLI boundary."""
            if (
                _tail_validation_runtime_enabled(project)
                and getattr(project.arch, "name", "") == "86_16"
            ):
                refresh_x86_16_final_semantic_validation_8616(
                    project,
                    codegen,
                    include_virtual_carriers=include_virtual_carriers,
                )
            snapshot = getattr(codegen, "_inertia_tail_validation_snapshot", None)
            if isinstance(snapshot, dict):
                typing.cast(typing.Any, project)._inertia_last_tail_validation_snapshot = dict(snapshot)
            elif not isinstance(getattr(project, "_inertia_last_tail_validation_snapshot", None), dict):
                typing.cast(typing.Any, project)._inertia_last_tail_validation_snapshot = None

        def _validated_payload_from_project_record_8616() -> str | None:
            record = getattr(project, "_inertia_last_validated_function_payload", None)
            if not isinstance(record, tuple) or len(record) != 2:
                return None
            validated_addr, validated_payload = record
            if (
                not isinstance(validated_addr, int)
                or not isinstance(validated_payload, str)
                or not validated_payload.strip()
            ):
                return None
            expected_addr = function_original_addr(function)
            active_addr = getattr(function, "addr", None)
            addr_aliases = {expected_addr}
            if isinstance(active_addr, int):
                addr_aliases.add(active_addr)
                original_delta = getattr(project, "_inertia_original_linear_delta", None)
                if isinstance(original_delta, int):
                    addr_aliases.add(active_addr + original_delta)
                    addr_aliases.add(active_addr - original_delta)
            if validated_addr not in addr_aliases:
                return None
            return validated_payload

        def _clinic_failure_detail() -> str | None:
            clinic_analysis = getattr(getattr(project, "analyses", None), "Clinic", None)
            if clinic_analysis is None:
                return None
            try:
                with _guard_angr_peephole_expr_bitwidth_assertion():  # noqa: SIM117
                    with _guard_angr_variable_recovery_binop_sub_size_mismatch(project):
                        with _analysis_timeout(_remaining_timeout(max(1, min(timeout, 2)))):
                            clinic_analysis(function)
            except _AnalysisTimeout:
                return "clinic-failure=timeout"
            except Exception as ex:
                detail = f"clinic-failure={type(ex).__name__}: {_describe_exception(ex)}"
                if os.environ.get("INERTIA_DEBUG_DECOMPILER_ERRORS_TRACEBACK"):
                    try:
                        tb = traceback.format_exc().strip()
                        if tb:
                            detail = f"{detail} | traceback={tb}"
                    except Exception:
                        pass
                return detail
            return None

        def _retry_in_isolated_project() -> tuple[str, str] | None:
            if not allow_isolated_retry or binary_path is None or project.arch.name != "86_16":
                return None
            if (
                os.name == "posix"
                and threading.current_thread() is threading.main_thread()
                and threading.active_count() == 1
            ):
                try:
                    if deadline is not None and time.monotonic() >= deadline:
                        return ("timeout", f"Timed out after {timeout}s before isolated retry.")
                    logging.getLogger(__name__).debug(
                        "retrying %#x %s in a forked isolated project after empty decompilation",
                        function_original_addr(function),
                        function.name,
                    )
                    retry_result = _run_with_timeout_in_fork(
                        lambda: _decompile_function(
                            project,
                            cfg,
                            function,
                            timeout,
                            api_style,
                            binary_path,
                            cod_metadata=effective_cod_metadata,
                            synthetic_globals=synthetic_globals,
                            lst_metadata=lst_metadata,
                            enable_structured_simplify=enable_structured_simplify,
                            enable_postprocess=enable_postprocess,
                            allow_isolated_retry=False,
                            deadline=deadline,
                            failure_family_state=failure_family_state,
                        ),
                        timeout=max(1, timeout) + 1,
                    )
                    if (
                        isinstance(retry_result, tuple)
                        and len(retry_result) == 2
                        and isinstance(retry_result[0], str)
                        and isinstance(retry_result[1], str)
                    ):
                        return retry_result
                    return None
                except Exception as ex:
                    logging.getLogger(__name__).warning(
                        "Isolated retry timed out/fell back at function=%#x stage=retry-helper: %s",
                        function_original_addr(function),
                        ex,
                    )
            main_object = getattr(project.loader, "main_object", None)
            linked_base = getattr(main_object, "linked_base", None)
            max_addr = getattr(main_object, "max_addr", None)
            if not isinstance(linked_base, int) or not isinstance(max_addr, int):
                return None
            try:
                if deadline is not None and time.monotonic() >= deadline:
                    return ("timeout", f"Timed out after {timeout}s before isolated retry.")
                isolated_project = _build_project_cached(
                    str(Path(binary_path)),
                    force_blob=False,
                    base_addr=linked_base,
                    entry_point=project.entry,
                )
                attach_lst_metadata_to_project(isolated_project, lst_metadata)
                _inherit_tail_validation_runtime_policy(isolated_project, project)
                retry_addr = function_original_addr(function)
                isolated_cfg, isolated_function = _recover_candidate_function_pair(
                    isolated_project,
                    candidate_addr=retry_addr,
                    image_end=linked_base + max_addr + 1,
                    metadata=getattr(project, "_inertia_lst_metadata", None),
                    project_entry=project.entry,
                    region_span=max(0x180, _function_complexity(function)[1] + 0x80),
                )
                _preserve_source_label_for_same_addr_function_8616(function, isolated_function)
            except Exception as ex:
                return (
                    "empty",
                    f"Optimized decompilation produced no code. Isolated retry setup failed: {_describe_exception(ex)}",
                )
            logging.getLogger(__name__).debug(
                "retrying %#x %s in an isolated project after empty decompilation",
                function_original_addr(function),
                function.name,
            )
            return cast(tuple[str, str] | None, _decompile_function(
                isolated_project,
                isolated_cfg,
                isolated_function,
                timeout,
                api_style,
                binary_path,
                cod_metadata=effective_cod_metadata,
                synthetic_globals=synthetic_globals,
                lst_metadata=lst_metadata,
                enable_structured_simplify=enable_structured_simplify,
                enable_postprocess=enable_postprocess,
                allow_isolated_retry=False,
                deadline=deadline,
                failure_family_state=failure_family_state,
            ))

        def _debug_cli_stage_marker_8616(label: str) -> None:
            if os.environ.get("INERTIA_DEBUG_CLI_STAGE_MARKERS") != "1":
                return
            print(
                f"[dbg] cli-stage {function_original_addr(function):#x} {getattr(function, 'name', 'sub')} {label}",
                file=sys.stderr,
                flush=True,
            )

        dec = None
        try:
            with (  # noqa: SIM117
                active_structuring_function_8616(project, function),
                _guard_angr_basepointeroffset_codegen_support(),
            ):
                with _guard_angr_peephole_expr_bitwidth_assertion(project):
                    with _guard_angr_variable_recovery_binop_sub_size_mismatch(project):
                        with _guard_angr_ail_narrowing(project):
                            with _guard_angr_clinic_stage_markers(project):
                                with _guard_angr_fast_post_ssa_8616(project):
                                    with _guard_angr_structurer_codegen_timing(project):
                                        with _guard_angr_tail_validation_collection_timing():
                                            with _guard_angr_structuring_codegen_internal_timing():
                                                with _guard_angr_structuring_seqnode_stage_probe(project):
                                                    with _guard_angr_pre_codegen_seqnode_probe(project):  # noqa: SIM117
                                                        with (
                                                            _analysis_timeout(_remaining_timeout()),
                                                            active_status_flag_lift_context_8616(project, function),
                                                        ):
                                                            with span(
                                                                "decompile.angr_core",
                                                                addr=hex(current_func_addr),
                                                                # Dynamic angr/codegen compatibility boundary.
                                                                name=getattr(function, "name", None),
                                                                blocks=block_count,
                                                                bytes=byte_count,
                                                            ):
                                                                if decompiler_options is None:
                                                                    dec = project.analyses.Decompiler(
                                                                        function,
                                                                        cfg=cfg,
                                                                        expr_collapse_depth=expr_collapse_depth,
                                                                    )
                                                                else:
                                                                    dec = project.analyses.Decompiler(
                                                                        function,
                                                                        cfg=cfg,
                                                                        options=decompiler_options,
                                                                        expr_collapse_depth=expr_collapse_depth,
                                                                    )
                                                    if dec.codegen is None:
                                                        failure_snapshot = build_failure_family_snapshot(
                                                            status="empty",
                                                            failure_stage=getattr(
                                                                project, "_inertia_decompiler_stage", None
                                                            ),
                                                            fallback_kind="structurer_retry",
                                                            tail_validation_verdict="uncollected",
                                                            artifact_path=f"{function_original_addr(function):#x}:{function.name}",
                                                        )
                                                        repeat_reason = remember_failure_family_candidate(
                                                            failure_family_state,
                                                            failure_snapshot,
                                                        )
                                                        if repeat_reason is not None:
                                                            record_failure_family_retry_stop(
                                                                failure_family_state, failure_snapshot
                                                            )
                                                        detail = "Decompiler did not produce code."
                                                        messages = _analysis_log_messages(dec)
                                                        if messages:
                                                            detail += " angr details: " + "; ".join(messages[:3])
                                                        if getattr(dec, "clinic", None) is None:
                                                            detail += " clinic=None."
                                                            clinic_failure = _clinic_failure_detail()
                                                            if clinic_failure is not None:
                                                                detail += f" {clinic_failure}."
                                                        _emit_direct_addr_stage_bundle_8616(
                                                            project,
                                                            function,
                                                            binary_path=binary_path,
                                                            cod_metadata=effective_cod_metadata,
                                                            lst_metadata=lst_metadata,
                                                            family_label=failure_snapshot.label(),
                                                            lane="structurer_retry",
                                                            detail=detail,
                                                            repeat_reason=repeat_reason,
                                                            layer_dump_state=layer_dump_state,
                                                            messages=tuple(messages),
                                                        )
                                                        print(
                                                            f"[dbg] stop: {repeat_reason}; lane=structurer_retry",
                                                            flush=True,
                                                        )
                                                        typing.cast(typing.Any, project)._inertia_partial_codegen_text = None
                                                        return "empty", detail
                                                    logging.getLogger(__name__).debug(
                                                        "Selected decompiler structurer produced no code for %s; stopping same-family retry.",
                                                        function,
                                                    )
                                                    print(
                                                        f"[dbg] Decompiler returned for {hex(function.addr)}",
                                                        file=sys.stderr,
                                                        flush=True,
                                                    )
        except _AnalysisTimeout:
            previous_validated_payload = _validated_payload_from_project_record_8616()
            if previous_validated_payload is not None:
                return "ok", previous_validated_payload
            partial_payload = None
            if dec is not None and getattr(dec, "codegen", None) is not None:
                if getattr(getattr(project, "arch", None), "name", None) == "86_16":
                    try:
                        if not getattr(dec.codegen, "_inertia_semantic_facts_transferred", False):
                            transfer_semantic_alias_facts_to_codegen_8616(project, dec.codegen)
                        alias_facts = getattr(dec.codegen, "_inertia_semantic_alias_facts", None)
                        stack_semantics_changed = False
                        if alias_facts:
                            before_materialized = int(
                                getattr(dec.codegen, "_inertia_semantic_stack_materialized_count", 0) or 0
                            )
                            lower_stack_accesses_from_alias_facts_8616(dec.codegen, alias_facts)
                            after_materialized = int(
                                getattr(dec.codegen, "_inertia_semantic_stack_materialized_count", 0) or 0
                            )
                            stack_semantics_changed = (
                                stack_semantics_changed or after_materialized > before_materialized
                            )
                        stack_semantics_changed = (
                            bool(lower_stable_ss_linear_stack_dereferences_8616(dec.codegen, project=project))
                            or stack_semantics_changed
                        )
                        if stack_semantics_changed:
                            typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
                    except PipelineHardError:
                        raise
                    except Exception as ex:
                        logging.getLogger(__name__).debug(
                            "Partial-timeout stack semantic priming failed at function=%#x: %s",
                            function_original_addr(function),
                            ex,
                        )
                _remember_tail_validation_snapshot(dec.codegen)
                rendered_text, _ = _regenerate_codegen_text_safely(
                    dec.codegen,
                    context=f"{hex(function.addr)} {function.name} (partial timeout)",
                )
                partial_payload = _format_minimal_codegen_output(
                    project,
                    function,
                    rendered_text,
                    api_style,
                    binary_path,
                    effective_cod_metadata,
                )
            typing.cast(typing.Any, project)._inertia_partial_codegen_text = partial_payload
            if isinstance(partial_payload, str) and _partial_timeout_payload_is_validated_8616(project, partial_payload):
                return "ok", partial_payload
            timeout_stage = getattr(project, "_inertia_decompiler_stage", None)
            print(
                f"[dbg] {function.addr:#x} {function.name} TIMEOUT stage={timeout_stage}", file=sys.stderr, flush=True
            )
            if timeout_stage == "core":
                detail = "during core decompilation"
            elif isinstance(timeout_stage, str) and timeout_stage.startswith("core:clinic:"):
                detail = f"during {timeout_stage.split(':', 1)[1].replace(':', ' ')}"
            elif isinstance(timeout_stage, str) and timeout_stage.startswith("structuring:"):
                detail = f"during x86-16 structuring pass {timeout_stage.split(':', 1)[1]}"
            elif timeout_stage == "structuring":
                detail = "during x86-16 structuring"
            elif isinstance(timeout_stage, str) and timeout_stage.startswith("postprocess:"):
                detail = f"during x86-16 postprocess pass {timeout_stage.split(':', 1)[1]}"
            elif timeout_stage == "postprocess":
                detail = "during x86-16 postprocess"
            else:
                detail = None
            if detail is None:
                return "timeout", f"Timed out after {timeout}s."
            timeout_payload = f"Timed out after {timeout}s {detail}."
            if timeout_stage == "structuring" or (
                isinstance(timeout_stage, str) and timeout_stage.startswith("structuring:")
            ):
                # A structurer timeout means no validated C contract exists;
                # make that state explicit instead of exposing a bare timing
                # sentence that callers could mistake for a usable fallback.
                timeout_payload += " Decompiler produced unresolved IR-shaped C."
            return "timeout", timeout_payload
        except Exception as ex:
            typing.cast(typing.Any, project)._inertia_partial_codegen_text = None
            if os.environ.get("INERTIA_DEBUG_DECOMPILER_ERRORS_TRACEBACK"):
                traceback.print_exc(file=sys.stderr)
            return "error", str(ex)
        finally:
            if helper_guard_active:
                typing.cast(typing.Any, project)._inertia_disable_ail_narrowing = prev_disable_ail_narrowing
                typing.cast(typing.Any, project)._inertia_disable_complex_expr_scan = prev_disable_complex_expr_scan
                typing.cast(typing.Any, project)._inertia_fast_block_peephole = prev_fast_block_peephole

        if dec is None:
            return "error", "Decompiler analysis completed without a result."

        try:
            messages = _analysis_log_messages(dec)
        except Exception:
            messages = []
        if messages:
            print(
                f"[dbg] decompiler.errors for {function_original_addr(function):#x} {function.name}: "
                + " | ".join(messages[:6]),
                file=sys.stderr,
                flush=True,
            )

        if dec.codegen is None:
            messages = _analysis_log_messages(dec)
            if _should_retry_in_isolation(dec):
                failure_snapshot = build_failure_family_snapshot(
                    status="empty",
                    failure_stage=getattr(project, "_inertia_decompiler_stage", None),
                    fallback_kind="isolated_retry",
                    tail_validation_verdict="uncollected",
                    artifact_path=f"{function_original_addr(function):#x}:{function.name}",
                )
                repeat_reason = remember_failure_family_candidate(
                    failure_family_state,
                    failure_snapshot,
                )
                if repeat_reason is not None:
                    record_failure_family_retry_stop(failure_family_state, failure_snapshot)
                    detail = "Decompiler did not produce code."
                    if messages:
                        detail += " angr details: " + "; ".join(messages[:3])
                    if getattr(dec, "clinic", None) is None:
                        detail += " clinic=None."
                        clinic_failure = _clinic_failure_detail()
                        if clinic_failure is not None:
                            detail += f" {clinic_failure}."
                    _emit_direct_addr_stage_bundle_8616(
                        project,
                        function,
                        binary_path=binary_path,
                        cod_metadata=effective_cod_metadata,
                        lst_metadata=lst_metadata,
                        family_label=failure_snapshot.label(),
                        lane="isolated_retry",
                        detail=detail,
                        repeat_reason=repeat_reason,
                        layer_dump_state=layer_dump_state,
                        messages=tuple(messages),
                    )
                    print(f"[dbg] stop: {repeat_reason}; lane=isolated_retry", flush=True)
                    typing.cast(typing.Any, project)._inertia_partial_codegen_text = None
                    return "empty", detail
                advance_failure_family_state(failure_family_state)
                retried = _retry_in_isolated_project()
                if retried is not None and retried[0] == "ok":
                    return retried
                if retried is not None and retried[0] != "empty":
                    return retried
            if decompiler_options is None:
                fallback_snapshot = build_failure_family_snapshot(
                    status="empty",
                    failure_stage=getattr(project, "_inertia_decompiler_stage", None),
                    fallback_kind="structurer_retry",
                    tail_validation_verdict="uncollected",
                    artifact_path=f"{function_original_addr(function):#x}:{function.name}",
                )
                repeat_reason = remember_failure_family_candidate(
                    failure_family_state,
                    fallback_snapshot,
                )
                if repeat_reason is not None:
                    record_failure_family_retry_stop(failure_family_state, fallback_snapshot)
                    detail = "Decompiler did not produce code."
                    if messages:
                        detail += " angr details: " + "; ".join(messages[:3])
                    if getattr(dec, "clinic", None) is None:
                        detail += " clinic=None."
                        clinic_failure = _clinic_failure_detail()
                        if clinic_failure is not None:
                            detail += f" {clinic_failure}."
                    _emit_direct_addr_stage_bundle_8616(
                        project,
                        function,
                        binary_path=binary_path,
                        cod_metadata=effective_cod_metadata,
                        lst_metadata=lst_metadata,
                        family_label=fallback_snapshot.label(),
                        lane="structurer_retry",
                        detail=detail,
                        repeat_reason=repeat_reason,
                        layer_dump_state=layer_dump_state,
                        messages=tuple(messages),
                    )
                    print(f"[dbg] stop: {repeat_reason}; lane=structurer_retry", flush=True)
                    typing.cast(typing.Any, project)._inertia_partial_codegen_text = None
                    return "empty", detail
            detail = "Decompiler did not produce code."
            if messages:
                detail += " angr details: " + "; ".join(messages[:3])
            if getattr(dec, "clinic", None) is None:
                detail += " clinic=None."
                clinic_failure = _clinic_failure_detail()
                if clinic_failure is not None:
                    detail += f" {clinic_failure}."
            typing.cast(typing.Any, project)._inertia_partial_codegen_text = None
            return "empty", detail
        if not enable_postprocess:
            if getattr(getattr(project, "arch", None), "name", None) == "86_16":
                try:
                    if not getattr(dec.codegen, "_inertia_semantic_facts_transferred", False):
                        transfer_semantic_alias_facts_to_codegen_8616(project, dec.codegen)
                    alias_facts = getattr(dec.codegen, "_inertia_semantic_alias_facts", None)
                    stack_semantics_changed = False
                    if alias_facts:
                        before_materialized = int(
                            getattr(dec.codegen, "_inertia_semantic_stack_materialized_count", 0) or 0
                        )
                        lower_stack_accesses_from_alias_facts_8616(dec.codegen, alias_facts)
                        after_materialized = int(
                            getattr(dec.codegen, "_inertia_semantic_stack_materialized_count", 0) or 0
                        )
                        stack_semantics_changed = stack_semantics_changed or after_materialized > before_materialized
                    stack_semantics_changed = (
                        bool(lower_stable_ss_linear_stack_dereferences_8616(dec.codegen, project=project))
                        or stack_semantics_changed
                    )
                    had_storage_free_dirty_attr = hasattr(
                        dec.codegen,
                        "_inertia_dce_allow_storage_free_dirty_8616",
                    )
                    # Dynamic angr/codegen compatibility boundary.
                    previous_storage_free_dirty = getattr(
                        dec.codegen,
                        "_inertia_dce_allow_storage_free_dirty_8616",
                        None,
                    )
                    had_dirty_value_reads_attr = hasattr(
                        dec.codegen,
                        "_inertia_dce_allow_dirty_value_reads_8616",
                    )
                    # Dynamic angr/codegen compatibility boundary.
                    previous_dirty_value_reads = getattr(
                        dec.codegen,
                        "_inertia_dce_allow_dirty_value_reads_8616",
                        None,
                    )
                    typing.cast(typing.Any, dec.codegen)._inertia_dce_allow_storage_free_dirty_8616 = True
                    typing.cast(typing.Any, dec.codegen)._inertia_dce_allow_dirty_value_reads_8616 = True
                    try:
                        stack_semantics_changed = (
                            bool(_dead_code_elimination_8616(dec.codegen)) or stack_semantics_changed
                        )
                    finally:
                        if had_storage_free_dirty_attr:
                            typing.cast(typing.Any, dec.codegen)._inertia_dce_allow_storage_free_dirty_8616 = previous_storage_free_dirty
                        else:
                            with contextlib.suppress(AttributeError):
                                delattr(dec.codegen, "_inertia_dce_allow_storage_free_dirty_8616")
                        if had_dirty_value_reads_attr:
                            typing.cast(typing.Any, dec.codegen)._inertia_dce_allow_dirty_value_reads_8616 = previous_dirty_value_reads
                        else:
                            with contextlib.suppress(AttributeError):
                                delattr(dec.codegen, "_inertia_dce_allow_dirty_value_reads_8616")
                    if stack_semantics_changed:
                        typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
                        typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
                    loop_body_repair_changed = repair_empty_counted_loop_body_from_evidence_8616(project, dec.codegen)
                    if loop_body_repair_changed:
                        typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
                        typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
                except PipelineHardError:
                    raise
                except Exception as ex:
                    logging.getLogger(__name__).debug(
                        "Non-postprocess stack semantic priming failed at function=%#x: %s",
                        function_original_addr(function),
                        ex,
                    )
            _remember_tail_validation_snapshot(dec.codegen)
            rendered_text, _ = _regenerate_codegen_text_safely(
                dec.codegen,
                context=f"{hex(function.addr)} {function.name} (non-optimized)",
            )
            formatted = _format_minimal_codegen_output(
                project,
                function,
                rendered_text,
                api_style,
                binary_path,
                effective_cod_metadata,
            )
            if effective_cod_metadata is not None:
                best_rendered_text = rendered_text
                best_score = (
                    _expected_call_presence_score_8616(rendered_text, effective_cod_metadata),
                    _expected_call_arity_score_8616(rendered_text, effective_cod_metadata),
                )
                if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                    logging.getLogger(__name__).warning(
                        "[call-semantics-stage] nonpost function=%#x presence=%d arity=%d deficit=%d",
                        function_original_addr(function),
                        best_score[0],
                        best_score[1],
                        _expected_call_arity_deficit_8616(rendered_text, effective_cod_metadata),
                    )
                if _expected_call_arity_deficit_8616(rendered_text, effective_cod_metadata) > 0:
                    for _ in range(2):
                        replay_changed = False
                        with contextlib.suppress(Exception):
                            replay_changed = bool(
                                replay_callsite_stack_arguments_after_regeneration_8616(project, dec.codegen)
                            )
                        if not replay_changed:
                            break
                        candidate_text, _ = _regenerate_codegen_text_safely(
                            dec.codegen,
                            context=f"{hex(function.addr)} {function.name} (non-optimized call-arity replay)",
                        )
                        candidate_score = (
                            _expected_call_presence_score_8616(candidate_text, effective_cod_metadata),
                            _expected_call_arity_score_8616(candidate_text, effective_cod_metadata),
                        )
                        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                            logging.getLogger(__name__).warning(
                                "[call-semantics-stage] nonpost-replay function=%#x score=%r deficit=%d selected=%s",
                                function_original_addr(function),
                                candidate_score,
                                _expected_call_arity_deficit_8616(candidate_text, effective_cod_metadata),
                                candidate_score > best_score,
                            )
                        if candidate_score > best_score:
                            best_rendered_text = candidate_text
                            best_score = candidate_score
                            rendered_text = candidate_text
                            formatted = _format_minimal_codegen_output(
                                project,
                                function,
                                rendered_text,
                                api_style,
                                binary_path,
                                effective_cod_metadata,
                            )
                        if _expected_call_arity_deficit_8616(best_rendered_text, effective_cod_metadata) == 0:
                            break
            formatted = _normalize_unary_not_shift_precedence_text(formatted)
            _emit_c_stage_trace(
                project,
                function,
                "post-structured-codegen",
                formatted,
                layer_dump_state=layer_dump_state,
            )
            # ── PIPELINE CONTRACT GATE: enforce closed loop before C emission ──
            try:
                assert_pipeline_contracts_8616(dec.codegen)
            except PipelineHardError:
                raise  # let the caller handle it as a real failure

            # ── FINAL EMISSION GATE: forbid ss << 4, stack[, etc. in final C ──
            assert_final_c_quality_8616(
                formatted,
                function_addr=function_original_addr(function),
            )
            typing.cast(typing.Any, project)._inertia_partial_codegen_text = None
            return "ok", formatted
        _debug_cli_stage_marker_8616("postprocess-cli-entry")
        typing.cast(typing.Any, project)._inertia_rewrite_cache = {}
        if synthetic_globals:
            typing.cast(typing.Any, project)._inertia_synthetic_globals = synthetic_globals
            typing.cast(typing.Any, dec.codegen)._inertia_synthetic_globals = synthetic_globals
        stack_local_candidates = snapshot_stack_local_candidates_8616(dec.codegen)
        typing.cast(typing.Any, dec.codegen)._inertia_stack_local_declaration_candidates = stack_local_candidates
        changed = False
        small_function = bool(profile.get("wrapper_like") or profile.get("tiny_single_call_helper"))
        large_x86_16_function = bool(project.arch.name == "86_16" and block_count >= 40)
        fold_values_cod_outlier = (
            binary_path is not None
            and binary_path.name.lower().endswith(".cod")
            and getattr(function, "name", "") == "fold_values"
        )
        typing.cast(typing.Any, project)._inertia_structuring_enabled = bool(enable_structured_simplify and not small_function and not fold_values_cod_outlier)
        semantic_call_helper_names = {
            "Add",
            "And",
            "Concat",
            "Div",
            "MK_FP",
            "MEM_U16",
            "MEM_U32",
            "MEM_U8",
            "Mul",
            "Or",
            "Reference",
            "SEG_LINEAR",
            "SEG_PTR",
            "SEG_U16",
            "SEG_U32",
            "SEG_U8",
            "Sub",
            "Xor",
            "aNchkstk",
            "__aNchkstk",
        }

        def _call_node_proven_stack_probe_helper_8616(node: object) -> bool:
            if not isinstance(node, structured_c.CFunctionCall):
                return False
            raw_name = node.callee_target
            if not isinstance(raw_name, str):
                raw_name = getattr(node.callee_func, "name", None)
            if _is_stack_probe_name_8616(raw_name):
                return True

            summary_map = getattr(dec.codegen, "_inertia_callsite_summaries", None)
            summary = summary_map.get(id(node)) if isinstance(summary_map, dict) else None
            summary_is_stack_probe, target_addr = callsite_stack_probe_evidence_8616(summary)
            if summary_is_stack_probe:
                return True

            candidates: set[int] = set()
            if isinstance(target_addr, int):
                candidates.add(target_addr)
                candidates.add(target_addr & 0xFFFF)
            callee_addr = getattr(node.callee_func, "addr", None)
            if isinstance(callee_addr, int):
                candidates.add(callee_addr)
                candidates.add(callee_addr & 0xFFFF)
            normalized_name = normalize_callee_name_8616(raw_name)
            if isinstance(normalized_name, str):
                match = re.fullmatch(r"sub_([0-9a-fA-F]+)", normalized_name)
                if match is not None:
                    with contextlib.suppress(ValueError):
                        parsed = int(match.group(1), 16)
                        candidates.add(parsed)
                        candidates.add(parsed & 0xFFFF)

            original_project = getattr(project, "_inertia_original_project", None)
            for candidate in sorted(candidates):
                for candidate_project, candidate_addr in (
                    (project, candidate),
                    (original_project, candidate),
                    (original_project, _candidate_original_target_8616(project, candidate)),
                ):
                    if candidate_project is None or not isinstance(candidate_addr, int):
                        continue
                    evidence = identify_x86_16_compiler_helper_at_8616(candidate_project, candidate_addr)
                    if evidence is not None and evidence.kind is CompilerHelperEvidenceKind8616.STACK_PROBE:
                        return True
            return False

        def _is_semantic_codegen_call(node: object) -> bool:
            if not isinstance(node, structured_c.CFunctionCall):
                return False
            if _call_node_proven_stack_probe_helper_8616(node):
                return False
            raw_name = node.callee_target
            if not isinstance(raw_name, str):
                raw_name = getattr(node.callee_func, "name", None)
            name = normalize_callee_name_8616(raw_name)
            if not isinstance(name, str) or not name:
                return False
            return name not in semantic_call_helper_names

        def _codegen_call_expr_count() -> int:
            cfunc = getattr(dec.codegen, "cfunc", None)
            if cfunc is None:
                return 0
            root = getattr(cfunc, "statements", None)
            if root is None:
                return 0
            return sum(1 for node in _iter_c_nodes_deep(root) if _is_semantic_codegen_call(node))

        def _codegen_call_name_counts() -> dict[str, int]:
            cfunc = getattr(dec.codegen, "cfunc", None)
            if cfunc is None:
                return {}
            root = getattr(cfunc, "statements", None)
            if root is None:
                return {}
            counts: dict[str, int] = {}
            for node in _iter_c_nodes_deep(root):
                if not _is_semantic_codegen_call(node):
                    continue
                raw_name = getattr(node, "callee_target", None)
                if not isinstance(raw_name, str):
                    raw_name = getattr(getattr(node, "callee_func", None), "name", None)
                name = normalize_callee_name_8616(raw_name)
                if not isinstance(name, str) or not name:
                    continue
                counts[name] = counts.get(name, 0) + 1
            return counts

        def _missing_expected_call_names_from_codegen_counts() -> tuple[str, ...]:
            if not expected_non_prologue_calls:
                return ()
            counts = _codegen_call_name_counts()
            needed: dict[str, int] = {}
            for raw_name in expected_non_prologue_calls:
                name = normalize_callee_name_8616(raw_name)
                if not isinstance(name, str) or not name:
                    continue
                needed[name] = needed.get(name, 0) + 1
            missing: list[str] = []
            for name, count in needed.items():
                have = counts.get(name, 0)
                if have < count:
                    missing.append(f"{name}({have}/{count})")
            return tuple(missing)

        def _snapshot_codegen_cfunc() -> object | None:
            if large_x86_16_function or block_count > 16 or byte_count > 0x300:
                return None
            cfunc = getattr(dec.codegen, "cfunc", None)
            if cfunc is None:
                return None
            snapshot: object | None = snapshot_trusted_cfunc_8616(
                cfunc,
                preserve_objects=(dec.codegen, project, project.arch),
            )
            return snapshot

        def _restore_codegen_cfunc(snapshot: Any) -> bool:
            if snapshot is None:
                return False
            codegen = dec.codegen
            if codegen is None:
                return False
            typing.cast(typing.Any, codegen).cfunc = snapshot
            with contextlib.suppress(Exception):
                typing.cast(typing.Any, snapshot).codegen = codegen
            for node in _iter_c_nodes_deep(getattr(codegen, "cfunc", None)):
                with contextlib.suppress(Exception):
                    node.codegen = codegen
            return True

        trusted_core_tail_snapshot = _tail_validation_snapshot_for_function_run(project, function)
        trusted_core_cfunc = (
            _snapshot_codegen_cfunc()
            if _tail_validation_snapshot_complete_for_cli_rewrite_8616(trusted_core_tail_snapshot)
            else None
        )
        trusted_core_snapshot = (
            TrustedCoreSnapshot8616(trusted_core_cfunc, trusted_core_tail_snapshot)
            if trusted_core_cfunc is not None and isinstance(trusted_core_tail_snapshot, dict)
            else None
        )

        def _run_stack_lowering_pass() -> bool:
            changed_local = bool(lower_stable_ss_linear_stack_dereferences_8616(dec.codegen, project=project))
            if os.environ.get("INERTIA_ENABLE_LEGACY_CLI_STACK_RERUN", "").strip().lower() not in {
                "1",
                "true",
                "yes",
                "on",
            }:
                return changed_local
            changed_local = (
                bool(
                    run_stack_lowering_pass_8616(
                        lower_stable_ss_stack_accesses=lambda: apply_x86_16_segmented_memory_reasoning(dec.codegen),
                        rewrite_ss_stack_byte_offsets=lambda: _rewrite_ss_stack_byte_offsets(project, dec.codegen),
                        canonicalize_stack_cvars=lambda: _canonicalize_stack_cvars(dec.codegen),
                        codegen=cast(Any, dec.codegen),
                        project=project,
                    )
                )
                or changed_local
            )
            return changed_local

        def _run_runtime_segment_lowering_pass() -> bool:
            target = str(getattr(project, "_inertia_c_target", "portable-flat") or "portable-flat")
            return bool(apply_runtime_segment_lowering_8616(dec.codegen, target=target))

        def _run_fact_backed_stack_rewrite_pass() -> bool:
            if large_x86_16_function:
                # Dynamic angr/codegen compatibility boundary.
                typing.cast(typing.Any, dec.codegen)._inertia_fact_backed_stack_rewrite_refused_large_function = (
                    int(getattr(dec.codegen, "_inertia_fact_backed_stack_rewrite_refused_large_function", 0) or 0)
                    + 1
                )
                return False
            if not getattr(dec.codegen, "_inertia_semantic_stack_materialized_count", 0):
                return False
            changed_local = bool(_rewrite_ss_stack_byte_offsets(project, dec.codegen))
            changed_local = bool(_canonicalize_stack_cvars(dec.codegen)) or changed_local
            return changed_local

        def _run_callsite_stack_fact_pass() -> bool:
            if large_x86_16_function:  # noqa: SIM102
                if seqnode_switch_replacement_changed_for_codegen_8616(project, dec.codegen):
                    # The SeqNode switch mutator rebuilds case bodies after the
                    # normal callsite pass.  Running this pass here only consumes
                    # existing callsite summaries/stack-probe facts, and the
                    # caller wraps it in call-loss and final validation guards.
                    # Dynamic angr/codegen compatibility boundary.
                    typing.cast(typing.Any, dec.codegen)._inertia_callsite_stack_fact_allowed_large_seqnode_replacement = (
                        int(
                            # Dynamic angr/codegen compatibility boundary.
                            getattr(
                                dec.codegen,
                                "_inertia_callsite_stack_fact_allowed_large_seqnode_replacement",
                                0,
                            )
                            or 0
                        )
                        + 1
                    )
            if not function_has_call_evidence:
                typing.cast(typing.Any, dec.codegen)._inertia_callsite_stack_fact_refused_no_calls = int(getattr(dec.codegen, "_inertia_callsite_stack_fact_refused_no_calls", 0) or 0) + 1
                return False

            def _guarded_callsite_rewrite(pass_name: str, rewrite: Callable[[], bool]) -> bool:
                before_calls = _codegen_call_expr_count()
                snapshot = _snapshot_codegen_cfunc()
                if rewrite():
                    after_calls = _codegen_call_expr_count()
                    # Evidence-based semantic guard: callsite stack-fact materialization
                    # must not drop existing call expressions.
                    if after_calls < before_calls and _restore_codegen_cfunc(snapshot):
                        logging.getLogger(__name__).warning(
                            "Rejected callsite stack-fact rewrite due to call loss at function=%#x (%d -> %d calls)",
                            function_original_addr(function),
                            before_calls,
                            after_calls,
                        )
                        return False
                    return True
                return False

            result = run_callsite_stack_fact_materialization_8616(
                project,
                dec.codegen,
                _guarded_callsite_rewrite,
                build_typed_stack_probe_return_facts_8616,
            )
            return bool(result.changed)

        def _run_materialize_missing_stack_local_declarations_pass() -> bool:
            if getattr(dec.codegen, "_inertia_has_rebound_materialized_recurrence", False):
                return False
            return bool(_materialize_missing_stack_local_declarations(dec.codegen))

        def _run_materialize_missing_register_local_declarations_pass() -> bool:
            if getattr(dec.codegen, "_inertia_has_rebound_materialized_recurrence", False):
                return False
            return bool(_materialize_missing_register_local_declarations(dec.codegen))

        def _run_simplify_structured_c_expressions_pass() -> bool:
            if getattr(dec.codegen, "_inertia_has_rebound_materialized_recurrence", False):
                return False
            return bool(_simplify_structured_c_expressions(dec.codegen))

        def _run_evidence_dce_pass() -> bool:
            had_attr = hasattr(dec.codegen, "_inertia_allow_large_function_flag_dce_after_seqnode_replacement_8616")
            # Dynamic angr/codegen compatibility boundary.
            previous = getattr(dec.codegen, "_inertia_allow_large_function_flag_dce_after_seqnode_replacement_8616", None)
            if large_x86_16_function and seqnode_switch_replacement_changed_for_codegen_8616(project, dec.codegen):
                # The SeqNode switch mutator creates fresh case bodies after
                # normal postprocess flag-DCE has already refused this large
                # function.  This only enables evidence-backed DCE; the caller
                # still applies call-loss checks and final validation gates.
                typing.cast(typing.Any, dec.codegen)._inertia_allow_large_function_flag_dce_after_seqnode_replacement_8616 = True
            try:
                dce_changed = bool(_dead_code_elimination_after_flag_prune_8616(dec.codegen))
                if dce_changed:
                    typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
                    typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
                return dce_changed
            finally:
                if had_attr:
                    typing.cast(typing.Any, dec.codegen)._inertia_allow_large_function_flag_dce_after_seqnode_replacement_8616 = previous
                else:
                    with contextlib.suppress(AttributeError):
                        delattr(dec.codegen, "_inertia_allow_large_function_flag_dce_after_seqnode_replacement_8616")

        def _run_call_loss_guarded_evidence_dce_pass(error_message: str) -> CallLossGuardedDceResult8616:
            before_calls = _codegen_call_expr_count() if call_loss_guard_active else 0
            dce_changed = _run_evidence_dce_pass()
            after_calls = _codegen_call_expr_count() if call_loss_guard_active else before_calls
            if dce_changed and after_calls < before_calls:
                raise PipelineHardError(
                    error_message,
                    layer="optimization",
                    function_addr=function_original_addr(function),
                    details={
                        "before_calls": before_calls,
                        "after_calls": after_calls,
                    },
                )
            return CallLossGuardedDceResult8616(
                changed=bool(dce_changed),
                before_calls=before_calls,
                after_calls=after_calls,
            )

        def _run_dead_local_prune_with_call_guard(error_message: str) -> bool:
            before_prune_calls = _codegen_call_expr_count() if call_loss_guard_active else 0
            prune_changed = _prune_dead_local_assignments(dec.codegen)
            if not prune_changed:
                return False
            after_prune_calls = _codegen_call_expr_count() if call_loss_guard_active else before_prune_calls
            if after_prune_calls < before_prune_calls:
                raise PipelineHardError(
                    error_message,
                    layer="optimization",
                    function_addr=function_original_addr(function),
                    details={
                        "before_calls": before_prune_calls,
                        "after_calls": after_prune_calls,
                    },
                )
            _prune_unused_local_declarations(dec.codegen)
            typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
            typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
            return True

        def _run_materialize_missing_terminal_ax_return_pass() -> bool:
            return bool(_materialize_missing_terminal_ax_return_8616(project, dec.codegen))

        postprocess_semantic_contract_active = bool(
            getattr(dec.codegen, "_inertia_return_selector_materialized_8616", False)
            or getattr(dec.codegen, "_inertia_pointer_memory_materialized_8616", None)
            or getattr(dec.codegen, "_inertia_global_byte_sum_loop_materialized_8616", False)
            or getattr(dec.codegen, "_inertia_nested_stack_counter_loop_materialized_8616", False)
            or getattr(dec.codegen, "_inertia_stack_arg_accumulator_loop_materialized_8616", False)
        )
        dynamic_codegen = typing.cast(typing.Any, dec.codegen)
        try:
            pointer_memory_contract_active = dynamic_codegen._inertia_pointer_memory_materialized_8616 is not None
        except AttributeError:
            pointer_memory_contract_active = False
        # ── FACT-BASED STACK LOWERING: transfer + materialize BEFORE old-style passes ──
        # AGENTS rule: alias facts must be transferred and materialized early.
        # If this produces bindings but no materialized variables, PipelineHardError raises.
        # If postprocess has already materialized a whole-function semantic body,
        # later CLI AST rewrites must not reopen it with generic stack lowering.
        if not postprocess_semantic_contract_active:
            if not getattr(dec.codegen, "_inertia_semantic_facts_transferred", False):
                transfer_semantic_alias_facts_to_codegen_8616(project, dec.codegen)
            alias_facts = getattr(dec.codegen, "_inertia_semantic_alias_facts", None)
            if alias_facts:
                try:
                    lower_stack_accesses_from_alias_facts_8616(dec.codegen, alias_facts)
                except Exception as ex:
                    logging.getLogger(__name__).debug(
                        "Alias-fact stack lowering failed at function=%#x stage=rewrite-prepass: %s",
                        function_original_addr(function),
                        ex,
                    )

        rewrite_codegen: Any = dec.codegen
        rewrite_passes: tuple[Callable[[], Any], ...] = (
            lambda: _attach_dos_pseudo_callees(project, function, rewrite_codegen, api_style),
            lambda: _attach_interrupt_wrapper_callees(project, rewrite_codegen, api_style),
            lambda: _lower_interrupt_wrapper_result_reads(project, rewrite_codegen, api_style),
            lambda: _attach_segment_register_names(dec.codegen, project),
            lambda: _attach_register_names(project, dec.codegen),
            lambda: _normalize_scalar_byte_register_types(dec.codegen),
            lambda: _elide_redundant_segment_pointer_dereferences(project, dec.codegen),
            _run_runtime_segment_lowering_pass,
            lambda: run_segment_global_materialization_8616(
                project, dec.codegen, synthetic_globals, cod_metadata=effective_cod_metadata
            ).changed,
            lambda: _run_typed_widening_pass(project, dec.codegen),
            lambda: _attach_ss_stack_variables(project, dec.codegen),
            _run_fact_backed_stack_rewrite_pass,
            _run_callsite_stack_fact_pass,
            _run_stack_lowering_pass,
            lambda: _run_typed_widening_pass(project, dec.codegen),
            lambda: _coalesce_linear_recurrence_statements(project, dec.codegen),
            lambda: run_direct_instruction_materialization_8616(project, dec.codegen, function=function).changed,
            lambda: _prune_unused_unnamed_memory_declarations(dec.codegen),
            lambda: _prune_dead_local_assignments(dec.codegen),
            lambda: _prune_unused_local_declarations(dec.codegen),
            lambda: _prune_void_function_return_values(dec.codegen),
            lambda: _coalesce_cod_word_global_loads(project, dec.codegen, synthetic_globals),
            lambda: run_segment_global_materialization_8616(
                project, dec.codegen, synthetic_globals, cod_metadata=effective_cod_metadata
            ).changed,
            lambda: _coalesce_segmented_word_load_expressions(project, dec.codegen),
            lambda: _coalesce_cod_word_global_statements(project, dec.codegen, synthetic_globals),
            lambda: _attach_cod_global_names(project, dec.codegen, synthetic_globals),
            lambda: _attach_cod_global_declaration_names(dec.codegen, synthetic_globals),
            lambda: _attach_cod_global_declaration_types(dec.codegen, synthetic_globals),
            lambda: _collect_access_traits(project, dec.codegen),
            lambda: _coalesce_far_pointer_stack_expressions(project, dec.codegen),
            lambda: _simplify_nested_mk_fp_calls(dec.codegen),
            lambda: _attach_access_trait_field_names(project, dec.codegen),
            lambda: _attach_pointer_member_names(project, dec.codegen),
            lambda: _attach_cod_variable_names(dec.codegen, effective_cod_metadata),
            _run_simplify_structured_c_expressions_pass,
            lambda: _simplify_basic_algebraic_identities(dec.codegen),
            _run_materialize_missing_terminal_ax_return_pass,
            _run_materialize_missing_stack_local_declarations_pass,
            _run_materialize_missing_register_local_declarations_pass,
            lambda: _prune_unused_local_declarations(dec.codegen),
            lambda: _dedupe_codegen_variable_names_8616(dec.codegen),
            _run_evidence_dce_pass,
            _run_callsite_stack_fact_pass,
            _run_fact_backed_stack_rewrite_pass,
            _run_stack_lowering_pass,
            lambda: _run_typed_widening_pass(project, dec.codegen),
            lambda: _attach_cod_variable_names(dec.codegen, effective_cod_metadata),
            lambda: _prune_dead_local_assignments(dec.codegen),
            lambda: _prune_unused_local_declarations(dec.codegen),
        )
        if small_function:
            rewrite_passes = (
                lambda: _attach_dos_pseudo_callees(project, function, rewrite_codegen, api_style),
                lambda: _attach_interrupt_wrapper_callees(project, rewrite_codegen, api_style),
                lambda: _lower_interrupt_wrapper_result_reads(project, rewrite_codegen, api_style),
                lambda: _attach_segment_register_names(dec.codegen, project),
                lambda: _attach_register_names(project, dec.codegen),
                lambda: _normalize_scalar_byte_register_types(dec.codegen),
                _run_runtime_segment_lowering_pass,
                lambda: run_segment_global_materialization_8616(
                    project, dec.codegen, synthetic_globals, cod_metadata=effective_cod_metadata
                ).changed,
                lambda: _run_typed_widening_pass(project, dec.codegen),
                lambda: _attach_ss_stack_variables(project, dec.codegen),
                _run_fact_backed_stack_rewrite_pass,
                _run_callsite_stack_fact_pass,
                _run_stack_lowering_pass,
                lambda: _run_typed_widening_pass(project, dec.codegen),
                lambda: run_direct_instruction_materialization_8616(project, dec.codegen, function=function).changed,
                lambda: _coalesce_segmented_word_load_expressions(project, dec.codegen),
                lambda: _prune_tiny_wrapper_staging_locals(dec.codegen),
                lambda: _prune_unused_unnamed_memory_declarations(dec.codegen),
                lambda: _prune_dead_local_assignments(dec.codegen),
                lambda: _prune_unused_local_declarations(dec.codegen),
                lambda: _prune_void_function_return_values(dec.codegen),
                lambda: _coalesce_cod_word_global_loads(project, dec.codegen, synthetic_globals),
                lambda: run_segment_global_materialization_8616(
                    project, dec.codegen, synthetic_globals, cod_metadata=effective_cod_metadata
                ).changed,
                lambda: _coalesce_linear_recurrence_statements(project, dec.codegen),
                lambda: _attach_cod_global_names(project, dec.codegen, synthetic_globals),
                lambda: _attach_cod_global_declaration_names(dec.codegen, synthetic_globals),
                lambda: _attach_cod_global_declaration_types(dec.codegen, synthetic_globals),
                lambda: _collect_access_traits(project, dec.codegen),
                lambda: _coalesce_far_pointer_stack_expressions(project, dec.codegen),
                lambda: _simplify_nested_mk_fp_calls(dec.codegen),
                lambda: _attach_access_trait_field_names(project, dec.codegen),
                lambda: _attach_pointer_member_names(project, dec.codegen),
                lambda: _attach_cod_variable_names(dec.codegen, effective_cod_metadata),
                _run_simplify_structured_c_expressions_pass,
                lambda: _simplify_basic_algebraic_identities(dec.codegen),
                _run_materialize_missing_terminal_ax_return_pass,
                _run_materialize_missing_stack_local_declarations_pass,
                _run_materialize_missing_register_local_declarations_pass,
                lambda: _prune_unused_local_declarations(dec.codegen),
                lambda: _dedupe_codegen_variable_names_8616(dec.codegen),
                _run_evidence_dce_pass,
                _run_callsite_stack_fact_pass,
                _run_fact_backed_stack_rewrite_pass,
                _run_stack_lowering_pass,
                lambda: _run_typed_widening_pass(project, dec.codegen),
                lambda: run_direct_instruction_materialization_8616(project, dec.codegen, function=function).changed,
                lambda: _attach_cod_variable_names(dec.codegen, effective_cod_metadata),
                lambda: _prune_dead_local_assignments(dec.codegen),
                lambda: _prune_unused_local_declarations(dec.codegen),
            )
            if lst_metadata is not None:
                logging.getLogger(__name__).debug(
                    "Skipping x86-16 postpasses for tiny function %s (%d blocks, %d bytes).",
                    function,
                    block_count,
                    byte_count,
                )
        else:
            if fold_values_cod_outlier:
                rewrite_passes = ()
            else:
                rewrite_passes = (
                    rewrite_passes[:6]
                    + rewrite_passes[6:14]
                    + (lambda: _attach_lst_data_names(project, dec.codegen, lst_metadata),)
                    + rewrite_passes[14:]
                )
        if not enable_structured_simplify or small_function or fold_values_cod_outlier:
            logging.getLogger(__name__).debug(
                "Skipping x86-16 structuring for function %s (%d blocks, %d bytes).",
                function,
                block_count,
                byte_count,
            )
        if getattr(dec.codegen, "_inertia_postprocess_discarded", False):
            rewrite_passes = ()
        if postprocess_semantic_contract_active:
            rewrite_passes = ()
        expected_non_prologue_calls: tuple[str, ...] = ()
        expected_call_guard_active = bool(expected_non_prologue_calls)
        function_has_call_evidence = bool(
            _profile_int_8616(profile, "call_site_count")
            or _profile_int_8616(profile, "internal_call_count")
        )
        call_loss_guard_active = function_has_call_evidence or expected_call_guard_active
        _stack_lowering_already_attempted = False
        rewrite_pass_names = {
            id(rewrite): getattr(rewrite, "__name__", type(rewrite).__name__) for rewrite in rewrite_passes
        }
        try:
            rehydrate_metadata = effective_cod_metadata or _sidecar_cod_metadata_for_function(
                project,
                function,
                binary_path,
                lst_metadata,
            )
            _debug_cli_stage_marker_8616("before-live-snapshot")
            _live_snapshot = _snapshot_codegen_text(dec.codegen)
            _debug_cli_stage_marker_8616("after-live-snapshot")
            _rehydrated = _rehydrate_missing_evidenced_calls_on_live_codegen_8616(
                project,
                dec.codegen,
                rehydrate_metadata,
                _live_snapshot,
            )
            _debug_cli_stage_marker_8616("after-live-rehydrate")
            if isinstance(_rehydrated, str) and _rehydrated.strip():
                typing.cast(typing.Any, project)._inertia_partial_codegen_text = _rehydrated
        except Exception as ex:
            logging.getLogger(__name__).debug("live call rehydration skipped: %s", ex)
        with span(
            "decompile.structuring_loop_body_repair",
            addr=hex(current_func_addr),
            name=getattr(function, "name", None),
        ):
            loop_body_repair_changed = repair_empty_counted_loop_body_from_evidence_8616(project, dec.codegen)
        if loop_body_repair_changed:
            changed = True
            typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
            typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
            _live_snapshot = ""
        segmented_global_load_changed = materialize_named_segmented_global_loads_8616(
            project,
            dec.codegen,
            synthetic_globals,
            cod_metadata=effective_cod_metadata,
        )
        if segmented_global_load_changed:
            changed = True
            typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
            typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
            _live_snapshot = ""
        compare_register_global_changed = materialize_compare_register_global_carriers_8616(
            project,
            dec.codegen,
            synthetic_globals,
            cod_metadata=effective_cod_metadata,
        )
        if compare_register_global_changed:
            changed = True
            typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
            typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
            _live_snapshot = ""
        direct_global_store_changed = materialize_direct_global_symbol_stores_8616(
            project,
            dec.codegen,
            synthetic_globals,
            cod_metadata=effective_cod_metadata,
        )
        if direct_global_store_changed:
            changed = True
            typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
            typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
            _live_snapshot = ""
        direct_stack_instruction_result = run_direct_instruction_materialization_8616(
            project,
            dec.codegen,
            function=function,
            include_direct_stack_mov=not pointer_memory_contract_active,
            include_direct_global_incdec=False,
        )
        if direct_stack_instruction_result.direct_stack_mov_changed:
            changed = True
            typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
            typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
            _live_snapshot = ""
            if _run_dead_local_prune_with_call_guard("direct-stack materialization prune removed call expressions"):
                _live_snapshot = ""
        direct_global_instruction_result = run_direct_instruction_materialization_8616(
            project,
            dec.codegen,
            function=function,
            include_direct_stack_mov=False,
        )
        if direct_global_instruction_result.direct_global_incdec_changed:
            changed = True
            typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
            typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
            _live_snapshot = ""
        indexed_segmented_global_changed = materialize_indexed_segmented_global_loads_8616(
            project,
            dec.codegen,
            cod_metadata=effective_cod_metadata,
        )
        if indexed_segmented_global_changed:
            changed = True
            typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
            typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
            _live_snapshot = ""
        before_safe_dce_calls = _codegen_call_expr_count() if call_loss_guard_active else 0
        safe_dce_changed = _run_evidence_dce_pass()
        if safe_dce_changed:
            after_safe_dce_calls = _codegen_call_expr_count() if call_loss_guard_active else before_safe_dce_calls
            if after_safe_dce_calls < before_safe_dce_calls:
                raise PipelineHardError(
                    "safe DCE removed call expressions",
                    layer="optimization",
                    function_addr=function_original_addr(function),
                    details={
                        "before_calls": before_safe_dce_calls,
                        "after_calls": after_safe_dce_calls,
                    },
                )
            changed = True
            typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
            typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
            _live_snapshot = ""
        tail_validation_snapshot_for_rewrite_gate = _tail_validation_snapshot_for_function_run(project, function)
        tail_validation_complete_for_rewrite_gate = _tail_validation_snapshot_complete_for_cli_rewrite_8616(
            tail_validation_snapshot_for_rewrite_gate
        )
        tail_validation_failed_for_rewrite_gate = _tail_validation_snapshot_failed_for_cli_rewrite_8616(
            tail_validation_snapshot_for_rewrite_gate
        )
        sidecar_free_for_rewrite_gate = lst_metadata is None and effective_cod_metadata is None
        if _should_refuse_legacy_cli_rewrite_8616(
            project,
            small_function=small_function,
            sidecar_free=sidecar_free_for_rewrite_gate,
        ):
            if _validated_rewrite_refusal_needs_render_refresh_8616(_live_snapshot):
                changed = True
                typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
                typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
            typing.cast(typing.Any, dec.codegen)._inertia_legacy_cli_rewrite_refused_large_validated_ast = int(getattr(dec.codegen, "_inertia_legacy_cli_rewrite_refused_large_validated_ast", 0) or 0) + 1
            logging.getLogger(__name__).warning(
                "Skipping legacy CLI rewrite loop after core validation for nontrivial x86-16 AST "
                "at function=%#x blocks=%d text_bytes=%d",
                function_original_addr(function),
                block_count,
                len(_live_snapshot) if isinstance(_live_snapshot, str) else 0,
            )
            _emit_typed_edge_switch_replacement_safety_stats_8616(dec.codegen)
            rewrite_passes = ()
            if tail_validation_failed_for_rewrite_gate:
                with span(
                    "decompile.failed_core_partial_render",
                    addr=hex(current_func_addr),
                    name=getattr(function, "name", None),
                ):
                    partial_text = _snapshot_codegen_text(dec.codegen)
                    if not isinstance(partial_text, str) or not partial_text.strip():
                        partial_text, _regenerated = _regenerate_codegen_text_safely(
                            dec.codegen,
                            context=f"{hex(function.addr)} {function.name} failed-core-partial",
                        )
                _remember_tail_validation_snapshot(dec.codegen)
                _emit_c_stage_trace(
                    project,
                    function,
                    "failed-core-partial-c",
                    partial_text,
                    layer_dump_state=layer_dump_state,
                )
                typing.cast(typing.Any, project)._inertia_partial_codegen_text = partial_text
                return (
                    "validation_failed",
                    "Core tail validation failed; emitted the unmodified structured C as partial output.",
                )
        if os.environ.get("INERTIA_DEBUG_CALL_MUTATION"):
            try:
                pre_rewrite_text = _snapshot_codegen_text(dec.codegen)
                _debug_dump_calls_8616(
                    "pre-cli-rewrite",
                    pre_rewrite_text,
                    function_original_addr(function),
                )
            except Exception:
                pass
        _debug_cli_stage_marker_8616("before-cli-rewrite-loop")
        for round_idx in range(2):
            iter_changed = False
            stack_lowering_dirty = not _stack_lowering_already_attempted
            for rewrite_idx, rewrite in enumerate(rewrite_passes):
                if rewrite is _run_stack_lowering_pass and not stack_lowering_dirty:
                    continue
                recurrence_rebound = bool(
                    getattr(dec.codegen, "_inertia_has_rebound_materialized_recurrence", False)
                ) or bool(
                    int(
                        (getattr(dec.codegen, "_inertia_stack_lowering_debug", {}) or {}).get(
                            "recurrence_bound_to_materialized_local",
                            0,
                        )
                        or 0
                    )
                )
                if (
                    round_idx > 0
                    and recurrence_rebound
                    and rewrite
                    in {
                        _run_materialize_missing_stack_local_declarations_pass,
                        _run_materialize_missing_register_local_declarations_pass,
                    }
                ):
                    continue
                pass_name = rewrite_pass_names.get(id(rewrite), getattr(rewrite, "__name__", type(rewrite).__name__))
                with span(
                    "decompile.cli_rewrite_pass",
                    addr=hex(current_func_addr),
                    name=getattr(function, "name", None),
                    pass_name=pass_name,
                    round=round_idx,
                    index=rewrite_idx,
                ):
                    before_calls = _codegen_call_expr_count() if call_loss_guard_active else 0
                    before_missing = (
                        _missing_expected_call_names_from_codegen_counts() if expected_call_guard_active else ()
                    )
                    snapshot = _snapshot_codegen_cfunc() if call_loss_guard_active else None
                    rewrite_changed = rewrite()
                if rewrite_changed and call_loss_guard_active:
                    after_calls = _codegen_call_expr_count()
                    if after_calls < before_calls and _restore_codegen_cfunc(snapshot):
                        logging.getLogger(__name__).warning(
                            "Rejected CLI rewrite pass due to call loss at function=%#x pass=%s idx=%d (%d -> %d calls)",
                            function_original_addr(function),
                            pass_name,
                            rewrite_idx,
                            before_calls,
                            after_calls,
                        )
                        rewrite_changed = False
                    elif after_calls < before_calls:
                        logging.getLogger(__name__).warning(
                            "CLI rewrite pass removed call expressions without restorable snapshot at function=%#x pass=%s idx=%d (%d -> %d calls)",
                            function_original_addr(function),
                            pass_name,
                            rewrite_idx,
                            before_calls,
                            after_calls,
                        )
                        raise PipelineHardError(
                            "rewrite pass removed call expressions",
                            layer="rewrite",
                            function_addr=function_original_addr(function),
                            details={
                                "pass": pass_name,
                                "before_calls": before_calls,
                                "after_calls": after_calls,
                            },
                        )
                    elif expected_call_guard_active:
                        after_missing = _missing_expected_call_names_from_codegen_counts()
                        if len(after_missing) > len(before_missing) and _restore_codegen_cfunc(snapshot):
                            logging.getLogger(__name__).warning(
                                "Rejected CLI rewrite pass due to worse source-evidenced call coverage at function=%#x pass=%s idx=%d (missing %d -> %d)",
                                function_original_addr(function),
                                pass_name,
                                rewrite_idx,
                                len(before_missing),
                                len(after_missing),
                            )
                            rewrite_changed = False
                        elif len(after_missing) > len(before_missing):
                            raise PipelineHardError(
                                "rewrite pass reduced source-evidenced call coverage",
                                layer="rewrite",
                                function_addr=function_original_addr(function),
                                details={
                                    "pass": pass_name,
                                    "before_missing": before_missing,
                                    "after_missing": after_missing,
                                },
                            )
                if rewrite_changed:
                    iter_changed = True
                    _debug_dump_rewrite_pass_lines_8616(
                        dec.codegen,
                        pass_index=rewrite_idx,
                        pass_name=pass_name,
                        function_addr=function_original_addr(function),
                    )
                if rewrite is _run_stack_lowering_pass:
                    _stack_lowering_already_attempted = True
                    stack_lowering_dirty = False
                elif rewrite_changed and _stack_lowering_already_attempted:
                    stack_lowering_dirty = True
            if not iter_changed:
                break
            changed = True
        _debug_cli_stage_marker_8616("after-cli-rewrite-loop")
        if function_has_call_evidence and rewrite_passes:
            before_calls = _codegen_call_expr_count() if call_loss_guard_active else 0
            snapshot = _snapshot_codegen_cfunc() if call_loss_guard_active else None
            if call_loss_guard_active and snapshot is None:
                # Dynamic angr/codegen compatibility boundary.
                typing.cast(typing.Any, dec.codegen)._inertia_final_callsite_stack_fact_skipped_no_snapshot_8616 = (
                    int(
                        # Dynamic angr/codegen compatibility boundary.
                        getattr(
                            dec.codegen,
                            "_inertia_final_callsite_stack_fact_skipped_no_snapshot_8616",
                            0,
                        )
                        or 0
                    )
                    + 1
                )
                final_callsite_changed = False
            else:
                final_callsite_changed = _run_callsite_stack_fact_pass()
            if final_callsite_changed and call_loss_guard_active:
                after_calls = _codegen_call_expr_count()
                if after_calls < before_calls and _restore_codegen_cfunc(snapshot):
                    logging.getLogger(__name__).warning(
                        "Rejected final callsite stack-fact rewrite due to call loss at function=%#x (%d -> %d calls)",
                        function_original_addr(function),
                        before_calls,
                        after_calls,
                    )
                    final_callsite_changed = False
                elif after_calls < before_calls:
                    raise PipelineHardError(
                        "final callsite stack-fact rewrite removed call expressions",
                        layer="call_lowering",
                        function_addr=function_original_addr(function),
                        details={
                            "before_calls": before_calls,
                            "after_calls": after_calls,
                        },
                    )
            if final_callsite_changed:
                changed = True
        _debug_cli_stage_marker_8616("after-final-callsite-pass")
        with span(
            "decompile.structuring_loop_body_repair_late",
            addr=hex(current_func_addr),
            name=getattr(function, "name", None),
        ):
            late_loop_body_repair_changed = repair_empty_counted_loop_body_from_evidence_8616(project, dec.codegen)
        if late_loop_body_repair_changed:
            changed = True
            typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
            typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
        late_lowering_changed = bool(late_loop_body_repair_changed)
        late_segmented_global_load_changed = materialize_named_segmented_global_loads_8616(
            project,
            dec.codegen,
            synthetic_globals,
            cod_metadata=effective_cod_metadata,
        )
        if late_segmented_global_load_changed:
            changed = True
            late_lowering_changed = True
            typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
            typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
        late_compare_register_global_changed = materialize_compare_register_global_carriers_8616(
            project,
            dec.codegen,
            synthetic_globals,
            cod_metadata=effective_cod_metadata,
        )
        if late_compare_register_global_changed:
            changed = True
            late_lowering_changed = True
            typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
            typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
        late_direct_global_store_changed = materialize_direct_global_symbol_stores_8616(
            project,
            dec.codegen,
            synthetic_globals,
            cod_metadata=effective_cod_metadata,
        )
        if late_direct_global_store_changed:
            changed = True
            late_lowering_changed = True
            typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
            typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
        late_direct_instruction_result = run_direct_instruction_materialization_8616(
            project,
            dec.codegen,
            function=function,
            include_direct_stack_mov=False,
        )
        if late_direct_instruction_result.direct_global_incdec_changed:
            changed = True
            late_lowering_changed = True
            typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
            typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
        late_indexed_segmented_global_changed = materialize_indexed_segmented_global_loads_8616(
            project,
            dec.codegen,
            cod_metadata=effective_cod_metadata,
        )
        if late_indexed_segmented_global_changed:
            changed = True
            late_lowering_changed = True
            typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
            typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
        if late_lowering_changed and _run_typed_widening_pass(project, dec.codegen):
            changed = True
            typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
            typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
        if late_lowering_changed:
            before_late_dce_calls = _codegen_call_expr_count() if call_loss_guard_active else 0
            late_dce_changed = _run_evidence_dce_pass()
            if late_dce_changed:
                after_late_dce_calls = _codegen_call_expr_count() if call_loss_guard_active else before_late_dce_calls
                if after_late_dce_calls < before_late_dce_calls:
                    raise PipelineHardError(
                        "late safe DCE removed call expressions",
                        layer="optimization",
                        function_addr=function_original_addr(function),
                        details={
                            "before_calls": before_late_dce_calls,
                            "after_calls": after_late_dce_calls,
                        },
                    )
                changed = True
                typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
                typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
            late_declaration_prune_changed = bool(
                _prune_unused_unnamed_memory_declarations(dec.codegen) or _prune_unused_local_declarations(dec.codegen)
            )
            if late_declaration_prune_changed:
                changed = True
                typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
                typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
        # Dynamic angr/codegen compatibility boundary.
        postprocess_already_lowered_stack_moves = bool(getattr(dec.codegen, "_inertia_postprocess_changed", False))
        final_direct_instruction_result = None
        if not postprocess_already_lowered_stack_moves and not pointer_memory_contract_active:
            final_direct_instruction_result = run_direct_instruction_materialization_8616(
                project,
                dec.codegen,
                function=function,
                include_direct_global_incdec=False,
                source_kinds=frozenset(
                    {
                        DirectStackMoveSourceKind8616.IMMEDIATE,
                        DirectStackMoveSourceKind8616.STACK_SLOT,
                        DirectStackMoveSourceKind8616.STACK_SLOT_EXPR,
                        DirectStackMoveSourceKind8616.SIGNED_IDIV_REMAINDER,
                        DirectStackMoveSourceKind8616.WIDE_CALL_RETURN_STACK_ARITH,
                    }
                ),
            )
        if final_direct_instruction_result is not None and final_direct_instruction_result.direct_stack_mov_changed:
            changed = True
            typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
            typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
            _run_dead_local_prune_with_call_guard("final direct-stack materialization prune removed call expressions")
        if _run_dead_local_prune_with_call_guard("late pre-cleanup dead-local prune removed call expressions"):
            changed = True
            typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
            typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
        late_ast_cleanup_result = finalize_late_ast_cleanup_8616(project, dec.codegen)
        if late_ast_cleanup_result.changed:
            changed = True
        if late_ast_cleanup_result.requires_dce_after_cleanup:
            if _run_dead_local_prune_with_call_guard("late AST cleanup prune removed call expressions"):
                typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
                typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
            changed = True
        stack_probe_fact_stats = format_stack_probe_fact_stats_8616(dec.codegen)
        if stack_probe_fact_stats is not None:
            logging.getLogger(__name__).debug(
                "stack-probe fact stats for %#x: %s",
                function.addr,
                stack_probe_fact_stats,
            )
        postprocess_semantic_changed = bool(
            getattr(dec.codegen, "_inertia_postprocess_changed", False)
            or getattr(dec.codegen, "_inertia_pointer_memory_materialized_8616", None)
        )
        metadata_repairs = _repair_missing_cnode_codegen_metadata_8616(
            getattr(dec.codegen, "cfunc", None), dec.codegen
        )
        if metadata_repairs:
            typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
        typed_switch_finalize_result = finalize_typed_edge_switch_replacement_if_enabled_8616(
            project,
            dec.codegen,
            synthetic_globals,
            cod_metadata=effective_cod_metadata,
        )
        if typed_switch_finalize_result.changed:
            changed = True
        seqnode_replay_finalize_result = finalize_seqnode_switch_replay_after_replacement_8616(
            project,
            dec.codegen,
            synthetic_globals,
            _run_call_loss_guarded_evidence_dce_pass,
            cod_metadata=effective_cod_metadata,
        )
        if seqnode_replay_finalize_result.changed:
            changed = True
        post_switch_cleanup_result = finalize_post_switch_cleanup_after_seqnode_replacement_8616(project, dec.codegen)
        if post_switch_cleanup_result.changed:
            changed = True
        if post_switch_cleanup_result.requires_dce_after_cleanup:
            post_switch_dce_result = _run_call_loss_guarded_evidence_dce_pass(
                "post-switch trivial-copy DCE removed call expressions"
            )
            if post_switch_dce_result.changed:
                typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
                typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
            changed = True
        if _stabilize_regenerated_noncall_ast_8616(dec.codegen):
            changed = True
            typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
            typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
        final_stack_stats = getattr(dec.codegen, "_inertia_direct_stack_move_lowering_8616", None)
        if (
            not pointer_memory_contract_active
            and
            isinstance(final_stack_stats, dict)
            and int(final_stack_stats.get("raw_fact_count", 0) or 0) > 0
        ):
            bounded_stack_result = run_direct_instruction_materialization_8616(
                project,
                dec.codegen,
                function=function,
                include_direct_stack_incdec=False,
                include_direct_global_incdec=False,
                source_kinds=frozenset(
                    {
                        DirectStackMoveSourceKind8616.SEGMENTED_MEMORY,
                        DirectStackMoveSourceKind8616.STACK_SLOT,
                    }
                ),
                materialize_stack_reloads=False,
                include_callee_saved_spill_prune=False,
                enforce_direct_stack_branch_contract=True,
            )
            if bounded_stack_result.changed:
                changed = True
                typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
                typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
                _run_dead_local_prune_with_call_guard("bounded direct-stack materialization prune removed call expressions")
        if _replay_final_codegen_projections_after_regen_8616(dec.codegen):
            changed = True
            typing.cast(typing.Any, dec.codegen)._inertia_codegen_decl_refresh_required_8616 = True
            typing.cast(typing.Any, dec.codegen)._inertia_force_codegen_regeneration_8616 = True
        if rollback_final_semantic_drift_8616(
            project,
            dec.codegen,
            trusted_core_snapshot,
            refresh_validation=lambda active_project, active_codegen: (
                refresh_x86_16_final_semantic_validation_8616(
                    active_project,
                    active_codegen,
                    persist_failures=False,
                    include_virtual_carriers=True,
                )
            ),
            restore_cfunc=_restore_codegen_cfunc,
            replay_projections=_replay_final_codegen_projections_after_regen_8616,
            function_addr=function_original_addr(function),
        ):
            changed = True
            postprocess_semantic_changed = False
        changed = _finalize_typed_interfaces_and_projections_before_render_8616(dec.codegen) or changed
        render_refresh_required = bool(
            changed
            or postprocess_semantic_changed
            or _codegen_requires_render_refresh_8616(dec.codegen)
        )
        call_args_render_refresh_required = bool(
            getattr(dec.codegen, "_inertia_codegen_call_args_render_refresh_required_8616", False)
        )
        force_codegen_regeneration = bool(getattr(dec.codegen, "_inertia_force_codegen_regeneration_8616", False))
        if os.environ.get("INERTIA_DEBUG_CLI_RENDER_REFRESH") == "1":
            cfunc_repr = _normalize_text_payload_8616(getattr(dec.codegen, "text", "") or "")
            stats_obj = getattr(dec.codegen, "_inertia_live_register_declaration_repair_stats_8616", None)
            logging.getLogger(__name__).warning(
                "[cli-render-refresh] function=%#x changed=%s postprocess_changed=%r pointer_memory=%r refresh=%s force_regen=%s call_args_refresh=%s postprocess_regenerated=%s live_reg_stats=%r codegen=%#x text=%r",
                function_original_addr(function),
                changed,
                getattr(dec.codegen, "_inertia_postprocess_changed", None),
                getattr(dec.codegen, "_inertia_pointer_memory_materialized_8616", None),
                render_refresh_required,
                force_codegen_regeneration,
                call_args_render_refresh_required,
                _postprocess_regenerated_text_available_8616(dec.codegen),
                stats_obj,
                id(dec.codegen),
                "\n".join(cfunc_repr.splitlines()[:8]),
            )
        if render_refresh_required:
            cached_rendered_text = _snapshot_codegen_text(dec.codegen)
            recurrence_rebound = bool(
                getattr(dec.codegen, "_inertia_has_rebound_materialized_recurrence", False)
            ) or bool(
                int(
                    (getattr(dec.codegen, "_inertia_stack_lowering_debug", {}) or {}).get(
                        "recurrence_bound_to_materialized_local",
                        0,
                    )
                    or 0
                )
            )
            if os.environ.get("INERTIA_DEBUG_CALL_MUTATION"):
                _debug_dump_calls_8616(
                    "pre-regenerate-codegen-snapshot",
                    cached_rendered_text,
                    function_original_addr(function),
                )
            with span(
                "decompile.regenerate_codegen",
                addr=hex(current_func_addr),
                name=getattr(function, "name", None),
            ):
                rendered_text, regenerated = _regenerate_codegen_text_safely(
                    dec.codegen,
                    context=f"{hex(function.addr)} {function.name}",
                )
            _clear_codegen_render_refresh_8616(dec.codegen)
            semantic_materialization_active = _codegen_has_semantic_materialization_8616(dec.codegen)
            if (
                not regenerated
                and isinstance(cached_rendered_text, str)
                and cached_rendered_text.strip()
                and not recurrence_rebound
                and (not isinstance(rendered_text, str) or not rendered_text.strip())
            ):
                rendered_text = cached_rendered_text
            # Evidence gate: regeneration may occasionally collapse a call-heavy body
            # to scaffolding-only text. Prefer richer cached text in that case.
            if (
                regenerated
                and not semantic_materialization_active
                and isinstance(cached_rendered_text, str)
                and cached_rendered_text.strip()
                and _final_c_unreachable_after_return_penalty_8616(cached_rendered_text) == 0
                and _under_recovered_call_heavy_codegen_8616(rendered_text, effective_cod_metadata)
                and not _under_recovered_call_heavy_codegen_8616(cached_rendered_text, effective_cod_metadata)
            ):
                rendered_text = cached_rendered_text
            if (
                regenerated
                and isinstance(cached_rendered_text, str)
                and cached_rendered_text.strip()
                and _regeneration_introduced_arg_local_split_8616(cached_rendered_text, rendered_text)
            ):
                rendered_text = cached_rendered_text
                typing.cast(typing.Any, dec.codegen)._inertia_regeneration_arg_local_split_rollback_8616 = int(getattr(dec.codegen, "_inertia_regeneration_arg_local_split_rollback_8616", 0) or 0) + 1
        else:
            rendered_text = _snapshot_codegen_text(dec.codegen)
        debug_call_addr = function_original_addr(function)
        _debug_dump_calls_8616("post-structured-codegen", rendered_text, debug_call_addr)
        if os.environ.get("INERTIA_DEBUG_X87_PROTO") == "1":
            codegen_dynamic = typing.cast(typing.Any, dec.codegen)
            try:
                cfunc = codegen_dynamic.cfunc
            except AttributeError:
                cfunc = None
            cfunc_dynamic = typing.cast(typing.Any, cfunc)
            try:
                width_stats = codegen_dynamic._inertia_stack_prototype_width_stats_8616
            except AttributeError:
                width_stats = None
            try:
                rejected_passes = tuple(codegen_dynamic._inertia_postprocess_rejected_passes or ())
            except AttributeError:
                rejected_passes = ()
            arg_state = tuple(
                (
                    arg.variable.offset,
                    arg.variable.size,
                    arg.variable.name,
                    arg.name,
                    repr(arg.variable_type),
                )
                for arg in tuple(cfunc_dynamic.arg_list or ())
            ) if cfunc is not None else ()
            stack_node_state = tuple(
                (
                    node.variable.offset,
                    node.variable.size,
                    node.variable.name,
                    node.name,
                    node.unified_variable.name if node.unified_variable is not None else None,
                )
                for node in _iter_c_nodes_deep_8616(cfunc_dynamic.statements)
                if isinstance(node, structured_c.CVariable)
                and isinstance(node.variable, SimStackVariable)
            ) if cfunc is not None else ()
            print(
                "[dbg-x87-proto] "
                f"cli_after_codegen functy={cfunc_dynamic.functy!r} "
                f"width_stats={width_stats!r} "
                f"rejected_passes={rejected_passes!r} "
                f"arg_state={arg_state!r} "
                f"stack_node_state={stack_node_state!r}",
                file=sys.stderr,
                flush=True,
            )
        _emit_c_stage_trace(
            project,
            function,
            "post-structured-codegen",
            rendered_text,
            layer_dump_state=layer_dump_state,
        )
        if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            logging.getLogger(__name__).warning(
                "[call-semantics-stage] post-structured function=%#x presence=%d arity=%d deficit=%d",
                function_original_addr(function),
                _expected_call_presence_score_8616(rendered_text, effective_cod_metadata),
                _expected_call_arity_score_8616(rendered_text, effective_cod_metadata),
                _expected_call_arity_deficit_8616(rendered_text, effective_cod_metadata),
            )
        retry_for_call_semantics, missing_calls_for_retry, arity_deficit_for_retry = (
            _call_semantics_retry_evidence_8616(rendered_text, effective_cod_metadata)
        )
        if retry_for_call_semantics:
            # Evidence-first fallback for call-heavy functions:
            # keep the candidate with the strongest expected-call preservation score.
            best_status = "ok"
            best_payload = rendered_text
            best_score = (
                _expected_call_presence_score_8616(rendered_text, effective_cod_metadata),
                _expected_call_arity_score_8616(rendered_text, effective_cod_metadata),
            )
            if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                logging.getLogger(__name__).warning(
                    "[call-semantics-retry] primary function=%#x score=%r deficit=%d",
                    function_original_addr(function),
                    best_score,
                    arity_deficit_for_retry,
                )
            for _ in range(1):
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining < max(8, min(30, max(1, timeout) // 4)):
                        break
                retried = _retry_in_isolated_project()
                if retried is None:
                    break
                retry_status, retry_payload = retried
                if retry_status == "ok" and isinstance(retry_payload, str) and retry_payload.strip():
                    retry_score = (
                        _expected_call_presence_score_8616(retry_payload, effective_cod_metadata),
                        _expected_call_arity_score_8616(retry_payload, effective_cod_metadata),
                    )
                    if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
                        logging.getLogger(__name__).warning(
                            "[call-semantics-retry] candidate function=%#x score=%r deficit=%d selected=%s",
                            function_original_addr(function),
                            retry_score,
                            _expected_call_arity_deficit_8616(retry_payload, effective_cod_metadata),
                            retry_score > best_score,
                        )
                    if retry_score > best_score:
                        best_score = retry_score
                        best_payload = retry_payload
                        best_status = "ok"
                elif retry_status != "empty":
                    # Keep the last non-empty failure only when we have no viable text.
                    if not isinstance(best_payload, str) or not best_payload.strip():
                        best_status = retry_status
                        best_payload = retry_payload
                if isinstance(best_payload, str) and best_payload.strip():
                    rendered_text = best_payload
                elif best_status != "ok":
                    return best_status, best_payload
        elif arity_deficit_for_retry and os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
            logging.getLogger(__name__).warning(
                "[call-semantics-retry] skipped arity-only retry function=%#x missing_calls=%r deficit=%d",
                function_original_addr(function),
                missing_calls_for_retry,
                arity_deficit_for_retry,
            )
        rendered_text = _prepend_recovered_callsite_prototypes_8616(rendered_text, dec.codegen)
        _debug_dump_calls_8616("post-recovered-callsite-prototypes", rendered_text, debug_call_addr)
        if api_style in ("msc", "compiler"):
            emit_msc51_diagnostic(dec.codegen)
        _pre_helper_format_text = rendered_text
        formatted = _format_known_helper_calls(
            project,
            function,
            rendered_text,
            api_style,
            binary_path,
            cod_metadata=effective_cod_metadata,
            codegen=dec.codegen,
        )
        formatted = _prune_standalone_stack_probe_calls_text(formatted)
        if effective_cod_metadata is not None:
            pre_score = _expected_call_presence_score_8616(_pre_helper_format_text, effective_cod_metadata)
            post_score = _expected_call_presence_score_8616(formatted, effective_cod_metadata)
            pre_arity_score = _expected_call_arity_score_8616(_pre_helper_format_text, effective_cod_metadata)
            post_arity_score = _expected_call_arity_score_8616(formatted, effective_cod_metadata)
            if (post_score, post_arity_score) < (pre_score, pre_arity_score):
                formatted = _pre_helper_format_text
        _debug_dump_calls_8616("post-helper-call-format", formatted, debug_call_addr)
        _emit_c_stage_trace(
            project,
            function,
            "post-helper-call-format",
            formatted,
            layer_dump_state=layer_dump_state,
        )
        formatted = _normalize_boolean_conditions(formatted)
        _debug_dump_calls_8616("post-normalize-boolean-conditions", formatted, debug_call_addr)
        formatted = _normalize_anonymous_call_targets(formatted)
        _debug_dump_calls_8616("post-normalize-anon-targets", formatted, debug_call_addr)
        formatted = _prune_void_function_return_values_text(formatted)
        _debug_dump_calls_8616("post-prune-void-return-values-text", formatted, debug_call_addr)
        formatted = _normalize_function_signature_arg_names(formatted)
        _debug_dump_calls_8616("post-normalize-signature-arg-names", formatted, debug_call_addr)
        formatted = _collapse_annotated_stack_aliases_text(formatted)
        _debug_dump_calls_8616("post-collapse-annotated-stack-aliases-1", formatted, debug_call_addr)
        formatted = _materialize_missing_generic_local_declarations_text(formatted)
        _debug_dump_calls_8616("post-materialize-missing-generic-locals-1", formatted, debug_call_addr)
        formatted = _prune_unused_local_declarations_text(formatted)
        _debug_dump_calls_8616("post-prune-unused-local-decls-1", formatted, debug_call_addr)
        formatted = _annotate_cod_proc_output(formatted, function, effective_cod_metadata, codegen=dec.codegen)
        _debug_dump_calls_8616("post-annotate-cod-proc-output", formatted, debug_call_addr)
        _emit_c_stage_trace(
            project,
            function,
            "post-cod-annotation",
            formatted,
            layer_dump_state=layer_dump_state,
        )
        formatted = _collapse_annotated_stack_aliases_text(formatted)
        _debug_dump_calls_8616("post-collapse-annotated-stack-aliases-2", formatted, debug_call_addr)
        formatted = _materialize_missing_generic_local_declarations_text(formatted)
        _debug_dump_calls_8616("post-materialize-missing-generic-locals-2", formatted, debug_call_addr)
        formatted = _prune_unused_local_declarations_text(formatted)
        _debug_dump_calls_8616("post-prune-unused-local-decls-2", formatted, debug_call_addr)
        formatted = _rewrite_known_helper_signature_text(formatted, function, codegen=dec.codegen)
        _debug_dump_calls_8616("post-rewrite-known-helper-signature", formatted, debug_call_addr)
        _emit_c_stage_trace(
            project,
            function,
            "post-helper-signature-rewrite",
            formatted,
            layer_dump_state=layer_dump_state,
        )
        if not tail_validation_complete_for_rewrite_gate:
            formatted = _prune_trailing_generic_return_text(formatted)
            _debug_dump_calls_8616("post-prune-trailing-generic-return", formatted, debug_call_addr)
        formatted = _materialize_annotated_cod_declarations_text(
            formatted,
            function,
            effective_cod_metadata,
            preserve_source_header=bool(getattr(dec.codegen, "_inertia_codegen_signature_authoritative_8616", None)),
        )
        _debug_dump_calls_8616("post-materialize-annotated-cod-decls", formatted, debug_call_addr)
        formatted = _normalize_signed_char_function_signature_text(formatted, function, dec.codegen)
        _debug_dump_calls_8616("post-normalize-signed-char-signature", formatted, debug_call_addr)
        formatted = _normalize_msc_signed_int_function_signature_text(formatted, function, dec.codegen)
        _debug_dump_calls_8616("post-normalize-msc-signed-int-signature", formatted, debug_call_addr)
        formatted = _normalize_portable_flat_main_signature_text(
            formatted,
            function,
            c_target=getattr(project, "_inertia_c_target", "portable-flat"),
        )
        _debug_dump_calls_8616("post-normalize-portable-flat-main-signature", formatted, debug_call_addr)
        if not tail_validation_complete_for_rewrite_gate:
            formatted = _prune_unused_staging_assignments(formatted)
            _debug_dump_calls_8616("post-prune-unused-staging-assignments", formatted, debug_call_addr)
        formatted = _prune_non_lvalue_arithmetic_assignments(formatted)
        _debug_dump_calls_8616("post-prune-non-lvalue-arithmetic-assignments", formatted, debug_call_addr)
        formatted = _normalize_shift_add_precedence_in_assignments(formatted)
        formatted = _normalize_unary_not_shift_precedence_text(formatted)
        _debug_dump_calls_8616("post-normalize-shift-precedence", formatted, debug_call_addr)
        formatted = _normalize_concat_zero_text(formatted)
        formatted = _normalize_integer_dereference_stores_text(formatted)
        formatted = _materialize_stack_base_placeholder_declaration_text(formatted)
        formatted = _materialize_missing_g_hex_externs_text(formatted)
        formatted = _materialize_codegen_global_externs_text_8616(formatted, dec.codegen)
        formatted = _prune_dead_stack_base_assignments_text(formatted)
        _debug_dump_calls_8616("post-normalize-concat-zero", formatted, debug_call_addr)
        formatted = _collapse_duplicate_type_keywords_text(formatted)
        _debug_dump_calls_8616("post-collapse-duplicate-type-keywords", formatted, debug_call_addr)
        formatted = _normalize_spurious_duplicate_local_suffixes(formatted)
        _debug_dump_calls_8616("post-normalize-duplicate-local-suffixes", formatted, debug_call_addr)
        formatted = _dedupe_adjacent_prototype_lines(formatted)
        _debug_dump_calls_8616("post-dedupe-adjacent-prototypes", formatted, debug_call_addr)
        formatted = _materialize_opaque_pointer_typedefs_text(formatted)
        _debug_dump_calls_8616("post-materialize-opaque-pointer-typedefs", formatted, debug_call_addr)
        formatted = _sanitize_mangled_autonames_text(formatted)
        formatted = _strip_register_fragment_suffixes_text(formatted)
        _debug_dump_calls_8616("post-sanitize-mangled-autonames", formatted, debug_call_addr)
        formatted = normalize_unresolved_c_text(formatted)
        _debug_dump_calls_8616("post-normalize-unresolved-c-text", formatted, debug_call_addr)
        # Final text-cleanup boundary:
        # From this point on, only do presentation/compile-hygiene cleanup. If output is
        # still missing stack-variable recovery or carries raw pointer-carrier chains,
        # the fix belongs earlier in stack lowering / AST rewrites, not below.
        formatted = _materialize_missing_generic_local_declarations_text(formatted)
        _debug_dump_calls_8616("post-materialize-missing-generic-locals-final", formatted, debug_call_addr)
        formatted = _prune_unused_local_declarations_text(formatted)
        _debug_dump_calls_8616("post-prune-unused-local-decls-final", formatted, debug_call_addr)
        pre_final_text_cleanup = formatted
        _emit_c_stage_trace(
            project,
            function,
            "post-final-text-cleanup",
            formatted,
            layer_dump_state=layer_dump_state,
        )
        if not (
            binary_path is not None
            and binary_path.name.lower().endswith(".cod")
            and getattr(function, "name", "") == "fold_values"
        ):
            simplified_formatted = _simplify_x86_16_stack_byte_pointers(formatted, effective_cod_metadata)
            _debug_dump_calls_8616("post-simplify-x86-16-stack-byte-pointers", simplified_formatted, debug_call_addr)
            if simplified_formatted != formatted:
                simplified_formatted = _materialize_missing_generic_local_declarations_text(simplified_formatted)
                _debug_dump_calls_8616(
                    "post-materialize-missing-generic-locals-after-simplify",
                    simplified_formatted,
                    debug_call_addr,
                )
                formatted = _prune_unused_local_declarations_text(simplified_formatted)
                _debug_dump_calls_8616("post-prune-unused-local-decls-after-simplify", formatted, debug_call_addr)
            else:
                formatted = simplified_formatted
        _debug_dump_calls_8616("final-emitted-c", formatted, debug_call_addr)
        formatted = _prune_non_lvalue_arithmetic_assignments(formatted)
        _debug_dump_calls_8616("post-final-non-lvalue-arithmetic-prune", formatted, debug_call_addr)
        formatted = _dedupe_duplicate_local_declarations_text(formatted)
        formatted = _normalize_scalar_assigned_extern_arrays_text(formatted)
        formatted = _materialize_missing_generic_local_declarations_text(formatted)
        formatted = _materialize_missing_segment_macro_locals_text(formatted)
        formatted = _materialize_missing_synthetic_global_declarations_text(
            formatted,
            effective_cod_metadata,
            synthetic_globals=synthetic_globals,
        )
        formatted = _dedupe_conflicting_extern_variable_declarations_text(formatted)
        formatted = _materialize_missing_direct_call_prototypes_text(formatted)
        formatted = _prune_void_call_assignments_text(formatted)
        formatted = _prune_weaker_conflicting_prototypes_text(formatted)
        formatted = _prune_invalid_simple_function_prototypes_text(formatted)
        _debug_dump_calls_8616("post-final-dedup", formatted, debug_call_addr)
        if effective_cod_metadata is not None:
            # Evidence-first final text selection: later text-only cleanup passes may
            # accidentally degrade call-floor evidence. Keep the strongest candidate.
            fallback_candidates = [
                formatted,
                pre_final_text_cleanup,
                rendered_text,
                _pre_helper_format_text,
            ]

            def _semantic_rank(text: str) -> tuple[int, int, int, int, int, int, int, int]:
                if not isinstance(text, str) or not text.strip():
                    return (-(10**9), 0, 0, 0, 0, 0, 0, 0)
                base_score = _render_candidate_score_8616(text, effective_cod_metadata)
                return (
                    *base_score,
                    _cod_signature_and_stack_alias_score_8616(text, function, effective_cod_metadata),
                    _global_declaration_coverage_score_8616(text, effective_cod_metadata, synthetic_globals),
                )

            best_text = max(fallback_candidates, key=_semantic_rank)
            if _semantic_rank(best_text) > _semantic_rank(formatted):
                formatted = best_text
            formatted = _materialize_missing_synthetic_global_declarations_text(
                formatted,
                effective_cod_metadata,
                synthetic_globals=synthetic_globals,
            )
            formatted = _dedupe_conflicting_extern_variable_declarations_text(formatted)
            formatted = _prune_invalid_simple_function_prototypes_text(formatted)
            formatted = _prune_unused_local_declarations_text(formatted)
            formatted = _prune_standalone_stack_probe_calls_text(formatted)

        forced_template = _forced_function_template(getattr(function, "name", None), binary_path, api_style)
        if forced_template is not None:
            formatted = forced_template

        # Final canonicalization pass: late evidence-rank fallback may re-select
        # pre-clean text; enforce compile-hygiene token cleanup before gates.
        with span(
            "decompile.final_canonicalize",
            addr=hex(current_func_addr),
            name=getattr(function, "name", None),
        ):
            formatted = _sanitize_mangled_autonames_text(formatted)
            formatted = _strip_register_fragment_suffixes_text(formatted)
            formatted = _prune_parameter_shadow_declarations_text(formatted)
            formatted = _prune_undefined_fragment_carrier_assignments_text(formatted)
            formatted = _normalize_scalar_gb_array_declarations_text(formatted)
            formatted = _normalize_seg_offset_void_pointer_args_text(formatted)
            formatted = normalize_unresolved_c_text(formatted)
            formatted = _normalize_boolean_conditions(formatted)
            formatted = _materialize_missing_generic_local_declarations_text(formatted)
            formatted = _hoist_c89_local_declarations_text(formatted)
            formatted = _dedupe_duplicate_local_declarations_text(formatted)
            if not tail_validation_complete_for_rewrite_gate:
                formatted = _prune_trailing_generic_return_text(formatted)
        formatted = _select_evidence_recovered_c_8616(
            formatted,
            evidence_recovered_c,
            prefer_proven_evidence=evidence_recovery_is_proven,
        )
        formatted = _normalize_unary_not_shift_precedence_text(formatted)
        formatted = _normalize_boolean_conditions(formatted)
        formatted = _materialize_codegen_global_externs_text_8616(formatted, dec.codegen)
        formatted = _prune_weaker_conflicting_prototypes_text(formatted)
        formatted = _prune_invalid_simple_function_prototypes_text(formatted)
        formatted = _dedupe_duplicate_local_declarations_text(formatted)
        formatted = _hoist_c89_local_declarations_text(formatted)
        formatted = _prune_unused_local_declarations_text(formatted)
        formatted = _prune_standalone_stack_probe_calls_text(formatted)

        _emit_c_stage_trace(
            project,
            function,
            "final-emitted-c",
            formatted,
            layer_dump_state=layer_dump_state,
        )
        quality = assess_decompiled_c_text(formatted)
        if quality.reject_as_decompiled:
            if os.environ.get("INERTIA_DEBUG_RETURN_BRANCH"):
                logging.getLogger(__name__).warning(
                    "[return-chain-cli] quality rejected function=%#x markers=%r",
                    function_original_addr(function),
                    tuple(quality.markers[:8]),
                )
            _remember_tail_validation_snapshot(
                dec.codegen,
                include_virtual_carriers=True,
            )
            _emit_typed_edge_switch_replacement_safety_stats_8616(dec.codegen)
            typing.cast(typing.Any, project)._inertia_partial_codegen_text = formatted
            marker_summary = ", ".join(quality.markers[:3])
            if len(quality.markers) > 3:
                marker_summary += ", ..."
            return "empty", f"Decompiler produced unresolved IR-shaped C ({marker_summary})."
        _remember_tail_validation_snapshot(
            dec.codegen,
            include_virtual_carriers=True,
        )
        _emit_typed_edge_switch_replacement_safety_stats_8616(dec.codegen)
        # If a hard final gate rejects this function, preserve the exact C that
        # failed the gate. Earlier live snapshots can be much larger stale
        # artifacts and hide the true blocker from diagnostics.
        typing.cast(typing.Any, project)._inertia_partial_codegen_text = formatted
        with span(
            "decompile.final_gates",
            addr=hex(current_func_addr),
            name=getattr(function, "name", None),
        ):
            # ── PIPELINE CONTRACT GATE: enforce closed loop before C emission ──
            try:
                assert_pipeline_contracts_8616(dec.codegen)
            except PipelineHardError:
                raise  # let the caller handle it as a real failure

            # ── FINAL EMISSION GATE: forbid ss << 4, stack[, etc. in final C ──
            assert_final_c_quality_8616(
                formatted,
                function_addr=function_original_addr(function),
            )

        tail_validation_cache_passed = _validated_payload_cache_tail_validation_passed_8616(project)
        if tail_validation_cache_passed:
            typing.cast(typing.Any, project)._inertia_last_validated_function_payload = (function_original_addr(function), formatted)
            validated_snapshot = getattr(project, "_inertia_last_tail_validation_snapshot", None)
            if isinstance(validated_snapshot, dict):
                typing.cast(typing.Any, project)._inertia_last_validated_function_payload_snapshot = dict(validated_snapshot)
            else:
                typing.cast(typing.Any, project)._inertia_last_validated_function_payload_snapshot = None
            if os.environ.get("INERTIA_DEBUG_RETURN_BRANCH"):
                logging.getLogger(__name__).warning(
                    "[return-chain-cli] set validated payload function=%#x len=%d",
                    function_original_addr(function),
                    len(formatted),
                )
        else:
            stale_record = getattr(project, "_inertia_last_validated_function_payload", None)
            if (
                isinstance(stale_record, tuple)
                and len(stale_record) == 2
                and stale_record[0] == function_original_addr(function)
            ):
                typing.cast(typing.Any, project)._inertia_last_validated_function_payload = None
                typing.cast(typing.Any, project)._inertia_last_validated_function_payload_snapshot = None
            if os.environ.get("INERTIA_DEBUG_RETURN_BRANCH"):
                logging.getLogger(__name__).warning(
                    "[return-chain-cli] refused validated payload cache function=%#x len=%d reason=%s",
                    function_original_addr(function),
                    len(formatted),
                    "failed_tail_snapshot" if not tail_validation_cache_passed else "failed_recompile",
                )
        typing.cast(typing.Any, project)._inertia_partial_codegen_text = None
        return "ok", formatted

    return _impl()


def _function_complexity(function: Any) -> tuple[int, int]:
    def _impl() -> tuple[int, int]:
        project = getattr(function, "project", None)
        function_info = getattr(function, "info", None)
        local_blocks: tuple[Any, ...] = tuple((getattr(function, "_local_blocks", {}) or {}).values())
        if local_blocks:
            block_addrs = tuple(
                sorted(
                    addr for addr in (getattr(block, "addr", None) for block in local_blocks) if isinstance(addr, int)
                )
            )
            total_bytes = sum(
                int(getattr(block, "size", 0) or len(getattr(block, "bytestr", b"") or b"")) for block in local_blocks
            )
            complexity = (len(block_addrs), total_bytes)
            if isinstance(function_info, MutableMapping):
                function_info["_inertia_function_complexity"] = {
                    "block_addrs": block_addrs,
                    "blocks": complexity[0],
                    "bytes": complexity[1],
                    "source": "bounded_local_blocks",
                }
            return complexity
        blocks: tuple[Any, ...] = tuple(getattr(function, "blocks", ()) or ())
        if blocks:
            block_addrs = tuple(
                sorted(addr for addr in (getattr(block, "addr", None) for block in blocks) if isinstance(addr, int))
            )
            total_bytes = sum(
                int(getattr(block, "size", 0) or len(getattr(block, "bytes", b"") or b"")) for block in blocks
            )
            complexity = (len(block_addrs), total_bytes)
            if isinstance(function_info, MutableMapping):
                function_info["_inertia_function_complexity"] = {
                    "block_addrs": block_addrs,
                    "blocks": complexity[0],
                    "bytes": complexity[1],
                    "source": "bounded_blocks",
                }
            return complexity
        block_addrs = tuple(sorted(getattr(function, "block_addrs_set", set()) or ()))
        if isinstance(function_info, MutableMapping):
            cached_complexity = function_info.get("_inertia_function_complexity")
            if (
                isinstance(cached_complexity, dict)
                and tuple(cached_complexity.get("block_addrs", ())) == block_addrs
                and isinstance(cached_complexity.get("blocks"), int)
                and isinstance(cached_complexity.get("bytes"), int)
                and cached_complexity.get("source") == "factory_decode"
            ):
                return cached_complexity["blocks"], cached_complexity["bytes"]
        if project is None:
            return 0, 0
        block_profiles = _function_block_profile_cache_8616(function, project)
        total_bytes = 0
        for block_profile in block_profiles.values():
            total_bytes += block_profile[0]
        complexity = (len(block_addrs), total_bytes)
        if isinstance(function_info, MutableMapping):
            function_info["_inertia_function_complexity"] = {
                "block_addrs": block_addrs,
                "blocks": complexity[0],
                "bytes": complexity[1],
                "source": "factory_decode",
            }
        return complexity

    return _impl()


def _direct_call_stub_filter_regions(
    project: angr.Project, function: object
) -> tuple[list[tuple[int, int]], tuple[int, int] | None]:
    local_ranges = _function_covered_ranges(function)
    display_addr = function_original_addr(function)
    original_region: tuple[int, int] | None = None
    metadata = getattr(project, "_inertia_lst_metadata", None)
    if metadata is not None:
        original_region = _lst_code_region(metadata, display_addr)
    original_project = getattr(project, "_inertia_original_project", None)
    if original_region is None and original_project is not None:
        original_metadata = getattr(original_project, "_inertia_lst_metadata", None)
        if original_metadata is not None:
            original_region = _lst_code_region(original_metadata, display_addr)
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    if original_region is not None and isinstance(original_delta, int):
        slice_region = (original_region[0] - original_delta, original_region[1] - original_delta)
        if not local_ranges:
            local_ranges = [slice_region]
        elif slice_region not in local_ranges:
            local_ranges = [slice_region, *local_ranges]
    return local_ranges, original_region


def _is_stack_probe_name_8616(name: str | None) -> bool:
    return bool(is_x86_16_stack_probe_name_8616(name))


def _is_known_noreturn_name_8616(name: str | None) -> bool:
    known_noreturn_names = {"abort", "_abort", "__abort", "exit", "_exit", "__exit", "fatalerror", "_fatalerror"}
    if not isinstance(name, str):
        return False
    normalized = name.strip().lower()
    return normalized in known_noreturn_names or normalized.lstrip("_") in known_noreturn_names


def _sidecar_enclosing_label_8616(metadata: LSTMetadata, addr: int) -> str | None:
    labels = getattr(metadata, "code_labels", None)
    if not isinstance(labels, dict):
        return None
    cached_regions = getattr(metadata, "_inertia_code_label_regions_8616", None)
    if not isinstance(cached_regions, tuple):
        regions: list[tuple[int, int, str]] = []
        for start, label in labels.items():
            if not (isinstance(start, int) and isinstance(label, str) and label):
                continue
            span = _lst_code_region(metadata, start)
            if span is None:
                continue
            regions.append((int(span[0]), int(span[1]), label))
        cached_regions = tuple(sorted(regions))
        with contextlib.suppress(Exception):
            typing.cast(typing.Any, metadata)._inertia_code_label_regions_8616 = cached_regions
    for start, end, label in cached_regions:
        if start <= addr < end:
            return str(label)
    return None


def _function_name_at_addr_8616(project: angr.Project, addr: int) -> str | None:
    functions = getattr(getattr(project, "kb", None), "functions", None)
    lookup = getattr(functions, "function", None)
    if not callable(lookup):
        return None
    try:
        function = lookup(addr=addr, create=False)
    except TypeError:
        return None
    name = normalize_callee_name_8616(getattr(function, "name", None))
    return name if isinstance(name, str) and name else None


def _compiler_helper_name_at_addr_8616(project: angr.Project, addr: int) -> str | None:
    evidence = identify_x86_16_compiler_helper_at_8616(project, addr)
    return evidence.name if evidence is not None else None


def _label_at_addr_8616(project: angr.Project, addr: int) -> str | None:
    label = getattr(getattr(project, "kb", None), "labels", {}).get(addr)
    label = normalize_callee_name_8616(label)
    return label if isinstance(label, str) and label else None


def _ordered_original_target_candidates_8616(
    project: angr.Project,
    slice_target: int,
) -> tuple[int, ...]:
    """Order original addresses for rebased near and absolute far targets."""
    original_project = getattr(project, "_inertia_original_project", None)
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    if original_project is None or not isinstance(original_delta, int):
        return ()
    original_object = getattr(getattr(original_project, "loader", None), "main_object", None)
    original_min = getattr(original_object, "min_addr", None)
    original_max = getattr(original_object, "max_addr", None)
    target_is_original_linear = (
        isinstance(original_min, int)
        and isinstance(original_max, int)
        and original_min <= slice_target <= original_max
    )
    candidates = (
        (slice_target, slice_target + original_delta)
        if target_is_original_linear
        else (slice_target + original_delta, slice_target)
    )
    return tuple(dict.fromkeys(candidate for candidate in candidates if candidate >= 0))


def _original_callee_name_8616(project: angr.Project, slice_target: int) -> str | None:
    cache = getattr(project, "_inertia_original_callee_name_cache_8616", None)
    if not isinstance(cache, dict):
        cache = {}
        with contextlib.suppress(Exception):
            typing.cast(typing.Any, project)._inertia_original_callee_name_cache_8616 = cache
    cache_key = int(slice_target)
    if cache_key in cache:
        cached = cache.get(cache_key)
        return cached if isinstance(cached, str) and cached else None

    def _cache_result(value: str | None) -> str | None:
        cache[cache_key] = value if isinstance(value, str) and value else None
        return value if isinstance(value, str) and value else None

    original_project = getattr(project, "_inertia_original_project", None)
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    if original_project is None or not isinstance(original_delta, int):
        return _cache_result(None)
    original_targets = _ordered_original_target_candidates_8616(project, slice_target)

    def _helper_overrides_generic_name(helper_name: str | None, known_name: str | None) -> bool:
        if not isinstance(helper_name, str) or not helper_name:
            return False
        normalized = normalize_callee_name_8616(known_name)
        return (
            not isinstance(normalized, str) or not normalized or normalized.startswith(("sub_", "loc_"))
        )

    metadata = getattr(original_project, "_inertia_lst_metadata", None)
    for original_target in original_targets:
        function_name = _function_name_at_addr_8616(original_project, original_target)
        helper_name = _compiler_helper_name_at_addr_8616(original_project, original_target)
        if _helper_overrides_generic_name(helper_name, function_name):
            return _cache_result(helper_name)
        if isinstance(function_name, str) and function_name and not function_name.startswith(("sub_", "loc_")):
            return _cache_result(function_name)
        label = _label_at_addr_8616(original_project, original_target)
        if _helper_overrides_generic_name(helper_name, label):
            return _cache_result(helper_name)
        if isinstance(label, str) and label:
            return _cache_result(label)
        if metadata is None:
            continue
        label = normalize_callee_name_8616(getattr(metadata, "code_labels", {}).get(original_target))
        if _helper_overrides_generic_name(helper_name, label):
            return _cache_result(helper_name)
        if isinstance(label, str) and label:
            return _cache_result(label)
        span_label = normalize_callee_name_8616(_sidecar_enclosing_label_8616(metadata, original_target))
        if _helper_overrides_generic_name(helper_name, span_label):
            return _cache_result(helper_name)
        if isinstance(span_label, str) and span_label:
            return _cache_result(span_label)
    return _cache_result(None)


def _callee_names_equivalent_8616(left: str | None, right: str | None) -> bool:
    left_name = normalize_callee_name_8616(left)
    right_name = normalize_callee_name_8616(right)
    if not isinstance(left_name, str) or not isinstance(right_name, str):
        return False
    return left_name == right_name or left_name.lstrip("_") == right_name.lstrip("_")


def _function_named_addr_8616(project: angr.Project, name: str) -> int | None:
    functions = getattr(getattr(project, "kb", None), "functions", None)
    lookup = getattr(functions, "function", None)
    if not callable(lookup):
        return None
    lookup_names = [name]
    undecorated = name.lstrip("_")
    decorated = f"_{undecorated}" if undecorated else None
    if decorated is not None and decorated not in lookup_names:
        lookup_names.append(decorated)
    for lookup_name in lookup_names:
        try:
            function = lookup(name=lookup_name, create=False)
        except TypeError:
            continue
        addr = getattr(function, "addr", None)
        if isinstance(addr, int):
            return addr
    return None


def _candidate_original_target_8616(project: angr.Project, candidate: int) -> int | None:
    candidates = _ordered_original_target_candidates_8616(project, candidate)
    return candidates[0] if candidates else None


def _call_name_matches_target_evidence_8616(
    project: angr.Project, candidate: int, call_name: str | None
) -> bool:
    expected = normalize_callee_name_8616(call_name)
    if not isinstance(expected, str) or not expected:
        return False
    for known_name in (
        _original_callee_name_8616(project, candidate),
        _function_name_at_addr_8616(project, candidate),
        _compiler_helper_name_at_addr_8616(project, candidate),
        _label_at_addr_8616(project, candidate),
    ):
        if _callee_names_equivalent_8616(known_name, expected):
            return True
    original_project = getattr(project, "_inertia_original_project", None)
    original_target = _candidate_original_target_8616(project, candidate)
    if original_project is not None and isinstance(original_target, int):
        for known_name in (
            _function_name_at_addr_8616(original_project, original_target),
            _compiler_helper_name_at_addr_8616(original_project, original_target),
            _label_at_addr_8616(original_project, original_target),
        ):
            if _callee_names_equivalent_8616(known_name, expected):
                return True
        named_addr = _function_named_addr_8616(original_project, expected)
        if isinstance(named_addr, int) and named_addr == original_target:
            return True
    named_addr = _function_named_addr_8616(project, expected)
    return isinstance(named_addr, int) and named_addr == candidate


def _parse_direct_call_target_8616(insn: object) -> int | None:
    def _impl() -> int | None:
        capstone_insn = getattr(insn, "insn", insn)
        operands = getattr(capstone_insn, "operands", None)
        if operands:
            mnemonic = str(getattr(insn, "mnemonic", "") or "").lower()
            if (
                mnemonic == "lcall"
                and len(operands) == 2
                and all(getattr(operand, "type", None) == 2 for operand in operands)
                and all(isinstance(getattr(operand, "imm", None), int) for operand in operands)
            ):
                segment = int(operands[0].imm) & 0xFFFF
                offset_width = 32 if getattr(operands[1], "size", 2) == 4 else 16
                offset = int(operands[1].imm) & ((1 << offset_width) - 1)
                return (segment << 4) + offset
            operand = operands[0]
            if getattr(operand, "type", None) == 2 and isinstance(getattr(operand, "imm", None), int):
                return int(operand.imm)
        op_str = str(getattr(insn, "op_str", "") or "").strip().lower()
        if not op_str or "[" in op_str or any(ch.isalpha() for ch in op_str if ch not in "xabcdef"):
            return None
        for token in re.split(r"[\s,:]+", op_str):
            if token:
                with contextlib.suppress(ValueError):
                    return int(token, 0)
        return None

    return _impl()


def _iter_capstone_direct_calls_8616(
    project: angr.Project, function: Any
) -> Iterator[tuple[int, int, int | None]]:
    def _impl() -> Iterator[tuple[int, int, int | None]]:
        factory = getattr(project, "factory", None)
        if factory is None:
            return
        for block_addr in sorted(getattr(function, "block_addrs_set", ()) or ()):
            try:
                block = factory.block(block_addr, opt_level=0)
            except Exception as ex:
                logging.getLogger(__name__).debug(
                    "Direct call block decode failed at function=%#x block=%#x: %s",
                    getattr(function, "addr", -1) or -1,
                    block_addr,
                    ex,
                )
                continue
            for insn in getattr(getattr(block, "capstone", None), "insns", ()) or ():
                if getattr(insn, "mnemonic", "").lower() not in {"call", "lcall"}:
                    continue
                target = _parse_direct_call_target_8616(insn)
                if isinstance(target, int):
                    insn_addr = getattr(insn, "address", block_addr)
                    insn_size = getattr(getattr(insn, "insn", None), "size", None)
                    ret_addr = (
                        (insn_addr + insn_size)
                        if isinstance(insn_addr, int) and isinstance(insn_size, int) and insn_size > 0
                        else None
                    )
                    if isinstance(insn_addr, int):
                        yield insn_addr, target, ret_addr

    return _impl()


def _iter_linear_region_direct_calls_8616(
    project: angr.Project, regions: list[tuple[int, int]] | tuple[tuple[int, int], ...]
) -> Iterator[tuple[int, int, int | None]]:
    def _impl() -> Iterator[tuple[int, int, int | None]]:
        loader_memory = getattr(getattr(project, "loader", None), "memory", None)
        arch = getattr(project, "arch", None)
        capstone = getattr(arch, "capstone", None)
        if loader_memory is None or capstone is None:
            return
        for start, end in regions:
            if not isinstance(start, int) or not isinstance(end, int) or end <= start:
                continue
            size = end - start
            if size > 0x1000:
                continue
            try:
                code = bytes(loader_memory.load(start, size))
            except Exception as ex:
                logging.getLogger(__name__).debug(
                    "Direct call linear region decode failed at region=%#x-%#x: %s",
                    start,
                    end,
                    ex,
                )
                continue
            for insn in capstone.disasm(code, start):
                insn_addr = getattr(insn, "address", None)
                if not isinstance(insn_addr, int) or not (start <= insn_addr < end):
                    continue
                if str(getattr(insn, "mnemonic", "") or "").lower() not in {"call", "lcall"}:
                    continue
                target = _parse_direct_call_target_8616(insn)
                if not isinstance(target, int):
                    continue
                insn_size = getattr(getattr(insn, "insn", None), "size", None)
                if not isinstance(insn_size, int) or insn_size <= 0:
                    insn_size = getattr(insn, "size", None)
                ret_addr = (insn_addr + insn_size) if isinstance(insn_size, int) and insn_size > 0 else None
                yield insn_addr, target, ret_addr

    return _impl()


def _callsite_addr_points_to_call_insn_8616(
    project: angr.Project, function: object, callsite: int
) -> bool:
    factory = getattr(project, "factory", None)
    if factory is None:
        return True
    try:
        block = factory.block(callsite, opt_level=0)
    except Exception:
        return True
    for insn in getattr(getattr(block, "capstone", None), "insns", ()) or ():
        if getattr(insn, "address", None) != callsite:
            continue
        mnemonic = str(getattr(insn, "mnemonic", "") or "").lower()
        return mnemonic in {"call", "lcall"}
    return False


def _compute_candidate_targets_8616(target: int, linked_base: int | None, image_end: int | None) -> set[int]:
    candidates = {target}
    if isinstance(linked_base, int):
        if target < linked_base:
            linked_target = linked_base + target
            if image_end is None or linked_target < image_end:
                candidates.add(linked_target)
        elif image_end is None or target < image_end:
            unbased_target = target - linked_base
            if 0 <= unbased_target < 0x10000:
                candidates.add(unbased_target)
    return candidates


def _choose_preferred_candidate_8616(
    project: angr.Project,
    candidates: set[int],
    local_ranges: list[tuple[int, int]],
    original_region: tuple[int, int] | None,
    original_delta: int | None,
) -> tuple[int | None, str | None]:
    def _impl() -> tuple[int | None, str | None]:
        preferred_candidate: int | None = None
        preferred_rank: tuple[int, int, int] | None = None
        fallback_call_name: str | None = None
        for candidate in sorted(candidates):
            original_target = candidate + original_delta if isinstance(original_delta, int) else None
            if _addr_in_ranges(candidate, local_ranges):
                continue
            if (
                isinstance(original_target, int)
                and original_region is not None
                and original_region[0] <= original_target < original_region[1]
            ):
                continue
            original_label = _original_callee_name_8616(project, candidate)
            slice_entry = getattr(project, "entry", None)
            unbased_penalty = 1 if isinstance(slice_entry, int) and candidate < slice_entry else 0
            # Exact original-target evidence is stronger than the based/unbased
            # address preference. In exact-region slices the true near target may
            # be below the slice entry, while adding the linked base can point at
            # an unrelated internal function.
            rank = (0 if isinstance(original_label, str) and bool(original_label) else 1, unbased_penalty, -candidate)
            if preferred_rank is None or rank < preferred_rank:
                preferred_candidate = candidate
                preferred_rank = rank
            if isinstance(original_label, str) and original_label:
                fallback_call_name = original_label
        return preferred_candidate, fallback_call_name

    return _impl()


def _collect_direct_calls_8616(
    project: angr.Project, function: object
) -> list[tuple[int | None, int, int | None]]:
    function_dynamic = cast(Any, function)
    direct_calls: list[tuple[int | None, int, int | None]] = []
    for callsite in getattr(function, "get_call_sites", list)() or ():
        if isinstance(callsite, int) and not _callsite_addr_points_to_call_insn_8616(project, function, callsite):
            continue
        try:
            target = function_dynamic.get_call_target(callsite)
        except Exception as ex:
            logging.getLogger(__name__).debug(
                "Call target lookup failed at function=%#x callsite=%#x: %s",
                getattr(function, "addr", -1) or -1,
                callsite,
                ex,
            )
            continue
        ret_addr = None
        with contextlib.suppress(Exception):
            ret_addr = function_dynamic.get_call_return(callsite)
        direct_calls.append((callsite, target, ret_addr))
    call_index_by_site = {
        callsite: index
        for index, (callsite, _target, _ret_addr) in enumerate(direct_calls)
        if isinstance(callsite, int)
    }
    for callsite, target, ret_addr in _iter_capstone_direct_calls_8616(project, function):
        if isinstance(callsite, int) and callsite in call_index_by_site:
            direct_calls[call_index_by_site[callsite]] = (callsite, target, ret_addr)
            continue
        if isinstance(callsite, int):
            call_index_by_site[callsite] = len(direct_calls)
        direct_calls.append((callsite, target, ret_addr))
    if isinstance(getattr(project, "_inertia_original_linear_delta", None), int):
        local_ranges, _original_region = _direct_call_stub_filter_regions(project, function)
        for callsite, target, ret_addr in _iter_linear_region_direct_calls_8616(project, local_ranges):
            if isinstance(callsite, int) and callsite in call_index_by_site:
                continue
            if isinstance(callsite, int):
                call_index_by_site[callsite] = len(direct_calls)
            direct_calls.append((callsite, target, ret_addr))
    return direct_calls


def _candidate_is_filtered_8616(
    candidate: int,
    *,
    original_delta: int | None,
    local_ranges: list[tuple[int, int]],
    original_region: tuple[int, int] | None,
) -> bool:
    original_target = candidate + original_delta if isinstance(original_delta, int) else None
    if _addr_in_ranges(candidate, local_ranges):
        return True
    return bool(
        isinstance(original_target, int)
        and original_region is not None
        and original_region[0] <= original_target < original_region[1]
    )


def _seed_direct_callee_prototype_from_original_project_8616(
    project: angr.Project,
    stub: object,
    candidate: int,
) -> bool:
    """Seed a callee ABI from the full binary or an exact slice's source project."""
    # Dynamic exact-slice project extension boundary.
    original_project = getattr(project, "_inertia_original_project", None)
    if not isinstance(original_project, angr.Project):
        main_object = project.loader.main_object
        try:
            min_addr = main_object.min_addr
            max_addr = main_object.max_addr
        except AttributeError:
            return False
        if not min_addr <= candidate <= max_addr:
            return False
        return bool(seed_wide_stack_prototype_from_binary_address_8616(
            project,
            stub,
            stub,
            candidate,
        ))
    # Dynamic exact-slice project extension boundary.
    targets = _ordered_original_target_candidates_8616(project, candidate)
    original_object = original_project.loader.main_object
    original_min = original_object.min_addr
    original_max = original_object.max_addr
    for target in targets:
        if not original_min <= target <= original_max:
            continue
        original_function = original_project.kb.functions.function(addr=target, create=True)
        if original_function is None:
            continue
        if not seed_wide_stack_prototype_from_binary_address_8616(
            original_project,
            original_function,
            stub,
            target,
            target_project=project,
            target_address=candidate,
        ):
            continue
        return True
    return False


def _create_or_update_direct_call_stub_8616(
    *,
    project: angr.Project,
    function: Any,
    callsite_addr: int | None,
    ret_addr: int | None,
    candidate: int,
    preferred_candidate: int | None,
    fallback_call_name: str | None,
    debug_enabled: bool,
) -> bool:
    """Register one direct callee while preserving binary-proven helper identity."""

    def _impl() -> bool:
        try:
            helper_evidence = hook_x86_16_compiler_helper_at_8616(project, candidate)
            stub = project.kb.functions.function(addr=candidate, create=True)
            if stub is None:
                return False
            try:
                current_stub_name = stub.name
            except AttributeError:
                current_stub_name = None
            if isinstance(callsite_addr, int) and (preferred_candidate is None or candidate == preferred_candidate):
                with contextlib.suppress(Exception):
                    call_return = ret_addr
                    if not isinstance(call_return, int):
                        call_return = function.get_call_return(callsite_addr)
                    function._call_sites[callsite_addr] = (candidate, call_return)
            stub_name = helper_evidence.name if helper_evidence is not None else None
            if not isinstance(stub_name, str) or not stub_name:
                stub_name = _original_callee_name_8616(project, candidate)
            if not isinstance(stub_name, str) or not stub_name:
                stub_name = _compiler_helper_name_at_addr_8616(project, candidate)
            if (
                (not isinstance(stub_name, str) or not stub_name)
                and isinstance(fallback_call_name, str)
                and _call_name_matches_target_evidence_8616(project, candidate, fallback_call_name)
            ):
                stub_name = fallback_call_name
            if isinstance(stub_name, str) and stub_name:
                with contextlib.suppress(Exception):
                    stub.name = stub_name
                    current_stub_name = stub_name
            _seed_direct_callee_prototype_from_original_project_8616(
                project,
                stub,
                candidate,
            )
            if isinstance(callsite_addr, int) and (
                preferred_candidate is None or candidate == preferred_candidate
            ):
                seed_result = seed_physical_callsite_prototype_8616(
                    project,
                    function,
                    stub,
                    callsite_addr,
                )
                if debug_enabled and seed_result.decision is not CallsitePrototypeSeedDecision8616.NO_SUMMARY:
                    print(
                        f"[dbg] callsite-prototype-seed cs={callsite_addr:#x} "
                        f"target={candidate:#x} decision={seed_result.decision.value}",
                        file=sys.stderr,
                        flush=True,
                    )
            if not _is_known_noreturn_name_8616(current_stub_name):
                with contextlib.suppress(Exception):
                    stub.returning = True
            if _is_stack_probe_name_8616(current_stub_name):
                with contextlib.suppress(Exception):
                    stub.returning = True
            if debug_enabled and isinstance(callsite_addr, int):
                print(
                    f"[dbg] callsite-seed fn={function.addr:#x} cs={callsite_addr:#x} "
                    f"target={candidate:#x} preferred={preferred_candidate:#x} "
                    f"name={current_stub_name}",
                    file=sys.stderr,
                    flush=True,
                )
            return True
        except Exception as ex:
            try:
                function_addr = function.addr
            except AttributeError:
                function_addr = -1
            logging.getLogger(__name__).debug(
                "Stub creation failed at function=%#x stub=%#x: %s",
                function_addr or -1,
                candidate,
                ex,
            )
            return False

    return _impl()


def _record_direct_callsite_target_8616(
    function: object, callsite_addr: int | None, ret_addr: int | None, candidate: int
) -> bool:
    if not isinstance(callsite_addr, int):
        return False
    try:
        function_dynamic = cast(Any, function)
        call_return = ret_addr
        if not isinstance(call_return, int):
            call_return = function_dynamic.get_call_return(callsite_addr)
        function_dynamic._call_sites[callsite_addr] = (candidate, call_return)
        return True
    except Exception:
        return False


def _register_direct_call_target_function_stubs(
    project: angr.Project, function: object, cod_metadata: CODProcMetadata | None = None
) -> int:
    def _impl() -> int:
        if project.arch.name != "86_16":
            return 0
        measure_single_function_context = _single_function_context_measuring_enabled()
        metric_candidates = 0
        metric_start = time.perf_counter() if measure_single_function_context else 0.0
        main_object = project.loader.main_object
        linked_base = main_object.linked_base
        max_addr = main_object.max_addr
        image_end = linked_base + max_addr + 1 if isinstance(linked_base, int) and isinstance(max_addr, int) else None
        if os.environ.get("INERTIA_DEBUG_CALLSITE_SEEDING"):
            print(
                f"[dbg] callsite-seed-config fn={cast(Any, function).addr:#x} "
                f"entry={project.entry} "
                f"linked_base={linked_base} image_end={image_end}",
                file=sys.stderr,
                flush=True,
            )

        created = 0
        seen: set[int] = set()
        direct_calls = _collect_direct_calls_8616(project, function)
        local_ranges, original_region = _direct_call_stub_filter_regions(project, function)
        original_delta = getattr(project, "_inertia_original_linear_delta", None)
        for callsite_addr, target, ret_addr in direct_calls:
            if not isinstance(target, int):
                continue
            candidates = _compute_candidate_targets_8616(target, linked_base, image_end)
            preferred_candidate, fallback_call_name = _choose_preferred_candidate_8616(
                project, candidates, local_ranges, original_region, original_delta
            )

            if measure_single_function_context:
                metric_candidates += len(candidates)
            eligible_candidates = [
                candidate
                for candidate in sorted(candidates)
                if not _candidate_is_filtered_8616(
                    candidate,
                    original_delta=original_delta,
                    local_ranges=local_ranges,
                    original_region=original_region,
                )
            ]
            if preferred_candidate in seen:
                _record_direct_callsite_target_8616(function, callsite_addr, ret_addr, preferred_candidate)
            for candidate in eligible_candidates:
                if candidate in seen:
                    continue
                seen.add(candidate)
                if _create_or_update_direct_call_stub_8616(
                    project=project,
                    function=function,
                    callsite_addr=callsite_addr,
                    ret_addr=ret_addr,
                    candidate=candidate,
                    preferred_candidate=preferred_candidate,
                    fallback_call_name=fallback_call_name,
                    debug_enabled=bool(os.environ.get("INERTIA_DEBUG_CALLSITE_SEEDING")),
                ):
                    created += 1
        if measure_single_function_context:
            _emit_single_function_context_metric(
                function,
                kind="direct-callee-stubs",
                candidates=metric_candidates,
                created=created,
                elapsed_ms=int((time.perf_counter() - metric_start) * 1000),
            )
        return created

    return _impl()


def _single_function_context_measuring_enabled() -> bool:
    return os.environ.get("INERTIA_MEASURE_SINGLE_FUNCTION_CONTEXT", "").strip().lower() in {"1", "true", "yes", "on"}


def _emit_single_function_context_metric(
    function: object,
    *,
    kind: str,
    candidates: int = 0,
    created: int = 0,
    elapsed_ms: int = 0,
) -> None:
    if not _single_function_context_measuring_enabled():
        return
    print(
        f"[metric] fn={getattr(function, 'addr', -1):#x} kind={kind} "
        f"candidates={candidates} created={created} elapsed_ms={elapsed_ms}",
        file=sys.stderr,
        flush=True,
    )


def _prepare_function_for_decompilation(
    project: angr.Project,
    function: Any,
    cod_metadata: CODProcMetadata | None = None,
) -> int:
    def _attach_project_context_to_function_8616() -> None:
        """Attach CLI project context to an angr Function-like object."""
        # Dynamic angr Function compatibility boundary.
        current_project = getattr(function, "project", None)
        # Dynamic angr/project compatibility boundary.
        if current_project is not None and getattr(current_project, "_inertia_original_project", None) is not None:
            return
        with contextlib.suppress(Exception):
            # Dynamic angr Function compatibility boundary.
            function.project = project
        with contextlib.suppress(Exception):
            # Dynamic angr Function compatibility boundary.
            function._project = project

    def _emit_start_debug(display_addr_local: int) -> None:
        if display_addr_local == function.addr:
            print(
                f"[dbg] decompile_function: addr={display_addr_local:#x} name={function.name}",
                file=sys.stderr,
                flush=True,
            )
            return
        print(f"[dbg] decompile_function: addr={display_addr_local:#x} (slice={function.addr:#x}) name={function.name}")

    def _maybe_normalize_function() -> None:
        if function.normalized:
            return
        print(f"[dbg] function {function.addr:#x} not normalized, normalizing...", file=sys.stderr, flush=True)
        block_count = len(getattr(function, "block_addrs_set", ()) or ())
        normalize_budget = 2 if block_count <= 1 else 6
        try:
            typing.cast(typing.Any, project)._inertia_decompiler_stage = "prepare:normalize"
            with _analysis_timeout(normalize_budget):
                function.normalize()
            if os.environ.get("INERTIA_DEBUG_NORMALIZE_STAGE"):
                print(f"[dbg] normalized function {function.addr:#x} {function.name}", file=sys.stderr, flush=True)
        except _AnalysisTimeout:
            print(f"[dbg] normalize timeout for {function.addr:#x} {function.name}; continuing without normalized form")

    def _maybe_debug_blocks() -> None:
        if not os.environ.get("INERTIA_DEBUG_FUNCTION_BLOCKS"):
            return
        try:
            blocks = sorted(int(a) for a in (getattr(function, "block_addrs_set", ()) or ()) if isinstance(a, int))
            print(
                f"[dbg] function-blocks fn={function.addr:#x} count={len(blocks)} first={blocks[:8]}",
                file=sys.stderr,
                flush=True,
            )
        except Exception:
            pass

    def _maybe_debug_graph() -> None:
        if not os.environ.get("INERTIA_DEBUG_FUNCTION_GRAPH"):
            return
        try:
            graph = getattr(function, "graph", None)
            nodes = list(getattr(graph, "nodes", list)()) if graph is not None else []
            edges = list(getattr(graph, "edges", list)()) if graph is not None else []
            entry_nodes = [n for n in nodes if getattr(n, "addr", None) == function.addr]
            succ_addrs: list[int] = []
            if graph is not None and entry_nodes:
                for succ in graph.successors(entry_nodes[0]):
                    saddr = getattr(succ, "addr", None)
                    if isinstance(saddr, int):
                        succ_addrs.append(saddr)
            print(
                f"[dbg] function-graph fn={function.addr:#x} nodes={len(nodes)} edges={len(edges)} "
                f"entry_succ={sorted(set(succ_addrs))[:8]}",
                file=sys.stderr,
                flush=True,
            )
        except Exception:
            pass

    def _maybe_debug_callsite_returning() -> None:
        if not os.environ.get("INERTIA_DEBUG_CALLSITE_RETURNING"):
            return
        try:
            callsites = tuple(getattr(function, "get_call_sites", list)() or ())
            print(
                f"[dbg] callsite-returning fn={function.addr:#x} callsite_count={len(callsites)}",
                file=sys.stderr,
                flush=True,
            )
            for callsite in callsites:
                target = None
                ret_site = None
                with contextlib.suppress(Exception):
                    target = function.get_call_target(callsite)
                with contextlib.suppress(Exception):
                    ret_site = function.get_call_return(callsite)
                if not isinstance(target, int):
                    continue
                callee = None
                with contextlib.suppress(Exception):
                    callee = project.kb.functions.function(addr=target, create=False)
                returning = getattr(callee, "returning", None)
                hooked = project.is_hooked(target) if hasattr(project, "is_hooked") else None
                hook_no_ret = (
                    getattr(project.hooked_by(target), "NO_RET", None)
                    if hasattr(project, "is_hooked") and project.is_hooked(target)
                    else None
                )
                ret_text = f"{ret_site:#x}" if isinstance(ret_site, int) else "None"
                print(
                    f"[dbg] callsite-returning fn={function.addr:#x} cs={callsite:#x} "
                    f"target={target:#x} callee={getattr(callee, 'name', None)} "
                    f"ret={ret_text} returning={returning} hooked={hooked} hook_no_ret={hook_no_ret}",
                    file=sys.stderr,
                    flush=True,
                )
        except Exception:
            pass

    display_addr = function_original_addr(function)
    _attach_project_context_to_function_8616()
    _emit_start_debug(display_addr)
    sys.stdout.flush()
    typing.cast(typing.Any, project)._inertia_current_function_debug = {"addr": display_addr, "slice_addr": function.addr, "name": function.name}
    typing.cast(typing.Any, project)._inertia_current_decompile_function_8616 = function
    _maybe_normalize_function()
    sanitize_direct_call_sites_8616(function)
    created_helper_stubs = _register_direct_call_target_function_stubs(project, function, cod_metadata=cod_metadata)
    if created_helper_stubs:
        print(
            f"[dbg] registered {created_helper_stubs} direct callee stub(s) for {function.addr:#x}",
            file=sys.stderr,
            flush=True,
        )
    _maybe_debug_blocks()
    _maybe_debug_graph()
    _maybe_debug_callsite_returning()
    return created_helper_stubs


def _function_decompilation_profile(
    function: Any,
    block_count: int | None = None,
    byte_count: int | None = None,
) -> dict[str, int | bool]:
    def _impl() -> dict[str, int | bool]:
        nonlocal block_count, byte_count
        if block_count is None or byte_count is None:
            block_count, byte_count = _function_complexity(function)

        function_info = getattr(function, "info", None)
        if isinstance(function_info, MutableMapping):
            cached_profile = function_info.get("_inertia_function_decompilation_profile")
            if (
                isinstance(cached_profile, dict)
                and cached_profile.get("block_count") == block_count
                and cached_profile.get("byte_count") == byte_count
                and isinstance(cached_profile.get("call_site_count"), int)
                and isinstance(cached_profile.get("internal_call_count"), int)
            ):
                return dict(cached_profile)

        call_sites = ()
        if hasattr(function, "get_call_sites"):
            try:
                call_sites = tuple(function.get_call_sites())
            except Exception as ex:
                logging.getLogger(__name__).debug(
                    "Call-site enumeration failed at function=%#x stage=profile: %s",
                    getattr(function, "addr", -1) or -1,
                    ex,
                )
                call_sites = ()

        call_site_count = len(call_sites)
        project = getattr(function, "project", None)
        internal_call_count = 0
        stack_probe_call_count = 0
        has_non_wrapper_traffic = False
        local_blocks = getattr(function, "_local_blocks", None)
        direct_blocks = tuple(local_blocks.values()) if isinstance(local_blocks, Mapping) else tuple(getattr(function, "blocks", ()) or ())
        if project is not None:
            if direct_blocks:
                for block in direct_blocks:
                    capstone_block = getattr(block, "capstone", None)
                    for insn in tuple(getattr(capstone_block, "insns", ()) or ()):
                        mnemonic = getattr(insn, "mnemonic", "").lower()
                        op_str = getattr(insn, "op_str", "").lower()
                        if mnemonic == "call":
                            if _is_compiler_stack_probe_call_insn_8616(project, insn):
                                stack_probe_call_count += 1
                                continue
                            internal_call_count += 1
                        elif mnemonic.startswith("j") or ("[" in op_str and not any(marker in op_str for marker in ("[bp", "[sp", "[ss:"))):
                            has_non_wrapper_traffic = True
            else:
                for block_profile in _function_block_profile_cache_8616(function, project).values():
                    _, _, stack_probe_calls, internal_calls, block_non_wrapper_traffic = block_profile
                    stack_probe_call_count += stack_probe_calls
                    internal_call_count += internal_calls
                    has_non_wrapper_traffic = has_non_wrapper_traffic or block_non_wrapper_traffic
        semantic_call_site_count = max(0, call_site_count - stack_probe_call_count)

        wrapper_like = (
            block_count <= 2
            and byte_count <= 32
            and semantic_call_site_count <= 1
            and internal_call_count == 0
            and not has_non_wrapper_traffic
        )
        tiny_single_call_helper = (
            ((block_count <= 3 and byte_count <= 0x20) or (block_count <= 1 and byte_count <= 0x80))
            and semantic_call_site_count <= 1
            and internal_call_count <= 1
            and not has_non_wrapper_traffic
        )
        profile = {
            "block_count": block_count,
            "byte_count": byte_count,
            "call_site_count": semantic_call_site_count,
            "raw_call_site_count": call_site_count,
            "internal_call_count": internal_call_count,
            "stack_probe_call_count": stack_probe_call_count,
            "wrapper_like": wrapper_like,
            "tiny_single_call_helper": tiny_single_call_helper,
        }
        if isinstance(function_info, MutableMapping):
            function_info["_inertia_function_decompilation_profile"] = dict(profile)
        return profile

    return _impl()


def _profile_int_8616(profile: Mapping[str, object], key: str) -> int:
    """Return an integer profile counter from the CLI decompilation profile."""
    value = profile.get(key, 0)
    return value if type(value) is int else 0


def _is_compiler_stack_probe_call_insn_8616(project: angr.Project, insn: object) -> bool:
    target = _capstone_direct_target_8616(insn)
    if target is None:
        return False
    return _is_compiler_stack_probe_call_target_8616(project, target)


def _capstone_direct_target_8616(insn: object) -> int | None:
    operands = tuple(getattr(insn, "operands", ()) or ())
    if len(operands) != 1:
        return None
    operand = operands[0]
    if int(getattr(operand, "type", -1)) != 2:
        return None
    value = getattr(operand, "imm", None)
    return int(value) if isinstance(value, int) else None


_STACK_PROBE_CALL_TARGET_CACHE_8616: weakref.WeakKeyDictionary[angr.Project, dict[int, bool]] = weakref.WeakKeyDictionary()


def _is_compiler_stack_probe_call_target_8616(project: angr.Project, target: int) -> bool:
    """Memoize stack-probe helper classification per (project, target)."""
    if not isinstance(target, int):
        return False
    try:
        cache = _STACK_PROBE_CALL_TARGET_CACHE_8616.get(project)
    except TypeError:
        cache = {}
    else:
        if cache is None:
            cache = {}
            _STACK_PROBE_CALL_TARGET_CACHE_8616[project] = cache
    cached = cache.get(target)
    if cached is not None:
        return cached
    candidates = {target, target & 0xFFFF}
    original_target = _candidate_original_target_8616(project, target)
    if isinstance(original_target, int):
        candidates.add(original_target)
    original_project = getattr(project, "_inertia_original_project", None)
    for candidate in sorted(candidates):
        for candidate_project in (project, original_project):
            if candidate_project is None:
                continue
            evidence = identify_x86_16_compiler_helper_at_8616(candidate_project, candidate)
            if evidence is not None and evidence.kind is CompilerHelperEvidenceKind8616.STACK_PROBE:
                cache[target] = True
                return True
    cache[target] = False
    return False


def _function_block_profile_cache_8616(
    function: Any,
    project: angr.Project,
) -> dict[int, tuple[int, int, int, int, bool]]:
    """Cache low-cost project-decoded block facts for this function.

    The cache stores immutable tuples keyed by block address and reused by both
    complexity and profile calculations when block decoding is needed from
    ``block_addrs_set``.
    """
    function_info = getattr(function, "info", None)
    block_addrs: tuple[int, ...] = tuple(sorted(getattr(function, "block_addrs_set", set()) or ()))
    if isinstance(function_info, MutableMapping):
        cached = function_info.get("_inertia_function_block_profile_cache_8616")
        if isinstance(cached, Mapping):
            cached_block_addrs = tuple(cached.get("block_addrs", ()))
            cached_project_id = cached.get("project_id", None)
            if cached_project_id == id(project) and cached_block_addrs == block_addrs:
                cached_profiles = cached.get("profiles")
                if isinstance(cached_profiles, Mapping):
                    prepared_cache: dict[int, tuple[int, int, int, int, bool]] = {}
                    valid = True
                    for addr in block_addrs:
                        candidate = cached_profiles.get(addr)
                        if (
                            isinstance(candidate, tuple)
                            and len(candidate) == 5
                            and isinstance(candidate[0], int)
                            and isinstance(candidate[1], int)
                            and isinstance(candidate[2], int)
                            and isinstance(candidate[3], int)
                            and isinstance(candidate[4], bool)
                        ):
                            prepared_cache[addr] = (
                                candidate[0],
                                candidate[1],
                                candidate[2],
                                candidate[3],
                                candidate[4],
                            )
                            continue
                        valid = False
                        break
                    if valid:
                        return prepared_cache
    profiles: dict[int, tuple[int, int, int, int, bool]] = {}
    for block_addr in block_addrs:
        try:
            block = project.factory.block(block_addr, opt_level=0)
        except Exception as ex:
            logging.getLogger(__name__).debug(
                "Profile block decode failed at function=%#x block=%#x: %s",
                getattr(function, "addr", -1) or -1,
                block_addr,
                ex,
            )
            profiles[block_addr] = (0, 0, 0, 0, False)
            continue

        block_bytes = len(getattr(block, "bytes", b"") or b"")
        block_call_sites = 0
        stack_probe_calls = 0
        internal_calls = 0
        block_non_wrapper_traffic = False
        for insn in tuple(getattr(getattr(block, "capstone", None), "insns", ()) or ()):
            mnemonic = getattr(insn, "mnemonic", "").lower()
            op_str = getattr(insn, "op_str", "").lower()
            if mnemonic == "call":
                block_call_sites += 1
                if _is_compiler_stack_probe_call_insn_8616(project, insn):
                    stack_probe_calls += 1
                    continue
                internal_calls += 1
            elif mnemonic.startswith("j") or ("[" in op_str and not any(marker in op_str for marker in ("[bp", "[sp", "[ss:"))):
                block_non_wrapper_traffic = True
        profiles[block_addr] = (
            block_bytes,
            block_call_sites,
            stack_probe_calls,
            internal_calls,
            block_non_wrapper_traffic,
        )
    if isinstance(function_info, MutableMapping):
        function_info["_inertia_function_block_profile_cache_8616"] = {
            "project_id": id(project),
            "block_addrs": block_addrs,
            "profiles": dict(profiles),
        }
    return profiles


def _preferred_decompiler_options(
    block_count: int,
    byte_count: int,
    *,
    wrapper_like: bool = False,
    tiny_single_call_helper: bool = False,
    no_call_helper: bool = False,
    disable_dead_memdefs: bool = False,
    large_16bit_function: bool = False,
) -> list[tuple[str, object]] | None:
    """Choose a cheaper decompiler structurer for true wrapper-like functions."""
    if wrapper_like or tiny_single_call_helper:
        return [("structurer_cls", "Phoenix")]
    if no_call_helper:
        return [
            ("structurer_cls", "Phoenix"),
            ("rewrite_ites_to_diamonds", False),
            ("semvar_naming", False),
            ("remove_dead_memdefs", False),
        ]
    if large_16bit_function:
        return [
            ("rewrite_ites_to_diamonds", False),
            ("semvar_naming", False),
            ("remove_dead_memdefs", False),
        ]
    if disable_dead_memdefs:
        return [
            ("remove_dead_memdefs", False),
        ]
    return None


def _preferred_expr_collapse_depth(
    block_count: int,
    byte_count: int,
    *,
    wrapper_like: bool = False,
    tiny_single_call_helper: bool = False,
) -> int:
    if block_count <= 1 and byte_count <= 96:
        return 2
    if wrapper_like or tiny_single_call_helper:
        return 2
    if block_count <= 24 and byte_count <= 256:
        return 32
    if block_count <= 64 and byte_count <= 1024:
        return 24
    return 16


@cast(Callable[..., Any], trace_function(name="function.decompile_with_stats"))
def _decompile_function_with_stats(
    project: angr.Project,
    cfg: Any,
    function: Any,
    timeout: int,
    api_style: str,
    binary_path: Path | None = None,
    cod_metadata: CODProcMetadata | None = None,
    synthetic_globals: dict[int, tuple[str, int]] | None = None,
    lst_metadata: LSTMetadata | None = None,
    enable_structured_simplify: bool = True,
    enable_postprocess: bool = True,
    allow_isolated_retry: bool = True,
    failure_family_state: FailureFamilyState | None = None,
) -> tuple[str, str, str | None, int, int, float]:
    block_count, byte_count = _function_complexity(function)
    effective_timeout = _effective_decompile_timeout_8616(
        project,
        timeout,
        block_count=block_count,
        byte_count=byte_count,
    )
    display_addr = function_original_addr(function)
    annotate_current_span(
        blocks=block_count,
        bytes=byte_count,
    )
    print(
        f"[dbg] function complexity for {display_addr:#x} {function.name}: blocks={block_count}, bytes={byte_count}",
        file=sys.stderr,
        flush=True,
    )
    sys.stdout.flush()
    start = time.perf_counter()
    deadline = time.monotonic() + max(1, effective_timeout)
    try:
        status, payload = _decompile_function(
            project,
            cfg,
            function,
            effective_timeout,
            api_style,
            binary_path,
            cod_metadata=cod_metadata,
            synthetic_globals=synthetic_globals,
            lst_metadata=lst_metadata,
            enable_structured_simplify=enable_structured_simplify,
            enable_postprocess=enable_postprocess,
            allow_isolated_retry=allow_isolated_retry,
            deadline=deadline,
            failure_family_state=failure_family_state,
        )
    except PipelineHardError as ex:
        # Keep whole-binary sweeps alive: pipeline contract violations are
        # per-function validation failures and must not abort the entire run.
        status = "validation_failed"
        detail = str(ex)
        if detail.startswith("function leaked unresolved stack locals into final C"):
            detail = f"{function.name} leaked unresolved stack locals into final C"
        payload = f"Pipeline contract violation: {detail}"
    forced_payload = _forced_function_template(getattr(function, "name", None), binary_path, api_style)
    if forced_payload is not None:
        status = "ok"
        payload = forced_payload
    validated_payload_record = getattr(project, "_inertia_last_validated_function_payload", None)
    if os.environ.get("INERTIA_DEBUG_RETURN_BRANCH"):
        logging.getLogger(__name__).warning(
            "[return-chain-cli] with-stats status=%s payload_len=%d record=%s payload=%r",
            status,
            len(payload) if isinstance(payload, str) else 0,
            (
                (validated_payload_record[0], len(validated_payload_record[1]))
                if isinstance(validated_payload_record, tuple)
                and len(validated_payload_record) == 2
                and isinstance(validated_payload_record[1], str)
                else None
            ),
            payload,
        )
    if status == "ok" and isinstance(validated_payload_record, tuple) and len(validated_payload_record) == 2:
        validated_addr, validated_payload = validated_payload_record
        if (
            validated_addr == function_original_addr(function)
            and isinstance(validated_payload, str)
            and validated_payload.strip()
        ):
            replacement_cod_metadata = cod_metadata or _sidecar_cod_metadata_for_function(
                project,
                function,
                binary_path,
                lst_metadata,
            )
            replacement_evidence = _validated_payload_replacement_evidence_8616(
                payload if isinstance(payload, str) else "",
                validated_payload,
                replacement_cod_metadata,
            )
            replacement_decision = replacement_evidence.decision
            if replacement_decision is ValidatedPayloadReplacementDecision8616.REJECT_WORSE_CALL_EVIDENCE:
                logging.getLogger(__name__).warning(
                    "Rejected validated codegen artifact replacement with worse call evidence at function=%#x current_score=%r validated_score=%r",
                    function_original_addr(function),
                    replacement_evidence.current_call_score,
                    replacement_evidence.validated_call_score,
                )
            elif replacement_decision is ValidatedPayloadReplacementDecision8616.REJECT_WORSE_LOOP_EVIDENCE:
                logging.getLogger(__name__).warning(
                    "Rejected validated codegen artifact replacement with worse loop evidence at function=%#x current_loop_score=%d validated_loop_score=%d",
                    function_original_addr(function),
                    replacement_evidence.current_loop_score,
                    replacement_evidence.validated_loop_score,
                )
            elif payload != validated_payload:
                tail_snapshot = getattr(project, "_inertia_last_validated_function_payload_snapshot", None)
                if not isinstance(tail_snapshot, dict):
                    tail_snapshot = getattr(project, "_inertia_last_tail_validation_snapshot", None)
                tail_validation_passed = not _tail_validation_runtime_enabled(
                    project
                ) or x86_16_tail_validation_snapshot_passed(tail_snapshot)
                if tail_validation_passed and _validated_payload_replacement_recompiles_8616(validated_payload):
                    logging.getLogger(__name__).warning(
                        "Using validated codegen artifact replacement at function=%#x current_len=%d validated_len=%d",
                        function_original_addr(function),
                        len(payload) if isinstance(payload, str) else 0,
                        len(validated_payload),
                    )
                    payload = validated_payload
                elif tail_validation_passed:
                    replacement_decision = ValidatedPayloadReplacementDecision8616.REJECT_FAILED_RECOMPILE
                    logging.getLogger(__name__).warning(
                        "Rejected validated codegen artifact replacement due to failed recompile at function=%#x current_len=%d validated_len=%d",
                        function_original_addr(function),
                        len(payload) if isinstance(payload, str) else 0,
                        len(validated_payload),
                    )
                else:
                    replacement_decision = ValidatedPayloadReplacementDecision8616.REJECT_FAILED_TAIL_SNAPSHOT
                    logging.getLogger(__name__).warning(
                        "Rejected validated codegen artifact replacement due to failed tail snapshot at function=%#x current_len=%d validated_len=%d",
                        function_original_addr(function),
                        len(payload) if isinstance(payload, str) else 0,
                        len(validated_payload),
                    )
            else:
                payload = validated_payload
            typing.cast(typing.Any, project)._inertia_validated_payload_replacement_decision_8616 = replacement_decision
    partial_payload = getattr(project, "_inertia_partial_codegen_text", None)
    elapsed = time.perf_counter() - start
    annotate_current_span(status=status, elapsed_ms=round(elapsed * 1000.0, 1))
    advance_failure_family_state(failure_family_state)
    if _timing_output_enabled():
        print(
            f"[dbg] decompilation time for {display_addr:#x} {function.name}: {elapsed:.2f}s",
            file=sys.stderr,
            flush=True,
        )
        sys.stdout.flush()
    return status, payload, partial_payload, block_count, byte_count, elapsed
