#!/usr/bin/env python3
"""Curated fast/default/expanded decompiler regression pipeline.

Layer: Tooling/gates.
Responsibility: run curated fast/default/expanded decompiler regression tiers.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import cast

REPO_ROOT: Path = Path(__file__).resolve().parents[1]
DEFAULT_OUT: Path = REPO_ROOT / "angr_platforms" / ".cache" / "test_pipeline" / "summary.json"
DEFAULT_KVIKDOS: Path = Path("/home/xor/kvikdos/kvikdos")
DEFAULT_MSC6_ROOT: Path = Path("/home/xor/inertia_player/dos_compilers/Microsoft C v6ax")
DEFAULT_ULTRA_QUICKC_ROOT: Path = REPO_ROOT / "borrow" / "UltraDecompiler" / "QuickC"

FOCUSED_PYTEST_TARGETS: tuple[str, ...] = (
    "angr_platforms/tests/test_x86_16_flags_physical_register_contract.py",
    "angr_platforms/tests/test_x86_16_packed_flags_state.py",
    "angr_platforms/tests/test_x86_16_stored_call_result_assignments.py",
    "angr_platforms/tests/test_x86_16_stored_call_result_definitions.py",
    "angr_platforms/tests/test_x86_16_validation_branch_conditions.py",
    "angr_platforms/tests/test_x86_16_validation_additive_semantic_casts.py",
    "angr_platforms/tests/test_x86_16_ir_memory_call_liveness.py",
    "angr_platforms/tests/test_x86_16_tail_callsite_inventory.py",
    "angr_platforms/tests/test_x86_16_segment_program_layout.py",
    "angr_platforms/tests/test_x86_16_register_source_wide_clobbers.py",
    "angr_platforms/tests/test_x86_16_register_entry_overwrite.py",
    "angr_platforms/tests/test_x86_16_consumed_stack_address_setup.py",
    "angr_platforms/tests/test_x86_16_register_source_memory_dependencies.py",
    "angr_platforms/tests/test_accepted_payload_integrity.py",
    "angr_platforms/tests/test_x86_16_callsite_return_use_zero_idiom.py",
    "angr_platforms/tests/test_x86_16_gp_partial_live_in.py",
    "angr_platforms/tests/test_x86_16_smoketest.py",
    "angr_platforms/tests/test_build_msc6_examples.py",
    "angr_platforms/tests/test_msc6_toolchain_lock.py",
    "angr_platforms/tests/test_check_changed_non_test_types.py",
    "angr_platforms/tests/test_import_ultra_quickc_fixtures.py",
    "angr_platforms/tests/test_generated_c_indexed_argument_contract.py",
    "angr_platforms/tests/test_omf_pat_lidata.py",
    "angr_platforms/tests/test_test_pipeline.py",
    "angr_platforms/tests/test_make_linter_inputs.py",
    "angr_platforms/tests/test_check_sortd_sidecar_free.py",
    "angr_platforms/tests/test_compare_ghidra_function_coverage.py",
    "angr_platforms/tests/test_generated_c_artifacts.py",
    "angr_platforms/tests/test_generated_translation_unit_assembly.py",
    "angr_platforms/tests/test_generated_translation_unit_gate.py",
    "angr_platforms/tests/test_cli_direct_argument_evidence_context.py",
    "angr_platforms/tests/test_x86_16_corpus_scan_timeout.py",
    "angr_platforms/tests/test_decompilation_quality.py",
    "angr_platforms/tests/test_cli_regeneration.py",
    "angr_platforms/tests/test_x86_16_alias_register_mvp.py",
    "angr_platforms/tests/test_x86_16_callsite_replay_safety.py",
    "angr_platforms/tests/test_x86_16_function_callsite_inventory.py",
    "angr_platforms/tests/test_x86_16_decompiler_postprocess_callsites.py",
    "angr_platforms/tests/test_x86_16_protected_call_arguments.py",
    "angr_platforms/tests/test_x86_16_call_argument_expression.py",
    "angr_platforms/tests/test_x86_16_condition_lowering.py",
    "angr_platforms/tests/test_x86_16_condition_register_carriers.py",
    "angr_platforms/tests/test_x86_16_condition_cache_relift.py",
    "angr_platforms/tests/test_x86_16_condition_lift_capture.py",
    "angr_platforms/tests/test_x86_16_status_flag_lift_context.py",
    "angr_platforms/tests/test_x86_16_function_condition_artifact.py",
    "angr_platforms/tests/test_x86_16_condition_transfer.py",
    "angr_platforms/tests/test_x86_16_frontend_condition_evidence.py",
    "angr_platforms/tests/test_x86_16_frontend_function_boundary_index.py",
    "angr_platforms/tests/test_x86_16_frontend_instruction_reachability.py",
    "angr_platforms/tests/test_x86_16_status_flag_cfg_liveness.py",
    "angr_platforms/tests/test_x86_16_status_flag_cfg_projection.py",
    "angr_platforms/tests/test_x86_16_typed_switch_seqnode.py",
    "angr_platforms/tests/test_x86_16_dead_local_structured_reads.py",
    "angr_platforms/tests/test_x86_16_stack_aggregate_coordinate_replay.py",
    "angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_runmenu_sidecar_free_preserves_binary_escape_exit",
    "angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_initmenu_pause_zero_guard_has_no_raw_flag_carrier",
    "angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_sidecar_free_initbars_preserves_binary_stack_array",
    "angr_platforms/tests/test_x86_16_decompiler_postprocess_typed_conditions.py",
    "angr_platforms/tests/test_x86_16_decompiler_postprocess_jcc.py",
    "angr_platforms/tests/test_x86_16_positive_bp_argument_plan.py",
    "angr_platforms/tests/test_x86_16_stack_lowering_contracts.py",
    "angr_platforms/tests/test_x86_16_stack_declaration_identity.py",
    "angr_platforms/tests/test_x86_16_stack_memory_ssa_lowering.py",
    "angr_platforms/tests/test_x86_16_stack_memory_ssa_safety.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_consumers.py",
    "angr_platforms/tests/test_x86_16_function_ssa_registry.py",
    "angr_platforms/tests/test_x86_16_call_stack_effects.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_live_out.py",
    "angr_platforms/tests/test_x86_16_terminal_memory_output_aliases.py",
    "angr_platforms/tests/test_x86_16_terminal_memory_output_views.py",
    "angr_platforms/tests/test_x86_16_terminal_pointer_outputs.py",
    "angr_platforms/tests/test_x86_16_terminal_pointer_output_aliases.py::"
    "test_every_store_site_binds_to_one_exact_positive_bp_parameter",
    "angr_platforms/tests/test_x86_16_terminal_pointer_output_aliases.py::"
    "test_unknown_or_non_parameter_source_refuses_atomically",
    "angr_platforms/tests/test_x86_16_terminal_pointer_output_aliases.py::"
    "test_competing_parameter_sources_refuse_without_partial_fact",
    "angr_platforms/tests/test_x86_16_terminal_pointer_output_views.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_pipeline.py",
    "angr_platforms/tests/test_x86_16_interprocedural_memory_output_objects.py",
    "angr_platforms/tests/test_x86_16_interprocedural_memory_output_validation.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_expression_defs.py",
    "angr_platforms/tests/test_x86_16_scalar_affine_trace.py",
    "angr_platforms/tests/test_x86_16_pointer_parameter_memory_outputs.py",
    "angr_platforms/tests/test_x86_16_pointer_parameter_object_types.py",
    "angr_platforms/tests/test_x86_16_pointer_parameter_output_pipeline.py",
    "angr_platforms/tests/test_x86_16_direct_stack_replay.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_slot_join.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_prototype_application.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_reaching_defs.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_return_passthrough.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_return_trial_collection.py",
    "angr_platforms/tests/test_x86_16_return_witness_addresses.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_simtypes.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_trial_collection.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_trials.py",
    "angr_platforms/tests/test_x86_16_unused_void_return_types.py",
    "angr_platforms/tests/test_x86_16_return_liveness_replay.py",
    "angr_platforms/tests/test_x86_16_alu_helpers.py",
    "angr_platforms/tests/test_x86_16_object_lowering.py",
    "angr_platforms/tests/test_x86_16_semantics_alias_query.py",
    "angr_platforms/tests/test_x86_16_semantics_expression_analysis.py",
    "angr_platforms/tests/test_x86_16_stack_frame_recovery.py",
    "angr_platforms/tests/test_x86_16_validation_canonicalize.py",
    "angr_platforms/tests/test_x86_16_validation_call_argument_sources.py",
    "angr_platforms/tests/test_x86_16_validation_calls.py",
    "angr_platforms/tests/test_x86_16_package_exports.py",
    "angr_platforms/tests/test_x86_16_bootstrap_import_order.py",
    "angr_platforms/tests/test_x86_16_pipeline_contracts.py",
    "angr_platforms/tests/test_x86_16_rewrite_boundary.py",
    "angr_platforms/tests/test_x86_16_array_matching.py",
    "angr_platforms/tests/test_x86_16_struct_merging.py",
    "angr_platforms/tests/test_x86_16_structuring_condition_materialization.py",
    "angr_platforms/tests/test_x86_16_condition_chain_refusal.py",
    "angr_platforms/tests/test_x86_16_recorded_return_argument_replay.py",
    "angr_platforms/tests/test_x86_16_stack_reload_instruction_ownership.py",
    "angr_platforms/tests/test_x86_16_runtime_call_results.py",
    "angr_platforms/tests/test_x86_16_runtime_memory_helpers.py",
    "angr_platforms/tests/test_x86_16_indexed_stack_ranges.py",
    "angr_platforms/tests/test_x86_16_indexed_stack_frame_terms.py",
    "angr_platforms/tests/test_x86_16_call_output_object_projection.py",
    "angr_platforms/tests/test_x86_16_condition_exit_normalization.py",
    "angr_platforms/tests/test_x86_16_structuring_multi_arm_condition_ownership.py",
    "angr_platforms/tests/test_x86_16_structuring_loop_body_repair.py",
    "angr_platforms/tests/test_x86_16_dce_optimization.py",
    "angr_platforms/tests/test_x86_16_trivial_copy_optimization.py",
    "angr_platforms/tests/test_x86_16_widening_copyprop.py",
    "angr_platforms/tests/test_x86_16_widening_copyprop_width.py",
    "angr_platforms/tests/test_x86_16_linear_global_decomposition_cache.py",
    "angr_platforms/tests/test_x86_16_widening_memory_fold.py",
    "angr_platforms/tests/test_x86_16_stack_subview_call_writes.py",
    "angr_platforms/tests/test_x86_16_stack_subview_projection.py",
    "angr_platforms/tests/test_x86_16_stack_subview_coordinates.py",
    "angr_platforms/tests/test_x86_16_machine_stack_names.py",
    "angr_platforms/tests/test_structured_simplifier_identity.py",
    "angr_platforms/tests/test_x86_16_stack_subview_projection_wide.py",
    "angr_platforms/tests/test_x86_16_widening_rules.py",
    "angr_platforms/tests/test_x86_16_generated_c_acceptance.py",
    "angr_platforms/tests/test_x86_16_sortdemo_decompiler_status.py",
    "angr_platforms/tests/test_x86_16_segment_access_policy.py",
    "angr_platforms/tests/test_x86_16_segment_address_policy.py",
    "angr_platforms/tests/test_x86_16_segment_state.py",
    "angr_platforms/tests/test_x86_16_segment_stack_restore.py",
    "angr_platforms/tests/test_segment_register_membership.py",
    "angr_platforms/tests/test_x86_16_vex_import.py",
    "angr_platforms/tests/test_x86_16_vex_integer_displacement.py",
    "angr_platforms/tests/test_x86_16_vex_bit_source.py",
    "angr_platforms/tests/test_x86_16_vex_import_cfg_successors.py",
    "angr_platforms/tests/test_x86_16_indexed_address_aliases.py",
    "angr_platforms/tests/test_x86_16_indexed_address_collector_parity.py",
    "angr_platforms/tests/test_x86_16_indexed_address_parity_inventory.py",
    "angr_platforms/tests/test_x86_16_sortd_indexed_address_parity_inventory.py",
    "angr_platforms/tests/test_x86_16_indexed_address_evidence.py",
    "angr_platforms/tests/test_x86_16_indexed_address_range_candidates.py",
    "angr_platforms/tests/test_x86_16_indexed_global_object_program_ranges.py",
    "angr_platforms/tests/test_x86_16_indexed_global_object_ranges.py",
    "angr_platforms/tests/test_x86_16_bounded_global_array_declarations.py",
    "angr_platforms/tests/test_x86_16_sortd_indexed_loop_topology.py",
    "angr_platforms/tests/test_x86_16_ssa_cfg.py",
    "angr_platforms/tests/test_x86_16_logical_memory_write_value.py",
    "angr_platforms/tests/test_x86_16_cod_global_identity.py",
    "angr_platforms/tests/test_x86_16_cod_module_caller_evidence.py",
    "angr_platforms/tests/test_x86_16_segmented_global_loads.py",
    "angr_platforms/tests/test_x86_16_segmented_lowering.py",
    "angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py",
    "angr_platforms/tests/test_x86_16_ir_segmented_load_carriers.py",
    "angr_platforms/tests/test_x86_16_reload_provenance_boundaries.py",
    "angr_platforms/tests/test_x86_16_postprocess_pass_transaction.py",
    "angr_platforms/tests/test_x86_16_postprocess_runtime_config.py",
    "angr_platforms/tests/test_x86_16_pointer_store_fold_safety.py",
    "angr_platforms/tests/test_generic_annotation_contracts.py",
    "angr_platforms/tests/test_access_trait_runtime_factory.py",
    "angr_platforms/tests/test_frame_carrier_type_contracts.py",
    "angr_platforms/tests/test_makefile_inventory.py",
    "angr_platforms/tests/test_mypy_import_contracts.py",
    "angr_platforms/tests/test_x86_16_layer_boundaries.py::"
    "test_quality_and_diagnostics_modules_are_wired_into_production_paths",
    "angr_platforms/tests/test_x86_16_layer_boundaries.py::"
    "test_layer_module_admission_status_matches_production_imports",
    "angr_platforms/tests/test_x86_16_layer_boundaries.py::"
    "test_quality_compatibility_exports_retain_canonical_identity",
    "angr_platforms/tests/test_x86_16_alu_effect_order.py",
    "angr_platforms/tests/test_x86_16_carry_predicate_execution.py",
    "angr_platforms/tests/test_x86_16_msc_caller_cleanup.py",
    "angr_platforms/tests/test_x86_16_segment_call_effects.py",
    "angr_platforms/tests/test_x86_16_native_segment_live_out.py",
    "angr_platforms/tests/test_x86_16_anonymous_store_width.py",
    "angr_platforms/tests/test_x86_16_decompiler_postprocess_calls.py::"
    "test_materialize_callsite_stack_arguments_requires_exact_consumed_push_evidence",
    "angr_platforms/tests/test_x86_16_decompiler_postprocess_calls.py::"
    "test_materialize_callsite_stack_arguments_keeps_unproven_far_pointer_stores",
    "angr_platforms/tests/test_x86_16_decompiler_postprocess_calls.py::"
    "test_materialize_callsite_stack_arguments_keeps_unproven_scalar_byte_pair_stores",
    "angr_platforms/tests/test_x86_16_simple_incdec_value_provenance.py",
    "angr_platforms/tests/test_x86_16_concrete_loop_conditions.py",
    "angr_platforms/tests/test_x86_16_lifting_opcode_tables.py",
    "angr_platforms/tests/test_x86_16_callsite_completeness_validation.py",
    "angr_platforms/tests/test_x86_16_cod_regressions.py::test_cod_dos_loadprogram_wrapper_keeps_err_guard_and_segment_stores",
    "angr_platforms/tests/test_cod_openfilewrapper_consolidation.py",
    "angr_platforms/tests/test_x86_16_near_pointer_argument_evidence.py",
    "angr_platforms/tests/test_project_loading_diagnostics.py",
    "angr_platforms/tests/test_cli_interrupt_call_boundary.py",
    "angr_platforms/tests/test_x86_16_annotation_argument_identity.py",
    "angr_platforms/tests/test_x86_16_assignment_lvalue_casts.py",
    "angr_platforms/tests/test_x86_16_stack_byte_writes.py",
    "angr_platforms/tests/test_x86_16_instruction_stack_write_width.py",
    "angr_platforms/tests/test_x86_16_semantic_cast.py",
    "angr_platforms/tests/test_x86_16_direct_stack_access_widths.py",
    "angr_platforms/tests/test_x86_16_stack_address_coordinates.py",
    "angr_platforms/tests/test_x86_16_native_stack_anchor.py",
    "angr_platforms/tests/test_x86_16_runtime_push_carrier.py",
    "angr_platforms/tests/test_x86_16_storage_prototype_snapshot.py",
    "angr_platforms/tests/test_x86_16_frame_prologue_carriers.py",
    "angr_platforms/tests/test_x86_16_frame_byte_carriers.py",
    "angr_platforms/tests/test_x86_16_frame_carrier_liveness.py",
    "angr_platforms/tests/test_x86_16_call_execution_frame_carriers.py",
    "angr_platforms/tests/test_x86_16_call_frame_base_effects.py",
    "angr_platforms/tests/test_x86_16_unobserved_return_maker.py",
    "angr_platforms/tests/test_x86_16_dosfunc_behavior.py",
    "angr_platforms/tests/test_x86_16_address_base_snapshots.py",
    "angr_platforms/tests/test_x86_16_memory_ssa_address_provenance.py",
    "angr_platforms/tests/test_x86_16_ir_stack_frame.py",
    "angr_platforms/tests/test_x86_16_vex_memory_access_fidelity.py",
    "angr_platforms/tests/test_makefile_quiet_output.py",
    "angr_platforms/tests/test_x86_16_canonical_frame_setup_carriers.py",
    "angr_platforms/tests/test_x86_16_stack_compat.py",
    "angr_platforms/tests/test_x86_16_stack_address_operand_roles.py",
    "angr_platforms/tests/test_x86_16_numeric_sp_call_return.py",
    "angr_platforms/tests/test_x86_16_call_frame_compat.py",
    "angr_platforms/tests/test_x86_16_callee_cleanup_compat.py",
    "angr_platforms/tests/test_x86_16_stack_pointer_provenance.py",
    "angr_platforms/tests/test_x86_16_ail_register_displacement.py",
    "angr_platforms/tests/test_x86_16_call_return_segment.py",
    "angr_platforms/tests/test_x86_16_stack_pointer_width.py",
    "angr_platforms/tests/test_x86_16_lifted_integer_constants.py",
    "angr_platforms/tests/test_x86_16_codegen_parentheses.py",
    "angr_platforms/tests/test_x86_16_telemetry_support.py",
    "angr_platforms/tests/test_x86_16_codegen_metadata.py",
    "angr_platforms/tests/test_x86_16_call_argument_shape_publication.py",
    "angr_platforms/tests/test_x86_16_instruction_bp_stack_access_index.py",
    "angr_platforms/tests/test_x86_16_direct_stack_move_loop_entries.py",
    "angr_platforms/tests/test_x86_16_direct_stack_move_pretest_body.py",
    "angr_platforms/tests/test_x86_16_direct_stack_move_pretest_initializers.py",
    "angr_platforms/tests/test_x86_16_stack_probe_local_preservation.py",
    "angr_platforms/tests/test_x86_16_casted_loop_induction.py",
    "angr_platforms/tests/test_x86_16_decompilation_cache_surface.py",
    "angr_platforms/tests/test_x86_16_return_compat_counters.py",
    "angr_platforms/tests/test_x86_16_return_expression_preservation.py",
    "angr_platforms/tests/test_x86_16_return_stack_address_compat.py",
    "angr_platforms/tests/test_x86_16_helper_abi.py",
    "angr_platforms/tests/test_x86_16_fixed_stack_probe_frames.py",
    "angr_platforms/tests/test_x86_16_structuring_pass_validation.py",
    "angr_platforms/tests/test_x86_16_symbolic_value_boundaries.py",
    "angr_platforms/tests/test_x86_16_direction_flag_execution.py",
    "angr_platforms/tests/test_x86_16_stack_helpers.py",
    "angr_platforms/tests/test_x86_16_memory.py",
)

MSC6_TINY_CONSTRUCTS: tuple[str, ...] = (
    "compare16",
    "simple_control",
    "loops_jumps",
    "storage_classes",
    "function_pointers",
    "pointer_memory",
    "scalar_types_io",
)
MSC6_TINY_SMOKE_CONSTRUCTS: tuple[str, ...] = ("storage_classes",)
MSC6_TINY_NEXT_CONSTRUCTS: tuple[str, ...] = ()

LANE_BUDGET_SECONDS: dict[str, float] = {
    "unit-focused": 30.0,
    "msc6-tiny-smoke": 90.0,
    "msc6-tiny-full-pipeline": 300.0,
    "ultra-quickc-fixtures": 180.0,
    "sortdemo-status": 2460.0,
    "sortdemo-status-proc-diagnostic": 2460.0,
    "sortd-sidecar-free": 1200.0,
    "sortd-generated-sort-core": 60.0,
    "sortd-generated-translation-unit": 60.0,
}

PIPELINE_TIERS: dict[str, tuple[str, ...]] = {
    "fast": ("unit-focused",),
    "default": ("unit-focused", "ultra-quickc-fixtures", "msc6-tiny-full-pipeline"),
    "expanded": (
        "unit-focused",
        "ultra-quickc-fixtures",
        "msc6-tiny-full-pipeline",
        "sortd-sidecar-free",
        "sortdemo-status",
    ),
}


class LaneStatus(StrEnum):
    """Structured terminal status for one curated pipeline lane."""

    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMED_OUT = "timed_out"


class BudgetStatus(StrEnum):
    """Structured runtime-budget verdict for a completed lane."""

    PASSED = "passed"
    OVER_BUDGET = "over_budget"


@dataclass(frozen=True, slots=True)
class LaneResult:
    """Serializable result contract for one curated pipeline lane."""

    name: str
    status: LaneStatus
    command: list[str]
    elapsed_seconds: float
    returncode: int | None = None
    reason: str | None = None
    budget_seconds: float | None = None
    budget_status: BudgetStatus | None = None
    children: list[dict[str, object]] | None = None
    details: dict[str, object] | None = None


def _budget_status(name: str, elapsed_seconds: float) -> tuple[float | None, BudgetStatus | None]:
    budget = LANE_BUDGET_SECONDS.get(name)
    if budget is None:
        return None, None
    return budget, BudgetStatus.PASSED if elapsed_seconds <= budget else BudgetStatus.OVER_BUDGET


def _run_command(name: str, cmd: list[str], *, env: dict[str, str] | None = None) -> LaneResult:
    start = time.monotonic()
    try:
        completed = subprocess.run(cmd, cwd=REPO_ROOT, env=env, check=False)
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - start
        rounded_elapsed = round(elapsed, 3)
        budget, budget_status = _budget_status(name, rounded_elapsed)
        return LaneResult(
            name=name,
            status=LaneStatus.TIMED_OUT,
            command=cmd,
            elapsed_seconds=rounded_elapsed,
            returncode=None,
            reason=f"timed out after {exc.timeout} seconds",
            budget_seconds=budget,
            budget_status=budget_status,
        )
    elapsed = time.monotonic() - start
    rounded_elapsed = round(elapsed, 3)
    budget, budget_status = _budget_status(name, rounded_elapsed)
    return LaneResult(
        name=name,
        status=LaneStatus.PASSED if completed.returncode == 0 else LaneStatus.FAILED,
        command=cmd,
        elapsed_seconds=rounded_elapsed,
        returncode=completed.returncode,
        budget_seconds=budget,
        budget_status=budget_status,
    )


def _captured_text(value: str | bytes | None) -> str:
    """Return captured subprocess output as text for JSON-safe lane details."""

    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return value


def _run_captured_command(name: str, cmd: list[str], *, env: dict[str, str] | None = None) -> LaneResult:
    start = time.monotonic()
    try:
        completed = subprocess.run(cmd, cwd=REPO_ROOT, env=env, check=False, capture_output=True, text=True)
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - start
        rounded_elapsed = round(elapsed, 3)
        budget, budget_status = _budget_status(name, rounded_elapsed)
        child: dict[str, object] = {
            "stdout": _captured_text(exc.stdout),
            "stderr": _captured_text(exc.stderr),
        }
        return LaneResult(
            name=name,
            status=LaneStatus.TIMED_OUT,
            command=cmd,
            elapsed_seconds=rounded_elapsed,
            returncode=None,
            reason=f"timed out after {exc.timeout} seconds",
            budget_seconds=budget,
            budget_status=budget_status,
            children=[child],
        )
    elapsed = time.monotonic() - start
    rounded_elapsed = round(elapsed, 3)
    budget, budget_status = _budget_status(name, rounded_elapsed)
    reason = None
    if completed.returncode != 0:
        reason = (completed.stderr or completed.stdout).strip()[:1000] or f"exit {completed.returncode}"
    completed_child: dict[str, object] = {
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }
    return LaneResult(
        name=name,
        status=LaneStatus.PASSED if completed.returncode == 0 else LaneStatus.FAILED,
        command=cmd,
        elapsed_seconds=rounded_elapsed,
        returncode=completed.returncode,
        reason=reason,
        budget_seconds=budget,
        budget_status=budget_status,
        children=[completed_child],
    )


def _external_tools_available(kvikdos: Path, msc6_root: Path) -> tuple[bool, str | None]:
    if not kvikdos.is_file() or not os.access(kvikdos, os.X_OK):
        return False, f"kvikdos not executable: {kvikdos}"
    if not msc6_root.is_dir():
        return False, f"MS C 6 root not found: {msc6_root}"
    return True, None


def _ultra_quickc_tools_available(kvikdos: Path, quickc_root: Path) -> tuple[bool, str | None]:
    if not kvikdos.is_file() or not os.access(kvikdos, os.X_OK):
        return False, f"kvikdos not executable: {kvikdos}"
    if not (quickc_root / "QCL.EXE").is_file():
        return False, f"Ultra QuickC compiler not found: {quickc_root / 'QCL.EXE'}"
    if not (quickc_root / "LINK.EXE").is_file():
        return False, f"Ultra QuickC linker not found: {quickc_root / 'LINK.EXE'}"
    return True, None


def _unit_lane() -> LaneResult:
    return _run_command(
        "unit-focused",
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-n",
            "7",
            "--dist",
            "loadgroup",
            "--durations=10",
            "--durations-min=1.0",
            *FOCUSED_PYTEST_TARGETS,
        ],
    )


def _msc6_construct_command(
    args: argparse.Namespace,
    *,
    construct: str,
    out_dir: Path,
) -> list[str]:
    return [
        sys.executable,
        "scripts/build_msc6_examples.py",
        "--only-constructs",
        construct,
        "--out-dir",
        str(out_dir),
        "--kvikdos",
        str(args.kvikdos),
        "--msc6-root",
        str(args.msc6_root),
        "--decompile-mode",
        "functions",
        "--decompile-max-functions",
        "0",
        "--decompile-timeout",
        str(args.decompile_timeout),
        "--decompile-run-timeout",
        str(args.decompile_run_timeout),
    ]


def _missing_external_lane(name: str, cmd: list[str], *, reason: str | None, require_external: bool) -> LaneResult:
    budget, budget_status = _budget_status(name, 0.0)
    if require_external:
        return LaneResult(
            name,
            LaneStatus.FAILED,
            cmd,
            0.0,
            returncode=1,
            reason=reason,
            budget_seconds=budget,
            budget_status=budget_status,
        )
    return LaneResult(
        name,
        LaneStatus.SKIPPED,
        cmd,
        0.0,
        reason=reason,
        budget_seconds=budget,
        budget_status=budget_status,
    )


def _sortdemo_status_command(
    args: argparse.Namespace,
    *,
    per_function_proc: bool = False,
) -> list[str]:
    """Build an authoritative whole-binary or explicit per-PROC diagnostic command."""
    status_out = args.sortdemo_status_out
    transcript_out = args.sortdemo_transcript_out
    command = [
        sys.executable,
        "scripts/sortdemo_decompiler_status.py",
        "--run-sortdemo",
        "--require-passed",
        "--binary",
        str(args.sortdemo_binary),
        "--decompile-timeout",
        str(args.sortdemo_decompile_timeout),
        "--run-timeout",
        str(args.sortdemo_run_timeout),
    ]
    if per_function_proc:
        command.append("--per-function-proc")
        status_out = status_out.with_name(f"{status_out.stem}_proc_diagnostic{status_out.suffix}")
        transcript_out = transcript_out.with_name(f"{transcript_out.stem}_proc_diagnostic{transcript_out.suffix}")
    if args.sortdemo_max_functions > 0:
        command.extend(("--max-functions", str(args.sortdemo_max_functions)))
    command.extend(
        [
            "--transcript-out",
            str(transcript_out),
            "--out",
            str(status_out),
            "--pretty",
        ]
    )
    return command


def _sortdemo_status_lane(
    args: argparse.Namespace,
    *,
    per_function_proc: bool = False,
) -> LaneResult:
    """Run the normal whole binary or the explicitly diagnostic per-PROC lane."""
    name = "sortdemo-status-proc-diagnostic" if per_function_proc else "sortdemo-status"
    cmd = _sortdemo_status_command(args, per_function_proc=per_function_proc)
    if not args.sortdemo_binary.is_file():
        return _missing_external_lane(
            name,
            cmd,
            reason=f"SORTDEMO binary not found: {args.sortdemo_binary}",
            require_external=bool(args.require_external),
        )
    env = dict(os.environ)
    env["INERTIA_ENABLE_TAIL_VALIDATION"] = "1"
    env["INERTIA_DISABLE_TIMING"] = "1"
    Path(cmd[cmd.index("--out") + 1]).parent.mkdir(parents=True, exist_ok=True)
    Path(cmd[cmd.index("--transcript-out") + 1]).parent.mkdir(parents=True, exist_ok=True)
    return _run_command(name, cmd, env=env)


def _sortd_sidecar_free_lane(args: argparse.Namespace) -> LaneResult:
    """Run the executable-only whole-binary discovery and acceptance ratchet."""
    args.sortd_report_out.parent.mkdir(parents=True, exist_ok=True)
    if not args.sortdemo_binary.is_file():
        cmd = [sys.executable, "scripts/check_sortd_sidecar_free.py"]
        return _missing_external_lane(
            "sortd-sidecar-free",
            cmd,
            reason=f"SORTDEMO source binary not found: {args.sortdemo_binary}",
            require_external=bool(args.require_external),
        )
    with tempfile.TemporaryDirectory(
        prefix="sortd-generated-functions-",
        dir=args.sortd_report_out.parent,
    ) as function_c_dir_text:
        function_c_dir = Path(function_c_dir_text)
        cmd = [
            sys.executable,
            "scripts/check_sortd_sidecar_free.py",
            "--source-binary",
            str(args.sortdemo_binary),
            "--run-timeout",
            str(args.sortd_run_timeout),
            "--transcript-out",
            str(args.sortd_transcript_out),
            "--report-out",
            str(args.sortd_report_out),
            "--function-c-dir",
            str(function_c_dir),
        ]
        sidecar_result = _run_command("sortd-sidecar-free", cmd)
        if sidecar_result.status is not LaneStatus.PASSED:
            return sidecar_result
        translation_unit_out = args.sortd_report_out.with_name("sortd_generated_translation_unit.c")
        translation_unit_report = args.sortd_report_out.with_name("sortd_generated_translation_unit.json")
        translation_unit_cmd = [
            sys.executable,
            "scripts/check_generated_translation_unit.py",
            "--function-c-dir",
            str(function_c_dir),
            "--output",
            str(translation_unit_out),
            "--report-out",
            str(translation_unit_report),
        ]
        translation_unit_result = _run_command(
            "sortd-generated-translation-unit",
            translation_unit_cmd,
        )
        behavior_cmd = [
            sys.executable,
            "scripts/check_sortd_generated_sort_core.py",
            "--transcript",
            str(args.sortd_transcript_out),
            "--function-c-dir",
            str(function_c_dir),
        ]
        behavior_result = _run_command("sortd-generated-sort-core", behavior_cmd)
    elapsed = round(
        sidecar_result.elapsed_seconds + translation_unit_result.elapsed_seconds + behavior_result.elapsed_seconds,
        3,
    )
    budget, budget_status = _budget_status("sortd-sidecar-free", elapsed)
    terminal_result = (
        translation_unit_result if translation_unit_result.status is not LaneStatus.PASSED else behavior_result
    )
    return LaneResult(
        name="sortd-sidecar-free",
        status=terminal_result.status,
        command=cmd,
        elapsed_seconds=elapsed,
        returncode=terminal_result.returncode,
        reason=terminal_result.reason,
        budget_seconds=budget,
        budget_status=budget_status,
        children=[
            asdict(sidecar_result),
            asdict(translation_unit_result),
            asdict(behavior_result),
        ],
    )


def _ultra_quickc_fixtures_command(args: argparse.Namespace) -> list[str]:
    return [
        sys.executable,
        "scripts/import_ultra_quickc_fixtures.py",
        "--kvikdos",
        str(args.kvikdos),
        "--quickc-root",
        str(args.ultra_quickc_root),
        "--output-root",
        str(args.ultra_quickc_out_dir),
        "--decompile-timeout",
        str(args.ultra_quickc_decompile_timeout),
    ]


def _ultra_quickc_fixtures_lane(args: argparse.Namespace) -> LaneResult:
    cmd = _ultra_quickc_fixtures_command(args)
    available, reason = _ultra_quickc_tools_available(args.kvikdos, args.ultra_quickc_root)
    if not available:
        return _missing_external_lane(
            "ultra-quickc-fixtures",
            cmd,
            reason=reason,
            require_external=bool(args.require_external),
        )
    result = _run_captured_command("ultra-quickc-fixtures", cmd)
    report_path = args.ultra_quickc_out_dir / "ultra_quickc_fixtures.json"
    details: dict[str, object] = {"report_path": str(report_path)}
    if report_path.is_file():
        try:
            payload = json.loads(report_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as ex:
            details["report_error"] = f"invalid JSON: {ex}"
        else:
            summary = payload.get("summary") if isinstance(payload, dict) else None
            if isinstance(summary, dict):
                details.update(summary)
    else:
        details["report_error"] = "fixture report not produced"
    return LaneResult(
        name=result.name,
        status=result.status,
        command=result.command,
        elapsed_seconds=result.elapsed_seconds,
        returncode=result.returncode,
        reason=result.reason,
        budget_seconds=result.budget_seconds,
        budget_status=result.budget_status,
        children=result.children,
        details=details,
    )


def _merge_msc6_reports(out_dir: Path, constructs: tuple[str, ...]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for construct in constructs:
        report_path = out_dir / construct / "report.json"
        if not report_path.exists():
            continue
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        if isinstance(payload, list):
            rows.extend(dict(row) for row in payload if isinstance(row, dict))
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return rows


def _float_field(row: dict[str, object], field_name: str) -> float | None:
    """Return a finite float field from a JSON row, if present."""

    value = row.get(field_name)
    if not isinstance(value, int | float):
        return None
    return float(value)


def _msc6_construct_timing_details(rows: list[dict[str, object]], *, limit: int = 5) -> dict[str, object]:
    """Return compact timing details from merged MS C construct reports."""

    timed_rows: list[dict[str, object]] = []
    for row in rows:
        seconds = _float_field(row, "decompile_wall_seconds")
        name = row.get("name")
        if seconds is None or not isinstance(name, str):
            continue
        timed_rows.append(
            {
                "construct": name,
                "decompile_wall_seconds": round(seconds, 3),
                "selected_functions": row.get("decompile_selected_functions"),
                "run_exit_code": row.get("decompile_run_exit_code"),
            }
        )
    timed_rows.sort(key=lambda item: cast(float, item["decompile_wall_seconds"]), reverse=True)
    total_seconds = round(sum(cast(float, item["decompile_wall_seconds"]) for item in timed_rows), 3)
    return {
        "construct_count": len(rows),
        "timed_construct_count": len(timed_rows),
        "decompile_wall_seconds_total": total_seconds,
        "slowest_constructs": timed_rows[: max(0, limit)],
    }


def _msc6_tiny_lane(args: argparse.Namespace, *, name: str, constructs: tuple[str, ...]) -> LaneResult:
    available, reason = _external_tools_available(args.kvikdos, args.msc6_root)
    representative_cmd = _msc6_construct_command(args, construct=",".join(constructs), out_dir=args.msc6_out_dir)
    if not available:
        return _missing_external_lane(
            name,
            representative_cmd,
            reason=reason,
            require_external=bool(args.require_external),
        )

    env = dict(os.environ)
    env["INERTIA_ENABLE_TAIL_VALIDATION"] = "1"
    env["INERTIA_DISABLE_TIMING"] = "1"
    env["INERTIA_DISABLE_SIGNATURES"] = "1"
    start = time.monotonic()
    requested_workers = int(args.msc6_workers or 1)
    allow_parallel = str(os.environ.get("INERTIA_ALLOW_PARALLEL_MSC6_WORKERS", "")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if requested_workers > 1 and not allow_parallel:
        print(
            "[test-pipeline] --msc6-workers > 1 ignored: construct-level parallelism is currently "
            "disabled by default; set INERTIA_ALLOW_PARALLEL_MSC6_WORKERS=1 to run with the requested "
            "parallelism.",
            file=sys.stderr,
        )
        requested_workers = 1

    max_workers = max(1, min(requested_workers, len(constructs)))
    child_results_by_construct: dict[str, LaneResult] = {}

    def run_construct(construct: str) -> LaneResult:
        out_dir = args.msc6_out_dir / construct
        cmd = _msc6_construct_command(args, construct=construct, out_dir=out_dir)
        return _run_captured_command(f"msc6-tiny:{construct}", cmd, env=env)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(run_construct, construct): construct for construct in constructs}
        for future in concurrent.futures.as_completed(future_map):
            construct = future_map[future]
            child_results_by_construct[construct] = future.result()

    child_results = [child_results_by_construct[construct] for construct in constructs]
    for child in child_results:
        if child.children:
            stdout = str(child.children[0].get("stdout", ""))
            stderr = str(child.children[0].get("stderr", ""))
            if stdout:
                print(stdout, end="" if stdout.endswith("\n") else "\n")
            if stderr:
                print(stderr, file=sys.stderr, end="" if stderr.endswith("\n") else "\n")

    report_rows = _merge_msc6_reports(args.msc6_out_dir, constructs)
    elapsed = round(time.monotonic() - start, 3)
    budget, budget_status = _budget_status(name, elapsed)
    unsuccessful_children = [child for child in child_results if child.status != LaneStatus.PASSED]
    timed_out_children = [child for child in unsuccessful_children if child.status == LaneStatus.TIMED_OUT]
    status = (
        LaneStatus.TIMED_OUT
        if timed_out_children
        else LaneStatus.FAILED
        if unsuccessful_children
        else LaneStatus.PASSED
    )
    reason_text = (
        "; ".join(f"{child.name}: {child.reason or child.returncode}" for child in unsuccessful_children) or None
    )
    return LaneResult(
        name=name,
        status=status,
        command=representative_cmd,
        elapsed_seconds=elapsed,
        returncode=None if timed_out_children else 1 if unsuccessful_children else 0,
        reason=reason_text,
        budget_seconds=budget,
        budget_status=budget_status,
        children=[asdict(child) for child in child_results],
        details=_msc6_construct_timing_details(report_rows),
    )


def _selected_lanes(args: argparse.Namespace) -> tuple[str, ...]:
    if args.lane:
        return tuple(args.lane)
    return PIPELINE_TIERS[args.tier]


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the curated decompiler regression pipeline.")
    parser.add_argument("--tier", choices=tuple(PIPELINE_TIERS), default="default")
    parser.add_argument(
        "--lane",
        action="append",
        choices=(
            "unit-focused",
            "ultra-quickc-fixtures",
            "msc6-tiny-smoke",
            "msc6-tiny-full-pipeline",
            "sortdemo-status",
            "sortdemo-status-proc-diagnostic",
            "sortd-sidecar-free",
        ),
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--msc6-out-dir", type=Path, default=REPO_ROOT / "examples" / "build_msc6_tiny")
    parser.add_argument("--ultra-quickc-root", type=Path, default=DEFAULT_ULTRA_QUICKC_ROOT)
    parser.add_argument(
        "--ultra-quickc-out-dir",
        type=Path,
        default=REPO_ROOT / "examples" / "build_ultra_quickc_pipeline",
    )
    parser.add_argument("--kvikdos", type=Path, default=DEFAULT_KVIKDOS)
    parser.add_argument("--msc6-root", type=Path, default=DEFAULT_MSC6_ROOT)
    parser.add_argument("--require-external", action="store_true")
    parser.add_argument("--decompile-timeout", type=int, default=60)
    parser.add_argument("--ultra-quickc-decompile-timeout", type=int, default=180)
    parser.add_argument("--decompile-run-timeout", type=int, default=600)
    parser.add_argument("--sortdemo-binary", type=Path, default=REPO_ROOT / "SORTDEMO.EXE")
    parser.add_argument("--sortdemo-max-functions", type=int, default=0)
    parser.add_argument("--sortdemo-decompile-timeout", type=int, default=360)
    parser.add_argument("--sortdemo-run-timeout", type=int, default=2400)
    parser.add_argument("--sortd-run-timeout", type=int, default=1200)
    parser.add_argument(
        "--sortdemo-status-out",
        type=Path,
        default=REPO_ROOT / "angr_platforms" / ".cache" / "test_pipeline" / "sortdemo_status.json",
    )
    parser.add_argument(
        "--sortdemo-transcript-out",
        type=Path,
        default=REPO_ROOT / "angr_platforms" / ".cache" / "test_pipeline" / "sortdemo_status.txt",
    )
    parser.add_argument(
        "--sortd-report-out",
        type=Path,
        default=REPO_ROOT / "angr_platforms" / ".cache" / "test_pipeline" / "sortd_sidecar_free.json",
    )
    parser.add_argument(
        "--sortd-transcript-out",
        type=Path,
        default=REPO_ROOT / "angr_platforms" / ".cache" / "test_pipeline" / "sortd_sidecar_free.txt",
    )
    parser.add_argument(
        "--msc6-workers",
        type=int,
        default=1,
        help=(
            "Maximum parallel MS C construct subprocesses. Defaults to serial because concurrent decompiler/toolchain "
            "runs still share cache/runtime state. Function fallback rebuilds inside each construct remain serial. "
            "Set INERTIA_ALLOW_PARALLEL_MSC6_WORKERS=1 to opt in to parallel construct execution."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run selected pipeline lanes and write the structured summary report."""

    args = _parse_args(argv)
    lane_names = _selected_lanes(args)
    lane_fns: dict[str, Callable[[], LaneResult]] = {
        "unit-focused": _unit_lane,
        "ultra-quickc-fixtures": lambda: _ultra_quickc_fixtures_lane(args),
        "msc6-tiny-smoke": lambda: _msc6_tiny_lane(args, name="msc6-tiny-smoke", constructs=MSC6_TINY_SMOKE_CONSTRUCTS),
        "msc6-tiny-full-pipeline": lambda: _msc6_tiny_lane(
            args,
            name="msc6-tiny-full-pipeline",
            constructs=MSC6_TINY_CONSTRUCTS,
        ),
        "sortdemo-status": lambda: _sortdemo_status_lane(args),
        "sortd-sidecar-free": lambda: _sortd_sidecar_free_lane(args),
        "sortdemo-status-proc-diagnostic": lambda: _sortdemo_status_lane(args, per_function_proc=True),
    }
    results = [lane_fns[name]() for name in lane_names]
    summary = {
        "schema": "inertia.test_pipeline.v1",
        "selected": len(results),
        "passed": sum(1 for item in results if item.status == LaneStatus.PASSED),
        "failed": sum(1 for item in results if item.status == LaneStatus.FAILED),
        "skipped": sum(1 for item in results if item.status == LaneStatus.SKIPPED),
        "timed_out": sum(1 for item in results if item.status == LaneStatus.TIMED_OUT),
        "results": [asdict(item) for item in results],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {key: summary[key] for key in ("selected", "passed", "failed", "skipped", "timed_out")},
            sort_keys=True,
        )
    )
    return 1 if summary["failed"] or summary["timed_out"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
