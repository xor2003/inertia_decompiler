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
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, cast
from xml.etree import ElementTree

if TYPE_CHECKING or __package__:
    from .compiler_coverage_provenance import KVMAccessStatus, kvm_access_evidence
else:
    from compiler_coverage_provenance import KVMAccessStatus, kvm_access_evidence

REPO_ROOT: Path = Path(__file__).resolve().parents[1]
DEFAULT_OUT: Path = REPO_ROOT / "angr_platforms" / ".cache" / "test_pipeline" / "summary.json"
DEFAULT_KVIKDOS: Path = Path("/home/xor/kvikdos/kvikdos")
DEFAULT_MSC6_ROOT: Path = Path("/home/xor/inertia_player/dos_compilers/Microsoft C v6ax")
DEFAULT_ULTRA_QUICKC_ROOT: Path = REPO_ROOT / "borrow" / "UltraDecompiler" / "QuickC"
PYTEST_WORKER_COUNT: int = 3
BUDGETED_BINARY_WORKERS: int = 2
BUDGETED_BINARY_PYTEST_TARGETS: tuple[str, ...] = (
    "angr_platforms/tests/test_dosunit_transitive_callees.py",
)

SPLIT_CONTROL_TEST_FILES: tuple[str, ...] = (
    "angr_platforms/tests/test_fork_owner_death.py",
    "angr_platforms/tests/test_pytest_live_failures.py",
    "angr_platforms/tests/test_compiler_coverage_runner.py",
    "angr_platforms/tests/test_x86_16_gp_word_runtime.py",
)
SERIAL_PYTEST_TARGETS: tuple[str, ...] = (
    "angr_platforms/tests/test_pytest_live_failures.py::test_live_failures_preserve_reports_and_emit_before_session_end",
)
LINUX_PROCESS_CASE_COUNTS: dict[str, int] = {
    "angr_platforms/tests/test_compiler_coverage_runner.py::test_real_timeout_stops_descendants_and_retains_both_output_streams": 2,
    "angr_platforms/tests/test_fork_owner_death.py::test_work_requires_live_supervision": 4,
    "angr_platforms/tests/test_fork_owner_death.py::test_owner_death_stops_owned_descendants": 2,
}
LINUX_PROCESS_PYTEST_TARGETS: tuple[str, ...] = tuple(LINUX_PROCESS_CASE_COUNTS)
GP_NATIVE_PYTEST_TARGETS: tuple[str, ...] = (
    "angr_platforms/tests/test_x86_16_gp_word_runtime.py::test_msc6_word_runtime_compiles_and_executes",
)

GNU_MAKE_ORACLE_TEST_FILE: str = "angr_platforms/tests/test_makefile_gnu_oracle.py"
GNU_MAKE_ORACLE_CASE_COUNTS: dict[str, int] = {
    'angr_platforms/tests/test_makefile_gnu_oracle.py::test_supported_cases_match_gnu_make': 10,
    'angr_platforms/tests/test_makefile_gnu_oracle.py::test_override_undefine_match_gnu_make': 19,
    'angr_platforms/tests/test_makefile_gnu_oracle.py::test_skipped_include_override_oracle_proves_flag_needed': 1,
    'angr_platforms/tests/test_makefile_gnu_oracle.py::test_conditional_override_undefine_oracle': 1,
    'angr_platforms/tests/test_makefile_gnu_oracle.py::test_include_cases_match_gnu_make': 1,
    'angr_platforms/tests/test_makefile_gnu_oracle.py::test_conditional_override_oracle_both_branches': 2,
    'angr_platforms/tests/test_makefile_gnu_oracle.py::test_conditional_override_undefine_oracle_both_branches': 1,
    'angr_platforms/tests/test_makefile_gnu_oracle.py::test_define_override_matches_gnu_make': 2,
    'angr_platforms/tests/test_makefile_gnu_oracle.py::test_unknown_global_assignment_gnu_oracle_proves_refusal_needed': 6,
}
GNU_MAKE_ORACLE_PYTEST_TARGETS: tuple[str, ...] = tuple(GNU_MAKE_ORACLE_CASE_COUNTS)

FOCUSED_PYTEST_TARGETS: tuple[str, ...] = (
    "angr_platforms/tests/test_compact_paths.py",
    "angr_platforms/tests/test_ordered_io_environment.py",
    "angr_platforms/tests/test_x86_16_immediate_port.py",
    "angr_platforms/tests/test_flat32_indirect_callbacks.py",
    "angr_platforms/tests/test_flat32_indirect_callback_effects.py",
    "angr_platforms/tests/test_flat32_loop_calls.py",
    "angr_platforms/tests/test_replay_capture_vectors.py",
    "angr_platforms/tests/test_pytest_directory_cache.py",
    "angr_platforms/tests/test_pytest_live_failures.py::test_registration_only_owns_controller_terminal",
    "angr_platforms/tests/test_pytest_live_failures.py::test_failure_flushes_immediately_without_mutating_report",
    "angr_platforms/tests/test_pytest_live_failures.py::test_nonfailure_reports_are_quiet",
    "angr_platforms/tests/test_native_relift_scope.py",
    "angr_platforms/tests/test_dosunit_kvikdos_strict.py",
    "angr_platforms/tests/test_dosunit_kvikdos_worker.py",
    "angr_platforms/tests/test_dosunit_kvikdos_memory_range.py",
    "angr_platforms/tests/test_dosunit_kvikdos_protocol_errors.py",
    "angr_platforms/tests/test_dosunit_kvikdos_snapshot_registry.py",
    "angr_platforms/tests/test_real16_control_boundary.py",
    "angr_platforms/tests/test_x86_16_aam_fault.py",
    "angr_platforms/tests/test_native_effect_environment_guards.py",
    "angr_platforms/tests/test_dosunit_io_read_state.py",
    "angr_platforms/tests/test_real16_control_target_proof.py",
    "angr_platforms/tests/test_binary_callee_control_target.py",
    "angr_platforms/tests/test_binary_callee_relative_call_coordinates.py",
    "angr_platforms/tests/test_real16_program_boot.py",
    "angr_platforms/tests/test_real16_program_resize.py",
    "angr_platforms/tests/test_real16_program_memory.py",
    "angr_platforms/tests/test_real16_program_interrupts.py",
    "angr_platforms/tests/test_real16_program_vectors.py",
    "angr_platforms/tests/test_real16_program_device_info.py",
    "angr_platforms/tests/test_real16_program_video.py",
    "angr_platforms/tests/test_real16_program_video_policy.py",
    "angr_platforms/tests/test_real16_video_state_policy.py",
    "angr_platforms/tests/test_real16_video_state_boundary.py",
    "angr_platforms/tests/test_real16_program_video_state.py",
    "angr_platforms/tests/test_real16_program_rom.py",
    "angr_platforms/tests/test_real16_program_rom_integration.py",
    "angr_platforms/tests/test_mz_invocation_source.py",
    "angr_platforms/tests/test_real16_boot_provenance.py",
    "angr_platforms/tests/test_pe32_program_boot.py",
    "angr_platforms/tests/test_real16_program_output.py",
    "angr_platforms/tests/test_real16_program_input.py",
    "angr_platforms/tests/test_x86_16_import_identity.py",
    "angr_platforms/tests/test_dosunit_ssa_source_identity_paths.py",
    "angr_platforms/tests/test_dosunit_vex_cache_identity.py",
    "angr_platforms/tests/test_recursive_joint_deadlines.py",
    "angr_platforms/tests/test_real16_domain_dispatch.py",
    "angr_platforms/tests/test_recursive_call_continuation_contracts.py",
    "angr_platforms/tests/test_recursive_fetched_code_composition.py",
    "angr_platforms/tests/test_recursive_native_deadlines.py",
    "angr_platforms/tests/test_recursive_entry_deadlines.py",
    "angr_platforms/tests/test_recursive_entry_layout_deadlines.py",
    "angr_platforms/tests/test_recursive_domain_deadlines.py",
    "angr_platforms/tests/test_recursive_consumer_model_refresh.py",
    "angr_platforms/tests/test_real16_address_final_seal.py",
    "angr_platforms/tests/test_flat32_model_namespaces.py",
    "angr_platforms/tests/test_flat32_code_write_domain.py",
    "angr_platforms/tests/test_real16_recursive_intake_controls.py",
    "angr_platforms/tests/test_symbolic_terminal_read_audit_lifetime.py",
    "angr_platforms/tests/test_real16_recursive_report_schema.py",
    "angr_platforms/tests/test_pe32_recursive_report_contracts.py",
    "angr_platforms/tests/test_recursive_loaded_memory_seed.py",
    "angr_platforms/tests/test_dosunit_callee_scope.py",
    "angr_platforms/tests/test_dosunit_alarm_boundary.py",
    "angr_platforms/tests/test_dosunit_induction_soundness.py",
    "angr_platforms/tests/test_real16_binary_compare.py",
    "angr_platforms/tests/test_real16_public_accounting.py",
    "angr_platforms/tests/test_real16_selected_lowering.py",
    "angr_platforms/tests/test_real16_self_lowering_reuse.py",
    "angr_platforms/tests/test_real16_call_composition.py",
    "angr_platforms/tests/test_real16_indirect_call_budgets.py",
    "angr_platforms/tests/test_real16_argument_controls.py",
    "angr_platforms/tests/test_real16_repeat_summary_contract.py",
    "angr_platforms/tests/test_dosunit_x86_lazy_conditions.py",
    "angr_platforms/tests/test_dosunit_x86_carry_helper.py",
    "angr_platforms/tests/test_real16_ail_control_contract.py",
    "angr_platforms/tests/test_real16_far_call_composition.py",
    "angr_platforms/tests/test_real16_loop_calls.py",
    "angr_platforms/tests/test_real16_far_loop_controls.py",
    "angr_platforms/tests/test_paired_region_graph.py",
    "angr_platforms/tests/test_dosunit_ssa_versions.py",
    "angr_platforms/tests/test_real16_region_proof.py",
    "angr_platforms/tests/test_register_state_relations.py",
    "angr_platforms/tests/test_proof_scope.py",
    "angr_platforms/tests/test_real16_register_regions.py",
    "angr_platforms/tests/test_real16_affine_regions.py",
    "angr_platforms/tests/test_flat32_affine_regions.py",
    "angr_platforms/tests/test_register_affine_relations.py",
    "angr_platforms/tests/test_affine_concrete_replay.py",
    'angr_platforms/tests/test_region_cover.py',
    'angr_platforms/tests/test_region_composition_admission.py',
    'angr_platforms/tests/test_memory_state_relations.py',
    'angr_platforms/tests/test_memory_relation_proposals.py',
    'angr_platforms/tests/test_memory_invariant_obligations.py',
    'angr_platforms/tests/test_memory_invariant_proposals.py',
    'angr_platforms/tests/test_memory_state_invariants.py',
    'angr_platforms/tests/test_invariant_retry_contracts.py',
    'angr_platforms/tests/test_flat32_source_closure.py',
    'angr_platforms/tests/test_region_branch_pairing.py',
    'angr_platforms/tests/test_branch_pairing_oracle.py',
    'angr_platforms/tests/test_region_pairing_reporting.py',
    "angr_platforms/tests/test_ssa_output_lemmas.py",
    "angr_platforms/tests/test_ssa_array_input_substitution.py",

    "angr_platforms/tests/test_real16_register_public.py",
    "angr_platforms/tests/test_flat32_register_regions.py",
    "angr_platforms/tests/test_flat32_register_replay.py",

    "angr_platforms/tests/test_real16_region_public.py",
    "angr_platforms/tests/test_real16_macro_public.py",
    "angr_platforms/tests/test_real16_retry_budget_diagnostics.py",
    "angr_platforms/tests/test_real16_replay_cli.py",
    "angr_platforms/tests/test_real16_call_admission.py",
    "angr_platforms/tests/test_real16_public_calls.py",
    "angr_platforms/tests/test_flat32_comparator_lane.py",
    "angr_platforms/tests/test_flat32_loop_controls.py",
    "angr_platforms/tests/test_flat32_stack_domain.py",
    "angr_platforms/tests/test_flat32_contextual_calls.py",
    "angr_platforms/tests/test_flat32_stack_domain_cli.py",
    "angr_platforms/tests/test_x86_16_clinic_terminal_control.py",
    "angr_platforms/tests/test_flat32_tail_transfer.py",
    "angr_platforms/tests/test_flat32_compose_total_budget.py",
    "angr_platforms/tests/test_flat32_tail_retry_projection.py",
    "angr_platforms/tests/test_flat32_conditional_boundaries.py",
    "angr_platforms/tests/test_flat32_loaded_byte_boundaries.py",
    "angr_platforms/tests/test_dosunit_binary_environment.py",
    "angr_platforms/tests/test_dosunit_ssa_provenance.py",
    "angr_platforms/tests/test_dosunit_proof_contracts.py",
    "angr_platforms/tests/test_dosunit_public_domain.py",
    "angr_platforms/tests/test_dosunit_public_domain_integration.py",
    "angr_platforms/tests/test_dosunit_proof_projection.py",
    "angr_platforms/tests/test_flat32_proof_seal.py",
    "angr_platforms/tests/test_flat32_concrete_replay.py",
    "angr_platforms/tests/test_dosunit_guarded_capture.py",
    "angr_platforms/tests/test_real16_write_readback.py",
    "angr_platforms/tests/test_flat32_replay_full_state.py",
    "angr_platforms/tests/test_flat32_replay_cli.py",
    "angr_platforms/tests/test_flat32_file_permissions.py",
    "angr_platforms/tests/test_flat32_mapping_contract.py",
    "angr_platforms/tests/test_flat32_observation_contract.py",
    "angr_platforms/tests/test_x86_16_calling_convention_compat.py",
    "angr_platforms/tests/test_fork_timeout.py",
    "angr_platforms/tests/test_x86_16_tail_validation_generation_atoms.py",
    "angr_platforms/tests/test_x86_16_tail_validation_generation_equality.py",
    "angr_platforms/tests/test_x86_16_validation_goto_target_identity.py",
    "angr_platforms/tests/test_batch_decompile_procs_runtime.py",
    "angr_platforms/tests/test_batch_decompile_scheduler.py",
    "angr_platforms/tests/test_batch_decompile_frame_deadline.py",
    "angr_platforms/tests/test_batch_decompile_result_contract.py",
    "angr_platforms/tests/test_x86_16_c_ast_utils.py",
    "angr_platforms/tests/test_cli_semantic_rollback.py",
    "angr_platforms/tests/test_cli_retry_outcome.py",
    "angr_platforms/tests/test_cli_c_text_postprocess.py::test_known_helper_signature_text_preserves_recovered_signature",
    "angr_platforms/tests/test_x86_16_cod_samples.py::test_dosfunc_cod_sample_process_helpers_stay_empty",
    "angr_platforms/tests/test_cod_stability_sweep.py",
    "angr_platforms/tests/test_x86_16_interprocedural_discarded_return.py",
    "angr_platforms/tests/test_x86_16_frontend_boundary_transport.py",
    "angr_platforms/tests/test_x86_16_frontend_caller_entry_identity.py",
    "angr_platforms/tests/test_x86_16_positive_bp_wide_arguments.py",
    "angr_platforms/tests/test_x86_16_wide_return_type_preservation.py",
    "angr_platforms/tests/test_x86_16_cod_regressions.py::test_cod_runner_hotspots_fall_back_through_scan_safe_classifier",
    "angr_platforms/tests/test_x86_16_cli.py::test_decompile_function_disables_structuring_for_tiny_single_call_helpers",
    "angr_platforms/tests/test_cli_fallback_slice_entry.py::"
    "test_sidecar_slice_refuses_truncated_cfg_ownership",
    "angr_platforms/tests/test_x86_16_bounded_linear_instruction_inventory.py::"
    "test_bounded_inventory_decodes_to_exact_region_end",
    "angr_platforms/tests/test_x86_16_wide_condition_ordering.py",
    "angr_platforms/tests/test_x86_16_wide_call_condition_source.py",
    "angr_platforms/tests/test_x86_16_wide_call_condition_capture.py",
    "angr_platforms/tests/test_x86_16_wide_call_condition_plan.py",
    "angr_platforms/tests/test_x86_16_stack_frame_projection.py",
    "angr_platforms/tests/test_x86_16_stack_prototype_codegen_api.py",
    "angr_platforms/tests/test_x86_16_function_pointer_parameters.py",
    "angr_platforms/tests/test_x86_16_function_pointer_argument_replay.py",
    "angr_platforms/tests/test_x86_16_stack_annotation_authority.py",
    "angr_platforms/tests/test_x86_16_stack_aggregate_objects.py",
    "angr_platforms/tests/test_x86_16_far_stack_probe_aggregate.py",
    "angr_platforms/tests/test_x86_16_far_return_pointer_use.py",
    "angr_platforms/tests/test_x86_16_far_return_expression_binding.py",
    "angr_platforms/tests/test_x86_16_near_return_c_ast_congruence.py",
    "angr_platforms/tests/test_x86_16_near_return_segment_use.py",
    "angr_platforms/tests/test_x86_16_near_return_entry_selector.py",
    "angr_platforms/tests/test_x86_16_near_pointer_stack_input_segment.py",
    "angr_platforms/tests/test_x86_16_near_return_expression.py",
    "angr_platforms/tests/test_x86_16_near_return_expression_replay.py",
    "angr_platforms/tests/test_x86_16_near_return_body_preflight.py",
    "angr_platforms/tests/test_x86_16_storage_word_input_binding.py",
    "angr_platforms/tests/test_x86_16_flags_physical_register_contract.py",
    "angr_platforms/tests/test_x86_16_packed_flags_state.py",
    "angr_platforms/tests/test_x86_16_packed_flags_cycles.py",
    "angr_platforms/tests/test_x86_16_stored_call_result_assignments.py",
    "angr_platforms/tests/test_x86_16_stored_call_result_definitions.py",
    "angr_platforms/tests/test_x86_16_validation_branch_conditions.py",
    "angr_platforms/tests/test_x86_16_validation_condition_coverage.py",
    "angr_platforms/tests/test_x86_16_composite_pretest_conditions.py",
    "angr_platforms/tests/test_x86_16_existing_loop_exit_conditions.py",
    "angr_platforms/tests/test_x86_16_terminal_loop_exit_conditions.py",
    "angr_platforms/tests/test_x86_16_terminal_wide_validation.py",
    "angr_platforms/tests/test_x86_16_render_compat.py",
    "angr_platforms/tests/test_x86_16_structuring_condition_processor.py",
    "angr_platforms/tests/test_x86_16_bound_call_condition.py",
    "angr_platforms/tests/test_x86_16_call_result_zero_validation.py",
    "angr_platforms/tests/test_x86_16_structuring_condition_ownership.py",
    "angr_platforms/tests/test_x86_16_shared_loop_exit.py",
    "angr_platforms/tests/test_x86_16_condition_decrement_fingerprints.py",
    "angr_platforms/tests/test_x86_16_storage_or_fingerprints.py",
    "angr_platforms/tests/test_x86_16_structured_tag_projection.py",
    "angr_platforms/tests/test_x86_16_validation_additive_semantic_casts.py",
    "angr_platforms/tests/test_x86_16_indexed_global_stack_coordinates.py",
    "angr_platforms/tests/test_x86_16_indexed_load_subviews.py",
    "angr_platforms/tests/test_x86_16_condition_argument_types.py",
    "angr_platforms/tests/test_x86_16_typed_condition_side_effect_preservation.py",
    "angr_platforms/tests/test_x86_16_ir_memory_call_liveness.py",
    "angr_platforms/tests/test_x86_16_tail_callsite_inventory.py",
    "angr_platforms/tests/test_x86_16_segment_program_layout.py",
    "angr_platforms/tests/test_x86_16_register_source_wide_clobbers.py",
    "angr_platforms/tests/test_x86_16_register_entry_overwrite.py",
    "angr_platforms/tests/test_x86_16_consumed_stack_address_setup.py",
    "angr_platforms/tests/test_x86_16_register_source_memory_dependencies.py",
    "angr_platforms/tests/test_accepted_payload_integrity.py",
    "angr_platforms/tests/test_acceptance_scorecard.py",
    "angr_platforms/tests/test_tail_validation_display_outcome.py",
    "angr_platforms/tests/test_acceptance_reporting.py",
    "angr_platforms/tests/test_x86_16_callsite_return_use_zero_idiom.py",
    "angr_platforms/tests/test_x86_16_gp_partial_live_in.py",
    "angr_platforms/tests/test_x86_16_gp_pointer_values.py",
    "angr_platforms/tests/test_x86_16_pointer_fill_behavior.py",
    "angr_platforms/tests/test_x86_16_pointer_sum_behavior.py",
    "angr_platforms/tests/test_x86_16_loop_condition_block_identity.py",
    "angr_platforms/tests/test_x86_16_pretest_loop_condition_ownership.py",
    "angr_platforms/tests/test_x86_16_nested_loop_behavior.py",
    "angr_platforms/tests/test_x86_16_goto_accumulate_behavior.py",
    "angr_platforms/tests/test_x86_16_stack_update_scope_guard.py",
    "angr_platforms/tests/test_x86_16_instruction_fragment_placement.py",
    "angr_platforms/tests/test_x86_16_smoketest.py",
    "angr_platforms/tests/test_build_msc6_examples.py",
    "angr_platforms/tests/test_msc6_batch_worker_budget.py",
    "angr_platforms/tests/test_msc6_dos_tmp.py",
    "angr_platforms/tests/test_msc6_binary_recovery_policy.py",
    "angr_platforms/tests/test_x86_16_frontend_capstone_decode.py",
    "angr_platforms/tests/test_compiler_coverage_manifest.py",
    "angr_platforms/tests/test_compiler_coverage_csmith.py",
    "angr_platforms/tests/test_compiler_coverage_pointer_oracle.py",
    "angr_platforms/tests/test_compiler_coverage_provenance.py",
    "angr_platforms/tests/test_kvm_marker_policy.py",
    "angr_platforms/tests/test_x86_16_confidence_and_assumptions.py",
    "angr_platforms/tests/test_msc6_memory_model.py",
    "angr_platforms/tests/test_compiler_coverage_result.py",
    "angr_platforms/tests/test_compiler_coverage_runner.py::test_invalid_deadline_rejected_before_creating_artifacts",
    "angr_platforms/tests/test_compiler_coverage_runner.py::test_existing_artifacts_cannot_be_reused",
    "angr_platforms/tests/test_compiler_coverage_runner.py::test_external_fixture_uses_existing_owner_and_fingerprints_headers",
    "angr_platforms/tests/test_compiler_coverage_runner.py::test_source_identity_is_retained_and_changes_refuse_acceptance",
    "angr_platforms/tests/test_compiler_coverage_runner.py::test_environment_drift_refuses_an_otherwise_passing_roundtrip",
    "angr_platforms/tests/test_compiler_coverage_runner.py::test_invalid_runtime_header_destinations_fail_before_launch",
    "angr_platforms/tests/test_compiler_coverage_runner.py::test_timeout_kills_group_and_reaps_child",
    "angr_platforms/tests/test_compiler_coverage_runner.py::test_launch_failure_retains_structured_result",
    "angr_platforms/tests/test_compiler_coverage_runner.py::test_missing_report_is_not_success",
    "angr_platforms/tests/test_compiler_coverage_runner.py::test_interruption_kills_group_and_propagates",
    "angr_platforms/tests/test_compiler_coverage_suite.py",
    "angr_platforms/tests/test_x86_16_nested_cdecl_arguments.py",
    "angr_platforms/tests/test_msc6_compat_headers.py",
    "angr_platforms/tests/test_msc6_entrypoint.py",
    "angr_platforms/tests/test_msc_storage_carry_oracle.py",
    "angr_platforms/tests/test_msc6_toolchain_lock.py",
    "angr_platforms/tests/test_check_changed_non_test_types.py",
    "angr_platforms/tests/test_import_ultra_quickc_fixtures.py",
    "angr_platforms/tests/test_generated_c_indexed_argument_contract.py",
    "angr_platforms/tests/test_omf_pat_lidata.py",
    "angr_platforms/tests/test_pat_literal_prefilter.py",
    "angr_platforms/tests/test_pat_catalog_cache_identity.py",
    "angr_platforms/tests/test_omf_pat_fixup_encoding.py",
    "angr_platforms/tests/test_test_pipeline.py",
    "angr_platforms/tests/test_msc6_runtime_gate_artifacts.py",
    "angr_platforms/tests/test_msc6_original_evidence.py",
    "angr_platforms/tests/test_discovery_pre_entry_order.py",
    "angr_platforms/tests/test_x86_16_image_extent_projection.py",
    "angr_platforms/tests/test_cli_loader_memory_boundary.py",
    "angr_platforms/tests/test_cli_shared_future_collection.py",
    "angr_platforms/tests/test_cli_ranked_task_queue.py",
    "angr_platforms/tests/test_cli_direct_caller_return_snapshot.py",
    "angr_platforms/tests/test_cli_core_isolated_recovery.py",
    "angr_platforms/tests/test_cli_function_discovery_regions.py",
    "angr_platforms/tests/test_cli_caller_range_binary_bounds.py",
    "angr_platforms/tests/test_signature_catalog_without_flair.py",
    "angr_platforms/tests/test_binary_signature_metadata.py",
    "angr_platforms/tests/test_signature_match_ambiguity.py",
    "angr_platforms/tests/test_ada_signature_integration.py",
    "angr_platforms/tests/test_default_signature_provenance.py",
    "angr_platforms/tests/test_metadata_evidence.py",
    "angr_platforms/tests/test_near_pointer_argument_values.py",
    "angr_platforms/tests/test_signature_region_bounds.py",
    "angr_platforms/tests/test_discovery_signature_isolation.py",
    "angr_platforms/tests/test_discovery_library_boundaries.py",
    "angr_platforms/tests/test_discovery_recovery_policy.py",
    "angr_platforms/tests/test_callsite_complement_sources.py",
    "angr_platforms/tests/test_x86_16_scalar_byte_behavior.py",
    "angr_platforms/tests/test_make_linter_inputs.py",
    "angr_platforms/tests/test_check_sortd_sidecar_free.py",
    "angr_platforms/tests/test_sortd_drawtime_gate.py",
    "angr_platforms/tests/test_runmenu_execution_evidence.py",
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
    "angr_platforms/tests/test_x86_16_condition_register_source_bindings.py",
    "angr_platforms/tests/test_x86_16_condition_register_byte_extension.py",
    "angr_platforms/tests/test_x86_16_condition_cache_relift.py",
    "angr_platforms/tests/test_x86_16_condition_lift_capture.py",
    "angr_platforms/tests/test_x86_16_status_flag_lift_context.py",
    "angr_platforms/tests/test_x86_16_function_condition_artifact.py",
    "angr_platforms/tests/test_x86_16_condition_transfer.py",
    "angr_platforms/tests/test_x86_16_condition_sign_extension.py",
    "angr_platforms/tests/test_x86_16_condition_full_width_masks.py",
    "angr_platforms/tests/test_x86_16_jcc_result_condition.py",
    "angr_platforms/tests/test_x86_16_frontend_condition_evidence.py",
    "angr_platforms/tests/test_x86_16_stack_condition_access_provenance.py",
    "angr_platforms/tests/test_x86_16_vex_logical_memory_accesses.py",
    "angr_platforms/tests/test_x86_16_cfg_direct_jump.py",
    "angr_platforms/tests/test_x86_16_cfg_direct_call.py",
    "angr_platforms/tests/test_x86_16_frontend_function_boundary_index.py",
    "angr_platforms/tests/test_x86_16_mapped_backward_boundary.py",
    "angr_platforms/tests/test_x86_16_frontend_instruction_reachability.py",
    "angr_platforms/tests/test_x86_16_status_flag_cfg_liveness.py",
    "angr_platforms/tests/test_x86_16_status_flag_cfg_projection.py",
    "angr_platforms/tests/test_x86_16_flag_lookahead_boundaries.py",
    "angr_platforms/tests/test_x86_16_typed_switch_seqnode.py",
    "angr_platforms/tests/test_x86_16_switch_definition_coverage.py",
    "angr_platforms/tests/test_x86_16_dead_local_structured_reads.py",
    "angr_platforms/tests/test_x86_16_stack_aggregate_coordinate_replay.py",
    "angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_runmenu_sidecar_free_preserves_binary_escape_exit",
    "angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_drawtime_sidecar_free_materializes_wide_delay_arguments",
    "angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_initmenu_pause_zero_guard_has_no_raw_flag_carrier",
    "angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_sidecar_free_initbars_preserves_binary_stack_array",
    "angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_insertionsort_sidecar_free_splits_header_and_rebases_source",
    "angr_platforms/tests/test_x86_16_decompiler_postprocess_typed_conditions.py",
    "angr_platforms/tests/test_x86_16_condition_register_definition.py",
    "angr_platforms/tests/test_x86_16_runtime_condition_projection.py",
    "angr_platforms/tests/test_x86_16_loop_instruction_tags.py",
    "angr_platforms/tests/test_x86_16_loop_break_topology.py",
    "angr_platforms/tests/test_x86_16_structuring_grouped_pass.py::test_decision_tree_accumulates_unresolved_normalized_affine_producers",
    "angr_platforms/tests/test_x86_16_void_return_pass_ownership.py",
    "angr_platforms/tests/test_x86_16_stack_prototype_promotion.py",
    "angr_platforms/tests/test_x86_16_decompiler_postprocess_jcc.py",
    "angr_platforms/tests/test_x86_16_jcc_register_evidence.py",
    "angr_platforms/tests/test_x86_16_positive_bp_argument_plan.py",
    "angr_platforms/tests/test_x86_16_stack_lowering_contracts.py",
    "angr_platforms/tests/test_x86_16_stack_declaration_identity.py",
    "angr_platforms/tests/test_x86_16_stack_memory_ssa_lowering.py",
    "angr_platforms/tests/test_x86_16_stack_memory_ssa_safety.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_consumers.py",
    "angr_platforms/tests/test_x86_16_function_ssa_registry.py",
    "angr_platforms/tests/test_x86_16_call_stack_effects.py",
    "angr_platforms/tests/test_x86_16_bp_call_preservation.py",
    "angr_platforms/tests/test_x86_16_synthetic_frame_call_effects.py",
    "angr_platforms/tests/test_x86_16_call_stack_allocation_guard.py",
    "angr_platforms/tests/test_x86_16_call_stack_allocation_proof.py",
    "angr_platforms/tests/test_x86_16_call_target_ssa_binding.py",
    "angr_platforms/tests/test_x86_16_call_target_evidence_retention.py",
    "angr_platforms/tests/test_x86_16_cython_backend.py",
    "angr_platforms/tests/test_mypyc_vex_bundle.py",
    "angr_platforms/tests/test_x86_16_stack_frame_register_alias.py",
    "angr_platforms/tests/test_x86_16_entry_stack_bytes.py",
    "angr_platforms/tests/test_x86_16_entry_stack_word_bits.py",
    "angr_platforms/tests/test_x86_16_entry_stack_word_values.py",
    "angr_platforms/tests/test_x86_16_entry_stack_word_boundaries.py",
    "angr_platforms/tests/test_x86_16_entry_stack_word_effects.py",
    "angr_platforms/tests/test_x86_16_scalar_instruction_effects.py",
    "angr_platforms/tests/test_x86_16_scalar_instruction_effects_emitter.py",
    "angr_platforms/tests/test_x86_16_entry_word_transport.py",
    "angr_platforms/tests/test_x86_16_entry_word_transport_sites.py",
    "angr_platforms/tests/test_x86_16_entry_word_transport_control.py",
    "angr_platforms/tests/test_x86_16_entry_word_transport_snapshots.py",
    "angr_platforms/tests/test_x86_16_entry_word_transport_snapshot_coherence.py",
    "angr_platforms/tests/test_x86_16_entry_stack_byte_refusals.py",
    "angr_platforms/tests/test_x86_16_entry_stack_pointer_snapshots.py",
    "angr_platforms/tests/test_x86_16_stack_tracker_allocation.py",
    "angr_platforms/tests/test_x86_16_stack_tracker_return_segment.py",
    "angr_platforms/tests/test_x86_16_register_definition_return.py",
    "angr_platforms/tests/test_x86_16_gp_stack_local_return.py",
    "angr_platforms/tests/test_x86_16_codegen_return_origin.py",
    "angr_platforms/tests/test_x86_16_callsite_inventory.py",
    "angr_platforms/tests/test_x86_16_gp_stack_local_reload.py",
    "angr_platforms/tests/test_x86_16_function_graph_extent_repair.py",
    "angr_platforms/tests/test_x86_16_call_stack_logical_width.py",
    "angr_platforms/tests/test_x86_16_call_stack_provenance.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_live_out.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_caller_context.py",
    "angr_platforms/tests/test_x86_16_terminal_memory_output_aliases.py",
    "angr_platforms/tests/test_x86_16_terminal_memory_output_views.py",
    "angr_platforms/tests/test_x86_16_terminal_pointer_outputs.py",
    "angr_platforms/tests/test_x86_16_conditional_pointer_output_native.py",
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
    "angr_platforms/tests/test_x86_16_affine_indexed_address.py",
    "angr_platforms/tests/test_x86_16_affine_induction_role.py",
    "angr_platforms/tests/test_x86_16_frame_register_livein.py",
    "angr_platforms/tests/test_x86_16_pointer_parameter_memory_outputs.py",
    "angr_platforms/tests/test_x86_16_pointer_parameter_object_types.py",
    "angr_platforms/tests/test_x86_16_pointer_parameter_output_pipeline.py",
    "angr_platforms/tests/test_x86_16_direct_stack_replay.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_slot_join.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_prototype_application.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_reaching_defs.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_return_passthrough.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_return_trial_collection.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_return_split.py",
    "angr_platforms/tests/test_x86_16_return_witness_addresses.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_simtypes.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_trial_collection.py",
    "angr_platforms/tests/test_x86_16_modular_input_type_join.py",
    "angr_platforms/tests/test_x86_16_interprocedural_storage_trials.py",
    "angr_platforms/tests/test_x86_16_unused_void_return_types.py",
    "angr_platforms/tests/test_x86_16_return_liveness_replay.py",
    "angr_platforms/tests/test_x86_16_lowered_register_carriers.py",
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
    "angr_platforms/tests/test_sortd_generated_sort_core_gate.py",
    "angr_platforms/tests/test_x86_16_indexed_stack_ranges.py",
    "angr_platforms/tests/test_x86_16_indexed_stack_frame_terms.py",
    "angr_platforms/tests/test_x86_16_call_output_object_projection.py",
    "angr_platforms/tests/test_x86_16_condition_exit_normalization.py",
    "angr_platforms/tests/test_x86_16_structuring_multi_arm_condition_ownership.py",
    "angr_platforms/tests/test_x86_16_local_condition_regions.py",
    "angr_platforms/tests/test_x86_16_structuring_loop_body_repair.py",
    "angr_platforms/tests/test_x86_16_dce_optimization.py",
    "angr_platforms/tests/test_x86_16_dce_purity.py",
    "angr_platforms/tests/test_x86_16_tail_validation_alias_cycles.py",
    "angr_platforms/tests/test_x86_16_validation_owned_condition_precision.py",
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
    "angr_platforms/tests/test_x86_16_cli_c_ast_rewrites.py",
    "angr_platforms/tests/test_x86_16_stack_subview_projection_wide.py",
    "angr_platforms/tests/test_x86_16_widening_rules.py",
    "angr_platforms/tests/test_x86_16_far_load_access_width.py",
    "angr_platforms/tests/test_x86_16_generated_c_acceptance.py",
    "angr_platforms/tests/test_x86_16_sortdemo_decompiler_status.py",
    "angr_platforms/tests/test_x86_16_segment_access_policy.py",
    "angr_platforms/tests/test_x86_16_segment_address_policy.py",
    "angr_platforms/tests/test_x86_16_segment_state.py",
    "angr_platforms/tests/test_x86_16_segment_state_call_boundary.py",
    "angr_platforms/tests/test_x86_16_segment_state_call_outputs.py",
    "angr_platforms/tests/test_x86_16_direct_call_segment_entry.py",
    "angr_platforms/tests/test_x86_16_direct_call_segment_entry_integrity.py",
    "angr_platforms/tests/test_x86_16_direct_call_segment_entry_provenance.py",
    "angr_platforms/tests/test_x86_16_direct_call_segment_context.py",
    "angr_platforms/tests/test_x86_16_memory_offset_word_value.py",
    "angr_platforms/tests/test_x86_16_frontend_block_partition.py",
    "angr_platforms/tests/test_x86_16_segment_function_summary.py",
    "angr_platforms/tests/test_x86_16_segment_contract.py",
    "angr_platforms/tests/test_x86_16_ir_boundary_cfg.py",
    "angr_platforms/tests/test_x86_16_segment_effect_closure.py",
    "angr_platforms/tests/test_x86_16_scoped_ir_view.py",
    "angr_platforms/tests/test_x86_16_near_call_frame_width.py",
    "angr_platforms/tests/test_x86_16_local_call_evidence.py",
    "angr_platforms/tests/test_x86_16_local_evidence_epoch.py",
    "angr_platforms/tests/test_x86_16_invocation_inventory_budgets.py",
    "angr_platforms/tests/test_x86_16_scoped_ir_view_counters.py",
    "angr_platforms/tests/test_x86_16_scoped_ir_coverage.py",
    "angr_platforms/tests/test_x86_16_scoped_ir_function_refusals.py",
    "angr_platforms/tests/test_x86_16_scoped_segment_state.py",
    "angr_platforms/tests/test_x86_16_scoped_resolution_guard.py",
    "angr_platforms/tests/test_x86_16_segment_call_preservation.py",
    "angr_platforms/tests/test_segment_nonleaf_contracts.py",
    "angr_platforms/tests/test_segment_nonleaf_budgets.py",
    "angr_platforms/tests/test_x86_16_input_offset_value.py",
    "angr_platforms/tests/test_x86_16_segment_stack_restore.py",
    "angr_platforms/tests/test_x86_16_stack_restore_ss_identity.py",
    "angr_platforms/tests/test_x86_16_bp_preservation.py",
    "angr_platforms/tests/test_x86_16_stack_restore_constants.py",
    "angr_platforms/tests/test_x86_16_ir_constant_known_lanes.py",
    "angr_platforms/tests/test_x86_16_ir_constant_flow_refusals.py",
    "angr_platforms/tests/test_x86_16_scalar_value_projection.py",
    "angr_platforms/tests/test_x86_16_ir_instruction_origin.py",
    "angr_platforms/tests/test_x86_16_segmented_load_origins.py",
    "angr_platforms/tests/test_x86_16_envsize_behavior.py",
    "angr_platforms/tests/test_x86_16_gp_restore_word_views.py",
    "angr_platforms/tests/test_x86_16_gp_constant_restore.py",
    "angr_platforms/tests/test_x86_16_stack_restore_value_identity.py",
    "angr_platforms/tests/test_x86_16_stack_restore_loops.py",
    "angr_platforms/tests/test_x86_16_gp_restore_binding.py",
    "angr_platforms/tests/test_x86_16_selector_return_projection.py",
    "angr_platforms/tests/test_x86_16_mask_accumulator_effects.py",
    "angr_platforms/tests/test_x86_16_global_sum_effects.py",
    "angr_platforms/tests/test_cli_assignment_effect_preservation.py",
    "angr_platforms/tests/test_x86_16_gp_stack_restore.py",
    "angr_platforms/tests/test_segment_register_membership.py",
    "angr_platforms/tests/test_x86_16_vex_import.py",
    "angr_platforms/tests/test_x86_16_entry_jump_domain.py",
    "angr_platforms/tests/test_x86_16_invocation_domain.py",
    "angr_platforms/tests/test_x86_16_invocation_edge_feasibility.py",
    "angr_platforms/tests/test_x86_16_edge_known_bits_soundness.py",
    "angr_platforms/tests/test_x86_16_unary_value_contract.py",
    "angr_platforms/tests/test_x86_16_unary_fold_contract.py",
    "angr_platforms/tests/test_x86_16_unary_storage_guards.py",
    "angr_platforms/tests/test_x86_16_unary_call_binding.py",
    "angr_platforms/tests/test_x86_16_unary_address_capture.py",
    "angr_platforms/tests/test_x86_16_unary_constant_flow.py",
    "angr_platforms/tests/test_x86_16_invocation_refusal_site.py",
    "angr_platforms/tests/test_x86_16_declared_interrupt_boundary.py",
    "angr_platforms/tests/test_x86_16_declared_interrupt_collision.py",
    "angr_platforms/tests/test_x86_16_invocation_domain_boundaries.py",
    "angr_platforms/tests/test_x86_16_invocation_partition_census.py",
    "angr_platforms/tests/test_x86_16_boot_call_prefix.py",
    "angr_platforms/tests/test_x86_16_invocation_unused_premise.py",
    "angr_platforms/tests/test_optimization_quality_guard_diagnostics.py",
    "angr_platforms/tests/test_x86_16_vex_binop_result_width.py",
    "angr_platforms/tests/test_x86_16_vex_wrtmp_result_width.py",
    "angr_platforms/tests/test_x86_16_vex_direct_constants.py",
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
    "angr_platforms/tests/test_x86_16_ssa_call_target_inputs.py",
    "angr_platforms/tests/test_x86_16_logical_memory_write_value.py",
    "angr_platforms/tests/test_x86_16_logical_constant_word_receipt.py",
    "angr_platforms/tests/test_x86_16_stack_word_call_window.py",
    "angr_platforms/tests/test_x86_16_stack_word_call_binding.py",
    "angr_platforms/tests/test_x86_16_logical_word_read_reaching_value.py",
    "angr_platforms/tests/test_x86_16_far_callback_call_value.py",
    "angr_platforms/tests/test_x86_16_binary_far_callback_targets.py",
    "angr_platforms/tests/test_x86_16_far_callback_call_materialization.py",
    "angr_platforms/tests/test_x86_16_typed_call_argument_path_conditions.py",
    "angr_platforms/tests/test_x86_16_cod_global_identity.py",
    "angr_platforms/tests/test_x86_16_cod_module_caller_evidence.py",
    "angr_platforms/tests/test_x86_16_segmented_global_loads.py",
    "angr_platforms/tests/test_x86_16_wide_store_call_preservation.py",
    "angr_platforms/tests/test_x86_16_global_object_layout.py",
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
    "angr_platforms/tests/test_makefile_variable_expansion.py",
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
    "angr_platforms/tests/test_x86_16_native_terminal_return_values.py",
    "angr_platforms/tests/test_x86_16_native_unsigned_constant_casts.py",
    "angr_platforms/tests/test_x86_16_loadprogram_behavior.py",
    "angr_platforms/tests/test_x86_16_configcrts_behavior.py",
    "angr_platforms/tests/test_x86_16_mset_pos_behavior.py",
    "angr_platforms/tests/test_x86_16_changeweather_behavior.py",
    "angr_platforms/tests/test_x86_16_cli.py::test_decompile_cli_can_extract_and_name_cod_procedure",
    "angr_platforms/tests/test_x86_16_mouse_position_behavior.py",
    "angr_platforms/tests/test_x86_16_native_integer_operations.py",
    "angr_platforms/tests/test_x86_16_ail_remainder.py",
    "angr_platforms/tests/test_x86_16_stack_reference_offsets.py",
    "angr_platforms/tests/test_x86_16_les_stack_argument_behavior.py",
    "angr_platforms/tests/test_x86_16_segment_stack_restore_carriers.py",
    "angr_platforms/tests/test_x86_16_far_return_boundary_carriers.py",
    "angr_platforms/tests/test_x86_16_string_corpus_anchors.py",
    "angr_platforms/tests/test_x86_16_stack_variable_identifier_coordinates.py",
    "angr_platforms/tests/test_x86_16_ss_traversal_contract.py",
    "angr_platforms/tests/test_x86_16_stack_prototype_wrapped_locals.py",
    "angr_platforms/tests/test_x86_16_ast_traversal_coverage.py",
    "angr_platforms/tests/test_x86_16_msetpos_behavior.py",
    "angr_platforms/tests/test_x86_16_projected_stack_argument_identity.py",
    "angr_platforms/tests/test_x86_16_stack_argument_identity.py",
    "angr_platforms/tests/test_x86_16_gp_livein_authority.py",
    "angr_platforms/tests/test_x86_16_wide_condition_provenance.py",
    "angr_platforms/tests/test_x86_16_anonymous_store_width.py",
    "angr_platforms/tests/test_x86_16_ssa_register_displacements.py",
    "angr_platforms/tests/test_x86_16_stack_coordinate_conflicts.py",
    "angr_platforms/tests/test_x86_16_escaped_stack_validation.py",
    "angr_platforms/tests/test_x86_16_bios_strict_compilation.py",
    "angr_platforms/tests/test_x86_16_rep_store_codegen.py",
    "angr_platforms/tests/test_x86_16_string_timeout_fallback.py",
    "angr_platforms/tests/test_x86_16_ir_memory_byte_ssa.py",
    "angr_platforms/tests/test_x86_16_string_codegen_override.py",
    "angr_platforms/tests/test_cli_codegen_policy.py",
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
    "angr_platforms/tests/test_x86_16_cod_regressions.py::test_cod_loadprog_preserves_binary_arguments_and_recompiles",
    "angr_platforms/tests/test_cod_openfilewrapper_consolidation.py",
    "angr_platforms/tests/test_x86_16_near_pointer_argument_evidence.py",
    "angr_platforms/tests/test_x86_16_near_pointer_index_binding.py",
    "angr_platforms/tests/test_project_loading_diagnostics.py",
    "angr_platforms/tests/test_cli_interrupt_call_boundary.py",
    "angr_platforms/tests/test_x86_16_annotation_argument_identity.py",
    "angr_platforms/tests/test_x86_16_assignment_lvalue_casts.py",
    "angr_platforms/tests/test_x86_16_stack_byte_writes.py",
    "angr_platforms/tests/test_x86_16_instruction_stack_write_width.py",
    "angr_platforms/tests/test_x86_16_semantic_cast.py",
    "angr_platforms/tests/test_x86_16_condition_operand_signedness.py",
    "angr_platforms/tests/test_x86_16_condition_signedness_storage_width.py",
    "angr_platforms/tests/test_x86_16_validation_argument_coordinates.py",
    "angr_platforms/tests/test_x86_16_validation_loop_condition_ir.py",
    "angr_platforms/tests/test_x86_16_condition_storage_views.py",
    "angr_platforms/tests/test_x86_16_wide_stack_pair_coordinates.py",
    "angr_platforms/tests/test_x86_16_inbox_long_live.py",
    "angr_platforms/tests/test_x86_16_wide_return_condition_coverage.py",
    "angr_platforms/tests/test_x86_16_setgear_behavior.py",
    "angr_platforms/tests/test_x86_16_tidshowrange_behavior.py",
    "angr_platforms/tests/test_x86_16_cli.py::test_decompile_cli_recovers_setgear_guard_logic",
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
    "angr_platforms/tests/test_x86_16_heapsort_behavior.py",
    "angr_platforms/tests/test_x86_16_quicksort_behavior.py",
    "angr_platforms/tests/test_x86_16_sleep_behavior.py",
    "angr_platforms/tests/test_x86_16_insertionsort_behavior.py",
    "angr_platforms/tests/test_x86_16_swapbars_behavior.py",
    "angr_platforms/tests/test_x86_16_gp_word_runtime.py::test_lowering_initializes_fresh_codegen_and_preserves_explicit_legacy_abi",
    "angr_platforms/tests/test_x86_16_gp_word_runtime.py::test_default_msc6_provider_matches_production_lowering",
    "angr_platforms/tests/test_x86_16_gp_word_runtime.py::test_lowering_rejects_corrupt_existing_abi_before_processing_ast",
    "angr_platforms/tests/test_x86_16_gp_word_runtime.py::test_final_result_cache_tracks_gp_runtime_and_projection_owners",
    "angr_platforms/tests/test_x86_16_gp_word_runtime.py::test_word_runtime_covers_existing_architectural_lanes",
    "angr_platforms/tests/test_x86_16_gp_word_runtime.py::test_compiled_shared_views_preserve_upper_words_and_wrap",
    "angr_platforms/tests/test_x86_16_gp_word_assignment.py",
    "angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortd_sidecar_free_swapbars_recovers_binary_stack_arguments",
    "angr_platforms/tests/test_x86_16_reinitbars_execution.py",
    "angr_platforms/tests/test_test_ownership_validation.py",
    "angr_platforms/tests/test_x86_16_address_base_snapshots.py",
    "angr_platforms/tests/test_x86_16_memory_ssa_address_provenance.py",
    "angr_platforms/tests/test_x86_16_ir_stack_frame.py",
    "angr_platforms/tests/test_x86_16_vex_memory_access_fidelity.py",
    "angr_platforms/tests/test_makefile_quiet_output.py",
    "angr_platforms/tests/test_inertia_telemetry.py",
    "angr_platforms/tests/test_x86_16_canonical_frame_setup_carriers.py",
    "angr_platforms/tests/test_x86_16_stack_compat.py",
    "angr_platforms/tests/test_x86_16_load_propagation.py",
    "angr_platforms/tests/test_x86_16_stack_address_operand_roles.py",
    "angr_platforms/tests/test_x86_16_numeric_sp_call_return.py",
    "angr_platforms/tests/test_x86_16_call_frame_compat.py",
    "angr_platforms/tests/test_x86_16_callee_cleanup_compat.py",
    "angr_platforms/tests/test_x86_16_stack_pointer_provenance.py",
    "angr_platforms/tests/test_x86_16_stack_extent_evidence.py",
    "angr_platforms/tests/test_x86_16_logical_frame_accesses.py",
    "angr_platforms/tests/test_x86_16_stack_address_escape.py",
    "angr_platforms/tests/test_x86_16_private_stack_writes.py",
    "angr_platforms/tests/test_x86_16_ir_terminal_control_flow.py",
    "angr_platforms/tests/test_x86_16_ail_register_displacement.py",
    "angr_platforms/tests/test_x86_16_call_return_segment.py",
    "angr_platforms/tests/test_x86_16_stack_pointer_width.py",
    "angr_platforms/tests/test_x86_16_lifted_integer_constants.py",
    "angr_platforms/tests/test_x86_16_codegen_parentheses.py",
    "angr_platforms/tests/test_x86_16_local_declarations.py",
    "angr_platforms/tests/test_x86_16_terminal_call_return_types.py",
    "angr_platforms/tests/test_x86_16_seed_calling_dependencies.py",
    "angr_platforms/tests/test_x86_16_stack_value_owner_identity.py",
    "angr_platforms/tests/test_x86_16_tagged_terminal_return_values.py",
    "angr_platforms/tests/test_x86_16_branch_return_expressions.py",
    "angr_platforms/tests/test_recompile_check.py",
    "angr_platforms/tests/test_workspace_sandbox.py",
    "angr_platforms/tests/test_cli_catalog_budget.py",
    "angr_platforms/tests/test_missing_dos_toolchain.py",
    "angr_platforms/tests/test_x86_16_pklite.py",
    "angr_platforms/tests/test_x86_16_debug.py",
    "angr_platforms/tests/test_msc6_runtime_state.py",
    "angr_platforms/tests/test_x86_16_telemetry_support.py",
    "angr_platforms/tests/test_x86_16_switch_segment_diagnostics.py",
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
    "angr_platforms/tests/test_x86_16_overlay_return_behavior.py",
    "angr_platforms/tests/test_x86_16_gp_register_versions.py",
    "angr_platforms/tests/test_x86_16_validation_indexed_bytes.py",
    "angr_platforms/tests/test_x86_16_gp_register_state.py",
    "angr_platforms/tests/test_x86_16_return_stack_address_compat.py",
    "angr_platforms/tests/test_x86_16_helper_abi.py",
    "angr_platforms/tests/test_x86_16_fixed_stack_probe_frames.py",
    "angr_platforms/tests/test_x86_16_far_probe_lifting.py",
    "angr_platforms/tests/test_x86_16_structuring_pass_validation.py",
    "angr_platforms/tests/test_x86_16_symbolic_value_boundaries.py",
    "angr_platforms/tests/test_x86_16_direction_flag_execution.py",
    "angr_platforms/tests/test_x86_16_stack_helpers.py",
    "angr_platforms/tests/test_x86_16_memory.py",
)

# Measured actual-binary SMT/replay controls run in default/expanded tiers.
# Keep admission/projection contracts in the fast unit lane.
RELATIONAL_BINARY_PYTEST_TARGETS: tuple[str, ...] = (
    "angr_platforms/tests/test_ordered_io_native.py",
    "angr_platforms/tests/test_ordered_io_native_extended.py",
    "angr_platforms/tests/test_x86_16_immediate_port_vex.py",
    "angr_platforms/tests/test_m4_exit_controls.py",
    "angr_platforms/tests/test_m4_pe32_relations.py",
    "angr_platforms/tests/test_flat32_loop_calls_public.py",
    "angr_platforms/tests/test_flat32_dependency_cache.py",
    "angr_platforms/tests/test_replay_capture_cohorts.py",
    "angr_platforms/tests/test_binary_callee_repeat_intake.py",
    "angr_platforms/tests/test_dosunit_kvikdos_strict_native.py",
    "angr_platforms/tests/test_dosunit_kvikdos_worker_native.py",
    "angr_platforms/tests/test_x86_16_clinic_binary_terminal_control.py",
    "angr_platforms/tests/test_binary_callee_region_scan.py",
    "angr_platforms/tests/test_binary_callee_region_intake.py",
    "angr_platforms/tests/test_ssa_declared_scope.py",
    "angr_platforms/tests/test_real16_program_replay.py",
    "angr_platforms/tests/test_pe32_program_replay.py",
    "angr_platforms/tests/test_pe32_program_cli.py",
    "angr_platforms/tests/test_real16_program_output_integration.py",
    "angr_platforms/tests/test_real16_program_input_integration.py",
    "angr_platforms/tests/test_real16_program_file_copy.py",
    "angr_platforms/tests/test_real16_program_cli.py",
    "angr_platforms/tests/test_binary_callee_intake.py",
    "angr_platforms/tests/test_binary_callee_intake_review.py",
    "angr_platforms/tests/test_real16_uncatalogued_calls.py",
    "angr_platforms/tests/test_recursive_call_continuation_binding.py",
    "angr_platforms/tests/test_real16_admission_control_domains.py",
    "angr_platforms/tests/test_recursive_joint_actual_binary.py",
    "angr_platforms/tests/test_flat32_pe32_recursive_joint.py",
    "angr_platforms/tests/test_real16_recursive_public.py",
    "angr_platforms/tests/test_pe32_recursive_public.py",
    "angr_platforms/tests/test_symbolic_terminal.py",
    "angr_platforms/tests/test_symbolic_terminal_services.py",
    "angr_platforms/tests/test_symbolic_terminal_service_census.py",
    "angr_platforms/tests/test_pe32_import_service.py",
    "angr_platforms/tests/test_pe32_import_service_schema.py",
    "angr_platforms/tests/test_pe32_import_service_cli.py",
    "angr_platforms/tests/test_symbolic_terminal_configured_limits.py",
    "angr_platforms/tests/test_symbolic_terminal_pe32_thunk_census.py",
    "angr_platforms/tests/test_symbolic_terminal_ivt_precision.py",
    "angr_platforms/tests/test_symbolic_terminal_cli.py",
    "angr_platforms/tests/test_symbolic_terminal_faults.py",
    "angr_platforms/tests/test_real16_indirect_call_composition.py",
    "angr_platforms/tests/test_real16_indirect_call_multiarm.py",
    "angr_platforms/tests/test_symbolic_terminal_signed_divmod.py",
    "angr_platforms/tests/test_dosunit_signed_divmod.py",
    "angr_platforms/tests/test_flat32_loop_call_failure_report.py",
    "angr_platforms/tests/test_symbolic_terminal_read_permissions.py",
    "angr_platforms/tests/test_symbolic_terminal_partial_pe_data.py",
    "angr_platforms/tests/test_symbolic_terminal_output_coverage.py",
    "angr_platforms/tests/test_real16_normal_outcome_scope.py",
    "angr_platforms/tests/test_real16_bound_control_scope.py",
    "angr_platforms/tests/test_real16_symbolic_call_control.py",
    "angr_platforms/tests/test_real16_symbolic_successors.py",
    "angr_platforms/tests/test_x86_16_relative_control_edge.py",
    "angr_platforms/tests/test_unicorn_engine_bounds.py",
    "angr_platforms/tests/test_x86_16_relative_condition_producers.py",
    "angr_platforms/tests/test_real16_native_control_scope.py",
    "angr_platforms/tests/test_real16_native_control_scope_edges.py",
    "angr_platforms/tests/test_real16_address_model_closure.py",
    "angr_platforms/tests/test_real16_loader_arch.py",
    "angr_platforms/tests/test_real16_direct_jmp_coordinates.py",
    "angr_platforms/tests/test_direct_near_call_target_binding.py",
    "angr_platforms/tests/test_x86_16_declared_call_consumption.py",
    "angr_platforms/tests/test_declared_call_transport.py",
    "angr_platforms/tests/test_projected_call_consumption.py",
    "angr_platforms/tests/test_declared_call_admission.py",
    "angr_platforms/tests/test_declared_call_schema.py",
    "angr_platforms/tests/test_declared_call_binding.py",
    "angr_platforms/tests/test_x86_16_native_helper_call_retention.py",
    "angr_platforms/tests/test_segment_call_binding_regression.py",
    "angr_platforms/tests/test_segment_nonleaf_native.py",
    "angr_platforms/tests/test_nop_census_8616.py",
    "angr_platforms/tests/test_nop_native_binding.py",
    "angr_platforms/tests/test_nop_cache_cost.py",
    "angr_platforms/tests/test_recursive_terminal_address_boundary.py",
    "angr_platforms/tests/test_recursive_static_control_shifts.py",
    "angr_platforms/tests/test_recursive_fetched_code_invariant.py",
    "angr_platforms/tests/test_x86_16_near_pointer_native_runtime.py",
    "angr_platforms/tests/test_real16_return_coordinates.py",
    'angr_platforms/tests/test_real16_branch_regions.py',
    'angr_platforms/tests/test_real16_rotation_regions.py',
    'angr_platforms/tests/test_flat32_rotation_regions.py',
    'angr_platforms/tests/test_rotation_concrete_replay.py',
    'angr_platforms/tests/test_relational_branch_public32.py',
    "angr_platforms/tests/test_macro_step_proof.py",
    "angr_platforms/tests/test_real16_region_control.py",
    "angr_platforms/tests/test_macro_step_admission.py",
    "angr_platforms/tests/test_macro_step_deadlines.py",
    "angr_platforms/tests/test_macro_step_concat_exhaustion.py",
    "angr_platforms/tests/test_macro_step_return_state.py",
    "angr_platforms/tests/test_flat32_macro_retry.py",
    "angr_platforms/tests/test_flat32_term_budget.py",
    'angr_platforms/tests/test_relational_rotation_public32.py',
    'angr_platforms/tests/test_relational_saved_public32.py',
    'angr_platforms/tests/test_relational_saved_public16.py',
)

MSC6_TINY_CONSTRUCTS: tuple[str, ...] = (
    "compare16",
    "mixwidth",
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
    "binary-budgeted": 120.0,
    "unit-focused": 30.0,
    "binary-relational": 300.0,
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
    "fast": ("binary-budgeted", "unit-focused", "pytest-serial", "linux-process-controls"),
    "default": ("binary-budgeted", "unit-focused", "pytest-serial", "linux-process-controls", "makefile-gnu-oracle", "gp-word-native", "binary-relational", "ultra-quickc-fixtures", "msc6-tiny-full-pipeline"),
    "expanded": (
        "binary-budgeted",
        "unit-focused",
        "pytest-serial",
        "linux-process-controls",
        "makefile-gnu-oracle",
        "gp-word-native",
        "binary-relational",
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


def _budgeted_binary_lane(workers: int = PYTEST_WORKER_COUNT) -> LaneResult:
    """Keep wall-budgeted proofs outside the broad worker pool without raising limits."""
    return _run_command(
        "binary-budgeted",
        [
            sys.executable, "-m", "pytest", "-p", "scripts.pytest_live_failures",
            "-q", "--tb=short", "-n", str(min(workers, BUDGETED_BINARY_WORKERS)),
            "--dist", "loadgroup", "--durations=10",
            *BUDGETED_BINARY_PYTEST_TARGETS,
        ],
    )


def _unit_lane(workers: int = PYTEST_WORKER_COUNT) -> LaneResult:
    """Run the focused inventory with the selected bounded worker count."""
    return _run_command(
        "unit-focused",
        [
            sys.executable,
            "-m",
            "pytest",
            "-p", "scripts.pytest_directory_cache", "-p", "scripts.pytest_live_failures",
            "-q",
            "--tb=short",
            "-n",
            str(workers),
            "--dist",
            "loadgroup",
            "--durations=10",
            "--durations-min=1.0",
            *FOCUSED_PYTEST_TARGETS,
        ],
    )


def _guarded_pytest_lane(
    name: str, targets: tuple[str, ...], *, expected_cases: int = 1, require_available: bool = False, strict_count: bool = False,
) -> LaneResult:
    """Run guarded controls serially and retain skipped or absent coverage."""
    with tempfile.TemporaryDirectory(prefix="inertia-control-") as directory:
        receipt = Path(directory) / "junit.xml"
        command = [
            sys.executable, "-m", "pytest", "-p", "scripts.pytest_live_failures",
            "-q", "--tb=short", "-n", "0", "-o", "addopts=", "--durations=10",
            "--junitxml", str(receipt), *targets,
        ]
        environment = {**os.environ, "PYTEST_ADDOPTS": ""}
        environment.pop("PYTEST_XDIST_WORKER", None)
        result = _run_command(name, command, env=environment)
        if result.status is not LaneStatus.PASSED:
            return result
        if not receipt.is_file():
            return replace(result, status=LaneStatus.FAILED, reason="pytest did not retain its control receipt")
        try:
            cases = ElementTree.parse(receipt).findall(".//testcase")
        except ElementTree.ParseError as error:
            return replace(result, status=LaneStatus.FAILED, reason=f"invalid pytest control receipt: {error}")
        skipped = [item for case in cases if (item := case.find("skipped")) is not None]
        failed = sum(case.find("failure") is not None or case.find("error") is not None for case in cases)
        details: dict[str, object] = {
            "collected": len(cases), "passed": len(cases) - len(skipped) - failed,
            "skipped": len(skipped), "failed": failed,
            "skip_reasons": [item.attrib.get("message", "") for item in skipped],
        }
        if failed or not cases or ((strict_count or not skipped) and len(cases) != expected_cases):
            return replace(result, status=LaneStatus.FAILED, reason="pytest control coverage incomplete or failed", details=details)
        if skipped:
            return replace(
                result, status=LaneStatus.FAILED if require_available else LaneStatus.SKIPPED,
                reason="pytest control skipped required coverage" if require_available else "pytest control unavailable",
                details=details,
            )
        return replace(result, details=details)


def _serial_pytest_lane(targets: tuple[str, ...] = SERIAL_PYTEST_TARGETS) -> LaneResult:
    """Execute both nested-pytest cases after every outer worker has exited."""
    expected_cases = sum(1 if "[" in target else 2 for target in targets)
    return _guarded_pytest_lane("pytest-serial", targets, expected_cases=expected_cases, require_available=True)


def _linux_process_lane(targets: tuple[str, ...] = LINUX_PROCESS_PYTEST_TARGETS) -> LaneResult:
    """Execute descendant controls on Linux and account for unsupported hosts."""
    if sys.platform != "linux":
        return LaneResult("linux-process-controls", LaneStatus.SKIPPED, [], 0.0, reason=f"requires Linux, got {sys.platform}")
    expected_cases = sum(1 if "[" in target else LINUX_PROCESS_CASE_COUNTS[target] for target in targets)
    return _guarded_pytest_lane("linux-process-controls", targets, expected_cases=expected_cases, require_available=True)


def _gp_word_native_lane(args: argparse.Namespace, targets: tuple[str, ...] = GP_NATIVE_PYTEST_TARGETS) -> LaneResult:
    """Require real DOS GP-word execution or report unavailable external evidence."""
    name = "gp-word-native"
    command = [sys.executable, "-m", "pytest", "-n", "0", *targets]
    if args.kvikdos != DEFAULT_KVIKDOS or args.msc6_root != DEFAULT_MSC6_ROOT:
        return LaneResult(name, LaneStatus.FAILED, command, 0.0, reason="GP-word control requires the default compiler/runtime paths")
    available, reason = _external_tools_available(DEFAULT_KVIKDOS, DEFAULT_MSC6_ROOT)
    if not available:
        return _missing_external_lane(name, command, reason=reason, require_external=args.require_external)
    evidence = kvm_access_evidence()
    if evidence.status is not KVMAccessStatus.READ_WRITE:
        return _missing_external_lane(
            name, command, reason=f"requires writable /dev/kvm ({evidence.status.value}, errno={evidence.error_number})",
            require_external=args.require_external,
        )
    return _guarded_pytest_lane(name, targets, require_available=args.require_external)


def _makefile_gnu_oracle_lane(
    args: argparse.Namespace, targets: tuple[str, ...] = GNU_MAKE_ORACLE_PYTEST_TARGETS,
) -> LaneResult:
    """Retain exact GNU oracle coverage or an explicit unavailable-tool result."""
    name = "makefile-gnu-oracle"
    command = [sys.executable, "-m", "pytest", "-n", "0", *targets]
    if any(target.partition("[")[0] not in GNU_MAKE_ORACLE_CASE_COUNTS for target in targets):
        return LaneResult(name, LaneStatus.FAILED, command, 0.0, reason="unknown GNU Make oracle selector")
    if shutil.which("make") is None:
        return _missing_external_lane(name, command, reason="make oracle unavailable", require_external=args.require_external)
    expected_cases = sum(1 if "[" in target else GNU_MAKE_ORACLE_CASE_COUNTS[target] for target in targets)
    return _guarded_pytest_lane(name, targets, expected_cases=expected_cases, require_available=args.require_external, strict_count=True)


def _selected_control_targets(selected: list[str] | None, defaults: tuple[str, ...]) -> tuple[str, ...]:
    """Retain explicitly selected guarded cases instead of widening their scope."""
    matching = tuple(target for target in selected or () if target.partition("[")[0] in defaults)
    return matching or defaults


def _relational_binary_lane(workers: int = PYTEST_WORKER_COUNT) -> LaneResult:
    """Run measured complete binary proofs and replay with bounded worker count."""
    return _run_command(
        "binary-relational",
        [
            sys.executable, "-m", "pytest", "-p", "scripts.pytest_directory_cache",
            "-p", "scripts.pytest_live_failures", "-q", "-n", str(workers),
            "--dist", "loadgroup", "--tb=short", "--durations=10",
            *RELATIONAL_BINARY_PYTEST_TARGETS,
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
    """Parse pipeline lanes, bounded test concurrency and external tool options."""
    parser = argparse.ArgumentParser(description="Run the curated decompiler regression pipeline.")
    parser.add_argument("--tier", choices=tuple(PIPELINE_TIERS), default="default")
    parser.add_argument(
        "--lane",
        action="append",
        choices=(
            "binary-budgeted",
            "unit-focused",
            "pytest-serial",
            "linux-process-controls",
            "makefile-gnu-oracle",
            "gp-word-native",
            "binary-relational",
            "ultra-quickc-fixtures",
            "msc6-tiny-smoke",
            "msc6-tiny-full-pipeline",
            "sortdemo-status",
            "sortdemo-status-proc-diagnostic",
            "sortd-sidecar-free",
        ),
    )
    parser.add_argument("--print-host-controls", action="store_true")
    parser.add_argument("--control-target", action="append")
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
    parser.add_argument(
        "--pytest-workers", type=int, choices=range(1, 7), default=PYTEST_WORKER_COUNT,
        help="Pytest workers per sequential test lane (1-6; default: 3).",
    )
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
    if args.print_host_controls:
        print(" ".join(target for target in FOCUSED_PYTEST_TARGETS if target.partition("::")[0] in SPLIT_CONTROL_TEST_FILES))
        return 0
    lane_names = _selected_lanes(args)
    lane_fns: dict[str, Callable[[], LaneResult]] = {
        "binary-budgeted": lambda: _budgeted_binary_lane(args.pytest_workers),
        "unit-focused": lambda: _unit_lane(args.pytest_workers),
        "pytest-serial": lambda: _serial_pytest_lane(_selected_control_targets(args.control_target, SERIAL_PYTEST_TARGETS)),
        "linux-process-controls": lambda: _linux_process_lane(_selected_control_targets(args.control_target, LINUX_PROCESS_PYTEST_TARGETS)),
        "makefile-gnu-oracle": lambda: _makefile_gnu_oracle_lane(args, tuple(target for target in args.control_target or () if target.partition("::")[0] == GNU_MAKE_ORACLE_TEST_FILE) or GNU_MAKE_ORACLE_PYTEST_TARGETS),
        "gp-word-native": lambda: _gp_word_native_lane(args, _selected_control_targets(args.control_target, GP_NATIVE_PYTEST_TARGETS)),
        "binary-relational": lambda: _relational_binary_lane(args.pytest_workers),
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
