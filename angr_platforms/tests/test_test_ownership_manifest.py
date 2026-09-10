from __future__ import annotations

import subprocess
import sys

import pytest

from scripts import test_ownership_manifest

EXISTING_SOURCE_PATH = "scripts/test_ownership_manifest.py"


@pytest.mark.parametrize("invocation", [("-m", "scripts.test_ownership_manifest"), ("scripts/test_ownership_manifest.py",)])
def test_manifest_execution_modes_select_identical_tests(invocation):
    source = "angr_platforms/angr_platforms/X86_16/ir/register_live_in.py"
    result = subprocess.run(
        [sys.executable, *invocation, source], cwd=test_ownership_manifest.REPO_ROOT,
        capture_output=True, text=True, check=False, timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == list(test_ownership_manifest.select_tests_for_files((source,)))


def test_selects_manifest_tests_for_implementation_file():
    selected = test_ownership_manifest.select_tests_for_files(("scripts/test_pipeline.py",))

    assert selected == (
        "angr_platforms/tests/test_check_sortd_sidecar_free.py",
        "angr_platforms/tests/test_test_pipeline.py",
    )


def test_selects_agent_context_check_tests_for_implementation_file():
    selected = test_ownership_manifest.select_tests_for_files(("scripts/agent_context_check.py",))

    assert selected == ("angr_platforms/tests/test_agent_context_check.py",)


def test_selects_type_ratchet_tests_for_implementation_file():
    selected = test_ownership_manifest.select_tests_for_files(("scripts/check_changed_non_test_types.py",))

    assert selected == ("angr_platforms/tests/test_check_changed_non_test_types.py",)


def test_selects_positive_bp_argument_plan_tests() -> None:
    selected = test_ownership_manifest.select_tests_for_files(
        ("angr_platforms/angr_platforms/X86_16/lowering/positive_bp_argument_plan.py",)
    )

    assert selected == (
        "angr_platforms/tests/test_x86_16_positive_bp_argument_plan.py",
        "angr_platforms/tests/test_x86_16_stack_argument_identity.py",
    )


def test_selects_ultra_quickc_fixture_tests_for_implementation_file():
    selected = test_ownership_manifest.select_tests_for_files(("scripts/import_ultra_quickc_fixtures.py",))

    assert selected == ("angr_platforms/tests/test_import_ultra_quickc_fixtures.py",)


def test_selects_real_mode_linear_focused_tests_for_implementation_file():
    selected = test_ownership_manifest.select_tests_for_files(
        ("angr_platforms/angr_platforms/X86_16/lowering/real_mode_linear.py",)
    )

    assert selected == (
        "angr_platforms/tests/test_x86_16_stack_reload_instruction_ownership.py",
        "angr_platforms/tests/test_x86_16_machine_stack_names.py",
        "angr_platforms/tests/test_x86_16_direct_stack_replay.py",
        "angr_platforms/tests/test_x86_16_direct_stack_reload_idempotence.py",
        "angr_platforms/tests/test_x86_16_linear_global_decomposition_cache.py",
        "angr_platforms/tests/test_x86_16_postprocess_snapshot.py",
        "angr_platforms/tests/test_x86_16_tail_validation.py::"
        "test_postprocess_optimization_reuses_witness_without_hiding_mutation",
        "angr_platforms/tests/test_x86_16_consumed_push_lvalues.py",
        "angr_platforms/tests/test_x86_16_segment_access_coverage.py",
        "angr_platforms/tests/test_x86_16_segment_access_policy.py",
        "angr_platforms/tests/test_x86_16_segment_address_policy.py",
        "angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py::"
        "test_materialize_direct_stack_mov_signed_half_inserts_before_outer_branch_first_use",
        "angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py::"
        "test_materialize_direct_stack_mov_signed_half_inserts_before_first_stack_use_without_tagged_stmt",
        "angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py::"
        "test_materialize_direct_stack_mov_arg_copy_inserts_inside_else_after_prior_stack_assignment",
    )


def test_selects_segment_global_materialization_owner_tests():
    selected = test_ownership_manifest.select_tests_for_files(
        ("angr_platforms/angr_platforms/X86_16/lowering/segment_global_materialization.py",)
    )

    assert selected == (
        "angr_platforms/tests/test_x86_16_segmented_global_loads.py",
        "angr_platforms/tests/test_x86_16_structuring_pass_validation.py",
        "angr_platforms/tests/test_x86_16_decompiler_postprocess_return_chain.py",
    )

def test_selects_pipeline_invariant_tests_for_implementation_file():
    selected = test_ownership_manifest.select_tests_for_files(
        ("angr_platforms/angr_platforms/X86_16/pipeline/invariants.py",)
    )

    assert selected == ("angr_platforms/tests/test_x86_16_rewrite_boundary.py",)


def test_selects_final_emission_guard_tests_for_architecture_guard_file():
    selected = test_ownership_manifest.select_tests_for_files(
        ("angr_platforms/angr_platforms/X86_16/pipeline/architecture_guard.py",)
    )

    assert selected == (
        "angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py::"
        "test_architecture_guard_rejects_raw_linear_segment_arithmetic",
        "angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py::"
        "test_architecture_guard_ignores_forbidden_tokens_inside_comments",
        "angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py::"
        "test_architecture_guard_rejects_unreachable_call_after_return",
        "angr_platforms/tests/test_x86_16_segmented_runtime_lowering.py::"
        "test_architecture_guard_rejects_unary_not_shift_precedence_leak",
    )


def test_selects_validation_semantics_tests_for_root_validation_file():
    selected = test_ownership_manifest.select_tests_for_files(
        ("angr_platforms/angr_platforms/X86_16/validation_semantics.py",)
    )

    assert selected == ("angr_platforms/tests/test_x86_16_validation_semantics.py",)


def test_selects_validation_dataflow_tests_for_root_validation_file():
    selected = test_ownership_manifest.select_tests_for_files(
        ("angr_platforms/angr_platforms/X86_16/validation_dataflow.py",)
    )

    assert selected == (
        "angr_platforms/tests/test_x86_16_validation_dataflow.py",
        "angr_platforms/tests/test_x86_16_validation_predicates.py",
        "angr_platforms/tests/test_x86_16_validation_virtual_carriers.py",
    )


def test_selects_validation_semantic_failure_tests_for_owner_file():
    selected = test_ownership_manifest.select_tests_for_files(
        ("angr_platforms/angr_platforms/X86_16/validation_semantic_failures.py",)
    )

    assert selected == (
        "angr_platforms/tests/test_x86_16_validation_semantic_failures.py",
    )


def test_selects_indexed_address_owner_for_ir_core():
    selected = test_ownership_manifest.select_tests_for_files(
        ("angr_platforms/angr_platforms/X86_16/ir/core.py",)
    )

    assert selected == (
        "angr_platforms/tests/test_x86_16_indexed_address_copies.py::"
        "test_main_path_publishes_ir_and_alias_copy_evidence_atomically",
        "angr_platforms/tests/test_x86_16_indexed_address_aliases.py::"
        "test_indexed_load_projects_symbolic_target_and_exact_stack_source",
        "angr_platforms/tests/test_x86_16_indexed_address_collector_parity.py::"
        "test_real_indexed_load_collectors_have_exact_identity_parity",
        "angr_platforms/tests/test_x86_16_indexed_address_parity_inventory.py::"
        "test_identity_conflict_is_classified_on_exact_instruction_site",
        "angr_platforms/tests/test_x86_16_sortd_indexed_address_parity_inventory.py",
        "angr_platforms/tests/test_x86_16_indexed_address_evidence.py",
        "angr_platforms/tests/test_x86_16_scalar_affine_trace.py",
        "angr_platforms/tests/test_x86_16_indexed_address_range_candidates.py",
        "angr_platforms/tests/test_x86_16_indexed_global_object_program_ranges.py",
        "angr_platforms/tests/test_x86_16_indexed_global_object_ranges.py",
        "angr_platforms/tests/test_x86_16_bounded_global_array_declarations.py",
        "angr_platforms/tests/test_x86_16_sortd_indexed_loop_topology.py",
        "angr_platforms/tests/test_x86_16_alias_global_object_layout.py",
        "angr_platforms/tests/test_x86_16_ir_core.py",
        "angr_platforms/tests/test_x86_16_ir_ssa.py",
        "angr_platforms/tests/test_x86_16_vex_memory_access_fidelity.py",
    )


def test_selects_semantics_layer_fallback_for_unowned_semantics_file():
    selected = test_ownership_manifest.select_tests_for_files(
        ("angr_platforms/angr_platforms/X86_16/semantics/branch_target_return.py",)
    )

    assert selected == ("angr_platforms/tests/test_x86_16_compare_semantics.py",)


def test_selects_structuring_layer_fallback_for_unowned_structuring_file():
    selected = test_ownership_manifest.select_tests_for_files(
        ("angr_platforms/angr_platforms/X86_16/structuring/control_flow.py",)
    )

    assert selected == ("angr_platforms/tests/test_x86_16_structuring_pass_validation.py",)


def test_specific_rule_takes_precedence_over_layer_fallback():
    selected = test_ownership_manifest.select_tests_for_files(
        ("angr_platforms/angr_platforms/X86_16/lowering/condition_transfer.py",)
    )

    assert selected == (
        "angr_platforms/tests/test_x86_16_condition_cache_relift.py",
        "angr_platforms/tests/test_x86_16_condition_transfer.py",
    )


def test_selects_tail_validation_family_tests_for_related_modules():
    selected = test_ownership_manifest.select_tests_for_files(
        ("angr_platforms/angr_platforms/X86_16/tail_validation_fingerprint.py",)
    )

    assert selected == (
        "angr_platforms/tests/test_x86_16_tail_validation.py",
        "angr_platforms/tests/test_x86_16_tail_validation_fingerprint.py",
        "angr_platforms/tests/test_x86_16_tail_validation_routing.py",
    )


def test_selects_tail_validation_routing_test_for_routing_module():
    selected = test_ownership_manifest.select_tests_for_files(
        ("angr_platforms/angr_platforms/X86_16/tail_validation_routing.py",)
    )

    assert selected == ("angr_platforms/tests/test_x86_16_tail_validation_routing.py",)


def test_selects_validation_package_tests_for_canonicalizer():
    selected = test_ownership_manifest.select_tests_for_files(
        ("angr_platforms/angr_platforms/X86_16/validation/canonicalize.py",)
    )

    assert selected == ("angr_platforms/tests/test_x86_16_validation_canonicalize.py",)


def test_selects_type_array_matching_tests_for_implementation_file():
    selected = test_ownership_manifest.select_tests_for_files(
        ("angr_platforms/angr_platforms/X86_16/type_array_matching.py",)
    )

    assert selected == (
        "angr_platforms/tests/test_generic_annotation_contracts.py",
        "angr_platforms/tests/test_x86_16_array_matching.py",
    )


def test_selects_type_equivalence_classes_tests_for_implementation_file():
    selected = test_ownership_manifest.select_tests_for_files(
        ("angr_platforms/angr_platforms/X86_16/type_equivalence_classes.py",)
    )

    assert selected == ("angr_platforms/tests/test_x86_16_type_equivalence_classes.py",)


def test_selects_type_structure_merging_tests_for_implementation_file():
    selected = test_ownership_manifest.select_tests_for_files(
        ("angr_platforms/angr_platforms/X86_16/type_structure_merging.py",)
    )

    assert selected == ("angr_platforms/tests/test_x86_16_struct_merging.py",)


def test_selects_postprocess_stage_direct_stack_validation_tests_for_implementation_file():
    selected = test_ownership_manifest.select_tests_for_files(
        ("angr_platforms/angr_platforms/X86_16/decompiler_postprocess_stage.py",)
    )

    assert selected == (
        "angr_platforms/tests/test_decompiler_architecture_check.py",
        "angr_platforms/tests/test_x86_16_jcc_instruction_reuse.py",
        "angr_platforms/tests/test_x86_16_jcc_typed_condition_order.py",
        "angr_platforms/tests/test_x86_16_decompiler_postprocess_utils.py",
        "angr_platforms/tests/test_x86_16_postprocess_snapshot.py::"
        "test_direct_stack_move_materialization_delta_accepts_evidenced_loop_body_write_precision",
        "angr_platforms/tests/test_x86_16_postprocess_snapshot.py::"
        "test_direct_stack_move_materialization_delta_accepts_for_body_global_high_byte_precision",
        "angr_platforms/tests/test_x86_16_postprocess_snapshot.py::"
        "test_direct_stack_move_materialization_delta_refuses_unrelated_for_body_global_precision",
    )


def test_selects_postprocess_callsite_argument_tests_for_implementation_file():
    selected = test_ownership_manifest.select_tests_for_files(
        ("angr_platforms/angr_platforms/X86_16/decompiler_postprocess_calls.py",)
    )

    assert selected == (
        "angr_platforms/tests/test_x86_16_stack_probe_local_preservation.py",
        "angr_platforms/tests/test_decompiler_architecture_check.py",
        "angr_platforms/tests/test_x86_16_jcc_instruction_reuse.py",
        "angr_platforms/tests/test_x86_16_jcc_typed_condition_order.py",
        "angr_platforms/tests/test_x86_16_decompiler_postprocess_utils.py",
        "angr_platforms/tests/test_x86_16_runtime_call_results.py",
        "angr_platforms/tests/test_x86_16_recorded_return_argument_replay.py",
        "angr_platforms/tests/test_x86_16_callsite_replay_safety.py",
        "angr_platforms/tests/test_x86_16_decompiler_postprocess_calls.py::"
        "test_conservative_call_arg_seed_uses_known_default_for_zero_arg_helper_summary",
        "angr_platforms/tests/test_x86_16_decompiler_postprocess_calls.py::"
        "test_materialize_callsite_stack_arguments_refuses_direct_ds_byte_pair_store_prune",
        "angr_platforms/tests/test_x86_16_decompiler_postprocess_calls.py::"
        "test_materialize_callsite_stack_arguments_keeps_unproven_scalar_byte_pair_stores",
        "angr_platforms/tests/test_x86_16_decompiler_postprocess_calls.py::"
        "test_materialize_callsite_stack_arguments_requires_exact_consumed_push_evidence",
    )


def test_selects_partial_register_regressions_for_ir_live_in_analysis():
    selected = test_ownership_manifest.select_tests_for_files(
        ("angr_platforms/angr_platforms/X86_16/ir/register_live_in.py",)
    )
    assert "angr_platforms/tests/test_x86_16_gp_partial_live_in.py" in selected
    assert "angr_platforms/tests/test_x86_16_gp_register_state.py" in selected


def test_selects_cli_direct_fallback_focused_tests_for_legacy_cli_file():
    selected = test_ownership_manifest.select_tests_for_files(
        (
            "inertia_decompiler/cli_core.py",
            "inertia_decompiler/cli_fallback_decompilation.py",
            "angr_platforms/tests/test_x86_16_cli.py",
        )
    )

    assert selected == (
        "angr_platforms/tests/test_architecture_import_attestation.py",
        "angr_platforms/tests/test_decompiler_architecture_check.py",
        "angr_platforms/tests/test_serial_clean_worker_cache.py",
        "angr_platforms/tests/test_segment_program_layout_reporting.py",
        "angr_platforms/tests/test_project_callee_callsite_transport.py",
        "angr_platforms/tests/test_serial_clean_worker_callsite_evidence.py",
        "angr_platforms/tests/test_serial_clean_worker_global_source_evidence.py",
        "angr_platforms/tests/test_x86_16_cli.py::"
        "test_serial_clean_worker_evidence_protocol_round_trips_and_hydrates",
        "angr_platforms/tests/test_x86_16_cli.py::"
        "test_serial_clean_worker_evidence_protocol_refuses_unknown_schema",
        "angr_platforms/tests/test_direct_request_cache.py",
        "angr_platforms/tests/test_x86_16_cli.py::"
        "test_direct_addr_project_local_fallback_addr_uses_rebased_function_addr",
        "angr_platforms/tests/test_x86_16_cli.py::"
        "test_try_decompile_sidecar_slice_uses_extended_bounded_timeout",
    )


def test_selects_promoted_sortdemo_anchor_for_sortdemo_regression_file():
    selected = test_ownership_manifest.select_tests_for_files(
        ("angr_platforms/tests/test_x86_16_sortdemo_regressions.py",)
    )

    assert selected == (
        "angr_platforms/tests/test_x86_16_sortdemo_regressions.py::"
        "test_sortdemo_bubblesort_direct_path_validates_and_preserves_array_calls",
    )


def test_selects_tail_validation_focused_tests_for_implementation_file():
    selected = test_ownership_manifest.select_tests_for_files(
        ("angr_platforms/angr_platforms/X86_16/tail_validation.py",)
    )

    assert selected == (
        "angr_platforms/tests/test_x86_16_validation_dataflow.py::"
        "test_tail_validation_refuses_def_use_failure_even_when_baseline_already_lost_definition",
        "angr_platforms/tests/test_x86_16_validation_control_flow.py::"
        "test_tail_validation_refuses_duplicate_guard_when_baseline_already_has_it",
        "angr_platforms/tests/test_x86_16_validation_storage.py::"
        "test_tail_validation_refuses_storage_loss_already_present_in_baseline",
        "angr_platforms/tests/test_x86_16_tail_validation.py::"
        "test_tail_validation_compare_suppresses_loop_body_local_stack_write_precision",
        "angr_platforms/tests/test_x86_16_tail_validation.py::"
        "test_tail_validation_compare_suppresses_added_loop_body_local_stack_write_precision",
        "angr_platforms/tests/test_x86_16_tail_validation.py::"
        "test_tail_validation_compare_keeps_loop_body_global_write_delta_observable",
    )


def test_selects_manifest_tests_for_absolute_path():
    selected = test_ownership_manifest.select_tests_for_files(
        (str(test_ownership_manifest.REPO_ROOT / "scripts" / "decompile_cod_dir.py"),)
    )

    assert selected == (
        "angr_platforms/tests/test_decompile_cod_dir_parallelism.py",
        "angr_platforms/tests/test_decompiler_architecture_check.py",
        "angr_platforms/tests/test_architecture_import_attestation.py",
    )


def test_selects_unique_tests_for_multiple_matching_files():
    selected = test_ownership_manifest.select_tests_for_files(
        (
            "scripts/check_decompiler_architecture.py",
            "inertia_decompiler/architecture_runtime_guard.py",
        )
    )

    assert selected == (
        "angr_platforms/tests/test_makefile_inventory.py",
        "angr_platforms/tests/test_architecture_import_attestation.py",
        "angr_platforms/tests/test_decompiler_architecture_check.py",
    )


def test_manifest_cli_prints_space_separated_pytest_targets(capsys):
    rc = test_ownership_manifest.main(["scripts/test_pipeline.py", "scripts/decompile_cod_dir.py"])

    captured = capsys.readouterr()
    assert rc == 0
    assert captured.out.strip() == (
        "angr_platforms/tests/test_check_sortd_sidecar_free.py "
        "angr_platforms/tests/test_test_pipeline.py "
        "angr_platforms/tests/test_decompile_cod_dir_parallelism.py "
        "angr_platforms/tests/test_decompiler_architecture_check.py "
        "angr_platforms/tests/test_architecture_import_attestation.py"
    )


def test_validate_manifest_targets_rejects_missing_pytest_file():
    rules = (
        test_ownership_manifest.TestOwnershipRule(
            owner="stale",
            paths=(EXISTING_SOURCE_PATH,),
            tests=("angr_platforms/tests/test_missing_file.py::test_case",),
        ),
    )

    violations = test_ownership_manifest.validate_manifest_targets(rules)

    assert len(violations) == 1
    assert violations[0].owner == "stale"
    assert violations[0].target == "angr_platforms/tests/test_missing_file.py::test_case"


def test_validate_manifest_targets_rejects_empty_owner():
    rules = (
        test_ownership_manifest.TestOwnershipRule(
            owner=" ",
            paths=(EXISTING_SOURCE_PATH,),
            tests=("angr_platforms/tests/test_test_ownership_manifest.py",),
        ),
    )

    violations = test_ownership_manifest.validate_manifest_targets(rules)

    assert len(violations) == 1
    assert violations[0].target == "<owner>"
    assert "non-empty owner" in violations[0].reason


def test_validate_manifest_targets_rejects_duplicate_owner_names():
    rules = (
        test_ownership_manifest.TestOwnershipRule(
            owner="duplicate-owner",
            paths=(EXISTING_SOURCE_PATH,),
            tests=("angr_platforms/tests/test_test_ownership_manifest.py",),
        ),
        test_ownership_manifest.TestOwnershipRule(
            owner="duplicate-owner",
            paths=("scripts/test_pipeline.py",),
            tests=("angr_platforms/tests/test_test_pipeline.py",),
        ),
    )

    violations = test_ownership_manifest.validate_manifest_targets(rules)

    assert len(violations) == 1
    assert violations[0].owner == "duplicate-owner"
    assert violations[0].target == "<owner>"
    assert "owner names must be unique" in violations[0].reason


def test_validate_manifest_targets_rejects_empty_source_paths():
    rules = (
        test_ownership_manifest.TestOwnershipRule(
            owner="empty-source-paths",
            paths=(),
            tests=("angr_platforms/tests/test_test_ownership_manifest.py",),
        ),
    )

    violations = test_ownership_manifest.validate_manifest_targets(rules)

    assert len(violations) == 1
    assert violations[0].owner == "empty-source-paths"
    assert violations[0].target == "<paths>"
    assert "at least one source path" in violations[0].reason


def test_validate_manifest_targets_rejects_duplicate_source_paths_within_rule():
    rules = (
        test_ownership_manifest.TestOwnershipRule(
            owner="duplicate-source-path",
            paths=(EXISTING_SOURCE_PATH, EXISTING_SOURCE_PATH),
            tests=("angr_platforms/tests/test_test_ownership_manifest.py",),
        ),
    )

    violations = test_ownership_manifest.validate_manifest_targets(rules)

    assert len(violations) == 1
    assert violations[0].owner == "duplicate-source-path"
    assert violations[0].target == EXISTING_SOURCE_PATH
    assert "source paths must be unique" in violations[0].reason


def test_validate_manifest_targets_rejects_non_posix_source_path():
    rules = (
        test_ownership_manifest.TestOwnershipRule(
            owner="non-posix-source-path",
            paths=("scripts\\test_ownership_manifest.py",),
            tests=("angr_platforms/tests/test_test_ownership_manifest.py",),
        ),
    )

    violations = test_ownership_manifest.validate_manifest_targets(rules)

    assert any(
        violation.owner == "non-posix-source-path"
        and violation.target == "scripts\\test_ownership_manifest.py"
        and "POSIX" in violation.reason
        for violation in violations
    )


def test_validate_manifest_targets_rejects_absolute_source_path():
    rules = (
        test_ownership_manifest.TestOwnershipRule(
            owner="absolute-source-path",
            paths=("/tmp/source.py",),
            tests=("angr_platforms/tests/test_test_ownership_manifest.py",),
        ),
    )

    violations = test_ownership_manifest.validate_manifest_targets(rules)

    assert any(
        violation.owner == "absolute-source-path"
        and violation.target == "/tmp/source.py"
        and "repository-relative" in violation.reason
        for violation in violations
    )


def test_validate_manifest_targets_rejects_empty_pytest_targets():
    rules = (
        test_ownership_manifest.TestOwnershipRule(
            owner="empty-pytest-targets",
            paths=(EXISTING_SOURCE_PATH,),
            tests=(),
        ),
    )

    violations = test_ownership_manifest.validate_manifest_targets(rules)

    assert len(violations) == 1
    assert violations[0].owner == "empty-pytest-targets"
    assert violations[0].target == "<tests>"
    assert "at least one pytest target" in violations[0].reason


def test_validate_manifest_targets_rejects_duplicate_pytest_targets_within_rule():
    rules = (
        test_ownership_manifest.TestOwnershipRule(
            owner="duplicate-pytest-target",
            paths=(EXISTING_SOURCE_PATH,),
            tests=(
                "angr_platforms/tests/test_test_ownership_manifest.py",
                "angr_platforms/tests/test_test_ownership_manifest.py",
            ),
        ),
    )

    violations = test_ownership_manifest.validate_manifest_targets(rules)

    assert len(violations) == 1
    assert violations[0].owner == "duplicate-pytest-target"
    assert violations[0].target == "angr_platforms/tests/test_test_ownership_manifest.py"
    assert "pytest targets must be unique" in violations[0].reason


def test_validate_manifest_targets_rejects_non_posix_pytest_target_path():
    rules = (
        test_ownership_manifest.TestOwnershipRule(
            owner="non-posix-pytest-path",
            paths=(EXISTING_SOURCE_PATH,),
            tests=("angr_platforms\\tests\\test_test_ownership_manifest.py",),
        ),
    )

    violations = test_ownership_manifest.validate_manifest_targets(rules)

    assert any(
        violation.owner == "non-posix-pytest-path"
        and violation.target == "angr_platforms\\tests\\test_test_ownership_manifest.py"
        and "POSIX" in violation.reason
        for violation in violations
    )


def test_validate_manifest_targets_rejects_pytest_target_outside_test_lane():
    rules = (
        test_ownership_manifest.TestOwnershipRule(
            owner="outside-test-lane",
            paths=(EXISTING_SOURCE_PATH,),
            tests=("scripts/test_ownership_manifest.py",),
        ),
    )

    violations = test_ownership_manifest.validate_manifest_targets(rules)

    assert any(
        violation.owner == "outside-test-lane"
        and violation.target == "scripts/test_ownership_manifest.py"
        and "angr_platforms/tests/" in violation.reason
        for violation in violations
    )


def test_validate_manifest_targets_rejects_pytest_target_non_test_module_name():
    rules = (
        test_ownership_manifest.TestOwnershipRule(
            owner="non-test-module-target",
            paths=(EXISTING_SOURCE_PATH,),
            tests=("angr_platforms/tests/helper_manifest.py",),
        ),
    )

    violations = test_ownership_manifest.validate_manifest_targets(rules)

    assert any(
        violation.owner == "non-test-module-target"
        and violation.target == "angr_platforms/tests/helper_manifest.py"
        and "test_*.py" in violation.reason
        for violation in violations
    )


def test_validate_manifest_targets_rejects_missing_source_path():
    rules = (
        test_ownership_manifest.TestOwnershipRule(
            owner="stale-source",
            paths=("missing/source.py",),
            tests=("angr_platforms/tests/test_test_ownership_manifest.py",),
        ),
    )

    violations = test_ownership_manifest.validate_manifest_targets(rules)

    assert len(violations) == 1
    assert violations[0].owner == "stale-source"
    assert violations[0].target == "missing/source.py"
    assert "source path does not exist" in violations[0].reason


def test_validate_manifest_targets_rejects_missing_pytest_node():
    rules = (
        test_ownership_manifest.TestOwnershipRule(
            owner="stale-node",
            paths=(EXISTING_SOURCE_PATH,),
            tests=("angr_platforms/tests/test_test_ownership_manifest.py::test_missing_case",),
        ),
    )

    violations = test_ownership_manifest.validate_manifest_targets(rules)

    assert len(violations) == 1
    assert violations[0].owner == "stale-node"
    assert violations[0].target == "angr_platforms/tests/test_test_ownership_manifest.py::test_missing_case"
    assert "pytest node does not exist" in violations[0].reason


def test_validate_manifest_targets_accepts_existing_pytest_node():
    rules = (
        test_ownership_manifest.TestOwnershipRule(
            owner="fresh-node",
            paths=(EXISTING_SOURCE_PATH,),
            tests=("angr_platforms/tests/test_test_ownership_manifest.py::test_manifest_cli_check_passes_for_current_manifest",),
        ),
    )

    violations = test_ownership_manifest.validate_manifest_targets(rules)

    assert violations == ()


def test_validate_manifest_targets_accepts_existing_class_pytest_node(monkeypatch, tmp_path):
    tests_dir = tmp_path / "angr_platforms" / "tests"
    tests_dir.mkdir(parents=True)
    test_file = tests_dir / "test_class_nodes.py"
    test_file.write_text(
        "class TestFocused:\n"
        "    def test_case(self):\n"
        "        pass\n",
        encoding="utf-8",
    )
    (tmp_path / "source.py").write_text('"""Temporary source path."""\n', encoding="utf-8")
    monkeypatch.setattr(test_ownership_manifest, "REPO_ROOT", tmp_path)
    rules = (
        test_ownership_manifest.TestOwnershipRule(
            owner="fresh-class-node",
            paths=("source.py",),
            tests=("angr_platforms/tests/test_class_nodes.py::TestFocused::test_case",),
        ),
    )

    violations = test_ownership_manifest.validate_manifest_targets(rules)

    assert violations == ()


def test_validate_manifest_targets_accepts_existing_class_pytest_container_node(monkeypatch, tmp_path):
    tests_dir = tmp_path / "angr_platforms" / "tests"
    tests_dir.mkdir(parents=True)
    test_file = tests_dir / "test_class_nodes.py"
    test_file.write_text(
        "class TestFocused:\n"
        "    def test_case(self):\n"
        "        pass\n",
        encoding="utf-8",
    )
    (tmp_path / "source.py").write_text('"""Temporary source path."""\n', encoding="utf-8")
    monkeypatch.setattr(test_ownership_manifest, "REPO_ROOT", tmp_path)
    rules = (
        test_ownership_manifest.TestOwnershipRule(
            owner="fresh-class-container-node",
            paths=("source.py",),
            tests=("angr_platforms/tests/test_class_nodes.py::TestFocused",),
        ),
    )

    violations = test_ownership_manifest.validate_manifest_targets(rules)

    assert violations == ()


def test_validate_manifest_targets_rejects_fast_pytest_target_skip(monkeypatch, tmp_path):
    tests_dir = tmp_path / "angr_platforms" / "tests"
    tests_dir.mkdir(parents=True)
    test_file = tests_dir / "test_fast_skip.py"
    test_file.write_text(
        "from __future__ import annotations\n\n"
        "import pytest\n\n"
        "def test_case():\n"
        "    pytest.skip('optional local fixture')\n",
        encoding="utf-8",
    )
    (tmp_path / "source.py").write_text('"""Temporary source path."""\n', encoding="utf-8")
    monkeypatch.setattr(test_ownership_manifest, "REPO_ROOT", tmp_path)
    rules = (
        test_ownership_manifest.TestOwnershipRule(
            owner="fast-skip",
            paths=("source.py",),
            tests=("angr_platforms/tests/test_fast_skip.py::test_case",),
        ),
    )

    violations = test_ownership_manifest.validate_manifest_targets(rules)

    assert len(violations) == 1
    assert violations[0].owner == "fast-skip"
    assert violations[0].target == "angr_platforms/tests/test_fast_skip.py::test_case"
    assert "must not use skip/xfail" in violations[0].reason


def test_validate_manifest_targets_allows_unselected_skip_in_legacy_test_file(monkeypatch, tmp_path):
    tests_dir = tmp_path / "angr_platforms" / "tests"
    tests_dir.mkdir(parents=True)
    test_file = tests_dir / "test_legacy_nodes.py"
    test_file.write_text(
        "from __future__ import annotations\n\n"
        "import pytest\n\n"
        "def test_optional_fixture_case():\n"
        "    pytest.skip('optional local fixture')\n\n"
        "def test_selected_fast_case():\n"
        "    assert True\n",
        encoding="utf-8",
    )
    (tmp_path / "source.py").write_text('"""Temporary source path."""\n', encoding="utf-8")
    monkeypatch.setattr(test_ownership_manifest, "REPO_ROOT", tmp_path)
    rules = (
        test_ownership_manifest.TestOwnershipRule(
            owner="selected-fast-node",
            paths=("source.py",),
            tests=("angr_platforms/tests/test_legacy_nodes.py::test_selected_fast_case",),
        ),
    )

    violations = test_ownership_manifest.validate_manifest_targets(rules)

    assert violations == ()


def test_validate_manifest_targets_rejects_missing_class_pytest_container_node(monkeypatch, tmp_path):
    tests_dir = tmp_path / "angr_platforms" / "tests"
    tests_dir.mkdir(parents=True)
    test_file = tests_dir / "test_class_nodes.py"
    test_file.write_text(
        "class TestFocused:\n"
        "    def test_case(self):\n"
        "        pass\n",
        encoding="utf-8",
    )
    (tmp_path / "source.py").write_text('"""Temporary source path."""\n', encoding="utf-8")
    monkeypatch.setattr(test_ownership_manifest, "REPO_ROOT", tmp_path)
    rules = (
        test_ownership_manifest.TestOwnershipRule(
            owner="stale-class-container-node",
            paths=("source.py",),
            tests=("angr_platforms/tests/test_class_nodes.py::TestMissing",),
        ),
    )

    violations = test_ownership_manifest.validate_manifest_targets(rules)

    assert len(violations) == 1
    assert violations[0].owner == "stale-class-container-node"
    assert "pytest node does not exist" in violations[0].reason


def test_validate_manifest_targets_rejects_missing_class_pytest_node(monkeypatch, tmp_path):
    tests_dir = tmp_path / "angr_platforms" / "tests"
    tests_dir.mkdir(parents=True)
    test_file = tests_dir / "test_class_nodes.py"
    test_file.write_text(
        "class TestFocused:\n"
        "    def test_case(self):\n"
        "        pass\n",
        encoding="utf-8",
    )
    (tmp_path / "source.py").write_text('"""Temporary source path."""\n', encoding="utf-8")
    monkeypatch.setattr(test_ownership_manifest, "REPO_ROOT", tmp_path)
    rules = (
        test_ownership_manifest.TestOwnershipRule(
            owner="stale-class-node",
            paths=("source.py",),
            tests=("angr_platforms/tests/test_class_nodes.py::TestFocused::test_missing",),
        ),
    )

    violations = test_ownership_manifest.validate_manifest_targets(rules)

    assert len(violations) == 1
    assert violations[0].owner == "stale-class-node"
    assert "pytest node does not exist" in violations[0].reason


def test_validate_manifest_targets_rejects_non_fast_rule_tier():
    rules = (
        test_ownership_manifest.TestOwnershipRule(
            owner="slow-rule",
            paths=(EXISTING_SOURCE_PATH,),
            tests=("angr_platforms/tests/test_test_ownership_manifest.py",),
            tier="slow",
        ),
    )

    violations = test_ownership_manifest.validate_manifest_targets(rules)

    assert len(violations) == 1
    assert violations[0].owner == "slow-rule"
    assert violations[0].target == "slow"
    assert "fast tier" in violations[0].reason


def test_validate_manifest_targets_requires_fallback_reason():
    rules = (
        test_ownership_manifest.TestOwnershipRule(
            owner="undocumented-fallback",
            paths=(EXISTING_SOURCE_PATH,),
            tests=("angr_platforms/tests/test_test_ownership_manifest.py",),
            fallback=True,
        ),
    )

    violations = test_ownership_manifest.validate_manifest_targets(rules)

    assert len(violations) == 1
    assert violations[0].owner == "undocumented-fallback"
    assert violations[0].target == "<reason>"
    assert "architectural coverage" in violations[0].reason


def test_validate_manifest_targets_rejects_vague_fallback_reason():
    rules = (
        test_ownership_manifest.TestOwnershipRule(
            owner="vague-fallback",
            paths=(EXISTING_SOURCE_PATH,),
            tests=("angr_platforms/tests/test_test_ownership_manifest.py",),
            fallback=True,
            reason="general fallback checks",
        ),
    )

    violations = test_ownership_manifest.validate_manifest_targets(rules)

    assert len(violations) == 1
    assert violations[0].owner == "vague-fallback"
    assert violations[0].target == "<reason>"
    assert "unowned scope and coverage" in violations[0].reason


def test_manifest_cli_check_fails_for_stale_manifest_rule(monkeypatch, capsys):
    monkeypatch.setattr(
        test_ownership_manifest,
        "TEST_OWNERSHIP_RULES",
        (
            test_ownership_manifest.TestOwnershipRule(
                owner="stale",
                paths=(EXISTING_SOURCE_PATH,),
                tests=("angr_platforms/tests/test_missing_file.py",),
            ),
        ),
    )

    rc = test_ownership_manifest.main(["--check"])

    captured = capsys.readouterr()
    assert rc == 1
    assert "pytest file does not exist" in captured.out


@pytest.mark.repository_contract
def test_manifest_cli_check_passes_for_current_manifest(capsys):
    rc = test_ownership_manifest.main(["--check"])

    captured = capsys.readouterr()
    assert rc == 0
    assert captured.out == ""
