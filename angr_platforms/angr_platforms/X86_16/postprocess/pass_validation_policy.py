"""Static policy for guarded postprocess-pass validation.

Layer: Rewrite/Postprocess cleanup.
Responsibility: classify pass names by the validation, rollback, and rejection
policy that the postprocess transaction driver must enforce. Consumes
already-proven IR, alias, widening, typed, and structuring facts. This module
owns policy data only; it must not execute passes. Do not recover new semantics,
storage identity, types, call signatures, control flow, or facts from rendered
text, COD, source, or CLI/reporting evidence here.
"""

from __future__ import annotations

from ..lowering.real_mode_linear import DirectStackMoveSourceKind8616
from .optimization.pass_driver import OPTIMIZATION_PASSES

__all__ = [
    "CALLSITE_STACK_ARGUMENT_PASS_NAMES_8616",
    "CALL_RECOVERY_VALIDATION_PASS_NAMES_8616",
    "DIRECT_GLOBAL_UPDATE_VALIDATION_PASS_NAMES_8616",
    "DIRECT_STACK_MOVE_VALIDATION_PASS_NAMES_8616",
    "DIRECT_STACK_UPDATE_VALIDATION_PASS_NAMES_8616",
    "FORCE_PER_PASS_VALIDATION_NAMES_8616",
    "HELPER_NAME_ONLY_VALIDATION_PASS_NAMES_8616",
    "JCC_REWRITE_VALIDATION_PASS_NAMES_8616",
    "LOCAL_PROOF_REQUIRED_POSTPROCESS_PASS_NAMES_8616",
    "MANDATORY_VALIDATION_PASS_NAMES_8616",
    "MISSING_TERMINAL_AX_RETURN_PASS_NAMES_8616",
    "NON_IDIV_DIRECT_STACK_MOVE_SOURCE_KINDS_8616",
    "OPTIMIZATION_VALIDATION_PASS_NAMES_8616",
    "PASS_LOCAL_REJECT_CONTINUE_PASS_NAMES_8616",
    "PASS_REJECT_BUDGET_DEFAULT_8616",
    "PASS_REJECT_BUDGET_ELIGIBLE_NAMES_8616",
    "POSTPROCESS_EXPENSIVE_VALIDATION_BASELINE_MS_8616",
]

FORCE_PER_PASS_VALIDATION_NAMES_8616: frozenset[str] = frozenset(
    {
        "_rewrite_decoded_jcc_conditions_8616",
        "_rewrite_decoded_jcc_conditions_after_calls_8616",
        "_materialize_unconsumed_loop_break_jcc_8616",
        "_repair_loop_exit_return_guards_8616",
        "_recover_missing_direct_calls_from_evidence_early_8616",
        "_recover_missing_direct_calls_from_evidence_8616",
        "_normalize_fact_backed_stack_accesses_8616",
        "_prune_return_address_stack_arguments_8616",
        "_normalize_call_target_names_8616",
        "_normalize_recovered_call_target_names_8616",
        "_materialize_callsite_stack_arguments_8616",
        "_materialize_callsite_prototypes_8616",
        "_materialize_recovered_callsite_stack_arguments_8616",
        "_materialize_stack_byte_pair_return_8616",
        "_materialize_direct_global_incdec_instructions_8616",
        "_materialize_direct_global_incdec_instructions_final_8616",
        "_recover_missing_direct_calls_final_8616",
        "_materialize_pointer_memory_idioms_8616",
        "_materialize_empty_if_return_branches_8616",
        "_prune_surplus_void_empty_return_guards_8616",
        "_prune_surplus_void_empty_return_guards_final_8616",
        "_prune_unreachable_after_return_final_8616",
        "_materialize_empty_if_return_branches_final_8616",
        "_prune_duplicate_empty_return_guard_before_cfg_suffix_8616",
        "_prune_duplicate_empty_return_guard_before_cfg_suffix_final_8616",
    }
)

MISSING_TERMINAL_AX_RETURN_PASS_NAMES_8616: frozenset[str] = frozenset(
    {"_materialize_missing_terminal_ax_return_8616"}
)

JCC_REWRITE_VALIDATION_PASS_NAMES_8616: frozenset[str] = frozenset(
    {
        "_rewrite_decoded_jcc_conditions_8616",
        "_rewrite_decoded_jcc_conditions_after_calls_8616",
        "_materialize_unconsumed_loop_break_jcc_8616",
        "_repair_conditional_continue_guards_after_loop_break_8616",
    }
)

DIRECT_GLOBAL_UPDATE_VALIDATION_PASS_NAMES_8616: frozenset[str] = frozenset(
    {
        "_materialize_direct_global_incdec_instructions_8616",
        "_materialize_direct_global_incdec_instructions_final_8616",
    }
)

DIRECT_STACK_UPDATE_VALIDATION_PASS_NAMES_8616: frozenset[str] = frozenset(
    {
        "_materialize_direct_stack_incdec_instructions_8616",
        "_materialize_direct_stack_incdec_instructions_final_8616",
    }
)

DIRECT_STACK_MOVE_VALIDATION_PASS_NAMES_8616: frozenset[str] = frozenset(
    {
        "_materialize_direct_stack_mov_instructions_8616",
        "_materialize_direct_stack_mov_instructions_final_8616",
        "_prune_unsupported_function_pointer_stack_move_assignments_8616",
    }
)

NON_IDIV_DIRECT_STACK_MOVE_SOURCE_KINDS_8616: frozenset[DirectStackMoveSourceKind8616] = frozenset(
    kind
    for kind in DirectStackMoveSourceKind8616
    if kind is not DirectStackMoveSourceKind8616.SIGNED_IDIV_REMAINDER
)

HELPER_NAME_ONLY_VALIDATION_PASS_NAMES_8616: frozenset[str] = JCC_REWRITE_VALIDATION_PASS_NAMES_8616 | frozenset(
    {
        "_materialize_callsite_stack_arguments_8616",
        "_materialize_callsite_stack_arguments_after_ss_lowering_8616",
        "_prune_consumed_segmented_stack_arg_stores_8616",
        "_prune_consumed_segmented_stack_arg_stores_final_8616",
        "_prune_consumed_segmented_stack_arg_stores_after_ss_lowering_8616",
    }
)

CALLSITE_STACK_ARGUMENT_PASS_NAMES_8616: frozenset[str] = frozenset(
    {
        "_materialize_callsite_stack_arguments_8616",
        "_materialize_callsite_stack_arguments_final_8616",
        "_materialize_callsite_stack_arguments_after_ss_lowering_8616",
        "_prune_consumed_segmented_stack_arg_stores_8616",
        "_prune_consumed_segmented_stack_arg_stores_final_8616",
        "_prune_consumed_segmented_stack_arg_stores_after_ss_lowering_8616",
        "_prune_scalar_global_high_byte_call_arg_remnants_after_ss_lowering_8616",
        "_materialize_recovered_callsite_stack_arguments_8616",
    }
)

CALL_RECOVERY_VALIDATION_PASS_NAMES_8616: frozenset[str] = frozenset(
    {
        "_recover_missing_direct_calls_from_evidence_early_8616",
        "_recover_missing_direct_calls_from_evidence_8616",
        "_normalize_call_target_names_8616",
        "_normalize_recovered_call_target_names_8616",
        "_materialize_callsite_stack_arguments_8616",
        "_materialize_callsite_stack_arguments_final_8616",
        "_materialize_recovered_callsite_stack_arguments_8616",
        "_recover_missing_direct_calls_final_8616",
    }
)

OPTIMIZATION_VALIDATION_PASS_NAMES_8616: frozenset[str] = frozenset(
    f"optimization:{spec.name}" for spec in OPTIMIZATION_PASSES
)

LOCAL_PROOF_REQUIRED_POSTPROCESS_PASS_NAMES_8616: frozenset[str] = (
    frozenset(
        {
            "optimization",
            "_apply_annotations_8616",
            "_apply_word_global_types_8616",
            "_apply_typed_condition_stack_arg_signedness_8616",
            "_materialize_stable_stack_semantics_bootstrap_8616",
            "_materialize_stable_stack_semantics_early_8616",
            "_promote_stack_prototype_from_bp_loads_8616",
            "_reconcile_exact_stack_argument_prototype_8616",
            "_prune_return_address_stack_arguments_8616",
            "_apply_typed_conditions_to_codegen_8616",
            "_simplify_boolean_cites_8616",
            "_simplify_structured_expressions_8616",
            "_maybe_eliminate_single_use_temporaries_8616",
            "_lower_stable_ss_stack_accesses_8616",
            "_simplify_structured_expressions_after_stack_lowering_8616",
            "_materialize_stable_stack_semantics_postprocess_8616",
            "_materialize_stable_stack_semantics_final_8616",
            "_lower_runtime_ss_segment_helpers_to_stack_final_8616",
            "_dead_code_elimination_after_callsite_stack_arguments_8616",
            "_dead_code_elimination_after_flag_prune_8616",
            "_dead_code_elimination_after_stable_stack_final_8616",
            "_dead_code_elimination_after_ss_callsite_stack_arguments_8616",
            "_dead_code_elimination_final_cleanup_8616",
            "_rewrite_flag_condition_pairs_8616",
            "_rewrite_flag_bit_value_uses_8616",
            "_prune_unused_flag_assignments_8616",
            "_prune_overwritten_flag_assignments_8616",
            "_fix_interval_guard_conditions_8616",
            "_materialize_global_byte_index_sum_loop_8616",
            "_repair_conditional_continue_guards_from_evidence_8616",
            "_materialize_cfg_selector_return_branches_early_8616",
            "_materialize_cfg_mask_accumulator_8616",
            "_materialize_cfg_selector_return_branches_8616",
            "_materialize_unconsumed_loop_break_jcc_8616",
            "_repair_conditional_continue_guards_after_loop_break_8616",
            "_repair_loop_exit_return_guards_8616",
            "_repair_unresolved_function_exit_gotos_8616",
            "_simplify_structured_expressions_after_call_stack_lowering_8616",
            "_simplify_structured_expressions_after_final_call_materialization_8616",
            "_recover_missing_direct_calls_from_evidence_early_8616",
            "_recover_missing_direct_calls_from_evidence_8616",
            "_normalize_fact_backed_stack_accesses_8616",
            "_normalize_call_target_names_8616",
            "_normalize_recovered_call_target_names_8616",
            "_materialize_callsite_stack_arguments_8616",
            "_materialize_callsite_stack_arguments_after_ss_lowering_8616",
            "_prune_consumed_segmented_stack_arg_stores_8616",
            "_prune_consumed_segmented_stack_arg_stores_final_8616",
            "_prune_consumed_segmented_stack_arg_stores_after_ss_lowering_8616",
            "_prune_scalar_global_high_byte_call_arg_remnants_after_ss_lowering_8616",
            "_materialize_callsite_prototypes_8616",
            "_materialize_recovered_callsite_stack_arguments_8616",
            "_materialize_stack_byte_pair_return_8616",
            "_recover_missing_direct_calls_final_8616",
            "_materialize_pointer_memory_idioms_8616",
            "_materialize_empty_if_return_branches_8616",
            "_materialize_void_tail_call_guard_from_cfg_8616",
            "_prune_surplus_void_empty_return_guards_8616",
            "_prune_surplus_void_empty_return_guards_final_8616",
            "_prune_unreachable_after_return_final_8616",
            "_materialize_empty_if_return_branches_final_8616",
            "_materialize_void_tail_call_guard_from_cfg_final_8616",
            "_prune_duplicate_empty_return_guard_before_cfg_suffix_8616",
            "_prune_duplicate_empty_return_guard_before_cfg_suffix_final_8616",
        }
    )
    | JCC_REWRITE_VALIDATION_PASS_NAMES_8616
    | DIRECT_GLOBAL_UPDATE_VALIDATION_PASS_NAMES_8616
    | DIRECT_STACK_UPDATE_VALIDATION_PASS_NAMES_8616
    | DIRECT_STACK_MOVE_VALIDATION_PASS_NAMES_8616
    | OPTIMIZATION_VALIDATION_PASS_NAMES_8616
)

MANDATORY_VALIDATION_PASS_NAMES_8616: frozenset[str] = frozenset(
    {
        "_apply_annotations_8616",
        "_apply_typed_condition_stack_arg_signedness_8616",
        "_apply_typed_conditions_to_codegen_8616",
        "_materialize_stable_stack_semantics_bootstrap_8616",
        "_materialize_stable_stack_semantics_early_8616",
        "_materialize_stable_stack_semantics_postprocess_8616",
        "_materialize_stable_stack_semantics_final_8616",
        "_lower_stable_ss_stack_accesses_8616",
        "_lower_runtime_ss_segment_helpers_to_stack_final_8616",
        "_promote_stack_prototype_from_bp_loads_8616",
        "_reconcile_exact_stack_argument_prototype_8616",
        "_prune_return_address_stack_arguments_8616",
        "_simplify_structured_expressions_8616",
        "_simplify_structured_expressions_after_stack_lowering_8616",
        "_simplify_structured_expressions_after_call_stack_lowering_8616",
        "_simplify_structured_expressions_after_final_call_materialization_8616",
        "_materialize_callsite_stack_arguments_after_ss_lowering_8616",
        "_materialize_global_byte_index_sum_loop_8616",
        "_materialize_unconsumed_loop_break_jcc_8616",
        "_prune_unused_flag_assignments_8616",
        "_prune_overwritten_flag_assignments_8616",
        "_dead_code_elimination_after_callsite_stack_arguments_8616",
        "_dead_code_elimination_after_flag_prune_8616",
        "_dead_code_elimination_after_stable_stack_final_8616",
        "_dead_code_elimination_after_ss_callsite_stack_arguments_8616",
        "_dead_code_elimination_final_cleanup_8616",
        "_classify_return_shape_8616",
        "_prune_consumed_segmented_stack_arg_stores_8616",
        "_prune_consumed_segmented_stack_arg_stores_final_8616",
        "_prune_consumed_segmented_stack_arg_stores_after_ss_lowering_8616",
        "_rerun_stack_lowering_consumers_after_calls_8616",
        "_materialize_direct_stack_mov_instructions_8616",
        "_materialize_direct_stack_mov_instructions_final_8616",
    }
    | CALL_RECOVERY_VALIDATION_PASS_NAMES_8616
    | DIRECT_GLOBAL_UPDATE_VALIDATION_PASS_NAMES_8616
    | DIRECT_STACK_UPDATE_VALIDATION_PASS_NAMES_8616
    | OPTIMIZATION_VALIDATION_PASS_NAMES_8616
)

PASS_LOCAL_REJECT_CONTINUE_PASS_NAMES_8616: frozenset[str] = frozenset(
    {
        "_apply_annotations_8616",
        "_apply_typed_condition_stack_arg_signedness_8616",
        "_apply_typed_conditions_to_codegen_8616",
        "_materialize_stable_stack_semantics_bootstrap_8616",
        "_materialize_stable_stack_semantics_early_8616",
        "_materialize_stable_stack_semantics_postprocess_8616",
        "_materialize_stable_stack_semantics_final_8616",
        "_lower_stable_ss_stack_accesses_8616",
        "_lower_runtime_ss_segment_helpers_to_stack_final_8616",
        "_promote_stack_prototype_from_bp_loads_8616",
        "_reconcile_exact_stack_argument_prototype_8616",
        "_prune_return_address_stack_arguments_8616",
        "_simplify_structured_expressions_8616",
        "_simplify_structured_expressions_after_stack_lowering_8616",
        "_simplify_structured_expressions_after_call_stack_lowering_8616",
        "_simplify_structured_expressions_after_final_call_materialization_8616",
        "_materialize_callsite_stack_arguments_after_ss_lowering_8616",
        "_materialize_global_byte_index_sum_loop_8616",
        "_materialize_unconsumed_loop_break_jcc_8616",
        "_prune_unused_flag_assignments_8616",
        "_prune_overwritten_flag_assignments_8616",
        "_prune_unused_unnamed_memory_declarations_8616",
        "_dead_code_elimination_after_callsite_stack_arguments_8616",
        "_dead_code_elimination_after_flag_prune_8616",
        "_dead_code_elimination_after_stable_stack_final_8616",
        "_dead_code_elimination_after_ss_callsite_stack_arguments_8616",
        "_classify_return_shape_8616",
        "_prune_consumed_segmented_stack_arg_stores_8616",
        "_prune_consumed_segmented_stack_arg_stores_final_8616",
        "_prune_consumed_segmented_stack_arg_stores_after_ss_lowering_8616",
        "_rerun_stack_lowering_consumers_after_calls_8616",
        "_materialize_direct_stack_mov_instructions_8616",
        "_materialize_direct_stack_mov_instructions_final_8616",
    }
    | CALL_RECOVERY_VALIDATION_PASS_NAMES_8616
    | DIRECT_GLOBAL_UPDATE_VALIDATION_PASS_NAMES_8616
    | DIRECT_STACK_UPDATE_VALIDATION_PASS_NAMES_8616
    | OPTIMIZATION_VALIDATION_PASS_NAMES_8616
)

PASS_REJECT_BUDGET_ELIGIBLE_NAMES_8616: frozenset[str] = (
    PASS_LOCAL_REJECT_CONTINUE_PASS_NAMES_8616
    - CALL_RECOVERY_VALIDATION_PASS_NAMES_8616
    - DIRECT_GLOBAL_UPDATE_VALIDATION_PASS_NAMES_8616
    - DIRECT_STACK_UPDATE_VALIDATION_PASS_NAMES_8616
    - DIRECT_STACK_MOVE_VALIDATION_PASS_NAMES_8616
    - JCC_REWRITE_VALIDATION_PASS_NAMES_8616
    - frozenset(
        {
            "_simplify_boolean_cites_8616",
            "_simplify_structured_expressions_8616",
            "_simplify_structured_expressions_after_stack_lowering_8616",
            "_simplify_structured_expressions_after_call_stack_lowering_8616",
            "_simplify_structured_expressions_after_final_call_materialization_8616",
            "_fix_interval_guard_conditions_8616",
        }
    )
)

PASS_REJECT_BUDGET_DEFAULT_8616: int = 6
POSTPROCESS_EXPENSIVE_VALIDATION_BASELINE_MS_8616: int = 2000
