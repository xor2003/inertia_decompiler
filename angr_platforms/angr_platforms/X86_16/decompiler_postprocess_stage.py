"""Decompiler postprocess orchestrator; do not make it a semantics layer.

Layer: Rewrite/Postprocess cleanup.
Responsibility: sequence cleanup passes and enforce validation-stable rewrites.

Dynamic boundary: attributes read with ``getattr`` in this compatibility
orchestrator belong to third-party angr codegen/C-AST objects whose runtime
surface varies by angr version. Owned Inertia contracts must use dot access.

This module wires the late rewrite pipeline, validation snapshots, pass gating,
tail-validation delta classification, and rollback/salvage decisions. It may
sequence postprocess passes and enforce that accepted changes are evidenced and
validation-stable.

Allowed work in this file:
- compose passes and runtime gates;
- take/restore validation snapshots and classify typed validation deltas;
- coordinate already-proven lowering consumers and final C AST cleanup;
- refuse or roll back changes when evidence or validation is missing.

Current migration debt:
- several materializers and CFG repairs still live here because earlier layers
  do not yet expose enough structured facts;
- selector/return-chain, pointer-loop, direct stack/global update, and
  unconsumed-JCC repairs inspect instructions or C shapes late;
- validation delta allowlists compensate for late materialization.

Those belong in their owning layers: frontend/CFG and structuring for control
shape, IR/semantics for instruction effects, alias/widening for storage proof,
lowering for stack/global/object materialization, and validation for semantic
comparison. As each fact becomes available earlier, replace the local rescue
with a pass that consumes the structured fact or delete the rescue entirely.

Do not add new semantic recovery, compiler-specific body repair, text-based
matching, or broad validation exceptions here. New postprocess work must be a
narrow orchestration/cleanup step with explicit evidence accounting and honest
tail-validation behavior.
"""

from __future__ import annotations

import contextlib
import copy
import cProfile
import itertools
import logging
import os
import re
import sys
import time
import typing
from collections.abc import Callable, Iterable, Mapping, MutableMapping
from dataclasses import dataclass, field
from typing import Any, cast

from angr.ailment.statement import Return as AILReturn
from angr.analyses.decompiler.decompiler import Decompiler
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CDirtyExpression,
    CDoWhileLoop,
    CExpression,
    CForLoop,
    CFunctionCall,
    CGoto,
    CIfBreak,
    CIfElse,
    CIndexedVariable,
    CReturn,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CUnsupportedStatement,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeBottom, SimTypeChar, SimTypeFunction, SimTypeLong, SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimStackVariable

from inertia_decompiler.runtime_support import AnalysisTimeout, analysis_timeout, timing_output_enabled
from inertia_decompiler.telemetry import annotate_current_span, span

from . import decompiler_postprocess as _post
from . import decompiler_postprocess_calls as _calls
from . import decompiler_postprocess_flags as _flags
from . import decompiler_postprocess_globals as _globals
from . import decompiler_postprocess_jcc as _jcc
from . import decompiler_postprocess_simplify as _simplify
from . import segmented_memory_reasoning as _segmented_mem
from .annotations import ANNOTATION_KEY
from .c_ast_utils import _c_ast_cycle_path_8616
from .callee_name_normalization import normalize_callee_name_8616
from .cod_known_objects import canonical_known_cod_object_name
from .compiler_helpers import is_x86_16_stack_probe_helper_at_8616, is_x86_16_stack_probe_name_8616
from .condition_trace import (
    dump_condition_trace_8616,
    materialized_condition_drift_detected_8616,
    record_ast_condition_trace_8616,
    record_tail_validation_condition_trace_8616,
)
from .decompiler_postprocess_typed_conditions import (
    _apply_typed_condition_stack_arg_signedness_8616,
    _apply_typed_conditions_to_codegen_8616,
)
from .decompiler_postprocess_utils import (
    _iter_c_nodes_deep_8616,
    _same_c_expression_8616,
    _structured_slot_names_8616,
)
from .decompiler_return_compat import (
    _return_compat_function_caller_return_use_8616,
    codegen_has_explicit_void_return_8616,
)
from .frontend_function_instructions import (
    BoundedLinearInstructionInventory8616,
    collect_bounded_linear_instruction_inventory_8616,
    collect_function_instruction_inventory_8616,
)
from .ir.condition_ir import (
    invert_condition_fingerprint_string_8616,
    normalize_condition_fingerprint_algebraic_8616,
    normalize_condition_fingerprint_string_8616,
)
from .ir.status_flag_lift_context import active_status_flag_lift_context_8616
from .lowering.argument_frame_base import proven_first_argument_machine_bp_offset_8616
from .lowering.condition_argument_types import apply_condition_argument_types_8616
from .lowering.condition_transfer import transfer_typed_conditions_to_codegen_8616
from .lowering.fact_transfer import transfer_semantic_alias_facts_to_codegen_8616
from .lowering.global_declarations import ctype_for_global_width_8616, record_global_declaration_spec_8616
from .lowering.ir_segmented_load_carriers import materialize_ir_segmented_load_carriers_8616
from .lowering.near_pointer_type import SimTypeNearPointer16_8616
from .lowering.real_mode_linear import (
    DirectStackMoveSourceKind8616,
    _direct_global_update_instruction_facts_8616,
    _direct_global_update_name_8616,
    _direct_stack_move_instruction_facts_8616,
    _direct_stack_update_instruction_facts_8616,
    _type_for_access_width_8616,
    lower_stable_ss_linear_stack_dereferences_8616,
    materialize_direct_global_incdec_instructions_8616,
    materialize_direct_stack_incdec_instructions_8616,
    materialize_direct_stack_mov_instructions_8616,
    prune_unsupported_function_pointer_stack_move_assignments_8616,
)
from .lowering.segment_global_materialization import (
    cod_metadata_for_codegen_8616,
    run_segment_global_materialization_8616,
)
from .lowering.segmented_global_loads import (
    materialize_direct_global_symbol_stores_8616,
    materialize_indexed_segmented_global_loads_8616,
    materialize_named_segmented_global_loads_8616,
)
from .lowering.segmented_memory_lowering import (
    finalize_runtime_stack_lowering_8616,
    materialize_runtime_helper_segment_carriers_8616,
    replay_final_codegen_projections_8616,
    runtime_segment_push_source_cvar_8616,
)
from .lowering.ss_bp_substitution import (
    apply_stack_variable_bindings_to_c_text,
)
from .lowering.stack_aggregate_objects import (
    decay_stack_aggregate_call_arguments_8616,
    reapply_stack_aggregate_object_facts_8616,
)
from .lowering.stack_lowering import run_stack_lowering_pass_8616
from .lowering.stack_lowering_from_facts import (
    _canonical_stack_offset_8616,
    _stack_object_name,
    lower_stack_accesses_from_alias_facts_8616,
    materialize_stack_cvar_at_offset_from_facts_8616,
)
from .lowering.stack_prototype_materialization import (
    materialize_annotated_stack_prototype_8616,
    positive_stack_specs_8616,
    reconcile_callsite_interface_declarations_8616,
    reconcile_exact_stack_argument_prototype_8616,
)
from .lowering.stack_value_projection import (
    StackValueProjectionStatus8616,
    project_stack_value_range_8616,
)
from .lowering.stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    publish_selected_stack_cvar_projection_8616,
    stack_cvar_for_machine_bp_range_8616,
)
from .lowering.stack_variable_display_names import (
    publish_stack_variable_projection_display_names_8616,
    reapply_stack_variable_projection_names_8616,
    rebind_restored_stack_coordinate_registry_8616,
)
from .pipeline.contracts import assert_pipeline_contracts_8616
from .pipeline.errors import PipelineHardError
from .pipeline.invariants import format_invariant_report_8616, validate_before_rewrite_8616
from .pipeline.result_contracts import require_optional_result_type_8616, require_result_type_8616
from .pipeline.structured_ast_generation import structured_ast_generation_8616
from .postprocess.affine_compound_assignment import (
    apply_affine_compound_assignment_identity_8616,
    restore_affine_compound_assignment_identity_8616,
)
from .postprocess.bootstrap_orchestration import (
    PostprocessBootstrapOperations8616,
    run_postprocess_bootstrap_steps_8616,
)
from .postprocess.optimization.dce import _dead_code_elimination_8616
from .postprocess.optimization.dead_condition_carriers import prune_unread_pure_condition_carriers_8616
from .postprocess.optimization.dead_setup import _count_dead_setup_escaped_8616
from .postprocess.optimization.local_declarations import dedupe_equivalent_stack_local_declarations_8616
from .postprocess.optimization.pass_driver import (
    OPTIMIZATION_PASSES,
    _normalize_cfunc_root_for_optimization_8616,
)
from .postprocess.optimization.structured_braces import normalize_multi_statement_braces_8616
from .postprocess.optimization.trivial_copy import prune_adjacent_temporary_copy_assignments_8616
from .postprocess.pass_runtime import (
    CallArgumentAstEffect8616,
    DecompilerPostprocessPassSpec,
    PostprocessRuntimeConfig8616,
)
from .postprocess.pass_transaction import (
    PostprocessMutationWitnessCache8616,
    PostprocessPassPreflightAction8616,
    PostprocessPassPreflightInput8616,
    PostprocessPassTransactionState8616,
    decide_postprocess_pass_preflight_8616,
)
from .postprocess.pass_validation_policy import (
    CALLSITE_STACK_ARGUMENT_PASS_NAMES_8616 as _CALLSITE_STACK_ARGUMENT_PASS_NAMES_8616,
)
from .postprocess.pass_validation_policy import (
    DIRECT_GLOBAL_UPDATE_VALIDATION_PASS_NAMES_8616 as _DIRECT_GLOBAL_UPDATE_VALIDATION_PASS_NAMES_8616,
)
from .postprocess.pass_validation_policy import (
    DIRECT_STACK_MOVE_VALIDATION_PASS_NAMES_8616 as _DIRECT_STACK_MOVE_VALIDATION_PASS_NAMES_8616,
)
from .postprocess.pass_validation_policy import (
    DIRECT_STACK_UPDATE_VALIDATION_PASS_NAMES_8616 as _DIRECT_STACK_UPDATE_VALIDATION_PASS_NAMES_8616,
)
from .postprocess.pass_validation_policy import (
    HELPER_NAME_ONLY_VALIDATION_PASS_NAMES_8616 as _HELPER_NAME_ONLY_VALIDATION_PASS_NAMES_8616,
)
from .postprocess.pass_validation_policy import (
    JCC_REWRITE_VALIDATION_PASS_NAMES_8616 as _JCC_REWRITE_VALIDATION_PASS_NAMES_8616,
)
from .postprocess.pass_validation_policy import (
    MANDATORY_VALIDATION_PASS_NAMES_8616 as _MANDATORY_VALIDATION_PASS_NAMES_8616,
)
from .postprocess.pass_validation_policy import (
    MISSING_TERMINAL_AX_RETURN_PASS_NAMES_8616 as _MISSING_TERMINAL_AX_RETURN_PASS_NAMES_8616,
)
from .postprocess.pass_validation_policy import (
    NON_IDIV_DIRECT_STACK_MOVE_SOURCE_KINDS_8616 as _NON_IDIV_DIRECT_STACK_MOVE_SOURCE_KINDS_8616,
)
from .postprocess.pass_validation_policy import (
    PASS_LOCAL_REJECT_CONTINUE_PASS_NAMES_8616 as _PASS_LOCAL_REJECT_CONTINUE_PASS_NAMES_8616,
)
from .postprocess.pass_validation_policy import (
    PASS_REJECT_BUDGET_DEFAULT_8616 as _PASS_REJECT_BUDGET_DEFAULT_8616,
)
from .postprocess.pass_validation_policy import (
    PASS_REJECT_BUDGET_ELIGIBLE_NAMES_8616 as _PASS_REJECT_BUDGET_ELIGIBLE_NAMES_8616,
)
from .postprocess.rollback_snapshot_cache import (
    PostprocessRollbackSnapshot8616,
    PostprocessRollbackSnapshotController8616,
    RollbackSnapshotInvalidation8616,
)
from .postprocess.runtime_configuration import configure_postprocess_runtime_8616
from .postprocess.validation_contracts import (
    CfgReturnExprDeltaRefusal8616 as _CfgReturnExprDeltaRefusal8616,
)
from .postprocess.validation_contracts import (
    DirectGlobalSymbolRef8616 as _DirectGlobalSymbolRef8616,
)
from .postprocess.validation_contracts import (
    PostprocessDestructiveSalvageFamily8616 as _PostprocessDestructiveSalvageFamily8616,
)
from .postprocess.validation_contracts import (
    PostprocessFunctionComplexity8616 as _PostprocessFunctionComplexity8616,
)
from .postprocess.validation_contracts import (
    PostprocessPassRefusalReason8616 as _PostprocessPassRefusalReason8616,
)
from .postprocess.validation_contracts import (
    PostprocessValidationBlockingReason8616 as _PostprocessValidationBlockingReason8616,
)
from .postprocess.validation_contracts import (
    PostprocessValidationDeltaKind8616 as _PostprocessValidationDeltaKind8616,
)
from .postprocess.validation_contracts import (
    TerminalStackArgDecision8616 as _TerminalStackArgDecision8616,
)
from .postprocess.validation_contracts import (
    VoidEmptyReturnGuardDecision8616 as _VoidEmptyReturnGuardDecision8616,
)
from .postprocess.validation_contracts import (
    VoidTailCallGuardDecision8616 as _VoidTailCallGuardDecision8616,
)
from .postprocess.validation_contracts import (
    postprocess_validation_blocking_reasons_8616 as _postprocess_validation_blocking_reasons_8616,
)
from .postprocess.validation_contracts import (
    record_postprocess_validation_blocking_reason_8616 as _record_postprocess_validation_blocking_reason_8616,
)
from .render_compat import repair_cfunctioncall_render_targets_8616
from .structuring.condition_provenance import (
    replay_codegen_structured_condition_segment_provenance_8616,
)
from .structuring.loop_body_repair import (
    repair_conditional_continue_guards_from_evidence_8616,
    repair_hoisted_jcc_target_copies_from_evidence_8616,
    repair_pretest_loop_break_guards_from_evidence_8616,
    repair_switch_loop_exit_returns_from_evidence_8616,
)
from .structuring.loop_break_jcc import (
    UnconsumedLoopBreakJccCallbacks8616,
    UnconsumedLoopBreakJccStats8616,
)
from .structuring.loop_break_jcc import (
    materialize_unconsumed_loop_break_jcc_8616 as _structuring_materialize_unconsumed_loop_break_jcc_8616,
)
from .structuring.loop_exit_return_guards import (
    default_loop_exit_return_guard_callbacks_8616,
    repair_loop_exit_return_guards_8616,
)
from .structuring.return_chains import (
    BranchTargetReturnBlockResult8616,
    BranchTargetReturnScanCallbacks8616,
    ComplexDecrementSwitchCallbacks8616,
    ConditionBranchTagCallbacks8616,
    ConditionBranchTagEvidence8616,
    ConditionIdentityCallbacks8616,
    DuplicateEmptyReturnGuardPruneReason8616,
    ExpressionFingerprintCallbacks8616,
    LastAxReturnValueCallbacks8616,
    MaskAccumulatorMaterializationCallbacks8616,
    MaskAccumulatorPairCallbacks8616,
    Return32BitConditionalPairCallbacks8616,
    ReturnChainCountCallbacks8616,
    ReturnChainEmptyIfCallbacks8616,
    ReturnChainFlattenCallbacks8616,
    ReturnChainProofCallbacks8616,
    ReturnConditionalExprPairCallbacks8616,
    ReturnConditionalVoidTailCallCallbacks8616,
    ReturnSelector32BitPairCallbacks8616,
    ReturnSelectorCallbacks8616,
    ReturnSelectorCallsiteProofCallbacks8616,
    SelectorStackExprCallbacks8616,
    SelectorUnsafeEffectsCallbacks8616,
    SequentialDecrementSwitchCallbacks8616,
    SurplusGuardCleanupEvidence8616,
    SurplusGuardCleanupStats8616,
    TerminalAxInstructionAction8616,
    TerminalAxReturnEffect8616,
    TerminalAxReturnEffectKind8616,
    TerminalAxReturnOperandKind8616,
    TerminalAxScanCallbacks8616,
    VoidTailCallGuardProof8616,
    VoidTailCallGuardStatus8616,
    VoidTailCallShapeCallbacks8616,
    VoidTailCallSuffixDiamondCallbacks8616,
    VoidTailCallSuffixDiamondStatus8616,
    compose_ax_byte_lanes_8616,
    ensure_return_chain_codegen_state_8616,
    return_expression_has_wide_word_composition_8616,
    terminal_ax_fallback_supports_widths_8616,
)
from .structuring.return_chains import (
    SurplusIfGuardKind8616 as _SurplusIfGuardKind8616,
)
from .structuring.return_chains import (
    branch_target_return_expr_8616 as _structuring_branch_target_return_expr_8616,
)
from .structuring.return_chains import (
    branch_target_return_value_8616 as _structuring_branch_target_return_value_8616,
)
from .structuring.return_chains import (
    c_node_semantically_empty_8616 as _structuring_c_node_semantically_empty_8616,
)
from .structuring.return_chains import (
    c_statement_shape_8616 as _structuring_c_statement_shape_8616,
)
from .structuring.return_chains import (
    call_argument_component_fingerprints_8616 as _structuring_call_argument_component_fingerprints_8616,
)
from .structuring.return_chains import (
    call_argument_fingerprints_8616 as _structuring_call_argument_fingerprints_8616,
)
from .structuring.return_chains import (
    calls_in_nodes_8616 as _structuring_calls_in_nodes_8616,
)
from .structuring.return_chains import (
    combine_dx_ax_return_expr_8616 as _structuring_combine_dx_ax_return_expr_8616,
)
from .structuring.return_chains import (
    condition_branch_return_value_8616 as _structuring_condition_branch_return_value_8616,
)
from .structuring.return_chains import (
    condition_branch_tag_evidence_8616 as _structuring_condition_branch_tag_evidence_8616,
)
from .structuring.return_chains import (
    condition_has_jcc_evidence_8616 as _structuring_condition_has_jcc_evidence_8616,
)
from .structuring.return_chains import (
    condition_identity_keys_8616 as _structuring_condition_identity_keys_8616,
)
from .structuring.return_chains import (
    conditional_branch_count_8616 as _structuring_conditional_branch_count_8616,
)
from .structuring.return_chains import (
    const_return_value_8616 as _structuring_const_return_value_8616,
)
from .structuring.return_chains import (
    duplicate_empty_return_guard_prune_plan_8616 as _structuring_duplicate_empty_return_guard_prune_plan_8616,
)
from .structuring.return_chains import (
    else_node_empty_8616 as _structuring_else_node_empty_8616,
)
from .structuring.return_chains import (
    equality_return_target_from_32bit_jcc_chain_8616 as _structuring_equality_return_target_from_32bit_jcc_chain_8616,
)
from .structuring.return_chains import (
    first_conditional_jcc_8616 as _structuring_first_conditional_jcc_8616,
)
from .structuring.return_chains import (
    flatten_conditional_return_chain_8616 as _structuring_flatten_conditional_return_chain_8616,
)
from .structuring.return_chains import (
    flatten_straightline_c_statements_8616 as _structuring_flatten_straightline_c_statements_8616,
)
from .structuring.return_chains import (
    identical_assignment_arm_condition_8616 as _structuring_identical_assignment_arm_condition_8616,
)
from .structuring.return_chains import (
    inequality_target_from_32bit_jcc_chain_8616 as _structuring_inequality_target_from_32bit_jcc_chain_8616,
)
from .structuring.return_chains import (
    is_conditional_branch_insn_8616 as _structuring_is_conditional_branch_insn_8616,
)
from .structuring.return_chains import (
    is_empty_return_statement_8616 as _structuring_is_empty_return_statement_8616,
)
from .structuring.return_chains import (
    is_register_call_assignment_8616 as _structuring_is_register_call_assignment_8616,
)
from .structuring.return_chains import (
    last_ax_return_value_8616 as _structuring_last_ax_return_value_8616,
)
from .structuring.return_chains import (
    last_call_addr_before_jcc_in_function_8616 as _structuring_last_call_addr_before_jcc_in_function_8616,
)
from .structuring.return_chains import (
    linear_jcc_block_starts_8616 as _structuring_linear_jcc_block_starts_8616,
)
from .structuring.return_chains import (
    linear_terminal_ax_return_scan_8616 as _structuring_linear_terminal_ax_return_scan_8616,
)
from .structuring.return_chains import (
    materialize_cfg_conditional_return_suffix_8616 as _structuring_materialize_cfg_conditional_return_suffix_8616,
)
from .structuring.return_chains import (
    materialize_cfg_mask_accumulator_8616 as _structuring_materialize_cfg_mask_accumulator_8616,
)
from .structuring.return_chains import (
    materialize_cfg_selector_return_branches_8616 as _structuring_materialize_cfg_selector_return_branches_8616,
)
from .structuring.return_chains import (
    materialize_complex_decrement_switch_return_chain_8616 as _structuring_materialize_complex_decrement_switch_return_chain_8616,
)
from .structuring.return_chains import (
    materialize_empty_if_return_branches_8616 as _structuring_materialize_empty_if_return_branches_8616,
)
from .structuring.return_chains import (
    materialize_sequential_decrement_switch_return_chain_8616 as _structuring_materialize_sequential_decrement_switch_return_chain_8616,
)
from .structuring.return_chains import (
    materialize_void_tail_call_guard_8616 as _structuring_materialize_void_tail_call_guard_8616,
)
from .structuring.return_chains import (
    materialize_void_tail_call_suffix_diamond_8616 as _structuring_materialize_void_tail_call_suffix_diamond_8616,
)
from .structuring.return_chains import (
    next_unconditional_target_after_jcc_8616 as _structuring_next_unconditional_target_after_jcc_8616,
)
from .structuring.return_chains import (
    node_component_fingerprints_8616 as _structuring_node_component_fingerprints_8616,
)
from .structuring.return_chains import (
    node_contains_call_8616 as _structuring_node_contains_call_8616,
)
from .structuring.return_chains import (
    ordered_32bit_conditional_return_pairs_from_cfg_8616 as _structuring_ordered_32bit_conditional_return_pairs_from_cfg_8616,
)
from .structuring.return_chains import (
    ordered_32bit_mask_update_pairs_from_cfg_8616 as _structuring_ordered_32bit_mask_update_pairs_from_cfg_8616,
)
from .structuring.return_chains import (
    ordered_32bit_selector_return_expr_pairs_from_cfg_8616 as _structuring_ordered_32bit_selector_return_expr_pairs_from_cfg_8616,
)
from .structuring.return_chains import (
    ordered_conditional_return_expr_pairs_from_cfg_8616 as _structuring_ordered_conditional_return_expr_pairs_from_cfg_8616,
)
from .structuring.return_chains import (
    ordered_conditional_return_pairs_from_cfg_8616 as _structuring_ordered_conditional_return_pairs_from_cfg_8616,
)
from .structuring.return_chains import (
    ordered_conditional_return_values_8616 as _structuring_ordered_conditional_return_values_8616,
)
from .structuring.return_chains import (
    ordered_conditional_void_tail_call_proofs_from_cfg_8616 as _structuring_ordered_conditional_void_tail_call_proofs_from_cfg_8616,
)
from .structuring.return_chains import (
    record_flattened_return_chain_8616 as _structuring_record_flattened_return_chain_8616,
)
from .structuring.return_chains import (
    resolve_one_hop_jmp_target_8616 as _structuring_resolve_one_hop_jmp_target_8616,
)
from .structuring.return_chains import (
    return_chain_counts_8616 as _structuring_return_chain_counts_8616,
)
from .structuring.return_chains import (
    return_chain_expected_counts_8616 as _structuring_return_chain_expected_counts_8616,
)
from .structuring.return_chains import (
    root_matches_flattened_return_chain_8616 as _structuring_root_matches_flattened_return_chain_8616,
)
from .structuring.return_chains import (
    scan_branch_target_return_block_8616 as _structuring_scan_branch_target_return_block_8616,
)
from .structuring.return_chains import (
    selector_condition_call_addrs_8616 as _structuring_selector_condition_call_addrs_8616,
)
from .structuring.return_chains import (
    selector_condition_call_addrs_from_cfg_8616 as _structuring_selector_condition_call_addrs_from_cfg_8616,
)
from .structuring.return_chains import (
    selector_function_has_unsafe_effects_8616 as _structuring_selector_function_has_unsafe_effects_8616,
)
from .structuring.return_chains import (
    selector_stack_expr_from_ax_load_8616 as _structuring_selector_stack_expr_from_ax_load_8616,
)
from .structuring.return_chains import (
    selector_targets_from_32bit_jcc_chain_8616 as _structuring_selector_targets_from_32bit_jcc_chain_8616,
)
from .structuring.return_chains import (
    single_if_return_8616 as _structuring_single_if_return_8616,
)
from .structuring.return_chains import (
    surplus_empty_guard_condition_8616 as _structuring_surplus_empty_guard_condition_8616,
)
from .structuring.return_chains import (
    tail_call_from_statement_8616 as _structuring_tail_call_from_statement_8616,
)
from .structuring.return_chains import (
    tail_call_payload_from_statement_8616 as _structuring_tail_call_payload_from_statement_8616,
)
from .structuring.selector_return_projection import storage_reconstruction_has_unconsumed_effects_8616
from .tail_validation import (
    X86_16TailValidationSummary,
    build_x86_16_tail_validation_cached_result,
    build_x86_16_tail_validation_verdict,
    callsite_consumed_stack_store_prune_delta_8616,
    callsite_far_pointer_remnant_prune_delta_8616,
    callsite_helper_control_target_delta_8616,
    callsite_mixed_helper_stack_control_delta_8616,
    callsite_resolved_indirect_helper_stack_delta_8616,
    callsite_stack_arg_slot_alias_condition_delta_8616,
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
    conditional_continue_guard_repair_delta_8616,
    direct_stack_move_function_pointer_prune_delta_8616,
    direct_stack_move_idiv_remainder_aux_delta_8616,
    exit_goto_repair_delta_8616,
    fingerprint_x86_16_tail_validation_boundary,
    name_only_helper_annotation_delta_8616,
    persist_x86_16_tail_validation_snapshot,
    segmented_stack_slot_size_precision_delta_8616,
    switch_loop_exit_return_repair_delta_8616,
    validation_delta_removes_stack_or_control_effects_8616,
    validation_delta_touched_fields_8616,
    validation_stack_offsets_in_token_8616,
    validation_stack_write_delta_offsets_are_evidenced_8616,
    validation_without_delta_fields_8616,
    void_tail_call_guard_materialization_delta_8616,
    x86_16_tail_validation_result_passed,
)
from .tail_validation_fingerprint import _expr_fingerprint, _stack_slot_fingerprint_from_slot_8616
from .tail_validation_generation import tail_validation_summary_input_generation_8616
from .validation_materialized_condition_storage import (
    capture_materialized_condition_storage_surface_8616,
    compare_materialized_condition_storage_surfaces_8616,
    record_materialized_condition_storage_failure_8616,
)

type AngrProjectValue = Any
type AngrFunctionValue = Any
type StructuredCodegenValue = Any
type StructuredAstValue = Any


def _boundary_tuple_8616(value: StructuredAstValue) -> tuple[StructuredAstValue, ...]:
    """Convert an iterable supplied by the dynamic angr/codegen boundary to a tuple."""
    return tuple(cast(Iterable[StructuredAstValue], value))


def _boundary_list_8616(value: StructuredAstValue) -> list[StructuredAstValue]:
    """Convert an iterable supplied by the dynamic angr/codegen boundary to a list."""
    return list(cast(Iterable[StructuredAstValue], value))


def _boundary_set_8616(value: StructuredAstValue) -> set[StructuredAstValue]:
    """Convert an iterable supplied by the dynamic angr/codegen boundary to a set."""
    return set(cast(Iterable[StructuredAstValue], value))


__all__ = [
    "DECOMPILER_POSTPROCESS_PASSES",
    "CallsiteStackFactMaterializationResult8616",
    "DecompilerPostprocessPassSpec",
    "LateAstCleanupResult8616",
    "PostSwitchCleanupResult8616",
    "_build_decompiler_postprocess_passes",
    "apply_x86_16_decompiler_postprocess",
    "describe_x86_16_decompiler_postprocess_stage",
    "finalize_late_ast_cleanup_8616",
    "finalize_post_switch_cleanup_after_seqnode_replacement_8616",
    "run_callsite_stack_fact_materialization_8616",
    "run_late_ast_cleanup_8616",
    "run_post_switch_cleanup_after_seqnode_replacement_8616",
]


_UnconsumedLoopBreakJccStats8616 = UnconsumedLoopBreakJccStats8616


_C_AST_CHILD_ATTRS_8616 = (
    "statements",
    "condition",
    "condition_and_nodes",
    "else_node",
    "lhs",
    "rhs",
    "operand",
    "expr",
    "variable",
    "base",
    "index",
    "iftrue",
    "iffalse",
    "callee",
    "args",
    "target",
)

_POSTPROCESS_ROLLBACK_METADATA_EXCLUDE_8616 = frozenset(
    {
        "_inertia_last_postprocess_pass",
        "_inertia_postprocess_accepted_validation_deltas",
        "_inertia_postprocess_changed",
        "_inertia_postprocess_passes",
        "_inertia_postprocess_pre_validation_summary",
        "_inertia_postprocess_rejected_passes",
        "_inertia_postprocess_validation_failed",
        "_inertia_postprocess_validation_failure_error",
        "_inertia_postprocess_validation_failure_pass",
        "_inertia_regeneration_context",
        "_inertia_regeneration_error",
        "_inertia_regeneration_failed",
        "_inertia_regeneration_last_pass",
        "_inertia_rewrite_failed",
        "_inertia_rewrite_failure_error",
        "_inertia_rewrite_failure_pass",
        "_inertia_skip_per_pass_validation_large_function",
        "_inertia_tail_validation_snapshot",
    }
)

_POSTPROCESS_METADATA_SNAPSHOT_SCALAR_TYPES_8616 = (str, bytes, int, float, bool, type(None))
_POSTPROCESS_METADATA_SNAPSHOT_MAX_DEPTH_8616 = 4
_POSTPROCESS_METADATA_SNAPSHOT_MAX_ITEMS_8616 = 512


def _debug_dump_calls_8616(label: str, ctext: str, function_addr: int) -> None:
    def _impl() -> None:
        if not os.environ.get("INERTIA_DEBUG_CALL_MUTATION"):
            return
        target_text = os.environ.get("INERTIA_DEBUG_CALL_MUTATION_ADDR")
        target_addr = int(target_text, 0) if isinstance(target_text, str) and target_text.strip() else None
        if isinstance(target_addr, int) and function_addr != target_addr:
            return
        log = logging.getLogger(__name__)
        filter_text = os.environ.get("INERTIA_DEBUG_CALL_MUTATION_FILTER", "")
        tracked = tuple(part.strip() for part in filter_text.split(",") if part.strip())
        call_line_re = re.compile(r"^\s*(?:[A-Za-z_]\w*\s*=\s*)?[A-Za-z_]\w*\s*\(")
        for line in str(ctext or "").splitlines():
            stripped = line.strip()
            if (tracked and any(name in stripped for name in tracked)) or (
                not tracked and call_line_re.match(stripped)
            ):
                log.warning("[call-mutation] %s: %s", label, stripped)

    return _impl()


def _debug_heap_call_lines_8616(label: str, c_text: str, function_addr: int) -> None:
    def _impl() -> None:
        if not os.environ.get("INERTIA_DEBUG_HEAPSORT_CALLS"):
            return
        log = logging.getLogger(__name__)
        for line in str(c_text or "").splitlines():
            if "Heap" in line or "heap" in line:
                log.warning("[heapsort-calls] %s %#x: %s", label, function_addr, line.strip())

    return _impl()


def _debug_stack_noise_8616(label: str, c_text: str, function_addr: int) -> None:
    def _impl() -> None:
        if not os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
            return
        target_text = os.environ.get("INERTIA_DEBUG_STACK_NOISE_ADDR")
        target_addr = int(target_text, 0) if isinstance(target_text, str) and target_text.strip() else None
        if isinstance(target_addr, int) and function_addr != target_addr:
            return
        log = logging.getLogger(__name__)
        for line in str(c_text or "").splitlines():
            if "&s_" in line or "s_" in line or "stack[" in line:
                log.warning("[stack-noise] %s: %s", label, line.strip())

    return _impl()


def _heap_postprocess_debug_enabled_8616() -> bool:
    return bool(os.environ.get("INERTIA_DEBUG_STACK_NOISE"))


def _normalize_pointer_high_byte_shifts_8616(codegen: StructuredAstValue) -> bool:
    """Ensure high-byte projection shifts operate on an integer expression.

    This keeps semantics explicit for 16-bit address-like carriers and avoids
    MS C C2116 on raw pointer shifts (e.g. ``&x >> 8``).
    """
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None)
    if root is None:
        return False
    changed = False

    def _transform(node: StructuredAstValue) -> StructuredAstValue:
        nonlocal changed
        if not isinstance(node, CBinaryOp) or getattr(node, "op", None) != "Shr":
            return node
        shift_value = getattr(getattr(node, "rhs", None), "value", None)
        if shift_value != 8:
            return node
        lhs = getattr(node, "lhs", None)
        while isinstance(lhs, CTypeCast):
            lhs = lhs.expr
        if not isinstance(lhs, CUnaryOp) or getattr(lhs, "op", None) not in {"Reference", "AddressOf"}:
            return node
        changed = True
        cast_lhs = CTypeCast(None, SimTypeShort(False), node.lhs, codegen=codegen)
        return CBinaryOp("Shr", cast_lhs, node.rhs, codegen=codegen, tags=getattr(node, "tags", None))

    new_root = _transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        root = new_root
    cast(Any, _post)._replace_c_children_8616(root, _transform)
    return changed


def _bind_type_to_arch_8616(type_: StructuredAstValue, arch: StructuredAstValue) -> StructuredAstValue:
    """Bind a SimType to the project arch, upgrading SimTypeBottom to short."""
    if type(type_) is SimTypeBottom:
        try:
            return SimTypeShort(False).with_arch(arch)
        except Exception:
            return SimTypeShort(False)
    if type_ is None or getattr(type_, "_arch", None) is not None or not hasattr(type_, "with_arch"):
        return type_
    try:
        return type_.with_arch(arch)
    except Exception:
        return type_


def _rebind_unified_local_types_8616(unified_locals: dict, arch: StructuredAstValue) -> None:
    """Rebind vartypes inside the unified-local map, dropping stale entries."""
    for variable, entries in list(unified_locals.items()):
        if not isinstance(entries, set):
            continue
        new_entries = set()
        changed = False
        for cvar, vartype in entries:
            bound = _bind_type_to_arch_8616(vartype, arch)
            if bound is not vartype:
                changed = True
            if bound is not getattr(cvar, "variable_type", None):
                cvar.variable_type = bound
            new_entries.add((cvar, bound))
        if changed:
            unified_locals[variable] = new_entries


def _rebind_cvar_map_types_8616(cfunc: StructuredAstValue, arch: StructuredAstValue) -> None:
    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        for cvar in variables_in_use.values():
            bound = _bind_type_to_arch_8616(getattr(cvar, "variable_type", None), arch)
            if bound is not getattr(cvar, "variable_type", None):
                cvar.variable_type = bound

    unified_locals = getattr(cfunc, "unified_local_vars", None)
    if isinstance(unified_locals, dict):
        _rebind_unified_local_types_8616(unified_locals, arch)


def _bind_codegen_variable_types_to_arch_8616(codegen: StructuredAstValue) -> None:
    """Bind every codegen-visible variable type to the project arch."""
    project = getattr(codegen, "project", None)
    arch = getattr(project, "arch", None)
    if arch is None:
        return

    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return

    _rebind_cvar_map_types_8616(cfunc, arch)

    root = getattr(cfunc, "statements", None)
    if root is None:
        return
    for node in _iter_c_nodes_deep_8616(root):
        bound = _bind_type_to_arch_8616(getattr(node, "variable_type", None), arch)
        if bound is not getattr(node, "variable_type", None):
            cast(Any, node).variable_type = bound



def _postprocess_exit_goto_repair_delta_8616(validation: Mapping[str, StructuredAstValue]) -> bool:
    """Compatibility shim for validation-owned exit-goto repair delta policy."""
    return require_result_type_8616(
        exit_goto_repair_delta_8616(validation),
        bool,
        owner="tail_validation.exit_goto_repair_delta_8616",
    )


def _postprocess_has_unresolved_gotos_8616(codegen: StructuredAstValue) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None) or cfunc
    return any(isinstance(node, CGoto) for node in _iter_c_nodes_deep_8616(root))


def _callsite_materialization_left_no_stack_lowering_input_8616(codegen: StructuredAstValue) -> bool:
    """Return True when dynamic codegen compatibility state exposes no new stack facts."""
    if (
        getattr(codegen, "_inertia_callsite_materialization_last_decision_8616", None)
        is not _calls.CallsiteMaterializationDecision8616.PROCESSED_NO_CHANGE
    ):
        return False
    if getattr(codegen, "_inertia_callsite_materialization_last_changed_8616", False):
        return False
    return _callsite_after_ss_lowering_rematerialization_unneeded_8616(codegen)


def _stack_lowering_rerun_refusal_kind_8616(codegen: StructuredAstValue) -> str | None:
    """Classify the refusal counter key for a post-call stack-lowering rerun."""
    try:
        pointer_memory_materialized = codegen._inertia_pointer_memory_materialized_8616 is not None
    except AttributeError:
        pointer_memory_materialized = False
    if pointer_memory_materialized:
        return "_inertia_stack_lowering_rerun_refused_pointer_memory_8616"
    if getattr(codegen, "_inertia_return_selector_materialized_8616", False):
        return "_inertia_stack_lowering_rerun_refused_selector_return_8616"
    if getattr(
        codegen, "_inertia_callsite_materialization_last_decision_8616", None
    ) is _calls.CallsiteMaterializationDecision8616.CACHE_HIT and not getattr(
        codegen, "_inertia_callsite_materialization_last_changed_8616", False
    ):
        return "_inertia_stack_lowering_rerun_refused_callsite_cache_hit_8616"
    if _callsite_materialization_left_no_stack_lowering_input_8616(codegen):
        return "_inertia_stack_lowering_rerun_skipped_callsite_no_input_8616"
    return None


def _structured_ast_too_large_for_broad_rerun_8616(codegen: StructuredAstValue, max_nodes: int = 1200) -> bool:
    """Return true when dynamic codegen AST state is too large for broad late reruns."""
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None)
    if root is None:
        return False
    visited = 0
    for _node in _iter_c_nodes_deep_8616(root):
        visited += 1
        if visited > max_nodes:
            codegen._inertia_stack_lowering_rerun_ast_node_count_8616 = visited
            return True
    codegen._inertia_stack_lowering_rerun_ast_node_count_8616 = visited
    return False


def _byte_offset_only_rerun_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, counter_key: str
) -> bool:
    """Bump the byte-only counter and run only the SS byte-offset rewrite."""
    setattr(codegen, counter_key, int(getattr(codegen, counter_key, 0) or 0) + 1)
    from inertia_decompiler.cli_c_ast_rewrites import (
        _rewrite_ss_stack_byte_offsets as _rewrite_stack_byte_offsets,
    )

    return require_result_type_8616(
        _rewrite_stack_byte_offsets(project, codegen),
        bool,
        owner="cli_c_ast_rewrites._rewrite_ss_stack_byte_offsets",
    )


def _rerun_stack_lowering_consumers_after_calls_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:
    """Rerun bounded stack-lowering consumers through dynamic codegen compatibility state."""
    refusal_key = _stack_lowering_rerun_refusal_kind_8616(codegen)
    if refusal_key is not None:
        setattr(codegen, refusal_key, int(getattr(codegen, refusal_key, 0) or 0) + 1)
        return False
    from inertia_decompiler.cli_c_ast_rewrites import (
        _canonicalize_stack_cvars as _rewrite_canonicalize_stack_cvars,
    )
    from inertia_decompiler.cli_c_ast_rewrites import (
        _rewrite_ss_stack_byte_offsets as _rewrite_stack_byte_offsets,
    )

    if getattr(codegen, "_inertia_skip_per_pass_validation_large_function", False):
        return _byte_offset_only_rerun_8616(
            project, codegen, "_inertia_stack_lowering_large_function_byte_only_8616"
        )
    if _structured_ast_too_large_for_broad_rerun_8616(codegen):
        return _byte_offset_only_rerun_8616(
            project, codegen, "_inertia_stack_lowering_rerun_ast_large_byte_only_8616"
        )

    previous_budget_exists = hasattr(codegen, "_inertia_stack_lowering_canonicalize_max_depth_8616")
    previous_budget = getattr(codegen, "_inertia_stack_lowering_canonicalize_max_depth_8616", None)
    current_budget = previous_budget if isinstance(previous_budget, int) and previous_budget > 0 else 64
    codegen._inertia_stack_lowering_canonicalize_max_depth_8616 = min(current_budget, 16)
    codegen._inertia_stack_lowering_after_call_canonicalize_budget_8616 = int(
        getattr(codegen, "_inertia_stack_lowering_canonicalize_max_depth_8616", 16) or 16
    )
    try:
        return require_result_type_8616(
            run_stack_lowering_pass_8616(
                lower_stable_ss_stack_accesses=lambda: False,
                rewrite_ss_stack_byte_offsets=lambda: _rewrite_stack_byte_offsets(project, codegen),
                canonicalize_stack_cvars=lambda: _rewrite_canonicalize_stack_cvars(codegen),
                codegen=codegen,
                project=project,
                # This is a late consumer rerun after callsite materialization. Keep
                # expensive global lowering disabled, but run runtime segment lowering
                # once because call materialization can expose fresh segment carriers.
                max_rounds=1,
                lower_global_segment_accesses=False,
                lower_runtime_segment_accesses=True,
            ),
            bool,
            owner="lowering.stack_lowering_impl.run_stack_lowering_pass_8616",
        )
    finally:
        if previous_budget_exists:
            codegen._inertia_stack_lowering_canonicalize_max_depth_8616 = previous_budget
        elif hasattr(codegen, "_inertia_stack_lowering_canonicalize_max_depth_8616"):
            delattr(codegen, "_inertia_stack_lowering_canonicalize_max_depth_8616")



def _normalize_fact_backed_stack_accesses_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:
    """Canonicalize AST stack accesses after alias-fact materialization.

    Stack identity is still owned by alias/lowering. This bridge only runs AST
    consumers after proven stack facts have materialized real SimStackVariables,
    so validation and live postprocess see the same canonical SS:BP form.
    """
    if getattr(codegen, "cfunc", None) is None:
        return False

    changed = False
    if not getattr(codegen, "_inertia_semantic_facts_transferred", False):
        transfer_semantic_alias_facts_to_codegen_8616(project, codegen)

    alias_facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
    if isinstance(alias_facts, list) and alias_facts:
        before_materialized = int(getattr(codegen, "_inertia_semantic_stack_materialized_count", 0) or 0)
        lower_stack_accesses_from_alias_facts_8616(codegen, alias_facts)
        after_materialized = int(getattr(codegen, "_inertia_semantic_stack_materialized_count", 0) or 0)
        changed = after_materialized > before_materialized

    if not getattr(codegen, "_inertia_semantic_stack_materialized_count", 0):
        return changed

    from inertia_decompiler.cli_c_ast_rewrites import (
        _canonicalize_stack_cvars as _rewrite_canonicalize_stack_cvars,
    )
    from inertia_decompiler.cli_c_ast_rewrites import (
        _rewrite_ss_stack_byte_offsets as _rewrite_stack_byte_offsets,
    )

    changed = bool(_rewrite_stack_byte_offsets(project, codegen)) or changed
    changed = bool(_rewrite_canonicalize_stack_cvars(codegen)) or changed
    return changed


def _fact_backed_stack_normalize_enabled_8616() -> bool:
    return os.environ.get("INERTIA_ENABLE_FACT_BACKED_STACK_NORMALIZE", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _repair_loop_exit_return_guards_pass_8616(codegen: StructuredAstValue) -> bool:
    handler = globals().get("_repair_loop_exit_return_guards_8616")
    if callable(handler):
        return bool(handler(codegen))
    return False


def _repair_switch_loop_exit_returns_from_evidence_pass_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Compatibility fallback for structuring-owned switch loop-exit return repair."""
    # Dynamic boundary: legacy angr codegen only has this flag after the structuring wrapper runs.
    if getattr(codegen, "_inertia_switch_loop_exit_return_structuring_pass_ran_8616", False):
        return False
    return require_result_type_8616(
        repair_switch_loop_exit_returns_from_evidence_8616(project, codegen),
        bool,
        owner="structuring.loop_body_repair.repair_switch_loop_exit_returns_from_evidence_8616",
    )


def _repair_conditional_continue_guards_from_evidence_pass_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Compatibility fallback for structuring-owned conditional-continue repair."""
    # Dynamic boundary: legacy angr codegen only has this flag after the structuring wrapper runs.
    if getattr(codegen, "_inertia_conditional_continue_guard_structuring_pass_ran_8616", False):
        return False
    return require_result_type_8616(
        repair_conditional_continue_guards_from_evidence_8616(project, codegen),
        bool,
        owner="structuring.loop_body_repair.repair_conditional_continue_guards_from_evidence_8616",
    )


def _repair_pretest_loop_break_guards_from_evidence_pass_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Replay structuring-owned pretest repair after legacy AST regeneration."""
    return require_result_type_8616(
        repair_pretest_loop_break_guards_from_evidence_8616(project, codegen),
        bool,
        owner="structuring.loop_body_repair.repair_pretest_loop_break_guards_from_evidence_8616",
    )


def _repair_hoisted_jcc_target_copies_from_evidence_pass_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Compatibility fallback for structuring-owned hoisted JCC target-copy repair."""
    # Dynamic boundary: legacy angr codegen only has this flag after the structuring wrapper runs.
    if getattr(codegen, "_inertia_hoisted_jcc_target_copy_structuring_pass_ran_8616", False):
        return False
    return require_result_type_8616(
        repair_hoisted_jcc_target_copies_from_evidence_8616(project, codegen),
        bool,
        owner="structuring.loop_body_repair.repair_hoisted_jcc_target_copies_from_evidence_8616",
    )


def _apply_typed_conditions_to_codegen_pass_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:
    """Compatibility fallback for structuring-owned typed condition materialization."""
    # Dynamic boundary: legacy angr codegen only has this flag after the structuring wrapper runs.
    if getattr(codegen, "_inertia_condition_materialization_structuring_pass_ran_8616", False):
        return False
    return require_result_type_8616(
        _apply_typed_conditions_to_codegen_8616(project, codegen),
        bool,
        owner="structuring.condition_materialization.apply_typed_conditions_to_codegen_8616",
    )


def _rewrite_decoded_jcc_conditions_pass_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:
    """Compatibility fallback for structuring-owned decoded-JCC condition materialization."""
    # Dynamic boundary: legacy angr codegen only has this flag after the structuring wrapper runs.
    if getattr(codegen, "_inertia_condition_materialization_structuring_pass_ran_8616", False):
        return False
    return require_result_type_8616(
        _jcc._rewrite_decoded_jcc_conditions_8616(project, codegen),
        bool,
        owner="decompiler_postprocess_jcc._rewrite_decoded_jcc_conditions_8616",
    )


def _rewrite_flag_condition_pairs_pass_8616(codegen: StructuredAstValue) -> bool:
    """Compatibility fallback for structuring-owned flag-condition pair cleanup."""
    # Dynamic boundary: legacy angr codegen only has this flag after the structuring cleanup wrapper runs.
    if getattr(codegen, "_inertia_condition_cleanup_structuring_pass_ran_8616", False):
        return False
    return require_result_type_8616(
        _flags._rewrite_flag_condition_pairs_8616(codegen),
        bool,
        owner="postprocess.flags_cleanup._rewrite_flag_condition_pairs_8616",
    )


def _rewrite_flag_bit_value_uses_pass_8616(codegen: StructuredAstValue) -> bool:
    """Compatibility fallback for structuring-owned flag-bit value cleanup."""
    # Dynamic boundary: legacy angr codegen only has this flag after the structuring cleanup wrapper runs.
    if getattr(codegen, "_inertia_condition_cleanup_structuring_pass_ran_8616", False):
        return False
    return require_result_type_8616(
        _flags._rewrite_flag_bit_value_uses_8616(codegen),
        bool,
        owner="postprocess.flags_cleanup._rewrite_flag_bit_value_uses_8616",
    )


def _fix_interval_guard_conditions_pass_8616(codegen: StructuredAstValue) -> bool:
    """Compatibility fallback for structuring-owned interval-guard cleanup."""
    # Dynamic boundary: legacy angr codegen only has this flag after the structuring cleanup wrapper runs.
    if getattr(codegen, "_inertia_condition_cleanup_structuring_pass_ran_8616", False):
        return False
    return require_result_type_8616(
        _flags._fix_interval_guard_conditions_8616(codegen),
        bool,
        owner="postprocess.flags_cleanup._fix_interval_guard_conditions_8616",
    )


def _signed_i16_immediate_8616(value: int) -> int:
    value = int(value) & 0xFFFF
    if value & 0x8000:
        return value - 0x10000
    return value


def _clone_c_expr_8616(expr: StructuredAstValue) -> StructuredAstValue:
    codegen = getattr(expr, "codegen", None)
    if isinstance(expr, CVariable):
        return CVariable(
            cast(Any, expr.variable),
            unified_variable=expr.unified_variable,
            variable_type=expr.variable_type,
            vvar_id=expr.vvar_id,
            codegen=codegen,
            tags=expr.tags,
        )
    if isinstance(expr, CConstant):
        return CConstant(
            expr.value,
            cast(Any, expr.type),
            reference_values=expr.reference_values,
            codegen=codegen,
            tags=expr.tags,
        )
    if isinstance(expr, CBinaryOp):
        return CBinaryOp(
            expr.op,
            _clone_c_expr_8616(expr.lhs),
            _clone_c_expr_8616(expr.rhs),
            codegen=codegen,
            tags=expr.tags,
        )
    if isinstance(expr, CUnaryOp):
        return CUnaryOp(
            expr.op,
            _clone_c_expr_8616(expr.operand),
            codegen=codegen,
            tags=expr.tags,
        )
    if isinstance(expr, CTypeCast):
        return CTypeCast(
            expr.src_type,
            cast(Any, expr.dst_type),
            _clone_c_expr_8616(expr.expr),
            codegen=codegen,
            tags=expr.tags,
        )
    with contextlib.suppress(Exception):
        return copy.copy(expr)
    return expr


def _record_terminal_stack_arg_decision_8616(
    codegen: StructuredAstValue, decision: StructuredAstValue
) -> None:
    if codegen is None:
        return
    history = _boundary_tuple_8616(getattr(codegen, "_inertia_terminal_stack_arg_decisions_8616", ()) or ())
    codegen._inertia_terminal_stack_arg_decisions_8616 = (*history, decision.value)


def _terminal_prototype_arg_map_8616(
    project: StructuredAstValue, cfunc: StructuredAstValue, canonical_disp: int, width: int
) -> tuple[StructuredAstValue, dict[int, tuple[StructuredAstValue, str | None]]]:
    """Resolve the function prototype and map canonical_disp to (arg_type, name)."""
    prototype = getattr(cfunc, "functy", None) or getattr(cfunc, "prototype", None)
    if prototype is None:
        try:
            if project is not None:
                function = project.kb.functions.function(addr=getattr(cfunc, "addr", None), create=False)
                prototype = getattr(function, "prototype", None)
        except Exception:
            prototype = None
    prototype_arg_map: dict[int, tuple[StructuredAstValue, str | None]] = {}
    if isinstance(prototype, SimTypeFunction):
        arg_offset = 4
        prototype_arg_names = _boundary_tuple_8616(prototype.arg_names or ())
        for arg_index, arg_type in enumerate(_boundary_tuple_8616(prototype.args or ())):
            if int(arg_offset) == canonical_disp:
                prototype_arg_name = prototype_arg_names[arg_index] if arg_index < len(prototype_arg_names) else None
                if not (
                    isinstance(prototype_arg_name, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", prototype_arg_name)
                ):
                    prototype_arg_name = None
                prototype_arg_map[canonical_disp] = (arg_type, prototype_arg_name)
                break
            arg_width = _post._type_size_bytes_8616(arg_type, default=width)
            if not isinstance(arg_width, int) or arg_width <= 0:
                arg_width = max(2, width)
            arg_offset += max(2, arg_width)
    return prototype, prototype_arg_map


def _terminal_existing_stack_slot_expr_8616(
    codegen: StructuredAstValue,
    variables_in_use: StructuredAstValue,
    canonical_disp: int,
    prototype_arg_info: tuple[StructuredAstValue, str | None] | None,
    project_arch: StructuredAstValue,
) -> StructuredAstValue:
    """Return an existing variables_in_use slot expression for canonical_disp."""
    if not isinstance(variables_in_use, Mapping):
        return None
    for var, candidate in variables_in_use.items():
        if (
            isinstance(var, SimStackVariable)
            and machine_bp_offset_for_stack_variable_8616(codegen, var) == canonical_disp
            and candidate is not None
        ):
            _apply_prototype_arg_identity_8616(candidate, prototype_arg_info, project_arch)
            _record_terminal_stack_arg_decision_8616(codegen, _TerminalStackArgDecision8616.EXISTING_STACK_SLOT)
            return _clone_c_expr_8616(candidate)
    return None


def _apply_prototype_arg_identity_8616(
    cvar: StructuredAstValue,
    prototype_arg_info: tuple[StructuredAstValue, str | None] | None,
    project_arch: StructuredAstValue,
) -> None:
    """Attach prototype identity through dynamic angr/codegen compatibility objects."""
    if prototype_arg_info is None or not isinstance(cvar, CVariable):
        return
    arg_type, prototype_arg_name = prototype_arg_info
    variable = getattr(cvar, "variable", None)
    if not isinstance(variable, SimStackVariable):
        return
    if isinstance(prototype_arg_name, str) and prototype_arg_name:
        variable.name = prototype_arg_name
        with contextlib.suppress(Exception):
            cast(Any, cvar).name = prototype_arg_name
    if arg_type is not None:
        cvar.variable_type = arg_type.with_arch(project_arch) if project_arch is not None else arg_type


def _materialize_terminal_arg_from_prototype_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    cfunc: StructuredAstValue,
    canonical_disp: int,
    width: int,
    prototype: StructuredAstValue,
    prototype_arg_map: dict[int, tuple[StructuredAstValue, str | None]],
    arg_list: list,
    variables_in_use: StructuredAstValue,
    project_arch: StructuredAstValue,
) -> StructuredAstValue:
    """Materialize a new CVariable arg from prototype evidence for canonical_disp."""
    arg_type, prototype_arg_name = prototype_arg_map[canonical_disp]
    arg_type = arg_type if arg_type is not None else SimTypeShort(False)
    arg_type = arg_type.with_arch(project_arch) if project_arch is not None else arg_type
    arg_name = prototype_arg_name or f"arg_{canonical_disp:x}"
    variable = SimStackVariable(
        canonical_disp,
        width,
        base="bp",
        name=arg_name,
        region=getattr(cfunc, "addr", None),
    )
    cvar = CVariable(variable, variable_type=arg_type, codegen=codegen)
    arg_list.append(cvar)
    arg_list.sort(
        key=lambda item: _canonical_stack_offset_8616(getattr(getattr(item, "variable", None), "offset", 0) or 0)
    )
    cfunc.arg_list = arg_list
    if isinstance(variables_in_use, dict):
        variables_in_use[variable] = cvar
    unified = getattr(cfunc, "unified_local_vars", None)
    if isinstance(unified, dict):
        unified[variable] = {(cvar, arg_type)}
    return_type = (
        getattr(prototype, "returnty", None) if isinstance(prototype, SimTypeFunction) else SimTypeShort(False)
    )
    arg_types = [getattr(arg, "variable_type", None) or SimTypeShort(False) for arg in arg_list]
    arg_names = [
        getattr(getattr(arg, "variable", None), "name", None) or f"arg_{index}"
        for index, arg in enumerate(arg_list)
    ]
    with contextlib.suppress(Exception):
        if project_arch is not None:
            new_proto = SimTypeFunction(arg_types, return_type, arg_names=arg_names).with_arch(project_arch)
            cfunc.functy = new_proto
            cfunc.prototype = new_proto
    codegen._inertia_missing_terminal_ax_return_stack_args_materialized_8616 = (
        int(getattr(codegen, "_inertia_missing_terminal_ax_return_stack_args_materialized_8616", 0) or 0) + 1
    )
    return _clone_c_expr_8616(cvar)


def _terminal_stack_arg_expr_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, disp: int, size: int
) -> StructuredAstValue:
    """Consume Lowering's stack views before legacy dynamic slot compatibility."""
    cfunc = getattr(codegen, "cfunc", None) if codegen is not None else None
    if int(disp) <= 2 or cfunc is None:
        _record_terminal_stack_arg_decision_8616(codegen, _TerminalStackArgDecision8616.FALLBACK)
        return _clone_c_expr_8616(_jcc._stack_slot_expr_8616(codegen, int(disp), int(size) or 2))
    assert codegen is not None
    project_arch = getattr(project, "arch", None)

    # ABI slot rounding does not change the width of a machine load.
    width = int(size) or 2
    canonical_disp = _canonical_stack_offset_8616(int(disp))
    if canonical_disp is None:
        _record_terminal_stack_arg_decision_8616(codegen, _TerminalStackArgDecision8616.FALLBACK)
        return _clone_c_expr_8616(_jcc._stack_slot_expr_8616(codegen, int(disp), width))

    projection = project_stack_value_range_8616(codegen, canonical_disp, width)
    if projection.status is StackValueProjectionStatus8616.CONTAINED_VALUE:
        _record_terminal_stack_arg_decision_8616(codegen, _TerminalStackArgDecision8616.EXISTING_STACK_SLOT)
        return projection.expression
    if projection.status not in {
        StackValueProjectionStatus8616.NO_OWNER,
        StackValueProjectionStatus8616.EXACT_VALUE,
    }:
        # A proven conflict or out-of-value access must not create competing storage.
        return None

    # Exact reads retain their existing interface identity and prototype binding.

    prototype, prototype_arg_map = _terminal_prototype_arg_map_8616(project, cfunc, canonical_disp, width)
    prototype_arg_info = prototype_arg_map.get(canonical_disp)

    arg_list = _boundary_list_8616(getattr(cfunc, "arg_list", ()) or ())
    for arg in arg_list:
        variable = getattr(arg, "variable", None)
        if (
            isinstance(variable, SimStackVariable)
            and machine_bp_offset_for_stack_variable_8616(codegen, variable) == canonical_disp
        ):
            _apply_prototype_arg_identity_8616(arg, prototype_arg_info, project_arch)
            _record_terminal_stack_arg_decision_8616(codegen, _TerminalStackArgDecision8616.EXISTING_ARG)
            return _clone_c_expr_8616(arg)

    variables_in_use = getattr(cfunc, "variables_in_use", None)
    existing = _terminal_existing_stack_slot_expr_8616(
        codegen, variables_in_use, canonical_disp, prototype_arg_info, project_arch
    )
    if existing is not None:
        return existing

    if canonical_disp in prototype_arg_map:
        result = _materialize_terminal_arg_from_prototype_8616(
            project, codegen, cfunc, canonical_disp, width, prototype, prototype_arg_map,
            arg_list, variables_in_use, project_arch,
        )
        _record_terminal_stack_arg_decision_8616(codegen, _TerminalStackArgDecision8616.MATERIALIZED_ARG)
        return result

    local_expr = materialize_stack_cvar_at_offset_from_facts_8616(
        codegen,
        canonical_disp,
        size=width,
        preferred_name=_stack_object_name(canonical_disp, codegen=codegen),
    )
    if local_expr is not None:
        _record_terminal_stack_arg_decision_8616(codegen, _TerminalStackArgDecision8616.MATERIALIZED_STACK_SLOT)
        return _clone_c_expr_8616(local_expr)

    _record_terminal_stack_arg_decision_8616(codegen, _TerminalStackArgDecision8616.FALLBACK)
    return _clone_c_expr_8616(_jcc._stack_slot_expr_8616(codegen, canonical_disp, width))



def _terminal_direct_global_expr_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, disp: int, size: int
) -> StructuredAstValue:
    cfunc = getattr(codegen, "cfunc", None)
    if project is None or cfunc is None:
        return None
    width = int(size) if int(size or 0) in {1, 2, 4} else 2
    addr = int(disp) & 0xFFFF
    symbol_ref = _direct_global_symbol_ref_for_disp_8616(project, codegen, addr, width)
    if symbol_ref is not None:
        name = symbol_ref.name
        base_addr = (addr - symbol_ref.relative_disp) & 0xFFFF
        variable = SimMemoryVariable(base_addr, width, name=name, region=getattr(cfunc, "addr", None))
        cvar = CVariable(variable, variable_type=_type_for_access_width_8616(width), codegen=codegen)
        array_len = None
        if symbol_ref.max_relative_disp > 0 and symbol_ref.max_relative_disp % width == 0:
            array_len = (symbol_ref.max_relative_disp // width) + 1
        record_global_declaration_spec_8616(
            codegen,
            ctype=ctype_for_global_width_8616(width),
            name=name,
            array_len=array_len,
        )
        if array_len is not None and symbol_ref.relative_disp % width == 0:
            return CIndexedVariable(
                _clone_c_expr_8616(cvar),
                CConstant(symbol_ref.relative_disp // width, SimTypeShort(False), codegen=codegen),
                variable_type=_type_for_access_width_8616(width),
                codegen=codegen,
            )
        return _clone_c_expr_8616(cvar)
    name = _direct_global_update_name_8616(project, getattr(cfunc, "addr", None), addr)
    variable = SimMemoryVariable(addr, width, name=name, region=getattr(cfunc, "addr", None))
    cvar = CVariable(variable, variable_type=_type_for_access_width_8616(width), codegen=codegen)
    record_global_declaration_spec_8616(
        codegen,
        ctype=ctype_for_global_width_8616(width),
        name=name,
        array_len=None,
    )
    return _clone_c_expr_8616(cvar)


def _direct_global_symbol_ref_for_disp_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    displacement: int,
    width: int,
) -> _DirectGlobalSymbolRef8616 | None:
    mapping = _direct_global_symbol_refs_by_displacement_8616(project, codegen)
    item = mapping.get((int(displacement) & 0xFFFF, int(width)))
    if item is not None:
        return item
    for (addr, _item_width), candidate in mapping.items():
        if addr == (int(displacement) & 0xFFFF):
            return candidate
    return None


def _direct_global_symbol_refs_by_displacement_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> dict[tuple[int, int], _DirectGlobalSymbolRef8616]:
    cached = getattr(codegen, "_inertia_direct_global_symbol_refs_8616", None)
    if isinstance(cached, dict):
        return cached
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    metadata = _cod_metadata_for_codegen_function_8616(project, func_addr)
    cod_refs = _cod_direct_global_refs_8616(metadata)
    binary_refs = _binary_direct_global_refs_8616(project, codegen, func_addr)
    if not cod_refs or len(cod_refs) != len(binary_refs):
        codegen._inertia_direct_global_symbol_refs_8616 = {}
        return {}
    max_by_name: dict[str, int] = {}
    for name, rel_disp, _width in cod_refs:
        max_by_name[name] = max(max_by_name.get(name, 0), int(rel_disp))
    mapping: dict[tuple[int, int], _DirectGlobalSymbolRef8616] = {}
    for (addr, actual_width), (name, rel_disp, cod_width) in zip(binary_refs, cod_refs, strict=False):
        width = int(actual_width or cod_width or 2)
        mapping[(int(addr) & 0xFFFF, width)] = _DirectGlobalSymbolRef8616(
            name=name,
            relative_disp=int(rel_disp),
            width=width,
            max_relative_disp=max_by_name.get(name, int(rel_disp)),
        )
    codegen._inertia_direct_global_symbol_refs_8616 = mapping
    return mapping


def _cod_metadata_for_codegen_function_8616(
    project: StructuredAstValue, func_addr: int | None
) -> StructuredAstValue | None:
    """Read optional COD metadata through dynamic project compatibility attributes."""
    maps = [getattr(project, "_inertia_cod_metadata_by_func_addr_8616", None)]
    original_project = getattr(project, "_inertia_original_project", None)
    if original_project is not None:
        maps.append(getattr(original_project, "_inertia_cod_metadata_by_func_addr_8616", None))
    candidates = [func_addr] if isinstance(func_addr, int) else []
    delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(delta, int) and isinstance(func_addr, int):
        candidates.extend([func_addr + delta, func_addr - delta])
    for metadata_by_addr in maps:
        if not isinstance(metadata_by_addr, dict):
            continue
        for candidate in candidates:
            metadata = metadata_by_addr.get(candidate)
            if metadata is not None:
                return metadata
        unique = {id(metadata): metadata for metadata in metadata_by_addr.values()}
        if len(unique) == 1:
            return next(iter(unique.values()))
    return None


_COD_DIRECT_GLOBAL_REF_RE_8616 = re.compile(
    r"\b(?P<width>BYTE|WORD|DWORD)\s+PTR\s+_?(?P<name>[A-Za-z_$?@][\w$?@]*)"
    r"(?P<disp>[+-](?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+H|\d+))?(?!\[)",
    re.IGNORECASE,
)
_COD_INDEXED_GLOBAL_REF_RE_8616 = re.compile(
    r"\b(?P<width>BYTE|WORD|DWORD)\s+PTR\s+_?(?P<name>[A-Za-z_$?@][\w$?@]*)"
    r"\[(?P<bracket>[^\]]*)\]",
    re.IGNORECASE,
)
_COD_GLOBAL_DISP_RE_8616 = re.compile(r"(?P<disp>[+-](?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+H|\d+))", re.IGNORECASE)


@dataclass(frozen=True)
class _CODGlobalNameRef8616:
    name: str
    relative_disp: int
    width: int


def _cod_direct_global_refs_8616(
    metadata: StructuredAstValue,
) -> tuple[tuple[str, int, int], ...]:
    return ()


def _parse_cod_global_disp_8616(text: str | None) -> int:
    if not text:
        return 0
    sign = -1 if text[0] == "-" else 1
    body = text[1:]
    if body.lower().startswith("0x"):
        value = int(body, 16)
    elif body.upper().endswith("H"):
        value = int(body[:-1], 16)
    else:
        value = int(body, 10)
    return sign * value


def _canonical_cod_global_name_8616(raw_name: str | None) -> str | None:
    if not isinstance(raw_name, str) or not raw_name:
        return None
    raw = raw_name.lstrip("_")
    static_match = re.match(r"^\$[A-Za-z]+\d+_(?P<name>[A-Za-z_]\w*)$", raw)
    name = static_match.group("name") if static_match is not None else canonical_known_cod_object_name(raw_name) or raw
    if not isinstance(name, str):
        return None
    name = name.lstrip("_")
    return name if re.fullmatch(r"[A-Za-z_]\w*", name) is not None else None


def _capstone_insn_bytes_for_match_8616(
    insn: StructuredAstValue,
    bytes_by_address: Mapping[int, bytes] | None,
) -> bytes | None:
    insn_bytes = _capstone_insn_bytes_8616(insn)
    if isinstance(insn_bytes, bytes):
        return insn_bytes
    address = _capstone_insn_address_8616(insn)
    if isinstance(address, int) and isinstance(bytes_by_address, Mapping):
        mapped = bytes_by_address.get(address)
        if isinstance(mapped, bytes):
            return mapped
    return None


def _cod_instruction_address_delta_8616(
    metadata: StructuredAstValue,
    insns: tuple[StructuredAstValue, ...],
    *,
    bytes_by_address: Mapping[int, bytes] | None = None,
) -> int:
    """Match COD refs to capstone instructions through dynamic compatibility attributes."""
    refs = _boundary_tuple_8616(getattr(metadata, "global_refs", ()) or ()) if metadata is not None else ()
    if not refs or not insns:
        return 0
    for ref in refs:
        offset = getattr(ref, "offset", None)
        raw_bytes = getattr(ref, "instruction_bytes", None)
        if not isinstance(offset, int) or not isinstance(raw_bytes, bytes):
            continue
        for insn in insns:
            address = _capstone_insn_address_8616(insn)
            insn_bytes = _capstone_insn_bytes_for_match_8616(insn, bytes_by_address)
            if not isinstance(address, int) or not isinstance(insn_bytes, bytes):
                continue
            if _cod_entry_bytes_match_binary_insn_8616(raw_bytes, insn_bytes):
                return int(address) - int(offset)
    return 0


def _cod_entry_modrm_disp16_match_8616(cod_bytes: bytes, insn_bytes: bytes, prefix_len: int) -> bool:
    """Match a COD entry whose modrm targets a disp16 field that may have been relocated."""
    if prefix_len + 3 >= len(cod_bytes):
        return False
    modrm = cod_bytes[prefix_len + 1]
    if insn_bytes[prefix_len + 1] != modrm:
        return False
    mod = (modrm >> 6) & 0x3
    rm = modrm & 0x7
    has_disp16 = mod == 2 or (mod == 0 and rm == 6)
    if not has_disp16:
        return False
    return (
        cod_bytes[: prefix_len + 2] == insn_bytes[: prefix_len + 2]
        and cod_bytes[prefix_len + 4 :] == insn_bytes[prefix_len + 4 :]
    )


def _cod_entry_bytes_match_binary_insn_8616(cod_bytes: bytes, insn_bytes: bytes) -> bool:
    if not cod_bytes or len(cod_bytes) != len(insn_bytes):
        return False
    if cod_bytes == insn_bytes:
        return True
    prefix_len = 0
    while prefix_len < len(cod_bytes) and cod_bytes[prefix_len] in {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67}:
        if insn_bytes[prefix_len] != cod_bytes[prefix_len]:
            return False
        prefix_len += 1
    if prefix_len >= len(cod_bytes):
        return False
    opcode = cod_bytes[prefix_len]
    if insn_bytes[prefix_len] != opcode:
        return False
    if opcode in {0xA0, 0xA1, 0xA2, 0xA3} and len(cod_bytes) == prefix_len + 3:
        return True
    return _cod_entry_modrm_disp16_match_8616(cod_bytes, insn_bytes, prefix_len)


def _capstone_insn_address_8616(insn: StructuredAstValue) -> int | None:
    """Return an instruction address from dynamic angr/capstone compatibility wrappers."""
    address = getattr(insn, "address", None)
    if isinstance(address, int):
        return address
    nested = getattr(insn, "insn", None)
    address = getattr(nested, "address", None)
    return address if isinstance(address, int) else None


def _capstone_insn_bytes_8616(insn: StructuredAstValue) -> bytes | None:
    """Return instruction bytes from dynamic angr/capstone compatibility wrappers."""
    cached_bytes = getattr(insn, "_inertia_bytes_8616", None)
    if isinstance(cached_bytes, bytes):
        return cached_bytes
    insn_bytes = getattr(insn, "bytes", None)
    if isinstance(insn_bytes, bytes):
        return insn_bytes
    nested = getattr(insn, "insn", None)
    insn_bytes = getattr(nested, "bytes", None)
    return insn_bytes if isinstance(insn_bytes, bytes) else None


def _cod_global_name_refs_by_address_8616(
    metadata: StructuredAstValue,
    insns: tuple[StructuredAstValue, ...],
    *,
    indexed: bool,
    bytes_by_address: Mapping[int, bytes] | None = None,
) -> dict[int, _CODGlobalNameRef8616]:
    """Collect COD global refs through dynamic COD/capstone compatibility attributes."""
    global_refs = _boundary_tuple_8616(getattr(metadata, "global_refs", ()) or ()) if metadata is not None else ()
    if not global_refs or not insns:
        return {}
    insn_by_address = {
        int(address): insn
        for insn in insns
        if isinstance((address := _capstone_insn_address_8616(insn)), int)
        and isinstance(_capstone_insn_bytes_for_match_8616(insn, bytes_by_address), bytes)
    }
    if not insn_by_address:
        return {}
    address_delta = _cod_instruction_address_delta_8616(metadata, insns, bytes_by_address=bytes_by_address)
    refs: dict[int, _CODGlobalNameRef8616] = {}
    for global_ref in global_refs:
        offset = getattr(global_ref, "offset", None)
        raw_bytes = getattr(global_ref, "instruction_bytes", None)
        if not isinstance(offset, int) or not isinstance(raw_bytes, bytes):
            continue
        if bool(getattr(global_ref, "indexed", False)) is not bool(indexed):
            continue
        address = int(offset) + int(address_delta)
        insn = insn_by_address.get(address)
        insn_bytes = _capstone_insn_bytes_for_match_8616(insn, bytes_by_address) if insn is not None else None
        if (
            insn is None
            or not isinstance(insn_bytes, bytes)
            or not _cod_entry_bytes_match_binary_insn_8616(raw_bytes, insn_bytes)
        ):
            continue
        name = _canonical_cod_global_name_8616(getattr(global_ref, "name", None))
        width = getattr(global_ref, "width", None)
        relative_disp = getattr(global_ref, "relative_disp", None)
        if name is None or not isinstance(width, int) or not isinstance(relative_disp, int):
            continue
        refs[address] = _CODGlobalNameRef8616(name=name, relative_disp=relative_disp, width=width)
    return refs


def _cod_global_name_ref_for_insn_8616(
    refs: Mapping[int, _CODGlobalNameRef8616],
    insn: StructuredAstValue,
) -> _CODGlobalNameRef8616 | None:
    address = _capstone_insn_address_8616(insn)
    if not isinstance(address, int):
        return None
    item = refs.get(address)
    if item is not None:
        return item
    return refs.get(address & 0xFFFF)


def _binary_direct_global_refs_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, func_addr: int | None
) -> tuple[tuple[int, int], ...]:
    """Read direct global references from dynamic angr/capstone compatibility objects."""
    function = getattr(codegen, "_inertia_current_function_8616", None)
    if function is None and isinstance(func_addr, int):
        with contextlib.suppress(Exception):
            function = project.kb.functions.function(addr=func_addr, create=False)
    block_addrs = (
        _boundary_tuple_8616(sorted(getattr(function, "block_addrs_set", ()) or ())) if function is not None else ()
    )
    refs: list[tuple[int, int]] = []
    for block_addr in block_addrs:
        try:
            block = project.factory.block(int(block_addr), opt_level=0)
        except Exception:
            continue
        for insn in _boundary_tuple_8616(getattr(getattr(block, "capstone", None), "insns", ()) or ()):
            operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
            for operand in operands:
                if int(getattr(operand, "type", -1)) != 3:
                    continue
                mem = getattr(operand, "mem", None)
                if mem is None:
                    continue
                base = int(getattr(mem, "base", 0) or 0)
                index = int(getattr(mem, "index", 0) or 0)
                if base != 0 or index != 0:
                    continue
                refs.append((int(getattr(mem, "disp", 0) or 0) & 0xFFFF, int(getattr(operand, "size", 0) or 2)))
    return tuple(refs)


def _branch_target_return_value_8616(project: StructuredAstValue, target_addr: int) -> int | None:
    """Compatibility shim for structuring-owned branch-target AX return proof."""

    def _load_block(block_addr: int) -> StructuredAstValue | None:
        return project.factory.block(block_addr, opt_level=0)

    return require_optional_result_type_8616(
        _structuring_branch_target_return_value_8616(
            target_addr,
            _load_block,
            _signed_i16_immediate_8616,
        ),
        int,
        owner="structuring.return_chains.branch_target_return_value_8616",
    )


def _scan_branch_target_return_block_8616(
    block: StructuredAstValue, project: StructuredAstValue, codegen: StructuredAstValue
) -> BranchTargetReturnBlockResult8616:
    """Scan one lifted block for a provable return expression."""

    def _combined_return_expr(
        ax_value: StructuredAstValue | None, dx_value: StructuredAstValue | None
    ) -> StructuredAstValue | None:
        return _structuring_combine_dx_ax_return_expr_8616(
            ax_value,
            dx_value,
            codegen,
            _terminal_ax_stack_offset_8616,
            lambda offset, size: _jcc._stack_slot_expr_8616(codegen, offset, size),
        )

    def _reg_imm(raw_imm: int) -> StructuredAstValue | None:
        return CConstant(
            _signed_i16_immediate_8616(raw_imm),
            SimTypeShort(False),
            codegen=codegen,
        )

    def _direct_global(offset: int, size: int) -> StructuredAstValue | None:
        return _terminal_direct_global_expr_8616(project, codegen, offset, size)

    def _ax_alu_imm(ax_value: StructuredAstValue, op: str, raw_imm: int) -> StructuredAstValue | None:
        imm = CConstant(
            _signed_i16_immediate_8616(raw_imm),
            SimTypeShort(False),
            codegen=codegen,
        )
        return CBinaryOp(op, ax_value, imm, codegen=codegen)

    def _ax_incdec(ax_value: StructuredAstValue, op: str) -> StructuredAstValue | None:
        one = CConstant(1, SimTypeShort(False), codegen=codegen)
        return CBinaryOp(op, ax_value, one, codegen=codegen)

    return _structuring_scan_branch_target_return_block_8616(
        block,
        BranchTargetReturnScanCallbacks8616(
            branch_target_imm=_jcc._branch_target_imm_8616,
            combine_return_expr=_combined_return_expr,
            materialize_reg_imm=_reg_imm,
            materialize_stack_load=lambda offset, size: _jcc._stack_slot_expr_8616(codegen, offset, size),
            materialize_direct_global_load=_direct_global,
            materialize_ax_alu_imm=_ax_alu_imm,
            materialize_ax_incdec=_ax_incdec,
        ),
    )


def _branch_target_return_expr_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    target_addr: int,
    *,
    _depth: int = 0,
    _seen: set[int] | None = None,
) -> StructuredAstValue | None:
    """Recover a branch-target return expression through legacy compatibility state."""

    def _load_block(block_addr: int) -> StructuredAstValue | None:
        return project.factory.block(block_addr, opt_level=0)

    return _structuring_branch_target_return_expr_8616(
        target_addr,
        _load_block,
        lambda block: _scan_branch_target_return_block_8616(block, project, codegen),
        _depth=_depth,
        _seen=_seen,
    )



def _terminal_ax_stack_offset_8616(expr: StructuredAstValue) -> int | None:
    """Read a stack offset from a dynamic codegen variable compatibility object."""
    if not isinstance(expr, CVariable):
        return None
    variable = expr.variable
    if not isinstance(variable, SimStackVariable):
        return None
    offset = variable.offset
    return offset if isinstance(offset, int) else None


def _terminal_ax_load_block_8616(project: StructuredAstValue, block_addr: int) -> StructuredAstValue | None:
    try:
        return project.factory.block(int(block_addr), opt_level=0)
    except Exception:
        return None


@dataclass
class _TerminalAxScanRun8616:
    """Run state for terminal-AX return expression recovery."""

    project: StructuredAstValue
    codegen: StructuredAstValue
    allow_al_return: bool
    ax_value: StructuredAstValue | None = None
    dx_value: StructuredAstValue | None = None
    cx_value: StructuredAstValue | None = None
    cl_value: StructuredAstValue | None = None

    def combined_return_expr_8616(self) -> StructuredAstValue | None:
        """Combine dynamic codegen compatibility expressions when both halves are proven."""
        if self.ax_value is None:
            return None
        if self.dx_value is None:
            return self.ax_value
        ax_offset = _terminal_ax_stack_offset_8616(self.ax_value)
        dx_offset = _terminal_ax_stack_offset_8616(self.dx_value)
        if isinstance(ax_offset, int) and isinstance(dx_offset, int) and dx_offset == ax_offset + 2:
            wide = _jcc._stack_slot_expr_8616(self.codegen, ax_offset, 4)
            if wide is not None:
                return wide
        if isinstance(self.ax_value, CConstant) and isinstance(self.dx_value, CConstant):
            low = int(self.ax_value.value or 0) & 0xFFFF
            high = int(self.dx_value.value or 0) & 0xFFFF
            value = (high << 16) | low
            if value & 0x80000000:
                value -= 0x100000000
            return CConstant(value, SimTypeLong(True), codegen=self.codegen)
        return self.ax_value

    def terminal_effect_value_expr_8616(
        self, effect: TerminalAxReturnEffect8616, *, size: int
    ) -> StructuredAstValue | None:
        """Materialize a typed terminal-AX effect into a dynamic codegen C expression."""
        if effect.kind is TerminalAxReturnEffectKind8616.MOV_REG_IMM:
            value = int(effect.imm or 0)
            if size == 1:
                return CConstant(value & 0xFF, SimTypeChar(False), codegen=self.codegen)
            return CConstant(_signed_i16_immediate_8616(value), SimTypeShort(False), codegen=self.codegen)
        if effect.kind is TerminalAxReturnEffectKind8616.MOV_REG_STACK:
            return _terminal_stack_arg_expr_8616(
                self.project, self.codegen, int(effect.mem_disp or 0), int(effect.mem_size or size)
            )
        if effect.kind is TerminalAxReturnEffectKind8616.MOV_REG_DIRECT_GLOBAL:
            return _terminal_direct_global_expr_8616(
                self.project,
                self.codegen,
                int(effect.mem_disp or 0),
                int(effect.mem_size or size),
            )
        return None

    def terminal_effect_rhs_expr_8616(
        self, effect: TerminalAxReturnEffect8616, *, size: int
    ) -> StructuredAstValue | None:
        """Materialize a typed terminal-AX RHS operand into a dynamic codegen C expression."""
        if effect.rhs_kind is TerminalAxReturnOperandKind8616.REGISTER:
            register_value = {
                "ax": self.ax_value, "dx": self.dx_value,
                "cx": self.cx_value, "cl": self.cl_value,
            }.get(effect.rhs_reg or "")
            return _clone_c_expr_8616(register_value) if register_value is not None else None
        if effect.rhs_kind is TerminalAxReturnOperandKind8616.IMM:
            value = int(effect.imm or 0)
            if size == 1:
                return CConstant(value & 0xFF, SimTypeChar(False), codegen=self.codegen)
            return CConstant(_signed_i16_immediate_8616(value), SimTypeShort(False), codegen=self.codegen)
        if effect.rhs_kind is TerminalAxReturnOperandKind8616.STACK:
            return _terminal_stack_arg_expr_8616(
                self.project, self.codegen, int(effect.mem_disp or 0), int(effect.mem_size or size)
            )
        if effect.rhs_kind is TerminalAxReturnOperandKind8616.DIRECT_GLOBAL:
            return _terminal_direct_global_expr_8616(
                self.project,
                self.codegen,
                int(effect.mem_disp or 0),
                int(effect.mem_size or size),
            )
        return None

    def _byte_stack_value_expr_from_disp_8616(self, disp: int) -> StructuredAstValue | None:
        """Materialize an 8-bit stack value from a typed BP-relative terminal effect."""
        byte = _terminal_stack_arg_expr_8616(self.project, self.codegen, disp, 1)
        if byte is None:
            return None
        return CBinaryOp(
            "And",
            _clone_c_expr_8616(byte),
            CConstant(0xFF, SimTypeShort(False), codegen=self.codegen),
            codegen=self.codegen,
        )

    def process_instruction_8616(
        self,
        insn: StructuredAstValue,
        effect: TerminalAxReturnEffect8616,
    ) -> TerminalAxInstructionAction8616:
        """Consume one dynamic capstone compatibility boundary instruction."""
        action = self._special_effect_8616(effect)
        if action is not None:
            return action
        action = self._ax_alu_effect_8616(effect)
        if action is not None:
            return action
        action = self._ax_shift_effect_8616(effect)
        if action is not None:
            return action
        action = self._cx_effect_8616(effect)
        if action is not None:
            return action
        action = self._reg_alu_value_effect_8616(effect)
        if action is not None:
            return action
        action = self._ax_mul_effect_8616(effect)
        if action is not None:
            return action
        if effect.kind in {
            TerminalAxReturnEffectKind8616.MOV_REG_IMM,
            TerminalAxReturnEffectKind8616.MOV_REG_STACK,
            TerminalAxReturnEffectKind8616.MOV_REG_DIRECT_GLOBAL,
        }:
            action = self._mov_value_effect_8616(effect)
            if action is not None:
                return action
        return TerminalAxInstructionAction8616()

    def _special_effect_8616(
        self, effect: TerminalAxReturnEffect8616
    ) -> TerminalAxInstructionAction8616 | None:
        """Handle abort/clobber/no-op effect kinds; ``None`` means no match."""
        if effect.kind is TerminalAxReturnEffectKind8616.OTHER and effect.dst_reg in {"al", "ah", "ax", "cl", "cx", "dx"}:
            return TerminalAxInstructionAction8616(abort=True)
        if effect.kind is TerminalAxReturnEffectKind8616.CALL_CLOBBER:
            self.ax_value = None
            self.dx_value = None
            self.cx_value = None
            self.cl_value = None
            return TerminalAxInstructionAction8616(classified=True)
        if effect.kind is TerminalAxReturnEffectKind8616.CLEAR_AH_TO_ZERO and self.ax_value is not None:
            return TerminalAxInstructionAction8616(classified=True)
        return None

    def _ax_alu_effect_8616(
        self, effect: TerminalAxReturnEffect8616
    ) -> TerminalAxInstructionAction8616 | None:
        """Apply AX_ALU_IMM/AX_INCDEC updates; ``None`` means no match."""
        if effect.kind is TerminalAxReturnEffectKind8616.AX_ALU_IMM and self.ax_value is not None and effect.op:
            imm = CConstant(
                _signed_i16_immediate_8616(int(effect.imm or 0)),
                SimTypeShort(False),
                codegen=self.codegen,
            )
            self.ax_value = CBinaryOp(effect.op, _clone_c_expr_8616(self.ax_value), imm, codegen=self.codegen)
            return TerminalAxInstructionAction8616(classified=True)
        if effect.kind is TerminalAxReturnEffectKind8616.AX_INCDEC and self.ax_value is not None and effect.op:
            one = CConstant(1, SimTypeShort(False), codegen=self.codegen)
            self.ax_value = CBinaryOp(effect.op, _clone_c_expr_8616(self.ax_value), one, codegen=self.codegen)
            return TerminalAxInstructionAction8616(classified=True)
        return None

    def _ax_shift_effect_8616(
        self, effect: TerminalAxReturnEffect8616
    ) -> TerminalAxInstructionAction8616 | None:
        """Apply AL_SHL_IMM/AX_SHR_CL updates; ``None`` means no match."""
        if effect.kind is TerminalAxReturnEffectKind8616.AL_SHL_IMM and self.ax_value is not None:
            imm = CConstant(int(effect.imm or 0), SimTypeChar(False), codegen=self.codegen)
            self.ax_value = CBinaryOp("Shl", _clone_c_expr_8616(self.ax_value), imm, codegen=self.codegen)
            return TerminalAxInstructionAction8616(classified=True)
        if effect.kind is TerminalAxReturnEffectKind8616.AX_SHR_CL and self.ax_value is not None and self.cl_value is not None:
            self.ax_value = CBinaryOp("Shr", _clone_c_expr_8616(self.ax_value), _clone_c_expr_8616(self.cl_value), codegen=self.codegen)
            return TerminalAxInstructionAction8616(classified=True)
        return None

    def _cx_effect_8616(
        self, effect: TerminalAxReturnEffect8616
    ) -> TerminalAxInstructionAction8616 | None:
        """Apply CX_SHL_IMM/AX_OR_CX updates; ``None`` means no match."""
        if effect.kind is TerminalAxReturnEffectKind8616.CX_SHL_IMM and self.cx_value is not None:
            imm = CConstant(int(effect.imm or 0), SimTypeShort(False), codegen=self.codegen)
            self.cx_value = CBinaryOp("Shl", _clone_c_expr_8616(self.cx_value), imm, codegen=self.codegen)
            return TerminalAxInstructionAction8616(classified=True)
        if effect.kind is TerminalAxReturnEffectKind8616.AX_OR_CX and self.ax_value is not None and self.cx_value is not None:
            self.ax_value = CBinaryOp("Or", _clone_c_expr_8616(self.ax_value), _clone_c_expr_8616(self.cx_value), codegen=self.codegen)
            return TerminalAxInstructionAction8616(classified=True)
        return None

    def _reg_alu_value_effect_8616(
        self, effect: TerminalAxReturnEffect8616
    ) -> TerminalAxInstructionAction8616 | None:
        """Apply a REG_ALU_VALUE update; ``None`` means no match."""
        if not (
            effect.kind is TerminalAxReturnEffectKind8616.REG_ALU_VALUE
            and effect.dst_reg in {"al", "ax"}
            and self.ax_value is not None
            and effect.op
        ):
            return None
        rhs_size = 1 if effect.dst_reg == "al" else 2
        rhs = self.terminal_effect_rhs_expr_8616(effect, size=rhs_size)
        if rhs is None:
            return TerminalAxInstructionAction8616(abort=True)
        self.ax_value = CBinaryOp(effect.op, _clone_c_expr_8616(self.ax_value), _clone_c_expr_8616(rhs), codegen=self.codegen)
        return TerminalAxInstructionAction8616(classified=True)

    def _ax_mul_effect_8616(
        self, effect: TerminalAxReturnEffect8616
    ) -> TerminalAxInstructionAction8616 | None:
        """Apply an AX_MUL_VALUE update; ``None`` means no match."""
        if effect.kind is not TerminalAxReturnEffectKind8616.AX_MUL_VALUE or self.ax_value is None:
            return None
        rhs = self.terminal_effect_rhs_expr_8616(effect, size=2)
        if rhs is None:
            return TerminalAxInstructionAction8616(abort=True)
        self.ax_value = CBinaryOp("Mul", _clone_c_expr_8616(self.ax_value), _clone_c_expr_8616(rhs), codegen=self.codegen)
        self.dx_value = None
        return TerminalAxInstructionAction8616(classified=True)

    def _mov_value_effect_8616(
        self, effect: TerminalAxReturnEffect8616
    ) -> TerminalAxInstructionAction8616 | None:
        """Route MOV_REG_* effects into tracked register values; ``None`` means no match."""
        if effect.dst_reg == "cl" and effect.kind is TerminalAxReturnEffectKind8616.MOV_REG_IMM:
            self.cl_value = CConstant(int(effect.imm or 0), SimTypeChar(False), codegen=self.codegen)
            return TerminalAxInstructionAction8616(classified=True)
        if effect.dst_reg == "cx":
            value = self.terminal_effect_value_expr_8616(effect, size=2)
            if value is not None:
                self.cx_value = value
                return TerminalAxInstructionAction8616(classified=True)
        if effect.dst_reg == "al":
            action = self._mov_al_effect_8616(effect)
            if action is not None:
                return action
        if effect.dst_reg == "ah":
            action = self._mov_ah_effect_8616(effect)
            if action is not None:
                return action
        if effect.dst_reg in {"ax", "dx"}:
            action = self._mov_ax_dx_effect_8616(effect)
            if action is not None:
                return action
        return None

    def _mov_ah_effect_8616(
        self, effect: TerminalAxReturnEffect8616
    ) -> TerminalAxInstructionAction8616 | None:
        """Compose a MOV-to-AH byte lane into AX; ``None`` means no proven value."""
        if self.ax_value is None:
            return None
        value = self.terminal_effect_value_expr_8616(effect, size=1)
        if isinstance(value, CExpression) and isinstance(self.ax_value, CExpression):
            self.ax_value = compose_ax_byte_lanes_8616(self.codegen, self.ax_value, value)
            self.dx_value = None
            return TerminalAxInstructionAction8616(classified=True)
        return None

    def _mov_ax_dx_effect_8616(
        self, effect: TerminalAxReturnEffect8616
    ) -> TerminalAxInstructionAction8616 | None:
        """Apply a MOV-to-AX/DX word value; ``None`` means no proven value."""
        value = self.terminal_effect_value_expr_8616(effect, size=2)
        if value is not None:
            if effect.dst_reg == "ax":
                self.ax_value = value
            elif effect.dst_reg == "dx":
                self.dx_value = value
            return TerminalAxInstructionAction8616(classified=True)
        return None

    def _mov_al_effect_8616(
        self, effect: TerminalAxReturnEffect8616
    ) -> TerminalAxInstructionAction8616 | None:
        """Apply a MOV-to-AL value update; ``None`` means no proven value."""
        value = None
        if not self.allow_al_return and effect.kind is TerminalAxReturnEffectKind8616.MOV_REG_STACK:
            value = self._byte_stack_value_expr_from_disp_8616(int(effect.mem_disp or 0))
        elif self.allow_al_return:
            value = self.terminal_effect_value_expr_8616(effect, size=1)
        if value is not None:
            self.ax_value = value
            self.dx_value = None
            return TerminalAxInstructionAction8616(classified=True)
        return None


def _linear_terminal_ax_return_expr_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, function: StructuredAstValue
) -> StructuredAstValue | None:
    """Materialize a terminal AX return expression through dynamic angr/codegen compatibility state."""
    block_addrs = _boundary_tuple_8616(sorted(getattr(function, "block_addrs_set", ()) or ()))
    debug = bool(os.environ.get("INERTIA_DEBUG_MISSING_AX_RETURN"))
    if debug:
        info = getattr(function, "info", None)
        logging.getLogger(__name__).warning(
            "[missing-ax-return] function=%#x block_addrs=%r info_complexity=%r local_blocks=%d blocks=%d",
            int(getattr(function, "addr", -1) or -1),
            block_addrs,
            (info or {}).get("_inertia_function_complexity") if isinstance(info, dict) else None,
            len(getattr(function, "_local_blocks", {}) or {}),
            len(_boundary_tuple_8616(getattr(function, "blocks", ()) or ())),
        )
    if not block_addrs:
        return None
    prototype = getattr(getattr(codegen, "cfunc", None), "functy", None) or getattr(
        getattr(codegen, "cfunc", None), "prototype", None
    )
    return_type = getattr(prototype, "returnty", None)
    return_bits = getattr(return_type, "size", None)
    allow_al_return = isinstance(return_type, SimTypeChar) or (isinstance(return_bits, int) and return_bits <= 8)

    run = _TerminalAxScanRun8616(project=project, codegen=codegen, allow_al_return=allow_al_return)
    scan_result = _structuring_linear_terminal_ax_return_scan_8616(
        block_addrs,
        lambda addr: _terminal_ax_load_block_8616(project, addr),
        _jcc._branch_target_imm_8616,
        TerminalAxScanCallbacks8616(
            combined_return_expr=run.combined_return_expr_8616,
            process_instruction=run.process_instruction_8616,
        ),
    )
    if scan_result.terminal_value_block_count:
        codegen._inertia_missing_terminal_ax_return_terminal_value_block_count_8616 = (
            scan_result.terminal_value_block_count
        )
    if scan_result.expr is not None:
        codegen._inertia_missing_terminal_ax_return_raw_fact_count_8616 = scan_result.raw_insns
        codegen._inertia_missing_terminal_ax_return_classified_fact_count_8616 = scan_result.classified
        if debug:
            logging.getLogger(__name__).warning(
                "[missing-ax-return] result=%s raw=%d classified=%d",
                _expr_fingerprint(scan_result.expr, project),
                scan_result.raw_insns,
                scan_result.classified,
            )
        return scan_result.expr
    if debug:
        logging.getLogger(__name__).warning(
            "[missing-ax-return] refused no terminal return raw=%d classified=%d",
            scan_result.raw_insns,
            scan_result.classified,
        )
    return None


def _next_unconditional_target_after_jcc_8616(
    project: StructuredAstValue, block_addr: int, jcc_addr: int
) -> int | None:
    """Compatibility shim for structuring-owned JCC fallthrough jump proof."""
    try:
        block = project.factory.block(int(block_addr), opt_level=0)
    except Exception:
        return None

    def _load_block(addr: int) -> StructuredAstValue | None:
        try:
            return project.factory.block(int(addr), opt_level=0)
        except Exception:
            return None

    return require_optional_result_type_8616(
        _structuring_next_unconditional_target_after_jcc_8616(
            block,
            jcc_addr,
            _load_block,
            _jcc._branch_target_imm_8616,
        ),
        int,
        owner="structuring.return_chains.next_unconditional_target_after_jcc_8616",
    )


def _linear_function_insns_for_codegen_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> tuple[StructuredAstValue, ...]:
    """Publish one cached Frontend-owned bounded instruction inventory."""
    base_insns = tuple(_jcc._function_insns_for_codegen_8616(project, codegen) or ())
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    previous = getattr(codegen, "_inertia_bounded_linear_instruction_inventory_8616", None)
    typed_previous = previous if isinstance(previous, BoundedLinearInstructionInventory8616) else None
    inventory = collect_bounded_linear_instruction_inventory_8616(
        project,
        function_entry=func_addr if isinstance(func_addr, int) else None,
        base_instructions=base_insns,
        previous=typed_previous,
    )
    bytes_by_addr: dict[int, bytes] = {}
    if inventory is not typed_previous:
        for insn in inventory.sequential_instructions:
            addr = int(getattr(insn, "address", 0) or 0)
            size = int(getattr(insn, "size", 0) or 0)
            if size > 0:
                with contextlib.suppress(Exception):
                    bytes_by_addr[int(addr)] = bytes(project.loader.memory.load(addr, size))
    result = tuple(inventory.instructions)
    if isinstance(func_addr, int):
        with contextlib.suppress(Exception):
            codegen._inertia_jcc_function_insns_8616 = result
            codegen._inertia_jcc_function_entry_8616 = func_addr
            codegen._inertia_bounded_linear_instruction_inventory_8616 = inventory
    if bytes_by_addr:
        with contextlib.suppress(Exception):
            codegen._inertia_instruction_bytes_by_addr_8616 = bytes_by_addr
    return result


def _linear_jcc_block_starts_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> tuple[tuple[int, StructuredAstValue], ...]:
    """Compatibility shim for structuring-owned linear JCC block-start proof."""
    insns = _linear_function_insns_for_codegen_8616(project, codegen)
    if not insns:
        return ()
    return require_result_type_8616(
        _structuring_linear_jcc_block_starts_8616(insns),
        tuple,
        owner="structuring.return_chains.linear_jcc_block_starts_8616",
    )


def _root_contains_ins_addr_8616(root: StructuredAstValue, target_addr: int) -> bool:
    if root is None:
        return False
    for node in (root, *_iter_c_nodes_deep_8616(root)):
        tags = getattr(node, "tags", None)
        if isinstance(tags, dict) and tags.get("ins_addr") == int(target_addr):
            return True
    return False


def _condition_keys_in_codegen_8616(codegen: StructuredAstValue) -> frozenset[tuple[int, int]]:
    keys: set[tuple[int, int]] = set()
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None) if cfunc is not None else None
    for node in (root, *_iter_c_nodes_deep_8616(root)):
        cond_pairs = getattr(node, "condition_and_nodes", None)
        if isinstance(cond_pairs, (list, tuple)):
            for cond, _body in tuple(cond_pairs):
                key = _jcc._condition_tags_8616(cond)
                if isinstance(key, tuple) and len(key) == 2:
                    keys.add(key)
        cond = getattr(node, "condition", None)
        key = _jcc._condition_tags_8616(cond)
        if isinstance(key, tuple) and len(key) == 2:
            keys.add(key)
    return frozenset(keys)


def _cifbreak_keys_in_root_8616(root: StructuredAstValue) -> frozenset[tuple[int, int]]:
    return frozenset(_break_guard_nodes_by_key_8616(root))


def _cifbreak_nodes_by_key_8616(
    root: StructuredAstValue,
) -> dict[tuple[int, int], tuple[StructuredAstValue, ...]]:
    return _break_guard_nodes_by_key_8616(root)


def _break_guard_nodes_by_key_8616(
    root: StructuredAstValue,
) -> dict[tuple[int, int], tuple[StructuredAstValue, ...]]:
    nodes_by_key: dict[tuple[int, int], list[StructuredAstValue]] = {}
    for node in (root, *_iter_c_nodes_deep_8616(root)):
        condition = _break_guard_condition_8616(node)
        if condition is None:
            continue
        key = _jcc._condition_tags_8616(condition)
        if isinstance(key, tuple) and len(key) == 2:
            nodes_by_key.setdefault(key, []).append(node)
    return {key: tuple(nodes) for key, nodes in nodes_by_key.items()}


def _break_guard_condition_8616(node: StructuredAstValue) -> StructuredAstValue:
    if isinstance(node, CIfBreak):
        return node.condition
    if not isinstance(node, CIfElse):
        return None
    if node.else_node is not None:
        return None
    pairs = _boundary_tuple_8616(node.condition_and_nodes or ())
    if len(pairs) != 1:
        return None
    condition, body = pairs[0]
    if isinstance(body, CBreak):
        return condition
    if not isinstance(body, CStatements):
        return None
    statements = _boundary_tuple_8616(body.statements or ())
    return condition if len(statements) == 1 and isinstance(statements[0], CBreak) else None


def _set_break_guard_condition_8616(node: StructuredAstValue, condition: StructuredAstValue) -> bool:
    if isinstance(node, CIfBreak):
        node.condition = condition
        return True
    if not isinstance(node, CIfElse):
        return False
    if node.else_node is not None:
        return False
    pairs = _boundary_list_8616(node.condition_and_nodes or ())
    if len(pairs) != 1:
        return False
    _old_condition, body = pairs[0]
    if isinstance(body, CBreak):
        pairs[0] = (condition, body)
        node.condition_and_nodes = pairs
        return True
    if not isinstance(body, CStatements):
        return False
    statements = _boundary_tuple_8616(body.statements or ())
    if len(statements) != 1 or not isinstance(statements[0], CBreak):
        return False
    pairs[0] = (condition, body)
    node.condition_and_nodes = pairs
    return True


def _root_contains_node_8616(root: StructuredAstValue, target: StructuredAstValue) -> bool:
    if root is target:
        return True
    return any(node is target for node in _iter_c_nodes_deep_8616(root))


def _loop_nodes_with_body_8616(root: StructuredAstValue) -> tuple[StructuredAstValue, ...]:
    loops = []
    seen: set[int] = set()
    for node in (root, *_iter_c_nodes_deep_8616(root)):
        if not isinstance(node, (CForLoop, CWhileLoop, CDoWhileLoop)):
            continue
        marker = id(node)
        if marker in seen:
            continue
        seen.add(marker)
        if isinstance(getattr(node, "body", None), CStatements):
            loops.append(node)
    return tuple(loops)


def _first_statement_index_containing_ins_addr_8616(
    statements: tuple[StructuredAstValue, ...], target_addr: int
) -> int | None:
    for idx, stmt in enumerate(statements):
        if _root_contains_ins_addr_8616(stmt, int(target_addr)):
            return idx
    return None


def _decoded_jcc_condition_expr_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, decoded: StructuredAstValue, tags: dict[str, int]
) -> StructuredAstValue:
    if getattr(decoded, "expr", None) is not None:
        expr = _clone_c_value_for_codegen_tree_8616(decoded.expr)
        with contextlib.suppress(Exception):
            expr.tags = dict(tags)
        return expr
    return _jcc._build_arch_safe_binary_op_8616(
        project,
        codegen,
        decoded.op,
        _clone_c_value_for_codegen_tree_8616(decoded.lhs),
        _clone_c_value_for_codegen_tree_8616(decoded.rhs),
        tags=dict(tags),
    )


def _invert_decoded_jcc_condition_expr_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, decoded: StructuredAstValue, tags: dict[str, int]
) -> StructuredAstValue:
    decoded_op = getattr(decoded, "op", None)
    inverted_op = _jcc._INVERT_CMP_OP_8616.get(decoded_op) if isinstance(decoded_op, str) else None
    if getattr(decoded, "expr", None) is None and inverted_op is not None:
        return _jcc._build_arch_safe_binary_op_8616(
            project,
            codegen,
            inverted_op,
            _clone_c_value_for_codegen_tree_8616(decoded.lhs),
            _clone_c_value_for_codegen_tree_8616(decoded.rhs),
            tags=dict(tags),
        )
    condition = _decoded_jcc_condition_expr_8616(project, codegen, decoded, tags)
    if condition is None:
        return None
    return CUnaryOp("Not", condition, codegen=codegen, tags=dict(tags))


def _record_inserted_jcc_condition_evidence_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, condition: StructuredAstValue
) -> None:
    _record_jcc_condition_validation_evidence_8616(project, codegen, removed_condition=None, added_condition=condition)


def _record_jcc_condition_validation_evidence_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    *,
    removed_condition: StructuredAstValue,
    added_condition: StructuredAstValue,
) -> None:
    try:
        added_fingerprint = _expr_fingerprint(added_condition, project)
    except Exception:
        added_fingerprint = repr(added_condition)
    if not added_fingerprint:
        return
    fingerprints = _boundary_tuple_8616(getattr(codegen, "_inertia_jcc_decoded_condition_fingerprints_8616", ()) or ())
    codegen._inertia_jcc_decoded_condition_fingerprints_8616 = tuple(
        dict.fromkeys((*fingerprints, str(added_fingerprint)))
    )
    evidence = _boundary_list_8616(getattr(codegen, "_inertia_jcc_condition_validation_evidence_8616", ()) or ())
    if removed_condition is None:
        removed_fingerprint = ""
    else:
        try:
            removed_fingerprint = _expr_fingerprint(removed_condition, project)
        except Exception:
            removed_fingerprint = repr(removed_condition)
    evidence.append({"removed": str(removed_fingerprint), "added": str(added_fingerprint)})
    codegen._inertia_jcc_condition_validation_evidence_8616 = tuple(evidence)
    codegen._inertia_semantic_condition_materialized_count = (
        int(getattr(codegen, "_inertia_semantic_condition_materialized_count", 0) or 0) + 1
    )


def _unconsumed_loop_break_jcc_callbacks_8616() -> UnconsumedLoopBreakJccCallbacks8616:
    """Build compatibility callbacks for structuring-owned loop-break JCC repair."""

    def _record_condition_evidence(
        project: StructuredAstValue,
        codegen: StructuredAstValue,
        removed: StructuredAstValue | None,
        added: StructuredAstValue,
    ) -> None:
        _record_jcc_condition_validation_evidence_8616(
            project,
            codegen,
            removed_condition=removed,
            added_condition=added,
        )

    return UnconsumedLoopBreakJccCallbacks8616(
        linear_jcc_block_starts=_linear_jcc_block_starts_8616,
        branch_target_imm=_jcc._branch_target_imm_8616,
        next_unconditional_target_after_jcc=_next_unconditional_target_after_jcc_8616,
        resolve_one_hop_jmp_target=_resolve_one_hop_jmp_target_8616,
        translate_cmp_jcc_guard=_jcc._translate_cmp_jcc_guard_8616,
        decoded_condition_expr=_decoded_jcc_condition_expr_8616,
        inverted_condition_expr=_invert_decoded_jcc_condition_expr_8616,
        expr_fingerprint=_expr_fingerprint,
        same_c_expression=_same_c_expression_8616,
        clone_c_value=_clone_c_value_for_codegen_tree_8616,
        record_condition_evidence=_record_condition_evidence,
    )


def _materialize_unconsumed_loop_break_jcc_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:
    """Compatibility fallback when Structuring did not run loop-JCC recovery."""
    # Dynamic boundary: legacy angr/codegen objects may enter Postprocess without
    # passing through the X86-16 Structuring wrapper.
    if getattr(codegen, "_inertia_unconsumed_loop_break_jcc_structuring_pass_ran_8616", False):
        return False
    return require_result_type_8616(
        _structuring_materialize_unconsumed_loop_break_jcc_8616(
            project,
            codegen,
            _unconsumed_loop_break_jcc_callbacks_8616(),
        ),
        bool,
        owner="structuring.return_chains.materialize_unconsumed_loop_break_jcc_8616",
    )


def _return_chain_proof_callbacks_8616() -> ReturnChainProofCallbacks8616:
    """Build dynamic postprocess adapters for structuring-owned CFG proof discovery."""
    return ReturnChainProofCallbacks8616(
        linear_jcc_block_starts=_linear_jcc_block_starts_8616,
        branch_target_imm=_jcc._branch_target_imm_8616,
        branch_target_return_value=_branch_target_return_value_8616,
        decoded_condition_expr=_decoded_cmp_condition_expr_8616,
        translate_cmp_jcc_guard=_jcc._translate_cmp_jcc_guard_8616,
        last_call_addr_before_jcc=_last_call_addr_before_jcc_in_function_8616,
        condition_tags=_jcc._condition_tags_8616,
        iter_c_nodes_deep=_iter_c_nodes_deep_8616,
    )


def _condition_branch_return_value_8616(project: StructuredAstValue, cond: StructuredAstValue) -> int | None:
    """Compatibility shim for structuring-owned CFG branch return proof."""
    return require_optional_result_type_8616(
        _structuring_condition_branch_return_value_8616(project, cond, _return_chain_proof_callbacks_8616()),
        int,
        owner="structuring.return_chains.condition_branch_return_value_8616",
    )


def _ordered_conditional_return_values_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> list[int]:
    """Compatibility shim for structuring-owned CFG branch return ordering."""
    return require_result_type_8616(
        _structuring_ordered_conditional_return_values_8616(project, codegen, _return_chain_proof_callbacks_8616()),
        list,
        owner="structuring.return_chains.ordered_conditional_return_values_8616",
    )


def _decoded_cmp_condition_expr_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    decoded: StructuredAstValue,
    tags: dict[str, int] | None = None,
) -> StructuredAstValue | None:
    """Build a decoded JCC condition across dynamic angr/codegen compatibility objects."""
    expr = getattr(decoded, "expr", None)
    if expr is not None:
        if tags:
            with contextlib.suppress(Exception):
                expr.tags = {**dict(getattr(expr, "tags", {}) or {}), **dict(tags)}
        return expr
    op = getattr(decoded, "op", None)
    lhs = getattr(decoded, "lhs", None)
    rhs = getattr(decoded, "rhs", None)
    if not isinstance(op, str) or lhs is None or rhs is None:
        return None
    arch = getattr(project, "arch", None)

    def bind_node_type(node: StructuredAstValue) -> None:
        if arch is None or node is None:
            return
        current_type = getattr(node, "variable_type", None)
        if current_type is None or getattr(current_type, "_arch", None) is not None:
            return
        if not hasattr(current_type, "with_arch"):
            return
        with contextlib.suppress(Exception):
            node.variable_type = current_type.with_arch(arch)

    bind_node_type(lhs)
    bind_node_type(rhs)
    try:
        return CBinaryOp(op, lhs, rhs, codegen=codegen, tags=dict(tags or {}))
    except Exception:
        return None


def _last_call_addr_before_jcc_in_block_8616(project: StructuredAstValue, block_addr: int, jcc_addr: int) -> int | None:
    """Return the last call before a JCC from dynamic angr/capstone compatibility objects."""
    try:
        block = project.factory.block(int(block_addr), opt_level=0)
    except Exception:
        return None
    last_call_addr: int | None = None
    for insn in _boundary_tuple_8616(getattr(getattr(block, "capstone", None), "insns", ()) or ()):
        insn_addr = int(getattr(insn, "address", -1))
        if insn_addr >= int(jcc_addr):
            break
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        if mnemonic in {"call", "lcall"}:
            last_call_addr = insn_addr
    return last_call_addr


def _last_call_addr_before_jcc_in_function_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, jcc_addr: int
) -> int | None:
    """Compatibility shim for structuring-owned pre-JCC callsite proof."""
    return require_optional_result_type_8616(
        _structuring_last_call_addr_before_jcc_in_function_8616(
            _jcc._function_insns_for_codegen_8616(project, codegen),
            jcc_addr,
        ),
        int,
        owner="structuring.return_chains.last_call_addr_before_jcc_in_function_8616",
    )


def _ordered_conditional_return_pairs_from_cfg_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> list[tuple[StructuredAstValue, int]]:
    """Compatibility shim for structuring-owned CFG return-chain proof ordering."""
    return require_result_type_8616(
        _structuring_ordered_conditional_return_pairs_from_cfg_8616(
            project,
            codegen,
            _return_chain_proof_callbacks_8616(),
        ),
        list,
        owner="structuring.return_chains.ordered_conditional_return_pairs_from_cfg_8616",
    )


def _ordered_conditional_return_expr_pairs_from_cfg_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    *,
    branch_target_return_expr: Callable[
        [StructuredAstValue, StructuredAstValue, int], StructuredAstValue | None
    ] = _branch_target_return_expr_8616,
) -> list[tuple[StructuredAstValue, StructuredAstValue, StructuredAstValue]]:
    """Compatibility shim for structuring-owned CFG return-expression pair ordering."""
    return require_result_type_8616(
        _structuring_ordered_conditional_return_expr_pairs_from_cfg_8616(
            project,
            codegen,
            ReturnConditionalExprPairCallbacks8616(
                linear_jcc_block_starts=_linear_jcc_block_starts_8616,
                branch_target_imm=_jcc._branch_target_imm_8616,
                next_unconditional_target_after_jcc=_next_unconditional_target_after_jcc_8616,
                branch_target_return_expr=branch_target_return_expr,
                translate_cmp_jcc_guard=_jcc._translate_cmp_jcc_guard_8616,
                decoded_condition_expr=_decoded_cmp_condition_expr_8616,
                last_call_addr_before_jcc_in_function=_last_call_addr_before_jcc_in_function_8616,
            ),
        ),
        list,
        owner="structuring.return_chains.ordered_conditional_return_expr_pairs_from_cfg_8616",
    )


def _ordered_conditional_void_tail_call_proofs_from_cfg_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> list[tuple[StructuredAstValue, StructuredAstValue]]:
    """Compatibility shim for structuring-owned void-tail-call proof ordering."""
    return require_result_type_8616(
        _structuring_ordered_conditional_void_tail_call_proofs_from_cfg_8616(
            project,
            codegen,
            ReturnConditionalVoidTailCallCallbacks8616(
                linear_jcc_block_starts=_linear_jcc_block_starts_8616,
                branch_target_imm=_jcc._branch_target_imm_8616,
                next_unconditional_target_after_jcc=_next_unconditional_target_after_jcc_8616,
                branch_target_return_expr=_branch_target_return_expr_8616,
                translate_cmp_jcc_guard=_jcc._translate_cmp_jcc_guard_8616,
                decoded_condition_expr=_decoded_cmp_condition_expr_8616,
            ),
        ),
        list,
        owner="structuring.return_chains.ordered_conditional_void_tail_call_proofs_from_cfg_8616",
    )


def _first_conditional_jcc_8616(block: StructuredAstValue) -> StructuredAstValue | None:
    """Compatibility shim for structuring-owned conditional-JCC selection."""
    return _structuring_first_conditional_jcc_8616(block)


def _selector_condition_call_addrs_8616(
    pairs: list[tuple[StructuredAstValue, StructuredAstValue, StructuredAstValue]],
) -> frozenset[int]:
    """Compatibility shim for structuring-owned selector condition call tags."""
    return require_result_type_8616(
        _structuring_selector_condition_call_addrs_8616(pairs, _iter_c_nodes_deep_8616),
        frozenset,
        owner="structuring.return_chains.selector_condition_call_addrs_8616",
    )


def _selector_condition_call_addrs_from_cfg_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> frozenset[int]:
    """Compatibility shim for structuring-owned selector CFG callsite proof."""
    return require_result_type_8616(
        _structuring_selector_condition_call_addrs_from_cfg_8616(
            project,
            codegen,
            ReturnSelectorCallsiteProofCallbacks8616(
                linear_jcc_block_starts=_linear_jcc_block_starts_8616,
                branch_target_imm=_jcc._branch_target_imm_8616,
                next_unconditional_target_after_jcc=_next_unconditional_target_after_jcc_8616,
                branch_target_return_expr=_branch_target_return_expr_8616,
                translate_cmp_jcc_guard=_jcc._translate_cmp_jcc_guard_8616,
                last_call_addr_before_jcc_in_function=_last_call_addr_before_jcc_in_function_8616,
            ),
        ),
        frozenset,
        owner="structuring.return_chains.selector_condition_call_addrs_from_cfg_8616",
    )


def _selector_function_has_unsafe_effects_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    *,
    allowed_call_addrs: frozenset[int] = frozenset(),
) -> bool:
    """Compatibility shim for structuring-owned selector unsafe-effect scan."""
    function_entry = getattr(getattr(codegen, "cfunc", None), "addr", None)
    inventory = collect_function_instruction_inventory_8616(
        project,
        function_entry=function_entry if isinstance(function_entry, int) else None,
    )
    return require_result_type_8616(
        _structuring_selector_function_has_unsafe_effects_8616(
            project,
            codegen,
            SelectorUnsafeEffectsCallbacks8616(
                function_inventory=lambda _project, _codegen: inventory,
                direct_call_target=_jcc._direct_call_target_8616,
                callee_name_for_target=_jcc._callee_name_for_target_8616,
                target_is_stack_probe_helper=_target_is_stack_probe_helper_8616,
            ),
            allowed_call_addrs=allowed_call_addrs,
        ),
        bool,
        owner="structuring.return_chains.selector_function_has_unsafe_effects_8616",
    )


def _stack_probe_candidate_addrs_8616(project: StructuredAstValue, target_addr: int) -> list[int]:
    """Build the deduped target-address candidates including linear-delta rebases."""
    candidate_addrs = [int(target_addr)]
    delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(delta, int):
        candidate_addrs.append(int(target_addr) + delta)
        rebased = int(target_addr) - delta
        if rebased >= 0:
            candidate_addrs.append(rebased)
    deduped_addrs: list[int] = []
    for addr in candidate_addrs:
        if addr not in deduped_addrs:
            deduped_addrs.append(addr)
    return deduped_addrs


def _target_is_stack_probe_helper_8616(
    project: StructuredAstValue, target_addr: int | None, name: str | None = None
) -> bool:
    if is_x86_16_stack_probe_name_8616(name):
        return True
    if not isinstance(target_addr, int):
        return False
    deduped_addrs = _stack_probe_candidate_addrs_8616(project, target_addr)
    for candidate_project in (project, getattr(project, "_inertia_original_project", None)):
        if candidate_project is None:
            continue
        for addr in deduped_addrs:
            if is_x86_16_stack_probe_helper_at_8616(candidate_project, addr):
                return True
    return False


def _selector_targets_from_32bit_jcc_chain_8616(
    project: StructuredAstValue, block_addr: int, jcc_insn: StructuredAstValue
) -> tuple[int, int] | None:
    """Compatibility shim for structuring-owned 32-bit selector target proof."""
    return require_optional_result_type_8616(
        _structuring_selector_targets_from_32bit_jcc_chain_8616(
            int(block_addr),
            jcc_insn,
            lambda addr: project.factory.block(int(addr), opt_level=0),
            _jcc._branch_target_imm_8616,
            lambda block, current_addr, jcc_addr: _structuring_next_unconditional_target_after_jcc_8616(
                block,
                int(jcc_addr),
                lambda addr: project.factory.block(int(addr), opt_level=0),
                _jcc._branch_target_imm_8616,
            ),
        ),
        tuple,
        owner="structuring.return_chains.selector_targets_from_32bit_jcc_chain_8616",
    )


def _equality_return_target_from_32bit_jcc_chain_8616(
    project: StructuredAstValue, block_addr: int, jcc_insn: StructuredAstValue
) -> int | None:
    """Compatibility shim for structuring-owned 32-bit equality target proof."""
    return require_optional_result_type_8616(
        _structuring_equality_return_target_from_32bit_jcc_chain_8616(
            int(block_addr),
            jcc_insn,
            lambda addr: project.factory.block(int(addr), opt_level=0),
            _jcc._branch_target_imm_8616,
            lambda block, current_addr, jcc_addr: _structuring_next_unconditional_target_after_jcc_8616(
                block,
                int(jcc_addr),
                lambda addr: project.factory.block(int(addr), opt_level=0),
                _jcc._branch_target_imm_8616,
            ),
        ),
        int,
        owner="structuring.return_chains.equality_return_target_from_32bit_jcc_chain_8616",
    )


def _inequality_target_from_32bit_jcc_chain_8616(
    project: StructuredAstValue, block_addr: int, jcc_insn: StructuredAstValue
) -> int | None:
    """Compatibility shim for structuring-owned 32-bit inequality target proof."""
    return require_optional_result_type_8616(
        _structuring_inequality_target_from_32bit_jcc_chain_8616(
            int(block_addr),
            jcc_insn,
            lambda addr: project.factory.block(int(addr), opt_level=0),
            _jcc._branch_target_imm_8616,
            lambda block, current_addr, jcc_addr: _structuring_next_unconditional_target_after_jcc_8616(
                block,
                int(jcc_addr),
                lambda addr: project.factory.block(int(addr), opt_level=0),
                _jcc._branch_target_imm_8616,
            ),
        ),
        int,
        owner="structuring.return_chains.inequality_target_from_32bit_jcc_chain_8616",
    )


def _ordered_32bit_selector_return_expr_pairs_from_cfg_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    *,
    branch_target_return_expr: Callable[
        [StructuredAstValue, StructuredAstValue, int], StructuredAstValue | None
    ] = _branch_target_return_expr_8616,
) -> list[tuple[StructuredAstValue, StructuredAstValue, StructuredAstValue]]:
    """Compatibility shim for structuring-owned 32-bit selector-return pair ordering."""

    def _function_block_addrs(local_project: StructuredAstValue, local_codegen: StructuredAstValue) -> tuple[int, ...]:
        """Read function block addresses from dynamic angr/codegen compatibility state."""
        # Dynamic angr/codegen compatibility boundary: cfunc is attached by structured codegen.
        cfunc = getattr(local_codegen, "cfunc", None)
        # Dynamic angr C function compatibility boundary: addr is optional in synthetic tests.
        func_addr = getattr(cfunc, "addr", None)
        if not isinstance(func_addr, int):
            return ()
        try:
            # Dynamic angr knowledge-base compatibility boundary.
            function = local_project.kb.functions.function(addr=func_addr, create=False)
        except Exception:
            return ()
        if function is None:
            return ()
        # Dynamic angr Function compatibility boundary: block address sets are optional.
        return _boundary_tuple_8616(sorted(int(addr) for addr in getattr(function, "block_addrs_set", set()) or ()))

    def _load_block(addr: int) -> StructuredAstValue | None:
        """Load a dynamic angr block for structuring-owned selector proof."""
        try:
            return project.factory.block(int(addr), opt_level=0)
        except Exception:
            return None

    return require_result_type_8616(
        _structuring_ordered_32bit_selector_return_expr_pairs_from_cfg_8616(
            project,
            codegen,
            ReturnSelector32BitPairCallbacks8616(
                function_block_addrs=_function_block_addrs,
                load_block=_load_block,
                branch_target_imm=_jcc._branch_target_imm_8616,
                next_unconditional_target_after_jcc=lambda block, block_addr, jcc_addr: (
                    _structuring_next_unconditional_target_after_jcc_8616(
                        block,
                        int(jcc_addr),
                        _load_block,
                        _jcc._branch_target_imm_8616,
                    )
                ),
                translate_cmp_jcc_guard=_jcc._translate_cmp_jcc_guard_8616,
                decoded_condition_expr=_decoded_cmp_condition_expr_8616,
                branch_target_return_expr=branch_target_return_expr,
            ),
        ),
        list,
        owner="structuring.return_chains.ordered_32bit_selector_return_expr_pairs_from_cfg_8616",
    )


def _selector_stack_expr_from_ax_load_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> StructuredAstValue | None:
    """Compatibility shim for structuring-owned selector stack-expression recovery."""
    return _structuring_selector_stack_expr_from_ax_load_8616(
        project,
        codegen,
        SelectorStackExprCallbacks8616(
            linear_function_insns=_linear_function_insns_for_codegen_8616,
            stack_slot_expr=lambda local_codegen, disp, size, local_project: _jcc._stack_slot_expr_8616(
                local_codegen,
                int(disp),
                int(size),
                project=local_project,
            ),
        ),
    )


def _selector_raw_stack_aliases_8616(
    project: StructuredAstValue, selector: StructuredAstValue
) -> dict[str, tuple[str, ...]]:
    """Return raw stack-slot aliases for a selector expression at the compatibility boundary."""
    selector_raw_aliases: dict[str, tuple[str, ...]] = {}
    # Dynamic angr C AST boundary: CVariable expressions expose optional variable metadata.
    selector_var = getattr(selector, "variable", None)
    # Dynamic angr SimVariable boundary: stack variable offset is optional in synthetic ASTs.
    selector_offset = getattr(selector_var, "offset", None)
    # Dynamic angr SimVariable boundary: stack variable size is optional in synthetic ASTs.
    selector_size = getattr(selector_var, "size", None)
    if isinstance(selector_var, SimStackVariable) and isinstance(selector_offset, int):
        selector_fp = _expr_fingerprint(selector, project)
        slot_sizes = {selector_size, 2}
        raw_slots = {
            _stack_slot_fingerprint_from_slot_8616(selector_offset, None),
        }
        raw_slots.update(
            _stack_slot_fingerprint_from_slot_8616(selector_offset, size)
            for size in slot_sizes
            if isinstance(size, int) and size > 0
        )
        if selector_offset > 0:
            source_view_offset = selector_offset + 4
            raw_slots.add(_stack_slot_fingerprint_from_slot_8616(source_view_offset, None))
            raw_slots.update(
                _stack_slot_fingerprint_from_slot_8616(source_view_offset, size)
                for size in slot_sizes
                if isinstance(size, int) and size > 0
            )
        selector_raw_aliases[selector_fp] = tuple(sorted(raw_slots))
    return selector_raw_aliases


def _next_linear_jmp_target_8616(insns: tuple[StructuredAstValue, ...], index: int) -> int | None:
    if index + 1 >= len(insns):
        return None
    next_insn = insns[index + 1]
    if str(getattr(next_insn, "mnemonic", "")).lower() not in {"jmp", "ljmp"}:
        return None
    return require_optional_result_type_8616(
        _jcc._branch_target_imm_8616(next_insn),
        int,
        owner="decompiler_postprocess_jcc._branch_target_imm_8616",
    )


def _resolve_one_hop_jmp_target_8616(project: StructuredAstValue, target: int | None) -> int | None:
    """Compatibility shim for structuring-owned one-hop CFG jump proof."""

    def _load_block(block_addr: int) -> StructuredAstValue | None:
        return project.factory.block(block_addr, opt_level=0)

    return require_optional_result_type_8616(
        _structuring_resolve_one_hop_jmp_target_8616(
            target,
            _load_block,
            _jcc._branch_target_imm_8616,
        ),
        int,
        owner="structuring.return_chains.resolve_one_hop_jmp_target_8616",
    )


def _is_dynamic_c_node_8616(obj: StructuredAstValue) -> bool:
    """Return True for angr structured-C nodes, identified through dynamic module state."""
    return hasattr(obj, "__slots__") and obj.__class__.__module__.startswith("angr.analyses.decompiler")


_CLONE_NOT_CONTAINER_8616 = object()


def _clone_c_container_8616(
    obj: StructuredAstValue, memo: dict[int, StructuredAstValue], *, preserve_cvariables: bool
) -> StructuredAstValue:
    """Clone builtin containers elementwise; returns the sentinel for non-containers."""
    if isinstance(obj, list):
        return [_clone_c_tree_8616(item, memo, preserve_cvariables=preserve_cvariables) for item in obj]
    if isinstance(obj, tuple):
        return tuple(_clone_c_tree_8616(item, memo, preserve_cvariables=preserve_cvariables) for item in obj)
    if isinstance(obj, dict):
        return {
            _clone_c_tree_8616(key, memo, preserve_cvariables=preserve_cvariables): _clone_c_tree_8616(
                item, memo, preserve_cvariables=preserve_cvariables
            )
            for key, item in obj.items()
        }
    return _CLONE_NOT_CONTAINER_8616


def _clone_c_slots_into_8616(
    obj: StructuredAstValue,
    cloned: StructuredAstValue,
    memo: dict[int, StructuredAstValue],
    *,
    preserve_cvariables: bool,
) -> None:
    """Clone each __slots__ attribute of obj into cloned."""
    slot_names: list[str] = []
    for cls in type(obj).__mro__:
        slots = getattr(cls, "__slots__", ())
        if isinstance(slots, str):
            slots = (slots,)
        slot_names.extend(str(slot) for slot in slots)
    for attr in dict.fromkeys(slot_names):
        if attr == "codegen" or not hasattr(obj, attr):
            continue
        try:
            child = getattr(obj, attr)
        except Exception:
            continue
        cloned_child = _clone_c_tree_8616(child, memo, preserve_cvariables=preserve_cvariables)
        if cloned_child is not child:
            with contextlib.suppress(Exception):
                setattr(cloned, attr, cloned_child)


def _clone_c_tree_8616(
    obj: StructuredAstValue, memo: dict[int, StructuredAstValue], *, preserve_cvariables: bool
) -> StructuredAstValue:
    """Deep-clone a structured C node tree, memoizing shared subobjects."""
    if obj is None:
        return None
    if preserve_cvariables and isinstance(obj, CVariable):
        return obj
    if isinstance(obj, (str, bytes, int, float, bool)):
        return obj
    container = _clone_c_container_8616(obj, memo, preserve_cvariables=preserve_cvariables)
    if container is not _CLONE_NOT_CONTAINER_8616:
        return container
    if not _is_dynamic_c_node_8616(obj):
        return obj
    obj_id = id(obj)
    if obj_id in memo:
        return memo[obj_id]
    cloned = copy.copy(obj)
    memo[obj_id] = cloned
    _clone_c_slots_into_8616(obj, cloned, memo, preserve_cvariables=preserve_cvariables)
    return cloned


def _clone_c_value_for_codegen_tree_8616(value: StructuredAstValue) -> StructuredAstValue:
    """Clone a structured C node before inserting it into a new C tree.

    The structured code renderer expects expression nodes to have a single
    tree owner. Selector-return materialization can reuse CFG-derived
    expressions in several branches, so clone on insertion to keep the final
    C AST acyclic and deterministic.
    """
    return _clone_c_tree_8616(value, {}, preserve_cvariables=False)


def _clone_c_value_preserving_cvariables_8616(value: StructuredAstValue) -> StructuredAstValue:
    """Clone expression structure while preserving canonical CVariable leaves."""
    return _clone_c_tree_8616(value, {}, preserve_cvariables=True)



def _materialize_decrement_switch_return_chain_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:
    """Compatibility shim for CFG-proven decrement-switch return materialization."""
    debug = os.environ.get("INERTIA_DEBUG_RETURN_BRANCH")
    log = logging.getLogger(__name__)
    sequential_materialized = require_result_type_8616(
        _structuring_materialize_sequential_decrement_switch_return_chain_8616(
            project,
            codegen,
            SequentialDecrementSwitchCallbacks8616(
                set_cfunc_statements_root=_set_cfunc_statements_root_8616,
                selector_stack_expr=_selector_stack_expr_from_ax_load_8616,
                selector_function_has_unsafe_effects=_selector_function_has_unsafe_effects_8616,
                selector_raw_stack_aliases=_selector_raw_stack_aliases_8616,
                linear_function_insns=_linear_function_insns_for_codegen_8616,
                next_linear_jmp_target=_next_linear_jmp_target_8616,
                resolve_one_hop_jmp_target=_resolve_one_hop_jmp_target_8616,
                branch_target_imm=_jcc._branch_target_imm_8616,
                branch_target_return_expr=_branch_target_return_expr_8616,
                clone_c_value=_clone_c_value_for_codegen_tree_8616,
                expr_fingerprint=_expr_fingerprint,
            ),
        ),
        bool,
        owner="structuring.return_chains.materialize_sequential_decrement_switch_return_chain_8616",
    )
    if sequential_materialized:
        if debug:
            log.warning("[cfg-selector-return] sequential decrement-switch materialized")
        return True
    materialized = require_result_type_8616(
        _structuring_materialize_complex_decrement_switch_return_chain_8616(
            project,
            codegen,
            ComplexDecrementSwitchCallbacks8616(
                set_cfunc_statements_root=_set_cfunc_statements_root_8616,
                selector_stack_expr=_selector_stack_expr_from_ax_load_8616,
                selector_function_has_unsafe_effects=_selector_function_has_unsafe_effects_8616,
                selector_raw_stack_aliases=_selector_raw_stack_aliases_8616,
                linear_function_insns=_linear_function_insns_for_codegen_8616,
                next_linear_jmp_target=_next_linear_jmp_target_8616,
                resolve_one_hop_jmp_target=_resolve_one_hop_jmp_target_8616,
                branch_target_imm=_jcc._branch_target_imm_8616,
                branch_target_return_expr=_branch_target_return_expr_8616,
                clone_c_value=_clone_c_value_for_codegen_tree_8616,
                expr_fingerprint=_expr_fingerprint,
            ),
        ),
        bool,
        owner="structuring.return_chains.materialize_complex_decrement_switch_return_chain_8616",
    )
    if debug and materialized:
        log.warning("[cfg-selector-return] decrement-switch materialized")
    return materialized


def _stack_mem_disp_size_8616(insn: StructuredAstValue, operand: StructuredAstValue) -> tuple[int, int] | None:
    """Return BP-relative memory displacement/size from a dynamic instruction operand."""
    # Dynamic third-party boundary: capstone operand type is numeric metadata.
    if int(getattr(operand, "type", -1)) != 3:
        return None
    # Dynamic third-party boundary: capstone operand memory descriptor is optional.
    mem = getattr(operand, "mem", None)
    # Dynamic third-party boundary: capstone memory base register metadata is optional.
    mem_base = getattr(mem, "base", None)
    if mem is None or not mem_base:
        return None
    try:
        if str(insn.reg_name(mem_base)).lower() != "bp":
            return None
    except Exception:
        return None
    # Dynamic third-party boundary: capstone operand size is numeric metadata.
    return (_signed_i16_immediate_8616(int(mem.disp)), int(getattr(operand, "size", 0) or 0))


def _reg_name_from_operand_8616(insn: StructuredAstValue, operand: StructuredAstValue) -> str | None:
    """Return a register operand name from a dynamic instruction operand."""
    # Dynamic third-party boundary: capstone operand type is numeric metadata.
    if int(getattr(operand, "type", -1)) != 1:
        return None
    try:
        return str(insn.reg_name(operand.reg)).lower()
    except Exception:
        return None


def _imm_from_operand_8616(operand: StructuredAstValue) -> int | None:
    """Return an immediate value from a dynamic instruction operand."""
    # Dynamic third-party boundary: capstone operand type is numeric metadata.
    if int(getattr(operand, "type", -1)) != 2:
        return None
    # Dynamic third-party boundary: capstone immediate value is optional.
    return int(getattr(operand, "imm", 0) or 0)


def _absolute_mem_disp_size_8616(operand: StructuredAstValue) -> tuple[int, int] | None:
    if int(getattr(operand, "type", -1)) != 3:
        return None
    mem = getattr(operand, "mem", None)
    if mem is None:
        return None
    if int(getattr(mem, "base", 0) or 0) != 0 or int(getattr(mem, "index", 0) or 0) != 0:
        return None
    return int(getattr(mem, "disp", 0) or 0), int(getattr(operand, "size", 0) or 0)


def _indexed_mem_disp_size_8616(
    insn: StructuredAstValue, operand: StructuredAstValue, *, base_reg: str
) -> tuple[int, int] | None:
    if int(getattr(operand, "type", -1)) != 3:
        return None
    mem = getattr(operand, "mem", None)
    if mem is None or not getattr(mem, "base", None):
        return None
    try:
        if str(insn.reg_name(mem.base)).lower() != base_reg:
            return None
    except Exception:
        return None
    if int(getattr(mem, "index", 0) or 0) != 0:
        return None
    return int(getattr(mem, "disp", 0) or 0), int(getattr(operand, "size", 0) or 0)


def _global_cvar_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, *, addr: int, size: int, name: str, signed: bool = False
) -> StructuredAstValue:
    """Build a global C variable through dynamic codegen compatibility objects."""
    cfunc = getattr(codegen, "cfunc", None)
    variable_type = SimTypeChar(signed) if int(size) == 1 else SimTypeShort(signed)
    variable_type = _bind_type_to_project_arch_8616(project, variable_type)
    return CVariable(
        SimMemoryVariable(int(addr), int(size), name=name, region=getattr(cfunc, "addr", None)),
        variable_type=variable_type,
        codegen=codegen,
    )


@dataclass
class _GlobalByteSumMatch8616:
    """Matched instruction-window evidence for the global byte sum loop."""

    word_global: tuple
    total_disp: int
    i_disp: int
    limit: int
    exit_addr: int
    mov_global: StructuredAstValue
    mov_al: StructuredAstValue
    byte_global: tuple


def _global_byte_sum_fail_8616(stats: dict) -> None:
    stats["failure_count"] = int(stats.get("failure_count", 0) or 0) + 1


def _global_byte_sum_init_window_8616(
    insns: tuple[StructuredAstValue, ...], init_idx: int
) -> tuple[tuple, int, int] | None:
    """Match the three-instruction init window; returns (word_global, total_disp, i_disp)."""
    mov_global = insns[init_idx]
    if str(getattr(mov_global, "mnemonic", "")).lower() != "mov":
        return None
    mov_global_ops = _boundary_tuple_8616(getattr(mov_global, "operands", ()) or ())
    if len(mov_global_ops) != 2 or _reg_name_from_operand_8616(mov_global, mov_global_ops[0]) != "ax":
        return None
    word_global = _absolute_mem_disp_size_8616(mov_global_ops[1])
    if word_global is None or int(word_global[1]) != 2:
        return None

    mov_total = insns[init_idx + 1]
    if str(getattr(mov_total, "mnemonic", "")).lower() != "mov":
        return None
    mov_total_ops = _boundary_tuple_8616(getattr(mov_total, "operands", ()) or ())
    if len(mov_total_ops) != 2 or _reg_name_from_operand_8616(mov_total, mov_total_ops[1]) != "ax":
        return None
    total_slot = _stack_mem_disp_size_8616(mov_total, mov_total_ops[0])
    if total_slot is None or int(total_slot[0]) >= 0:
        return None

    mov_i_zero = insns[init_idx + 2]
    i_disp = _match_stack_zero_init_8616(mov_i_zero)
    if i_disp is None or int(i_disp) >= 0 or int(i_disp) == int(total_slot[0]):
        return None
    return word_global, int(total_slot[0]), int(i_disp), mov_global


def _global_byte_sum_loop_match_8616(
    project: StructuredAstValue,
    insns: tuple[StructuredAstValue, ...],
    index_by_addr: dict[int, int],
    init_idx: int,
    stats: dict,
) -> _GlobalByteSumMatch8616 | None:
    """Match the mov/cmp/jl/body instruction window for the byte sum loop."""
    window = _global_byte_sum_init_window_8616(insns, init_idx)
    if window is None:
        return None
    word_global, total_disp0, i_disp, mov_global = window
    total_slot = (total_disp0,)
    stats["raw_fact_count"] = int(stats.get("raw_fact_count", 0) or 0) + 1

    jmp_to_cmp = insns[init_idx + 3]
    if str(getattr(jmp_to_cmp, "mnemonic", "")).lower() not in {"jmp", "ljmp"}:
        _global_byte_sum_fail_8616(stats)
        return None
    cmp_addr = _resolve_one_hop_jmp_target_8616(project, _jcc._branch_target_imm_8616(jmp_to_cmp))
    cmp_idx = index_by_addr.get(int(cmp_addr)) if cmp_addr is not None else None
    if cmp_idx is None or cmp_idx + 2 >= len(insns):
        _global_byte_sum_fail_8616(stats)
        return None

    inc_idx = init_idx + 4
    if not _match_stack_inc_8616(insns[inc_idx], int(i_disp)):
        _global_byte_sum_fail_8616(stats)
        return None
    cmp_i = insns[cmp_idx]
    cmp_ops = _boundary_tuple_8616(getattr(cmp_i, "operands", ()) or ())
    cmp_slot = _stack_mem_disp_size_8616(cmp_i, cmp_ops[0]) if len(cmp_ops) == 2 else None
    limit = _imm_from_operand_8616(cmp_ops[1]) if len(cmp_ops) == 2 else None
    if (
        str(getattr(cmp_i, "mnemonic", "")).lower() != "cmp"
        or cmp_slot is None
        or int(cmp_slot[0]) != int(i_disp)
        or limit is None
    ):
        _global_byte_sum_fail_8616(stats)
        return None
    jl = insns[cmp_idx + 1]
    if str(getattr(jl, "mnemonic", "")).lower() not in {"jl", "jnge"}:
        _global_byte_sum_fail_8616(stats)
        return None
    body_addr = _jcc._branch_target_imm_8616(jl)
    exit_addr = _resolve_one_hop_jmp_target_8616(project, _next_linear_jmp_target_8616(insns, cmp_idx + 1))
    body_idx = index_by_addr.get(int(body_addr)) if body_addr is not None else None
    if body_idx is None or body_idx + 4 >= len(insns) or exit_addr is None:
        _global_byte_sum_fail_8616(stats)
        return None

    body = _global_byte_sum_body_match_8616(project, insns, body_idx, inc_idx, i_disp, total_slot, stats)
    if body is None:
        return None
    mov_al, byte_global = body
    return _GlobalByteSumMatch8616(
        word_global=word_global,
        total_disp=int(total_slot[0]),
        i_disp=int(i_disp),
        limit=int(limit),
        exit_addr=int(exit_addr),
        mov_global=mov_global,
        mov_al=mov_al,
        byte_global=byte_global,
    )


def _global_byte_sum_body_match_8616(
    project: StructuredAstValue,
    insns: tuple[StructuredAstValue, ...],
    body_idx: int,
    inc_idx: int,
    i_disp: int,
    total_slot: tuple,
    stats: dict,
) -> tuple[StructuredAstValue, tuple] | None:
    """Match the five-instruction accumulation body; returns (mov_al, byte_global)."""
    mov_bx = insns[body_idx]
    mov_bx_ops = _boundary_tuple_8616(getattr(mov_bx, "operands", ()) or ())
    if (
        str(getattr(mov_bx, "mnemonic", "")).lower() != "mov"
        or len(mov_bx_ops) != 2
        or _reg_name_from_operand_8616(mov_bx, mov_bx_ops[0]) != "bx"
    ):
        _global_byte_sum_fail_8616(stats)
        return None
    bx_slot = _stack_mem_disp_size_8616(mov_bx, mov_bx_ops[1])
    if bx_slot is None or int(bx_slot[0]) != int(i_disp):
        _global_byte_sum_fail_8616(stats)
        return None

    mov_al = insns[body_idx + 1]
    mov_al_ops = _boundary_tuple_8616(getattr(mov_al, "operands", ()) or ())
    if (
        str(getattr(mov_al, "mnemonic", "")).lower() != "mov"
        or len(mov_al_ops) != 2
        or _reg_name_from_operand_8616(mov_al, mov_al_ops[0]) != "al"
    ):
        _global_byte_sum_fail_8616(stats)
        return None
    byte_global = _indexed_mem_disp_size_8616(mov_al, mov_al_ops[1], base_reg="bx")
    if byte_global is None or int(byte_global[1]) != 1:
        _global_byte_sum_fail_8616(stats)
        return None

    clear_ah = insns[body_idx + 2]
    clear_ops = _boundary_tuple_8616(getattr(clear_ah, "operands", ()) or ())
    if (
        str(getattr(clear_ah, "mnemonic", "")).lower() not in {"sub", "xor"}
        or len(clear_ops) != 2
        or _reg_name_from_operand_8616(clear_ah, clear_ops[0]) != "ah"
        or _reg_name_from_operand_8616(clear_ah, clear_ops[1]) != "ah"
    ):
        _global_byte_sum_fail_8616(stats)
        return None

    add_total = insns[body_idx + 3]
    add_ops = _boundary_tuple_8616(getattr(add_total, "operands", ()) or ())
    add_slot = _stack_mem_disp_size_8616(add_total, add_ops[0]) if len(add_ops) == 2 else None
    if (
        str(getattr(add_total, "mnemonic", "")).lower() != "add"
        or add_slot is None
        or int(add_slot[0]) != int(total_slot[0])
        or _reg_name_from_operand_8616(add_total, add_ops[1]) != "ax"
    ):
        _global_byte_sum_fail_8616(stats)
        return None

    back_jmp = insns[body_idx + 4]
    back_target = _resolve_one_hop_jmp_target_8616(project, _jcc._branch_target_imm_8616(back_jmp))
    if str(getattr(back_jmp, "mnemonic", "")).lower() not in {"jmp", "ljmp"} or int(back_target or -1) != int(
        getattr(insns[inc_idx], "address", -1)
    ):
        _global_byte_sum_fail_8616(stats)
        return None
    return mov_al, byte_global


def _emit_global_byte_sum_loop_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    match: _GlobalByteSumMatch8616,
    total_expr: StructuredAstValue,
    i_expr: StructuredAstValue,
    cod_direct_refs: dict,
    cod_indexed_refs: dict,
) -> None:
    """Emit the recovered global byte sum for-loop into the function body."""
    word_addr = int(match.word_global[0]) & 0xFFFF
    byte_addr = int(match.byte_global[0]) & 0xFFFF
    word_ref = _cod_global_name_ref_for_insn_8616(cod_direct_refs, match.mov_global)
    byte_ref = _cod_global_name_ref_for_insn_8616(cod_indexed_refs, match.mov_al)
    counter_name = (
        word_ref.name if word_ref is not None and int(word_ref.width) == 2 else f"global_word_{word_addr:04x}"
    )
    table_name = (
        byte_ref.name if byte_ref is not None and int(byte_ref.width) == 1 else f"global_u8_{byte_addr:04x}"
    )
    counter_base_addr = (word_addr - int(word_ref.relative_disp)) & 0xFFFF if word_ref is not None else word_addr
    table_base_addr = (byte_addr - int(byte_ref.relative_disp)) & 0xFFFF if byte_ref is not None else byte_addr
    counter_expr = _global_cvar_8616(
        project, codegen, addr=counter_base_addr, size=2, name=counter_name, signed=True
    )
    table_expr = _global_cvar_8616(project, codegen, addr=table_base_addr, size=1, name=table_name, signed=False)
    indexed_byte = CIndexedVariable(
        table_expr,
        i_expr,
        variable_type=_bind_type_to_project_arch_8616(project, SimTypeChar(False)),
        codegen=codegen,
    )
    init_total = CAssignment(
        total_expr,
        counter_expr,
        codegen=codegen,
    )
    init_i = CAssignment(
        i_expr,
        CConstant(0, SimTypeShort(True), codegen=codegen),
        codegen=codegen,
    )
    condition = CBinaryOp(
        "CmpLT",
        i_expr,
        CConstant(int(match.limit), SimTypeShort(True), codegen=codegen),
        codegen=codegen,
    )
    iterator = _inc_assignment_8616(i_expr, codegen)
    body = CStatements(
        statements=[
            CAssignment(
                total_expr,
                CBinaryOp(
                    "Add",
                    total_expr,
                    indexed_byte,
                    codegen=codegen,
                ),
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        statements=[
            init_total,
            CForLoop(init_i, condition, iterator, body, codegen=codegen),
            CReturn(total_expr, codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen._inertia_global_byte_sum_loop_materialized_8616 = True
    codegen._inertia_global_byte_sum_loop_evidence_8616 = {
        "total_disp": int(match.total_disp),
        "index_disp": int(match.i_disp),
        "word_global": int(match.word_global[0]),
        "byte_global": int(match.byte_global[0]),
        "limit": int(match.limit),
        "counter_name": counter_name,
        "table_name": table_name,
    }
    record_global_declaration_spec_8616(
        codegen,
        ctype="short",
        name=counter_name,
        array_len=None,
    )
    record_global_declaration_spec_8616(
        codegen,
        ctype="unsigned char",
        name=table_name,
        array_len=int(match.limit),
    )


def _materialize_global_byte_index_sum_loop_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:
    """Recover a word accumulator loop through dynamic angr/codegen compatibility objects.

    Generic MS C shape:
        total = global_word;
        for (i = 0; i < limit; ++i)
            total += global_byte_array[i];
        return total;
    """
    if getattr(codegen, "_inertia_global_byte_sum_loop_materialized_8616", False):
        return False
    insns = _linear_function_insns_for_codegen_8616(project, codegen)
    if len(insns) < 12:
        return False
    index_by_addr = {int(getattr(insn, "address", -1)): idx for idx, insn in enumerate(insns)}
    metadata = _cod_metadata_for_codegen_function_8616(project, getattr(getattr(codegen, "cfunc", None), "addr", None))
    bytes_by_address = getattr(codegen, "_inertia_instruction_bytes_by_addr_8616", None)
    bytes_by_address = bytes_by_address if isinstance(bytes_by_address, Mapping) else None
    cod_direct_refs = _cod_global_name_refs_by_address_8616(
        metadata, insns, indexed=False, bytes_by_address=bytes_by_address
    )
    cod_indexed_refs = _cod_global_name_refs_by_address_8616(
        metadata, insns, indexed=True, bytes_by_address=bytes_by_address
    )
    if os.environ.get("INERTIA_DEBUG_GLOBAL_BYTE_SUM"):
        logging.getLogger(__name__).warning(
            "[global-byte-sum] metadata=%s refs=%s indexed=%s insns=%s",
            metadata is not None,
            {hex(k): v for k, v in cod_direct_refs.items()},
            {hex(k): v for k, v in cod_indexed_refs.items()},
            tuple(
                (
                    hex(addr),
                    insn_bytes.hex() if isinstance(insn_bytes, bytes) else type(insn_bytes).__name__,
                )
                for insn in insns
                if (addr := _capstone_insn_address_8616(insn)) is not None
                for insn_bytes in (_capstone_insn_bytes_for_match_8616(insn, bytes_by_address),)
            ),
        )
    stats = getattr(codegen, "_inertia_global_byte_sum_loop_stats_8616", None)
    if not isinstance(stats, dict):
        stats = {"raw_fact_count": 0, "classified_fact_count": 0, "materialized_count": 0, "failure_count": 0}
        codegen._inertia_global_byte_sum_loop_stats_8616 = stats

    for init_idx in range(len(insns) - 8):
        match = _global_byte_sum_loop_match_8616(project, insns, index_by_addr, init_idx, stats)
        if match is None:
            continue

        exit_expr = _branch_target_return_expr_8616(project, codegen, int(match.exit_addr))
        total_expr = _named_stack_expr_from_evidence_8616(project, codegen, int(match.total_disp), 2)
        i_expr = _named_stack_expr_from_evidence_8616(project, codegen, int(match.i_disp), 2)
        if exit_expr is None or total_expr is None or i_expr is None:
            _global_byte_sum_fail_8616(stats)
            continue
        if _expr_fingerprint(exit_expr, project) != _expr_fingerprint(total_expr, project):
            _global_byte_sum_fail_8616(stats)
            continue

        if storage_reconstruction_has_unconsumed_effects_8616(codegen.cfunc.statements, (total_expr, i_expr)):
            # Optional reconstruction cannot consume unrelated effects; keep the native body.
            _global_byte_sum_fail_8616(stats)
            continue

        stats["classified_fact_count"] = int(stats.get("classified_fact_count", 0) or 0) + 1
        _emit_global_byte_sum_loop_8616(
            project, codegen, match, total_expr, i_expr, cod_direct_refs, cod_indexed_refs
        )
        stats["materialized_count"] = int(stats.get("materialized_count", 0) or 0) + 1
        return True
    return False



def _block_insns_8616(project: StructuredAstValue, addr: int) -> tuple[StructuredAstValue, ...]:
    try:
        block = project.factory.block(int(addr), opt_level=0)
    except Exception:
        return ()
    return _boundary_tuple_8616(getattr(getattr(block, "capstone", None), "insns", ()) or ())


def _match_stack_zero_init_8616(insn: StructuredAstValue) -> int | None:
    if str(getattr(insn, "mnemonic", "")).lower() != "mov":
        return None
    operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
    if len(operands) != 2 or _imm_from_operand_8616(operands[1]) != 0:
        return None
    slot = _stack_mem_disp_size_8616(insn, operands[0])
    return int(slot[0]) if slot is not None else None


def _match_stack_inc_8616(insn: StructuredAstValue, disp: int) -> bool:
    if str(getattr(insn, "mnemonic", "")).lower() != "inc":
        return False
    operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
    if len(operands) != 1:
        return False
    slot = _stack_mem_disp_size_8616(insn, operands[0])
    return slot is not None and int(slot[0]) == int(disp)


def _match_mov_ax_stack_8616(insn: StructuredAstValue, disp: int) -> bool:
    if str(getattr(insn, "mnemonic", "")).lower() != "mov":
        return False
    operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
    if len(operands) != 2 or _reg_name_from_operand_8616(insn, operands[0]) != "ax":
        return False
    slot = _stack_mem_disp_size_8616(insn, operands[1])
    return slot is not None and int(slot[0]) == int(disp)


def _match_cmp_stack_ax_8616(insn: StructuredAstValue, disp: int) -> bool:
    if str(getattr(insn, "mnemonic", "")).lower() != "cmp":
        return False
    operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
    if len(operands) != 2 or _reg_name_from_operand_8616(insn, operands[1]) != "ax":
        return False
    slot = _stack_mem_disp_size_8616(insn, operands[0])
    return slot is not None and int(slot[0]) == int(disp)


def _mem_base_index_size_8616(
    insn: StructuredAstValue, operand: StructuredAstValue
) -> tuple[str | None, str | None, int, int] | None:
    if int(getattr(operand, "type", -1)) != 3:
        return None
    mem = getattr(operand, "mem", None)
    if mem is None:
        return None
    base = str(insn.reg_name(mem.base)).lower() if getattr(mem, "base", 0) else None
    index = str(insn.reg_name(mem.index)).lower() if getattr(mem, "index", 0) else None
    size = int(getattr(operand, "size", 0) or 0)
    return base, index, int(getattr(mem, "disp", 0) or 0), size


def _match_stack_mov_to_reg_8616(insn: StructuredAstValue, reg_name: str, disp: int, *, size: int = 2) -> bool:
    if str(getattr(insn, "mnemonic", "")).lower() != "mov":
        return False
    operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
    if len(operands) != 2 or _reg_name_from_operand_8616(insn, operands[0]) != reg_name:
        return False
    slot = _stack_mem_disp_size_8616(insn, operands[1])
    return slot is not None and int(slot[0]) == int(disp) and int(slot[1]) == int(size)


def _match_indexed_reg_store_8616(
    insn: StructuredAstValue, *, base_reg: str, index_reg: str, src_reg: str, size: int
) -> bool:
    if str(getattr(insn, "mnemonic", "")).lower() != "mov":
        return False
    operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
    if len(operands) != 2 or _reg_name_from_operand_8616(insn, operands[1]) != src_reg:
        return False
    mem = _mem_base_index_size_8616(insn, operands[0])
    if mem is None:
        return False
    base, index, disp, mem_size = mem
    return disp == 0 and int(mem_size) == int(size) and {base, index} == {base_reg, index_reg}


def _match_indexed_reg_load_8616(
    insn: StructuredAstValue,
    *,
    dst_reg: str,
    base_reg: str,
    index_reg: str,
    size: int,
    disp: int = 0,
) -> bool:
    if str(getattr(insn, "mnemonic", "")).lower() != "mov":
        return False
    operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
    if len(operands) != 2 or _reg_name_from_operand_8616(insn, operands[0]) != dst_reg:
        return False
    mem = _mem_base_index_size_8616(insn, operands[1])
    if mem is None:
        return False
    base, index, mem_disp, mem_size = mem
    return int(mem_disp) == int(disp) and int(mem_size) == int(size) and {base, index} == {base_reg, index_reg}


def _match_cmp_indexed_reg_8616(
    insn: StructuredAstValue, *, base_reg: str, index_reg: str, rhs_reg: str, size: int, disp: int = 0
) -> bool:
    if str(getattr(insn, "mnemonic", "")).lower() != "cmp":
        return False
    operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
    if len(operands) != 2 or _reg_name_from_operand_8616(insn, operands[1]) != rhs_reg:
        return False
    mem = _mem_base_index_size_8616(insn, operands[0])
    if mem is None:
        return False
    base, index, mem_disp, mem_size = mem
    return int(mem_disp) == int(disp) and int(mem_size) == int(size) and {base, index} == {base_reg, index_reg}


def _match_reg_indirect_load_8616(
    insn: StructuredAstValue, *, dst_reg: str, base_reg: str, size: int, disp: int = 0
) -> bool:
    if str(getattr(insn, "mnemonic", "")).lower() != "mov":
        return False
    operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
    if len(operands) != 2 or _reg_name_from_operand_8616(insn, operands[0]) != dst_reg:
        return False
    mem = _mem_base_index_size_8616(insn, operands[1])
    if mem is None:
        return False
    base, index, mem_disp, mem_size = mem
    return base == base_reg and index is None and int(mem_disp) == int(disp) and int(mem_size) == int(size)


def _match_reg_indirect_store_8616(
    insn: StructuredAstValue, *, base_reg: str, src_reg: str, size: int, disp: int = 0
) -> bool:
    if str(getattr(insn, "mnemonic", "")).lower() != "mov":
        return False
    operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
    if len(operands) != 2 or _reg_name_from_operand_8616(insn, operands[1]) != src_reg:
        return False
    mem = _mem_base_index_size_8616(insn, operands[0])
    if mem is None:
        return False
    base, index, mem_disp, mem_size = mem
    return base == base_reg and index is None and int(mem_disp) == int(disp) and int(mem_size) == int(size)


def _stack_expr_8616(codegen: StructuredAstValue, disp: int, size: int = 2) -> StructuredAstValue:
    return _jcc._stack_slot_expr_8616(codegen, int(disp), int(size) or 2)


def _bind_type_to_project_arch_8616(project: StructuredAstValue, type_: StructuredAstValue) -> StructuredAstValue:
    arch = getattr(project, "arch", None)
    if arch is None or type_ is None or not hasattr(type_, "with_arch"):
        return type_
    try:
        return type_.with_arch(arch)
    except Exception:
        return type_


def _word_type_for_project_8616(project: StructuredAstValue) -> StructuredAstValue:
    return _bind_type_to_project_arch_8616(project, SimTypeShort(False))


def _signed_word_type_for_project_8616(project: StructuredAstValue) -> StructuredAstValue:
    return _bind_type_to_project_arch_8616(project, SimTypeShort(True))


def _void_type_for_project_8616(project: StructuredAstValue) -> StructuredAstValue:
    return _bind_type_to_project_arch_8616(project, SimTypeBottom(label="void"))


def _pointer_type_for_project_8616(
    project: StructuredAstValue, pointee_size: int, *, signed: bool = False
) -> StructuredAstValue:
    pointee = SimTypeChar(signed) if int(pointee_size) == 1 else SimTypeShort(signed)
    return _bind_type_to_project_arch_8616(
        project,
        SimTypeNearPointer16_8616(_bind_type_to_project_arch_8616(project, pointee)),
    )


def _type_size_bytes_for_stack_arg_8616(
    project: StructuredAstValue, type_: StructuredAstValue, default: int = 2
) -> int:
    if isinstance(type_, SimTypePointer) and getattr(getattr(project, "arch", None), "name", None) == "86_16":
        return 2
    bits = getattr(type_, "size", None)
    if isinstance(bits, int) and bits > 0:
        return max(1, (bits + 7) // 8)
    return max(1, int(default) if isinstance(default, int) else 2)


def _stack_alias_name_from_optional_cod_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, disp: int
) -> str | None:
    return None


def _fallback_stack_arg_name_8616(disp: int) -> str:
    if int(disp) >= 4:
        return f"arg_{max(((int(disp) - 4) // 2) + 1, 1)}"
    return require_result_type_8616(
        _stack_object_name(int(disp)),
        str,
        owner="lowering.stack_lowering_from_facts._stack_object_name",
    )


def _yield_unseen_cvars_8616(exprs: StructuredAstValue, yielded: set[int]) -> StructuredAstValue:
    """Yield each CVariable once across all cfunc surfaces."""
    for expr in exprs:
        if isinstance(expr, CVariable) and id(expr) not in yielded:
            yielded.add(id(expr))
            yield expr


def _iter_stack_cvars_for_cfunc_8616(cfunc: StructuredAstValue) -> StructuredAstValue:
    yielded: set[int] = set()
    yield from _yield_unseen_cvars_8616(
        _boundary_tuple_8616(getattr(cfunc, "arg_list", ()) or ()), yielded
    )
    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict):
        yield from _yield_unseen_cvars_8616(variables_in_use.values(), yielded)
    unified = getattr(cfunc, "unified_local_vars", None)
    if isinstance(unified, dict):
        yield from _yield_unseen_cvars_8616(
            (
                item[0]
                for entries in unified.values()
                for item in entries or ()
                if isinstance(item, tuple) and item
            ),
            yielded,
        )
    root = getattr(cfunc, "statements", None)
    if root is not None:
        yield from _yield_unseen_cvars_8616(_iter_c_nodes_deep_8616(root), yielded)


def _canonical_stack_cvar_at_offset_8616(cfunc: StructuredAstValue, offset: int) -> StructuredAstValue:
    best = None
    best_score = None
    for cvar in _iter_stack_cvars_for_cfunc_8616(cfunc):
        variable = getattr(cvar, "variable", None)
        if not isinstance(variable, SimStackVariable) or getattr(variable, "offset", None) != int(offset):
            continue
        name = getattr(variable, "name", None) or getattr(cvar, "name", None)
        name_score = 2
        if isinstance(name, str) and name.startswith(("stack_bp_", "s_", "arg_", "local_")):
            name_score = 1
        if isinstance(name, str) and name and not name.startswith(("stack_bp_", "s_")):
            name_score += 1
        score = (name_score, int(getattr(variable, "size", 0) or 0))
        if best_score is None or score > best_score:
            best = cvar
            best_score = score
    return best


def _replace_stack_variable_entry_8616(
    table: dict, variable: SimStackVariable, offset: int, value: StructuredAstValue
) -> None:
    """Drop stale stack entries at the same offset and install the canonical one."""
    for existing_variable in tuple(table.keys()):
        if not isinstance(existing_variable, SimStackVariable):
            continue
        if existing_variable.offset == offset and existing_variable is not variable:
            del table[existing_variable]
    table[variable] = value


def _install_canonical_stack_cvar_8616(
    cfunc: StructuredAstValue, cvar: StructuredAstValue, variable_type: StructuredAstValue = None
) -> None:
    variable = getattr(cvar, "variable", None)
    if not isinstance(cvar, CVariable) or not isinstance(variable, SimStackVariable):
        return
    offset = getattr(variable, "offset", None)
    if not isinstance(offset, int):
        return
    if variable_type is None:
        variable_type = getattr(cvar, "variable_type", None)
    variables = getattr(cfunc, "variables_in_use", None)
    if isinstance(variables, dict):
        _replace_stack_variable_entry_8616(variables, variable, offset, cvar)
    unified = getattr(cfunc, "unified_local_vars", None)
    if isinstance(unified, dict):
        _replace_stack_variable_entry_8616(unified, variable, offset, {(cvar, variable_type)})


def _stack_arg_prototype_8616(
    project: StructuredAstValue, cfunc: StructuredAstValue, word_type: StructuredAstValue
) -> StructuredAstValue:
    """Return the function prototype, synthesizing a word-typed default when absent."""
    prototype = getattr(cfunc, "functy", None) or getattr(cfunc, "prototype", None)
    if prototype is None:
        func_addr = getattr(cfunc, "addr", None)
        func = project.kb.functions.function(addr=func_addr, create=False) if isinstance(func_addr, int) else None
        prototype = getattr(func, "prototype", None) if func is not None else None
    if prototype is None:
        prototype = _bind_type_to_project_arch_8616(
            project,
            SimTypeFunction([], word_type, arg_names=(), variadic=False),
        )
    return prototype


def _stack_arg_target_index_8616(
    project: StructuredAstValue,
    args: list,
    arg_names: list,
    disp: int,
    first_argument_bp_offset: int,
    arg_type: StructuredAstValue,
    word_type: StructuredAstValue,
    arg_name: str,
) -> int | None:
    """Locate or extend the prototype arg list so that disp has a slot."""
    cursor = first_argument_bp_offset
    target_index = None
    for idx, existing_type in enumerate(args):
        if cursor == disp:
            target_index = idx
            break
        cursor += max(2, _type_size_bytes_for_stack_arg_8616(project, existing_type))
    while target_index is None and cursor <= disp and disp <= 0x40:
        new_type = arg_type if cursor == disp else word_type
        args.append(new_type)
        arg_names.append(arg_name if cursor == disp else _fallback_stack_arg_name_8616(cursor))
        if cursor == disp:
            target_index = len(args) - 1
            break
        cursor += max(2, _type_size_bytes_for_stack_arg_8616(project, new_type))
    return target_index


def _build_desired_stack_args_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    cfunc: StructuredAstValue,
    args: list,
    arg_names: list,
    disp: int,
    first_argument_bp_offset: int,
) -> tuple[list, StructuredAstValue]:
    """Build the desired CVariable arg list; returns (args, target_cvar)."""
    desired_args: list[CVariable] = []
    func_addr = getattr(cfunc, "addr", None)
    cursor = first_argument_bp_offset
    target_cvar = None
    for idx, current_type in enumerate(args):
        width = max(2, _type_size_bytes_for_stack_arg_8616(project, current_type))
        name = arg_names[idx] if idx < len(arg_names) and isinstance(arg_names[idx], str) and arg_names[idx] else None
        if name is None:
            name = _fallback_stack_arg_name_8616(cursor)
        cvar = stack_cvar_for_machine_bp_range_8616(codegen, cursor, width)
        if not isinstance(cvar, CVariable):
            legacy_cvar = _canonical_stack_cvar_at_offset_8616(cfunc, cursor)
            legacy_variable = getattr(legacy_cvar, "variable", None)
            cvar = (
                legacy_cvar
                if isinstance(legacy_cvar, CVariable)
                and isinstance(legacy_variable, SimStackVariable)
                and machine_bp_offset_for_stack_variable_8616(codegen, legacy_variable) == cursor
                else None
            )
        variable = getattr(cvar, "variable", None) if cvar is not None else None
        if not isinstance(cvar, CVariable) or not isinstance(variable, SimStackVariable):
            variable = SimStackVariable(cursor, width, base="bp", name=name, region=func_addr)
            cvar = CVariable(variable, variable_type=current_type, codegen=codegen)
        else:
            variable.name = name
            variable.size = width
            cvar.variable_type = current_type
        publish_selected_stack_cvar_projection_8616(
            codegen,
            cvar,
            bp_offset=cursor,
            size=width,
            entry_sp_offset=variable.offset,
        )
        _install_canonical_stack_cvar_8616(cfunc, cvar, current_type)
        desired_args.append(cvar)
        if cursor == disp:
            target_cvar = cvar
        cursor += width
    return desired_args, target_cvar


def _publish_stack_arg_prototype_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    cfunc: StructuredAstValue,
    prototype: StructuredAstValue,
    args: list,
    arg_names: list,
    word_type: StructuredAstValue,
    first_argument_bp_offset: int,
) -> None:
    """Install the rebuilt prototype on cfunc and the KB function."""
    normalized_arg_names = tuple(
        name
        if isinstance(name, str)
        and name
        else _fallback_stack_arg_name_8616(first_argument_bp_offset + idx * 2)
        for idx, name in enumerate(arg_names[: len(args)])
    )
    new_prototype = SimTypeFunction(
        args,
        getattr(prototype, "returnty", word_type),
        arg_names=normalized_arg_names,
        variadic=getattr(prototype, "variadic", False),
    )
    new_prototype = _bind_type_to_project_arch_8616(project, new_prototype)
    cfunc.functy = new_prototype
    with contextlib.suppress(Exception):
        cfunc.prototype = new_prototype
    func_addr = getattr(cfunc, "addr", None)
    func = project.kb.functions.function(addr=func_addr, create=False) if isinstance(func_addr, int) else None
    if func is not None:
        func.prototype = new_prototype
        func.is_prototype_guessed = False

    refresh = getattr(cfunc, "refresh", None)
    if callable(refresh):
        with contextlib.suppress(Exception):
            refresh()


def _ensure_typed_stack_arg_expr_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    disp: int,
    arg_type: StructuredAstValue,
    *,
    fallback_name: str | None = None,
) -> StructuredAstValue:
    """Materialize one typed argument using its authoritative machine-BP identity."""
    cfunc = getattr(codegen, "cfunc", None)
    first_argument_bp_offset = proven_first_argument_machine_bp_offset_8616(codegen)
    if cfunc is None or int(disp) < first_argument_bp_offset:
        return None
    disp = int(disp)
    word_type = _word_type_for_project_8616(project)
    arg_name = (
        _stack_alias_name_from_optional_cod_8616(project, codegen, disp)
        or fallback_name
        or _fallback_stack_arg_name_8616(disp)
    )

    prototype = _stack_arg_prototype_8616(project, cfunc, word_type)

    arg_type = _bind_type_to_project_arch_8616(project, arg_type)
    args = _boundary_list_8616(getattr(prototype, "args", ()) or ())
    arg_names = _boundary_list_8616(getattr(prototype, "arg_names", None) or ())
    target_index = _stack_arg_target_index_8616(
        project, args, arg_names, disp, first_argument_bp_offset, arg_type, word_type, arg_name
    )
    if target_index is None:
        return None

    args[target_index] = arg_type
    while len(arg_names) < len(args):
        arg_names.append(_fallback_stack_arg_name_8616(first_argument_bp_offset + len(arg_names) * 2))
    arg_names[target_index] = arg_name

    desired_args, target_cvar = _build_desired_stack_args_8616(
        project, codegen, cfunc, args, arg_names, disp, first_argument_bp_offset
    )

    cfunc.arg_list = desired_args
    _publish_stack_arg_prototype_8616(
        project, codegen, cfunc, prototype, args, arg_names, word_type, first_argument_bp_offset
    )
    return target_cvar



def _ensure_pointer_stack_arg_expr_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    disp: int,
    *,
    pointee_size: int,
    fallback_name: str | None = None,
) -> StructuredAstValue:
    """Materialize BP-positive slots proven by register-indirect memory use as pointer args."""
    pointer_type = _pointer_type_for_project_8616(project, int(pointee_size))
    return _ensure_typed_stack_arg_expr_8616(project, codegen, disp, pointer_type, fallback_name=fallback_name)


def _named_stack_expr_from_evidence_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, disp: int, size: int = 2
) -> StructuredAstValue:
    expr = _stack_expr_8616(codegen, int(disp), int(size) or 2)
    alias_name = _stack_alias_name_from_optional_cod_8616(project, codegen, int(disp))
    variable = getattr(expr, "variable", None)
    if isinstance(alias_name, str) and isinstance(variable, SimStackVariable):
        variable.name = alias_name
    if isinstance(expr, CVariable):
        if expr.variable_type is None:
            expr.variable_type = _word_type_for_project_8616(project)
        cfunc = getattr(codegen, "cfunc", None)
        if cfunc is not None:
            _install_canonical_stack_cvar_8616(cfunc, expr, expr.variable_type)
    return expr


def _inc_assignment_8616(expr: StructuredAstValue, codegen: StructuredAstValue) -> StructuredAstValue:
    return CAssignment(
        _clone_c_value_for_codegen_tree_8616(expr),
        CBinaryOp(
            "Add",
            _clone_c_value_for_codegen_tree_8616(expr),
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )


def _match_reg_shl1_8616(insn: StructuredAstValue, reg_name: str) -> bool:
    if str(getattr(insn, "mnemonic", "")).lower() != "shl":
        return False
    operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
    return (
        len(operands) == 2
        and _reg_name_from_operand_8616(insn, operands[0]) == reg_name
        and _imm_from_operand_8616(operands[1]) == 1
    )


def _const_short_8616(codegen: StructuredAstValue, value: int, *, signed: bool = False) -> StructuredAstValue:
    return CConstant(int(value), SimTypeShort(signed), codegen=codegen)


def _mul_expr_8616(lhs: StructuredAstValue, rhs: StructuredAstValue, codegen: StructuredAstValue) -> StructuredAstValue:
    return CBinaryOp(
        "Mul",
        _clone_c_value_preserving_cvariables_8616(lhs),
        _clone_c_value_preserving_cvariables_8616(rhs),
        codegen=codegen,
    )


def _add_expr_8616(lhs: StructuredAstValue, rhs: StructuredAstValue, codegen: StructuredAstValue) -> StructuredAstValue:
    return CBinaryOp(
        "Add",
        _clone_c_value_preserving_cvariables_8616(lhs),
        _clone_c_value_preserving_cvariables_8616(rhs),
        codegen=codegen,
    )


def _inc_assignment_preserving_cvariables_8616(
    expr: StructuredAstValue, codegen: StructuredAstValue
) -> StructuredAstValue:
    return CAssignment(
        _clone_c_value_preserving_cvariables_8616(expr),
        CBinaryOp(
            "Add",
            _clone_c_value_preserving_cvariables_8616(expr),
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )


def _deref_expr_8616(expr: StructuredAstValue, codegen: StructuredAstValue) -> StructuredAstValue:
    project = getattr(codegen, "project", None)
    word_type = _word_type_for_project_8616(project)
    return CIndexedVariable(
        _clone_c_value_for_codegen_tree_8616(expr),
        CConstant(0, word_type, codegen=codegen),
        variable_type=word_type,
        codegen=codegen,
    )


def _indexed_word_pointer_expr_8616(
    base_expr: StructuredAstValue,
    index_expr: StructuredAstValue,
    codegen: StructuredAstValue,
    *,
    variable_type: StructuredAstValue = None,
) -> StructuredAstValue:
    return CIndexedVariable(
        _clone_c_value_preserving_cvariables_8616(base_expr),
        _clone_c_value_preserving_cvariables_8616(index_expr),
        variable_type=variable_type,
        codegen=codegen,
    )


def _mark_codegen_signature_authoritative_8616(
    _project: StructuredAstValue, codegen: StructuredAstValue, reason: str
) -> None:
    """Mark the current codegen signature as protected from text rewrites.

    The marker belongs to the mutable codegen compatibility surface.  angr
    ``Function`` objects may be slotted, and they are not an owned metadata
    contract; attempting to copy the marker onto them can abort postprocessing.
    """
    codegen._inertia_codegen_signature_authoritative_8616 = reason


def _set_codegen_return_type_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, return_type: StructuredAstValue
) -> None:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return
    prototype = getattr(cfunc, "functy", None) or getattr(cfunc, "prototype", None)
    arg_list = _boundary_list_8616(getattr(cfunc, "arg_list", ()) or ())
    if prototype is not None:
        args = _boundary_list_8616(getattr(prototype, "args", ()) or ())
        arg_names = _boundary_list_8616(getattr(prototype, "arg_names", None) or ())
    else:
        args = [getattr(arg, "variable_type", None) or _word_type_for_project_8616(project) for arg in arg_list]
        arg_names = []
    if arg_list and len(args) != len(arg_list):
        args = [getattr(arg, "variable_type", None) or _word_type_for_project_8616(project) for arg in arg_list]
    if arg_list and len(arg_names) != len(arg_list):
        arg_names = [
            getattr(getattr(arg, "variable", None), "name", None) or getattr(arg, "name", None) or f"arg_{idx}"
            for idx, arg in enumerate(arg_list)
        ]
    new_prototype = SimTypeFunction(
        args,
        _bind_type_to_project_arch_8616(project, return_type),
        arg_names=tuple(arg_names),
        variadic=getattr(prototype, "variadic", False) if prototype is not None else False,
    )
    new_prototype = _bind_type_to_project_arch_8616(project, new_prototype)
    cfunc.functy = new_prototype
    with contextlib.suppress(Exception):
        cfunc.prototype = new_prototype
    func_addr = getattr(cfunc, "addr", None)
    func = project.kb.functions.function(addr=func_addr, create=False) if isinstance(func_addr, int) else None
    if func is not None:
        func.prototype = new_prototype
        func.is_prototype_guessed = False






def _pair_accum_header_match_8616(
    project: StructuredAstValue,
    insns: tuple[StructuredAstValue, ...],
    index_by_addr: dict[int, int],
    init_idx: int,
    i_disp: int,
    stats: dict[str, int],
) -> tuple[int, int, int] | None:
    """Match the accumulation loop header; returns (inc_addr, body_target, exit_target)."""
    first_jmp = insns[init_idx + 2]
    if str(getattr(first_jmp, "mnemonic", "")).lower() not in {"jmp", "ljmp"}:
        stats["failure_count"] += 1
        return None
    inc_addr = int(getattr(insns[init_idx + 3], "address", -1))
    if not _match_stack_inc_8616(insns[init_idx + 3], i_disp):
        stats["failure_count"] += 1
        return None
    cond_target = _resolve_one_hop_jmp_target_8616(project, _jcc._branch_target_imm_8616(first_jmp))
    if cond_target is None or int(cond_target) != int(getattr(insns[init_idx + 4], "address", -1)):
        stats["failure_count"] += 1
        return None
    if not _match_stack_mov_to_reg_8616(insns[init_idx + 4], "ax", 6):
        stats["failure_count"] += 1
        return None
    if not _match_cmp_stack_ax_8616(insns[init_idx + 5], i_disp):
        stats["failure_count"] += 1
        return None
    jcc = insns[init_idx + 6]
    if str(getattr(jcc, "mnemonic", "")).lower() not in {"jl", "jnge"}:
        stats["failure_count"] += 1
        return None
    body_target = _jcc._branch_target_imm_8616(jcc)
    exit_target = _resolve_one_hop_jmp_target_8616(
        project,
        _next_linear_jmp_target_8616(insns, index_by_addr.get(int(getattr(jcc, "address", -1)), -1)),
    )
    if body_target is None or exit_target is None:
        stats["failure_count"] += 1
        return None
    return inc_addr, int(body_target), int(exit_target)


def _pair_accum_body_match_8616(
    project: StructuredAstValue,
    body: StructuredAstValue,
    i_disp: int,
    total_disp: int,
    inc_addr: int,
    stats: dict[str, int],
) -> bool:
    """Match the 14-instruction accumulation body; records a failure on mismatch."""
    if len(body) < 14:
        stats["failure_count"] += 1
        return False
    if not (
        _match_stack_mov_to_reg_8616(body[0], "bx", i_disp)
        and _match_reg_shl1_8616(body[1], "bx")
        and _match_reg_shl1_8616(body[2], "bx")
        and _match_stack_mov_to_reg_8616(body[3], "si", 4)
        and _match_indexed_reg_load_8616(body[4], dst_reg="ax", base_reg="bx", index_reg="si", size=2)
        and _match_reg_shl1_8616(body[5], "ax")
    ):
        stats["failure_count"] += 1
        return False
    add_left_ops = _boundary_tuple_8616(getattr(body[6], "operands", ()) or ())
    add_left_slot = _stack_mem_disp_size_8616(body[6], add_left_ops[0]) if len(add_left_ops) == 2 else None
    if (
        str(getattr(body[6], "mnemonic", "")).lower() != "add"
        or add_left_slot is None
        or int(add_left_slot[0]) != int(total_disp)
        or _reg_name_from_operand_8616(body[6], add_left_ops[1]) != "ax"
    ):
        stats["failure_count"] += 1
        return False
    if not (
        _match_stack_mov_to_reg_8616(body[7], "si", i_disp)
        and _match_reg_shl1_8616(body[8], "si")
        and _match_reg_shl1_8616(body[9], "si")
        and _match_stack_mov_to_reg_8616(body[10], "bx", 4)
        and _match_indexed_reg_load_8616(body[11], dst_reg="ax", base_reg="bx", index_reg="si", size=2, disp=2)
    ):
        stats["failure_count"] += 1
        return False
    add_right_ops = _boundary_tuple_8616(getattr(body[12], "operands", ()) or ())
    add_right_slot = _stack_mem_disp_size_8616(body[12], add_right_ops[0]) if len(add_right_ops) == 2 else None
    if (
        str(getattr(body[12], "mnemonic", "")).lower() != "add"
        or add_right_slot is None
        or int(add_right_slot[0]) != int(total_disp)
        or _reg_name_from_operand_8616(body[12], add_right_ops[1]) != "ax"
    ):
        stats["failure_count"] += 1
        return False
    if _resolve_one_hop_jmp_target_8616(project, _jcc._branch_target_imm_8616(body[13])) != inc_addr:
        stats["failure_count"] += 1
        return False
    return True


def _pair_accum_exprs_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, i_disp: int
) -> tuple[StructuredAstValue, StructuredAstValue, StructuredAstValue] | None:
    pairs_expr = _ensure_pointer_stack_arg_expr_8616(
        project,
        codegen,
        4,
        pointee_size=2,
        fallback_name="pairs",
    ) or _stack_expr_8616(codegen, 4, 2)
    count_expr = _ensure_typed_stack_arg_expr_8616(
        project,
        codegen,
        6,
        _word_type_for_project_8616(project),
        fallback_name="count",
    ) or _stack_expr_8616(codegen, 6, 2)
    i_expr = _named_stack_expr_from_evidence_8616(project, codegen, int(i_disp), 2)
    if any(expr is None for expr in (pairs_expr, count_expr, i_expr)):
        return None
    return pairs_expr, count_expr, i_expr


def _emit_word_pair_accumulation_loop_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    total_expr: StructuredAstValue,
    i_expr: StructuredAstValue,
    pairs_expr: StructuredAstValue,
    count_expr: StructuredAstValue,
) -> None:
    """Emit the recovered pair-accumulation while loop into the function body."""
    word_type = _word_type_for_project_8616(project)
    word_index = _mul_expr_8616(i_expr, _const_short_8616(codegen, 2), codegen)
    next_word_index = _add_expr_8616(word_index, _const_short_8616(codegen, 1), codegen)
    left_word = _indexed_word_pointer_expr_8616(pairs_expr, word_index, codegen, variable_type=word_type)
    right_word = _indexed_word_pointer_expr_8616(pairs_expr, next_word_index, codegen, variable_type=word_type)
    left_twice = _mul_expr_8616(left_word, _const_short_8616(codegen, 2), codegen)
    pair_total = _add_expr_8616(left_twice, right_word, codegen)
    body_node = CStatements(
        statements=[
            CAssignment(
                _clone_c_value_preserving_cvariables_8616(total_expr),
                _add_expr_8616(total_expr, pair_total, codegen),
                codegen=codegen,
            ),
            _inc_assignment_preserving_cvariables_8616(i_expr, codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        statements=[
            CAssignment(
                _clone_c_value_preserving_cvariables_8616(total_expr),
                CConstant(0, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            CAssignment(
                _clone_c_value_preserving_cvariables_8616(i_expr),
                CConstant(0, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            CWhileLoop(
                CBinaryOp(
                    "CmpLT",
                    _clone_c_value_preserving_cvariables_8616(i_expr),
                    _clone_c_value_preserving_cvariables_8616(count_expr),
                    codegen=codegen,
                ),
                body_node,
                codegen=codegen,
            ),
            CReturn(_clone_c_value_preserving_cvariables_8616(total_expr), codegen=codegen),
        ],
        codegen=codegen,
    )


def _materialize_word_pair_pointer_accumulation_loop_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    insns: tuple[StructuredAstValue, ...],
    index_by_addr: dict[int, int],
) -> bool:
    """Recover loops that accumulate two adjacent word fields from a pointer array.

    Generic MS C shape:
        total = 0;
        for (i = 0; i < count; ++i) {
            total += words[i * 2] * 2;
            total += words[i * 2 + 1];
        }

    This intentionally materializes a word-pointer view, not a struct.  Struct
    naming remains a later typed-object recovery problem.
    """
    stats = {
        "raw_fact_count": 0,
        "classified_fact_count": 0,
        "materialized_count": 0,
        "failure_count": 0,
    }
    codegen._inertia_word_pair_pointer_accumulation_stats_8616 = stats

    for init_idx in range(len(insns) - 18):
        total_disp = _match_stack_zero_init_8616(insns[init_idx])
        i_disp = _match_stack_zero_init_8616(insns[init_idx + 1])
        if total_disp is None or i_disp is None or total_disp >= 0 or i_disp >= 0 or total_disp == i_disp:
            continue
        stats["raw_fact_count"] += 1

        match = _pair_accum_header_match_8616(project, insns, index_by_addr, init_idx, i_disp, stats)
        if match is None:
            continue
        inc_addr, body_target, exit_target = match

        exit_expr = _branch_target_return_expr_8616(project, codegen, int(exit_target))
        total_expr = _named_stack_expr_from_evidence_8616(project, codegen, int(total_disp), 2)
        if (
            exit_expr is None
            or total_expr is None
            or _expr_fingerprint(exit_expr, project) != _expr_fingerprint(total_expr, project)
        ):
            stats["failure_count"] += 1
            continue

        body = _block_insns_8616(project, int(body_target))
        if not _pair_accum_body_match_8616(project, body, i_disp, total_disp, inc_addr, stats):
            continue

        exprs = _pair_accum_exprs_8616(project, codegen, i_disp)
        if exprs is None:
            stats["failure_count"] += 1
            continue
        pairs_expr, count_expr, i_expr = exprs

        stats["classified_fact_count"] += 1
        _emit_word_pair_accumulation_loop_8616(project, codegen, total_expr, i_expr, pairs_expr, count_expr)
        stats["materialized_count"] += 1
        codegen._inertia_pointer_memory_materialized_8616 = "word_pair_accumulation_loop"
        _mark_codegen_signature_authoritative_8616(project, codegen, "word_pair_pointer_accumulation_loop")
        return True
    return False



def _first_gt_loop_body_match_8616(
    project: StructuredAstValue,
    insns: tuple[StructuredAstValue, ...],
    index_by_addr: dict[int, int],
    i_disp: int,
    cond_addr: int,
    body_target: int,
    stats: dict[str, int],
) -> int | None:
    """Match the loop body window; returns return_i_target or None."""
    body = _block_insns_8616(project, int(body_target))
    if len(body) < 6:
        stats["failure_count"] += 1
        return None
    if not (
        _match_stack_mov_to_reg_8616(body[0], "bx", i_disp)
        and _match_reg_shl1_8616(body[1], "bx")
        and _match_stack_mov_to_reg_8616(body[2], "si", 4)
        and _match_stack_mov_to_reg_8616(body[3], "ax", 8)
        and _match_cmp_indexed_reg_8616(body[4], base_reg="bx", index_reg="si", rhs_reg="ax", size=2)
    ):
        stats["failure_count"] += 1
        return None
    value_jcc = body[5]
    if str(getattr(value_jcc, "mnemonic", "")).lower() not in {"jg", "jnle"}:
        stats["failure_count"] += 1
        return None
    return_i_target = _jcc._branch_target_imm_8616(value_jcc)
    inc_target = _resolve_one_hop_jmp_target_8616(
        project,
        _next_linear_jmp_target_8616(insns, index_by_addr.get(int(getattr(value_jcc, "address", -1)), -1)),
    )
    if return_i_target is None or inc_target is None:
        stats["failure_count"] += 1
        return None

    inc_block = _block_insns_8616(project, int(inc_target))
    if len(inc_block) < 2 or not _match_stack_inc_8616(inc_block[0], i_disp):
        stats["failure_count"] += 1
        return None
    if _resolve_one_hop_jmp_target_8616(project, _jcc._branch_target_imm_8616(inc_block[1])) != cond_addr:
        stats["failure_count"] += 1
        return None
    return int(return_i_target)


def _first_gt_loop_window_match_8616(
    project: StructuredAstValue,
    insns: tuple[StructuredAstValue, ...],
    index_by_addr: dict[int, int],
    init_idx: int,
    i_disp: int,
    stats: dict[str, int],
) -> tuple[int, int, int] | None:
    """Match the first-greater-than loop window; returns (cond_addr, exit_target, return_i_target)."""
    cond_addr = int(getattr(insns[init_idx + 1], "address", -1))
    if not _match_stack_mov_to_reg_8616(insns[init_idx + 1], "ax", i_disp):
        stats["failure_count"] += 1
        return None
    if not _match_cmp_stack_ax_8616(insns[init_idx + 2], 6):
        stats["failure_count"] += 1
        return None
    count_jcc = insns[init_idx + 3]
    if str(getattr(count_jcc, "mnemonic", "")).lower() not in {"jg", "jnle"}:
        stats["failure_count"] += 1
        return None
    body_target = _jcc._branch_target_imm_8616(count_jcc)
    exit_target = _resolve_one_hop_jmp_target_8616(
        project,
        _next_linear_jmp_target_8616(insns, index_by_addr.get(int(getattr(count_jcc, "address", -1)), -1)),
    )
    if body_target is None or exit_target is None:
        stats["failure_count"] += 1
        return None

    return_i_target = _first_gt_loop_body_match_8616(
        project, insns, index_by_addr, i_disp, cond_addr, body_target, stats
    )
    if return_i_target is None:
        return None
    return cond_addr, int(exit_target), return_i_target


def _first_gt_loop_exprs_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    i_disp: int,
    signed_word: StructuredAstValue,
) -> tuple[StructuredAstValue, StructuredAstValue, StructuredAstValue, StructuredAstValue] | None:
    """Resolve the loop's C expressions from stack evidence, or None."""
    i_expr = _named_stack_expr_from_evidence_8616(project, codegen, int(i_disp), 2)
    values_expr = _ensure_typed_stack_arg_expr_8616(
        project,
        codegen,
        4,
        _pointer_type_for_project_8616(project, 2, signed=True),
        fallback_name="values",
    ) or _stack_expr_8616(codegen, 4, 2)
    count_expr = _ensure_typed_stack_arg_expr_8616(
        project, codegen, 6, signed_word, fallback_name="count"
    ) or _stack_expr_8616(codegen, 6, 2)
    threshold_expr = _ensure_typed_stack_arg_expr_8616(
        project,
        codegen,
        8,
        signed_word,
        fallback_name="threshold",
    ) or _stack_expr_8616(codegen, 8, 2)
    if any(expr is None for expr in (i_expr, values_expr, count_expr, threshold_expr)):
        return None
    return i_expr, values_expr, count_expr, threshold_expr


def _emit_word_pointer_first_gt_loop_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    i_expr: StructuredAstValue,
    values_expr: StructuredAstValue,
    count_expr: StructuredAstValue,
    threshold_expr: StructuredAstValue,
    signed_word: StructuredAstValue,
    minus_one: StructuredAstValue,
) -> None:
    """Emit the recovered first-greater-than while loop into the function body."""
    indexed_value = _indexed_word_pointer_expr_8616(values_expr, i_expr, codegen, variable_type=signed_word)
    if_body = CStatements(
        statements=[CReturn(_clone_c_value_preserving_cvariables_8616(i_expr), codegen=codegen)],
        codegen=codegen,
    )
    loop_body = CStatements(
        statements=[
            CIfElse(
                [
                    (
                        CBinaryOp(
                            "CmpGT",
                            _clone_c_value_preserving_cvariables_8616(indexed_value),
                            _clone_c_value_preserving_cvariables_8616(threshold_expr),
                            codegen=codegen,
                        ),
                        if_body,
                    )
                ],
                else_node=None,
                cstyle_ifs=True,
                codegen=codegen,
            ),
            _inc_assignment_preserving_cvariables_8616(i_expr, codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        statements=[
            CAssignment(
                _clone_c_value_preserving_cvariables_8616(i_expr),
                CConstant(0, signed_word, codegen=codegen),
                codegen=codegen,
            ),
            CWhileLoop(
                CBinaryOp(
                    "CmpLT",
                    _clone_c_value_preserving_cvariables_8616(i_expr),
                    _clone_c_value_preserving_cvariables_8616(count_expr),
                    codegen=codegen,
                ),
                loop_body,
                codegen=codegen,
            ),
            CReturn(minus_one, codegen=codegen),
        ],
        codegen=codegen,
    )


def _materialize_word_pointer_first_gt_loop_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    insns: tuple[StructuredAstValue, ...],
    index_by_addr: dict[int, int],
) -> bool:
    """Recover signed word-pointer first-greater-than search loops."""
    stats = {
        "raw_fact_count": 0,
        "classified_fact_count": 0,
        "materialized_count": 0,
        "failure_count": 0,
    }
    codegen._inertia_word_pointer_first_gt_stats_8616 = stats

    signed_word = _signed_word_type_for_project_8616(project)
    for init_idx in range(len(insns) - 6):
        i_disp = _match_stack_zero_init_8616(insns[init_idx])
        if i_disp is None or i_disp >= 0:
            continue
        stats["raw_fact_count"] += 1
        match = _first_gt_loop_window_match_8616(project, insns, index_by_addr, init_idx, i_disp, stats)
        if match is None:
            continue
        _cond_addr, exit_target, return_i_target = match

        exprs = _first_gt_loop_exprs_8616(project, codegen, i_disp, signed_word)
        if exprs is None:
            stats["failure_count"] += 1
            continue
        i_expr, values_expr, count_expr, threshold_expr = exprs
        if isinstance(i_expr, CVariable):
            i_expr.variable_type = signed_word
            _install_canonical_stack_cvar_8616(codegen.cfunc, i_expr, signed_word)

        return_i_expr = _branch_target_return_expr_8616(project, codegen, int(return_i_target))
        return_minus_one_expr = _branch_target_return_expr_8616(project, codegen, int(exit_target))
        if return_i_expr is None or _expr_fingerprint(return_i_expr, project) != _expr_fingerprint(i_expr, project):
            stats["failure_count"] += 1
            continue
        minus_one = CConstant(-1, signed_word, codegen=codegen)
        if return_minus_one_expr is None or _expr_fingerprint(return_minus_one_expr, project) != _expr_fingerprint(
            minus_one, project
        ):
            stats["failure_count"] += 1
            continue

        stats["classified_fact_count"] += 1
        _emit_word_pointer_first_gt_loop_8616(
            project, codegen, i_expr, values_expr, count_expr, threshold_expr, signed_word, minus_one
        )
        _set_codegen_return_type_8616(project, codegen, signed_word)
        stats["materialized_count"] += 1
        codegen._inertia_pointer_memory_materialized_8616 = "word_pointer_first_gt_loop"
        _mark_codegen_signature_authoritative_8616(project, codegen, "word_pointer_first_gt_loop")
        return True
    return False



def _rotate3_match_or_fail_8616(stats: dict[str, int], matched: bool) -> int | None:
    """Shared rotate3 window gate: record a failure and return None when unmatched."""
    if not matched:
        stats["failure_count"] += 1
    return None


def _word_pointer_rotate3_tmp_disp_8616(
    insns: tuple[StructuredAstValue, ...], idx: int, stats: dict[str, int]
) -> int | None:
    """Match the 14-instruction rotate3 window; returns the tmp slot disp or None."""
    tmp_ops = _boundary_tuple_8616(getattr(insns[idx + 2], "operands", ()) or ())
    tmp_slot = _stack_mem_disp_size_8616(insns[idx + 2], tmp_ops[0]) if len(tmp_ops) == 2 else None
    if str(getattr(insns[idx + 2], "mnemonic", "")).lower() != "mov" or tmp_slot is None:
        return _rotate3_match_or_fail_8616(stats, False)
    tmp_disp = int(tmp_slot[0])
    if tmp_disp >= 0 or _reg_name_from_operand_8616(insns[idx + 2], tmp_ops[1]) != "ax":
        return _rotate3_match_or_fail_8616(stats, False)
    if not (
        _match_stack_mov_to_reg_8616(insns[idx + 3], "bx", 4)
        and _match_reg_indirect_load_8616(insns[idx + 4], dst_reg="ax", base_reg="bx", size=2, disp=2)
        and _match_stack_mov_to_reg_8616(insns[idx + 5], "bx", 4)
        and _match_reg_indirect_store_8616(insns[idx + 6], base_reg="bx", src_reg="ax", size=2)
        and _match_stack_mov_to_reg_8616(insns[idx + 7], "bx", 4)
        and _match_reg_indirect_load_8616(insns[idx + 8], dst_reg="ax", base_reg="bx", size=2, disp=4)
        and _match_stack_mov_to_reg_8616(insns[idx + 9], "bx", 4)
        and _match_reg_indirect_store_8616(insns[idx + 10], base_reg="bx", src_reg="ax", size=2, disp=2)
        and _match_stack_mov_to_reg_8616(insns[idx + 11], "ax", tmp_disp)
        and _match_stack_mov_to_reg_8616(insns[idx + 12], "bx", 4)
        and _match_reg_indirect_store_8616(insns[idx + 13], base_reg="bx", src_reg="ax", size=2, disp=4)
    ):
        return _rotate3_match_or_fail_8616(stats, False)
    return tmp_disp


def _emit_word_pointer_rotate3_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    values_expr: StructuredAstValue,
    tmp_expr: StructuredAstValue,
) -> None:
    """Emit the rotate3 assignment chain into the function body."""
    word_type = _word_type_for_project_8616(project)
    value_0 = _indexed_word_pointer_expr_8616(
        values_expr, _const_short_8616(codegen, 0), codegen, variable_type=word_type
    )
    value_1 = _indexed_word_pointer_expr_8616(
        values_expr, _const_short_8616(codegen, 1), codegen, variable_type=word_type
    )
    value_2 = _indexed_word_pointer_expr_8616(
        values_expr, _const_short_8616(codegen, 2), codegen, variable_type=word_type
    )
    codegen.cfunc.statements = CStatements(
        statements=[
            CAssignment(
                _clone_c_value_preserving_cvariables_8616(tmp_expr),
                _clone_c_value_preserving_cvariables_8616(value_0),
                codegen=codegen,
            ),
            CAssignment(
                _clone_c_value_preserving_cvariables_8616(value_0),
                _clone_c_value_preserving_cvariables_8616(value_1),
                codegen=codegen,
            ),
            CAssignment(
                _clone_c_value_preserving_cvariables_8616(value_1),
                _clone_c_value_preserving_cvariables_8616(value_2),
                codegen=codegen,
            ),
            CAssignment(
                _clone_c_value_preserving_cvariables_8616(value_2),
                _clone_c_value_preserving_cvariables_8616(tmp_expr),
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )


def _materialize_word_pointer_rotate3_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    insns: tuple[StructuredAstValue, ...],
    _index_by_addr: dict[int, int],
) -> bool:
    stats = {
        "raw_fact_count": 0,
        "classified_fact_count": 0,
        "materialized_count": 0,
        "failure_count": 0,
    }
    codegen._inertia_word_pointer_rotate3_stats_8616 = stats

    for idx in range(max(0, len(insns) - 13)):
        if not _match_stack_mov_to_reg_8616(insns[idx], "bx", 4):
            continue
        stats["raw_fact_count"] += 1
        if not _match_reg_indirect_load_8616(insns[idx + 1], dst_reg="ax", base_reg="bx", size=2):
            stats["failure_count"] += 1
            continue
        tmp_disp = _word_pointer_rotate3_tmp_disp_8616(insns, idx, stats)
        if tmp_disp is None:
            continue

        values_expr = _ensure_pointer_stack_arg_expr_8616(
            project,
            codegen,
            4,
            pointee_size=2,
            fallback_name="values",
        ) or _stack_expr_8616(codegen, 4, 2)
        tmp_expr = _named_stack_expr_from_evidence_8616(project, codegen, int(tmp_disp), 2)
        if any(expr is None for expr in (values_expr, tmp_expr)):
            stats["failure_count"] += 1
            continue

        stats["classified_fact_count"] += 1
        _emit_word_pointer_rotate3_8616(project, codegen, values_expr, tmp_expr)
        _set_codegen_return_type_8616(project, codegen, _void_type_for_project_8616(project))
        stats["materialized_count"] += 1
        codegen._inertia_pointer_memory_materialized_8616 = "word_pointer_rotate3"
        _mark_codegen_signature_authoritative_8616(project, codegen, "word_pointer_rotate3")
        return True
    return False



def _pointer_swap_pattern_tmp_disp_8616(insns: tuple[StructuredAstValue, ...], idx: int) -> int | None:
    """Match the 10-instruction pointer-swap window; returns the tmp slot disp or None."""
    if not _match_stack_mov_to_reg_8616(insns[idx], "bx", 4):
        return None
    if not _match_reg_indirect_load_8616(insns[idx + 1], dst_reg="ax", base_reg="bx", size=2):
        return None
    tmp_slot = _stack_mem_disp_size_8616(
        insns[idx + 2], _boundary_tuple_8616(getattr(insns[idx + 2], "operands", ()) or ())[0]
    )
    if str(getattr(insns[idx + 2], "mnemonic", "")).lower() != "mov" or tmp_slot is None:
        return None
    tmp_disp = int(tmp_slot[0])
    if tmp_disp >= 0:
        return None
    if not (
        _match_stack_mov_to_reg_8616(insns[idx + 3], "bx", 6)
        and _match_reg_indirect_load_8616(insns[idx + 4], dst_reg="ax", base_reg="bx", size=2)
        and _match_stack_mov_to_reg_8616(insns[idx + 5], "bx", 4)
        and _match_reg_indirect_store_8616(insns[idx + 6], base_reg="bx", src_reg="ax", size=2)
        and _match_stack_mov_to_reg_8616(insns[idx + 7], "ax", tmp_disp)
        and _match_stack_mov_to_reg_8616(insns[idx + 8], "bx", 6)
        and _match_reg_indirect_store_8616(insns[idx + 9], base_reg="bx", src_reg="ax", size=2)
    ):
        return None
    return tmp_disp


def _pointer_swap_exprs_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, tmp_disp: int
) -> tuple[StructuredAstValue, StructuredAstValue, StructuredAstValue] | None:
    left_expr = _ensure_pointer_stack_arg_expr_8616(
        project,
        codegen,
        4,
        pointee_size=2,
        fallback_name="left",
    ) or _stack_expr_8616(codegen, 4, 2)
    right_expr = _ensure_pointer_stack_arg_expr_8616(
        project,
        codegen,
        6,
        pointee_size=2,
        fallback_name="right",
    ) or _stack_expr_8616(codegen, 6, 2)
    tmp_expr = _named_stack_expr_from_evidence_8616(project, codegen, int(tmp_disp), 2)
    if any(expr is None for expr in (left_expr, right_expr, tmp_expr)):
        return None
    return left_expr, right_expr, tmp_expr


def _materialize_pointer_swap_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    insns: tuple[StructuredAstValue, ...],
    _index_by_addr: dict[int, int],
    *,
    splice_pointer_swap: Callable[
        [object, CVariable, CVariable, CVariable, frozenset[int], frozenset[int]],
        bool,
    ]
    | None = None,
) -> bool:
    debug_pointer_memory = os.environ.get("INERTIA_DEBUG_POINTER_MEMORY_IDIOMS") == "1"
    for idx in range(max(0, len(insns) - 9)):
        tmp_disp = _pointer_swap_pattern_tmp_disp_8616(insns, idx)
        if tmp_disp is None:
            continue
        exprs = _pointer_swap_exprs_8616(project, codegen, tmp_disp)
        if exprs is None:
            continue
        left_expr, right_expr, tmp_expr = exprs
        if debug_pointer_memory:
            logging.getLogger(__name__).warning(
                "[pointer-memory] materialize pointer_swap function=%#x idx=%d tmp=%r left=%r right=%r",
                getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
                idx,
                tmp_disp,
                getattr(getattr(left_expr, "variable", None), "name", None),
                getattr(getattr(right_expr, "variable", None), "name", None),
            )
        if splice_pointer_swap is None or not all(
            isinstance(expr, CVariable) for expr in (left_expr, right_expr, tmp_expr)
        ):
            continue
        proven_ins_addrs = _codegen_instruction_window_addrs_8616(codegen, insns, idx, idx + 10)
        required_write_ins_addrs = frozenset(
            {
                *_codegen_instruction_window_addrs_8616(codegen, insns, idx + 6, idx + 7),
                *_codegen_instruction_window_addrs_8616(codegen, insns, idx + 9, idx + 10),
            }
        )
        if not splice_pointer_swap(
            codegen,
            left_expr,
            right_expr,
            tmp_expr,
            proven_ins_addrs,
            required_write_ins_addrs,
        ):
            if debug_pointer_memory:
                logging.getLogger(__name__).warning(
                    "[pointer-memory] pointer_swap splice refused function=%#x stats=%r",
                    getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
                    getattr(codegen, "_inertia_pointer_swap_splice_stats_8616", None),
                )
            continue
        if debug_pointer_memory:
            logging.getLogger(__name__).warning(
                "[pointer-memory] pointer_swap splice materialized function=%#x stats=%r",
                getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
                getattr(codegen, "_inertia_pointer_swap_splice_stats_8616", None),
            )
        typed_codegen = cast(Any, codegen)
        current_return_type = typed_codegen.cfunc.functy.returnty
        if current_return_type is None:
            current_return_type = _word_type_for_project_8616(project)
        _set_codegen_return_type_8616(project, codegen, current_return_type)
        codegen._inertia_pointer_memory_materialized_8616 = "pointer_swap"
        _mark_codegen_signature_authoritative_8616(project, codegen, "pointer_swap_args")
        return True
    return False



def _codegen_instruction_window_addrs_8616(
    codegen: StructuredAstValue,
    insns: tuple[StructuredAstValue, ...],
    start: int,
    stop: int,
) -> frozenset[int]:
    """Map decoded instruction addresses into the codegen function address space."""
    if not insns:
        return frozenset()
    decoded_base = int(cast(Any, insns[0]).address)
    codegen_base = int(cast(Any, codegen).cfunc.addr)
    return frozenset(
        codegen_base + int(cast(Any, insn).address) - decoded_base for insn in insns[start:stop]
    )


def _materialize_pointer_memory_idioms_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:
    """Recover near-pointer C memory idioms from instruction and stack-slot evidence."""
    debug_pointer_memory = os.environ.get("INERTIA_DEBUG_POINTER_MEMORY_IDIOMS") == "1"
    insns = _linear_function_insns_for_codegen_8616(project, codegen)
    if debug_pointer_memory:
        logging.getLogger(__name__).warning(
            "[pointer-memory] enter function=%#x codegen=%#x marker=%r insns=%d",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            id(codegen),
            getattr(codegen, "_inertia_pointer_memory_materialized_8616", None),
            len(insns) if insns else 0,
        )
    if not insns:
        return False
    index_by_addr = {int(getattr(insn, "address", -1)): idx for idx, insn in enumerate(insns)}
    changed = (
        _materialize_word_pair_pointer_accumulation_loop_8616(project, codegen, insns, index_by_addr)
        or _materialize_word_pointer_first_gt_loop_8616(project, codegen, insns, index_by_addr)
        or _materialize_word_pointer_rotate3_8616(project, codegen, insns, index_by_addr)
        or _materialize_pointer_swap_8616(project, codegen, insns, index_by_addr)
    )
    if debug_pointer_memory:
        logging.getLogger(__name__).warning(
            "[pointer-memory] exit function=%#x codegen=%#x changed=%s marker=%r",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            id(codegen),
            changed,
            getattr(codegen, "_inertia_pointer_memory_materialized_8616", None),
        )
    return changed


def _materialize_pointer_memory_idioms_postprocess_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Compatibility fallback for lowering-owned pointer-memory idiom materialization."""
    # Dynamic boundary: legacy angr codegen only has this flag after structuring semantic priming runs.
    if getattr(codegen, "_inertia_pointer_memory_idiom_lowering_pass_ran_8616", False):
        return False
    return _materialize_pointer_memory_idioms_8616(project, codegen)


def _ordered_32bit_conditional_return_pairs_from_cfg_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> list[tuple[StructuredAstValue, int]]:
    """Compatibility shim for structuring-owned 32-bit condition/value ordering."""

    def _function_block_addrs(local_project: StructuredAstValue, local_codegen: StructuredAstValue) -> tuple[int, ...]:
        """Read function block addresses from dynamic angr/codegen compatibility state."""
        # Dynamic angr/codegen compatibility boundary: cfunc is attached by structured codegen.
        cfunc = getattr(local_codegen, "cfunc", None)
        # Dynamic angr C function compatibility boundary: addr is optional in synthetic tests.
        func_addr = getattr(cfunc, "addr", None)
        if not isinstance(func_addr, int):
            return ()
        try:
            # Dynamic angr knowledge-base compatibility boundary.
            function = local_project.kb.functions.function(addr=func_addr, create=False)
        except Exception:
            return ()
        if function is None:
            return ()
        # Dynamic angr Function compatibility boundary: block address sets are optional.
        return _boundary_tuple_8616(sorted(int(addr) for addr in getattr(function, "block_addrs_set", set()) or ()))

    def _load_block(addr: int) -> StructuredAstValue | None:
        """Load a dynamic angr block for structuring-owned 32-bit condition proof."""
        try:
            return project.factory.block(int(addr), opt_level=0)
        except Exception:
            return None

    return require_result_type_8616(
        _structuring_ordered_32bit_conditional_return_pairs_from_cfg_8616(
            project,
            codegen,
            Return32BitConditionalPairCallbacks8616(
                function_block_addrs=_function_block_addrs,
                load_block=_load_block,
                branch_target_imm=_jcc._branch_target_imm_8616,
                next_unconditional_target_after_jcc=lambda block, block_addr, jcc_addr: (
                    _structuring_next_unconditional_target_after_jcc_8616(
                        block,
                        int(jcc_addr),
                        _load_block,
                        _jcc._branch_target_imm_8616,
                    )
                ),
                branch_target_return_value=_branch_target_return_value_8616,
                translate_cmp_jcc_guard=_jcc._translate_cmp_jcc_guard_8616,
                decoded_condition_expr=_decoded_cmp_condition_expr_8616,
                expr_fingerprint=_expr_fingerprint,
            ),
        ),
        list,
        owner="structuring.return_chains.ordered_32bit_conditional_return_pairs_from_cfg_8616",
    )


def _first_stack_zero_init_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> int | None:
    for insn in _jcc._function_insns_for_codegen_8616(project, codegen):
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
        if mnemonic != "mov" or len(operands) != 2:
            continue
        if int(getattr(operands[0], "type", -1)) != 3 or int(getattr(operands[1], "type", -1)) != 2:
            continue
        mem = operands[0].mem
        if not mem.base or str(insn.reg_name(mem.base)).lower() != "bp":
            continue
        if int(getattr(operands[1], "imm", 0) or 0) == 0:
            return _signed_i16_immediate_8616(int(mem.disp))
    return None


def _or_stack_update_imm_8616(
    project: StructuredAstValue, target_addr: int, slot_offset: int, *, _depth: int = 0
) -> int | None:
    if _depth > 2:
        return None
    try:
        block = project.factory.block(int(target_addr), opt_level=0)
    except Exception:
        return None
    for insn in _boundary_tuple_8616(getattr(getattr(block, "capstone", None), "insns", ()) or ()):
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
        if mnemonic in {"jmp", "ljmp"}:
            next_target = _jcc._branch_target_imm_8616(insn)
            if next_target is None:
                return None
            return _or_stack_update_imm_8616(project, next_target, slot_offset, _depth=_depth + 1)
        if mnemonic == "or" and len(operands) == 2 and int(getattr(operands[0], "type", -1)) == 3:
            mem = operands[0].mem
            if (
                mem.base
                and str(insn.reg_name(mem.base)).lower() == "bp"
                and _signed_i16_immediate_8616(int(mem.disp)) == int(slot_offset)
            ) and int(getattr(operands[1], "type", -1)) == 2:
                return int(getattr(operands[1], "imm", 0) or 0)
        if mnemonic in {"ret", "retf", "iret"}:
            return None
    return None


def _last_ax_stack_load_offset_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> int | None:
    result = None
    for insn in _jcc._function_insns_for_codegen_8616(project, codegen):
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
        if mnemonic != "mov" or len(operands) != 2:
            continue
        if int(getattr(operands[0], "type", -1)) != 1 or int(getattr(operands[1], "type", -1)) != 3:
            continue
        if str(insn.reg_name(operands[0].reg)).lower() != "ax":
            continue
        mem = operands[1].mem
        if mem.base and str(insn.reg_name(mem.base)).lower() == "bp":
            result = _signed_i16_immediate_8616(int(mem.disp))
    return result


def _has_ax_stack_load_offset_8616(project: StructuredAstValue, codegen: StructuredAstValue, slot_offset: int) -> bool:
    for insn in _jcc._function_insns_for_codegen_8616(project, codegen):
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
        if mnemonic != "mov" or len(operands) != 2:
            continue
        if int(getattr(operands[0], "type", -1)) != 1 or int(getattr(operands[1], "type", -1)) != 3:
            continue
        if str(insn.reg_name(operands[0].reg)).lower() != "ax":
            continue
        mem = operands[1].mem
        if (
            mem.base
            and str(insn.reg_name(mem.base)).lower() == "bp"
            and _signed_i16_immediate_8616(int(mem.disp)) == int(slot_offset)
        ):
            return True
    return False


def _ordered_32bit_mask_update_pairs_from_cfg_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, slot_offset: int
) -> list[tuple[StructuredAstValue, int]]:
    """Compatibility shim for structuring-owned mask-accumulator pair ordering."""
    # Dynamic angr/codegen compatibility boundary: cfunc is attached by structured codegen.
    cfunc = getattr(codegen, "cfunc", None)
    # Dynamic angr C function compatibility boundary: addr is optional in synthetic tests.
    func_addr = getattr(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        return []
    return require_result_type_8616(
        _structuring_ordered_32bit_mask_update_pairs_from_cfg_8616(
            project,
            codegen,
            int(slot_offset),
            MaskAccumulatorPairCallbacks8616(
                linear_jcc_block_starts=_linear_jcc_block_starts_8616,
                selector_targets_from_32bit_jcc_chain=lambda block_addr, insn: _selector_targets_from_32bit_jcc_chain_8616(
                    project,
                    int(block_addr),
                    insn,
                ),
                equality_return_target_from_32bit_jcc_chain=lambda block_addr, insn: (
                    _equality_return_target_from_32bit_jcc_chain_8616(
                        project,
                        int(block_addr),
                        insn,
                    )
                ),
                inequality_target_from_32bit_jcc_chain=lambda block_addr, insn: (
                    _inequality_target_from_32bit_jcc_chain_8616(
                        project,
                        int(block_addr),
                        insn,
                    )
                ),
                branch_target_imm=_jcc._branch_target_imm_8616,
                next_unconditional_target_after_jcc=_next_unconditional_target_after_jcc_8616,
                or_stack_update_imm=_or_stack_update_imm_8616,
                translate_cmp_jcc_guard=_jcc._translate_cmp_jcc_guard_8616,
                decoded_condition_expr=_decoded_cmp_condition_expr_8616,
                expr_fingerprint=_expr_fingerprint,
            ),
        ),
        list,
        owner="structuring.return_chains.ordered_32bit_mask_update_pairs_from_cfg_8616",
    )


def _materialize_cfg_mask_accumulator_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:
    """Compatibility shim for structuring-owned mask-accumulator materialization."""
    # Dynamic angr/codegen compatibility boundary: structuring owner flags are attached during staged codegen.
    ensure_return_chain_codegen_state_8616(codegen)
    if getattr(codegen, "_inertia_cfg_mask_accumulator_structuring_pass_ran_8616", False):
        return False
    # Dynamic angr/codegen compatibility boundary: cfunc is attached by structured codegen.
    if getattr(codegen, "cfunc", None) is None:
        return False
    debug = os.environ.get("INERTIA_DEBUG_RETURN_BRANCH")
    materialized = require_result_type_8616(
        _structuring_materialize_cfg_mask_accumulator_8616(
            project,
            codegen,
            MaskAccumulatorMaterializationCallbacks8616(
                first_stack_zero_init=_first_stack_zero_init_8616,
                ordered_mask_update_pairs=_ordered_32bit_mask_update_pairs_from_cfg_8616,
                stack_slot_expr=_jcc._stack_slot_expr_8616,
                expr_fingerprint=_expr_fingerprint,
            ),
        ),
        bool,
        owner="structuring.return_chains.materialize_cfg_mask_accumulator_8616",
    )
    if debug and materialized:
        logging.getLogger(__name__).warning(
            "[cfg-mask-accum] materialized imms=%r",
            tuple(codegen._inertia_mask_accumulator_update_immediates_8616),
        )
    return materialized


def _return_selector_callbacks_8616(
    *,
    branch_target_return_expr: Callable[
        [StructuredAstValue, StructuredAstValue, int], StructuredAstValue | None
    ] = _branch_target_return_expr_8616,
) -> ReturnSelectorCallbacks8616:
    """Build dynamic adapters from legacy postprocess selector-return proof providers."""
    ordered_32bit_pairs: Callable[
        [StructuredAstValue, StructuredAstValue],
        list[tuple[StructuredAstValue, StructuredAstValue, StructuredAstValue]],
    ]
    ordered_conditional_pairs: Callable[
        [StructuredAstValue, StructuredAstValue],
        list[tuple[StructuredAstValue, StructuredAstValue, StructuredAstValue]],
    ]
    if branch_target_return_expr is _branch_target_return_expr_8616:
        ordered_32bit_pairs = _ordered_32bit_selector_return_expr_pairs_from_cfg_8616
        ordered_conditional_pairs = _ordered_conditional_return_expr_pairs_from_cfg_8616
    else:
        def _injected_ordered_32bit_pairs(
            project: StructuredAstValue,
            codegen: StructuredAstValue,
        ) -> list[tuple[StructuredAstValue, StructuredAstValue, StructuredAstValue]]:
            """Bind the Structuring-owned branch-expression provider."""
            return _ordered_32bit_selector_return_expr_pairs_from_cfg_8616(
                project,
                codegen,
                branch_target_return_expr=branch_target_return_expr,
            )

        def _injected_ordered_conditional_pairs(
            project: StructuredAstValue,
            codegen: StructuredAstValue,
        ) -> list[tuple[StructuredAstValue, StructuredAstValue, StructuredAstValue]]:
            """Bind the Structuring-owned branch-expression provider."""
            return _ordered_conditional_return_expr_pairs_from_cfg_8616(
                project,
                codegen,
                branch_target_return_expr=branch_target_return_expr,
            )

        ordered_32bit_pairs = _injected_ordered_32bit_pairs
        ordered_conditional_pairs = _injected_ordered_conditional_pairs
    return ReturnSelectorCallbacks8616(
        materialize_decrement_switch_return_chain=_materialize_decrement_switch_return_chain_8616,
        ordered_32bit_selector_return_expr_pairs=ordered_32bit_pairs,
        ordered_conditional_return_expr_pairs=ordered_conditional_pairs,
        selector_condition_call_addrs=_selector_condition_call_addrs_8616,
        selector_condition_call_addrs_from_cfg=_selector_condition_call_addrs_from_cfg_8616,
        selector_function_has_unsafe_effects=lambda project, codegen, allowed: (
            _selector_function_has_unsafe_effects_8616(
                project,
                codegen,
                allowed_call_addrs=allowed,
            )
        ),
        clone_c_value_for_codegen_tree=_clone_c_value_for_codegen_tree_8616,
        set_cfunc_statements_root=_set_cfunc_statements_root_8616,
        expr_fingerprint=_expr_fingerprint,
    )


def _materialize_cfg_selector_return_branches_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    *,
    branch_target_return_expr: Callable[
        [StructuredAstValue, StructuredAstValue, int], StructuredAstValue | None
    ] = _branch_target_return_expr_8616,
) -> bool:
    """Compatibility shim for structuring-owned CFG selector-return materialization."""
    ensure_return_chain_codegen_state_8616(codegen)
    return require_result_type_8616(
        _structuring_materialize_cfg_selector_return_branches_8616(
            project,
            codegen,
            _return_selector_callbacks_8616(
                branch_target_return_expr=branch_target_return_expr,
            ),
        ),
        bool,
        owner="structuring.return_chains.materialize_cfg_selector_return_branches_8616",
    )


def _materialize_cfg_selector_return_branches_pass_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Compatibility fallback for structuring-owned CFG selector-return materialization."""
    # Dynamic boundary: legacy angr codegen only has this flag after the structuring wrapper runs.
    if getattr(codegen, "_inertia_selector_return_structuring_pass_ran_8616", False):
        return False
    return _materialize_cfg_selector_return_branches_8616(project, codegen)


def _last_ax_return_value_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> int | None:
    """Compatibility shim for structuring-owned terminal AX return-value proof."""
    return require_optional_result_type_8616(
        _structuring_last_ax_return_value_8616(
            project,
            codegen,
            LastAxReturnValueCallbacks8616(
                function_insns=_jcc._function_insns_for_codegen_8616,
                signed_i16_immediate=_signed_i16_immediate_8616,
            ),
        ),
        int,
        owner="structuring.return_chains.last_ax_return_value_8616",
    )


def _return_chain_flatten_callbacks_8616() -> ReturnChainFlattenCallbacks8616:
    """Build dynamic postprocess adapters for structuring-owned return-chain flattening."""
    return ReturnChainFlattenCallbacks8616(
        set_cfunc_statements_root=_set_cfunc_statements_root_8616,
        final_return_value=_last_ax_return_value_8616,
        expr_fingerprint=_expr_fingerprint,
        iter_c_nodes_deep=_iter_c_nodes_deep_8616,
        single_if_return=_single_if_return_8616,
        const_return_value=_const_return_value_8616,
    )


def _record_flattened_return_chain_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    cond_return_pairs: list[tuple[StructuredAstValue, int]],
    final_value: int,
) -> None:
    """Compatibility shim for structuring-owned return-chain evidence records."""
    _structuring_record_flattened_return_chain_8616(
        project,
        codegen,
        cond_return_pairs,
        final_value,
        _return_chain_flatten_callbacks_8616(),
    )


def _root_matches_flattened_return_chain_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    cond_return_pairs: list[tuple[StructuredAstValue, int]],
    final_value: int,
) -> bool:
    """Compatibility shim for structuring-owned return-chain idempotency checks."""
    return require_result_type_8616(
        _structuring_root_matches_flattened_return_chain_8616(
            project,
            codegen,
            cond_return_pairs,
            final_value,
            _return_chain_flatten_callbacks_8616(),
        ),
        bool,
        owner="structuring.return_chains.root_matches_flattened_return_chain_8616",
    )


def _flatten_conditional_return_chain_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    cond_return_pairs: list[tuple[StructuredAstValue, int]],
) -> bool:
    """Compatibility shim for structuring-owned CFG return-chain flattening."""
    return require_result_type_8616(
        _structuring_flatten_conditional_return_chain_8616(
            project,
            codegen,
            cond_return_pairs,
            _return_chain_flatten_callbacks_8616(),
        ),
        bool,
        owner="structuring.return_chains.flatten_conditional_return_chain_8616",
    )


def _node_contains_call_8616(node: StructuredAstValue) -> bool:
    """Compatibility shim for structuring-owned return-chain call-node scans."""
    return require_result_type_8616(
        _structuring_node_contains_call_8616(node, _return_chain_flatten_callbacks_8616()),
        bool,
        owner="structuring.return_chains.node_contains_call_8616",
    )


def _is_register_call_assignment_8616(stmt: StructuredAstValue) -> bool:
    """Compatibility shim for structuring-owned return-chain call-assignment scans."""
    return require_result_type_8616(
        _structuring_is_register_call_assignment_8616(stmt, _return_chain_flatten_callbacks_8616()),
        bool,
        owner="structuring.return_chains.is_register_call_assignment_8616",
    )


def _materialize_cfg_conditional_return_suffix_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    cond_return_pairs: list[tuple[StructuredAstValue, int]],
) -> bool:
    """Compatibility shim for structuring-owned CFG return-chain suffix rebuilds."""
    return require_result_type_8616(
        _structuring_materialize_cfg_conditional_return_suffix_8616(
            project,
            codegen,
            cond_return_pairs,
            _return_chain_flatten_callbacks_8616(),
        ),
        bool,
        owner="structuring.return_chains.materialize_cfg_conditional_return_suffix_8616",
    )


def _return_chain_empty_if_callbacks_8616() -> ReturnChainEmptyIfCallbacks8616:
    """Build dynamic adapters from legacy postprocess proof providers."""
    return ReturnChainEmptyIfCallbacks8616(
        ordered_return_values=_ordered_conditional_return_values_8616,
        selector_function_has_unsafe_effects=lambda project, codegen, allowed: _selector_function_has_unsafe_effects_8616(
            project, codegen, allowed_call_addrs=allowed
        ),
        condition_call_addrs=lambda conditions: _structuring_selector_condition_call_addrs_8616(
            ((condition,) for condition in conditions), _iter_c_nodes_deep_8616
        ),
        condition_branch_return_value=_condition_branch_return_value_8616,
        condition_branch_is_non_branch=lambda project, cond: (
            _condition_branch_tag_evidence_8616(project, cond) is ConditionBranchTagEvidence8616.NON_BRANCH
        ),
        condition_tags=_jcc._condition_tags_8616,
        ordered_return_expr_pairs=_ordered_conditional_return_expr_pairs_from_cfg_8616,
        ordered_return_pairs=_ordered_conditional_return_pairs_from_cfg_8616,
        ordered_32bit_return_pairs=_ordered_32bit_conditional_return_pairs_from_cfg_8616,
        flatten_conditional_return_chain=_flatten_conditional_return_chain_8616,
        materialize_conditional_return_suffix=_materialize_cfg_conditional_return_suffix_8616,
        prune_duplicate_empty_return_guard=_prune_duplicate_empty_return_guard_before_cfg_suffix_8616,
        expr_fingerprint=_expr_fingerprint,
        iter_c_nodes_deep=_iter_c_nodes_deep_8616,
    )


def _materialize_empty_if_return_branches_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:
    """Compatibility shim for structuring-owned empty-if return-chain materialization."""
    ensure_return_chain_codegen_state_8616(codegen)
    return require_result_type_8616(
        _structuring_materialize_empty_if_return_branches_8616(
            project,
            codegen,
            _return_chain_empty_if_callbacks_8616(),
        ),
        bool,
        owner="structuring.return_chains.materialize_empty_if_return_branches_8616",
    )


def _materialize_empty_if_return_branches_pass_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:
    """Compatibility fallback for structuring-owned empty-if return-chain materialization."""
    # Dynamic boundary: legacy angr codegen only has this flag after the structuring wrapper runs.
    if getattr(codegen, "_inertia_return_chains_structuring_pass_ran_8616", False):
        return False
    return _materialize_empty_if_return_branches_8616(project, codegen)


def _single_if_return_8616(
    stmt: StructuredAstValue,
) -> tuple[StructuredAstValue, StructuredAstValue] | None:
    """Compatibility shim for structuring-owned single-if-return proof."""
    return require_optional_result_type_8616(
        _structuring_single_if_return_8616(stmt),
        tuple,
        owner="structuring.return_chains.single_if_return_8616",
    )


def _const_return_value_8616(expr: StructuredAstValue) -> int | None:
    """Compatibility shim for structuring-owned constant-return proof."""
    return require_optional_result_type_8616(
        _structuring_const_return_value_8616(expr),
        int,
        owner="structuring.return_chains.const_return_value_8616",
    )


def _is_empty_return_statement_8616(stmt: StructuredAstValue) -> bool:
    """Compatibility shim for structuring-owned empty-return statement proof."""
    return require_result_type_8616(
        _structuring_is_empty_return_statement_8616(stmt),
        bool,
        owner="structuring.return_chains.is_empty_return_statement_8616",
    )


def _codegen_has_explicit_void_return_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:
    """Compatibility shim for return-compat-owned void return proof."""
    return require_result_type_8616(
        codegen_has_explicit_void_return_8616(project, codegen),
        bool,
        owner="decompiler_return_compat.codegen_has_explicit_void_return_8616",
    )


def _void_tail_call_shape_callbacks_8616() -> VoidTailCallShapeCallbacks8616:
    """Build compatibility callbacks for structuring-owned tail-call shape proof."""
    return VoidTailCallShapeCallbacks8616(c_node_semantically_empty=_c_node_semantically_empty_8616)


def _tail_call_from_statement_8616(stmt: StructuredAstValue) -> CFunctionCall | None:
    """Compatibility shim for structuring-owned tail-call statement proof."""
    return _structuring_tail_call_from_statement_8616(stmt, _void_tail_call_shape_callbacks_8616())


def _flatten_straightline_c_statements_8616(
    stmt: StructuredAstValue,
) -> tuple[StructuredAstValue, ...] | None:
    """Compatibility shim for structuring-owned straight-line C statement proof."""
    return require_optional_result_type_8616(
        _structuring_flatten_straightline_c_statements_8616(stmt, _void_tail_call_shape_callbacks_8616()),
        tuple,
        owner="structuring.return_chains.flatten_straightline_c_statements_8616",
    )


def _tail_call_payload_from_statement_8616(
    stmt: StructuredAstValue, codegen: StructuredAstValue
) -> tuple[CFunctionCall, StructuredAstValue] | None:
    """Compatibility shim for structuring-owned void tail-call payload proof."""
    return require_optional_result_type_8616(
        _structuring_tail_call_payload_from_statement_8616(stmt, codegen, _void_tail_call_shape_callbacks_8616()),
        tuple,
        owner="structuring.return_chains.tail_call_payload_from_statement_8616",
    )


def _void_tail_call_suffix_diamond_callbacks_8616(
    project: StructuredAstValue,
) -> VoidTailCallSuffixDiamondCallbacks8616:
    """Build compatibility callbacks for structuring-owned suffix-diamond repair."""
    return VoidTailCallSuffixDiamondCallbacks8616(
        c_node_semantically_empty=_c_node_semantically_empty_8616,
        calls_in_nodes=lambda nodes: _structuring_calls_in_nodes_8616(nodes, _return_chain_flatten_callbacks_8616()),
        node_component_fingerprints=lambda node: _node_component_fingerprints_8616(project, node),
        call_argument_component_fingerprints=lambda call: _call_argument_component_fingerprints_8616(project, call),
    )


def _condition_identity_keys_8616(
    project: StructuredAstValue, cond: StructuredAstValue
) -> frozenset[StructuredAstValue]:
    """Compatibility shim for structuring-owned condition identity proof keys."""
    return require_result_type_8616(
        _structuring_condition_identity_keys_8616(
            project,
            cond,
            ConditionIdentityCallbacks8616(
                condition_tags=_jcc._condition_tags_8616,
                expr_fingerprint=_expr_fingerprint,
            ),
        ),
        frozenset,
        owner="structuring.return_chains.condition_identity_keys_8616",
    )


def _expression_fingerprint_callbacks_8616() -> ExpressionFingerprintCallbacks8616:
    """Build compatibility callbacks for structuring-owned C AST fingerprints."""
    return ExpressionFingerprintCallbacks8616(
        expr_fingerprint=_expr_fingerprint,
        iter_c_nodes_deep=_iter_c_nodes_deep_8616,
    )


def _call_argument_fingerprints_8616(project: StructuredAstValue, call: CFunctionCall) -> frozenset[str]:
    """Compatibility shim for structuring-owned call argument fingerprints."""
    return require_result_type_8616(
        _structuring_call_argument_fingerprints_8616(project, call, _expression_fingerprint_callbacks_8616()),
        frozenset,
        owner="structuring.return_chains.call_argument_fingerprints_8616",
    )


def _call_argument_component_fingerprints_8616(project: StructuredAstValue, call: CFunctionCall) -> frozenset[str]:
    """Compatibility shim for structuring-owned call argument component fingerprints."""
    return require_result_type_8616(
        _structuring_call_argument_component_fingerprints_8616(
            project,
            call,
            _expression_fingerprint_callbacks_8616(),
        ),
        frozenset,
        owner="structuring.return_chains.call_argument_component_fingerprints_8616",
    )


def _node_component_fingerprints_8616(project: StructuredAstValue, node: StructuredAstValue) -> frozenset[str]:
    """Compatibility shim for structuring-owned C AST component fingerprints."""
    return require_result_type_8616(
        _structuring_node_component_fingerprints_8616(project, node, _expression_fingerprint_callbacks_8616()),
        frozenset,
        owner="structuring.return_chains.node_component_fingerprints_8616",
    )


def _c_statement_shape_8616(stmt: StructuredAstValue, *, max_depth: int = 3) -> StructuredAstValue:
    """Compatibility shim for structuring-owned C statement shape fingerprints."""
    return _structuring_c_statement_shape_8616(stmt, max_depth=max_depth)


@dataclass
class _VoidTailCallGuardRun8616:
    """Run state for void tail-call guard materialization from CFG proofs."""

    project: StructuredAstValue
    codegen: StructuredAstValue
    stats: dict[str, int]
    proofs: list
    has_explicit_void_return: bool
    debug: StructuredAstValue
    log: StructuredAstValue
    changed: bool = False

    def _materialize_suffix_diamond_8616(
        self,
        *,
        stmt: CIfElse,
        statements: list[StructuredAstValue],
        index: int,
        cond: StructuredAstValue,
        false_body: StructuredAstValue,
        cond_keys: frozenset[StructuredAstValue],
    ) -> bool:
        result = _structuring_materialize_void_tail_call_suffix_diamond_8616(
            stmt=stmt,
            statements=statements,
            index=index,
            cond=cond,
            false_body=false_body,
            cond_keys=cond_keys,
            proofs=((proof.condition_keys, proof.true_fingerprint) for proof in self.proofs),
            codegen=self.codegen,
            callbacks=_void_tail_call_suffix_diamond_callbacks_8616(self.project),
        )
        if result.status is not VoidTailCallSuffixDiamondStatus8616.MATERIALIZED:
            if self.debug:
                self.log.warning(
                    "[void-tail-call-guard] suffix-diamond refused status=%s fp=%r matches=%d suffix_types=%r "
                    "cond_keys=%r",
                    result.status.value,
                    result.match_fingerprint,
                    result.match_count,
                    result.suffix_types,
                    cond_keys,
                )
            return False
        self.stats["materialized"] += 1
        self.codegen._inertia_void_tail_call_guard_decision_8616 = (
            _VoidTailCallGuardDecision8616.MATERIALIZE_SUFFIX_DIAMOND.value
        )
        self.codegen._inertia_void_tail_call_guard_materialized_8616 = (
            int(getattr(self.codegen, "_inertia_void_tail_call_guard_materialized_8616", 0) or 0) + 1
        )
        if self.debug:
            self.log.warning(
                "[void-tail-call-guard] materialized suffix diamond index=%d match=%r",
                index,
                result.match_fingerprint,
            )
        return True

    def _guard_arm(
        self,
        block: StructuredAstValue,
        statements: list,
        index: int,
        stmt: CIfElse,
        cond: StructuredAstValue,
        body: StructuredAstValue,
    ) -> int:
        """Handle the ``if (cond) guard; ...`` arm. Returns the next index."""
        self.stats["candidates"] += 1
        if not self.has_explicit_void_return:
            self.stats["refused"] += 1
            self.codegen._inertia_void_tail_call_guard_decision_8616 = (
                _VoidTailCallGuardDecision8616.KEEP_NOT_VOID.value
            )
            return index + 1
        cond_keys = _condition_identity_keys_8616(self.project, cond)
        if self._materialize_suffix_diamond_8616(
            stmt=stmt,
            statements=statements,
            index=index,
            cond=cond,
            false_body=body,
            cond_keys=cond_keys,
        ):
            block.statements = statements
            self.changed = True
            return index + 1
        self.stats["refused"] += 1
        return index + 1

    def _match_unique_proof(
        self,
        cond_keys: frozenset,
        call_arg_fps: StructuredAstValue,
    ) -> StructuredAstValue | None:
        """Return the single matched proof, recording refusals; None when unmatched."""
        exact_proofs = [proof for proof in self.proofs if cond_keys & proof.condition_keys]
        argument_proofs = [proof for proof in self.proofs if proof.true_fingerprint in call_arg_fps]
        if not exact_proofs and len(argument_proofs) == 1:
            exact_proofs = argument_proofs
        if not exact_proofs:
            self.stats["refused"] += 1
            self.codegen._inertia_void_tail_call_guard_decision_8616 = (
                _VoidTailCallGuardDecision8616.KEEP_NO_BRANCH_MATCH.value
            )
            if self.debug:
                self.log.warning("[void-tail-call-guard] refused no-branch-match")
            return None
        unique_proofs = {
            (proof.condition_keys, proof.true_fingerprint): proof for proof in exact_proofs
        }
        if len(unique_proofs) != 1:
            self.stats["refused"] += 1
            self.codegen._inertia_void_tail_call_guard_decision_8616 = (
                _VoidTailCallGuardDecision8616.KEEP_AMBIGUOUS_BRANCH_MATCH.value
            )
            if self.debug:
                self.log.warning(
                    "[void-tail-call-guard] refused ambiguous-match matches=%r",
                    tuple(unique_proofs),
                )
            return None
        return next(iter(unique_proofs.values()))

    def _apply_guard_materialization(
        self,
        block: StructuredAstValue,
        statements: list,
        index: int,
        stmt: CIfElse,
        matched_proof: StructuredAstValue,
        tail_from_else: bool,
        tail_payload: StructuredAstValue,
    ) -> None:
        """Apply the structuring-owned guard materialization and record stats."""
        result = _structuring_materialize_void_tail_call_guard_8616(
            stmt=stmt,
            statements=statements,
            index=index,
            proof=matched_proof,
            tail_from_else=tail_from_else,
            tail_payload=tail_payload,
            codegen=self.codegen,
        )
        if result.status is not VoidTailCallGuardStatus8616.MATERIALIZED:
            self.stats["refused"] += 1
            self.codegen._inertia_void_tail_call_guard_decision_8616 = (
                _VoidTailCallGuardDecision8616.KEEP_NO_TAIL_CALL.value
            )
            if self.debug:
                self.log.warning(
                    "[void-tail-call-guard] refused materialization status=%s payload=%r",
                    result.status.value,
                    result.payload_type,
                )
            return
        if result.removed_following_tail:
            block.statements = statements
        self.stats["materialized"] += 1
        self.codegen._inertia_void_tail_call_guard_decision_8616 = _VoidTailCallGuardDecision8616.MATERIALIZE.value
        self.codegen._inertia_void_tail_call_guard_materialized_8616 = (
            int(getattr(self.codegen, "_inertia_void_tail_call_guard_materialized_8616", 0) or 0) + 1
        )
        if self.debug:
            self.log.warning(
                "[void-tail-call-guard] materialized index=%d condition_keys=%r match=%r",
                index,
                matched_proof.condition_keys,
                matched_proof.true_fingerprint,
            )
        self.changed = True

    def _tail_call_arm(
        self,
        block: StructuredAstValue,
        statements: list,
        index: int,
        stmt: CIfElse,
        cond: StructuredAstValue,
    ) -> int:
        """Handle the tail-call arm. Returns the next index."""
        else_node = stmt.else_node
        tail_from_else = else_node is not None
        if not tail_from_else and index + 1 >= len(statements):
            return index + 1
        tail_stmt = else_node if tail_from_else else statements[index + 1]
        tail_payload = _tail_call_payload_from_statement_8616(tail_stmt, self.codegen)
        if self.debug:
            self.log.warning(
                "[void-tail-call-guard] candidate index=%d cond_keys=%r tail=%s",
                index,
                _condition_identity_keys_8616(self.project, cond),
                type(tail_stmt).__name__,
            )
        if tail_payload is None:
            self.stats["candidates"] += 1
            self.stats["refused"] += 1
            self.codegen._inertia_void_tail_call_guard_decision_8616 = (
                _VoidTailCallGuardDecision8616.KEEP_NO_TAIL_CALL.value
            )
            if self.debug:
                self.log.warning(
                    "[void-tail-call-guard] refused no-tail-call shape=%r", _c_statement_shape_8616(tail_stmt)
                )
            return index + 1
        tail_call = tail_payload[0]
        if isinstance(tail_stmt, CFunctionCall) and not self.has_explicit_void_return:
            self.stats["candidates"] += 1
            self.stats["refused"] += 1
            self.codegen._inertia_void_tail_call_guard_decision_8616 = _VoidTailCallGuardDecision8616.KEEP_NOT_VOID.value
            return index + 1

        self.stats["candidates"] += 1
        cond_keys = _condition_identity_keys_8616(self.project, cond)
        call_arg_fps = _call_argument_fingerprints_8616(self.project, tail_call)
        if self.debug:
            self.log.warning(
                "[void-tail-call-guard] candidate args=%r proofs=%r",
                call_arg_fps,
                self.proofs,
            )
        matched_proof = self._match_unique_proof(cond_keys, call_arg_fps)
        if matched_proof is None:
            return index + 1
        self._apply_guard_materialization(
            block, statements, index, stmt, matched_proof, tail_from_else, tail_payload
        )
        return index + 1

    def _scan_block(self, block: StructuredAstValue) -> None:
        statements = _boundary_list_8616(getattr(block, "statements", ()) or ())
        if not statements:
            return
        index = 0
        while index < len(statements):
            stmt = statements[index]
            if not isinstance(stmt, CIfElse):
                index += 1
                continue
            if self.debug:
                self.log.warning(
                    "[void-tail-call-guard] inspect block_len=%d index=%d next=%s all=%r",
                    len(statements),
                    index,
                    type(statements[index + 1]).__name__ if index + 1 < len(statements) else None,
                    tuple(type(item).__name__ for item in statements),
                )
            cond_nodes = _boundary_tuple_8616(stmt.condition_and_nodes or ())
            if len(cond_nodes) != 1:
                index += 1
                continue
            cond, body = cond_nodes[0]
            if not _is_empty_return_statement_8616(body):
                index = self._guard_arm(block, statements, index, stmt, cond, body)
            else:
                index = self._tail_call_arm(block, statements, index, stmt, cond)

    def run(self, root: StructuredAstValue) -> bool:
        seen_blocks: set[int] = set()
        for block in [root, *[node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CStatements)]]:
            block_id = id(block)
            if block_id in seen_blocks:
                continue
            seen_blocks.add(block_id)
            self._scan_block(block)
        return self.changed


def _materialize_void_tail_call_guard_from_cfg_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:
    """Repair ``if (cond) return; return call();`` when CFG proves the call is the true branch.

    This is structuring-owned even though it currently lives with legacy CFG
    return helpers: the input proof is branch target evidence, and the output
    changes structured control flow before validation/postprocess cleanup.
    """
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None) if cfunc is not None else None
    if not isinstance(root, CStatements):
        return False
    debug = os.environ.get("INERTIA_DEBUG_RETURN_BRANCH")
    log = logging.getLogger(__name__)

    stats = getattr(codegen, "_inertia_void_tail_call_guard_stats_8616", None)
    if not isinstance(stats, dict):
        stats = {"candidates": 0, "materialized": 0, "refused": 0}
        codegen._inertia_void_tail_call_guard_stats_8616 = stats

    has_explicit_void_return = _codegen_has_explicit_void_return_8616(project, codegen)

    proofs: list[VoidTailCallGuardProof8616] = []
    cfg_pairs = _ordered_conditional_void_tail_call_proofs_from_cfg_8616(project, codegen)
    for cond, true_expr in cfg_pairs:
        true_fp = _expr_fingerprint(true_expr, project)
        proofs.append(
            VoidTailCallGuardProof8616(
                condition=cond,
                condition_keys=frozenset(_condition_identity_keys_8616(project, cond)),
                true_fingerprint=true_fp,
            )
        )
    if debug:
        log.warning(
            "[void-tail-call-guard] scan pairs=%d proofs=%r explicit_void=%s",
            len(cfg_pairs),
            proofs,
            has_explicit_void_return,
        )
    if not proofs:
        codegen._inertia_void_tail_call_guard_decision_8616 = _VoidTailCallGuardDecision8616.KEEP_NO_CFG_PROOF.value
        return False

    return _VoidTailCallGuardRun8616(
        project=project,
        codegen=codegen,
        stats=stats,
        proofs=proofs,
        has_explicit_void_return=has_explicit_void_return,
        debug=debug,
        log=log,
    ).run(root)



def _materialize_void_tail_call_guard_from_cfg_pass_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Compatibility fallback for structuring-owned void tail-call guard materialization."""
    # Dynamic boundary: legacy angr codegen only has this flag after the structuring wrapper runs.
    if getattr(codegen, "_inertia_void_tail_call_guard_structuring_pass_ran_8616", False):
        return False
    return _materialize_void_tail_call_guard_from_cfg_8616(project, codegen)


def _is_void_tail_call_guard_materialization_delta_8616(
    codegen: StructuredAstValue,
    validation: Mapping[str, StructuredAstValue],
) -> bool:
    """Compatibility shim for validation-owned void-tail-call guard delta policy."""
    # Dynamic codegen compatibility boundary for legacy materialization counters.
    materialized_count = int(getattr(codegen, "_inertia_void_tail_call_guard_materialized_8616", 0) or 0)
    return require_result_type_8616(
        void_tail_call_guard_materialization_delta_8616(materialized_count, validation),
        bool,
        owner="tail_validation.void_tail_call_guard_materialization_delta_8616",
    )


def _is_conditional_branch_insn_8616(insn: StructuredAstValue) -> bool:
    """Compatibility shim for structuring-owned conditional-branch classification."""
    return require_result_type_8616(
        _structuring_is_conditional_branch_insn_8616(insn),
        bool,
        owner="structuring.return_chains.is_conditional_branch_insn_8616",
    )


def _real_conditional_branch_count_for_codegen_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> int | None:
    """Compatibility shim for structuring-owned conditional branch counting."""
    insns = _linear_function_insns_for_codegen_8616(project, codegen)
    return require_optional_result_type_8616(
        _structuring_conditional_branch_count_8616(insns),
        int,
        owner="structuring.return_chains.conditional_branch_count_8616",
    )


def _else_node_empty_8616(node: StructuredAstValue | None) -> bool:
    """Compatibility shim for structuring-owned else-node emptiness proof."""
    return require_result_type_8616(
        _structuring_else_node_empty_8616(node),
        bool,
        owner="structuring.return_chains.else_node_empty_8616",
    )


def _c_node_semantically_empty_8616(node: StructuredAstValue) -> bool:
    """Compatibility shim for structuring-owned semantic-empty C AST proof."""
    return require_result_type_8616(
        _structuring_c_node_semantically_empty_8616(node, _return_chain_flatten_callbacks_8616()),
        bool,
        owner="structuring.return_chains.c_node_semantically_empty_8616",
    )


def _surplus_empty_guard_condition_8616(
    stmt: StructuredAstValue,
) -> tuple[StructuredAstValue, _SurplusIfGuardKind8616] | None:
    """Compatibility shim for structuring-owned surplus empty-if guard proof."""
    return require_optional_result_type_8616(
        _structuring_surplus_empty_guard_condition_8616(stmt, _return_chain_flatten_callbacks_8616()),
        tuple,
        owner="structuring.return_chains.surplus_empty_guard_condition_8616",
    )


def _condition_branch_tag_callbacks_8616(project: StructuredAstValue) -> ConditionBranchTagCallbacks8616:
    """Build compatibility callbacks for structuring-owned condition branch-tag evidence."""

    def _load_block(addr: int) -> StructuredAstValue | None:
        with contextlib.suppress(Exception):
            return project.factory.block(int(addr), num_inst=1, opt_level=0)
        return None

    return ConditionBranchTagCallbacks8616(
        condition_tags=_jcc._condition_tags_8616,
        load_block=_load_block,
        is_conditional_branch_insn=_is_conditional_branch_insn_8616,
    )


def _condition_branch_tag_evidence_8616(
    project: StructuredAstValue, cond: StructuredAstValue
) -> ConditionBranchTagEvidence8616:
    """Compatibility shim for structuring-owned condition branch-tag evidence."""
    return _structuring_condition_branch_tag_evidence_8616(cond, _condition_branch_tag_callbacks_8616(project))


def _condition_has_jcc_evidence_8616(project: StructuredAstValue, cond: StructuredAstValue) -> bool:
    """Compatibility shim for structuring-owned condition JCC evidence policy."""
    return require_result_type_8616(
        _structuring_condition_has_jcc_evidence_8616(cond, _condition_branch_tag_callbacks_8616(project)),
        bool,
        owner="structuring.return_chains.condition_has_jcc_evidence_8616",
    )


def _debug_guard_shape_refusal_8616(stmt: StructuredAstValue, project: StructuredAstValue, log: StructuredAstValue) -> None:
    """Dump the refused guard shape evidence for branch-prune debugging."""
    cond_nodes = _boundary_tuple_8616(stmt.condition_and_nodes or ())
    log.warning(
        "[void-empty-return-guard] shape-refusal cond_nodes=%d "
        "body_types=%s body_empty=%s else_type=%s else_empty=%s",
        len(cond_nodes),
        tuple(type(body).__name__ for _cond, body in cond_nodes),
        tuple(_c_node_semantically_empty_8616(body) for _cond, body in cond_nodes),
        type(stmt.else_node).__name__,
        _c_node_semantically_empty_8616(stmt.else_node),
    )
    log.warning(
        "[void-empty-return-guard] shape-children bodies=%s else=%s",
        tuple(
            tuple(type(child).__name__ for child in _boundary_tuple_8616(body.statements))
            if isinstance(body, CStatements)
            else ()
            for _cond, body in cond_nodes
        ),
        tuple(
            type(child).__name__
            for child in _boundary_tuple_8616(stmt.else_node.statements)
        )
        if isinstance(stmt.else_node, CStatements)
        else (),
    )
    assignments = tuple(
        child
        for _cond, body in cond_nodes
        if isinstance(body, CStatements)
        for child in _boundary_tuple_8616(body.statements)
        if isinstance(child, CAssignment)
    ) + tuple(
        child
        for child in (
            _boundary_tuple_8616(stmt.else_node.statements)
            if isinstance(stmt.else_node, CStatements)
            else ()
        )
        if isinstance(child, CAssignment)
    )
    log.warning(
        "[void-empty-return-guard] shape-assignment-fingerprints=%s",
        tuple(
            (
                _expr_fingerprint(assignment.lhs, project),
                _expr_fingerprint(assignment.rhs, project),
            )
            for assignment in assignments
        ),
    )


def _surplus_guard_candidate_8616(
    stmt: StructuredAstValue, project: StructuredAstValue
) -> tuple[StructuredAstValue, _SurplusIfGuardKind8616, tuple[StructuredAstValue, ...]] | None:
    """Return (cond, kind, replacement) for a surplus-guard statement, or None."""
    candidate = _surplus_empty_guard_condition_8616(stmt)
    if candidate is not None:
        cond, kind = candidate
        return cond, kind, ()
    identical_arms = _structuring_identical_assignment_arm_condition_8616(
        stmt,
        project,
        _expression_fingerprint_callbacks_8616(),
    )
    if identical_arms is None:
        return None
    cond, replacement = identical_arms
    return cond, _SurplusIfGuardKind8616.IDENTICAL_ASSIGNMENT_ARMS, replacement


def _collect_surplus_guard_candidates_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    root: StructuredAstValue,
    debug: StructuredAstValue,
    log: StructuredAstValue,
) -> tuple[list, int, int]:
    """Collect eligible surplus guards; returns (candidates, refused_shape, refused_branch_backed)."""
    candidates: list[
        tuple[
            CStatements,
            int,
            _SurplusIfGuardKind8616,
            tuple[StructuredAstValue, ...],
        ]
    ] = []
    refused_branch_backed = 0
    refused_shape = 0
    seen_blocks: set[int] = set()
    blocks = [node for node in (root, *_iter_c_nodes_deep_8616(root)) if isinstance(node, CStatements)]
    for block in blocks:
        block_id = id(block)
        if block_id in seen_blocks:
            continue
        seen_blocks.add(block_id)
        for index, stmt in enumerate(_boundary_list_8616(getattr(block, "statements", ()) or ())):
            resolved = _surplus_guard_candidate_8616(stmt, project)
            if resolved is None:
                if isinstance(stmt, CIfElse):
                    refused_shape += 1
                    if debug:
                        _debug_guard_shape_refusal_8616(stmt, project, log)
                continue
            cond, kind, replacement = resolved
            codegen._inertia_void_empty_return_guard_candidates_8616 = (
                int(getattr(codegen, "_inertia_void_empty_return_guard_candidates_8616", 0) or 0) + 1
            )
            if _condition_has_jcc_evidence_8616(project, cond):
                refused_branch_backed += 1
                continue
            if kind is _SurplusIfGuardKind8616.EMPTY_NOOP:
                codegen._inertia_void_empty_return_guard_noop_candidates_8616 = (
                    int(getattr(codegen, "_inertia_void_empty_return_guard_noop_candidates_8616", 0) or 0) + 1
                )
            candidates.append((block, index, kind, replacement))
    return candidates, refused_shape, refused_branch_backed


def _surplus_guard_kind_counts_8616(candidates: list, prune_budget: int) -> tuple[int, int, int]:
    """Count the pruned candidates by guard kind."""
    pruned_noop = sum(
        1
        for _block, _index, kind, _replacement in candidates[:prune_budget]
        if kind is _SurplusIfGuardKind8616.EMPTY_NOOP
    )
    pruned_empty_return = sum(
        1
        for _block, _index, kind, _replacement in candidates[:prune_budget]
        if kind is _SurplusIfGuardKind8616.EMPTY_RETURN
    )
    collapsed_identical_arms = sum(
        1
        for _block, _index, kind, _replacement in candidates[:prune_budget]
        if kind is _SurplusIfGuardKind8616.IDENTICAL_ASSIGNMENT_ARMS
    )
    return pruned_noop, pruned_empty_return, collapsed_identical_arms


def _apply_surplus_guard_prune_8616(candidates: list, prune_budget: int) -> int:
    """Rewrite each candidate block with its replacements; returns the pruned count."""
    prune_by_block: dict[
        int,
        tuple[CStatements, dict[int, tuple[StructuredAstValue, ...]]],
    ] = {}
    for block, index, _kind, replacement in candidates[:prune_budget]:
        block_id = id(block)
        if block_id not in prune_by_block:
            prune_by_block[block_id] = (block, {})
        prune_by_block[block_id][1][index] = replacement

    pruned = 0
    for block, replacements in prune_by_block.values():
        old_statements = _boundary_list_8616(getattr(block, "statements", ()) or ())
        rebuilt: list[StructuredAstValue] = []
        for index, statement in enumerate(old_statements):
            statement_replacement = replacements.get(index)
            if statement_replacement is None:
                rebuilt.append(statement)
            else:
                rebuilt.extend(statement_replacement)
                pruned += 1
        block.statements = rebuilt
    return pruned


def _record_surplus_guard_prune_8616(
    codegen: StructuredAstValue,
    branch_count: int,
    total_if_nodes: int,
    surplus: int,
    candidates: list,
    pruned: int,
    pruned_noop: int,
    pruned_empty_return: int,
    collapsed_identical_arms: int,
    debug: StructuredAstValue,
    log: StructuredAstValue,
) -> None:
    codegen._inertia_void_empty_return_guard_pruned_8616 = (
        int(getattr(codegen, "_inertia_void_empty_return_guard_pruned_8616", 0) or 0) + pruned
    )
    codegen._inertia_void_empty_return_guard_branch_count_8616 = int(branch_count)
    codegen._inertia_void_empty_return_guard_total_ifs_8616 = int(total_if_nodes)
    codegen._inertia_void_empty_return_guard_noop_pruned_8616 = (
        int(getattr(codegen, "_inertia_void_empty_return_guard_noop_pruned_8616", 0) or 0) + pruned_noop
    )
    codegen._inertia_void_empty_return_guard_empty_return_pruned_8616 = (
        int(getattr(codegen, "_inertia_void_empty_return_guard_empty_return_pruned_8616", 0) or 0) + pruned_empty_return
    )
    codegen._inertia_void_empty_return_guard_identical_arms_collapsed_8616 = (
        int(
            getattr(
                codegen,
                "_inertia_void_empty_return_guard_identical_arms_collapsed_8616",
                0,
            )
            or 0
        )
        + collapsed_identical_arms
    )
    codegen._inertia_surplus_empty_guard_cleanup_artifact_8616 = (
        SurplusGuardCleanupEvidence8616(
            branch_count=int(branch_count),
            total_if_count=int(total_if_nodes),
            noop_materialized_count=pruned_noop,
            empty_return_materialized_count=pruned_empty_return,
            identical_arms_materialized_count=collapsed_identical_arms,
            stats=SurplusGuardCleanupStats8616(
                raw_fact_count=len(candidates),
                normalized_fact_count=len(candidates),
                classified_fact_count=len(candidates),
                materialized_count=pruned,
                failure_count=len(candidates) - pruned,
            ),
        )
    )
    codegen._inertia_void_empty_return_guard_decision_8616 = _VoidEmptyReturnGuardDecision8616.PRUNE.value
    if debug:
        log.warning(
            "[void-empty-return-guard] pruned=%d ifs=%d branches=%d surplus=%d candidates=%d",
            pruned,
            total_if_nodes,
            int(branch_count),
            int(surplus),
            len(candidates),
        )


def _surplus_guard_branch_budget_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    root: StructuredAstValue,
    debug: StructuredAstValue,
    log: StructuredAstValue,
) -> tuple[int, int] | None:
    """Return (branch_count, total_if_nodes) when surplus guards exist, or None on refusal."""
    if not _codegen_has_explicit_void_return_8616(project, codegen):
        codegen._inertia_void_empty_return_guard_refused_not_void_8616 = (
            int(getattr(codegen, "_inertia_void_empty_return_guard_refused_not_void_8616", 0) or 0) + 1
        )
        codegen._inertia_void_empty_return_guard_decision_8616 = _VoidEmptyReturnGuardDecision8616.KEEP_NOT_VOID.value
        if debug:
            log.warning("[void-empty-return-guard] refused reason=not-void")
        return None

    branch_count = _real_conditional_branch_count_for_codegen_8616(project, codegen)
    if branch_count is None:
        codegen._inertia_void_empty_return_guard_refused_no_branch_proof_8616 = (
            int(getattr(codegen, "_inertia_void_empty_return_guard_refused_no_branch_proof_8616", 0) or 0) + 1
        )
        codegen._inertia_void_empty_return_guard_decision_8616 = (
            _VoidEmptyReturnGuardDecision8616.KEEP_NO_BRANCH_PROOF.value
        )
        if debug:
            log.warning("[void-empty-return-guard] refused reason=no-branch-proof")
        return None

    total_if_nodes = sum(1 for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CIfElse))
    surplus = total_if_nodes - int(branch_count)
    if surplus <= 0:
        codegen._inertia_void_empty_return_guard_refused_within_branch_budget_8616 = (
            int(getattr(codegen, "_inertia_void_empty_return_guard_refused_within_branch_budget_8616", 0) or 0) + 1
        )
        codegen._inertia_void_empty_return_guard_decision_8616 = (
            _VoidEmptyReturnGuardDecision8616.KEEP_WITHIN_BRANCH_BUDGET.value
        )
        if debug:
            log.warning(
                "[void-empty-return-guard] refused reason=within-budget ifs=%d branches=%d",
                total_if_nodes,
                int(branch_count),
            )
        return None
    return int(branch_count), total_if_nodes


def _record_surplus_guard_refusals_8616(
    codegen: StructuredAstValue,
    branch_count: int,
    total_if_nodes: int,
    surplus: int,
    refused_shape: int,
    refused_branch_backed: int,
    debug: StructuredAstValue,
    log: StructuredAstValue,
) -> None:
    """Record refused-shape/branch-backed counters and the no-candidate decision."""
    if refused_shape:
        codegen._inertia_void_empty_return_guard_refused_non_empty_shape_8616 = (
            int(getattr(codegen, "_inertia_void_empty_return_guard_refused_non_empty_shape_8616", 0) or 0)
            + refused_shape
        )
    if refused_branch_backed:
        codegen._inertia_void_empty_return_guard_refused_branch_backed_8616 = (
            int(getattr(codegen, "_inertia_void_empty_return_guard_refused_branch_backed_8616", 0) or 0)
            + refused_branch_backed
        )
    codegen._inertia_void_empty_return_guard_decision_8616 = (
        _VoidEmptyReturnGuardDecision8616.KEEP_BRANCH_BACKED_CONDITION.value
    )
    if debug:
        log.warning(
            "[void-empty-return-guard] refused reason=no-eligible-candidates ifs=%d branches=%d "
            "surplus=%d refused_shape=%d refused_branch_backed=%d",
            total_if_nodes,
            int(branch_count),
            int(surplus),
            refused_shape,
            refused_branch_backed,
        )


def _prune_surplus_void_empty_return_guards_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:
    """Replay structuring-owned surplus-branch proofs at the compatibility boundary.

    Empty-return and identical-assignment branch classification belongs in
    ``structuring/return_chains.py``. This legacy pass only adapts dynamic angr
    AST callbacks after regeneration; do not add a new proof or semantic
    mutation here. Migrate each remaining branch kind into Structuring, then
    reduce this function to replay or remove it.
    """
    debug = os.environ.get("INERTIA_DEBUG_RETURN_BRANCH")
    log = logging.getLogger(__name__)
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None) if cfunc is not None else None
    if root is None:
        return False

    budget = _surplus_guard_branch_budget_8616(project, codegen, root, debug, log)
    if budget is None:
        return False
    branch_count, total_if_nodes = budget
    surplus = total_if_nodes - branch_count

    candidates, refused_shape, refused_branch_backed = _collect_surplus_guard_candidates_8616(
        project, codegen, root, debug, log
    )

    if not candidates:
        _record_surplus_guard_refusals_8616(
            codegen, branch_count, total_if_nodes, surplus, refused_shape, refused_branch_backed, debug, log
        )
        return False

    # Refusal counters are recorded even on the accepted path.
    if refused_shape:
        codegen._inertia_void_empty_return_guard_refused_non_empty_shape_8616 = (
            int(getattr(codegen, "_inertia_void_empty_return_guard_refused_non_empty_shape_8616", 0) or 0)
            + refused_shape
        )
    if refused_branch_backed:
        codegen._inertia_void_empty_return_guard_refused_branch_backed_8616 = (
            int(getattr(codegen, "_inertia_void_empty_return_guard_refused_branch_backed_8616", 0) or 0)
            + refused_branch_backed
        )

    prune_budget = min(int(surplus), len(candidates))
    pruned_noop, pruned_empty_return, collapsed_identical_arms = _surplus_guard_kind_counts_8616(
        candidates, prune_budget
    )
    pruned = _apply_surplus_guard_prune_8616(candidates, prune_budget)

    if pruned <= 0:
        return False
    _record_surplus_guard_prune_8616(
        codegen,
        branch_count,
        total_if_nodes,
        surplus,
        candidates,
        pruned,
        pruned_noop,
        pruned_empty_return,
        collapsed_identical_arms,
        debug,
        log,
    )
    return True



def _debug_duplicate_empty_prune_refusal_8616(log: StructuredAstValue, statements: list, values: tuple) -> None:
    """Dump the nearby statement shapes when the duplicate-empty prune refuses."""
    nearby = []
    for index, stmt in enumerate(statements[: min(len(statements), 12)]):
        item = _single_if_return_8616(stmt)
        nearby.append(
            (
                index,
                type(stmt).__name__,
                None if item is None else type(item[1]).__name__,
                None if item is None else _const_return_value_8616(item[1]),
            )
        )
    log.warning(
        "[cfg-return-chain] duplicate-empty prune refused: statements=%d values=%d nearby=%r",
        len(statements),
        len(values),
        nearby,
    )


def _codegen_has_materialized_return_chain_8616(codegen: StructuredAstValue) -> bool:
    """Return True when any return-chain materialization flag is set on codegen."""
    return any(
        bool(getattr(codegen, attr, False))
        for attr in (
            "_inertia_return_chain_suffix_materialized_8616",
            "_inertia_return_chain_flattened_8616",
            "_inertia_return_expr_chain_materialized_8616",
            "_inertia_decrement_switch_return_materialized_8616",
        )
    )


def _cfg_derived_return_chain_values_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> tuple[int, ...] | None:
    """Derive return-chain values from CFG evidence when no chain was materialized."""
    cfg_values = _ordered_conditional_return_values_8616(project, codegen)
    final_value = _last_ax_return_value_8616(project, codegen)
    if not cfg_values or final_value is None:
        return None
    return (*tuple(int(value) for value in cfg_values), int(final_value))


def _duplicate_empty_prune_values_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, log: StructuredAstValue, debug: StructuredAstValue
) -> tuple | None:
    """Resolve the return-chain value tuple for the duplicate-empty prune, or refuse."""
    has_materialized_return_chain = _codegen_has_materialized_return_chain_8616(codegen)
    values = _boundary_tuple_8616(
        int(value)
        for value in _boundary_tuple_8616(getattr(codegen, "_inertia_return_chain_materialized_values_8616", ()) or ())
    )
    if not has_materialized_return_chain:
        derived = _cfg_derived_return_chain_values_8616(project, codegen)
        if derived is None:
            if debug:
                log.warning("[cfg-return-chain] duplicate-empty prune refused: return chain not materialized")
            return None
        values = derived
    if not values:
        if debug:
            log.warning("[cfg-return-chain] duplicate-empty prune refused: no values")
        return None
    return values


def _prune_duplicate_empty_return_guard_before_cfg_suffix_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Prune duplicate empty-return guards using structuring-owned prune planning."""
    debug = os.environ.get("INERTIA_DEBUG_RETURN_BRANCH")
    log = logging.getLogger(__name__)
    values = _duplicate_empty_prune_values_8616(project, codegen, log, debug)
    if values is None:
        return False
    # Dynamic codegen/C AST compatibility boundary.
    cfunc = getattr(codegen, "cfunc", None)
    # Dynamic codegen/C AST compatibility boundary.
    statements_node = getattr(cfunc, "statements", None)
    # Dynamic codegen/C AST compatibility boundary.
    statements = _boundary_list_8616(getattr(statements_node, "statements", ()) or ())
    plan = _structuring_duplicate_empty_return_guard_prune_plan_8616(
        project,
        statements,
        values,
        _return_chain_flatten_callbacks_8616(),
    )
    if plan is None:
        if debug:
            _debug_duplicate_empty_prune_refusal_8616(log, statements, values)
        return False
    del statements[plan.index]
    codegen.cfunc.statements = CStatements(statements=statements, codegen=codegen)
    if plan.reason is DuplicateEmptyReturnGuardPruneReason8616.EMPTY_PREFIX_BEFORE_CHAIN:
        codegen._inertia_return_chain_empty_prefix_pruned_8616 = True
        if debug:
            log.warning("[cfg-return-chain] empty return prefix pruned index=%d", plan.index)
        return True
    codegen._inertia_return_chain_duplicate_empty_pruned_8616 = True
    if debug:
        log.warning(
            "[cfg-return-chain] duplicate-empty pruned index=%d reason=%s value=%r",
            plan.index,
            plan.reason.value,
            plan.value,
        )
    return True


def _return_chain_count_callbacks_8616() -> ReturnChainCountCallbacks8616:
    """Build compatibility callbacks for structuring-owned return-chain accounting."""
    return ReturnChainCountCallbacks8616(iter_c_nodes_deep=_iter_c_nodes_deep_8616)


def _return_chain_counts_8616(codegen: StructuredAstValue) -> tuple[int, int]:
    """Compatibility shim for structuring-owned return-chain AST counts."""
    # Dynamic boundary: angr codegen may or may not expose cfunc/statements.
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    return require_result_type_8616(
        _structuring_return_chain_counts_8616(root, _return_chain_count_callbacks_8616()),
        tuple,
        owner="structuring.return_chains.return_chain_counts_8616",
    )


def _return_chain_expected_counts_8616(codegen: StructuredAstValue) -> tuple[int, int] | None:
    """Compatibility shim for structuring-owned return-chain metadata counts."""
    ensure_return_chain_codegen_state_8616(codegen)
    return require_optional_result_type_8616(
        _structuring_return_chain_expected_counts_8616(codegen),
        tuple,
        owner="structuring.return_chains.return_chain_expected_counts_8616",
    )


def _repair_unresolved_function_exit_gotos_pass_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:
    """Run unresolved exit-goto repair from the guarded postprocess compatibility hook."""
    # Dynamic boundary: legacy angr codegen only has this flag after the structuring CFG repair owner runs.
    if getattr(codegen, "_inertia_unresolved_exit_goto_structuring_pass_ran_8616", False):
        return False
    return bool(
        _post._repair_unresolved_function_exit_gotos_8616(
            project if project is not None else getattr(codegen, "project", None),
            codegen,
        )
    )


def _record_unchanged_postprocess_validation_skip_8616(codegen: StructuredAstValue, pass_name: str) -> None:
    """Record a validation skip in dynamic codegen compatibility state.

    Per-pass validation remains mandatory for every accepted postprocess
    mutation. A pass returning ``False`` is the local no-mutation contract; when
    it holds, the existing baseline summary is still current and re-collecting
    live-out validation facts only burns time.
    """
    skipped = _boundary_list_8616(
        getattr(codegen, "_inertia_postprocess_unchanged_validation_skipped_passes_8616", ()) or ()
    )
    skipped.append(pass_name)
    codegen._inertia_postprocess_unchanged_validation_skipped_passes_8616 = tuple(skipped)
    codegen._inertia_postprocess_unchanged_validation_skip_count_8616 = (
        int(getattr(codegen, "_inertia_postprocess_unchanged_validation_skip_count_8616", 0) or 0) + 1
    )


def _codegen_has_structured_condition_8616(codegen: StructuredAstValue) -> bool:
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if root is None:
        return False
    for node in (root, *_iter_c_nodes_deep_8616(root)):
        if isinstance(node, (CIfBreak, CIfElse, CWhileLoop, CDoWhileLoop, CForLoop)):
            return True
        if getattr(node, "condition", None) is not None or getattr(node, "cond", None) is not None:
            return True
        if getattr(node, "condition_and_nodes", None):
            return True
    return False


def _dead_code_elimination_after_flag_prune_8616(codegen: StructuredAstValue) -> bool:
    complexity = getattr(codegen, "_inertia_postprocess_function_complexity_8616", None)
    if isinstance(complexity, Mapping):
        block_count = _coerce_nonnegative_int_8616(complexity.get("blocks"))
        byte_count = _coerce_nonnegative_int_8616(complexity.get("bytes"))
        allow_large_seqnode_dce = bool(
            getattr(codegen, "_inertia_allow_large_function_flag_dce_after_seqnode_replacement_8616", False)
        )
        if (block_count >= 64 or byte_count >= 0x200) and not allow_large_seqnode_dce:
            refused = _boundary_list_8616(getattr(codegen, "_inertia_postprocess_refused_passes_8616", ()) or ())
            refused.append(
                {
                    "pass": "_dead_code_elimination_after_flag_prune_8616",
                    "reason": _PostprocessPassRefusalReason8616.VERY_LARGE_FUNCTION_LOCAL_VALIDATION_UNAVAILABLE.value,
                }
            )
            codegen._inertia_postprocess_refused_passes_8616 = tuple(refused)
            return False
        if allow_large_seqnode_dce:
            codegen._inertia_large_function_flag_dce_after_seqnode_replacement_8616 = (
                int(getattr(codegen, "_inertia_large_function_flag_dce_after_seqnode_replacement_8616", 0) or 0) + 1
            )
    had_attr = hasattr(codegen, "_inertia_dce_allow_storage_free_dirty_8616")
    previous = getattr(codegen, "_inertia_dce_allow_storage_free_dirty_8616", None)
    had_dirty_read_attr = hasattr(codegen, "_inertia_dce_allow_dirty_value_reads_8616")
    previous_dirty_read = getattr(codegen, "_inertia_dce_allow_dirty_value_reads_8616", None)
    codegen._inertia_dce_allow_storage_free_dirty_8616 = True
    codegen._inertia_dce_allow_dirty_value_reads_8616 = True
    try:
        return require_result_type_8616(
            _dead_code_elimination_8616(codegen),
            bool,
            owner="postprocess.optimization.dce._dead_code_elimination_8616",
        )
    finally:
        if had_attr:
            codegen._inertia_dce_allow_storage_free_dirty_8616 = previous
        else:
            with contextlib.suppress(Exception):
                delattr(codegen, "_inertia_dce_allow_storage_free_dirty_8616")
        if had_dirty_read_attr:
            codegen._inertia_dce_allow_dirty_value_reads_8616 = previous_dirty_read
        else:
            with contextlib.suppress(Exception):
                delattr(codegen, "_inertia_dce_allow_dirty_value_reads_8616")


def _collapse_unsupported_ail_return_before_materialized_return_8616(codegen: StructuredAstValue) -> bool:
    """Drop an angr return wrapper superseded by a proven materialized return."""
    if int(getattr(codegen, "_inertia_missing_terminal_ax_return_materialized_8616", 0) or 0) <= 0:
        return False
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    if root is None:
        return False
    changed = False
    removed = 0
    for container in (root, *_iter_c_nodes_deep_8616(root)):
        if not isinstance(container, CStatements):
            continue
        statements = _boundary_list_8616(container.statements or ())
        rewritten: list[StructuredAstValue] = []
        index = 0
        while index < len(statements):
            stmt = statements[index]
            next_stmt = statements[index + 1] if index + 1 < len(statements) else None
            if (
                isinstance(stmt, CUnsupportedStatement)
                and isinstance(stmt.stmt, AILReturn)
                and isinstance(next_stmt, CReturn)
            ):
                rewritten.append(next_stmt)
                removed += 1
                changed = True
                index += 2
                continue
            rewritten.append(stmt)
            index += 1
        if len(rewritten) != len(statements):
            container.statements = rewritten
    if removed:
        codegen._inertia_unsupported_ail_returns_superseded_8616 = (
            int(getattr(codegen, "_inertia_unsupported_ail_returns_superseded_8616", 0) or 0) + removed
        )
    return changed


def _dead_code_elimination_final_cleanup_8616(codegen: StructuredAstValue) -> bool:
    """Run terminal DCE and final unresolved-return carrier cleanup."""
    had_storage_free_attr = hasattr(codegen, "_inertia_dce_allow_storage_free_dirty_8616")
    previous_storage_free = getattr(codegen, "_inertia_dce_allow_storage_free_dirty_8616", None)
    had_dirty_read_attr = hasattr(codegen, "_inertia_dce_allow_dirty_value_reads_8616")
    previous_dirty_read = getattr(codegen, "_inertia_dce_allow_dirty_value_reads_8616", None)
    codegen._inertia_dce_allow_storage_free_dirty_8616 = True
    codegen._inertia_dce_allow_dirty_value_reads_8616 = True
    try:
        changed = _dead_code_elimination_8616(codegen)
    finally:
        if had_storage_free_attr:
            codegen._inertia_dce_allow_storage_free_dirty_8616 = previous_storage_free
        else:
            with contextlib.suppress(Exception):
                delattr(codegen, "_inertia_dce_allow_storage_free_dirty_8616")
        if had_dirty_read_attr:
            codegen._inertia_dce_allow_dirty_value_reads_8616 = previous_dirty_read
        else:
            with contextlib.suppress(Exception):
                delattr(codegen, "_inertia_dce_allow_dirty_value_reads_8616")
    changed = _collapse_unsupported_ail_return_before_materialized_return_8616(codegen) or changed
    changed = _post._collapse_adjacent_unresolved_return_carrier_8616(cast(Any, object()), codegen) or changed
    return changed


def _materialize_stable_stack_semantics_postprocess_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Compatibility fallback for stack alias and stable SS lowering after structuring."""
    # Dynamic boundary: legacy angr codegen only has this flag after the structuring stack owner runs.
    if getattr(codegen, "_inertia_stable_stack_semantics_structuring_pass_ran_8616", False):
        return False
    changed = False
    try:
        debug_stack_noise = bool(os.environ.get("INERTIA_DEBUG_STACK_NOISE"))
        before_ss_linear = int(getattr(codegen, "_inertia_ss_linear_materialized_count", 0) or 0)
        before_semantic_stack = int(getattr(codegen, "_inertia_semantic_stack_materialized_count", 0) or 0)
        _invalidate_tail_validation_derived_caches_8616(codegen)
        transfer_semantic_alias_facts_to_codegen_8616(project, codegen)
        alias_facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
        if isinstance(alias_facts, list) and alias_facts:
            before_materialized = int(getattr(codegen, "_inertia_semantic_stack_materialized_count", 0) or 0)
            lower_stack_accesses_from_alias_facts_8616(codegen, alias_facts)
            after_materialized = int(getattr(codegen, "_inertia_semantic_stack_materialized_count", 0) or 0)
            changed = changed or after_materialized > before_materialized
        from .lowering.real_mode_linear import lower_stable_ss_linear_stack_dereferences_8616

        changed = bool(lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project)) or changed
        if _fact_backed_stack_normalize_enabled_8616():
            changed = bool(_normalize_fact_backed_stack_accesses_8616(project, codegen)) or changed
        if changed:
            codegen._inertia_codegen_decl_refresh_required_8616 = True
        _invalidate_tail_validation_derived_caches_8616(codegen)
        if debug_stack_noise:
            logging.getLogger(__name__).warning(
                "[stable-stack-postprocess] function=%#x alias_facts=%d "
                "semantic_delta=%d ss_linear_delta=%d changed=%s",
                getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
                len(alias_facts) if isinstance(alias_facts, list) else 0,
                int(getattr(codegen, "_inertia_semantic_stack_materialized_count", 0) or 0) - before_semantic_stack,
                int(getattr(codegen, "_inertia_ss_linear_materialized_count", 0) or 0) - before_ss_linear,
                changed,
            )
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Stable stack semantics postprocess materialization failed at function=%#x: %s",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            ex,
        )
    return changed


def _statement_ends_in_return_8616(stmt: StructuredAstValue) -> bool:
    if isinstance(stmt, CReturn):
        return True
    if not isinstance(stmt, CStatements):
        return False
    nested = _boundary_list_8616(stmt.statements or ())
    while nested and isinstance(nested[-1], CStatements):
        nested = _boundary_list_8616(getattr(nested[-1], "statements", ()) or ())
    return bool(nested and isinstance(nested[-1], CReturn))


def _prune_block_after_return_8616(node: StructuredAstValue) -> int:
    """Drop statements after a terminating return in one block; returns removed count."""
    statements = _boundary_list_8616(node.statements or ())
    if not statements:
        return 0
    kept = []
    removed = 0
    terminated = False
    for stmt in statements:
        if terminated:
            removed += 1
            continue
        kept.append(stmt)
        if _statement_ends_in_return_8616(stmt):
            terminated = True
    if len(kept) != len(statements):
        node.statements = kept
    return removed


def _debug_unreachable_prune_8616(root: StructuredAstValue, scanned_blocks: int, removed: int, changed: bool) -> None:
    if not os.environ.get("INERTIA_DEBUG_UNREACHABLE_PRUNE"):
        return
    top_types = ()
    with contextlib.suppress(Exception):
        top_types = _boundary_tuple_8616(
            type(stmt).__name__ for stmt in _boundary_tuple_8616(getattr(root, "statements", ()) or ())
        )
    logging.getLogger(__name__).warning(
        "[unreachable-prune] blocks=%d removed=%d changed=%s root_type=%s top=%r",
        scanned_blocks,
        removed,
        changed,
        type(root).__name__,
        top_types,
    )


def _prune_unreachable_after_return_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    root = getattr(cfunc, "statements", None)
    if root is None:
        return False

    removed = 0
    scanned_blocks = 0
    seen: set[int] = set()
    blocks = [node for node in (root, *_iter_c_nodes_deep_8616(root)) if isinstance(node, CStatements)]
    for node in reversed(blocks):
        node_id = id(node)
        if node_id in seen:
            continue
        seen.add(node_id)
        scanned_blocks += 1
        removed += _prune_block_after_return_8616(node)

    changed = bool(removed)
    if removed:
        codegen._inertia_unreachable_after_return_pruned_8616 = (
            int(getattr(codegen, "_inertia_unreachable_after_return_pruned_8616", 0) or 0) + removed
        )
    _debug_unreachable_prune_8616(root, scanned_blocks, removed, changed)
    return changed



def _select_artifact_return_8616(
    root: StructuredAstValue, return_nodes: list[StructuredAstValue]
) -> tuple[str, StructuredAstValue]:
    """Return ("none"|"replace"|"refuse", node) for the artifact-return selection gate."""
    debug = bool(os.environ.get("INERTIA_DEBUG_MISSING_AX_RETURN"))
    log = logging.getLogger(__name__)
    if not return_nodes:
        return "none", None
    artifact_returns = [
        node
        for node in return_nodes
        if _return_expr_has_insert_artifact_8616(getattr(node, "retval", None))
        or _return_depends_on_insert_artifact_8616(root, node)
        or _return_expr_has_untyped_dereference_artifact_8616(getattr(node, "retval", None))
        or _return_expr_has_dirty_carrier_artifact_8616(getattr(node, "retval", None))
    ]
    if len(artifact_returns) > 1:
        if debug:
            log.warning(
                "[missing-ax-return] refused artifact_count=%d return_nodes=%d",
                len(artifact_returns),
                len(return_nodes),
            )
        return "refuse", None
    if artifact_returns:
        return "replace", artifact_returns[0]
    segmented_artifact_returns = [
        node
        for node in return_nodes
        if _return_expr_has_segmented_linear_artifact_8616(getattr(node, "retval", None))
    ]
    if len(segmented_artifact_returns) == 1:
        return "replace", segmented_artifact_returns[0]
    generic_artifact_returns = [
        node
        for node in return_nodes
        if _return_expr_has_generic_register_artifact_8616(getattr(node, "retval", None))
    ]
    if len(generic_artifact_returns) != 1 or not _generic_return_replacement_is_side_effect_free_8616(
        root, generic_artifact_returns[0]
    ):
        if debug:
            log.warning(
                "[missing-ax-return] refused segmented_artifact_count=%d "
                "generic_artifact_count=%d return_nodes=%d",
                len(segmented_artifact_returns),
                len(generic_artifact_returns),
                len(return_nodes),
            )
        return "refuse", None
    return "replace", generic_artifact_returns[0]


def _terminal_ax_return_function_context_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, cfunc: StructuredAstValue
) -> tuple[int | None, StructuredAstValue, StructuredAstValue] | None:
    """Return (func_addr, function, concrete_return_types) when the return type gate passes."""
    func_addr = getattr(cfunc, "addr", None)
    function = getattr(codegen, "_inertia_current_function_8616", None)
    if isinstance(func_addr, int) and function is None:
        with contextlib.suppress(Exception):
            function = project.kb.functions.function(addr=func_addr, create=False)

    return_types: list[StructuredAstValue] = []
    for candidate in (
        getattr(function, "prototype", None) if function is not None else None,
        getattr(cfunc, "functy", None),
        getattr(cfunc, "prototype", None),
    ):
        candidate_return_type = getattr(candidate, "returnty", None)
        if candidate_return_type is not None:
            return_types.append(candidate_return_type)

    if any(type(return_type) is SimTypeBottom and getattr(return_type, "label", None) == "void" for return_type in return_types):
        codegen._inertia_missing_terminal_ax_return_refused_void_8616 = (
            int(getattr(codegen, "_inertia_missing_terminal_ax_return_refused_void_8616", 0) or 0) + 1
        )
        return None
    concrete_return_types = tuple(return_type for return_type in return_types if type(return_type) is not SimTypeBottom)
    if not concrete_return_types:
        return None
    return_widths: list[int | None] = []
    for return_type in concrete_return_types:
        try:
            return_widths.append(return_type.size)
        except (AttributeError, ValueError):
            return_widths.append(None)
    if not terminal_ax_fallback_supports_widths_8616(return_widths):
        codegen._inertia_missing_terminal_ax_return_refused_width_8616 = (
            int(getattr(codegen, "_inertia_missing_terminal_ax_return_refused_width_8616", 0) or 0) + 1
        )
        return None
    return func_addr, function, concrete_return_types


def _replace_unsupported_ail_return_8616(
    root: StructuredAstValue, codegen: StructuredAstValue, retval: StructuredAstValue, unsupported_return: StructuredAstValue
) -> bool:
    """Replace the single unsupported AIL return statement with a typed C return."""
    replacement = CReturn(retval, codegen=codegen)
    replaced = False
    for container in (root, *_iter_c_nodes_deep_8616(root)):
        if not isinstance(container, CStatements):
            continue
        container_statements = _boundary_list_8616(container.statements or ())
        for index, stmt in enumerate(container_statements):
            if stmt is not unsupported_return:
                continue
            container_statements[index] = replacement
            container.statements = container_statements
            replaced = True
            break
        if replaced:
            break
    return replaced


def _record_terminal_ax_materialization_8616(
    codegen: StructuredAstValue,
    project: StructuredAstValue,
    retval: StructuredAstValue,
    replaced_fingerprint: StructuredAstValue,
) -> None:
    fingerprint = None
    with contextlib.suppress(Exception):
        fingerprint = _expr_fingerprint(retval, project)
    codegen._inertia_missing_terminal_ax_return_materialized_8616 = (
        int(getattr(codegen, "_inertia_missing_terminal_ax_return_materialized_8616", 0) or 0) + 1
    )
    if fingerprint is not None:
        codegen._inertia_missing_terminal_ax_return_fingerprints_8616 = (
            *_boundary_tuple_8616(getattr(codegen, "_inertia_missing_terminal_ax_return_fingerprints_8616", ()) or ()),
            fingerprint,
        )
    if replaced_fingerprint is not None:
        codegen._inertia_missing_terminal_ax_return_replaced_fingerprints_8616 = (
            *_boundary_tuple_8616(
                getattr(codegen, "_inertia_missing_terminal_ax_return_replaced_fingerprints_8616", ()) or ()
            ),
            replaced_fingerprint,
        )


def _terminal_ax_return_surface_8616(
    codegen: StructuredAstValue, cfunc: StructuredAstValue
) -> tuple[StructuredAstValue, StructuredAstValue, list, list] | None:
    """Return (root, statements, return_nodes, unsupported_return_nodes), or None."""
    root = getattr(cfunc, "statements", None) or getattr(cfunc, "body", None)
    if root is None:
        return None
    statements = getattr(root, "statements", None)
    if not isinstance(statements, (list, tuple)):
        return None
    return_nodes = [node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CReturn)]
    unsupported_return_nodes = [
        stmt
        for container in (root, *_iter_c_nodes_deep_8616(root))
        if isinstance(container, CStatements)
        for stmt in _boundary_tuple_8616(container.statements or ())
        if isinstance(stmt, CUnsupportedStatement) and isinstance(stmt.stmt, AILReturn)
    ]
    if os.environ.get("INERTIA_DEBUG_MISSING_AX_RETURN"):
        logging.getLogger(__name__).warning(
            "[missing-ax-return] pass-entry func=%#x return_nodes=%d root=%s",
            getattr(cfunc, "addr", -1) or -1,
            len(return_nodes),
            type(root).__name__,
        )
    return root, statements, return_nodes, unsupported_return_nodes


def _terminal_ax_wide_gate_8616(codegen: StructuredAstValue, return_nodes: list) -> bool:
    """Return True when a wide-composition return refuses the fallback."""
    wide_return_nodes = [
        node
        for node in return_nodes
        if return_expression_has_wide_word_composition_8616(getattr(node, "retval", None))
    ]
    if not wide_return_nodes:
        return False
    codegen._inertia_missing_terminal_ax_return_refused_wide_8616 = (
        int(getattr(codegen, "_inertia_missing_terminal_ax_return_refused_wide_8616", 0) or 0) + 1
    )
    return True


def _terminal_ax_proven_retval_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, func_addr: int, function: StructuredAstValue
) -> StructuredAstValue:
    """Return the proven terminal AX return expression, or None (recording refusal)."""
    if function is not None:
        retval = _linear_terminal_ax_return_expr_8616(project, codegen, function)
    else:
        retval = _branch_target_return_expr_8616(project, codegen, func_addr)
    if retval is None:
        if os.environ.get("INERTIA_DEBUG_MISSING_AX_RETURN"):
            logging.getLogger(__name__).warning(
                "[missing-ax-return] refused no terminal AX proof func=%#x function=%r",
                func_addr,
                function,
            )
        codegen._inertia_missing_terminal_ax_return_refused_8616 = (
            int(getattr(codegen, "_inertia_missing_terminal_ax_return_refused_8616", 0) or 0) + 1
        )
    return retval


def _replace_artifact_return_8616(
    root: StructuredAstValue,
    cfunc: StructuredAstValue,
    codegen: StructuredAstValue,
    project: StructuredAstValue,
    artifact_return: StructuredAstValue,
    retval: StructuredAstValue,
) -> StructuredAstValue:
    """Rewrite the artifact return in place; returns the replaced fingerprint."""
    replaced_return_keys = _c_variables_read_by_expr_8616(getattr(artifact_return, "retval", None))
    replaced_fingerprint = None
    with contextlib.suppress(Exception):
        replaced_fingerprint = _expr_fingerprint(getattr(artifact_return, "retval", None), project)
    artifact_return.retval = retval
    cfunc.statements = root
    if hasattr(cfunc, "body"):
        cfunc.body = root
    _prune_replaced_insert_artifact_assignments_8616(root, replaced_return_keys, codegen)
    return replaced_fingerprint


def _publish_cfunc_root_8616(cfunc: StructuredAstValue, root: StructuredAstValue) -> None:
    cfunc.statements = root
    if hasattr(cfunc, "body"):
        cfunc.body = root


def _apply_terminal_ax_replacement_8616(
    root: StructuredAstValue,
    cfunc: StructuredAstValue,
    codegen: StructuredAstValue,
    statements: StructuredAstValue,
    unsupported_return_nodes: list,
    retval: StructuredAstValue,
) -> bool:
    """Apply the unsupported-AIL-return or append-terminal-return replacement."""
    if len(unsupported_return_nodes) == 1:
        if not _replace_unsupported_ail_return_8616(root, codegen, retval, unsupported_return_nodes[0]):
            return False
        _publish_cfunc_root_8616(cfunc, root)
        codegen._inertia_missing_terminal_ax_return_replaced_unsupported_ail_return_8616 = (
            int(
                getattr(
                    codegen,
                    "_inertia_missing_terminal_ax_return_replaced_unsupported_ail_return_8616",
                    0,
                )
                or 0
            )
            + 1
        )
        return True
    updated = list(statements)
    updated.append(CReturn(retval, codegen=codegen))
    root.statements = updated if isinstance(statements, list) else tuple(updated)
    _publish_cfunc_root_8616(cfunc, root)
    return True


def _terminal_ax_proven_retval_or_none_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, cfunc: StructuredAstValue
) -> StructuredAstValue:
    """Resolve the function context and proven retval, or None on refusal."""
    context = _terminal_ax_return_function_context_8616(project, codegen, cfunc)
    if context is None:
        return None
    func_addr, function, _concrete_return_types = context
    if not isinstance(func_addr, int):
        return None
    return _terminal_ax_proven_retval_8616(project, codegen, func_addr, function)


def _materialize_missing_terminal_ax_return_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:
    """Materialize a proven terminal AX return as a guarded compatibility fallback."""
    # Dynamic angr/codegen compatibility boundary: structuring owner flags are attached during staged codegen.
    if getattr(codegen, "_inertia_missing_terminal_ax_return_structuring_pass_ran_8616", False):
        return False
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    surface = _terminal_ax_return_surface_8616(codegen, cfunc)
    if surface is None:
        return False
    root, statements, return_nodes, unsupported_return_nodes = surface
    if _terminal_ax_wide_gate_8616(codegen, return_nodes):
        return False
    artifact_verdict, artifact_return = _select_artifact_return_8616(root, return_nodes)
    if artifact_verdict == "refuse":
        return False

    retval = _terminal_ax_proven_retval_or_none_8616(project, codegen, cfunc)
    if retval is None:
        return False
    replaced_fingerprint = None
    if artifact_return is not None:
        replaced_fingerprint = _replace_artifact_return_8616(
            root, cfunc, codegen, project, artifact_return, retval
        )
    elif not _apply_terminal_ax_replacement_8616(
        root, cfunc, codegen, statements, unsupported_return_nodes, retval
    ):
        return False
    _record_terminal_ax_materialization_8616(codegen, project, retval, replaced_fingerprint)
    return True



def _return_expr_has_insert_artifact_8616(expr: StructuredAstValue) -> bool:
    if expr is None:
        return False
    debug = bool(os.environ.get("INERTIA_DEBUG_MISSING_AX_RETURN"))
    for node in _iter_c_nodes_deep_8616(expr):
        if not isinstance(node, CFunctionCall):
            continue
        callee = node.callee_target
        if callee is None:
            callee = getattr(node, "callee", None)
        if debug:
            logging.getLogger(__name__).warning(
                "[missing-ax-return] return-call-artifact candidate callee_target=%r callee=%r attrs=%r",
                node.callee_target,
                getattr(node, "callee", None),
                _boundary_tuple_8616(
                    sorted(k for k in getattr(node, "__dict__", {}) if "callee" in k or "target" in k or "name" in k)
                ),
            )
        text = str(callee or "")
        if text in {"_INSERT", "__INSERT"} or text.endswith("._INSERT"):
            return True
    return False


def _call_callee_name_8616(node: StructuredAstValue) -> str | None:
    callee = getattr(node, "callee_target", None)
    if callee is None:
        callee = getattr(node, "callee", None)
    name = getattr(callee, "name", None)
    if isinstance(name, str):
        return name
    if isinstance(callee, str):
        return callee
    return None


def _c_const_int_value_8616(node: StructuredAstValue) -> int | None:
    return (
        int(getattr(node, "value", 0))
        if isinstance(node, CConstant) and isinstance(getattr(node, "value", None), int)
        else None
    )


def _expr_has_segment_scale_8616(node: StructuredAstValue) -> bool:
    for child in _iter_c_nodes_deep_8616(node):
        if not isinstance(child, CBinaryOp):
            continue
        op = child.op
        lhs_const = _c_const_int_value_8616(child.lhs)
        rhs_const = _c_const_int_value_8616(child.rhs)
        if op == "Mul" and (lhs_const == 16 or rhs_const == 16):
            return True
        if op == "Shl" and rhs_const == 4:
            return True
    return False


def _return_expr_has_segmented_linear_artifact_8616(expr: StructuredAstValue) -> bool:
    if expr is None:
        return False

    for node in _iter_c_nodes_deep_8616(expr):
        if isinstance(node, CFunctionCall) and _call_callee_name_8616(node) in {"SEG_U8", "SEG_U16", "SEG_U32"}:
            return True
        if isinstance(node, CUnaryOp) and getattr(node, "op", None) == "Dereference":  # noqa: SIM102
            if _expr_has_segment_scale_8616(node.operand):
                return True
    return False



def _return_expr_has_generic_register_artifact_8616(expr: StructuredAstValue) -> bool:
    if expr is None:
        return False
    artifact_name_re = re.compile(r"^(?:v\d+|vvar_\d+|ir_\d+(?:_\d+)?)$")
    debug = bool(os.environ.get("INERTIA_DEBUG_MISSING_AX_RETURN"))
    seen_debug: list[tuple[str, tuple[str, ...]]] = []

    def _cvariable_names(node: StructuredAstValue) -> tuple[str, ...]:
        names: list[str] = []
        for source in (
            node,
            getattr(node, "variable", None),
            getattr(node, "unified_variable", None),
        ):
            name = getattr(source, "name", None)
            if isinstance(name, str) and name:
                names.append(name)
        return tuple(dict.fromkeys(names))

    for node in _iter_c_nodes_deep_8616(expr):
        if not isinstance(node, CVariable):
            continue
        names = _cvariable_names(node)
        if debug:
            seen_debug.append((type(node.variable).__name__, names))
        if any(artifact_name_re.fullmatch(name) for name in names):
            return True
    if debug and seen_debug:
        logging.getLogger(__name__).warning("[missing-ax-return] generic-artifact vars=%r", tuple(seen_debug))
    return False


def _return_expr_node_is_pointer_typed_8616(node: StructuredAstValue) -> bool:
    node_type = getattr(node, "variable_type", None)
    if isinstance(node_type, SimTypePointer):
        return True
    if isinstance(node, CTypeCast):
        dst_type = node.dst_type
        return isinstance(dst_type, SimTypePointer)
    return False


def _untyped_deref_artifact_node_8616(node: StructuredAstValue) -> bool:
    """Return True when this node is a dereference through an untyped/dirty operand."""
    if not isinstance(node, CUnaryOp) or getattr(node, "op", None) != "Dereference":
        return False
    operand = getattr(node, "operand", None)
    if any(isinstance(child, CDirtyExpression) for child in _iter_c_nodes_deep_8616(operand)):
        return True
    while isinstance(operand, CTypeCast) and not _return_expr_node_is_pointer_typed_8616(operand):
        operand = getattr(operand, "expr", None)
    return not _return_expr_node_is_pointer_typed_8616(operand)


def _return_expr_has_untyped_dereference_artifact_8616(expr: StructuredAstValue) -> bool:
    if expr is None:
        return False
    debug = bool(os.environ.get("INERTIA_DEBUG_MISSING_AX_RETURN"))
    seen_debug: list[tuple[str, StructuredAstValue, StructuredAstValue]] = []

    for node in _iter_c_nodes_deep_8616(expr):
        if debug:
            seen_debug.append((type(node).__name__, getattr(node, "op", None), getattr(node, "name", None)))
        if _untyped_deref_artifact_node_8616(node):
            return True
    if debug and seen_debug:
        logging.getLogger(__name__).warning("[missing-ax-return] deref-artifact nodes=%r", tuple(seen_debug))
    return False



def _return_expr_has_dirty_carrier_artifact_8616(expr: StructuredAstValue) -> bool:
    if expr is None:
        return False
    return any(isinstance(node, CDirtyExpression) for node in _iter_c_nodes_deep_8616(expr))


def _return_safety_has_call_or_memory_effect_8616(node: StructuredAstValue) -> bool:
    for child in _iter_c_nodes_deep_8616(node):
        if isinstance(child, CFunctionCall):
            return True
        if isinstance(child, CUnaryOp) and getattr(child, "op", None) == "Dereference":
            return True
    return False


def _return_safety_contains_return_node_8616(node: StructuredAstValue, return_node: CReturn) -> bool:
    if node is return_node:
        return True
    return any(child is return_node for child in _iter_c_nodes_deep_8616(node))


def _return_safety_is_control_node_8616(node: StructuredAstValue) -> bool:
    return type(node).__name__ in {
        "CBreak",
        "CContinue",
        "CDoWhileLoop",
        "CForLoop",
        "CGoto",
        "CIfElse",
        "CSwitchCase",
        "CWhileLoop",
    }


def _return_safety_refuse_8616(debug: bool, log: StructuredAstValue, kind: str, stmt: StructuredAstValue) -> bool:
    if debug:
        if kind:
            log.warning(
                "[missing-ax-return] generic artifact replacement refused %s stmt=%s",
                kind,
                type(stmt).__name__,
            )
        else:
            log.warning(
                "[missing-ax-return] generic artifact replacement refused stmt=%s", type(stmt).__name__
            )
    return False


def _return_safety_stmt_verdict_8616(
    stmt: StructuredAstValue, return_node: CReturn, debug: bool, log: StructuredAstValue
) -> bool | None:
    """Return True/False verdict for this statement, or None to keep scanning."""
    if stmt is return_node:
        return True
    if isinstance(stmt, CAssignment):
        if _return_safety_has_call_or_memory_effect_8616(stmt.lhs):
            return _return_safety_refuse_8616(debug, log, "lhs-effect", stmt)
        if _return_safety_has_call_or_memory_effect_8616(stmt.rhs):
            return _return_safety_refuse_8616(debug, log, "rhs-effect", stmt)
        return None
    if isinstance(stmt, CReturn):
        return stmt is return_node
    if _return_safety_contains_return_node_8616(stmt, return_node):
        return not _return_safety_is_control_node_8616(stmt) and not _return_safety_has_call_or_memory_effect_8616(stmt)
    if _return_safety_is_control_node_8616(stmt):
        return _return_safety_refuse_8616(debug, log, "control", stmt)
    if not _return_safety_has_call_or_memory_effect_8616(stmt):
        return None
    return _return_safety_refuse_8616(debug, log, "", stmt)


def _generic_return_replacement_is_side_effect_free_8616(root: StructuredAstValue, return_node: CReturn) -> bool:
    statements = getattr(root, "statements", None)
    if not isinstance(statements, (list, tuple)):
        return False
    debug = bool(os.environ.get("INERTIA_DEBUG_MISSING_AX_RETURN"))
    log = logging.getLogger(__name__)

    for stmt in statements:
        verdict = _return_safety_stmt_verdict_8616(stmt, return_node, debug, log)
        if verdict is not None:
            return verdict
    return False



def _c_variable_key_8616(expr: StructuredAstValue) -> tuple[StructuredAstValue, ...] | None:
    if not isinstance(expr, CVariable):
        return None
    variable = expr.variable
    if variable is not None:
        return (
            type(variable).__name__,
            getattr(variable, "name", None),
            getattr(variable, "offset", None),
            getattr(variable, "reg", None),
            getattr(variable, "size", None),
        )
    name = expr.name
    return ("CVariable", name) if name is not None else None


def _c_variables_read_by_expr_8616(expr: StructuredAstValue) -> frozenset[tuple[StructuredAstValue, ...]]:
    keys: set[tuple[StructuredAstValue, ...]] = set()
    if expr is None:
        return frozenset()
    for node in _iter_c_nodes_deep_8616(expr):
        key = _c_variable_key_8616(node)
        if key is not None:
            keys.add(key)
    return frozenset(keys)


def _iter_structured_children_for_reads_8616(node: StructuredAstValue) -> StructuredAstValue:
    for attr in _C_AST_CHILD_ATTRS_8616:
        value = None
        with contextlib.suppress(Exception):
            value = getattr(node, attr)
        if value is None:
            continue
        if isinstance(value, dict):
            yield from value.values()
        elif isinstance(value, (list, tuple, set, frozenset)):
            yield from value
        else:
            yield value


def _c_variables_read_by_tree_8616(root: StructuredAstValue) -> frozenset[tuple[StructuredAstValue, ...]]:
    keys: set[tuple[StructuredAstValue, ...]] = set()
    seen: set[int] = set()

    def _walk(node: StructuredAstValue) -> None:
        if node is None:
            return
        if isinstance(node, (list, tuple, set, frozenset)):
            for item in node:
                _walk(item)
            return
        node_id = id(node)
        if node_id in seen:
            return
        seen.add(node_id)
        if isinstance(node, CVariable):
            key = _c_variable_key_8616(node)
            if key is not None:
                keys.add(key)
            return
        if isinstance(node, CAssignment):
            _walk(node.rhs)
            return
        for child in _iter_structured_children_for_reads_8616(node):
            _walk(child)

    _walk(root)
    return frozenset(keys)


def _return_depends_on_insert_artifact_8616(root: StructuredAstValue, return_node: CReturn) -> bool:
    read_keys = _c_variables_read_by_expr_8616(getattr(return_node, "retval", None))
    if not read_keys:
        return False
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CAssignment):
            continue
        lhs_key = _c_variable_key_8616(node.lhs)
        if lhs_key is None or lhs_key not in read_keys:
            continue
        if _return_expr_has_insert_artifact_8616(node.rhs):
            return True
    return False


def _prune_replaced_insert_artifact_assignments_8616(
    root: StructuredAstValue,
    replaced_return_keys: frozenset[tuple[StructuredAstValue, ...]],
    codegen: StructuredAstValue,
) -> int:
    remaining_reads = _c_variables_read_by_tree_8616(root)
    pruned = 0
    for block in tuple(node for node in (root, *_iter_c_nodes_deep_8616(root)) if isinstance(node, CStatements)):
        statements = getattr(block, "statements", None)
        if not isinstance(statements, (list, tuple)):
            continue
        updated = []
        changed = False
        for stmt in statements:
            if isinstance(stmt, CAssignment):
                lhs_key = _c_variable_key_8616(stmt.lhs)
                if (
                    lhs_key is not None
                    and lhs_key not in remaining_reads
                    and _return_expr_has_insert_artifact_8616(stmt.rhs)
                ):
                    pruned += 1
                    changed = True
                    continue
            updated.append(stmt)
        if changed:
            block.statements = updated if isinstance(statements, list) else tuple(updated)
    if pruned:
        codegen._inertia_missing_terminal_ax_return_artifact_assignments_pruned_8616 = (
            int(getattr(codegen, "_inertia_missing_terminal_ax_return_artifact_assignments_pruned_8616", 0) or 0)
            + pruned
        )
    return pruned


@dataclass
class _StackBytePairScan8616:
    """Instruction scan collecting byte-store facts for the pair-return materializer."""

    codegen: StructuredAstValue
    byte_stores: dict[int, StructuredAstValue] = field(default_factory=dict)
    al_source: StructuredAstValue = None
    returned_base: int | None = None
    raw_fact_count: int = 0
    classified_fact_count: int = 0

    @staticmethod
    def _reg_name(insn: StructuredAstValue, operand: StructuredAstValue) -> str | None:
        with contextlib.suppress(Exception):
            return str(insn.reg_name(operand.reg)).lower()
        return None

    @staticmethod
    def _bp_mem_disp(insn: StructuredAstValue, operand: StructuredAstValue, *, size: int | None = None) -> int | None:
        if int(getattr(operand, "type", -1)) != 3:
            return None
        if size is not None and int(getattr(operand, "size", 0) or 0) != size:
            return None
        mem = operand.mem
        if str(insn.reg_name(mem.base)).lower() != "bp":
            return None
        disp = getattr(mem, "disp", None)
        return int(disp) if isinstance(disp, int) else None

    def _stack_byte_expr(self, disp: int) -> StructuredAstValue:
        return _jcc._stack_slot_expr_8616(self.codegen, int(disp), 1)

    def scan(self, insns: StructuredAstValue) -> None:
        for insn in insns:
            self._classify(insn)

    def _classify(self, insn: StructuredAstValue) -> None:
        mnemonic = str(getattr(insn, "mnemonic", "")).lower()
        operands = _boundary_tuple_8616(getattr(insn, "operands", ()) or ())
        if mnemonic != "mov" or len(operands) != 2:
            return
        dst, src = operands
        if int(getattr(dst, "type", -1)) == 1 and self._reg_name(insn, dst) == "al":
            self._classify_al_load(insn, src)
            return
        if int(getattr(dst, "type", -1)) == 3 and int(getattr(dst, "size", 0) or 0) == 1:
            self._classify_byte_store(insn, dst, src)
            return
        if int(getattr(dst, "type", -1)) == 1 and self._reg_name(insn, dst) == "ax":
            self._classify_ax_load(insn, src)

    def _classify_al_load(self, insn: StructuredAstValue, src: StructuredAstValue) -> None:
        src_disp = self._bp_mem_disp(insn, src, size=1)
        if src_disp is not None:
            self.raw_fact_count += 1
            self.al_source = self._stack_byte_expr(src_disp)
            if self.al_source is not None:
                self.classified_fact_count += 1

    def _classify_byte_store(self, insn: StructuredAstValue, dst: StructuredAstValue, src: StructuredAstValue) -> None:
        dst_disp = self._bp_mem_disp(insn, dst, size=1)
        if dst_disp is not None and int(getattr(src, "type", -1)) == 1 and self._reg_name(insn, src) == "al":
            self.raw_fact_count += 1
            if self.al_source is not None:
                self.byte_stores[int(dst_disp)] = _clone_c_value_for_codegen_tree_8616(self.al_source)
                self.classified_fact_count += 1

    def _classify_ax_load(self, insn: StructuredAstValue, src: StructuredAstValue) -> None:
        src_disp = self._bp_mem_disp(insn, src, size=2)
        if src_disp is not None and src_disp in self.byte_stores and src_disp + 1 in self.byte_stores:
            self.raw_fact_count += 1
            self.returned_base = int(src_disp)
            self.classified_fact_count += 1


def _materialize_stack_byte_pair_return_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:
    """Recover word returns built by storing adjacent stack bytes then loading the word."""
    insns = _linear_function_insns_for_codegen_8616(project, codegen)
    if not insns:
        return False

    scan = _StackBytePairScan8616(codegen)
    scan.scan(insns)

    stats = {
        "raw_fact_count": scan.raw_fact_count,
        "classified_fact_count": scan.classified_fact_count,
        "materialized_count": 0,
        "failure_count": 0,
    }
    codegen._inertia_stack_byte_pair_return_stats_8616 = stats
    if scan.returned_base is None:
        if scan.raw_fact_count:
            stats["failure_count"] = 1
        return False

    low_expr = scan.byte_stores.get(scan.returned_base)
    high_expr = scan.byte_stores.get(scan.returned_base + 1)
    if low_expr is None or high_expr is None:
        stats["failure_count"] = 1
        return False

    high_shift = CBinaryOp(
        "Shl",
        _clone_c_value_for_codegen_tree_8616(high_expr),
        CConstant(8, SimTypeChar(False), codegen=codegen),
        codegen=codegen,
    )
    return_expr = CBinaryOp(
        "Or",
        _clone_c_value_for_codegen_tree_8616(low_expr),
        high_shift,
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        statements=[CReturn(return_expr, codegen=codegen)],
        codegen=codegen,
    )
    stats["materialized_count"] = 1
    codegen._inertia_stack_byte_pair_return_materialized_8616 = True
    return True



def _materialize_stack_byte_pair_return_pass_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:
    """Compatibility fallback for structuring-owned stack-byte pair returns."""
    # Dynamic boundary: legacy angr codegen only has this flag after structuring return-chain priming runs.
    if getattr(codegen, "_inertia_stack_byte_pair_return_structuring_pass_ran_8616", False):
        return False
    return _materialize_stack_byte_pair_return_8616(project, codegen)


def _materialize_global_byte_index_sum_loop_postprocess_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Compatibility fallback for structuring-owned global byte-index sum loops."""
    # Dynamic boundary: legacy angr codegen only has this flag after structuring loop idiom priming runs.
    if getattr(codegen, "_inertia_loop_idiom_structuring_pass_ran_8616", False):
        return False
    return _materialize_global_byte_index_sum_loop_8616(project, codegen)


def _materialize_direct_global_incdec_instructions_postprocess_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Run direct global inc/dec lowering from the guarded postprocess compatibility hook."""
    # Dynamic boundary: legacy angr codegen only has this flag after the structuring direct-instruction facade runs.
    if getattr(codegen, "_inertia_direct_global_incdec_materialization_structuring_pass_ran_8616", False):
        return False
    function = _current_postprocess_function_for_codegen_8616(project, codegen)
    return require_result_type_8616(
        materialize_direct_global_incdec_instructions_8616(codegen, project=project, function=function),
        bool,
        owner="lowering.real_mode_linear.materialize_direct_global_incdec_instructions_8616",
    )


def _materialize_direct_stack_incdec_instructions_postprocess_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Run direct stack inc/dec lowering from the postprocess compatibility hook."""
    # Dynamic boundary: legacy angr codegen only has this flag after the structuring stack materializer runs.
    if getattr(codegen, "_inertia_direct_stack_materialization_structuring_pass_ran_8616", False):
        return False
    function = _current_postprocess_function_for_codegen_8616(project, codegen)
    return require_result_type_8616(
        materialize_direct_stack_incdec_instructions_8616(codegen, project=project, function=function),
        bool,
        owner="lowering.real_mode_linear.materialize_direct_stack_incdec_instructions_8616",
    )


def _materialize_direct_stack_mov_instructions_postprocess_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, *, allow_stack_slot_fallback: bool = True
) -> bool:
    """Run direct stack-move lowering from the postprocess compatibility hook."""
    # Dynamic boundary: legacy angr codegen only has this flag after the structuring stack materializer runs.
    if getattr(codegen, "_inertia_direct_stack_materialization_structuring_pass_ran_8616", False):
        return False
    # Dynamic boundary: codegen carries optional per-pass validation state.
    if bool(getattr(codegen, "_inertia_skip_per_pass_validation_large_function", False)) and bool(
        getattr(codegen, "_inertia_pre_validation_stack_semantics_primed", False)
    ):
        stats = getattr(codegen, "_inertia_direct_stack_move_lowering_8616", None)
        if isinstance(stats, dict) and int(stats.get("raw_fact_count", 0) or 0) > 0:
            codegen._inertia_direct_stack_mov_postprocess_repeat_refused_large_function_8616 = (
                int(
                    getattr(
                        codegen,
                        "_inertia_direct_stack_mov_postprocess_repeat_refused_large_function_8616",
                        0,
                    )
                    or 0
                )
                + 1
            )
            return False
    function = _current_postprocess_function_for_codegen_8616(project, codegen)
    return require_result_type_8616(
        materialize_direct_stack_mov_instructions_8616(
            codegen, project=project, function=function, allow_stack_slot_fallback=allow_stack_slot_fallback
        ),
        bool,
        owner="lowering.real_mode_linear.materialize_direct_stack_mov_instructions_8616",
    )


def _prune_unsupported_function_pointer_stack_move_assignments_postprocess_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
) -> bool:
    function = _current_postprocess_function_for_codegen_8616(project, codegen)
    return require_result_type_8616(
        prune_unsupported_function_pointer_stack_move_assignments_8616(
            codegen,
            project=project,
            function=function,
        ),
        bool,
        owner="lowering.real_mode_linear.prune_unsupported_function_pointer_stack_move_assignments_8616",
    )


def _materialize_direct_stack_mov_incdec_instructions_bootstrap_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    function = _current_postprocess_function_for_codegen_8616(project, codegen)
    changed = bool(
        materialize_direct_stack_mov_instructions_8616(
            codegen,
            project=project,
            function=function,
            allow_stack_slot_fallback=True,
        )
    )
    changed = (
        bool(
            materialize_direct_stack_incdec_instructions_8616(
                codegen,
                project=project,
                function=function,
            )
        )
        or changed
    )
    return changed


def _materialize_callsite_stack_arguments_with_target_identity_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
) -> bool:
    """Replay the Types/Lowering target identity after legacy argument rebuilding."""
    changed = bool(_calls._materialize_callsite_stack_arguments_8616(project, codegen))
    return bool(_calls._replay_call_target_identity_consumer_8616(project, codegen)) or changed


def _materialize_callsite_stack_arguments_preserve_setup_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Run callsite stack-argument materialization while preserving setup statements."""
    _calls._bind_segment_push_source_lowerer_8616(
        codegen,
        runtime_segment_push_source_cvar_8616,
    )
    controls = _calls._ensure_callsite_materialization_controls_8616(codegen)
    previous_consumed_arg_store_prune = controls._inertia_callsite_disable_consumed_arg_store_prune_8616
    previous_stack_probe_setup_prune = controls._inertia_callsite_disable_stack_probe_setup_prune_8616
    controls._inertia_callsite_disable_consumed_arg_store_prune_8616 = True
    controls._inertia_callsite_disable_stack_probe_setup_prune_8616 = True
    try:
        return _materialize_callsite_stack_arguments_with_target_identity_8616(project, codegen)
    finally:
        controls._inertia_callsite_disable_consumed_arg_store_prune_8616 = previous_consumed_arg_store_prune
        controls._inertia_callsite_disable_stack_probe_setup_prune_8616 = previous_stack_probe_setup_prune


def _recover_missing_direct_calls_from_evidence_early_postprocess_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Compatibility fallback for structuring-owned early direct-call recovery."""
    # Dynamic boundary: legacy angr codegen only has this flag after structuring callsite priming runs.
    if getattr(codegen, "_inertia_callsite_stack_arguments_structuring_pass_ran_8616", False):
        return False
    return require_result_type_8616(
        _calls._recover_missing_direct_calls_from_evidence_8616(project, codegen),
        bool,
        owner="lowering.callsite_materialization._recover_missing_direct_calls_from_evidence_8616",
    )


def _materialize_callsite_stack_arguments_postprocess_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Compatibility fallback for structuring-owned initial callsite stack arguments."""
    # Dynamic boundary: legacy angr codegen only has this flag after structuring callsite priming runs.
    if getattr(codegen, "_inertia_callsite_stack_arguments_structuring_pass_ran_8616", False):
        return False
    return _materialize_callsite_stack_arguments_preserve_setup_8616(project, codegen)


def _materialize_recovered_callsite_stack_arguments_postprocess_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Compatibility fallback for structuring-owned recovered callsite stack arguments."""
    # Dynamic boundary: legacy angr codegen only has this flag after structuring callsite priming runs.
    if getattr(codegen, "_inertia_callsite_stack_arguments_structuring_pass_ran_8616", False):
        return False
    return _materialize_callsite_stack_arguments_preserve_setup_8616(project, codegen)


def _recover_missing_direct_calls_final_postprocess_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Compatibility fallback for structuring-owned final direct-call recovery."""
    # Dynamic boundary: legacy angr codegen lacks this flag when structuring
    # semantic priming was unavailable.
    if getattr(codegen, "_inertia_callsite_stack_arguments_structuring_pass_ran_8616", False):
        return False
    return require_result_type_8616(
        _calls._recover_missing_direct_calls_from_evidence_8616(project, codegen),
        bool,
        owner="lowering.callsite_materialization._recover_missing_direct_calls_from_evidence_8616",
    )


def _materialize_callsite_stack_arguments_final_postprocess_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Compatibility fallback for structuring-owned final stack arguments."""
    # Dynamic boundary: legacy angr codegen lacks this flag when structuring
    # semantic priming was unavailable.
    if getattr(codegen, "_inertia_callsite_stack_arguments_structuring_pass_ran_8616", False):
        return False
    return _materialize_callsite_stack_arguments_preserve_setup_8616(project, codegen)


def _callsite_after_ss_lowering_rematerialization_unneeded_8616(codegen: StructuredAstValue) -> bool:
    """Read dynamic codegen compatibility state for after-SS callsite evidence gaps."""
    if not bool(getattr(codegen, "_inertia_callsite_materialization_complete_8616", False)):
        return False
    gaps = getattr(codegen, "_inertia_callsite_unmaterialized_arg_gaps_8616", None)
    return isinstance(gaps, tuple) and not gaps


def _materialize_callsite_stack_arguments_after_ss_lowering_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Compatibility fallback for stack arguments after legacy SS lowering."""
    # The normal pipeline owns call argument materialization in structuring.
    # Rewrite must not infer new call semantics from its transformed C AST.
    if getattr(codegen, "_inertia_callsite_stack_arguments_structuring_pass_ran_8616", False):
        return False
    if _callsite_after_ss_lowering_rematerialization_unneeded_8616(codegen):
        codegen._inertia_callsite_after_ss_lowering_skipped_no_gaps_8616 = (
            int(getattr(codegen, "_inertia_callsite_after_ss_lowering_skipped_no_gaps_8616", 0) or 0) + 1
        )
        return False
    return _materialize_callsite_stack_arguments_preserve_setup_8616(project, codegen)


def _materialize_callsite_prototypes_postprocess_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:
    """Compatibility fallback for structuring-owned callsite prototype materialization."""
    # Dynamic boundary: legacy angr codegen only has this flag after structuring semantic priming runs.
    if getattr(codegen, "_inertia_callsite_prototypes_structuring_pass_ran_8616", False):
        return False
    return require_result_type_8616(
        _calls._materialize_callsite_prototypes_8616(project, codegen),
        bool,
        owner="lowering.callsite_materialization._materialize_callsite_prototypes_8616",
    )


def _materialize_stdlib_call_chains_postprocess_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:
    """Compatibility fallback for structuring-owned stdlib call-chain materialization."""
    # Dynamic boundary: legacy angr codegen only has this flag after structuring semantic priming runs.
    if getattr(codegen, "_inertia_stdlib_call_chains_structuring_pass_ran_8616", False):
        return False
    return require_result_type_8616(
        _calls._materialize_stdlib_call_chains_8616(project, codegen),
        bool,
        owner="lowering.callsite_materialization._materialize_stdlib_call_chains_8616",
    )


def _current_postprocess_function_for_codegen_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> StructuredAstValue:
    """Return the active function object carrying exact-region instruction evidence."""
    for candidate in (
        getattr(codegen, "_inertia_current_function_8616", None),
        getattr(codegen, "_func", None),
    ):
        if candidate is not None:
            return candidate
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    with contextlib.suppress(Exception):
        functions = getattr(getattr(project, "kb", None), "functions", None)
        if functions is not None and isinstance(func_addr, int):
            return functions.function(addr=func_addr, create=False)
    return None


def _materialize_direct_stack_mov_instructions_final_postprocess_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    return _materialize_direct_stack_mov_instructions_postprocess_8616(project, codegen, allow_stack_slot_fallback=True)


def _lower_runtime_ss_segment_helpers_to_stack_final_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    changed = require_result_type_8616(
        materialize_runtime_helper_segment_carriers_8616(codegen, project=project),
        bool,
        owner="lowering.segmented_memory_lowering.materialize_runtime_helper_segment_carriers_8616",
    )
    lowered = require_result_type_8616(
        finalize_runtime_stack_lowering_8616(codegen, project=project),
        bool,
        owner="lowering.segmented_memory_lowering.finalize_runtime_stack_lowering_8616",
    )
    return lowered or changed


def _materialize_pointer_arg_indirect_loads_postprocess_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Retain a no-op slot; pointer semantics are owned by Types/Lowering."""
    del project, codegen
    return False


def _build_decompiler_postprocess_passes() -> tuple[DecompilerPostprocessPassSpec, ...]:
    return (
        DecompilerPostprocessPassSpec("_apply_word_global_types_8616", _globals._apply_word_global_types_8616, True),
        DecompilerPostprocessPassSpec("_apply_annotations_8616", _post._apply_annotations_8616, True),
        DecompilerPostprocessPassSpec(
            "_materialize_stable_stack_semantics_early_8616",
            _materialize_stable_stack_semantics_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_promote_stack_prototype_from_bp_loads_8616",
            _post._promote_stack_prototype_from_bp_loads_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_prune_return_address_stack_arguments_8616",
            _post._prune_return_address_stack_arguments_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_prune_unused_unnamed_memory_declarations_8616",
            _globals._prune_unused_unnamed_memory_declarations_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_pointer_memory_idioms_8616",
            _materialize_pointer_memory_idioms_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_global_byte_index_sum_loop_8616",
            _materialize_global_byte_index_sum_loop_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_repair_conditional_continue_guards_from_evidence_8616",
            _repair_conditional_continue_guards_from_evidence_pass_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_repair_pretest_loop_break_guards_from_evidence_8616",
            _repair_pretest_loop_break_guards_from_evidence_pass_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_cfg_selector_return_branches_early_8616",
            _materialize_cfg_selector_return_branches_pass_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_rewrite_decoded_jcc_conditions_8616", _rewrite_decoded_jcc_conditions_pass_8616, True
        ),
        DecompilerPostprocessPassSpec(
            "_repair_hoisted_jcc_target_copies_from_evidence_8616",
            _repair_hoisted_jcc_target_copies_from_evidence_pass_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_rewrite_flag_condition_pairs_8616", _rewrite_flag_condition_pairs_pass_8616, False
        ),
        DecompilerPostprocessPassSpec(
            "_rewrite_flag_bit_value_uses_8616", _rewrite_flag_bit_value_uses_pass_8616, False
        ),
        DecompilerPostprocessPassSpec(
            "_prune_unused_flag_assignments_8616", _flags._prune_unused_flag_assignments_8616, True
        ),
        DecompilerPostprocessPassSpec(
            "_prune_overwritten_flag_assignments_8616", _flags._prune_overwritten_flag_assignments_8616, True
        ),
        DecompilerPostprocessPassSpec(
            "_dead_code_elimination_after_flag_prune_8616", _dead_code_elimination_after_flag_prune_8616, False
        ),
        DecompilerPostprocessPassSpec(
            "_fix_interval_guard_conditions_8616", _fix_interval_guard_conditions_pass_8616, False
        ),
        DecompilerPostprocessPassSpec(
            "_simplify_boolean_cites_8616",
            _simplify._simplify_boolean_cites_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_simplify_structured_expressions_8616",
            _simplify._simplify_structured_expressions_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_maybe_eliminate_single_use_temporaries_8616",
            _simplify._maybe_eliminate_single_use_temporaries_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_attach_callsite_summaries_8616",
            _calls._attach_callsite_summaries_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_recover_missing_direct_calls_from_evidence_early_8616",
            _recover_missing_direct_calls_from_evidence_early_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_lower_stable_ss_stack_accesses_8616",
            _segmented_mem._lower_stable_ss_stack_accesses_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_simplify_structured_expressions_after_stack_lowering_8616",
            _simplify._simplify_structured_expressions_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_normalize_fact_backed_stack_accesses_8616",
            _normalize_fact_backed_stack_accesses_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_stable_stack_semantics_postprocess_8616",
            _materialize_stable_stack_semantics_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_apply_typed_condition_stack_arg_signedness_8616",
            _apply_typed_condition_stack_arg_signedness_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_callsite_stack_arguments_8616",
            _materialize_callsite_stack_arguments_postprocess_8616,
            True,
            call_argument_effect=CallArgumentAstEffect8616.REBUILDS,
        ),
        DecompilerPostprocessPassSpec(
            "_reconcile_exact_stack_argument_prototype_8616",
            reconcile_callsite_interface_declarations_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_prune_consumed_segmented_stack_arg_stores_8616",
            _calls.prune_consumed_segmented_stack_byte_arg_stores_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_dead_code_elimination_after_callsite_stack_arguments_8616",
            _dead_code_elimination_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_direct_global_incdec_instructions_8616",
            _materialize_direct_global_incdec_instructions_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_direct_stack_mov_instructions_8616",
            _materialize_direct_stack_mov_instructions_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_prune_unsupported_function_pointer_stack_move_assignments_8616",
            _prune_unsupported_function_pointer_stack_move_assignments_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_repair_hoisted_jcc_target_copies_after_direct_stack_mov_8616",
            _repair_hoisted_jcc_target_copies_from_evidence_pass_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_direct_stack_incdec_instructions_8616",
            _materialize_direct_stack_incdec_instructions_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_repair_pretest_loop_break_guards_after_direct_stack_incdec_8616",
            _repair_pretest_loop_break_guards_from_evidence_pass_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_missing_terminal_ax_return_8616",
            _materialize_missing_terminal_ax_return_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_stack_byte_pair_return_8616",
            _materialize_stack_byte_pair_return_pass_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_rewrite_decoded_jcc_conditions_after_calls_8616",
            _rewrite_decoded_jcc_conditions_pass_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_repair_hoisted_jcc_target_copies_after_calls_8616",
            _repair_hoisted_jcc_target_copies_from_evidence_pass_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_unconsumed_loop_break_jcc_8616",
            _materialize_unconsumed_loop_break_jcc_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_repair_conditional_continue_guards_after_loop_break_8616",
            _repair_conditional_continue_guards_from_evidence_pass_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_repair_pretest_loop_break_guards_after_loop_break_8616",
            _repair_pretest_loop_break_guards_from_evidence_pass_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_cfg_mask_accumulator_8616",
            _materialize_cfg_mask_accumulator_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_cfg_selector_return_branches_8616",
            _materialize_cfg_selector_return_branches_pass_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_repair_switch_loop_exit_returns_from_evidence_8616",
            _repair_switch_loop_exit_returns_from_evidence_pass_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_empty_if_return_branches_8616",
            _materialize_empty_if_return_branches_pass_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_void_tail_call_guard_from_cfg_8616",
            _materialize_void_tail_call_guard_from_cfg_pass_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_prune_duplicate_empty_return_guard_before_cfg_suffix_8616",
            _prune_duplicate_empty_return_guard_before_cfg_suffix_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_stdlib_call_chains_8616",
            _materialize_stdlib_call_chains_postprocess_8616,
            True,
            call_argument_effect=CallArgumentAstEffect8616.REBUILDS,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_callsite_prototypes_8616",
            _materialize_callsite_prototypes_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_repair_loop_exit_return_guards_8616",
            _repair_loop_exit_return_guards_pass_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_repair_unresolved_function_exit_gotos_8616",
            _repair_unresolved_function_exit_gotos_pass_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_rerun_stack_lowering_consumers_after_calls_8616",
            _rerun_stack_lowering_consumers_after_calls_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_simplify_structured_expressions_after_call_stack_lowering_8616",
            _simplify._simplify_structured_expressions_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_normalize_function_prototype_arg_names_8616",
            _post._normalize_function_prototype_arg_names_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_pointer_arg_indirect_loads_8616",
            _materialize_pointer_arg_indirect_loads_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_normalize_call_target_names_8616",
            _calls._normalize_call_target_names_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_recover_missing_direct_calls_from_evidence_8616",
            _calls._recover_missing_direct_calls_from_evidence_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_recovered_callsite_stack_arguments_8616",
            _materialize_recovered_callsite_stack_arguments_postprocess_8616,
            True,
            call_argument_effect=CallArgumentAstEffect8616.REBUILDS,
        ),
        DecompilerPostprocessPassSpec(
            "_normalize_recovered_call_target_names_8616",
            _calls._normalize_call_target_names_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_collapse_adjacent_unresolved_return_carrier_final_8616",
            _post._collapse_adjacent_unresolved_return_carrier_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_classify_return_shape_8616",
            _post._classify_return_shape_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_prune_surplus_void_empty_return_guards_8616",
            _prune_surplus_void_empty_return_guards_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_dedupe_codegen_variable_names_8616",
            _post._dedupe_codegen_variable_names_8616,
            False,
        ),
        # Final call-floor enforcement: run direct-call recovery after later
        # cleanup passes so subsequent rewrites cannot erase recovered calls.
        DecompilerPostprocessPassSpec(
            "_recover_missing_direct_calls_final_8616",
            _recover_missing_direct_calls_final_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_callsite_stack_arguments_final_8616",
            _materialize_callsite_stack_arguments_final_postprocess_8616,
            True,
            callsite_final_gate=True,
            call_argument_effect=CallArgumentAstEffect8616.REBUILDS,
        ),
        DecompilerPostprocessPassSpec(
            "_prune_consumed_segmented_stack_arg_stores_final_8616",
            _calls.prune_consumed_segmented_stack_byte_arg_stores_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_stable_stack_semantics_final_8616",
            _materialize_stable_stack_semantics_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_dead_code_elimination_after_stable_stack_final_8616",
            _dead_code_elimination_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_direct_stack_mov_instructions_final_8616",
            _materialize_direct_stack_mov_instructions_final_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_repair_hoisted_jcc_target_copies_after_direct_stack_mov_final_8616",
            _repair_hoisted_jcc_target_copies_from_evidence_pass_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_direct_stack_incdec_instructions_final_8616",
            _materialize_direct_stack_incdec_instructions_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_repair_pretest_loop_break_guards_after_direct_stack_incdec_final_8616",
            _repair_pretest_loop_break_guards_from_evidence_pass_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_lower_runtime_ss_segment_helpers_to_stack_final_8616",
            _lower_runtime_ss_segment_helpers_to_stack_final_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_callsite_stack_arguments_after_ss_lowering_8616",
            _materialize_callsite_stack_arguments_after_ss_lowering_8616,
            True,
            call_argument_effect=CallArgumentAstEffect8616.REBUILDS,
        ),
        DecompilerPostprocessPassSpec(
            "_prune_consumed_segmented_stack_arg_stores_after_ss_lowering_8616",
            _calls.prune_consumed_segmented_stack_byte_arg_stores_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_dead_code_elimination_after_ss_callsite_stack_arguments_8616",
            _dead_code_elimination_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_prune_scalar_global_high_byte_call_arg_remnants_after_ss_lowering_8616",
            _calls._prune_scalar_global_high_byte_call_arg_remnants_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_direct_global_incdec_instructions_final_8616",
            _materialize_direct_global_incdec_instructions_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_pointer_arg_indirect_loads_final_8616",
            _materialize_pointer_arg_indirect_loads_postprocess_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_simplify_structured_expressions_after_final_call_materialization_8616",
            _simplify._simplify_structured_expressions_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_normalize_call_target_names_final_8616",
            _calls._normalize_call_target_names_8616,
            False,
            callsite_final_gate=True,
        ),
        DecompilerPostprocessPassSpec(
            "_prune_surplus_void_empty_return_guards_final_8616",
            _prune_surplus_void_empty_return_guards_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_prune_unreachable_after_return_final_8616",
            _prune_unreachable_after_return_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_empty_if_return_branches_final_8616",
            _materialize_empty_if_return_branches_pass_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_materialize_void_tail_call_guard_from_cfg_final_8616",
            _materialize_void_tail_call_guard_from_cfg_pass_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_prune_duplicate_empty_return_guard_before_cfg_suffix_final_8616",
            _prune_duplicate_empty_return_guard_before_cfg_suffix_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_repair_switch_loop_exit_returns_from_evidence_final_8616",
            _repair_switch_loop_exit_returns_from_evidence_pass_8616,
            True,
        ),
        DecompilerPostprocessPassSpec(
            "_dead_code_elimination_final_cleanup_8616",
            _dead_code_elimination_final_cleanup_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_dedupe_equivalent_stack_local_declarations_final_8616",
            dedupe_equivalent_stack_local_declarations_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_normalize_multi_statement_braces_final_8616",
            normalize_multi_statement_braces_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_apply_affine_compound_assignment_identity_final_8616",
            apply_affine_compound_assignment_identity_8616,
            False,
        ),
        DecompilerPostprocessPassSpec(
            "_replay_lowering_projections_after_cleanup_8616",
            replay_final_codegen_projections_8616,
            False,
        ),
    )


def _assert_call_argument_pass_contract_8616(
    passes: tuple[DecompilerPostprocessPassSpec, ...],
) -> None:
    """Fail startup when a known call-argument rebuilder omits its typed postcondition."""
    for spec in passes:
        if (
            (
                "materialize_callsite_stack_arguments" in spec.name
                or spec.name == "_materialize_stdlib_call_chains_8616"
            )
            and spec.call_argument_effect is not CallArgumentAstEffect8616.REBUILDS
        ):
            raise PipelineHardError(
                f"postprocess pass {spec.name!r} must declare call_argument_effect=REBUILDS"
            )


def _run_decompiler_postprocess_pass_spec_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    spec: DecompilerPostprocessPassSpec,
) -> bool:
    """Run one pass and enforce its declared call-argument postcondition."""
    changed = bool(spec.func(project, codegen) if spec.needs_project else spec.func(codegen))
    if spec.call_argument_effect is not CallArgumentAstEffect8616.REBUILDS:
        return changed
    object_replay_changed = reapply_stack_aggregate_object_facts_8616(codegen)
    decay_changed = decay_stack_aggregate_call_arguments_8616(codegen)
    replayed = _boundary_list_8616(
        getattr(codegen, "_inertia_stack_aggregate_decay_replayed_after_passes_8616", ()) or ()
    )
    replayed.append(spec.name)
    codegen._inertia_stack_aggregate_decay_replayed_after_passes_8616 = tuple(replayed)
    return object_replay_changed or decay_changed or changed


DECOMPILER_POSTPROCESS_PASSES: tuple[DecompilerPostprocessPassSpec, ...] = _build_decompiler_postprocess_passes()
_assert_call_argument_pass_contract_8616(DECOMPILER_POSTPROCESS_PASSES)


def _truthy_env_8616(name: str, *, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _apply_skip_names_8616(
    passes: tuple[DecompilerPostprocessPassSpec, ...], skip_names: set[str]
) -> tuple[DecompilerPostprocessPassSpec, ...]:
    if not skip_names:
        return passes
    return tuple(spec for spec in passes if spec.name not in skip_names)


def _wrapper_passes_8616() -> tuple[DecompilerPostprocessPassSpec, ...]:
    wrapper_pass_names = {
        "_lower_stable_ss_stack_accesses_8616",
        "_attach_callsite_summaries_8616",
        "_recover_missing_direct_calls_from_evidence_early_8616",
        "_materialize_callsite_stack_arguments_8616",
        "_materialize_missing_terminal_ax_return_8616",
        "_materialize_recovered_callsite_stack_arguments_8616",
        "_materialize_callsite_prototypes_8616",
        "_rewrite_decoded_jcc_conditions_after_calls_8616",
        "_classify_return_shape_8616",
        "_materialize_empty_if_return_branches_8616",
        "_materialize_void_tail_call_guard_from_cfg_8616",
        "_prune_surplus_void_empty_return_guards_8616",
        "_prune_surplus_void_empty_return_guards_final_8616",
        "_prune_unreachable_after_return_final_8616",
        "_materialize_empty_if_return_branches_final_8616",
        "_materialize_void_tail_call_guard_from_cfg_final_8616",
        "_prune_duplicate_empty_return_guard_before_cfg_suffix_8616",
        "_prune_duplicate_empty_return_guard_before_cfg_suffix_final_8616",
        "_normalize_call_target_names_8616",
        "_normalize_recovered_call_target_names_8616",
    }
    return tuple(
        spec for idx, spec in enumerate(DECOMPILER_POSTPROCESS_PASSES) if spec.name in wrapper_pass_names or idx < 11
    )


def _postprocess_skip_names_8616(codegen: StructuredAstValue) -> set[str]:
    """Collect the environment/priming-driven postprocess pass skip set."""
    skip_names = _env_postprocess_skip_names_8616()
    _add_primed_skip_names_8616(codegen, skip_names)
    _add_gated_skip_names_8616(skip_names)
    return skip_names


def _env_postprocess_skip_names_8616() -> set[str]:
    skip_env = os.environ.get("INERTIA_SKIP_POSTPROCESS_PASSES")
    skip_names: set[str] = set()
    if isinstance(skip_env, str) and skip_env.strip():
        skip_names = {name.strip() for name in skip_env.split(",") if name.strip()}
    if not _fact_backed_stack_normalize_enabled_8616():
        skip_names.add("_normalize_fact_backed_stack_accesses_8616")
    return skip_names


def _add_primed_skip_names_8616(codegen: StructuredAstValue, skip_names: set[str]) -> None:
    """Skip passes whose pre-validation priming already consumed their work."""
    if getattr(codegen, "_inertia_pre_validation_callsite_summaries_primed", False):
        skip_names.add("_attach_callsite_summaries_8616")
    if getattr(codegen, "_inertia_pre_validation_typed_conditions_primed", False):
        skip_names.update(
            {
                "_apply_typed_conditions_to_codegen_8616",
                "_rewrite_decoded_jcc_conditions_8616",
                "_rewrite_decoded_jcc_conditions_after_calls_8616",
            }
        )
    if getattr(codegen, "_inertia_pre_validation_return_address_pruned_8616", False):
        skip_names.add("_prune_return_address_stack_arguments_8616")
    if getattr(codegen, "_inertia_pre_validation_stack_prototype_primed", False):
        skip_names.add("_promote_stack_prototype_from_bp_loads_8616")


def _add_gated_skip_names_8616(skip_names: set[str]) -> None:
    """Skip feature-gated passes: callsite rewrite, floor recovery, simplifies."""
    # Evidence-driven default: keep callsite summary/materialization enabled.
    # Disabling it drops proven call-argument facts and can erase semantics.
    callsite_rewrite_enabled = _truthy_env_8616("INERTIA_ENABLE_CALLSITE_REWRITE", default=True)
    if not callsite_rewrite_enabled:
        skip_names.update(
            {
                "_attach_callsite_summaries_8616",
                "_materialize_callsite_stack_arguments_8616",
                "_materialize_recovered_callsite_stack_arguments_8616",
                "_materialize_callsite_prototypes_8616",
                "_normalize_call_target_names_8616",
                "_normalize_recovered_call_target_names_8616",
            }
        )
    # Legacy rescue only: this pass synthesizes calls after Structuring and
    # cannot prove their placement from the structured AST.  Normal recovery
    # must preserve the original tagged call nodes in the owning earlier layer.
    direct_call_floor_recovery_enabled = _truthy_env_8616(
        "INERTIA_ENABLE_DIRECT_CALL_FLOOR_RECOVERY",
        default=False,
    )
    if not direct_call_floor_recovery_enabled:
        skip_names.update(
            {
                "_recover_missing_direct_calls_from_evidence_8616",
                "_recover_missing_direct_calls_from_evidence_early_8616",
                "_recover_missing_direct_calls_final_8616",
                "_materialize_recovered_callsite_stack_arguments_8616",
                "_materialize_callsite_stack_arguments_final_8616",
                "_normalize_recovered_call_target_names_8616",
                "_normalize_call_target_names_final_8616",
            }
        )
    if not _truthy_env_8616("INERTIA_ENABLE_STRUCTURED_SIMPLIFY_REWRITE"):
        skip_names.add("_simplify_structured_expressions_8616")
    if not _truthy_env_8616("INERTIA_ENABLE_BOOLEAN_SIMPLIFY_REWRITE"):
        skip_names.add("_simplify_boolean_cites_8616")


def _decompiler_postprocess_passes_for_function(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> StructuredAstValue:
    skip_names = _postprocess_skip_names_8616(codegen)

    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if func_addr is None:
        return _apply_skip_names_8616(DECOMPILER_POSTPROCESS_PASSES, skip_names)

    func = project.kb.functions.function(addr=func_addr, create=False)
    if func is None:
        return _apply_skip_names_8616(DECOMPILER_POSTPROCESS_PASSES, skip_names)

    info = getattr(func, "info", None)
    if not isinstance(info, dict):
        return _apply_skip_names_8616(DECOMPILER_POSTPROCESS_PASSES, skip_names)

    profile = info.get("x86_16_decompilation_profile", {})
    if isinstance(profile, dict) and profile.get("wrapper_like"):
        return _apply_skip_names_8616(_wrapper_passes_8616(), skip_names)

    return _apply_skip_names_8616(DECOMPILER_POSTPROCESS_PASSES, skip_names)



def describe_x86_16_decompiler_postprocess_stage() -> tuple[tuple[str, bool], ...]:
    """Return the ordered postprocess pass names and project requirements."""
    return tuple((spec.name, spec.needs_project) for spec in DECOMPILER_POSTPROCESS_PASSES)


def _snapshot_codegen_cfunc(codegen: StructuredAstValue) -> StructuredAstValue:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return None
    try:
        with contextlib.suppress(Exception):
            delattr(codegen, "_inertia_postprocess_snapshot_error")
        return _deepcopy_cfunc_for_validation_8616(cfunc)
    except Exception as ex:
        with contextlib.suppress(Exception):
            codegen._inertia_postprocess_snapshot_error = f"{type(ex).__name__}: {ex}"
        logging.getLogger(__name__).log(
            logging.WARNING if os.environ.get("INERTIA_DEBUG_POSTPROCESS_SNAPSHOT") else logging.DEBUG,
            "Failed to snapshot codegen cfunc at function=%#x stage=postprocess-snapshot: %s",
            getattr(cfunc, "addr", -1) or -1,
            ex,
            exc_info=bool(os.environ.get("INERTIA_DEBUG_POSTPROCESS_SNAPSHOT")),
        )
        return None


def _repair_cfunc_statements_wrapper(codegen: StructuredAstValue) -> bool:
    """Ensure codegen.cfunc.statements/body share one CStatements root.

    Multiple transform() callbacks return plain Python lists instead of
    CStatements objects, which corrupts all downstream passes. This repair
    function is called before every postprocess step to guard against poisoning.
    Validation reads ``body`` first while most postprocess passes update
    ``statements``; keeping both roots synchronized prevents stale-body
    validation against a different AST than the emitted C.
    """
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    statements = getattr(cfunc, "statements", None)
    if statements is None:
        return False
    changed = False
    if isinstance(statements, list) and not isinstance(statements, CStatements):
        statements = CStatements(statements=statements, codegen=codegen)
        cfunc.statements = statements
        changed = True
    if isinstance(statements, CStatements) and getattr(cfunc, "body", None) is not statements:
        with contextlib.suppress(Exception):
            cfunc.body = statements
            changed = True
    return changed


def _set_cfunc_statements_root_8616(codegen: StructuredAstValue, root: CStatements) -> None:
    """Keep the dynamic angr C-function root projections identical."""
    cfunc = codegen.cfunc
    cfunc.statements = root
    with contextlib.suppress(Exception):
        cfunc.body = root


def _restore_codegen_cfunc(codegen: StructuredAstValue, snapshot: StructuredAstValue) -> bool:
    if snapshot is None:
        return False
    codegen.cfunc = snapshot
    with contextlib.suppress(Exception):
        codegen.cfunc.codegen = codegen
    for node in _iter_c_nodes_deep_8616(codegen.cfunc):
        with contextlib.suppress(Exception):
            typing.cast(typing.Any, node).codegen = codegen
    _invalidate_tail_validation_derived_caches_8616(codegen)
    return True


_PROJECT_FUNCTION_METADATA_SNAPSHOT_ATTRS_8616 = (
    "name",
    "prototype",
    "calling_convention",
    "returning",
    "is_prototype_guessed",
    "info",
)


def _project_function_for_postprocess_snapshot_8616(
    project: StructuredAstValue, func_addr: int | None
) -> StructuredAstValue:
    if not isinstance(func_addr, int):
        return None
    functions = getattr(getattr(project, "kb", None), "functions", None)
    lookup = getattr(functions, "function", None)
    if not callable(lookup):
        return None
    with contextlib.suppress(Exception):
        return lookup(addr=func_addr, create=False)
    return None


def _snapshot_project_function_metadata_8616(project: StructuredAstValue, func_addr: int | None) -> StructuredAstValue:
    function = _project_function_for_postprocess_snapshot_8616(project, func_addr)
    if function is None:
        return None
    values = {}
    for attr in _PROJECT_FUNCTION_METADATA_SNAPSHOT_ATTRS_8616:
        if hasattr(function, attr):
            with contextlib.suppress(Exception):
                values[attr] = copy.deepcopy(getattr(function, attr))
    labels = getattr(getattr(project, "kb", None), "labels", None)
    labels_snapshot = copy.deepcopy(labels) if isinstance(labels, MutableMapping) else None
    return {
        "function": function,
        "values": values,
        "labels": labels_snapshot,
        "project": project,
    }


def _restore_project_function_metadata_8616(snapshot: StructuredAstValue) -> bool:
    if not isinstance(snapshot, Mapping):
        return False
    function = snapshot.get("function")
    values = snapshot.get("values")
    if isinstance(values, Mapping):
        for attr, value in values.items():
            if isinstance(attr, str):
                with contextlib.suppress(Exception):
                    setattr(function, attr, copy.deepcopy(value))
    project = snapshot.get("project")
    labels_snapshot = snapshot.get("labels")
    labels = getattr(getattr(project, "kb", None), "labels", None)
    if isinstance(labels, MutableMapping) and isinstance(labels_snapshot, Mapping):
        labels.clear()
        labels.update(copy.deepcopy(dict(labels_snapshot)))
    return True


def _clone_cfunc_validation_fields_8616(
    cfunc: StructuredAstValue, cloned: StructuredAstValue, memo: dict[int, StructuredAstValue]
) -> None:
    """Clone the full CFunction surface used by validation rollback.

    Validation reads more than the statement list: function args, body aliases,
    and structured-codegen slot fields can all carry condition/call/type state.
    A rollback snapshot is only evidence if these fields are independent of the
    live postprocess-mutated function.
    """
    attrs: set[str] = set()
    with contextlib.suppress(Exception):
        attrs.update(_structured_slot_names_8616(cfunc))
    attrs.update(
        {
            "arg_list",
            "body",
            "statements",
            "unified_local_vars",
            "variable_kb",
            "variables_in_use",
        }
    )
    value_dict = getattr(cfunc, "__dict__", None)
    if isinstance(value_dict, dict):
        attrs.update(
            attr
            for attr in value_dict
            if isinstance(attr, str) and not attr.startswith("_") and attr not in _SNAPSHOT_IDENTITY_ATTRS_8616
        )

    source_statements = getattr(cfunc, "statements", None)
    cloned_statements = getattr(cloned, "statements", None)
    for attr in sorted(attrs):
        if attr in _SNAPSHOT_IDENTITY_ATTRS_8616 or not hasattr(cfunc, attr):
            continue
        with contextlib.suppress(Exception):
            value = getattr(cfunc, attr)
            if attr == "body" and value is source_statements:
                setattr(cloned, attr, cloned_statements)
                continue
            setattr(cloned, attr, _snapshot_c_ast_value_for_validation_8616(value, memo))

    with contextlib.suppress(Exception):
        if getattr(cfunc, "body", None) is source_statements:
            cloned.body = cloned.statements


def _snapshot_codegen_inertia_metadata_8616(codegen: StructuredAstValue) -> dict[str, StructuredAstValue]:
    if codegen is None:
        return {}
    attrs = getattr(codegen, "__dict__", {})
    if not isinstance(attrs, dict):
        return {}
    memo: dict[int, StructuredAstValue | None] = {id(codegen): None}
    project = getattr(codegen, "project", None)
    if project is not None:
        memo[id(project)] = None
    snapshot: dict[str, StructuredAstValue] = {}
    for name, value in attrs.items():
        if not isinstance(name, str) or not name.startswith("_inertia_"):
            continue
        if name in _POSTPROCESS_ROLLBACK_METADATA_EXCLUDE_8616:
            continue
        try:
            snapshot[name] = _snapshot_inertia_metadata_value_8616(value, memo)
        except Exception:
            snapshot[name] = value
    return snapshot


def _metadata_snapshot_tuple_8616(
    value: tuple, value_id: int, memo: dict[int, StructuredAstValue | None], depth: int
) -> StructuredAstValue:
    if len(value) > _POSTPROCESS_METADATA_SNAPSHOT_MAX_ITEMS_8616:
        return tuple(value)
    cloned_tuple = tuple(_snapshot_inertia_metadata_value_8616(item, memo, depth=depth + 1) for item in value)
    memo[value_id] = cloned_tuple
    return cloned_tuple


def _metadata_snapshot_list_8616(
    value: list, value_id: int, memo: dict[int, StructuredAstValue | None], depth: int
) -> StructuredAstValue:
    cloned_list: list[StructuredAstValue] = []
    memo[value_id] = cloned_list
    if len(value) > _POSTPROCESS_METADATA_SNAPSHOT_MAX_ITEMS_8616:
        cloned_list.extend(value)
    else:
        cloned_list.extend(_snapshot_inertia_metadata_value_8616(item, memo, depth=depth + 1) for item in value)
    return cloned_list


def _metadata_snapshot_dict_8616(
    value: dict, value_id: int, memo: dict[int, StructuredAstValue | None], depth: int
) -> StructuredAstValue:
    cloned_dict: dict[StructuredAstValue, StructuredAstValue] = {}
    memo[value_id] = cloned_dict
    items = tuple(value.items())
    if len(items) > _POSTPROCESS_METADATA_SNAPSHOT_MAX_ITEMS_8616:
        cloned_dict.update(value)
    else:
        for key, item in items:
            cloned_key = _snapshot_inertia_metadata_value_8616(key, memo, depth=depth + 1)
            cloned_dict[cloned_key] = _snapshot_inertia_metadata_value_8616(item, memo, depth=depth + 1)
    return cloned_dict


def _metadata_snapshot_set_8616(
    value: StructuredAstValue, value_id: int, memo: dict[int, StructuredAstValue | None], depth: int
) -> StructuredAstValue:
    if len(value) > _POSTPROCESS_METADATA_SNAPSHOT_MAX_ITEMS_8616:
        cloned_items = set(value)
    else:
        cloned_items = {_snapshot_inertia_metadata_value_8616(item, memo, depth=depth + 1) for item in value}
    cloned_set = frozenset(cloned_items) if isinstance(value, frozenset) else cloned_items
    memo[value_id] = cloned_set
    return cloned_set


def _snapshot_inertia_metadata_value_8616(
    value: StructuredAstValue, memo: dict[int, StructuredAstValue | None], *, depth: int = 0
) -> StructuredAstValue:
    if isinstance(value, _POSTPROCESS_METADATA_SNAPSHOT_SCALAR_TYPES_8616):
        return value

    value_id = id(value)
    if value_id in memo:
        memo_value = memo[value_id]
        return value if memo_value is None else memo_value

    if depth >= _POSTPROCESS_METADATA_SNAPSHOT_MAX_DEPTH_8616:
        return value

    if isinstance(value, tuple):
        return _metadata_snapshot_tuple_8616(value, value_id, memo, depth)
    if isinstance(value, list):
        return _metadata_snapshot_list_8616(value, value_id, memo, depth)
    if isinstance(value, dict):
        return _metadata_snapshot_dict_8616(value, value_id, memo, depth)
    if isinstance(value, (set, frozenset)):
        return _metadata_snapshot_set_8616(value, value_id, memo, depth)

    # Do not recursively copy arbitrary angr/AIL/codegen objects here. The C AST
    # is snapshotted separately; metadata rollback only needs stable top-level
    # containers and evidence counters.
    return value


def _restore_codegen_inertia_metadata_8616(
    codegen: StructuredAstValue, snapshot: dict[str, StructuredAstValue] | None
) -> None:
    if codegen is None or snapshot is None:
        return
    attrs = getattr(codegen, "__dict__", {})
    if not isinstance(attrs, dict):
        return
    for name in tuple(attrs):
        if (
            isinstance(name, str)
            and name.startswith("_inertia_")
            and name not in _POSTPROCESS_ROLLBACK_METADATA_EXCLUDE_8616
            and name not in snapshot
        ):
            with contextlib.suppress(Exception):
                delattr(codegen, name)
    for name, value in snapshot.items():
        with contextlib.suppress(Exception):
            setattr(codegen, name, value)
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is not None:
        rebind_restored_stack_coordinate_registry_8616(codegen, cfunc)
    _invalidate_tail_validation_derived_caches_8616(codegen)


_IT_COUNT_TYPE = type(itertools.count())
_CTYPES_POINTER_PICKLE_ERROR_8616 = "ctypes objects containing pointers cannot be pickled"
_SNAPSHOT_IDENTITY_ATTRS_8616 = frozenset({"codegen", "project", "arch"})


def _deepcopy_itertools_count_8616(value: StructuredAstValue, memo: StructuredAstValue) -> StructuredAstValue:
    match = re.fullmatch(r"count\(([-+]?\d+)(?:,\s*([-+]?\d+))?\)", repr(value))
    if match is None:
        raise TypeError(f"Unsupported itertools.count repr during validation clone: {value!r}")
    start = int(match.group(1))
    step = int(match.group(2)) if match.group(2) is not None else 1
    cloned = itertools.count(start, step)
    memo[id(value)] = cloned
    return cloned


def _manual_validation_fallback_clone_8616(cfunc: StructuredAstValue) -> StructuredAstValue:
    """Best-effort manual clone used when the primary snapshot path fails."""
    with contextlib.suppress(Exception):
        fallback = copy.copy(cfunc)
        memo = _validation_snapshot_identity_memo_8616(cfunc)
        statements = getattr(cfunc, "statements", None)
        with contextlib.suppress(Exception):
            fallback.statements = _snapshot_c_ast_value_for_validation_8616(statements, memo)
        next_counter = getattr(cfunc, "_next_counter", None)
        if isinstance(next_counter, _IT_COUNT_TYPE):
            fallback._next_counter = _snapshot_c_ast_value_for_validation_8616(next_counter, memo)
        _clone_cfunc_validation_fields_8616(cfunc, fallback, memo)
        with contextlib.suppress(Exception):
            fallback._inertia_validation_snapshot_fallback = "manual"
        return fallback
    return None


def _restore_deepcopy_dispatch_8616(dispatch: StructuredAstValue, previous: StructuredAstValue, sentinel: object) -> None:
    if not isinstance(dispatch, dict):
        return
    if previous is sentinel:
        with contextlib.suppress(Exception):
            del dispatch[_IT_COUNT_TYPE]
    else:
        dispatch[_IT_COUNT_TYPE] = previous


def _deepcopy_cfunc_for_validation_8616(cfunc: StructuredAstValue) -> StructuredAstValue:
    dispatch = getattr(copy, "_deepcopy_dispatch", None)
    sentinel = object()
    previous = sentinel

    if isinstance(dispatch, dict):
        previous = dispatch.get(_IT_COUNT_TYPE, sentinel)
        dispatch[_IT_COUNT_TYPE] = _deepcopy_itertools_count_8616
    try:
        cloned = copy.copy(cfunc)
        # A postprocess validation snapshot is only evidence if statement
        # ownership is independent. C AST nodes still need a valid codegen
        # back-pointer for structured-codegen invariants, so preserve that
        # pointer by identity while preventing deepcopy from traversing the
        # loader/project graph.
        memo: dict[int, StructuredAstValue | None] = _validation_snapshot_identity_memo_8616(cfunc)
        statements = getattr(cfunc, "statements", None)
        try:
            cloned.statements = copy.deepcopy(statements, memo)
        except ValueError as ex:
            if _CTYPES_POINTER_PICKLE_ERROR_8616 not in str(ex):
                raise
            # Some angr/codegen metadata carries ctypes pointers and cannot be
            # pickled by deepcopy. Preserve that metadata by identity while
            # still cloning the emitted C statement tree; otherwise validation
            # cannot safely roll back semantic postprocess regressions.
            memo = _validation_snapshot_identity_memo_8616(cfunc)
            cloned.statements = _snapshot_c_ast_value_for_validation_8616(
                statements,
                memo,
            )
            with contextlib.suppress(Exception):
                cloned._inertia_validation_snapshot_fallback = "ctypes_metadata_identity"
        next_counter = getattr(cfunc, "_next_counter", None)
        if isinstance(next_counter, _IT_COUNT_TYPE):
            cloned._next_counter = _snapshot_c_ast_value_for_validation_8616(next_counter, memo)
        _clone_cfunc_validation_fields_8616(cfunc, cloned, memo)
        return cloned
    except Exception:
        fallback = _manual_validation_fallback_clone_8616(cfunc)
        if fallback is not None:
            return fallback
        raise
    finally:
        _restore_deepcopy_dispatch_8616(dispatch, previous, sentinel)



def _validation_snapshot_identity_memo_8616(cfunc: StructuredAstValue) -> dict[int, StructuredAstValue]:
    """Preserve project-owned boundaries while cloning the structured C tree."""
    memo: dict[int, StructuredAstValue] = {}
    codegen = getattr(cfunc, "codegen", None)
    if codegen is not None:
        memo[id(codegen)] = codegen
        project = getattr(codegen, "project", None)
        if project is not None:
            memo[id(project)] = project
            arch = getattr(project, "arch", None)
            if arch is not None:
                memo[id(arch)] = arch
    root = getattr(cfunc, "statements", None)
    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, CFunctionCall) and node.callee_func is not None:
            memo[id(node.callee_func)] = node.callee_func
    return memo


def _snapshot_itertools_count_8616(
    value: StructuredAstValue, value_id: int, memo: dict[int, StructuredAstValue]
) -> StructuredAstValue:
    match = re.fullmatch(r"count\(([-+]?\d+)(?:,\s*([-+]?\d+))?\)", repr(value))
    if match is None:
        memo[value_id] = value
        return value
    start = int(match.group(1))
    step = int(match.group(2)) if match.group(2) is not None else 1
    cloned_count = itertools.count(start, step)
    memo[value_id] = cloned_count
    return cloned_count


def _snapshot_c_ast_object_8616(
    value: StructuredAstValue, value_id: int, memo: dict[int, StructuredAstValue]
) -> StructuredAstValue:
    """Shallow-clone an object and snapshot its dict/slot attribute values."""
    try:
        cloned = copy.copy(value)
    except Exception:
        memo[value_id] = value
        return value
    memo[value_id] = cloned

    value_dict = getattr(value, "__dict__", None)
    if isinstance(value_dict, dict):
        for attr, attr_value in value_dict.items():
            cloned_value = (
                attr_value
                if attr in _SNAPSHOT_IDENTITY_ATTRS_8616
                else _snapshot_c_ast_value_for_validation_8616(attr_value, memo)
            )
            with contextlib.suppress(Exception):
                setattr(cloned, attr, cloned_value)

    for attr in _structured_slot_names_8616(value):
        if isinstance(value_dict, dict) and attr in value_dict:
            continue
        if not hasattr(value, attr):
            continue
        with contextlib.suppress(Exception):
            setattr(cloned, attr, _snapshot_c_ast_value_for_validation_8616(getattr(value, attr), memo))

    return cloned


def _snapshot_c_ast_value_for_validation_8616(
    value: StructuredAstValue, memo: dict[int, StructuredAstValue]
) -> StructuredAstValue:
    if value is None or isinstance(value, (str, bytes, int, float, bool)):
        return value

    value_id = id(value)
    if value_id in memo:
        return memo[value_id]

    if isinstance(value, _IT_COUNT_TYPE):
        return _snapshot_itertools_count_8616(value, value_id, memo)

    if isinstance(value, list):
        cloned_list: list[StructuredAstValue] = []
        memo[value_id] = cloned_list
        cloned_list.extend(_snapshot_c_ast_value_for_validation_8616(item, memo) for item in value)
        return cloned_list

    if isinstance(value, tuple):
        cloned_tuple = tuple(_snapshot_c_ast_value_for_validation_8616(item, memo) for item in value)
        memo[value_id] = cloned_tuple
        return cloned_tuple

    if isinstance(value, dict):
        cloned_dict: dict[StructuredAstValue, StructuredAstValue] = {}
        memo[value_id] = cloned_dict
        for key, item in value.items():
            cloned_key = _snapshot_c_ast_value_for_validation_8616(key, memo)
            cloned_dict[cloned_key] = _snapshot_c_ast_value_for_validation_8616(item, memo)
        return cloned_dict

    if isinstance(value, (set, frozenset)):
        cloned_items = {_snapshot_c_ast_value_for_validation_8616(item, memo) for item in value}
        cloned_set = frozenset(cloned_items) if isinstance(value, frozenset) else cloned_items
        memo[value_id] = cloned_set
        return cloned_set

    return _snapshot_c_ast_object_8616(value, value_id, memo)


def _clone_codegen_for_validation_summary_8616(codegen: StructuredAstValue) -> StructuredAstValue:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return None
    try:
        cloned_codegen = copy.copy(codegen)
        cloned_codegen.cfunc = _deepcopy_cfunc_for_validation_8616(cfunc)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Failed to clone codegen at function=%#x stage=tail-validation-baseline: %s",
            getattr(cfunc, "addr", -1) or -1,
            ex,
        )
        if os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
            logging.getLogger(__name__).warning(
                "Failed to clone codegen at function=%#x stage=tail-validation-baseline: %s",
                getattr(cfunc, "addr", -1) or -1,
                ex,
                exc_info=True,
            )
        return None
    with contextlib.suppress(Exception):
        cloned_codegen.cfunc.codegen = cloned_codegen
    for node in _iter_c_nodes_deep_8616(cloned_codegen.cfunc):
        with contextlib.suppress(Exception):
            typing.cast(typing.Any, node).codegen = cloned_codegen
    _clear_tail_validation_clone_caches_8616(cloned_codegen)
    rebind_report = rebind_restored_stack_coordinate_registry_8616(
        cloned_codegen,
        (*tuple(getattr(cloned_codegen.cfunc, "arg_list", ()) or ()), cloned_codegen.cfunc),
    )
    cloned_codegen._inertia_validation_clone_stack_coordinate_rebind_8616 = rebind_report
    if rebind_report.failure_count:
        raise PipelineHardError(
            "validation clone stack-coordinate rebinding is incomplete",
            layer="tail_validation",
        )
    return cloned_codegen


def _clear_tail_validation_clone_caches_8616(codegen: StructuredAstValue) -> None:
    # Force validation-side canonicalization to rebuild from the cloned AST
    # instead of reusing stale caches copied from the live codegen.
    for attr in (
        "_inertia_tail_validation_summary_cache",
        "_inertia_assignment_maps",
        "_inertia_vvar_carrier_deltas",
        "_inertia_stack_offset_cache",
        "_inertia_stack_pointer_aliases_for_cvars",
        "_inertia_stack_variable_bindings",
        "_inertia_stack_bindings",
        "_inertia_stack_canonicalization_bridges",
        "_inertia_stack_lowering_debug",
        "_inertia_has_rebound_materialized_recurrence",
        "_inertia_pre_validation_stack_semantics_primed",
        "_inertia_pre_validation_stack_prototype_primed",
        "_inertia_pre_validation_callsite_summaries_primed",
        "_inertia_pre_validation_return_chains_primed",
        "_inertia_recurrence_state",
        "_inertia_cached_text",
        "_inertia_regenerated_text",
        "_inertia_stack_lowered_from_facts",
        "_inertia_semantic_facts_transferred",
        "_inertia_typed_conditions_transferred",
        "_inertia_tail_validation_widened_carriers",
        "_inertia_jcc_register_exprs_by_ins_addr_8616",
    ):
        with contextlib.suppress(Exception):
            setattr(codegen, attr, None)
    with contextlib.suppress(Exception):
        if hasattr(codegen, "_x86_16_tail_validation_cache"):
            delattr(codegen, "_x86_16_tail_validation_cache")


def _invalidate_tail_validation_derived_caches_8616(codegen: StructuredAstValue) -> None:
    # AST-mutating semantic priming and postprocess passes must not reuse
    # fingerprint/summary/assignment-map caches from the previous AST shape.
    for attr in (
        "_inertia_tail_validation_summary_cache",
        "_inertia_assignment_maps",
        "_inertia_stack_offset_cache",
        "_inertia_stack_pointer_aliases_for_cvars",
        "_inertia_jcc_register_exprs_by_ins_addr_8616",
        "_inertia_direct_stack_replay_stable_generation_8616",
        "_inertia_direct_stack_ownership_replay_stable_generation_8616",
        "_inertia_direct_stack_move_ownership_replayed_8616",
    ):
        with contextlib.suppress(Exception):
            setattr(codegen, attr, None)
    with contextlib.suppress(Exception):
        if hasattr(codegen, "_x86_16_tail_validation_cache"):
            delattr(codegen, "_x86_16_tail_validation_cache")


_CODEGEN_TEXT_SNAPSHOT_MISSING_8616 = object()
_CODEGEN_TEXT_SNAPSHOT_ATTRS_8616 = ("text", "_text")


def _snapshot_codegen_text_state_8616(codegen: StructuredAstValue) -> dict[str, StructuredAstValue]:
    if codegen is None:
        return {}
    return {
        attr: getattr(codegen, attr, _CODEGEN_TEXT_SNAPSHOT_MISSING_8616) for attr in _CODEGEN_TEXT_SNAPSHOT_ATTRS_8616
    }


def _restore_codegen_text_state_8616(
    codegen: StructuredAstValue, snapshot: Mapping[str, StructuredAstValue] | None
) -> None:
    if codegen is None or not isinstance(snapshot, Mapping):
        return
    for attr, value in snapshot.items():
        if value is _CODEGEN_TEXT_SNAPSHOT_MISSING_8616:
            with contextlib.suppress(Exception):
                delattr(codegen, attr)
            continue
        with contextlib.suppress(Exception):
            setattr(codegen, attr, value)


def _wc_name_candidates_8616(variable: StructuredAstValue, cvar: StructuredAstValue) -> tuple[str, ...]:
    names: list[str] = []
    for candidate in (
        getattr(cvar, "name", None),
        getattr(variable, "name", None),
    ):
        if isinstance(candidate, str) and candidate and candidate not in names:
            names.append(candidate)
    return tuple(names)


def _wc_parse_stack_slot_fingerprint_8616(
    fingerprint: str,
) -> tuple[int, int | None, str | None] | None:
    if not isinstance(fingerprint, str):
        return None
    if fingerprint.startswith("Reference(") and fingerprint.endswith(")"):
        fingerprint = fingerprint[len("Reference(") : -1]
    match = re.fullmatch(r"stack_slot:SS:BP([+-]0x[0-9a-fA-F]+)(?::size(\d+))?", fingerprint)
    if match is None:
        return None
    try:
        offset = int(match.group(1), 16)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "stack slot fingerprint offset parse failed: %s",
            ex,
        )
        return None
    size_text = match.group(2)
    size = int(size_text) if isinstance(size_text, str) else None
    return offset, size, fingerprint


def _wc_proof_for_slot_8616(
    slot_offset: int, slot_size: int, carrier_size: int, source: str
) -> dict[str, StructuredAstValue]:
    return {"offset": slot_offset, "size": slot_size, "carrier_size": carrier_size, "source": source}


def _wc_record_proof_8616(
    carrier_map: dict[StructuredAstValue, StructuredAstValue],
    variable: StructuredAstValue,
    cvar: StructuredAstValue,
    carrier_size: int,
    proof: dict[str, StructuredAstValue],
) -> None:
    variable_offset = getattr(variable, "offset", None)
    if cvar is not None:
        carrier_map[id(cvar)] = proof
    carrier_map[id(variable)] = proof
    for name in _wc_name_candidates_8616(variable, cvar or variable):
        carrier_map[name] = proof
        carrier_map[(name, carrier_size)] = proof
    if isinstance(variable_offset, int):
        carrier_map[(variable_offset, carrier_size)] = proof


def _wc_collect_recurrence_proofs_8616(
    codegen: StructuredAstValue,
    cfunc: StructuredAstValue,
    carrier_map: dict[StructuredAstValue, StructuredAstValue],
    *,
    c_variable_type: StructuredAstValue,
    sim_stack_variable_type: StructuredAstValue,
    expr_fingerprint: StructuredAstValue,
) -> None:
    recurrence_state = getattr(codegen, "_inertia_recurrence_state", None)
    if recurrence_state is None or not hasattr(recurrence_state, "resolve_known_copy_alias_expr"):
        return
    for walk_node in _iter_c_nodes_deep_8616(getattr(cfunc, "statements", None)):
        if not isinstance(walk_node, c_variable_type):
            continue
        variable = walk_node.variable
        if not isinstance(variable, sim_stack_variable_type):
            continue
        carrier_size = variable.size
        if not isinstance(carrier_size, int) or carrier_size >= 2:
            continue
        try:
            resolved_expr = recurrence_state.resolve_known_copy_alias_expr(walk_node)
            resolved_fp = expr_fingerprint(resolved_expr, codegen.project)
        except Exception as ex:
            logging.getLogger(__name__).debug("stack slot fingerprint via recurrence state failed: %s", ex)
            continue
        slot_info = _wc_parse_stack_slot_fingerprint_8616(resolved_fp)
        if slot_info is None:
            continue
        slot_offset, slot_size, _display = slot_info
        if not isinstance(slot_size, int) or slot_size <= carrier_size:
            continue
        _wc_record_proof_8616(
            carrier_map,
            variable,
            walk_node,
            carrier_size,
            _wc_proof_for_slot_8616(slot_offset, slot_size, carrier_size, "recurrence_state_resolved_expr"),
        )


def _wc_assignment_proof_for_name_8616(
    codegen: StructuredAstValue,
    carrier_map: dict[StructuredAstValue, StructuredAstValue],
    variable: StructuredAstValue,
    cvar: StructuredAstValue,
    carrier_size: int,
    name: str,
    var_id_map: StructuredAstValue,
    name_map: StructuredAstValue,
    first_name_map: StructuredAstValue,
    expr_fingerprint: StructuredAstValue,
) -> None:
    """Record a widened-carrier proof when the name's first assignment resolves to a wider slot."""
    if re.fullmatch(r"(?:arg_\d+|local_\d+|s_[0-9a-fA-F]+|v\d+|vvar_\d+|ir_\d+)", name) is None:
        return
    rhs = first_name_map.get(name) or var_id_map.get(id(variable)) or name_map.get(name)
    if rhs is None:
        return
    try:
        rhs_fp = expr_fingerprint(rhs, codegen.project)
    except Exception as ex:
        logging.getLogger(__name__).debug("rhs fingerprint via name map failed name=%s: %s", name, ex)
        return
    slot_info = _wc_parse_stack_slot_fingerprint_8616(rhs_fp)
    if slot_info is None:
        return
    slot_offset, slot_size, _display = slot_info
    if not isinstance(slot_size, int) or slot_size <= carrier_size:
        return
    _wc_record_proof_8616(
        carrier_map,
        variable,
        cvar,
        carrier_size,
        _wc_proof_for_slot_8616(slot_offset, slot_size, carrier_size, "first_assignment_stack_slot"),
    )


def _wc_collect_assignment_map_proofs_8616(
    codegen: StructuredAstValue,
    carrier_map: dict[StructuredAstValue, StructuredAstValue],
    variables_in_use: dict[StructuredAstValue, StructuredAstValue],
    *,
    function_addr: int,
    sim_stack_variable_type: StructuredAstValue,
    ensure_assignment_maps: StructuredAstValue,
    expr_fingerprint: StructuredAstValue,
) -> None:
    try:
        var_id_map, name_map, _reg_map, _multi_var, _multi_name, _multi_reg, first_name_map, _first_reg_map = (
            ensure_assignment_maps(codegen)
        )
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Tail-validation widened-carrier provenance assignment-map build failed at function=%#x "
            "stage=baseline-canonicalization: %s",
            function_addr,
            ex,
        )
        return
    for variable, cvar in variables_in_use.items():
        if not isinstance(variable, sim_stack_variable_type) or getattr(variable, "base", None) != "bp":
            continue
        carrier_size = getattr(variable, "size", None)
        if not isinstance(carrier_size, int) or carrier_size >= 2:
            continue
        for name in _wc_name_candidates_8616(variable, cvar):
            _wc_assignment_proof_for_name_8616(
                codegen,
                carrier_map,
                variable,
                cvar,
                carrier_size,
                name,
                var_id_map,
                name_map,
                first_name_map,
                expr_fingerprint,
            )


def _attach_tail_validation_widened_carrier_provenance_8616(
    codegen: StructuredAstValue, cfunc: StructuredAstValue, *, function_addr: int
) -> None:
    """Validation-only metadata.

    Attach widened stable-slot provenance to plain byte carriers that are
    already proved to seed from a materialized stack slot on the clone path.
    This is used only by tail-validation fingerprinting and must not mutate
    emitted/live semantics.
    """
    try:
        from angr.analyses.decompiler.structured_codegen.c import CVariable
        from angr.sim_variable import SimStackVariable

        from .lowering.real_mode_linear import _ensure_assignment_maps_8616
        from .tail_validation_fingerprint import _expr_fingerprint
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Tail-validation widened-carrier provenance import failed at function=%#x "
            "stage=baseline-canonicalization: %s",
            function_addr,
            ex,
        )
        return

    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if not isinstance(variables_in_use, dict):
        return
    carrier_map: dict[str, dict[str, StructuredAstValue]] = {}
    _wc_collect_recurrence_proofs_8616(
        codegen,
        cfunc,
        carrier_map,
        c_variable_type=CVariable,
        sim_stack_variable_type=SimStackVariable,
        expr_fingerprint=_expr_fingerprint,
    )
    _wc_collect_assignment_map_proofs_8616(
        codegen,
        carrier_map,
        variables_in_use,
        function_addr=function_addr,
        sim_stack_variable_type=SimStackVariable,
        ensure_assignment_maps=_ensure_assignment_maps_8616,
        expr_fingerprint=_expr_fingerprint,
    )

    if carrier_map:
        codegen._inertia_tail_validation_widened_carriers = carrier_map
        if os.environ.get("INERTIA_DEBUG_TAIL_STACK_ALIAS"):
            logging.getLogger(__name__).warning(
                "[tail-widened-carriers] func=%#x entries=%r",
                function_addr,
                carrier_map,
            )
    elif os.environ.get("INERTIA_DEBUG_TAIL_STACK_ALIAS"):
        logging.getLogger(__name__).warning(
            "[tail-widened-carriers] func=%#x entries=()",
            function_addr,
        )



def _tv_clone_debug_enabled_8616() -> bool:
    return bool(os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"))


def _tv_clone_debug_write_8616(message: str) -> None:
    sys.stderr.write(message)
    sys.stderr.flush()


def _baseline_clone_skip_reason_8616(
    spec: DecompilerPostprocessPassSpec, cloned_codegen: StructuredAstValue
) -> str | None:
    """Return the skip reason for a baseline-clone pass, or None when it must run."""
    if spec.name == "_normalize_fact_backed_stack_accesses_8616":
        return "already applied"
    if spec.name in _selector_return_contract_skip_passes_8616() and _selector_return_contract_active_8616(
        cloned_codegen
    ):
        return "skipped selector-return contract"
    if spec.name == "_rerun_stack_lowering_consumers_after_calls_8616":
        return "skipped validation-clone replay"
    return None


def _replay_baseline_clone_passes_8616(project: StructuredAstValue, cloned_codegen: StructuredAstValue) -> None:
    debug = _tv_clone_debug_enabled_8616()
    pass_start = time.perf_counter() if debug else 0.0
    for spec in _decompiler_postprocess_passes_for_function(project, cloned_codegen):
        skip_reason = _baseline_clone_skip_reason_8616(spec, cloned_codegen)
        if skip_reason is not None:
            if debug:
                _tv_clone_debug_write_8616(f"[dbg] tv-baseline clone pass: {spec.name} {skip_reason}\n")
            continue
        try:
            with analysis_timeout(3):
                _run_decompiler_postprocess_pass_spec_8616(project, cloned_codegen, spec)
        except AnalysisTimeout as ex:
            raise PipelineHardError(
                f"validation baseline clone pass timed out: {spec.name}",
                layer="tail_validation",
            ) from ex
        if debug:
            _tv_clone_debug_write_8616(
                f"[dbg] tv-baseline clone pass: {spec.name} ({time.perf_counter() - pass_start:.3f}s)\n"
            )
            pass_start = time.perf_counter()


def _baseline_clone_stack_lowering_8616(
    project: StructuredAstValue, cloned_codegen: StructuredAstValue, debug_stats: dict[str, int]
) -> None:
    transfer_semantic_alias_facts_to_codegen_8616(project, cloned_codegen)
    alias_facts = getattr(cloned_codegen, "_inertia_semantic_alias_facts", None)
    if isinstance(alias_facts, list):
        debug_stats["validation_clone_stack_alias_facts"] = len(alias_facts)
        if alias_facts:
            lower_stack_accesses_from_alias_facts_8616(cloned_codegen, alias_facts)
    from .lowering.real_mode_linear import lower_stable_ss_linear_stack_dereferences_8616

    lower_stable_ss_linear_stack_dereferences_8616(cloned_codegen, project=project)
    if _fact_backed_stack_normalize_enabled_8616():
        _normalize_fact_backed_stack_accesses_8616(project, cloned_codegen)
    bindings = getattr(cloned_codegen, "_inertia_stack_variable_bindings", None)
    if isinstance(bindings, tuple | list):
        debug_stats["validation_clone_stack_bindings"] = len(bindings)


def _baseline_clone_finalize_stats_8616(
    cloned_codegen: StructuredAstValue, debug_stats: dict[str, int], function_addr: int
) -> None:
    _attach_tail_validation_widened_carrier_provenance_8616(
        cloned_codegen,
        cloned_codegen.cfunc,
        function_addr=function_addr,
    )
    clone_debug = getattr(cloned_codegen, "_inertia_stack_lowering_debug", None)
    if isinstance(clone_debug, dict):
        debug_stats["validation_clone_stack_materialized"] = int(
            clone_debug.get("stack_slot_materialized", 0) or 0
        )
        debug_stats["validation_clone_recurrence_materialized"] = int(
            clone_debug.get("recurrence_bound_to_materialized_local", 0) or 0
        )
    if (
        debug_stats["validation_clone_stack_bindings"] > 0
        and debug_stats["validation_clone_stack_materialized"] == 0
    ):
        raise PipelineHardError(
            "validation baseline clone stack bindings not materialized",
            layer="tail_validation",
        )


def _prepare_tail_validation_baseline_clone_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, *, function_addr: int
) -> StructuredAstValue:
    clone_debug = _tv_clone_debug_enabled_8616()
    if clone_debug:
        _tv_clone_debug_write_8616(
            f"[dbg] tv-baseline clone start: func={function_addr:#x} clone_id={id(codegen)}\n"
        )
        clone_start = time.perf_counter()

    cloned_codegen = _clone_codegen_for_validation_summary_8616(codegen)
    if cloned_codegen is None:
        if clone_debug:
            logging.getLogger(__name__).warning(
                "Tail-validation baseline clone unavailable at function=%#x stage=baseline-canonicalization",
                function_addr,
            )
        return None
    _repair_cfunc_statements_wrapper(cloned_codegen)
    debug_stats = {
        "validation_clone_stack_alias_facts": 0,
        "validation_clone_stack_bindings": 0,
        "validation_clone_stack_materialized": 0,
        "validation_clone_recurrence_materialized": 0,
        "validation_clone_failure_count": 0,
    }
    try:
        _baseline_clone_stack_lowering_8616(project, cloned_codegen, debug_stats)
        _replay_baseline_clone_passes_8616(project, cloned_codegen)
        _baseline_clone_finalize_stats_8616(cloned_codegen, debug_stats, function_addr)
    except Exception:
        debug_stats["validation_clone_failure_count"] += 1
        cloned_codegen._inertia_validation_clone_debug = debug_stats
        if clone_debug:
            _tv_clone_debug_write_8616(
                f"[dbg] tv-baseline clone failed: func={function_addr:#x} err={debug_stats!r}\n"
            )
        raise
    cloned_codegen._inertia_validation_clone_debug = debug_stats
    if clone_debug:
        _tv_clone_debug_write_8616(
            f"[dbg] tv-baseline clone done: func={function_addr:#x} "
            f"elapsed={time.perf_counter() - clone_start:.3f}s\n"
        )
    return cloned_codegen



def _debug_tail_validation_baseline_condition_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, *, function_addr: int, label: str
) -> None:
    def _impl() -> None:
        if not os.environ.get("INERTIA_DEBUG_TV_BASELINE"):
            return
        try:
            from angr.analyses.decompiler.structured_codegen.c import (
                CDoWhileLoop,
                CForLoop,
                CIfBreak,
                CVariable,
                CWhileLoop,
            )

            from .tail_validation_fingerprint import _expr_fingerprint, _lookup_widened_carrier_proof_8616
        except Exception as ex:
            logging.getLogger(__name__).debug(
                "Baseline condition debug import failed at function=%#x stage=%s: %s",
                function_addr,
                label,
                ex,
            )
            return

        log = logging.getLogger(__name__)
        root = getattr(getattr(codegen, "cfunc", None), "statements", None)
        for node_index, node in enumerate(_iter_c_nodes_deep_8616(root)):
            if not isinstance(node, (CForLoop, CWhileLoop, CDoWhileLoop, CIfBreak)):
                continue
            cond = node.condition
            try:
                cond_fp = _expr_fingerprint(cond, project)
            except Exception as ex:
                cond_fp = f"<fingerprint-error:{type(ex).__name__}:{ex}>"
            log.warning(
                "[baseline-cond] %s node_index=%d node=%s cond=%r fp=%s node_tags=%r cond_tags=%r",
                label,
                node_index,
                type(node).__name__,
                cond,
                cond_fp,
                getattr(node, "tags", None),
                getattr(cond, "tags", None),
            )
            for child in _iter_c_nodes_deep_8616(cond):
                if not isinstance(child, CVariable):
                    continue
                variable = child.variable
                resolved_fp = None
                recurrence_state = getattr(codegen, "_inertia_recurrence_state", None)
                if recurrence_state is not None and hasattr(recurrence_state, "resolve_known_copy_alias_expr"):
                    with contextlib.suppress(Exception):
                        resolved_fp = _expr_fingerprint(
                            recurrence_state.resolve_known_copy_alias_expr(child),
                            project,
                        )
                log.warning(
                    "[baseline-cond] %s cvar_id=%s name=%r offset=%r size=%r proof=%r resolved=%r",
                    label,
                    id(child),
                    child.name or getattr(variable, "name", None),
                    getattr(variable, "offset", None),
                    getattr(variable, "size", None),
                    _lookup_widened_carrier_proof_8616(child, child.codegen),
                    resolved_fp,
                )

    return _impl()


def _debug_condition_progress_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, *, function_addr: int, label: str
) -> None:
    if not os.environ.get("INERTIA_DEBUG_CONDITION_PROGRESS"):
        return
    target_text = os.environ.get("INERTIA_DEBUG_CONDITION_PROGRESS_ADDR")
    target_addr = int(target_text, 0) if isinstance(target_text, str) and target_text.strip() else None
    if isinstance(target_addr, int) and function_addr != target_addr:
        return
    try:
        from angr.analyses.decompiler.structured_codegen.c import CForLoop

        from .tail_validation_fingerprint import _expr_fingerprint
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Condition progress debug import failed at function=%#x stage=%s: %s",
            function_addr,
            label,
            ex,
        )
        return
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CForLoop):
            continue
        cond = node.condition
        try:
            cond_fp = _expr_fingerprint(cond, project)
        except Exception as ex:
            cond_fp = f"<fingerprint-error:{type(ex).__name__}:{ex}>"
        logging.getLogger(__name__).warning(
            "[reinitbars-cond] %s fp=%s repr=%r",
            label,
            cond_fp,
            cond,
        )
        break


def _repair_loop_exit_return_guards_8616(codegen: StructuredAstValue) -> bool:
    """Compatibility shim for structuring-owned loop-exit return guard repair."""
    # Dynamic boundary: legacy angr codegen only has this flag after the structuring wrapper runs.
    if getattr(codegen, "_inertia_loop_exit_guard_structuring_pass_ran_8616", False):
        return False
    return require_result_type_8616(
        repair_loop_exit_return_guards_8616(codegen, default_loop_exit_return_guard_callbacks_8616()),
        bool,
        owner="structuring.loop_exit_return_guards.repair_loop_exit_return_guards_8616",
    )


def _coerce_nonnegative_int_8616(value: StructuredAstValue) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int) and value >= 0:
        return value
    return 0


def _postprocess_complexity_from_info_8616(
    info: StructuredAstValue, *, source: str
) -> _PostprocessFunctionComplexity8616:
    if not isinstance(info, MutableMapping):
        return _PostprocessFunctionComplexity8616(source=f"{source}:no_info")
    cached = info.get("_inertia_function_complexity")
    if not isinstance(cached, MutableMapping):
        return _PostprocessFunctionComplexity8616(source=f"{source}:no_cached_complexity")
    block_count = _coerce_nonnegative_int_8616(cached.get("blocks"))
    byte_count = _coerce_nonnegative_int_8616(cached.get("bytes"))
    block_addrs = cached.get("block_addrs")
    if block_count == 0 and isinstance(block_addrs, (tuple, list, set, frozenset)):
        block_count = len(block_addrs)
    if block_count <= 0 and byte_count <= 0:
        return _PostprocessFunctionComplexity8616(source=f"{source}:empty_cached_complexity")
    cached_source = cached.get("source")
    suffix = cached_source if isinstance(cached_source, str) and cached_source else "cached"
    return _PostprocessFunctionComplexity8616(
        block_count=block_count,
        byte_count=byte_count,
        source=f"{source}:{suffix}",
    )


def _postprocess_complexity_from_function_8616(
    function: StructuredAstValue, *, source: str
) -> _PostprocessFunctionComplexity8616:
    if function is None:
        return _PostprocessFunctionComplexity8616(source=f"{source}:missing")
    info_complexity = _postprocess_complexity_from_info_8616(getattr(function, "info", None), source=source)
    if info_complexity.block_count > 0 or info_complexity.byte_count > 0:
        return info_complexity
    local_blocks = _boundary_tuple_8616((getattr(function, "_local_blocks", {}) or {}).values())
    if local_blocks:
        total_bytes = sum(
            _coerce_nonnegative_int_8616(getattr(block, "size", 0) or len(getattr(block, "bytestr", b"") or b""))
            for block in local_blocks
        )
        return _PostprocessFunctionComplexity8616(
            block_count=len(local_blocks),
            byte_count=total_bytes,
            source=f"{source}:local_blocks",
        )
    block_addrs = _boundary_tuple_8616(getattr(function, "block_addrs_set", ()) or ())
    if block_addrs:
        return _PostprocessFunctionComplexity8616(
            block_count=len(block_addrs),
            byte_count=0,
            source=f"{source}:block_addrs_set",
        )
    return _PostprocessFunctionComplexity8616(source=f"{source}:empty_function")


def _lookup_postprocess_kb_function_8616(project: StructuredAstValue, func_addr: int | None) -> StructuredAstValue:
    if not isinstance(func_addr, int) or func_addr < 0:
        return None
    kb_funcs = getattr(getattr(project, "kb", None), "functions", None)
    if kb_funcs is None:
        return None
    try:
        return kb_funcs.function(func_addr, create=False)
    except TypeError:
        try:
            return kb_funcs.function(addr=func_addr, create=False)
        except TypeError:
            return None
    except Exception:
        return None


def _postprocess_function_complexity_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, func_addr: int | None
) -> _PostprocessFunctionComplexity8616:
    current_function = getattr(codegen, "_inertia_current_function_8616", None)
    current_complexity = _postprocess_complexity_from_function_8616(current_function, source="current_function")
    if current_complexity.block_count > 0 or current_complexity.byte_count > 0:
        return current_complexity

    candidates: list[int] = []
    if isinstance(func_addr, int):
        candidates.append(func_addr)
        delta = getattr(project, "_inertia_original_linear_delta", None)
        if isinstance(delta, int):
            candidates.extend((func_addr + delta, func_addr - delta))
    seen: set[int] = set()
    for candidate_addr in candidates:
        if candidate_addr in seen:
            continue
        seen.add(candidate_addr)
        fn = _lookup_postprocess_kb_function_8616(project, candidate_addr)
        kb_complexity = _postprocess_complexity_from_function_8616(fn, source=f"kb:{candidate_addr:#x}")
        if kb_complexity.block_count > 0 or kb_complexity.byte_count > 0:
            return kb_complexity
    return _PostprocessFunctionComplexity8616()


def _collect_direct_tail_summary_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    *,
    mode: str,
    boundary_fingerprint: str | None = None,
) -> X86_16TailValidationSummary:
    return collect_x86_16_tail_validation_summary(
        project,
        codegen,
        mode=mode,
        boundary_fingerprint=boundary_fingerprint,
    )


def _prepare_baseline_clone_or_none_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    *,
    function_addr: int,
) -> StructuredAstValue | None:
    """Canonicalize a baseline clone within a bounded timeout, or return None."""
    try:
        with analysis_timeout(3):
            return _prepare_tail_validation_baseline_clone_8616(
                project,
                codegen,
                function_addr=function_addr,
            )
    except AnalysisTimeout:
        logging.getLogger(__name__).warning(
            "Tail-validation baseline canonicalization timed out at function=%#x; "
            "falling back to direct summary collection",
            function_addr,
        )
        return None
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Tail-validation baseline canonicalization failed at function=%#x "
            "stage=baseline-canonicalization: %s",
            function_addr,
            ex,
        )
        return None


def _debug_baseline_clone_witnesses_8616(cloned_codegen: StructuredAstValue, function_addr: int) -> None:
    if not os.environ.get("INERTIA_DEBUG_TV_BASELINE"):
        return
    logger = logging.getLogger(__name__)
    rs = getattr(cloned_codegen, "_inertia_recurrence_state", None)
    wc = getattr(cloned_codegen, "_inertia_tail_validation_widened_carriers", None)
    logger.warning(
        "[baseline-debug] func=%#x recurrence_state=%s widened_carriers=%s entries=%s",
        function_addr,
        rs is not None,
        bool(wc),
        len(wc) if isinstance(wc, dict) else "N/A",
    )
    if isinstance(wc, dict) and wc:
        for key, proof in list(wc.items())[:6]:
            logger.warning(
                "[baseline-debug] proof key=%r offset=%r size=%r carrier_size=%r source=%r",
                key,
                proof.get("offset"),
                proof.get("size"),
                proof.get("carrier_size"),
                proof.get("source"),
            )


def _collect_tail_validation_summary_with_baseline_canonicalization_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    *,
    mode: str,
    boundary_fingerprint: str | None = None,
    force_baseline_canonicalization: bool = False,
) -> X86_16TailValidationSummary:
    """Collect the canonical typed baseline without erasing validation evidence."""
    canonicalization_setting = os.environ.get("INERTIA_ENABLE_TV_BASELINE_CANONICALIZATION", "1").strip().lower()
    if canonicalization_setting in {"0", "false", "no", "off"}:
        return _collect_direct_tail_summary_8616(
            project, codegen, mode=mode, boundary_fingerprint=boundary_fingerprint
        )
    function_addr = getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1
    if hasattr(codegen, "_inertia_postprocess_mutation_generation_8616") and not force_baseline_canonicalization:
        codegen._inertia_tail_validation_direct_final_summary_count_8616 = (
            int(getattr(codegen, "_inertia_tail_validation_direct_final_summary_count_8616", 0) or 0) + 1
        )
        return _collect_direct_tail_summary_8616(
            project, codegen, mode=mode, boundary_fingerprint=boundary_fingerprint
        )
    # Large functions frequently time out in baseline clone canonicalization.
    # For those, use direct summary collection to keep validation deterministic
    # and avoid repeated timeout churn.
    complexity = _postprocess_function_complexity_8616(project, codegen, function_addr)
    if complexity.is_expensive_for_local_validation:
        return _collect_direct_tail_summary_8616(
            project, codegen, mode=mode, boundary_fingerprint=boundary_fingerprint
        )

    cloned_codegen = _prepare_baseline_clone_or_none_8616(project, codegen, function_addr=function_addr)
    if cloned_codegen is None:
        return _collect_direct_tail_summary_8616(
            project, codegen, mode=mode, boundary_fingerprint=boundary_fingerprint
        )
    try:
        _repair_cfunc_statements_wrapper(cloned_codegen)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Tail-validation baseline clone final repair failed at function=%#x "
            "stage=baseline-canonicalization: %s",
            function_addr,
            ex,
        )
    try:
        _post._repair_unresolved_function_exit_gotos_8616(project, cloned_codegen)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Tail-validation baseline clone unresolved-exit repair failed at function=%#x "
            "stage=baseline-canonicalization: %s",
            function_addr,
            ex,
        )
    _debug_baseline_clone_witnesses_8616(cloned_codegen, function_addr)
    _debug_tail_validation_baseline_condition_8616(
        project,
        cloned_codegen,
        function_addr=function_addr,
        label="baseline-clone",
    )
    try:
        with analysis_timeout(3):
            return collect_x86_16_tail_validation_summary(project, cloned_codegen, mode=mode)
    except AnalysisTimeout:
        logging.getLogger(__name__).warning(
            "Tail-validation baseline summary timed out at function=%#x; falling back to direct summary collection",
            function_addr,
        )
        return _collect_direct_tail_summary_8616(
            project, codegen, mode=mode, boundary_fingerprint=boundary_fingerprint
        )



def _structuring_tail_validation_baseline_summary_8616(
    codegen: StructuredAstValue,
    *,
    mode: str,
    before_fingerprint: StructuredAstValue,
) -> StructuredAstValue:
    del mode, before_fingerprint
    # Fingerprint equality is not sufficient proof that the summary surface is
    # identical: summaries retain width/provenance precision that can change
    # without changing the boundary fingerprint. Keep this helper diagnostic-only
    # until the summary cache has its own equivalence key.
    if isinstance(getattr(codegen, "_inertia_structuring_tail_validation_artifacts_8616", None), Mapping):
        codegen._inertia_tail_validation_structuring_baseline_reuse_refused_8616 = (
            int(getattr(codegen, "_inertia_tail_validation_structuring_baseline_reuse_refused_8616", 0) or 0) + 1
        )
    return None


def _prime_stack_semantics_before_validation_baseline_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Prime stack and pointer-memory compatibility semantics before validation."""
    if getattr(codegen, "_inertia_pre_validation_stack_semantics_primed", False):
        return False
    try:
        pointer_memory_materialized = codegen._inertia_pointer_memory_materialized_8616 is not None
    except AttributeError:
        pointer_memory_materialized = False
    if pointer_memory_materialized:
        codegen._inertia_pre_validation_stack_semantics_refused_pointer_memory_8616 = 1
        codegen._inertia_pre_validation_stack_semantics_primed = True
        _invalidate_tail_validation_derived_caches_8616(codegen)
        return False
    changed = False
    try:
        with span("x86_16.decompile.prime_stack.invalidate"):
            _invalidate_tail_validation_derived_caches_8616(codegen)
        with span("x86_16.decompile.prime_stack.alias_transfer"):
            transfer_semantic_alias_facts_to_codegen_8616(project, codegen)
        alias_facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
        if isinstance(alias_facts, list) and alias_facts:
            with span("x86_16.decompile.prime_stack.alias_lower", facts=len(alias_facts)):
                before_materialized = int(getattr(codegen, "_inertia_semantic_stack_materialized_count", 0) or 0)
                lower_stack_accesses_from_alias_facts_8616(codegen, alias_facts)
                after_materialized = int(getattr(codegen, "_inertia_semantic_stack_materialized_count", 0) or 0)
                changed = changed or after_materialized > before_materialized
        from .lowering.real_mode_linear import (
            lower_stable_ds_es_linear_global_dereferences_8616,
            lower_stable_ss_linear_stack_dereferences_8616,
        )

        with span("x86_16.decompile.prime_stack.lower_ss_linear"):
            changed = bool(lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project)) or changed
        with span("x86_16.decompile.prime_stack.lower_ds_es_linear"):
            changed = bool(lower_stable_ds_es_linear_global_dereferences_8616(codegen, project=project)) or changed
        function = _current_postprocess_function_for_codegen_8616(project, codegen)
        if function is not None:
            with span("x86_16.decompile.prime_stack.direct_mov"):
                changed = (
                    bool(
                        materialize_direct_stack_mov_instructions_8616(
                            codegen,
                            project=project,
                            function=function,
                            allow_stack_slot_fallback=True,
                        )
                    )
                    or changed
                )
            with span("x86_16.decompile.prime_stack.direct_incdec"):
                changed = (
                    bool(
                        materialize_direct_stack_incdec_instructions_8616(
                            codegen,
                            project=project,
                            function=function,
                        )
                    )
                    or changed
                )
        if _fact_backed_stack_normalize_enabled_8616():
            with span("x86_16.decompile.prime_stack.fact_backed_normalize"):
                changed = bool(_normalize_fact_backed_stack_accesses_8616(project, codegen)) or changed
        with span("x86_16.decompile.prime_stack.pointer_memory"):
            changed = bool(_materialize_pointer_memory_idioms_postprocess_8616(project, codegen)) or changed
        with span("x86_16.decompile.prime_stack.invalidate_after"):
            _invalidate_tail_validation_derived_caches_8616(codegen)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Pre-validation stack semantics priming failed at function=%#x stage=pre-validation-baseline: %s",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            ex,
        )
    finally:
        codegen._inertia_pre_validation_stack_semantics_primed = True
    return changed


def _prime_stack_prototype_before_validation_baseline_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Materialize stack interface state before validation baseline capture.

    Return-address pruning changes angr's declaration maps and therefore must
    precede exact type reconciliation and ConditionIR operand materialization.
    Replay the typed Lowering owners here so later cleanup cannot invalidate
    condition projections or introduce a new function-parameter type surface.
    """
    if getattr(codegen, "_inertia_pre_validation_stack_prototype_primed", False):
        return False
    changed = False
    try:
        with span("x86_16.decompile.prime_stack.prototype"):
            changed = bool(materialize_annotated_stack_prototype_8616(project, codegen))
        with span("x86_16.decompile.prime_stack.return_address"):
            changed = bool(_post._prune_return_address_stack_arguments_8616(project, codegen)) or changed
        with span("x86_16.decompile.prime_stack.prototype_types"):
            changed = bool(reconcile_exact_stack_argument_prototype_8616(project, codegen)) or changed
        codegen._inertia_pre_validation_return_address_pruned_8616 = True
        if changed:
            with span("x86_16.decompile.prime_stack.prototype.invalidate_after"):
                _invalidate_tail_validation_derived_caches_8616(codegen)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Pre-validation stack prototype priming failed at function=%#x stage=pre-validation-baseline: %s",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            ex,
        )
    finally:
        codegen._inertia_pre_validation_stack_prototype_primed = True
    return changed


def _replay_segment_global_lowering_before_validation_baseline_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
) -> bool:
    """Replay all segment/global Types/Lowering on the final regenerated AST."""
    if getattr(codegen, "_inertia_pre_validation_segment_global_lowering_replayed_8616", False):
        return False
    changed = False
    try:
        synthetic_globals = getattr(
            codegen,
            "_inertia_synthetic_globals",
            getattr(project, "_inertia_synthetic_globals", None),
        )
        with span("x86_16.decompile.prime_segment_global.replay"):
            provenance_changed = replay_codegen_structured_condition_segment_provenance_8616(codegen).changed
            lowering_changed = run_segment_global_materialization_8616(
                project,
                codegen,
                synthetic_globals,
                cod_metadata=cod_metadata_for_codegen_8616(project, codegen),
                include_runtime_segment=True,
            ).changed
            changed = provenance_changed or lowering_changed
        if changed:
            _invalidate_tail_validation_derived_caches_8616(codegen)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Pre-validation segment/global lowering replay failed at function=%#x: %s",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            ex,
        )
    finally:
        codegen._inertia_pre_validation_segment_global_lowering_replayed_8616 = True
    return changed


def _prime_callsite_summaries_before_validation_baseline_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Prime callsite summaries and initial stack arguments before validation."""
    if getattr(codegen, "_inertia_pre_validation_callsite_summaries_primed", False):
        return False
    changed = False
    try:
        with span("x86_16.decompile.prime_calls.attach"):
            changed = bool(_calls._attach_callsite_summaries_8616(project, codegen))
        # Callsite argument values are binary-derived lowering facts, not
        # cleanup. Materialize them before the postprocess validation baseline
        # so validation compares the emitted C against the same call semantics
        # instead of rejecting a late rewrite or accepting a rollback that lost
        # the arguments.
        with span("x86_16.decompile.prime_calls.materialize_stack_args"):
            if getattr(codegen, "_inertia_callsite_stack_arguments_structuring_pass_ran_8616", False):
                changed = bool(
                    _calls._replay_bound_callsite_argument_consumer_8616(
                        project,
                        codegen,
                    )
                ) or changed
            else:
                changed = bool(
                    _materialize_callsite_stack_arguments_postprocess_8616(
                        project,
                        codegen,
                    )
                ) or changed
        with span("x86_16.decompile.prime_calls.normalize_targets"):
            changed = bool(_calls._normalize_call_target_names_8616(codegen)) or changed
        if changed:
            with span("x86_16.decompile.prime_calls.invalidate_after"):
                _invalidate_tail_validation_derived_caches_8616(codegen)
    except PipelineHardError:
        raise
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Pre-validation callsite semantic priming failed at function=%#x stage=pre-validation-baseline: %s",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            ex,
        )
    finally:
        codegen._inertia_pre_validation_callsite_summaries_primed = True
    return changed


def _prime_return_shape_before_validation_baseline_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
) -> bool:
    """Reapply typed caller-return evidence after prototype priming and before cleanup."""
    if getattr(codegen, "_inertia_pre_validation_return_shape_primed_8616", False):
        return False
    changed = False
    try:
        with span("x86_16.decompile.prime_return_shape.classify"):
            changed = bool(_post._classify_return_shape_8616(project, codegen))
        with span("x86_16.decompile.prime_return_shape.prune_void"):
            changed = bool(_post._prune_void_function_return_values_8616(project, codegen)) or changed
        if changed:
            with span("x86_16.decompile.prime_return_shape.invalidate_after"):
                _invalidate_tail_validation_derived_caches_8616(codegen)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Pre-validation return-shape priming failed at function=%#x stage=pre-validation-baseline: %s",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            ex,
        )
    finally:
        codegen._inertia_pre_validation_return_shape_primed_8616 = True
    return changed


def _prime_return_chains_before_validation_baseline_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Materialize CFG return chains through dynamic codegen state before validation baseline capture."""
    if getattr(codegen, "_inertia_pre_validation_return_chains_primed", False):
        return False
    changed = False
    try:
        with span("x86_16.decompile.prime_control.return_chains"):
            changed = bool(_materialize_cfg_selector_return_branches_pass_8616(project, codegen))
        if changed:
            with span("x86_16.decompile.prime_control.return_chains.invalidate_after"):
                _invalidate_tail_validation_derived_caches_8616(codegen)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Pre-validation return-chain priming failed at function=%#x stage=pre-validation-baseline: %s",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            ex,
        )
    finally:
        codegen._inertia_pre_validation_return_chains_primed = True
    return changed


def _prime_typed_conditions_before_validation_baseline_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> bool:
    """Apply proven condition and signed-argument facts before validation baseline capture."""
    if getattr(codegen, "_inertia_pre_validation_typed_conditions_primed", False):
        return False
    changed = False
    try:
        if not getattr(codegen, "_inertia_typed_conditions_transferred", False):
            cfunc = getattr(codegen, "cfunc", None)
            func_addr = getattr(cfunc, "addr", None) if cfunc is not None else None
            if isinstance(func_addr, int):
                with span("x86_16.decompile.prime_conditions.transfer"):
                    transfer_typed_conditions_to_codegen_8616(project, func_addr, codegen)
            codegen._inertia_typed_conditions_transferred = True
        # ConditionIR is semantic evidence from lift/transfer. Apply it before
        # the postprocess baseline so rewrite does not own guard recovery.
        with span("x86_16.decompile.prime_conditions.apply_typed"):
            changed = bool(_apply_typed_conditions_to_codegen_pass_8616(project, codegen))
        # Temporary bridge for legacy decoded-JCC facts that are not yet fully
        # represented as ConditionIR. This still runs before the validation
        # baseline; delete it when IR/condition transfer owns all guard facts.
        with span("x86_16.decompile.prime_conditions.rewrite_decoded_jcc"):
            changed = bool(_rewrite_decoded_jcc_conditions_pass_8616(project, codegen)) or changed
        # Lowering owns condition-proven argument types and their projected
        # stack coordinates. Run it after all condition materialization bridges
        # so cfunc.arg_list/prototype state is current at baseline capture.
        with span("x86_16.decompile.prime_conditions.apply_stack_arg_types"):
            argument_type_result = apply_condition_argument_types_8616(project, codegen)
            changed = argument_type_result.changed or changed
        # Compatibility-only fallback for raw condition wrappers that have not
        # reached the normalized Lowering fact contract. Never bypass a typed
        # refusal when normalized facts exist.
        if argument_type_result.stats.normalized_fact_count == 0:
            with span("x86_16.decompile.prime_conditions.apply_legacy_stack_arg_signedness"):
                changed = bool(_apply_typed_condition_stack_arg_signedness_8616(project, codegen)) or changed
        # ConditionIR signedness can narrow a generated argument type. Replay
        # the Types/Lowering interface owner immediately so its parameter-width
        # facts describe that same pre-validation surface instead of the stale
        # pre-signedness prototype.
        with span("x86_16.decompile.prime_conditions.reconcile_interface"):
            changed = bool(reconcile_callsite_interface_declarations_8616(project, codegen)) or changed
        if changed:
            with span("x86_16.decompile.prime_conditions.invalidate_after"):
                _invalidate_tail_validation_derived_caches_8616(codegen)
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Pre-validation typed condition priming failed at function=%#x stage=pre-validation-baseline: %s",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            ex,
        )
    finally:
        codegen._inertia_pre_validation_typed_conditions_primed = True
    return changed


def _postprocess_runtime_config_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, pass_specs: StructuredAstValue
) -> PostprocessRuntimeConfig8616:
    return configure_postprocess_runtime_8616(
        project,
        codegen,
        pass_specs,
        complexity_resolver=_postprocess_function_complexity_8616,
        baseline_summary_collector=lambda active_project, active_codegen: (
            _collect_tail_validation_summary_with_baseline_canonicalization_8616(
                active_project,
                active_codegen,
                mode="live_out",
            )
        ),
        fact_backed_stack_normalize_enabled=(
            _fact_backed_stack_normalize_enabled_8616()
        ),
    )


def _large_function_for_postprocess_snapshot_8616(project: StructuredAstValue, func_addr: int | None) -> bool:
    return _postprocess_function_complexity_8616(project, None, func_addr).is_expensive_for_local_validation


def _postprocess_optimization_enabled_8616() -> bool:
    disabled = os.environ.get("INERTIA_DISABLE_POSTPROCESS_OPT", "").strip().lower()
    if disabled in {"1", "true", "yes", "on"}:
        return False
    enabled = os.environ.get("INERTIA_ENABLE_POSTPROCESS_OPT", "").strip().lower()
    if enabled in {"0", "false", "no", "off"}:
        return False
    if enabled in {"1", "true", "yes", "on"}:
        return True
    return True


def _postprocess_spec_enabled_8616(spec_name: str) -> bool:
    if spec_name == "_prune_overwritten_flag_assignments_8616":
        return os.environ.get("INERTIA_DISABLE_FLAG_OVERWRITE_PRUNE", "").strip().lower() not in {
            "1",
            "true",
            "yes",
            "on",
        }
    if spec_name == "_materialize_callsite_stack_arguments_final_8616":
        return os.environ.get("INERTIA_ENABLE_FINAL_CALLSITE_REMATERIALIZE", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
    if spec_name == "_normalize_call_target_names_final_8616":
        return os.environ.get("INERTIA_ENABLE_FINAL_CALL_TARGET_NORMALIZE", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
    if spec_name == "_normalize_fact_backed_stack_accesses_8616":
        return _fact_backed_stack_normalize_enabled_8616()
    return True


def _selector_return_contract_active_8616(codegen: StructuredAstValue) -> bool:
    return bool(
        getattr(codegen, "_inertia_return_selector_materialized_8616", False)
        or getattr(codegen, "_inertia_pointer_memory_materialized_8616", None)
        or getattr(codegen, "_inertia_global_byte_sum_loop_materialized_8616", False)
    )


def _selector_return_contract_skip_passes_8616() -> frozenset[str]:
    return frozenset(
        {
            "_apply_annotations_8616",
            "_promote_stack_prototype_from_bp_loads_8616",
            "_prune_return_address_stack_arguments_8616",
            "_lower_stable_ss_stack_accesses_8616",
            "_normalize_function_prototype_arg_names_8616",
            "_materialize_callsite_stack_arguments_8616",
            "_materialize_callsite_stack_arguments_after_ss_lowering_8616",
            "_prune_consumed_segmented_stack_arg_stores_8616",
            "_prune_consumed_segmented_stack_arg_stores_after_ss_lowering_8616",
            "_materialize_stable_stack_semantics_final_8616",
            "_materialize_direct_stack_mov_instructions_final_8616",
            "_materialize_direct_stack_incdec_instructions_final_8616",
            "_rewrite_decoded_jcc_conditions_8616",
            "_rewrite_decoded_jcc_conditions_after_calls_8616",
        }
    )


def _local_stack_fact_evidence_8616(
    codegen: StructuredAstValue,
    facts_fn: Callable[[StructuredAstValue, StructuredAstValue], StructuredAstValue],
    evidence_attr: str,
) -> bool:
    """Compute local stack-fact evidence for a validation pass and record its count."""
    project = getattr(codegen, "project", None)
    function = _current_postprocess_function_for_codegen_8616(project, codegen) if project is not None else None
    if function is None:
        setattr(codegen, evidence_attr, 0)
        return False
    facts = facts_fn(project, function)
    setattr(codegen, evidence_attr, len(facts))
    return bool(facts)


def _callsite_stack_arg_local_evidence_8616(codegen: StructuredAstValue) -> bool:
    """Return whether callsite summaries carry push-argument evidence for local validation."""
    complexity = getattr(codegen, "_inertia_postprocess_function_complexity_8616", None)
    if isinstance(complexity, Mapping):
        block_count = _coerce_nonnegative_int_8616(complexity.get("blocks"))
        byte_count = _coerce_nonnegative_int_8616(complexity.get("bytes"))
        if block_count >= 64 or byte_count >= 0x200:
            return False
    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    if not isinstance(summary_map, dict):
        return False
    for summary in summary_map.values():
        push_sources = getattr(summary, "push_arg_sources", None)
        if isinstance(push_sources, tuple) and any(source is not None for source in push_sources):
            return True
    return False


def _postprocess_pass_has_local_evidence_8616(pass_name: str, codegen: StructuredAstValue) -> bool:
    if pass_name in {
        "optimization:adjacent_temporary_copy_prune",
        "_prune_surplus_void_empty_return_guards_8616",
        "_prune_surplus_void_empty_return_guards_final_8616",
    }:
        # The empty-guard pass computes a closed branch-count/JCC-tag proof
        # before every mutation; final validation independently checks its
        # exact evidence census and observable delta.
        return True
    if pass_name in {
        "_materialize_callsite_stack_arguments_final_8616",
        "_materialize_recovered_callsite_stack_arguments_8616",
    }:
        return False
    if pass_name in _DIRECT_STACK_MOVE_VALIDATION_PASS_NAMES_8616:
        return _local_stack_fact_evidence_8616(
            codegen,
            _direct_stack_move_instruction_facts_8616,
            "_inertia_direct_stack_move_local_evidence_count_8616",
        )
    if pass_name in _DIRECT_STACK_UPDATE_VALIDATION_PASS_NAMES_8616:
        return _local_stack_fact_evidence_8616(
            codegen,
            _direct_stack_update_instruction_facts_8616,
            "_inertia_direct_stack_update_local_evidence_count_8616",
        )
    if pass_name not in _CALLSITE_STACK_ARGUMENT_PASS_NAMES_8616:
        return False
    return _callsite_stack_arg_local_evidence_8616(codegen)


def _postprocess_local_validation_refusal_reason_8616(
    pass_name: str,
    codegen: StructuredAstValue,
) -> _PostprocessPassRefusalReason8616:
    if pass_name in _CALLSITE_STACK_ARGUMENT_PASS_NAMES_8616:
        complexity = getattr(codegen, "_inertia_postprocess_function_complexity_8616", None)
        if isinstance(complexity, Mapping):
            block_count = _coerce_nonnegative_int_8616(complexity.get("blocks"))
            byte_count = _coerce_nonnegative_int_8616(complexity.get("bytes"))
            if block_count >= 64 or byte_count >= 0x200:
                return _PostprocessPassRefusalReason8616.VERY_LARGE_FUNCTION_LOCAL_VALIDATION_UNAVAILABLE
    return _PostprocessPassRefusalReason8616.LARGE_FUNCTION_LOCAL_VALIDATION_UNAVAILABLE


def _postprocess_set_completion_state_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, state: PostprocessPassTransactionState8616
) -> bool:
    codegen._inertia_postprocess_mutation_generation_8616 = state.mutation_generation()
    codegen._inertia_postprocess_changed = state.accepted_changed
    project._inertia_decompiler_stage = "postprocess"
    return bool(state.accepted_changed)


def _postprocess_codegen_has_text_8616(codegen: StructuredAstValue) -> bool:
    for attr in ("text", "_text"):
        value = getattr(codegen, attr, None)
        if isinstance(value, str) and value.strip():
            return True
    return False


def _postprocess_should_regenerate_final_8616(codegen: StructuredAstValue, accepted_changed: bool) -> bool:
    if accepted_changed:
        return True
    return not _postprocess_codegen_has_text_8616(codegen)


def _postprocess_run_bootstrap_steps_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    skip_names: set[str],
    apply_step: Callable[[str, Callable[[], bool]], bool],
) -> bool:
    """Run semantic bootstrap consumers through guarded postprocess validation."""
    result = run_postprocess_bootstrap_steps_8616(
        codegen,
        skip_names,
        apply_step,
        PostprocessBootstrapOperations8616(
            normalize_fact_backed_stack_accesses=lambda: (
                _normalize_fact_backed_stack_accesses_8616(project, codegen)
            ),
            materialize_direct_stack_mov=lambda: (
                _materialize_direct_stack_mov_instructions_postprocess_8616(
                    project,
                    codegen,
                )
            ),
            materialize_direct_stack_incdec=lambda: (
                _materialize_direct_stack_incdec_instructions_postprocess_8616(
                    project,
                    codegen,
                )
            ),
            apply_typed_conditions=lambda: (
                _apply_typed_conditions_to_codegen_pass_8616(project, codegen)
            ),
            materialize_global_byte_index_sum_loop=lambda: (
                _materialize_global_byte_index_sum_loop_postprocess_8616(
                    project,
                    codegen,
                )
            ),
            materialize_selector_return_branches=lambda: (
                _materialize_cfg_selector_return_branches_pass_8616(
                    project,
                    codegen,
                )
            ),
            rewrite_decoded_jcc_conditions=lambda: (
                _rewrite_decoded_jcc_conditions_pass_8616(project, codegen)
            ),
            selector_return_contract_active=lambda: (
                _selector_return_contract_active_8616(codegen)
            ),
        ),
        debug_enabled=_heap_postprocess_debug_enabled_8616(),
        timing_enabled=(
            timing_output_enabled()
            and os.environ.get("INERTIA_TAIL_VALIDATION_STDERR_JSON") != "1"
        ),
    )
    return bool(result)


def _postprocess_run_optimization_step_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    per_pass_validation_enabled: bool,
    apply_step: StructuredAstValue,
) -> bool:
    """Run cleanup optimizations through the guarded postprocess pass contract."""
    _ = per_pass_validation_enabled
    if not _postprocess_optimization_enabled_8616():
        return True
    if getattr(codegen, "cfunc", None) is None:
        return True

    _normalize_cfunc_root_for_optimization_8616(codegen)
    debug_enabled = os.environ.get("INERTIA_DEBUG_OPTIMIZATION", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    for spec in OPTIMIZATION_PASSES:
        pass_name = f"optimization:{spec.name}"
        pass_started = time.perf_counter()

        def _run_spec(spec: StructuredAstValue = spec) -> StructuredAstValue:
            changed = bool(spec.func(codegen))
            if debug_enabled:
                state = "pass_changed" if changed else "pass_stable"
                print(f"[optimization] {state}={spec.name}", file=sys.stderr, flush=True)
            return changed

        keep_running = apply_step(pass_name, _run_spec)
        if timing_output_enabled() and os.environ.get("INERTIA_TAIL_VALIDATION_STDERR_JSON") != "1":
            print(
                f"[{time.strftime('%H:%M:%S')}] optimization pass: {spec.name} "
                f"({time.perf_counter() - pass_started:.3f}s)",
                file=sys.stderr,
                flush=True,
            )
        if not keep_running:
            return False
        if codegen._inertia_postprocess_validation_failed:
            return False
    if debug_enabled:
        print(
            "[optimization] counters "
            f"dce_candidates={int(getattr(codegen, 'dce_candidates', 0) or 0)} "
            f"dce_deleted={int(getattr(codegen, 'dce_deleted', 0) or 0)} "
            f"dce_keep_live_use={int(getattr(codegen, 'dce_keep_live_use', 0) or 0)} "
            f"dce_keep_side_effect={int(getattr(codegen, 'dce_keep_side_effect', 0) or 0)} "
            f"dce_keep_protected={int(getattr(codegen, 'dce_keep_protected', 0) or 0)} "
            f"dce_keep_observable={int(getattr(codegen, 'dce_keep_observable', 0) or 0)} "
            f"dce_keep_unknown={int(getattr(codegen, 'dce_keep_unknown', 0) or 0)} "
            f"dce_duplicate_assignment_candidates="
            f"{int(getattr(codegen, 'dce_duplicate_assignment_candidates', 0) or 0)} "
            f"dce_duplicate_assignment_deleted="
            f"{int(getattr(codegen, 'dce_duplicate_assignment_deleted', 0) or 0)} "
            f"dce_duplicate_assignment_refused="
            f"{int(getattr(codegen, 'dce_duplicate_assignment_refused', 0) or 0)}",
            file=sys.stderr,
            flush=True,
        )
    return not codegen._inertia_postprocess_validation_failed


def _selector_return_skip_spec_8616(spec: DecompilerPostprocessPassSpec, codegen: StructuredAstValue) -> bool:
    """Return True when the selector-return contract requires skipping this pass."""
    if spec.name not in _selector_return_contract_skip_passes_8616() or not _selector_return_contract_active_8616(
        codegen
    ):
        return False
    skipped = _boundary_list_8616(
        getattr(codegen, "_inertia_postprocess_selector_return_skipped_passes_8616", ()) or ()
    )
    skipped.append(spec.name)
    codegen._inertia_postprocess_selector_return_skipped_passes_8616 = tuple(skipped)
    return True


def _apply_spec_with_callsite_gate_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    spec: DecompilerPostprocessPassSpec,
    apply_step: Callable[[str, Callable[[], bool]], bool],
) -> bool:
    def step(current_spec: DecompilerPostprocessPassSpec = spec) -> bool:
        """Run the current pass with its declared postconditions."""
        return _run_decompiler_postprocess_pass_spec_8616(project, codegen, current_spec)

    had_callsite_final_gate = hasattr(codegen, "_inertia_callsite_final_gate_active_8616")
    previous_callsite_final_gate = getattr(codegen, "_inertia_callsite_final_gate_active_8616", None)
    codegen._inertia_callsite_final_gate_active_8616 = bool(spec.callsite_final_gate)
    try:
        return apply_step(spec.name, step)
    finally:
        if had_callsite_final_gate:
            codegen._inertia_callsite_final_gate_active_8616 = previous_callsite_final_gate
        else:
            with contextlib.suppress(Exception):
                delattr(codegen, "_inertia_callsite_final_gate_active_8616")


def _post_spec_debug_traces_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    spec: DecompilerPostprocessPassSpec,
    trace_func_addr: StructuredAstValue,
    trace_after_callsite: bool,
) -> bool:
    """Emit post-pass debug traces; returns updated trace_after_callsite flag."""
    if isinstance(trace_func_addr, int):
        _debug_condition_progress_8616(project, codegen, function_addr=trace_func_addr, label=spec.name)
    if spec.name == "_materialize_callsite_stack_arguments_8616":
        trace_after_callsite = True
    if (
        trace_after_callsite
        and os.environ.get("INERTIA_DEBUG_CALL_MUTATION")
        and isinstance(trace_func_addr, int)
    ) and _regenerate_text_safely(codegen, context=f"{trace_func_addr:#x} trace:{spec.name}"):
        _debug_dump_calls_8616(spec.name, getattr(codegen, "text", ""), trace_func_addr)
    if trace_after_callsite and isinstance(trace_func_addr, int) and _heap_postprocess_debug_enabled_8616():  # noqa: SIM102
        if _regenerate_text_safely(codegen, context=f"{trace_func_addr:#x} stack-noise-trace:{spec.name}"):
            _debug_stack_noise_8616(spec.name, getattr(codegen, "text", ""), trace_func_addr)
    return trace_after_callsite


def _postprocess_run_pass_specs_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    pass_specs: tuple[DecompilerPostprocessPassSpec, ...],
    trace_func_addr: StructuredAstValue,
    apply_step: Callable[[str, Callable[[], bool]], bool],
) -> None:
    import time as _ppt

    _t_pp_start = _ppt.perf_counter()
    trace_after_callsite = False
    for spec in pass_specs:
        if not _postprocess_spec_enabled_8616(spec.name):
            continue
        if _selector_return_skip_spec_8616(spec, codegen):
            continue
        project._inertia_decompiler_stage = f"postprocess:{spec.name}"
        _t_pass = _ppt.perf_counter()
        if timing_output_enabled() and os.environ.get("INERTIA_TAIL_VALIDATION_STDERR_JSON") != "1":
            import sys as _ppsys

            _ppsys.stderr.write(
                f"[{_ppt.strftime('%H:%M:%S')}] postprocess pass: {spec.name} (+{_t_pass - _t_pp_start:.1f}s)\n"
            )
            _ppsys.stderr.flush()
        if not _apply_spec_with_callsite_gate_8616(project, codegen, spec, apply_step):
            break
        if codegen._inertia_postprocess_validation_failed:
            break
        trace_after_callsite = _post_spec_debug_traces_8616(
            project, codegen, spec, trace_func_addr, trace_after_callsite
        )



@dataclass
class _PostprocessPassRun8616:
    """Run state for one postprocess pass transaction."""

    project: StructuredAstValue
    codegen: StructuredAstValue
    validation_enabled: StructuredAstValue
    per_pass_validation_enabled: StructuredAstValue
    pass_timeout_seconds: StructuredAstValue
    timeout_continue_passes: StructuredAstValue
    trace_func_addr: StructuredAstValue
    transaction_state: StructuredAstValue
    rollback_snapshots: StructuredAstValue
    optimization_witnesses: StructuredAstValue
    pass_name: str = ""
    step_func: StructuredAstValue = None
    debug_pointer_ast: bool = False
    pointer_ast_before: StructuredAstValue = ()
    prototype_arg_state_before: StructuredAstValue = ()
    prototype_before: StructuredAstValue = None
    preflight: StructuredAstValue = None
    is_optimization_pass: bool = False
    force_pass_validation: bool = False
    requires_snapshot: bool = False
    return_chain_expected: StructuredAstValue = None
    cycle_before: StructuredAstValue = None
    cycle_after: StructuredAstValue = None
    snapshot: StructuredAstValue = None
    metadata_snapshot: StructuredAstValue = None
    text_snapshot: StructuredAstValue = None
    project_function_snapshot: StructuredAstValue = None
    optimization_before: StructuredAstValue = None
    step_changed: bool = False

    def _optimization_witness_8616(self) -> tuple[object, object]:
        """Build the exact AST and validation-input witness for one state."""
        return (
            structured_ast_generation_8616(self.codegen),
            tail_validation_summary_input_generation_8616(self.project, self.codegen),
        )

    def _pointer_ast_lines_8616(self) -> tuple[str, ...]:
        """Render pointer-relevant lines at the explicit angr C-AST boundary."""
        if not self.debug_pointer_ast:
            return ()
        try:
            text = str(self.codegen.cfunc.c_repr())
        except (AttributeError, TypeError):
            return ()
        return tuple(
            line.strip()
            for line in text.splitlines()
            if "[0]" in line or "SEG_U16" in line
        )


    def _prototype_arg_state_8616(self) -> tuple[tuple[int, int, str], ...]:
        """Return argument storage/type state at the explicit angr boundary."""
        if os.environ.get("INERTIA_DEBUG_X87_PROTO") != "1":
            return ()
        try:
            return tuple(
                (arg.variable.offset, arg.variable.size, repr(arg.variable_type))
                for arg in tuple(self.codegen.cfunc.arg_list or ())
            )
        except AttributeError:
            return ()


    def _materialize_rollback_snapshot_8616(self) -> PostprocessRollbackSnapshot8616 | None:
        """Capture every projection restored after a rejected postprocess pass."""
        cfunc_snapshot = _snapshot_codegen_cfunc(self.codegen)
        if cfunc_snapshot is None:
            return None
        return PostprocessRollbackSnapshot8616(
            cfunc=cfunc_snapshot,
            metadata=_snapshot_codegen_inertia_metadata_8616(self.codegen),
            text=_snapshot_codegen_text_state_8616(self.codegen),
            project_function=_snapshot_project_function_metadata_8616(
                self.project,
                getattr(getattr(self.codegen, "cfunc", None), "addr", None),
            ),
            cycle_path=self.cycle_before,
        )


    def _restore_step_state_8616(self, *, context: str | None = None) -> None:
        _restore_project_function_metadata_8616(self.project_function_snapshot)
        _restore_codegen_cfunc(self.codegen, self.snapshot)
        _restore_codegen_inertia_metadata_8616(self.codegen, self.metadata_snapshot)
        _restore_codegen_text_state_8616(self.codegen, self.text_snapshot)
        self.transaction_state.record_cycle_path(self.cycle_before)
        self.rollback_snapshots.invalidate(RollbackSnapshotInvalidation8616.RESTORE_CONSUMED)


    def _preflight_gate_8616(self) -> bool | None:
        """Decide the pass preflight; ``None`` means continue to execution."""
        self.prototype_before = self.codegen.cfunc.functy
        large_function_skip = bool(getattr(self.codegen, "_inertia_skip_per_pass_validation_large_function", False))
        optional_reject_budget = int(
            getattr(
                self.codegen,
                "_inertia_postprocess_optional_reject_budget_8616",
                _PASS_REJECT_BUDGET_DEFAULT_8616,
            )
            or 0
        )
        optional_reject_count = int(
            getattr(self.codegen, "_inertia_postprocess_optional_reject_count_8616", 0) or 0
        )
        preflight_input = PostprocessPassPreflightInput8616(
            pass_name=self.pass_name,
            validation_enabled=self.validation_enabled,
            per_pass_validation_enabled=self.per_pass_validation_enabled,
            large_function_skip=large_function_skip,
            force_per_pass_requested=bool(os.environ.get("INERTIA_FORCE_PER_PASS_TV")),
            optional_reject_budget=optional_reject_budget,
            optional_reject_count=optional_reject_count,
        )
        self.preflight = decide_postprocess_pass_preflight_8616(preflight_input)
        if self.preflight.action is PostprocessPassPreflightAction8616.PROBE_LOCAL_EVIDENCE:
            self.preflight = decide_postprocess_pass_preflight_8616(
                preflight_input.with_local_evidence(
                    _postprocess_pass_has_local_evidence_8616(self.pass_name, self.codegen)
                )
            )
        if self.preflight.action is PostprocessPassPreflightAction8616.REFUSE_LOCAL_PROOF:
            reason = _postprocess_local_validation_refusal_reason_8616(self.pass_name, self.codegen)
            refused = _boundary_list_8616(getattr(self.codegen, "_inertia_postprocess_refused_passes_8616", ()) or ())
            refused.append({"pass": self.pass_name, "reason": reason.value})
            self.codegen._inertia_postprocess_refused_passes_8616 = tuple(refused)
            skipped = _boundary_list_8616(getattr(self.codegen, "_inertia_postprocess_rejected_passes", ()) or ())
            skipped.append(self.pass_name)
            self.codegen._inertia_postprocess_rejected_passes = tuple(skipped)
            return True
        if self.preflight.action is PostprocessPassPreflightAction8616.SKIP_REJECT_BUDGET:
            skipped = _boundary_list_8616(
                getattr(self.codegen, "_inertia_postprocess_reject_budget_skipped_passes_8616", ()) or ()
            )
            skipped.append(self.pass_name)
            self.codegen._inertia_postprocess_reject_budget_skipped_passes_8616 = tuple(skipped)
            rejected = _boundary_list_8616(getattr(self.codegen, "_inertia_postprocess_rejected_passes", ()) or ())
            rejected.append(self.pass_name)
            self.codegen._inertia_postprocess_rejected_passes = tuple(rejected)
            return True
        if self.preflight.action is not PostprocessPassPreflightAction8616.EXECUTE:
            raise PipelineHardError(
                "postprocess preflight did not close its local-evidence request",
                layer="rewrite/postprocess:pass_transaction",
            )
        self.is_optimization_pass = self.preflight.is_optimization_pass
        self.force_pass_validation = self.preflight.force_pass_validation
        self.requires_snapshot = self.preflight.requires_snapshot
        self.return_chain_expected = _return_chain_expected_counts_8616(self.codegen)
        self.cycle_before = self.transaction_state.known_cycle_path


    def _snapshot_setup_8616(self) -> bool | None:
        """Acquire the rollback snapshot family; ``None`` means continue."""
        snapshot_state = (
            self.rollback_snapshots.acquire(self._materialize_rollback_snapshot_8616)
            if self.requires_snapshot or self.return_chain_expected is not None
            else None
        )
        self.rollback_snapshots.stats()
        self.snapshot = snapshot_state.cfunc if snapshot_state is not None else None
        if self.requires_snapshot and self.snapshot is None:
            rejected = _boundary_list_8616(getattr(self.codegen, "_inertia_postprocess_rejected_passes", ()) or ())
            rejected.append(self.pass_name)
            self.codegen._inertia_postprocess_rejected_passes = tuple(rejected)
            logging.getLogger(__name__).warning(
                "Skipping 86_16 postprocess pass %s at function=%#x: validation snapshot unavailable: %s",
                self.pass_name,
                self.trace_func_addr if isinstance(self.trace_func_addr, int) else -1,
                getattr(self.codegen, "_inertia_postprocess_snapshot_error", None) or "unknown",
            )
            return True
        self.metadata_snapshot = snapshot_state.metadata if snapshot_state is not None else None
        self.text_snapshot = snapshot_state.text if snapshot_state is not None else None
        self.project_function_snapshot = snapshot_state.project_function if snapshot_state is not None else None
        if snapshot_state is not None:
            self.cycle_before = snapshot_state.cycle_path
        self.optimization_before = (
            self.optimization_witnesses.current_or_build(self._optimization_witness_8616)
            if self.is_optimization_pass
            else None
        )


    def _execute_step_8616(self) -> bool | None:
        """Execute the pass step with timeout and debug surfacing; ``None`` means continue."""
        try:
            if isinstance(self.pass_timeout_seconds, int) and self.pass_timeout_seconds > 0:
                with analysis_timeout(self.pass_timeout_seconds):  # noqa: SIM117
                    with span("x86_16.postprocess.pass.execute", function=self.trace_func_addr, pass_name=self.pass_name):
                        self.step_changed = bool(self.step_func())
            else:
                with span("x86_16.postprocess.pass.execute", function=self.trace_func_addr, pass_name=self.pass_name):
                    self.step_changed = bool(self.step_func())
            if os.environ.get("INERTIA_DEBUG_X87_PROTO") == "1" and self.codegen.cfunc.functy != self.prototype_before:
                print(
                    "[dbg-x87-proto] "
                    f"pass={self.pass_name} changed={self.step_changed} "
                    f"before={self.prototype_before!r} after={self.codegen.cfunc.functy!r}",
                    file=sys.stderr,
                    flush=True,
                )
            prototype_arg_state_after = self._prototype_arg_state_8616()
            if prototype_arg_state_after != self.prototype_arg_state_before:
                print(
                    "[dbg-x87-proto] "
                    f"pass={self.pass_name} changed={self.step_changed} "
                    f"args_before={self.prototype_arg_state_before!r} args_after={prototype_arg_state_after!r}",
                    file=sys.stderr,
                    flush=True,
                )
            pointer_ast_after = self._pointer_ast_lines_8616()
            if pointer_ast_after != self.pointer_ast_before:
                logging.getLogger(__name__).warning(
                    "[pointer-memory-postprocess-mutation] pass=%s reported_changed=%s before=%r after=%r",
                    self.pass_name,
                    self.step_changed,
                    self.pointer_ast_before,
                    pointer_ast_after,
                )
        except AnalysisTimeout as ex:
            return self._on_pass_timeout_8616(ex)
        except PipelineHardError:
            self._restore_or_invalidate_on_error_8616()
            raise
        except Exception as ex:
            return self._on_pass_error_8616(ex)
        return None

    def _restore_or_invalidate_on_error_8616(self) -> None:
        """Restore the snapshot when validation requires it, else invalidate it."""
        if self.per_pass_validation_enabled or self.force_pass_validation or self.is_optimization_pass:
            self._restore_step_state_8616()
        else:
            self.rollback_snapshots.invalidate(RollbackSnapshotInvalidation8616.PASS_EXCEPTION)

    def _on_pass_timeout_8616(self, ex: StructuredAstValue) -> bool:
        """Record a pass timeout; continue only for allow-listed passes."""
        self._restore_or_invalidate_on_error_8616()
        self.codegen._inertia_rewrite_failed = True
        self.codegen._inertia_rewrite_failure_pass = self.pass_name
        self.codegen._inertia_rewrite_failure_error = f"timeout: {ex}"
        timed_out = _boundary_list_8616(getattr(self.codegen, "_inertia_postprocess_timeout_passes", ()) or ())
        timed_out.append(self.pass_name)
        self.codegen._inertia_postprocess_timeout_passes = tuple(timed_out)
        logging.getLogger(__name__).warning(
            "Skipping 86_16 postprocess pass %s after %s: timeout (%s)",
            self.pass_name,
            self.transaction_state.last_changed_pass or "no earlier rewrite",
            ex,
        )
        if self.pass_name in self.timeout_continue_passes:
            continued = _boundary_list_8616(
                getattr(self.codegen, "_inertia_postprocess_timeout_continued_passes", ()) or ()
            )
            continued.append(self.pass_name)
            self.codegen._inertia_postprocess_timeout_continued_passes = tuple(continued)
            return True
        return False

    def _on_pass_error_8616(self, ex: Exception) -> bool:
        """Record a pass failure and reject the step."""
        self._restore_or_invalidate_on_error_8616()
        self.codegen._inertia_rewrite_failed = True
        self.codegen._inertia_rewrite_failure_pass = self.pass_name
        self.codegen._inertia_rewrite_failure_error = str(ex)
        logging.getLogger(__name__).warning(
            "Skipping 86_16 postprocess pass %s after %s: %s",
            self.pass_name,
            self.transaction_state.last_changed_pass or "no earlier rewrite",
            ex,
            exc_info=ex,
        )
        return False


    def _cycle_gate_8616(self) -> bool | None:
        """Reject passes that introduce a C AST cycle; ``None`` means continue."""
        self.cycle_after = _c_ast_cycle_path_8616(getattr(getattr(self.codegen, "cfunc", None), "statements", None))
        if self.cycle_after and not self.cycle_before:
            rejected_cycles = _boundary_list_8616(
                getattr(self.codegen, "_inertia_postprocess_cycle_rejected_passes_8616", ()) or ()
            )
            rejected_cycles.append({"pass": self.pass_name, "path": self.cycle_after})
            self.codegen._inertia_postprocess_cycle_rejected_passes_8616 = tuple(rejected_cycles)
            logging.getLogger(__name__).warning(
                "postprocess C AST cycle rejected function=%#x pass=%s path=%s",
                self.trace_func_addr if isinstance(self.trace_func_addr, int) else -1,
                self.pass_name,
                " -> ".join(self.cycle_after),
            )
            if self.snapshot is None:
                self.codegen._inertia_rewrite_failed = True
                self.codegen._inertia_rewrite_failure_pass = self.pass_name
                self.codegen._inertia_rewrite_failure_error = (
                    "pass introduced a structured C AST cycle without rollback state"
                )
                return False
            self._restore_step_state_8616(context=f"postprocess:{self.pass_name}:cycle-restore")
            rejected = _boundary_list_8616(getattr(self.codegen, "_inertia_postprocess_rejected_passes", ()) or ())
            rejected.append(self.pass_name)
            self.codegen._inertia_postprocess_rejected_passes = tuple(rejected)
            return True
        self.transaction_state.record_cycle_path(self.cycle_after)


    def _return_chain_gate_8616(self) -> bool | None:
        """Reject passes that regress the proven return chain; ``None`` means continue."""
        if self.return_chain_expected is not None:
            actual_if_count, actual_return_count = _return_chain_counts_8616(self.codegen)
            expected_if_count, expected_return_count = self.return_chain_expected
            if actual_if_count < expected_if_count or actual_return_count < expected_return_count:
                logging.getLogger(__name__).warning(
                    "postprocess semantic gate restored function=%#x pass=%s reason=return-chain-regression "
                    "ifs=%d/%d returns=%d/%d",
                    self.trace_func_addr if isinstance(self.trace_func_addr, int) else -1,
                    self.pass_name,
                    actual_if_count,
                    expected_if_count,
                    actual_return_count,
                    expected_return_count,
                )
                self._restore_step_state_8616()
                rejected = _boundary_list_8616(getattr(self.codegen, "_inertia_postprocess_rejected_passes", ()) or ())
                rejected.append(self.pass_name)
                self.codegen._inertia_postprocess_rejected_passes = tuple(rejected)
                return True


    def _misreport_invalidate_8616(self) -> None:
        """Record optimization misreports and invalidate stale witnesses/snapshots."""
        if self.is_optimization_pass and not self.step_changed:
            optimization_after = self._optimization_witness_8616()
            self.optimization_witnesses.record(optimization_after)
            if optimization_after != self.optimization_before:
                self.step_changed = True
                misreported = _boundary_list_8616(
                    getattr(
                        self.codegen,
                        "_inertia_postprocess_misreported_unchanged_passes_8616",
                        (),
                    )
                    or ()
                )
                misreported.append(self.pass_name)
                self.codegen._inertia_postprocess_misreported_unchanged_passes_8616 = tuple(misreported)
        if self.step_changed:
            self.optimization_witnesses.invalidate()
            self.rollback_snapshots.invalidate(RollbackSnapshotInvalidation8616.PASS_REPORTED_CHANGE)
        elif self.cycle_after != self.cycle_before:
            self.rollback_snapshots.invalidate(RollbackSnapshotInvalidation8616.PASS_MUTATION_DETECTED)


    def _regen_gate_8616(self) -> bool | None:
        """Handle the unchanged-skip and regeneration gates; ``None`` means continue."""
        if not self.step_changed:
            _record_unchanged_postprocess_validation_skip_8616(self.codegen, self.pass_name)
            return True
        if self.step_changed:
            _invalidate_tail_validation_derived_caches_8616(self.codegen)
            validation_context = (
                f"{self.trace_func_addr:#x} postprocess:{self.pass_name}:validation"
                if isinstance(self.trace_func_addr, int)
                else f"postprocess:{self.pass_name}:validation"
            )
            if getattr(self.codegen, "_inertia_postprocess_regeneration_disabled", False):
                rejected = _boundary_list_8616(
                    getattr(self.codegen, "_inertia_postprocess_rejected_passes", ()) or ()
                )
                rejected.append(self.pass_name)
                self.codegen._inertia_postprocess_rejected_passes = tuple(rejected)
                logging.getLogger(__name__).warning(
                    "postprocess validation skipped function=%#x pass=%s verdict=regeneration-disabled",
                    self.trace_func_addr if isinstance(self.trace_func_addr, int) else -1,
                    self.pass_name,
                )
                self._restore_step_state_8616(context=f"{validation_context}:restore")
                return True
            if not _regenerate_text_safely(self.codegen, context=validation_context):
                self._restore_step_state_8616(context=f"{validation_context}:restore")
                rejected = _boundary_list_8616(
                    getattr(self.codegen, "_inertia_postprocess_rejected_passes", ()) or ()
                )
                rejected.append(self.pass_name)
                self.codegen._inertia_postprocess_rejected_passes = tuple(rejected)
                return True


    def _validation_gate_8616(self) -> bool | None:
        """Run per-pass tail-validation gating; ``None`` means continue."""
        if not (
            self.validation_enabled
            and self.preflight.enforce_pass_validation
            and self.transaction_state.baseline_summary is not None
        ):
            return None
        result = self._regen_gate_8616()
        if result is not None:
            return result
        with span("x86_16.postprocess.validation.summary", function=self.trace_func_addr, pass_name=self.pass_name):
            current_summary = collect_x86_16_tail_validation_summary(self.project, self.codegen, mode="live_out")
        if (
            self.step_changed
            and os.environ.get("INERTIA_DEBUG_POSTPROCESS_DELTA")
        ):
            logging.getLogger(__name__).warning(
                "[postprocess-validation-surface] function=%#x pass=%s "
                "conditions=%r",
                self.trace_func_addr
                if isinstance(self.trace_func_addr, int)
                else -1,
                self.pass_name,
                current_summary.conditions,
            )
        with span("x86_16.postprocess.validation.compare", function=self.trace_func_addr, pass_name=self.pass_name):
            validation = compare_x86_16_tail_validation_summaries(
                self.transaction_state.baseline_summary,
                current_summary,
            )
        if x86_16_tail_validation_result_passed(validation):
            return None
        is_exit_goto_repair_delta = _postprocess_exit_goto_repair_delta_8616(validation)
        has_structured_blocking_reason = bool(_postprocess_validation_blocking_reasons_8616(validation))
        delta_kind = _classify_postprocess_validation_delta_8616(validation)
        delta_kind, is_blocking_delta = self._classify_validation_delta_8616(
            validation, delta_kind, is_exit_goto_repair_delta, has_structured_blocking_reason
        )
        if not is_blocking_delta:
            self.transaction_state.replace_baseline(current_summary)
            _dump_postprocess_trace_text_8616(
                self.codegen,
                pass_name=f"accepted.{self.pass_name}",
                trace_func_addr=self.trace_func_addr,
            )
            # Non-blocking per-pass delta: keep pass result and continue.
            if self.step_changed:
                self.transaction_state.accept_change(self.pass_name)
                self.codegen._inertia_last_postprocess_pass = self.pass_name
            return True
        return self._reject_validation_delta_8616(validation)

    def _classify_validation_delta_8616(
        self, validation: StructuredAstValue, delta_kind: StructuredAstValue,
        is_exit_goto_repair_delta: bool, has_structured_blocking_reason: bool,
    ) -> tuple[StructuredAstValue, bool]:
        """Resolve the delta kind and whether it blocks, via ordered pass arms."""
        for arm in (
            self._delta_helper_name_only_8616,
            self._delta_missing_terminal_ax_8616,
            self._delta_stack_prototype_width_8616,
            self._delta_jcc_rewrite_8616,
            self._delta_direct_global_update_8616,
            self._delta_stack_mov_incdec_bootstrap_8616,
            self._delta_direct_stack_update_8616,
            self._delta_direct_stack_move_8616,
            self._delta_global_byte_sum_loop_8616,
            self._delta_unreachable_after_return_8616,
            self._delta_switch_loop_exit_return_8616,
            self._delta_callsite_cleanup_8616,
            self._delta_return_shape_8616,
            self._delta_unobserved_scalar_return_8616,
            self._delta_exposed_stack_arg_return_8616,
            self._delta_exit_goto_repair_8616,
        ):
            result = arm(validation, delta_kind, is_exit_goto_repair_delta, has_structured_blocking_reason)
            if result is not None:
                return result
        return delta_kind, True


    def _accept_delta_8616(self, delta_kind: StructuredAstValue) -> None:
        """Record an accepted non-blocking validation delta."""
        accepted = _boundary_list_8616(
            getattr(self.codegen, "_inertia_postprocess_accepted_validation_deltas", ()) or ()
        )
        accepted.append({"pass": self.pass_name, "kind": delta_kind.value})
        self.codegen._inertia_postprocess_accepted_validation_deltas = tuple(accepted)
        logging.getLogger(__name__).warning(
            "postprocess validation accepted function=%#x pass=%s kind=%s",
            self.trace_func_addr if isinstance(self.trace_func_addr, int) else -1,
            self.pass_name,
            delta_kind.value,
        )


    def _delta_helper_name_only_8616(
        self, validation: StructuredAstValue, delta_kind: StructuredAstValue,
        is_exit_goto_repair_delta: bool, has_structured_blocking_reason: bool,
    ) -> tuple[StructuredAstValue, bool] | None:
        """Classify one validation-delta arm; ``None`` means gate miss."""
        if not (self.pass_name in _HELPER_NAME_ONLY_VALIDATION_PASS_NAMES_8616
                    and delta_kind is _PostprocessValidationDeltaKind8616.NAME_ONLY_HELPER_ANNOTATION):
            return None
        is_blocking_delta = True
        is_blocking_delta = has_structured_blocking_reason
        if not is_blocking_delta:
            self._accept_delta_8616(delta_kind)
        return delta_kind, is_blocking_delta

    def _delta_missing_terminal_ax_8616(
        self, validation: StructuredAstValue, delta_kind: StructuredAstValue,
        is_exit_goto_repair_delta: bool, has_structured_blocking_reason: bool,
    ) -> tuple[StructuredAstValue, bool] | None:
        """Classify one validation-delta arm; ``None`` means gate miss."""
        if self.pass_name not in _MISSING_TERMINAL_AX_RETURN_PASS_NAMES_8616:
            return None
        is_blocking_delta = True
        if _is_missing_terminal_ax_return_delta_8616(self.codegen, validation) or (
            int(getattr(self.codegen, "_inertia_missing_terminal_ax_return_materialized_8616", 0) or 0) > 0
            and _is_direct_callsite_helper_delta_only_8616(
                self.project,
                getattr(self.codegen, "_inertia_current_function_8616", None),
                validation,
            )
        ):
            delta_kind = _PostprocessValidationDeltaKind8616.MISSING_TERMINAL_AX_RETURN
            is_blocking_delta = False
            self._accept_delta_8616(delta_kind)
        else:
            is_blocking_delta = True
        return delta_kind, is_blocking_delta

    def _delta_stack_prototype_width_8616(
        self, validation: StructuredAstValue, delta_kind: StructuredAstValue,
        is_exit_goto_repair_delta: bool, has_structured_blocking_reason: bool,
    ) -> tuple[StructuredAstValue, bool] | None:
        """Classify one validation-delta arm; ``None`` means gate miss."""
        if not (self.pass_name == "_reconcile_exact_stack_argument_prototype_8616"
                    and _is_stack_prototype_width_reconciliation_delta_8616(self.codegen, validation)):
            return None
        is_blocking_delta = True
        delta_kind = _PostprocessValidationDeltaKind8616.STACK_PROTOTYPE_WIDTH_RECONCILIATION
        is_blocking_delta = False
        self._accept_delta_8616(delta_kind)
        return delta_kind, is_blocking_delta

    def _delta_jcc_rewrite_8616(
        self, validation: StructuredAstValue, delta_kind: StructuredAstValue,
        is_exit_goto_repair_delta: bool, has_structured_blocking_reason: bool,
    ) -> tuple[StructuredAstValue, bool] | None:
        """Classify one validation-delta arm; ``None`` means gate miss."""
        if self.pass_name not in _JCC_REWRITE_VALIDATION_PASS_NAMES_8616:
            return None
        is_blocking_delta = True
        if is_exit_goto_repair_delta:
            is_blocking_delta = False
        elif (
            self.pass_name == "_repair_conditional_continue_guards_after_loop_break_8616"
            and _is_conditional_continue_guard_repair_delta_8616(self.codegen, validation)
        ):
            delta_kind = _PostprocessValidationDeltaKind8616.CONDITIONAL_CONTINUE_GUARD_REPAIR
            is_blocking_delta = False
            self._accept_delta_8616(delta_kind)
        elif _is_jcc_call_return_condition_rebinding_delta_8616(self.codegen, validation):
            delta_kind = _PostprocessValidationDeltaKind8616.JCC_CALL_RETURN_CONDITION_REBINDING
            is_blocking_delta = False
            self._accept_delta_8616(delta_kind)
        elif _is_jcc_condition_materialization_validation_delta_8616(
            self.project,
            self.codegen,
            validation,
            function=getattr(self.codegen, "_inertia_current_function_8616", None),
        ):
            delta_kind = _PostprocessValidationDeltaKind8616.JCC_CONDITION_MATERIALIZATION
            is_blocking_delta = False
            self.codegen._inertia_jcc_condition_materialization_validation_accepts = (
                int(
                    getattr(self.codegen, "_inertia_jcc_condition_materialization_validation_accepts", 0)
                    or 0
                )
                + 1
            )
            self._accept_delta_8616(delta_kind)
        else:
            is_blocking_delta = True
        return delta_kind, is_blocking_delta

    def _delta_direct_global_update_8616(
        self, validation: StructuredAstValue, delta_kind: StructuredAstValue,
        is_exit_goto_repair_delta: bool, has_structured_blocking_reason: bool,
    ) -> tuple[StructuredAstValue, bool] | None:
        """Classify one validation-delta arm; ``None`` means gate miss."""
        if self.pass_name not in _DIRECT_GLOBAL_UPDATE_VALIDATION_PASS_NAMES_8616:
            return None
        is_blocking_delta = True
        if _is_direct_global_update_materialization_delta_8616(self.codegen, validation):
            delta_kind = _PostprocessValidationDeltaKind8616.DIRECT_GLOBAL_UPDATE_MATERIALIZATION
            is_blocking_delta = False
            self.codegen._inertia_direct_global_update_validation_accepts_8616 = (
                int(getattr(self.codegen, "_inertia_direct_global_update_validation_accepts_8616", 0) or 0)
                + 1
            )
            self._accept_delta_8616(delta_kind)
        else:
            is_blocking_delta = True
        return delta_kind, is_blocking_delta

    def _delta_stack_mov_incdec_bootstrap_8616(
        self, validation: StructuredAstValue, delta_kind: StructuredAstValue,
        is_exit_goto_repair_delta: bool, has_structured_blocking_reason: bool,
    ) -> tuple[StructuredAstValue, bool] | None:
        """Classify one validation-delta arm; ``None`` means gate miss."""
        if self.pass_name != "_materialize_direct_stack_mov_incdec_instructions_bootstrap_8616":
            return None
        is_blocking_delta = True
        if _is_direct_stack_move_update_materialization_delta_8616(self.codegen, validation):
            delta_kind = _PostprocessValidationDeltaKind8616.DIRECT_STACK_MOVE_UPDATE_MATERIALIZATION
            is_blocking_delta = False
            self.codegen._inertia_direct_stack_move_update_validation_accepts_8616 = (
                int(
                    getattr(
                        self.codegen,
                        "_inertia_direct_stack_move_update_validation_accepts_8616",
                        0,
                    )
                    or 0
                )
                + 1
            )
            self._accept_delta_8616(delta_kind)
        else:
            is_blocking_delta = True
        return delta_kind, is_blocking_delta

    def _delta_direct_stack_update_8616(
        self, validation: StructuredAstValue, delta_kind: StructuredAstValue,
        is_exit_goto_repair_delta: bool, has_structured_blocking_reason: bool,
    ) -> tuple[StructuredAstValue, bool] | None:
        """Classify one validation-delta arm; ``None`` means gate miss."""
        if self.pass_name not in _DIRECT_STACK_UPDATE_VALIDATION_PASS_NAMES_8616:
            return None
        is_blocking_delta = True
        direct_update_delta = _is_direct_stack_update_materialization_delta_8616(self.codegen, validation)
        direct_move_delta = _is_direct_stack_move_materialization_delta_8616(
            self.codegen, validation
        ) or _is_direct_stack_move_idiv_remainder_materialization_delta_8616(self.codegen, validation)
        if direct_update_delta or direct_move_delta:
            delta_kind = (
                _PostprocessValidationDeltaKind8616.DIRECT_STACK_UPDATE_MATERIALIZATION
                if direct_update_delta
                else _PostprocessValidationDeltaKind8616.DIRECT_STACK_MOVE_MATERIALIZATION
            )
            is_blocking_delta = False
            if direct_update_delta:
                self.codegen._inertia_direct_stack_update_validation_accepts_8616 = (
                    int(
                        getattr(self.codegen, "_inertia_direct_stack_update_validation_accepts_8616", 0) or 0
                    )
                    + 1
                )
            if direct_move_delta:
                self.codegen._inertia_direct_stack_move_validation_accepts_8616 = (
                    int(getattr(self.codegen, "_inertia_direct_stack_move_validation_accepts_8616", 0) or 0)
                    + 1
                )
            self._accept_delta_8616(delta_kind)
        else:
            is_blocking_delta = True
        return delta_kind, is_blocking_delta

    def _delta_direct_stack_move_8616(
        self, validation: StructuredAstValue, delta_kind: StructuredAstValue,
        is_exit_goto_repair_delta: bool, has_structured_blocking_reason: bool,
    ) -> tuple[StructuredAstValue, bool] | None:
        """Classify one validation-delta arm; ``None`` means gate miss."""
        if self.pass_name not in _DIRECT_STACK_MOVE_VALIDATION_PASS_NAMES_8616:
            return None
        is_blocking_delta = True
        direct_move_delta_kind = _direct_stack_move_validation_delta_kind_8616(self.codegen, validation)
        if direct_move_delta_kind is not None:
            delta_kind = direct_move_delta_kind
            is_blocking_delta = False
            if delta_kind is _PostprocessValidationDeltaKind8616.DIRECT_STACK_MOVE_MATERIALIZATION:
                self.codegen._inertia_direct_stack_move_validation_accepts_8616 = (
                    int(getattr(self.codegen, "_inertia_direct_stack_move_validation_accepts_8616", 0) or 0)
                    + 1
                )
            elif (
                delta_kind
                is _PostprocessValidationDeltaKind8616.CALLSITE_STACK_ARGUMENT_MATERIALIZATION
            ):
                self.codegen._inertia_direct_stack_move_callsite_arg_validation_accepts_8616 = (
                    int(
                        getattr(
                            self.codegen,
                            "_inertia_direct_stack_move_callsite_arg_validation_accepts_8616",
                            0,
                        )
                        or 0
                    )
                    + 1
                )
            self._accept_delta_8616(delta_kind)
        else:
            is_blocking_delta = True
        return delta_kind, is_blocking_delta

    def _delta_global_byte_sum_loop_8616(
        self, validation: StructuredAstValue, delta_kind: StructuredAstValue,
        is_exit_goto_repair_delta: bool, has_structured_blocking_reason: bool,
    ) -> tuple[StructuredAstValue, bool] | None:
        """Classify one validation-delta arm; ``None`` means gate miss."""
        if self.pass_name != "_materialize_global_byte_index_sum_loop_8616":
            return None
        is_blocking_delta = True
        if _is_global_byte_sum_loop_materialization_delta_8616(self.codegen, validation):
            delta_kind = _PostprocessValidationDeltaKind8616.GLOBAL_BYTE_SUM_LOOP_MATERIALIZATION
            is_blocking_delta = False
            self._accept_delta_8616(delta_kind)
        else:
            is_blocking_delta = True
        return delta_kind, is_blocking_delta

    def _delta_unreachable_after_return_8616(
        self, validation: StructuredAstValue, delta_kind: StructuredAstValue,
        is_exit_goto_repair_delta: bool, has_structured_blocking_reason: bool,
    ) -> tuple[StructuredAstValue, bool] | None:
        """Classify one validation-delta arm; ``None`` means gate miss."""
        if self.pass_name != "_prune_unreachable_after_return_final_8616":
            return None
        is_blocking_delta = True
        if int(getattr(self.codegen, "_inertia_unreachable_after_return_pruned_8616", 0) or 0) > 0:
            delta_kind = _PostprocessValidationDeltaKind8616.UNREACHABLE_AFTER_RETURN_PRUNE
            is_blocking_delta = False
            self._accept_delta_8616(delta_kind)
        else:
            is_blocking_delta = True
        return delta_kind, is_blocking_delta

    def _delta_switch_loop_exit_return_8616(
        self, validation: StructuredAstValue, delta_kind: StructuredAstValue,
        is_exit_goto_repair_delta: bool, has_structured_blocking_reason: bool,
    ) -> tuple[StructuredAstValue, bool] | None:
        """Classify one validation-delta arm; ``None`` means gate miss."""
        if self.pass_name not in {
                    "_repair_switch_loop_exit_returns_from_evidence_8616",
                    "_repair_switch_loop_exit_returns_from_evidence_final_8616",
                }:
            return None
        is_blocking_delta = True
        if bool(getattr(self.codegen, "_inertia_switch_loop_exit_return_materialized_8616", False)):
            delta_kind = _PostprocessValidationDeltaKind8616.SWITCH_LOOP_EXIT_RETURN_REPAIR
            is_blocking_delta = False
            self._accept_delta_8616(delta_kind)
        else:
            is_blocking_delta = True
        return delta_kind, is_blocking_delta

    def _delta_callsite_cleanup_8616(
        self, validation: StructuredAstValue, delta_kind: StructuredAstValue,
        is_exit_goto_repair_delta: bool, has_structured_blocking_reason: bool,
    ) -> tuple[StructuredAstValue, bool] | None:
        """Classify one validation-delta arm; ``None`` means gate miss."""
        if self.pass_name not in {
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
                    "_recover_missing_direct_calls_final_8616",
                    "_materialize_empty_if_return_branches_8616",
                    "_materialize_empty_if_return_branches_final_8616",
                    "_materialize_void_tail_call_guard_from_cfg_8616",
                    "_materialize_void_tail_call_guard_from_cfg_final_8616",
                    "_prune_surplus_void_empty_return_guards_8616",
                    "_prune_surplus_void_empty_return_guards_final_8616",
                    "_prune_duplicate_empty_return_guard_before_cfg_suffix_8616",
                    "_prune_duplicate_empty_return_guard_before_cfg_suffix_final_8616",
                }:
            return None
        is_blocking_delta = True
        if is_exit_goto_repair_delta:
            is_blocking_delta = False
        elif _is_stack_probe_helper_cleanup_delta_8616(self.codegen, validation):
            delta_kind = _PostprocessValidationDeltaKind8616.STACK_PROBE_HELPER_CLEANUP
            is_blocking_delta = False
            self._accept_delta_8616(delta_kind)
        elif (
            self.pass_name in _CALLSITE_STACK_ARGUMENT_PASS_NAMES_8616
            and _is_callsite_stack_argument_materialization_delta_8616(self.codegen, validation)
        ):
            delta_kind = _PostprocessValidationDeltaKind8616.CALLSITE_STACK_ARGUMENT_MATERIALIZATION
            is_blocking_delta = False
            self._accept_delta_8616(delta_kind)
        else:
            current_function = getattr(self.codegen, "_inertia_current_function_8616", None)
            if (
                self.pass_name
                in {
                    "_prune_surplus_void_empty_return_guards_8616",
                    "_prune_surplus_void_empty_return_guards_final_8616",
                }
                and _is_proven_surplus_empty_guard_cleanup_delta_8616(
                    self.codegen,
                    validation,
                )
            ):
                delta_kind = (
                    _PostprocessValidationDeltaKind8616.PROVEN_SURPLUS_EMPTY_GUARD_CLEANUP
                )
                is_blocking_delta = False
                accepted = _boundary_list_8616(
                    getattr(
                        self.codegen,
                        "_inertia_postprocess_accepted_validation_deltas",
                        (),
                    )
                    or ()
                )
                accepted.append(
                    {
                        "pass": self.pass_name,
                        "kind": delta_kind.value,
                    }
                )
                self.codegen._inertia_postprocess_accepted_validation_deltas = tuple(accepted)
                logging.getLogger(__name__).warning(
                    "postprocess validation accepted function=%#x pass=%s kind=%s",
                    self.trace_func_addr if isinstance(self.trace_func_addr, int) else -1,
                    self.pass_name,
                    delta_kind.value,
                )
            elif self.pass_name in {
                "_materialize_empty_if_return_branches_8616",
                "_materialize_empty_if_return_branches_final_8616",
                "_prune_surplus_void_empty_return_guards_8616",
                "_prune_surplus_void_empty_return_guards_final_8616",
                "_prune_duplicate_empty_return_guard_before_cfg_suffix_8616",
                "_prune_duplicate_empty_return_guard_before_cfg_suffix_final_8616",
            } and _is_cfg_return_chain_callsite_materialization_delta_8616(
                self.project, current_function, self.codegen, validation
            ):
                delta_kind = _PostprocessValidationDeltaKind8616.CFG_RETURN_CHAIN_MATERIALIZATION
                is_blocking_delta = False
                self._accept_delta_8616(delta_kind)
            elif self.pass_name in {
                "_materialize_void_tail_call_guard_from_cfg_8616",
                "_materialize_void_tail_call_guard_from_cfg_final_8616",
            } and _is_void_tail_call_guard_materialization_delta_8616(self.codegen, validation):
                delta_kind = (
                    _PostprocessValidationDeltaKind8616.CFG_VOID_TAIL_CALL_GUARD_MATERIALIZATION
                )
                is_blocking_delta = False
                self._accept_delta_8616(delta_kind)
            elif self.pass_name in {
                "_materialize_cfg_selector_return_branches_early_8616",
                "_materialize_cfg_selector_return_branches_8616",
                "_materialize_empty_if_return_branches_8616",
                "_materialize_empty_if_return_branches_final_8616",
            } and _is_cfg_return_expr_chain_materialization_delta_8616(
                self.project, current_function, self.codegen, validation
            ):
                delta_kind = _PostprocessValidationDeltaKind8616.CFG_RETURN_EXPR_CHAIN_MATERIALIZATION
                is_blocking_delta = False
                self._accept_delta_8616(delta_kind)
            else:
                is_blocking_delta = True
        return delta_kind, is_blocking_delta

    def _delta_return_shape_8616(
        self, validation: StructuredAstValue, delta_kind: StructuredAstValue,
        is_exit_goto_repair_delta: bool, has_structured_blocking_reason: bool,
    ) -> tuple[StructuredAstValue, bool] | None:
        """Classify one validation-delta arm; ``None`` means gate miss."""
        if self.pass_name != "_classify_return_shape_8616":
            return None
        is_blocking_delta = True
        if _is_default_scalar_void_return_classification_delta_8616(self.codegen, validation):
            delta_kind = _PostprocessValidationDeltaKind8616.DEFAULT_SCALAR_VOID_RETURN_CLASSIFICATION
            is_blocking_delta = False
            self._accept_delta_8616(delta_kind)
        return delta_kind, is_blocking_delta

    def _delta_unobserved_scalar_return_8616(
        self, validation: StructuredAstValue, delta_kind: StructuredAstValue,
        is_exit_goto_repair_delta: bool, has_structured_blocking_reason: bool,
    ) -> tuple[StructuredAstValue, bool] | None:
        """Classify one validation-delta arm; ``None`` means gate miss."""
        if not (_is_unobserved_default_scalar_synthetic_return_delta_8616(
                    getattr(self.codegen, "_inertia_current_function_8616", None),
                    validation,
                )):
            return None
        is_blocking_delta = True
        delta_kind = _PostprocessValidationDeltaKind8616.UNOBSERVED_DEFAULT_SCALAR_SYNTHETIC_RETURN
        is_blocking_delta = False
        self._accept_delta_8616(delta_kind)
        return delta_kind, is_blocking_delta

    def _delta_exposed_stack_arg_return_8616(
        self, validation: StructuredAstValue, delta_kind: StructuredAstValue,
        is_exit_goto_repair_delta: bool, has_structured_blocking_reason: bool,
    ) -> tuple[StructuredAstValue, bool] | None:
        """Classify one validation-delta arm; ``None`` means gate miss."""
        if not (_is_exposed_nonvoid_stack_arg_scalar_return_delta_8616(
                    getattr(self.codegen, "_inertia_current_function_8616", None),
                    validation,
                )):
            return None
        is_blocking_delta = True
        delta_kind = _PostprocessValidationDeltaKind8616.EXPOSED_NONVOID_STACK_ARG_SCALAR_RETURN
        is_blocking_delta = False
        self._accept_delta_8616(delta_kind)
        return delta_kind, is_blocking_delta

    def _delta_exit_goto_repair_8616(
        self, validation: StructuredAstValue, delta_kind: StructuredAstValue,
        is_exit_goto_repair_delta: bool, has_structured_blocking_reason: bool,
    ) -> tuple[StructuredAstValue, bool] | None:
        """Classify one validation-delta arm; ``None`` means gate miss."""
        if not (is_exit_goto_repair_delta):
            return None
        is_blocking_delta = True
        is_blocking_delta = False
        return delta_kind, is_blocking_delta

    def _reject_validation_delta_8616(self, validation: StructuredAstValue) -> bool:
        """Reject a blocking validation delta: record, dump, restore, and decide."""
        rejected = _boundary_list_8616(getattr(self.codegen, "_inertia_postprocess_rejected_passes", ()) or ())
        rejected.append(self.pass_name)
        self.codegen._inertia_postprocess_rejected_passes = tuple(rejected)
        logging.getLogger(__name__).warning(
            "postprocess validation rejected function=%#x pass=%s verdict=%s",
            self.trace_func_addr if isinstance(self.trace_func_addr, int) else -1,
            self.pass_name,
            validation.get("summary_text") or validation.get("verdict") or validation.get("status"),
        )
        if os.environ.get("INERTIA_DEBUG_POSTPROCESS_VALIDATION") or os.environ.get(
            "INERTIA_DEBUG_POSTPROCESS_DELTA"
        ):
            logging.getLogger(__name__).warning(
                "[postprocess-validation] function=%#x pass=%s delta=%s",
                self.trace_func_addr if isinstance(self.trace_func_addr, int) else -1,
                self.pass_name,
                validation.get("summary_text") or validation.get("delta"),
            )
        destructive_rejected_delta = (
            _validation_delta_removes_stack_or_control_effects_8616(validation)
            and self.pass_name not in _PASS_LOCAL_REJECT_CONTINUE_PASS_NAMES_8616
        )
        if os.environ.get("INERTIA_DEBUG_POSTPROCESS_VALIDATION") or os.environ.get(
            "INERTIA_DEBUG_POSTPROCESS_DELTA"
        ):
            logging.getLogger(__name__).warning(
                "[postprocess-validation] function=%#x pass=%s destructive_rejected_delta=%s",
                self.trace_func_addr if isinstance(self.trace_func_addr, int) else -1,
                self.pass_name,
                destructive_rejected_delta,
            )
        rejected_dump_dir = os.environ.get("INERTIA_DEBUG_REJECTED_POSTPROCESS_TEXT_DIR")
        if rejected_dump_dir:
            with contextlib.suppress(Exception):
                _regenerate_text_safely(
                    self.codegen,
                    context=(
                        f"{self.trace_func_addr:#x} postprocess:{self.pass_name}:rejected-dump"
                        if isinstance(self.trace_func_addr, int)
                        else f"postprocess:{self.pass_name}:rejected-dump"
                    ),
                )
                os.makedirs(rejected_dump_dir, exist_ok=True)
                dump_addr = self.trace_func_addr if isinstance(self.trace_func_addr, int) else 0
                safe_pass_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", self.pass_name)
                with open(
                    os.path.join(rejected_dump_dir, f"{dump_addr:x}.{safe_pass_name}.c"),
                    "w",
                    encoding="utf-8",
                ) as fp:
                    fp.write(getattr(self.codegen, "text", "") or "")
        self._restore_step_state_8616(
            context=(
                f"{self.trace_func_addr:#x} postprocess:{self.pass_name}:restore"
                if isinstance(self.trace_func_addr, int)
                else f"postprocess:{self.pass_name}:restore"
            ),
        )
        restore_proof_required = (
            destructive_rejected_delta or self.pass_name in _MANDATORY_VALIDATION_PASS_NAMES_8616
        )
        if restore_proof_required:
            restored_step_proven = _postprocess_restored_step_matches_baseline_8616(
                self.project,
                self.codegen,
                self.transaction_state.baseline_summary,
                restored_cfunc_snapshot=self.snapshot,
            )
            if restored_step_proven:
                if destructive_rejected_delta:
                    _clear_proven_destructive_rejection_8616(self.codegen)
                else:
                    _clear_proven_rejected_pass_restore_8616(self.codegen)
                logging.getLogger(__name__).warning(
                    "postprocess validation restored rejected pass function=%#x pass=%s destructive=%s",
                    self.trace_func_addr if isinstance(self.trace_func_addr, int) else -1,
                    self.pass_name,
                    destructive_rejected_delta,
                )
                return True
        if destructive_rejected_delta:
            destructive_validation = dict(validation)
            _mark_destructive_postprocess_validation_failure_8616(
                self.project,
                self.codegen,
                destructive_validation,
                pass_name=self.pass_name,
                summary_text=(
                    validation.get("summary_text") or validation.get("verdict") or validation.get("status")
                ),
            )
            return False
        if self.pass_name in _PASS_LOCAL_REJECT_CONTINUE_PASS_NAMES_8616:
            # Optional metadata pass: keep baseline snapshot and
            # continue. Semantic rewrites still require typed
            # acceptance above or they fail the stage.
            if self.pass_name in _PASS_REJECT_BUDGET_ELIGIBLE_NAMES_8616:
                self.codegen._inertia_postprocess_optional_reject_count_8616 = (
                    int(getattr(self.codegen, "_inertia_postprocess_optional_reject_count_8616", 0) or 0) + 1
                )
            return True
        self.codegen._inertia_postprocess_validation_failed = True
        self.codegen._inertia_postprocess_validation_failure_pass = self.pass_name
        self.codegen._inertia_postprocess_validation_failure_error = (
            validation.get("summary_text") or validation.get("verdict") or validation.get("status")
        )
        return False




    def apply_step_8616(self, pass_name: str, step_func: StructuredAstValue) -> bool:
        """Run one pass through dynamic codegen compatibility state and validation guards."""
        self.pass_name = pass_name
        self.step_func = step_func
        self.debug_pointer_ast = os.environ.get("INERTIA_DEBUG_POINTER_MEMORY_IDIOMS") == "1"
        self.pointer_ast_before = self._pointer_ast_lines_8616()
        self.prototype_arg_state_before = self._prototype_arg_state_8616()
        # Repair: ensure statements is always CStatements before every pass.
        # Many transform() callbacks return plain lists, which corrupts downstream.
        if _repair_cfunc_statements_wrapper(self.codegen):
            self.rollback_snapshots.invalidate(RollbackSnapshotInvalidation8616.PREPASS_REPAIR)
            self.optimization_witnesses.invalidate()
        for phase in (
            self._preflight_gate_8616,
            self._snapshot_setup_8616,
            self._execute_step_8616,
            self._cycle_gate_8616,
            self._return_chain_gate_8616,
        ):
            result = phase()
            if result is not None:
                return result
        self._misreport_invalidate_8616()
        result = self._validation_gate_8616()
        if result is not None:
            return result
        if self.step_changed:
            self.transaction_state.accept_change(self.pass_name)
            self.codegen._inertia_last_postprocess_pass = self.pass_name
        return True


def _reset_postprocess_run_flags_8616(codegen: StructuredAstValue) -> None:
    """Reset the per-run rewrite and validation failure surface on codegen."""
    codegen._inertia_rewrite_failed = False
    codegen._inertia_rewrite_failure_pass = None
    codegen._inertia_rewrite_failure_error = None
    codegen._inertia_last_postprocess_pass = None
    codegen._inertia_postprocess_regeneration_disabled = False
    codegen._inertia_regeneration_suppressed_contexts = ()
    codegen._inertia_postprocess_validation_failed = False
    codegen._inertia_postprocess_validation_failure_pass = None
    codegen._inertia_postprocess_validation_failure_error = None


def _transfer_typed_conditions_once_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> None:
    """Transfer typed conditions to codegen exactly once per function."""
    if getattr(codegen, "_inertia_typed_conditions_transferred", False):
        return
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None) if cfunc is not None else None
    if func_addr is not None:
        try:
            transfer_typed_conditions_to_codegen_8616(project, func_addr, codegen)
        except Exception as ex:
            logging.getLogger(__name__).debug(
                "Typed condition transfer failed at function=%#x stage=postprocess-transfer: %s",
                func_addr,
                ex,
            )
    codegen._inertia_typed_conditions_transferred = True


def _regenerate_final_postprocess_text_8616(
    codegen: StructuredAstValue,
    transaction_state: StructuredAstValue,
    trace_func_addr: StructuredAstValue,
) -> None:
    """Regenerate the final text when validation passed and regeneration is allowed."""
    if codegen._inertia_postprocess_validation_failed or getattr(
        codegen, "_inertia_postprocess_regeneration_disabled", False
    ) or not _postprocess_should_regenerate_final_8616(
        codegen,
        transaction_state.accepted_changed,
    ):
        return
    final_context = (
        f"{trace_func_addr:#x} postprocess:final"
        if isinstance(trace_func_addr, int)
        else "postprocess:final"
    )
    _regenerate_text_safely(codegen, context=final_context)
    _dump_postprocess_trace_text_8616(
        codegen,
        pass_name="final",
        trace_func_addr=trace_func_addr,
    )


def _debug_pointer_surface_8616(codegen: StructuredAstValue, label: str) -> None:
    """Log the typed pointer surface at the angr C-AST boundary."""
    if os.environ.get("INERTIA_DEBUG_POINTER_MEMORY_IDIOMS") != "1":
        return
    try:
        pointer_text = str(codegen.cfunc.c_repr())
    except (AttributeError, TypeError):
        return
    logging.getLogger(__name__).warning(
        "[pointer-memory-postprocess-surface] label=%s lines=%r",
        label,
        tuple(line.strip() for line in pointer_text.splitlines() if "[0]" in line or "SEG_U16" in line),
    )


def _postprocess_codegen_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> bool:
    """Run guarded cleanup over an already structured and semantically primed C AST."""

    def _impl() -> bool:
        setup_started = time.perf_counter()
        if getattr(codegen, "cfunc", None) is None:
            return False

        _debug_pointer_surface_8616(codegen, "entry")

        _reset_postprocess_run_flags_8616(codegen)
        pass_specs = _decompiler_postprocess_passes_for_function(project, codegen)
        pass_timeout_seconds, validation_enabled, per_pass_validation_enabled, skip_names, initial_baseline_summary = (
            _postprocess_runtime_config_8616(project, codegen, pass_specs)
        )
        if timing_output_enabled() and os.environ.get("INERTIA_TAIL_VALIDATION_STDERR_JSON") != "1":
            print(
                f"[{time.strftime('%H:%M:%S')}] postprocess setup: runtime-config "
                f"({time.perf_counter() - setup_started:.3f}s)",
                file=sys.stderr,
                flush=True,
            )
        _debug_pointer_surface_8616(codegen, "after-runtime-config")
        trace_func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
        delta = getattr(project, "_inertia_original_linear_delta", None)
        if isinstance(trace_func_addr, int) and isinstance(delta, int):
            trace_func_addr = trace_func_addr + delta
        timeout_continue_passes = {
            "_apply_annotations_8616",
            "_promote_stack_prototype_from_bp_loads_8616",
        }
        transaction_state = PostprocessPassTransactionState8616(
            baseline_summary=initial_baseline_summary,
            known_cycle_path=_c_ast_cycle_path_8616(
                getattr(getattr(codegen, "cfunc", None), "statements", None)
            ),
        )
        rollback_snapshots = PostprocessRollbackSnapshotController8616(codegen)
        optimization_witnesses = PostprocessMutationWitnessCache8616[
            tuple[object, object]
        ]()


        def _complete_postprocess_8616() -> bool:
            """Publish closed witness accounting before completing the transaction."""
            codegen._inertia_postprocess_optimization_witness_stats_8616 = (
                optimization_witnesses.stats()
            )
            return _postprocess_set_completion_state_8616(
                project,
                codegen,
                transaction_state,
            )

        run = _PostprocessPassRun8616(
            project=project,
            codegen=codegen,
            validation_enabled=validation_enabled,
            per_pass_validation_enabled=per_pass_validation_enabled,
            pass_timeout_seconds=pass_timeout_seconds,
            timeout_continue_passes=timeout_continue_passes,
            trace_func_addr=trace_func_addr,
            transaction_state=transaction_state,
            rollback_snapshots=rollback_snapshots,
            optimization_witnesses=optimization_witnesses,
        )


        # ── Transfer typed conditions BEFORE typed condition pass ──
        _transfer_typed_conditions_once_8616(project, codegen)

        if timing_output_enabled() and os.environ.get("INERTIA_TAIL_VALIDATION_STDERR_JSON") != "1":
            print(
                f"[{time.strftime('%H:%M:%S')}] postprocess setup: ready "
                f"({time.perf_counter() - setup_started:.3f}s)",
                file=sys.stderr,
                flush=True,
            )

        if not _postprocess_run_bootstrap_steps_8616(project, codegen, skip_names, run.apply_step_8616):
            return _complete_postprocess_8616()
        if not _postprocess_run_optimization_step_8616(project, codegen, per_pass_validation_enabled, run.apply_step_8616):
            return _complete_postprocess_8616()

        _postprocess_run_pass_specs_8616(project, codegen, pass_specs, trace_func_addr, run.apply_step_8616)
        _regenerate_final_postprocess_text_8616(codegen, transaction_state, trace_func_addr)
        return _complete_postprocess_8616()

    return _impl()


def _debug_first_condition_8616(codegen: StructuredAstValue, cfunc: StructuredAstValue, label: str) -> None:
    """Log the first rendered condition fingerprint for selector-return debugging."""
    if not os.environ.get("INERTIA_DEBUG_RETURN_BRANCH"):
        return
    logger = logging.getLogger(__name__)
    project = getattr(codegen, "project", None)
    root = getattr(cfunc, "statements", None) if cfunc is not None else None
    first_stmt = next(iter(getattr(root, "statements", ()) or ()), None)
    first_cond = None
    if isinstance(first_stmt, CIfElse):
        cond_nodes = first_stmt.condition_and_nodes or ()
        if cond_nodes:
            first_cond = cond_nodes[0][0]
    if first_cond is None or project is None:
        return
    logger.warning(
        "[cfg-selector-return] regen %s cond_fp=%r lhs_offset=%r rhs_offset=%r args=%r",
        label,
        _expr_fingerprint(first_cond, project),
        getattr(getattr(getattr(first_cond, "lhs", None), "variable", None), "offset", None),
        getattr(getattr(getattr(first_cond, "rhs", None), "variable", None), "offset", None),
        [
            (
                getattr(getattr(arg, "variable", None), "offset", None),
                getattr(arg, "name", None),
                getattr(getattr(arg, "variable", None), "name", None),
            )
            for arg in (getattr(cfunc, "arg_list", ()) or ())
        ],
    )


def _regenerate_text_safely(codegen: StructuredAstValue, *, context: str) -> bool:
    logger = logging.getLogger(__name__)
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None) if cfunc is not None else None
    if getattr(codegen, "_inertia_postprocess_regeneration_disabled", False):
        codegen._inertia_regeneration_failed = True
        codegen._inertia_regeneration_error = "suppressed by earlier recursion guard"
        codegen._inertia_regeneration_context = context
        codegen._inertia_regeneration_last_pass = getattr(codegen, "_inertia_last_postprocess_pass", None)
        return False

    with span(
        "x86_16.postprocess.regenerate_text",
        context=context,
        function=func_addr,
        last_pass=getattr(codegen, "_inertia_last_postprocess_pass", None),
    ):
        try:
            with span("x86_16.postprocess.regenerate.repair_metadata", function=func_addr):
                _repair_missing_cnode_codegen_metadata_8616(cfunc, codegen)
            with span("x86_16.postprocess.regenerate.repair_call_targets", function=func_addr):
                repair_cfunctioncall_render_targets_8616(codegen)
            with span("x86_16.postprocess.regenerate.normalize_stack_identifiers", function=func_addr):
                _normalize_stack_variable_identifiers_8616(codegen)
            _debug_first_condition_8616(codegen, cfunc, "after-normalize-stack-identifiers")
            with span("x86_16.postprocess.regenerate.replay_stack_aggregates", function=func_addr):
                reapply_stack_aggregate_object_facts_8616(codegen)
            with span("x86_16.postprocess.regenerate.replay_stack_coordinate_names", function=func_addr):
                reapply_stack_variable_projection_names_8616(codegen)
            with span("x86_16.postprocess.regenerate.bind_types", function=func_addr):
                _bind_codegen_variable_types_to_arch_8616(codegen)
            _debug_first_condition_8616(codegen, cfunc, "after-bind-types")
            if cfunc is not None:
                with span("x86_16.postprocess.regenerate.render_text", function=func_addr):
                    rendered = codegen.render_text(cfunc)
                _debug_first_condition_8616(codegen, cfunc, "after-render-text")
                if isinstance(rendered, tuple):
                    rendered = rendered[0] if rendered and isinstance(rendered[0], str) else ""
                if isinstance(rendered, str) and rendered.strip():
                    codegen.text = rendered
                    codegen._inertia_regeneration_failed = False
                    codegen._inertia_regeneration_error = None
                    codegen._inertia_regeneration_context = context
                    codegen._inertia_regeneration_last_pass = getattr(codegen, "_inertia_last_postprocess_pass", None)
                    return True
            with span("x86_16.postprocess.regenerate.codegen_regenerate_text", function=func_addr):
                codegen.regenerate_text()
        except Exception as ex:
            codegen._inertia_regeneration_failed = True
            codegen._inertia_regeneration_error = str(ex)
            codegen._inertia_regeneration_context = context
            codegen._inertia_regeneration_last_pass = getattr(codegen, "_inertia_last_postprocess_pass", None)
            if isinstance(ex, RecursionError):
                codegen._inertia_postprocess_regeneration_disabled = True
                suppressed_contexts = _boundary_set_8616(
                    getattr(codegen, "_inertia_regeneration_suppressed_contexts", ())
                )
                if context not in suppressed_contexts:
                    logger.warning(
                        "Skipping 86_16 postprocess regeneration for %s after %s: %s",
                        context,
                        getattr(codegen, "_inertia_last_postprocess_pass", None) or "no prior rewrite",
                        ex,
                    )
                    suppressed_contexts.add(context)
                codegen._inertia_regeneration_suppressed_contexts = tuple(sorted(suppressed_contexts))
            else:
                logger.warning(
                    "Skipping 86_16 postprocess regeneration for %s after %s: %s",
                    context,
                    getattr(codegen, "_inertia_last_postprocess_pass", None) or "no prior rewrite",
                    ex,
                    exc_info=True,
                )
            return False
        codegen._inertia_regeneration_failed = False
        codegen._inertia_regeneration_error = None
        codegen._inertia_regeneration_context = context
        codegen._inertia_regeneration_last_pass = getattr(codegen, "_inertia_last_postprocess_pass", None)
        return True


def _dump_postprocess_trace_text_8616(
    codegen: StructuredAstValue, *, pass_name: str, trace_func_addr: StructuredAstValue
) -> None:
    dump_dir = os.environ.get("INERTIA_DEBUG_POSTPROCESS_TEXT_TRACE_DIR")
    if not dump_dir:
        return
    with contextlib.suppress(Exception):
        os.makedirs(dump_dir, exist_ok=True)
        dump_addr = trace_func_addr if isinstance(trace_func_addr, int) else 0
        safe_pass_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", pass_name)
        with open(
            os.path.join(dump_dir, f"{dump_addr:x}.{safe_pass_name}.c"),
            "w",
            encoding="utf-8",
        ) as fp:
            fp.write(getattr(codegen, "text", "") or "")


@dataclass
class _CNodeMetadataRepair8616:
    """Walker that backfills missing C-node codegen rendering metadata."""

    codegen: StructuredAstValue
    repaired: int = 0
    seen: set[int] = field(default_factory=set)

    def run(self, root: StructuredAstValue) -> int:
        self._walk(root)
        return self.repaired

    def _walk(self, node: StructuredAstValue) -> None:
        if node is None or isinstance(node, (str, bytes, int, float, bool)):
            return
        if isinstance(node, dict):
            for key, value in tuple(node.items()):
                self._walk(key)
                self._walk(value)
            return
        if isinstance(node, (list, tuple, set, frozenset)):
            for item in tuple(node):
                self._walk(item)
            return

        node_id = id(node)
        if node_id in self.seen:
            return
        self.seen.add(node_id)

        if hasattr(node, "codegen") and getattr(node, "codegen", None) is None:
            with contextlib.suppress(Exception):
                node.codegen = self.codegen
                self.repaired += 1

        for attr in _C_AST_CHILD_ATTRS_8616:
            if hasattr(node, attr):
                with contextlib.suppress(Exception):
                    self._walk(getattr(node, attr))


def _repair_missing_cnode_codegen_metadata_8616(root: StructuredAstValue, codegen: StructuredAstValue) -> int:
    """Repair rendering metadata only; Types/Lowering owns declarations."""
    repaired = _CNodeMetadataRepair8616(codegen).run(root)
    if repaired:
        codegen._inertia_codegen_metadata_repaired = (
            int(getattr(codegen, "_inertia_codegen_metadata_repaired", 0) or 0) + repaired
        )
    return repaired


def _terminal_ax_returns_delta_ok_8616(
    codegen: StructuredAstValue, delta: dict, expected_returns: StructuredAstValue
) -> bool:
    """Return whether the returns delta only adds evidenced terminal AX returns."""
    returns_delta = delta.get("returns")
    if not isinstance(returns_delta, dict):
        return False
    added_returns = _boundary_set_8616(returns_delta.get("added") or ())
    removed_returns = _boundary_set_8616(returns_delta.get("removed") or ())
    if not added_returns or added_returns - expected_returns:
        return False
    replaced_returns = _boundary_set_8616(
        getattr(codegen, "_inertia_missing_terminal_ax_return_replaced_fingerprints_8616", ()) or ()
    )
    return not (removed_returns - ({"none", "const:0"} | replaced_returns))


def _is_missing_terminal_ax_return_delta_8616(
    codegen: StructuredAstValue, validation: dict[str, StructuredAstValue]
) -> bool:
    if not isinstance(validation, dict):
        return False
    if int(getattr(codegen, "_inertia_missing_terminal_ax_return_materialized_8616", 0) or 0) <= 0:
        return False
    expected_returns = _boundary_set_8616(
        getattr(codegen, "_inertia_missing_terminal_ax_return_fingerprints_8616", ()) or ()
    )
    if not expected_returns:
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    touched_fields = _validation_delta_touched_fields_8616(delta)
    if not touched_fields or touched_fields - {"returns", "control_flow_effects"} or "returns" not in touched_fields:
        return False
    if not _terminal_ax_returns_delta_ok_8616(codegen, delta, expected_returns):
        return False
    control_delta = delta.get("control_flow_effects")
    if isinstance(control_delta, dict):
        added_control = _boundary_set_8616(control_delta.get("added") or ())
        removed_control = _boundary_set_8616(control_delta.get("removed") or ())
        if added_control - {"return"} or removed_control:
            return False
    return True


def _surplus_empty_guard_census_8616(codegen: StructuredAstValue) -> tuple[int, int, int] | None:
    """Return (pruned, branch_count, total_if_count) for a proven surplus cleanup, or None."""
    artifact = getattr(codegen, "_inertia_surplus_empty_guard_cleanup_artifact_8616", None)
    if isinstance(artifact, SurplusGuardCleanupEvidence8616):
        if not artifact.complete:
            return None
        pruned = artifact.stats.materialized_count
        noop_pruned = artifact.noop_materialized_count
        empty_return_pruned = artifact.empty_return_materialized_count
        identical_arms_collapsed = artifact.identical_arms_materialized_count
        branch_count: object = artifact.branch_count
        total_if_count: object = artifact.total_if_count
    else:
        if (
            getattr(codegen, "_inertia_void_empty_return_guard_decision_8616", None)
            != _VoidEmptyReturnGuardDecision8616.PRUNE.value
        ):
            return None
        pruned = int(getattr(codegen, "_inertia_void_empty_return_guard_pruned_8616", 0) or 0)
        noop_pruned = int(getattr(codegen, "_inertia_void_empty_return_guard_noop_pruned_8616", 0) or 0)
        empty_return_pruned = int(
            getattr(codegen, "_inertia_void_empty_return_guard_empty_return_pruned_8616", 0) or 0
        )
        identical_arms_collapsed = int(
            getattr(codegen, "_inertia_void_empty_return_guard_identical_arms_collapsed_8616", 0) or 0
        )
        branch_count = getattr(codegen, "_inertia_void_empty_return_guard_branch_count_8616", None)
        total_if_count = getattr(codegen, "_inertia_void_empty_return_guard_total_ifs_8616", None)
    counts_ok = (
        pruned > 0
        and noop_pruned == pruned
        and empty_return_pruned == 0
        and identical_arms_collapsed == 0
    )
    census_ok = (
        isinstance(branch_count, int)
        and isinstance(total_if_count, int)
        and total_if_count - branch_count >= pruned
    )
    if not (counts_ok and census_ok):
        return None
    return pruned, branch_count, total_if_count


def _is_proven_surplus_empty_guard_cleanup_delta_8616(
    codegen: StructuredAstValue,
    validation: dict[str, StructuredAstValue],
) -> bool:
    """Accept only the exact no-op guards classified as binary-proven surplus.

    The mutation is cleanup owned by Structuring's branch-count and JCC-tag
    proofs. This compatibility validation consumes its closed evidence census;
    it does not infer branch semantics from validation fingerprint text.
    """
    if not isinstance(validation, dict):
        return False
    census = _surplus_empty_guard_census_8616(codegen)
    if census is None:
        return False
    pruned, _branch_count, _total_if_count = census

    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    if _validation_delta_touched_fields_8616(delta) != {"conditions", "control_flow_effects"}:
        return False
    conditions_delta = delta.get("conditions")
    control_delta = delta.get("control_flow_effects")
    if not isinstance(conditions_delta, dict) or not isinstance(control_delta, dict):
        return False
    added_conditions = _boundary_tuple_8616(conditions_delta.get("added") or ())
    removed_conditions = _boundary_tuple_8616(conditions_delta.get("removed") or ())
    added_control = _boundary_tuple_8616(control_delta.get("added") or ())
    removed_control = _boundary_tuple_8616(control_delta.get("removed") or ())
    if added_conditions or added_control:
        return False
    if len(removed_conditions) != pruned or len(removed_control) != pruned:
        return False
    if any(not isinstance(token, str) for token in removed_conditions):
        return False
    return set(removed_control) == {f"if:{token}" for token in removed_conditions}


def _is_default_scalar_void_return_classification_delta_8616(
    codegen: StructuredAstValue, validation: dict[str, StructuredAstValue]
) -> bool:
    """Return true for proven default-scalar return cleanup to a void return."""
    if not isinstance(validation, dict):
        return False
    prototype = getattr(getattr(codegen, "cfunc", None), "functy", None) or getattr(
        getattr(codegen, "cfunc", None), "prototype", None
    )
    return_type = getattr(prototype, "returnty", None)
    if not (type(return_type) is SimTypeBottom and getattr(return_type, "label", None) == "void"):
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    touched_fields = _validation_delta_touched_fields_8616(delta)
    if touched_fields not in ({"returns"}, {"returns", "segmented_writes"}):
        return False
    returns_delta = delta.get("returns")
    if not isinstance(returns_delta, dict):
        return False
    added_returns = _boundary_set_8616(returns_delta.get("added") or ())
    removed_returns = _boundary_set_8616(returns_delta.get("removed") or ())
    if not (added_returns == {"none"} and bool(removed_returns) and "none" not in removed_returns):
        return False
    segmented_delta = delta.get("segmented_writes")
    if isinstance(segmented_delta, dict):
        removed_segmented = _boundary_tuple_8616(segmented_delta.get("removed") or ())
        added_segmented = _boundary_tuple_8616(segmented_delta.get("added") or ())
        if removed_segmented:
            return False
        if any(
            not isinstance(token, str) or "reg:ss" not in token or "stack_slot:SS:" not in token
            for token in added_segmented
        ):
            return False
    return True


def _write_delta_adds_only_8616(write_delta: dict, added_token_ok: StructuredAstValue) -> bool:
    """Return True when a write delta removes nothing and all added tokens satisfy the predicate."""
    removed = _boundary_tuple_8616(write_delta.get("removed") or ())
    added = _boundary_tuple_8616(write_delta.get("added") or ())
    if removed:
        return False
    return not any(not added_token_ok(token) for token in added)


def _returns_delta_is_unobserved_synthetic_8616(returns_delta: StructuredAstValue) -> bool:
    """Return True when removed returns are all call reads and added ones are synthetic."""
    if not isinstance(returns_delta, dict):
        return False
    added_returns = _boundary_tuple_8616(returns_delta.get("added") or ())
    removed_returns = _boundary_tuple_8616(returns_delta.get("removed") or ())
    if not added_returns or not removed_returns:
        return False
    if not all(isinstance(token, str) and token.startswith("call:") for token in removed_returns):
        return False
    return all(_is_unresolved_synthetic_return_delta_token_8616(token) for token in added_returns)


def _is_unobserved_default_scalar_synthetic_return_delta_8616(
    function: StructuredAstValue,
    validation: dict[str, StructuredAstValue],
) -> bool:
    """Return true when caller evidence proves a synthetic scalar return is unobserved."""
    if function is None or not isinstance(validation, dict):
        return False
    prototype = getattr(function, "prototype", None)
    return_type = getattr(prototype, "returnty", None)
    if type(return_type) is not SimTypeShort:
        return False
    if _return_compat_function_caller_return_use_8616(function) is True:
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    touched_fields = _validation_delta_touched_fields_8616(delta)
    if touched_fields - {"returns", "stack_writes", "segmented_writes"} or "returns" not in touched_fields:
        return False
    if not _returns_delta_is_unobserved_synthetic_8616(delta.get("returns")):
        return False
    stack_delta = delta.get("stack_writes")
    if isinstance(stack_delta, dict) and not _write_delta_adds_only_8616(
        stack_delta, lambda token: isinstance(token, str) and token.startswith("stack_slot:SS:")
    ):
        return False
    segmented_delta = delta.get("segmented_writes")
    return not isinstance(segmented_delta, dict) or _write_delta_adds_only_8616(
        segmented_delta,
        lambda token: isinstance(token, str) and "reg:ss" in token and "stack_slot:SS:" in token,
    )


def _is_exposed_nonvoid_stack_arg_scalar_return_delta_8616(
    function: StructuredAstValue,
    validation: dict[str, StructuredAstValue],
) -> bool:
    """Return true when cleanup exposes a typed scalar return from a stack argument."""
    if function is None or not isinstance(validation, dict):
        return False
    prototype = getattr(function, "prototype", None)
    return_type = getattr(prototype, "returnty", None)
    if return_type is None or (type(return_type) is SimTypeBottom and getattr(return_type, "label", None) == "void"):
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    if _validation_delta_touched_fields_8616(delta) != {"returns"}:
        return False
    returns_delta = delta.get("returns")
    if not isinstance(returns_delta, dict):
        return False
    added_returns = _boundary_tuple_8616(returns_delta.get("added") or ())
    removed_returns = _boundary_tuple_8616(returns_delta.get("removed") or ())
    return (
        removed_returns == ("none",)
        and len(added_returns) == 1
        and _is_positive_bp_stack_arg_scalar_return_delta_token_8616(added_returns[0])
    )


def _is_positive_bp_stack_arg_scalar_return_delta_token_8616(token: StructuredAstValue) -> bool:
    """Return true for validation tokens that read a positive BP stack argument slot."""
    if not isinstance(token, str):
        return False
    if any(marker in token for marker in ("call:", "helper:", "global:", "reg:", "SEG_", "MEM_")):
        return False
    marker = "stack_slot:SS:BP+0x"
    marker_index = token.find(marker)
    if marker_index < 0:
        return False
    offset_start = marker_index + len(marker)
    offset_end = token.find(":", offset_start)
    if offset_end < 0:
        return False
    try:
        offset = int(token[offset_start:offset_end], 16)
    except ValueError:
        return False
    return offset > 0 and ":size" in token[offset_end:]


def _is_unresolved_synthetic_return_delta_token_8616(token: StructuredAstValue) -> bool:
    """Return true for validation return tokens made only from generated carriers."""
    if not isinstance(token, str):
        return False
    if token == "none":
        return True
    if token.startswith("call:"):
        return False
    synthetic_markers = (
        "CIndexedVariable",
        "stack_slot:SS:",
        "virtual:vvar_",
        "vvar_",
        "tmp_",
        "ir_",
    )
    return any(marker in token for marker in synthetic_markers)


def _callsite_expected_target_tokens_8616(project: StructuredAstValue, function: StructuredAstValue) -> set[str]:
    """Build the normalized helper-target token set justified by direct callsite evidence."""
    expected_targets: set[str] = set()
    callsites = _boundary_tuple_8616(sorted(getattr(function, "get_call_sites", list)() or ()))
    for callsite_addr in callsites:
        target = getattr(function, "get_call_target", lambda _addr: None)(callsite_addr)
        if isinstance(target, int):
            addr_fp = f"addr:{target:#x}"
            expected_targets.add(addr_fp)
            expected_targets.add(f"name:{addr_fp}")
            if target > 0xFFFF:
                unbased = target & 0xFFFF
                unbased_fp = f"addr:{unbased:#x}"
                expected_targets.add(unbased_fp)
                expected_targets.add(f"name:{unbased_fp}")
            elif target >= 0x1000:
                # rebased exact-slice call targets may appear normalized to low 16-bit addresses.
                unbased = target - 0x1000
                if unbased >= 0:
                    unbased_fp = f"addr:{unbased:#x}"
                    expected_targets.add(unbased_fp)
                    expected_targets.add(f"name:{unbased_fp}")
            callee = project.kb.functions.function(addr=target, create=False)
            callee_name = getattr(callee, "name", None)
            if isinstance(callee_name, str) and callee_name:
                expected_targets.add(f"name:{callee_name}")
                normalized = normalize_callee_name_8616(callee_name)
                if isinstance(normalized, str) and normalized:
                    expected_targets.add(f"name:{normalized}")
                    expected_targets.add(f"name:_{normalized}")
    return expected_targets


def _accept_callsite_helper_delta_8616(
    project: StructuredAstValue,
    function: StructuredAstValue,
    added: tuple,
    removed: tuple,
) -> bool:
    """Accept helper-call deltas justified by direct callsite evidence."""
    expected_targets = _callsite_expected_target_tokens_8616(project, function)
    # Accept helper-call deltas when every added helper target can be justified
    # by direct callsite evidence after normalization.
    if not expected_targets:
        expected_targets = set()
    if not expected_targets:
        _debug_call_recover_reject_8616("no-expected-targets")
        return False
    delta_targets = set(added or removed)
    if delta_targets and all(isinstance(tok, str) and tok.startswith("name:addr:0x") for tok in delta_targets):
        _debug_call_recover_accept_8616("addr-only-helper-tokens", delta_targets=sorted(delta_targets))
        return True
    accepted = delta_targets.issubset(expected_targets)
    _debug_call_recover_accept_8616(
        str(accepted),
        delta_targets=sorted(delta_targets),
        expected_targets_sample=sorted(expected_targets)[:12],
    )
    return accepted



def _is_direct_callsite_helper_delta_only_8616(
    project: StructuredAstValue, function: StructuredAstValue, validation: dict[str, StructuredAstValue]
) -> bool:
    def _impl() -> bool:
        if function is None or not isinstance(validation, dict):
            return False
        delta = validation.get("delta")
        if not isinstance(delta, dict):
            return False
        if not _helper_delta_touches_only_allowed_fields_8616(delta):
            return False
        helper_delta = delta.get("helper_calls")
        if not isinstance(helper_delta, dict):
            return False
        added = _boundary_tuple_8616(helper_delta.get("added") or ())
        removed = _boundary_tuple_8616(helper_delta.get("removed") or ())
        if not added and not removed:
            _debug_call_recover_reject_8616("added-removed", added=added, removed=removed)
            return False
        if added or removed:
            return True
        return _accept_callsite_helper_delta_8616(project, function, added, removed)

    return _impl()


def _is_direct_callsite_helper_and_return_delta_8616(
    project: StructuredAstValue,
    function: StructuredAstValue,
    codegen: StructuredAstValue,
    validation: dict[str, StructuredAstValue],
) -> bool:
    if function is None or not isinstance(validation, dict):
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    touched_fields = {
        key
        for key, field_delta in delta.items()
        if isinstance(field_delta, dict) and ((field_delta.get("added") or ()) or (field_delta.get("removed") or ()))
    }
    if not touched_fields or touched_fields - {"helper_calls", "returns"}:
        return False
    returns_delta = delta.get("returns")
    if not isinstance(returns_delta, dict):
        return False
    removed_returns = _boundary_tuple_8616(returns_delta.get("removed") or ())
    added_returns = _boundary_tuple_8616(returns_delta.get("added") or ())
    if removed_returns or not added_returns:
        return False
    expected_return_tokens = {f"const:{value}" for value in _ordered_conditional_return_values_8616(project, codegen)}
    if not set(added_returns).issubset(expected_return_tokens):
        return False
    helper_delta = delta.get("helper_calls")
    if isinstance(helper_delta, dict) and ((helper_delta.get("added") or ()) or (helper_delta.get("removed") or ())):
        helper_validation = dict(validation)
        helper_validation["delta"] = {"helper_calls": helper_delta}
        return _is_direct_callsite_helper_delta_only_8616(project, function, helper_validation)
    return True


def _validation_delta_touched_fields_8616(delta: dict[str, StructuredAstValue]) -> set[str]:
    """Compatibility shim for validation-owned touched-field detection."""
    return require_result_type_8616(
        validation_delta_touched_fields_8616(delta),
        set,
        owner="tail_validation.validation_delta_touched_fields_8616",
    )


def _validation_delta_removes_stack_or_control_effects_8616(validation: dict[str, StructuredAstValue]) -> bool:
    """Compatibility shim for validation-owned destructive delta detection."""
    return require_result_type_8616(
        validation_delta_removes_stack_or_control_effects_8616(validation),
        bool,
        owner="tail_validation.validation_delta_removes_stack_or_control_effects_8616",
    )


def _postprocess_validation_failed_pass_name_8616(codegen: StructuredAstValue) -> str | None:
    """Return the validation-failure pass from dynamic codegen compatibility state."""
    for attr_name in ("_inertia_postprocess_validation_failure_pass", "_inertia_last_postprocess_pass"):
        pass_name = getattr(codegen, attr_name, None)
        if isinstance(pass_name, str) and pass_name:
            return pass_name
    return None


def _postprocess_destructive_salvage_family_for_pass_8616(
    pass_name: str | None,
) -> _PostprocessDestructiveSalvageFamily8616 | None:
    """Classify which isolated salvage family may retry a destructive failed pass."""
    if pass_name is None:
        return None
    if pass_name in _DIRECT_STACK_UPDATE_VALIDATION_PASS_NAMES_8616:
        return _PostprocessDestructiveSalvageFamily8616.DIRECT_STACK_UPDATE
    if pass_name in _DIRECT_STACK_MOVE_VALIDATION_PASS_NAMES_8616:
        return _PostprocessDestructiveSalvageFamily8616.DIRECT_STACK_MOVE
    return _PostprocessDestructiveSalvageFamily8616.UNKNOWN


def _postprocess_destructive_salvage_family_allowed_8616(
    salvage_family: _PostprocessDestructiveSalvageFamily8616 | None,
    expected_family: _PostprocessDestructiveSalvageFamily8616,
) -> bool:
    """Allow unknown legacy failures, otherwise keep destructive salvage in-family."""
    return salvage_family is None or salvage_family is expected_family


def _postprocess_restored_step_matches_baseline_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    baseline_summary: StructuredAstValue,
    *,
    restored_cfunc_snapshot: StructuredAstValue | None = None,
) -> bool:
    """Prove a rejected per-pass rollback restored the accepted validation baseline."""
    if restored_cfunc_snapshot is not None and getattr(codegen, "cfunc", None) is restored_cfunc_snapshot:
        codegen._inertia_postprocess_restored_snapshot_identity_proven_8616 = (
            int(getattr(codegen, "_inertia_postprocess_restored_snapshot_identity_proven_8616", 0) or 0) + 1
        )
        return True
    if baseline_summary is None:
        return False
    try:
        _invalidate_tail_validation_derived_caches_8616(codegen)
        restored_summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")
        validation = compare_x86_16_tail_validation_summaries(baseline_summary, restored_summary)
    except Exception:
        logging.getLogger(__name__).debug(
            "postprocess restored-step identity proof failed",
            exc_info=True,
        )
        return False
    return require_result_type_8616(
        x86_16_tail_validation_result_passed(validation),
        bool,
        owner="tail_validation.x86_16_tail_validation_result_passed",
    )


def _clear_proven_destructive_rejection_8616(codegen: StructuredAstValue) -> None:
    """Clear transient failure state after a rejected pass is proven fully restored."""
    _clear_proven_rejected_pass_restore_8616(codegen)
    try:
        restore_count = int(codegen._inertia_postprocess_destructive_rejected_restore_proven_8616 or 0)
    except AttributeError:
        restore_count = 0
    codegen._inertia_postprocess_destructive_rejected_restore_proven_8616 = restore_count + 1


def _clear_proven_rejected_pass_restore_8616(codegen: StructuredAstValue) -> None:
    """Record a proven per-pass rollback and clear only its transient failure state."""
    try:
        restore_count = int(codegen._inertia_postprocess_rejected_restore_proven_8616 or 0)
    except AttributeError:
        restore_count = 0
    codegen._inertia_postprocess_rejected_restore_proven_8616 = restore_count + 1
    codegen._inertia_postprocess_validation_failed = False
    codegen._inertia_postprocess_validation_failure_pass = None
    codegen._inertia_postprocess_validation_failure_error = None


def _mark_destructive_postprocess_validation_failure_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    validation: dict[str, StructuredAstValue],
    *,
    pass_name: StructuredAstValue,
    summary_text: StructuredAstValue,
    function_info: MutableMapping[str, StructuredAstValue] | None = None,
) -> None:
    failure_pass = str(pass_name or "unknown")
    failure_summary = str(summary_text or "destructive postprocess validation delta")
    validation["changed"] = True
    validation["status"] = "changed"
    validation["summary_text"] = f"destructive rejected postprocess delta in {failure_pass}: {failure_summary}"
    validation["destructive_postprocess_validation_failure"] = True
    validation["destructive_postprocess_validation_pass"] = failure_pass
    _record_postprocess_validation_blocking_reason_8616(
        validation,
        _PostprocessValidationBlockingReason8616.DESTRUCTIVE_POSTPROCESS_VALIDATION_DELTA,
    )
    validation["verdict"] = build_x86_16_tail_validation_verdict("postprocess", validation)
    persist_x86_16_tail_validation_snapshot(
        function_info=function_info,
        codegen=codegen,
        stage="postprocess",
        validation=validation,
    )
    snapshot = getattr(codegen, "_inertia_tail_validation_snapshot", None)
    if isinstance(snapshot, dict):
        project._inertia_last_tail_validation_snapshot = dict(snapshot)
    codegen._inertia_postprocess_validation_failed = True
    codegen._inertia_postprocess_validation_failure_pass = failure_pass
    codegen._inertia_postprocess_validation_failure_error = f"destructive rejected postprocess delta: {failure_summary}"


def _is_virtual_carrier_segmented_write_delta_token_8616(token: StructuredAstValue) -> bool:
    if not isinstance(token, str):
        return False
    if not token.startswith("deref:"):
        return False
    if "virtual:vvar_" not in token:
        return False
    return not any(marker in token for marker in ("reg:", "stack_slot:", "global:", "call:"))


def _jcc_rebinding_condition_tokens_8616(condition_delta: StructuredAstValue) -> tuple | None:
    """Return (added, removed) condition tokens when the delta has the rebinding shape."""
    if not isinstance(condition_delta, dict):
        return None
    added_conditions = _boundary_tuple_8616(condition_delta.get("added") or ())
    removed_conditions = _boundary_tuple_8616(condition_delta.get("removed") or ())
    if not added_conditions or not removed_conditions:
        return None
    if not any(isinstance(item, str) and "reg:ax" in item for item in removed_conditions):
        return None
    if any(isinstance(item, str) and "reg:ax" in item for item in added_conditions):
        return None
    if any(
        not isinstance(item, str) or ("virtual:vvar_" not in item and not item.startswith("Cmp"))
        for item in added_conditions
    ):
        return None
    return added_conditions, removed_conditions


def _jcc_rebinding_control_delta_ok_8616(
    control_delta: dict, added_conditions: tuple, removed_conditions: tuple
) -> bool:
    """Return True when control-flow deltas are only the rebound if-effects."""
    added_control = _boundary_tuple_8616(control_delta.get("added") or ())
    removed_control = _boundary_tuple_8616(control_delta.get("removed") or ())
    expected_added = {f"if:{item}" for item in added_conditions}
    expected_removed = {f"if:{item}" for item in removed_conditions}
    if set(added_control) - expected_added:
        return False
    return not (set(removed_control) - expected_removed)


def _segmented_delta_all_virtual_carriers_8616(segmented_delta: dict) -> bool:
    """Return True when every segmented-write token is a virtual carrier."""
    segmented_tokens = _boundary_tuple_8616(segmented_delta.get("added") or ()) + _boundary_tuple_8616(
        segmented_delta.get("removed") or ()
    )
    return not segmented_tokens or all(
        _is_virtual_carrier_segmented_write_delta_token_8616(tok) for tok in segmented_tokens
    )


def _is_jcc_call_return_condition_rebinding_delta_8616(
    codegen: StructuredAstValue, validation: dict[str, StructuredAstValue]
) -> bool:
    if not isinstance(validation, dict):
        return False
    if int(getattr(codegen, "_inertia_jcc_call_return_register_rebindings", 0) or 0) <= 0:
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    touched_fields = _validation_delta_touched_fields_8616(delta)
    allowed_fields = {"conditions", "control_flow_effects", "segmented_writes"}
    if not touched_fields or touched_fields - allowed_fields:
        return False

    condition_tokens = _jcc_rebinding_condition_tokens_8616(delta.get("conditions"))
    if condition_tokens is None:
        return False
    added_conditions, removed_conditions = condition_tokens

    control_delta = delta.get("control_flow_effects")
    if isinstance(control_delta, dict) and not _jcc_rebinding_control_delta_ok_8616(
        control_delta, added_conditions, removed_conditions
    ):
        return False

    segmented_delta = delta.get("segmented_writes")
    return not isinstance(segmented_delta, dict) or _segmented_delta_all_virtual_carriers_8616(segmented_delta)


def _tail_validation_summary_tokens_8616(
    validation: dict[str, StructuredAstValue], summary_name: str, field_name: str
) -> set[str]:
    summary = validation.get(summary_name)
    if not isinstance(summary, dict):
        return set()
    values = summary.get(field_name)
    if not isinstance(values, (tuple, list, set, frozenset)):
        return set()
    return {value for value in values if isinstance(value, str)}


def _global_write_token_addr_8616(token: StructuredAstValue) -> int | None:
    if not isinstance(token, str) or not token.startswith("global:"):
        return None
    with contextlib.suppress(ValueError):
        return int(token.split(":", 1)[1], 0)
    return None


def _is_adjacent_global_high_byte_precision_delta_8616(
    token: StructuredAstValue, validation: dict[str, StructuredAstValue]
) -> bool:
    addr = _global_write_token_addr_8616(token)
    if not isinstance(addr, int) or addr <= 0:
        return False
    low_byte_token = f"global:{addr - 1:#x}"
    before_globals = _tail_validation_summary_tokens_8616(validation, "before", "global_writes")
    after_globals = _tail_validation_summary_tokens_8616(validation, "after", "global_writes")
    # A newly visible high byte is accepted only when the low byte survives in
    # both summaries. This treats byte-pair precision churn as validation noise,
    # not as permission to add unrelated global effects.
    return low_byte_token in before_globals and low_byte_token in after_globals


def _is_segmented_stack_slot_size_precision_delta_8616(validation: Mapping[str, StructuredAstValue]) -> bool:
    """Compatibility shim for validation-owned segmented stack-slot size precision policy."""
    return require_result_type_8616(
        segmented_stack_slot_size_precision_delta_8616(validation),
        bool,
        owner="tail_validation.segmented_stack_slot_size_precision_delta_8616",
    )


def _is_stack_prototype_width_reconciliation_delta_8616(
    codegen: StructuredAstValue,
    validation: Mapping[str, StructuredAstValue],
) -> bool:
    """Accept a size-only prototype delta backed by typed push-source evidence."""
    try:
        stats = codegen._inertia_stack_prototype_width_stats_8616
    except AttributeError:
        return False
    if stats.materialized_count <= 0 or not _has_direct_push_source_evidence_8616(codegen):
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict) or _validation_delta_touched_fields_8616(delta) != {"returns"}:
        return False
    returns_delta = delta.get("returns")
    if not isinstance(returns_delta, dict):
        return False
    added = _boundary_tuple_8616(returns_delta.get("added") or ())
    removed = _boundary_tuple_8616(returns_delta.get("removed") or ())
    if not added or len(added) != len(removed):
        return False
    for added_token, removed_token in zip(added, removed, strict=True):
        if not isinstance(added_token, str) or not isinstance(removed_token, str):
            return False
        normalized_added = re.sub(r"(stack_slot:SS:BP[+-]0x[0-9a-fA-F]+):size\d+", r"\1", added_token)
        normalized_removed = re.sub(r"(stack_slot:SS:BP[+-]0x[0-9a-fA-F]+):size\d+", r"\1", removed_token)
        if (
            normalized_added == added_token
            or normalized_removed == removed_token
            or normalized_added != normalized_removed
        ):
            return False
    try:
        accepted_count = codegen._inertia_stack_prototype_width_validation_accepts_8616
    except AttributeError:
        accepted_count = 0
    codegen._inertia_stack_prototype_width_validation_accepts_8616 = int(accepted_count or 0) + 1
    return True


def _stack_offset_marker_8616(offset: int) -> str:
    sign = "-" if offset < 0 else "+"
    return f"BP{sign}0x{abs(int(offset)):x}"


def _direct_global_update_evidence_addresses_8616(codegen: StructuredAstValue) -> frozenset[int]:
    addresses: set[int] = set()
    for start, _width in _direct_global_update_evidence_spans_8616(codegen):
        addresses.add(start)
    return frozenset(addresses)


def _direct_global_update_evidence_spans_8616(
    codegen: StructuredAstValue,
) -> frozenset[tuple[int, int]]:
    spans: set[tuple[int, int]] = set()
    for evidence in _boundary_tuple_8616(getattr(codegen, "_inertia_direct_global_update_evidence_8616", ()) or ()):
        if not isinstance(evidence, (tuple, list)):
            continue
        displacement = None
        width = 1
        for item in tuple(evidence):
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                continue
            key, value = item
            if key == "displacement" and isinstance(value, int):
                displacement = value & 0xFFFF
            elif key == "width" and isinstance(value, int):
                width = max(1, int(value))
        if displacement is not None:
            spans.add((displacement, width))
    return frozenset(spans)


def _direct_global_update_candidate_spans_8616(
    codegen: StructuredAstValue,
) -> frozenset[tuple[int, int]]:
    spans = _direct_global_update_evidence_spans_8616(codegen)
    if spans:
        return spans
    project = getattr(codegen, "project", None)
    function = getattr(codegen, "_inertia_current_function_8616", None)
    if project is None or function is None:
        return frozenset()
    candidate_spans: set[tuple[int, int]] = set()
    for fact in _direct_global_update_instruction_facts_8616(project, function):
        displacement = getattr(fact, "displacement", None)
        width = getattr(fact, "width", None)
        if isinstance(displacement, int) and isinstance(width, int):
            candidate_spans.add((displacement & 0xFFFF, max(1, int(width))))
    return frozenset(candidate_spans)


def _addr_in_direct_global_update_spans_8616(addr: int, spans: frozenset[tuple[int, int]]) -> bool:
    normalized_addr = int(addr) & 0xFFFF
    for start, width in spans:
        for offset in range(max(1, int(width))):
            if ((int(start) + offset) & 0xFFFF) == normalized_addr:
                return True
    return False


def _canonical_direct_global_update_addr_8616(addr: int, spans: frozenset[tuple[int, int]]) -> int | None:
    normalized_addr = int(addr) & 0xFFFF
    for start, width in spans:
        normalized_start = int(start) & 0xFFFF
        for offset in range(max(1, int(width))):
            if ((normalized_start + offset) & 0xFFFF) == normalized_addr:
                return normalized_start
    return None


def _validation_token_has_decimal_const_8616(token: str, value: int) -> bool:
    return re.search(rf"const:{int(value) & 0xFFFF}(?![0-9])", token.lower()) is not None


def _global_addr_token_matches_direct_global_evidence_8616(
    token: StructuredAstValue, spans: frozenset[tuple[int, int]]
) -> bool:
    if not isinstance(token, str) or not spans:
        return False
    lowered = token.lower()
    global_match = re.search(r"global:0x([0-9a-f]+)", lowered)
    if global_match is not None:
        with contextlib.suppress(ValueError):
            return _addr_in_direct_global_update_spans_8616(int(global_match.group(1), 16), spans)
    if token.startswith("deref:") and not any(segment in lowered for segment in ("reg:ds", "reg:es")):
        return False
    for start, width in spans:
        for offset in range(max(1, int(width))):
            addr = (int(start) + offset) & 0xFFFF
            if _validation_token_has_decimal_const_8616(token, addr):
                return True
            # Some fingerprints preserve equivalent DS/ES address arithmetic as
            # Add(Mul(DS,16), const:addr-1), const:1. Accept this only inside a
            # memory-write token tied to a data segment.
            if (
                token.startswith("deref:")
                and _validation_token_has_decimal_const_8616(token, (addr - 1) & 0xFFFF)
                and _validation_token_has_decimal_const_8616(token, 1)
            ):
                return True
    return False


def _return_token_matches_direct_global_evidence_8616(
    token: StructuredAstValue, spans: frozenset[tuple[int, int]]
) -> bool:
    if not isinstance(token, str) or not spans:
        return False
    if "Dereference(" not in token and not token.startswith("global:"):
        return False
    return _global_addr_token_matches_direct_global_evidence_8616(token, spans)


def _normalize_direct_global_update_control_flow_token_8616(
    token: StructuredAstValue,
    spans: frozenset[tuple[int, int]],
) -> tuple[str, bool] | None:
    if not isinstance(token, str) or not spans:
        return None
    lowered = token.lower()
    if not lowered.startswith(("while-body-writes:", "for-body-writes:")):
        return None
    matched_evidence = False

    def _replace_global(match: re.Match[str]) -> str:
        nonlocal matched_evidence
        with contextlib.suppress(ValueError):
            canonical = _canonical_direct_global_update_addr_8616(int(match.group(1), 16), spans)
            if canonical is not None:
                matched_evidence = True
                return f"global:0x{canonical:x}"
        return match.group(0).lower()

    normalized = re.sub(r"global:0x([0-9a-f]+)", _replace_global, lowered)
    for start, _width in spans:
        canonical = f"global:0x{int(start) & 0xFFFF:x}"
        previous = None
        while previous != normalized:
            previous = normalized
            normalized = normalized.replace(f"{canonical},{canonical}", canonical)
    return normalized, matched_evidence


def _control_flow_delta_matches_direct_global_update_evidence_8616(
    field_delta: StructuredAstValue,
    spans: frozenset[tuple[int, int]],
) -> bool:
    if not isinstance(field_delta, dict) or not spans:
        return False
    normalized_added: set[str] = set()
    normalized_removed: set[str] = set()
    checked_evidence_token = False
    for token in _boundary_tuple_8616(field_delta.get("added") or ()):
        normalized = _normalize_direct_global_update_control_flow_token_8616(token, spans)
        if normalized is None:
            return False
        normalized_token, matched_evidence = normalized
        normalized_added.add(normalized_token)
        checked_evidence_token = checked_evidence_token or matched_evidence
    for token in _boundary_tuple_8616(field_delta.get("removed") or ()):
        normalized = _normalize_direct_global_update_control_flow_token_8616(token, spans)
        if normalized is None:
            return False
        normalized_token, matched_evidence = normalized
        normalized_removed.add(normalized_token)
        checked_evidence_token = checked_evidence_token or matched_evidence
    return checked_evidence_token and normalized_added == normalized_removed


def _control_flow_delta_is_covered_by_direct_global_update_evidence_8616(
    field_delta: StructuredAstValue,
    spans: frozenset[tuple[int, int]],
) -> bool:
    """Return whether every changed control-flow token has direct-global evidence.

    This is weaker than equality after canonicalization and is only suitable for
    direct-global update materialization.  That pass consumes binary INC/DEC
    facts, so replacing an unrelated byte artifact with the proven global update
    is a semantic correction, not cleanup.
    """
    if not isinstance(field_delta, dict) or not spans:
        return False
    saw_token = False
    saw_added_evidence = False
    for token in _boundary_tuple_8616(field_delta.get("added") or ()):
        normalized = _normalize_direct_global_update_control_flow_token_8616(token, spans)
        if normalized is None:
            return False
        _normalized_token, matched_evidence = normalized
        if not matched_evidence:
            return False
        saw_token = True
        saw_added_evidence = True
    for token in _boundary_tuple_8616(field_delta.get("removed") or ()):
        normalized = _normalize_direct_global_update_control_flow_token_8616(token, spans)
        if normalized is None:
            return False
        _normalized_token, matched_evidence = normalized
        if not matched_evidence:
            return False
        saw_token = True
    return saw_token and saw_added_evidence


def _direct_global_memory_tokens_checked_count_8616(delta: dict, spans: StructuredAstValue) -> int | None:
    """Return checked token count, or None on a rejected token."""
    checked = 0
    for field_name in ("global_writes", "segmented_writes"):
        field_delta = delta.get(field_name)
        if not isinstance(field_delta, dict):
            continue
        for token in _boundary_tuple_8616(field_delta.get("added") or ()) + _boundary_tuple_8616(
            field_delta.get("removed") or ()
        ):
            if not _global_addr_token_matches_direct_global_evidence_8616(token, spans):
                return None
            checked += 1
    return checked


def _direct_global_return_delta_ok_8616(
    delta: dict, touched_fields: StructuredAstValue, spans: StructuredAstValue
) -> bool | None:
    """Return True when checked, False on rejection, None when the field is absent."""
    return_delta = delta.get("returns")
    if isinstance(return_delta, dict):
        for token in _boundary_tuple_8616(return_delta.get("added") or ()) + _boundary_tuple_8616(
            return_delta.get("removed") or ()
        ):
            if not _return_token_matches_direct_global_evidence_8616(token, spans):
                return False
        return True
    if "returns" in touched_fields:
        return False
    return None


def _direct_global_register_delta_ok_8616(delta: dict, touched_fields: StructuredAstValue) -> bool | None:
    """Return True when checked, False on rejection, None when the field is absent."""
    register_delta = delta.get("register_writes")
    if isinstance(register_delta, dict):
        added_registers = _boundary_tuple_8616(register_delta.get("added") or ())
        removed_registers = _boundary_tuple_8616(register_delta.get("removed") or ())
        if added_registers:
            return False
        if any(not isinstance(token, str) or not token.startswith("reg:") for token in removed_registers):
            return False
        return None
    return None


def _direct_global_control_delta_ok_8616(
    delta: dict, touched_fields: StructuredAstValue, spans: StructuredAstValue
) -> bool | None:
    """Return True when checked, False on rejection, None when the field is absent."""
    control_flow_delta = delta.get("control_flow_effects")
    if isinstance(control_flow_delta, dict):
        control_tokens = _boundary_tuple_8616(control_flow_delta.get("added") or ()) + _boundary_tuple_8616(
            control_flow_delta.get("removed") or ()
        )
        if any(
            isinstance(token, str) and _direct_global_update_control_write_locations_include_stack_8616(token)
            for token in control_tokens
        ):
            return False
        return (
            _control_flow_delta_matches_direct_global_update_evidence_8616(control_flow_delta, spans)
            or _control_flow_delta_is_covered_by_direct_global_update_evidence_8616(control_flow_delta, spans)
        )
    if "control_flow_effects" in touched_fields:
        return False
    return None


def _is_direct_global_update_materialization_delta_8616(
    codegen: StructuredAstValue, validation: dict[str, StructuredAstValue]
) -> bool:
    if not isinstance(validation, dict):
        return False
    stats = getattr(codegen, "_inertia_direct_global_update_lowering_8616", None)
    if not isinstance(stats, dict) or int(stats.get("materialized_count", 0) or 0) <= 0:
        return False
    spans = _direct_global_update_evidence_spans_8616(codegen)
    if not spans:
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    touched_fields = _validation_delta_touched_fields_8616(delta)
    allowed_fields = {"global_writes", "segmented_writes", "register_writes", "returns", "control_flow_effects"}
    if not touched_fields or touched_fields - allowed_fields:
        return False

    memory_checked = _direct_global_memory_tokens_checked_count_8616(delta, spans)
    if memory_checked is None:
        return False
    checked_evidence_token = memory_checked > 0

    for field_result in (
        _direct_global_return_delta_ok_8616(delta, touched_fields, spans),
        _direct_global_register_delta_ok_8616(delta, touched_fields),
        _direct_global_control_delta_ok_8616(delta, touched_fields, spans),
    ):
        if field_result is False:
            return False
        checked_evidence_token = checked_evidence_token or bool(field_result)

    return checked_evidence_token

def _direct_global_update_control_write_locations_include_stack_8616(token: str) -> bool:
    if "-body-writes:" not in token:
        return False
    marker_positions = [
        idx
        for marker in ("global:", "deref:", "reg:", "stack:", "stack_slot:")
        for idx in (token.find(marker),)
        if idx >= 0 and idx > 0 and token[idx - 1] == ":"
    ]
    if not marker_positions:
        return False
    locations = token[min(marker_positions) :]
    return any(part.startswith(("stack:", "stack_slot:")) for part in locations.split(","))


def _stack_slot_token_from_disp_8616(disp: int, size: int) -> str:
    sign = "+" if int(disp) >= 0 else "-"
    return f"stack_slot:SS:BP{sign}0x{abs(int(disp)):x}:size{int(size)}"


def _global_byte_sum_loop_evidence_tokens_8616(
    codegen: StructuredAstValue,
) -> tuple[str, str, int] | None:
    """Return (index_token, total_token, limit) from byte-sum evidence, or None."""
    stats = getattr(codegen, "_inertia_global_byte_sum_loop_stats_8616", None)
    if not isinstance(stats, dict) or int(stats.get("materialized_count", 0) or 0) <= 0:
        return None
    evidence = getattr(codegen, "_inertia_global_byte_sum_loop_evidence_8616", None)
    if not isinstance(evidence, Mapping):
        return None
    try:
        index_token = _stack_slot_token_from_disp_8616(int(evidence["index_disp"]), 2)
        total_token = _stack_slot_token_from_disp_8616(int(evidence["total_disp"]), 2)
        limit = int(evidence["limit"])
    except (KeyError, TypeError, ValueError):
        return None
    return index_token, total_token, limit


def _global_byte_sum_delta_body_ok_8616(delta: dict, index_token: str, total_token: str, limit: int) -> bool:
    touched_fields = _validation_delta_touched_fields_8616(delta)
    if not touched_fields or touched_fields - {"stack_writes", "control_flow_effects"}:
        return False
    stack_delta = delta.get("stack_writes")
    if not isinstance(stack_delta, dict):
        return False
    if _boundary_tuple_8616(stack_delta.get("removed") or ()):
        return False
    if _boundary_tuple_8616(stack_delta.get("added") or ()) != (index_token,):
        return False
    control_delta = delta.get("control_flow_effects")
    if not isinstance(control_delta, dict):
        return False
    if _boundary_tuple_8616(control_delta.get("removed") or ()):
        return False
    expected_control = f"for-body-writes:CmpLT({index_token},const:{limit}):{total_token}"
    return _boundary_tuple_8616(control_delta.get("added") or ()) == (expected_control,)


def _is_global_byte_sum_loop_materialization_delta_8616(
    codegen: StructuredAstValue, validation: dict[str, StructuredAstValue]
) -> bool:
    if not isinstance(validation, dict):
        return False
    evidence_tokens = _global_byte_sum_loop_evidence_tokens_8616(codegen)
    if evidence_tokens is None:
        return False
    index_token, total_token, limit = evidence_tokens
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    return _global_byte_sum_delta_body_ok_8616(delta, index_token, total_token, limit)

def _direct_global_symbol_spans_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> frozenset[tuple[int, int]]:
    spans: set[tuple[int, int]] = set()
    for item in _boundary_tuple_8616(getattr(codegen, "_inertia_direct_global_symbol_store_spans_8616", ()) or ()):
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            continue
        addr, width = item
        if isinstance(addr, int) and isinstance(width, int) and width > 0:
            spans.add((addr & 0xFFFF, max(1, int(width))))
    if spans:
        return frozenset(spans)
    for key in _direct_global_symbol_refs_by_displacement_8616(project, codegen):
        if not isinstance(key, tuple) or len(key) != 2:
            continue
        addr, width = key
        if isinstance(addr, int) and isinstance(width, int) and width > 0:
            spans.add((addr & 0xFFFF, max(1, int(width))))
    return frozenset(spans)


def _segmented_global_salvage_debug_refuse_8616(
    debug: bool, reason: str, **fields: StructuredAstValue
) -> None:
    if debug:
        logging.getLogger(__name__).warning(
            "[segmented-global-salvage] refused reason=%s fields=%r",
            reason,
            fields,
        )


def _segmented_global_salvage_spans_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, debug: bool
) -> StructuredAstValue | None:
    """Return direct-global-symbol spans for salvage, or None when evidence is absent."""
    stats = getattr(codegen, "_inertia_segmented_global_load_stats_8616", None)
    direct_materialized = int(getattr(stats, "direct_symbol_materialized_count", 0) or 0)
    store_materialized = int(getattr(stats, "direct_symbol_store_materialized_count", 0) or 0)
    if direct_materialized <= 0 and store_materialized <= 0:
        _segmented_global_salvage_debug_refuse_8616(
            debug,
            "no-direct-symbol-materialization",
            stats_type=type(stats).__name__,
            direct_materialized=direct_materialized,
            store_materialized=store_materialized,
        )
        return None
    spans = _direct_global_symbol_spans_8616(project, codegen)
    if not spans:
        _segmented_global_salvage_debug_refuse_8616(
            debug,
            "no-spans",
            recorded_spans=getattr(codegen, "_inertia_direct_global_symbol_store_spans_8616", None),
        )
        return None
    return spans


def _segmented_global_memory_tokens_evidence_8616(
    delta: dict, spans: StructuredAstValue, debug: bool
) -> bool | None:
    """Return True when evidence tokens were checked, False on refusal, None when absent."""
    checked = False
    for field_name in ("global_writes", "segmented_writes"):
        field_delta = delta.get(field_name)
        if not isinstance(field_delta, dict):
            continue
        for token in _boundary_tuple_8616(field_delta.get("added") or ()) + _boundary_tuple_8616(
            field_delta.get("removed") or ()
        ):
            if not _global_addr_token_matches_direct_global_evidence_8616(token, spans):
                _segmented_global_salvage_debug_refuse_8616(
                    debug, "unmatched-memory-token", field=field_name, token=token, spans=sorted(spans)
                )
                return False
            checked = True
    return checked


def _is_segmented_global_symbol_materialization_delta_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, validation: dict[str, StructuredAstValue]
) -> bool:
    debug = bool(os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_SALVAGE"))
    if not isinstance(validation, dict):
        _segmented_global_salvage_debug_refuse_8616(
            debug, "validation-not-dict", validation_type=type(validation).__name__
        )
        return False
    spans = _segmented_global_salvage_spans_8616(project, codegen, debug)
    if spans is None:
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        _segmented_global_salvage_debug_refuse_8616(debug, "delta-not-dict", delta_type=type(delta).__name__)
        return False
    touched_fields = _validation_delta_touched_fields_8616(delta)
    allowed_fields = {"global_writes", "segmented_writes", "control_flow_effects"}
    if not touched_fields or touched_fields - allowed_fields:
        _segmented_global_salvage_debug_refuse_8616(
            debug, "unexpected-fields", touched_fields=sorted(touched_fields), spans=sorted(spans)
        )
        return False

    memory_checked = _segmented_global_memory_tokens_evidence_8616(delta, spans, debug)
    if memory_checked is False:
        return False
    checked_evidence_token = bool(memory_checked)

    control_flow_delta = delta.get("control_flow_effects")
    if isinstance(control_flow_delta, dict):
        if not _control_flow_delta_matches_direct_global_update_evidence_8616(control_flow_delta, spans):
            _segmented_global_salvage_debug_refuse_8616(
                debug, "control-flow-mismatch", control_flow_delta=control_flow_delta, spans=sorted(spans)
            )
            return False
        checked_evidence_token = True
    elif "control_flow_effects" in touched_fields:
        _segmented_global_salvage_debug_refuse_8616(
            debug, "control-flow-not-dict", control_flow_type=type(control_flow_delta).__name__
        )
        return False

    if not checked_evidence_token:
        _segmented_global_salvage_debug_refuse_8616(debug, "no-evidence-token", spans=sorted(spans))
    return checked_evidence_token

def _direct_stack_update_evidence_offsets_8616(codegen: StructuredAstValue) -> frozenset[int]:
    offsets: set[int] = set()
    for evidence in _boundary_tuple_8616(getattr(codegen, "_inertia_direct_stack_update_evidence_8616", ()) or ()):
        if not isinstance(evidence, (tuple, list)):
            continue
        for item in tuple(evidence):
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                continue
            key, value = item
            if key == "offset" and isinstance(value, int):
                offsets.add(value)
    return frozenset(offsets)


def _added_condition_introduces_raw_register_8616(token: StructuredAstValue) -> bool:
    if not isinstance(token, str):
        return False
    condition_token = token
    for prefix in ("for:", "if:", "ifbreak:", "while:"):
        if condition_token.startswith(prefix):
            condition_token = condition_token[len(prefix) :]
            break
    raw_register_markers = (
        "reg:ax",
        "reg:bx",
        "reg:cx",
        "reg:dx",
        "reg:si",
        "reg:di",
        "reg:sp",
        "reg:bp",
        "reg:flags",
        "reg:eflags",
    )
    return any(marker in condition_token for marker in raw_register_markers)


def _without_evidenced_stack_writes_8616(effect: str, evidence_markers: StructuredAstValue) -> str:
    """Remove only exact evidenced stack-write items from a validation effect."""
    canonical = effect
    for marker in evidence_markers:
        needle = f"stack_slot:SS:{marker}:"
        while (start := canonical.find(needle)) >= 0:
            end = canonical.find(",", start)
            if end >= 0:
                canonical = canonical[:start] + canonical[end + 1 :]
                continue
            previous_comma = canonical.rfind(",", 0, start)
            canonical = canonical[:previous_comma] if previous_comma >= 0 else canonical[:start]
    return canonical


def _control_delta_matches_stack_update_evidence_8616(
    token: StructuredAstValue,
    evidence_markers: StructuredAstValue,
    *,
    paired_added: tuple[StructuredAstValue, ...] = (),
) -> bool:
    if not isinstance(token, str):
        return False
    if token.startswith(("for-body-writes:", "while-body-writes:", "dowhile-body-writes:")):
        if any(marker in token for marker in evidence_markers):
            return True
        return bool(paired_added) and any(
            isinstance(added, str)
            and any(marker in added for marker in evidence_markers)
            and _without_evidenced_stack_writes_8616(added, evidence_markers)
            == _without_evidenced_stack_writes_8616(token, evidence_markers)
            for added in paired_added
        )
    if token.startswith("ifbreak:") and paired_added:
        condition = token[len("ifbreak:") :]
        loop_prefixes = (
            f"for-body-writes:{condition}:",
            f"while-body-writes:{condition}:",
            f"dowhile-body-writes:{condition}:",
            f"do-while-body-writes:{condition}:",
        )
        return any(
            isinstance(added, str)
            and added.startswith(loop_prefixes)
            and any(marker in added for marker in evidence_markers)
            for added in paired_added
        )
    return False


def _stack_offset_condition_delta_8616(
    delta: dict,
) -> tuple[tuple[StructuredAstValue, ...], tuple[StructuredAstValue, ...]] | None:
    """Return (added, removed) condition tokens, or None on a rejected delta."""
    condition_delta = delta.get("conditions")
    added_conditions: tuple[StructuredAstValue, ...] = ()
    removed_conditions: tuple[StructuredAstValue, ...] = ()
    if isinstance(condition_delta, dict):
        added_conditions = _boundary_tuple_8616(condition_delta.get("added") or ())
        removed_conditions = _boundary_tuple_8616(condition_delta.get("removed") or ())
        if any(
            not isinstance(item, str) or not item.startswith("Cmp") for item in added_conditions + removed_conditions
        ):
            return None
        added_ops = sorted({item.split("(", 1)[0] for item in added_conditions if isinstance(item, str)})
        removed_ops = sorted({item.split("(", 1)[0] for item in removed_conditions if isinstance(item, str)})
        if added_ops != removed_ops:
            return None
        if any(_added_condition_introduces_raw_register_8616(item) for item in added_conditions):
            return None
    return added_conditions, removed_conditions


def _stack_offset_control_delta_ok_8616(
    delta: dict,
    added_conditions: tuple[StructuredAstValue, ...],
    removed_conditions: tuple[StructuredAstValue, ...],
    evidence_markers: StructuredAstValue,
) -> bool:
    control_delta = delta.get("control_flow_effects")
    if not isinstance(control_delta, dict):
        return True
    added_control = _boundary_tuple_8616(control_delta.get("added") or ())
    removed_control = _boundary_tuple_8616(control_delta.get("removed") or ())
    expected_added = {f"for:{item}" for item in added_conditions} | {f"if:{item}" for item in added_conditions}
    expected_removed = {f"for:{item}" for item in removed_conditions} | {
        f"if:{item}" for item in removed_conditions
    }
    unexpected_added = set(added_control) - expected_added
    unexpected_removed = set(removed_control) - expected_removed
    if unexpected_added and not all(
        _control_delta_matches_stack_update_evidence_8616(item, evidence_markers) for item in unexpected_added
    ):
        return False
    if unexpected_removed and not all(
        _control_delta_matches_stack_update_evidence_8616(
            item, evidence_markers, paired_added=tuple(unexpected_added)
        )
        for item in unexpected_removed
    ):
        return False
    return not any(
        _added_condition_introduces_raw_register_8616(item)
        and not any(
            isinstance(item, str)
            and isinstance(removed, str)
            and _without_evidenced_stack_writes_8616(item, evidence_markers)
            == _without_evidenced_stack_writes_8616(removed, evidence_markers)
            for removed in removed_control
        )
        for item in added_control
    )


def _stack_offset_delta_tokens_8616(delta: dict) -> list[str] | None:
    """Return all added/removed tokens, or None when a non-string token appears."""
    tokens: list[str] = []
    for field_name in ("segmented_writes", "stack_writes", "conditions", "control_flow_effects"):
        field_delta = delta.get(field_name)
        if not isinstance(field_delta, dict):
            continue
        for item in _boundary_tuple_8616(field_delta.get("added") or ()) + _boundary_tuple_8616(
            field_delta.get("removed") or ()
        ):
            if not isinstance(item, str):
                return None
            tokens.append(item)
    return tokens


def _added_indexed_segmented_write_ok_8616(delta: dict) -> bool:
    segmented_delta = delta.get("segmented_writes")
    if not isinstance(segmented_delta, dict):
        return False
    added = _boundary_tuple_8616(segmented_delta.get("added") or ())
    removed = _boundary_tuple_8616(segmented_delta.get("removed") or ())
    return (
        bool(added)
        and not removed
        and all(
            isinstance(item, str) and item.startswith("deref:") and "CIndexedVariable" in item for item in added
        )
    )


def _is_stack_offset_materialization_delta_8616(
    validation: dict[str, StructuredAstValue],
    evidence_offsets: frozenset[int],
    *,
    allow_added_indexed_segmented_write: bool,
) -> bool:
    if not evidence_offsets:
        return False
    if not isinstance(validation, dict):
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    touched_fields = _validation_delta_touched_fields_8616(delta)
    allowed_fields = {"segmented_writes", "stack_writes", "conditions", "control_flow_effects"}
    if not touched_fields or touched_fields - allowed_fields:
        return False
    evidence_markers = {_stack_offset_marker_8616(offset) for offset in evidence_offsets}

    conditions = _stack_offset_condition_delta_8616(delta)
    if conditions is None:
        return False
    added_conditions, removed_conditions = conditions
    if not _stack_offset_control_delta_ok_8616(
        delta, added_conditions, removed_conditions, evidence_markers
    ):
        return False

    tokens = _stack_offset_delta_tokens_8616(delta)
    if not tokens:
        return False
    if any(marker in token for marker in evidence_markers for token in tokens):
        return True

    # Some stack-array writes fingerprint only as CIndexedVariable after the
    # stack update fact has been consumed. Keep this limited to direct updates,
    # added segmented-write precision, and consumed direct stack-update evidence.
    if allow_added_indexed_segmented_write and touched_fields == {"segmented_writes"}:
        return _added_indexed_segmented_write_ok_8616(delta)
    return False

def _is_direct_stack_update_materialization_delta_8616(
    codegen: StructuredAstValue, validation: dict[str, StructuredAstValue]
) -> bool:
    stats = getattr(codegen, "_inertia_direct_stack_update_lowering_8616", None)
    if not isinstance(stats, dict) or int(stats.get("materialized_count", 0) or 0) <= 0:
        return False
    evidence_offsets = _direct_stack_update_evidence_offsets_8616(codegen)
    delta = validation.get("delta") if isinstance(validation, dict) else None
    if (
        isinstance(delta, dict)
        and not (_validation_delta_touched_fields_8616(delta) & {"global_writes", "register_writes", "returns"})
        and not validation_stack_write_delta_offsets_are_evidenced_8616(validation, evidence_offsets)
    ):
        return False
    if _is_stack_offset_materialization_delta_8616(
        validation,
        evidence_offsets,
        allow_added_indexed_segmented_write=True,
    ):
        return True
    return _is_direct_stack_and_global_update_materialization_delta_8616(codegen, validation)


def _is_direct_stack_move_update_materialization_delta_8616(
    codegen: StructuredAstValue, validation: dict[str, StructuredAstValue]
) -> bool:
    move_stats = getattr(codegen, "_inertia_direct_stack_move_lowering_8616", None)
    update_stats = getattr(codegen, "_inertia_direct_stack_update_lowering_8616", None)
    move_materialized = isinstance(move_stats, dict) and int(move_stats.get("materialized_count", 0) or 0) > 0
    update_materialized = isinstance(update_stats, dict) and int(update_stats.get("materialized_count", 0) or 0) > 0
    if not (move_materialized or update_materialized):
        return False
    evidence_offsets = frozenset(
        set(_direct_stack_move_evidence_offsets_8616(codegen))
        | set(_direct_stack_update_evidence_offsets_8616(codegen))
    )
    delta = validation.get("delta") if isinstance(validation, dict) else None
    if (
        isinstance(delta, dict)
        and not (_validation_delta_touched_fields_8616(delta) & {"global_writes", "register_writes", "returns"})
        and not validation_stack_write_delta_offsets_are_evidenced_8616(validation, evidence_offsets)
    ):
        return False
    return _is_stack_offset_materialization_delta_8616(
        validation,
        evidence_offsets,
        allow_added_indexed_segmented_write=True,
    )


def _is_direct_stack_and_global_update_materialization_delta_8616(
    codegen: StructuredAstValue, validation: dict[str, StructuredAstValue]
) -> bool:
    if not isinstance(validation, dict):
        return False
    stack_stats = getattr(codegen, "_inertia_direct_stack_update_lowering_8616", None)
    global_stats = getattr(codegen, "_inertia_direct_global_update_lowering_8616", None)
    if not isinstance(stack_stats, dict) or int(stack_stats.get("materialized_count", 0) or 0) <= 0:
        return False
    global_materialized = isinstance(global_stats, dict) and int(global_stats.get("materialized_count", 0) or 0) > 0
    global_spans = _direct_global_update_candidate_spans_8616(codegen)
    if not global_materialized and not global_spans:
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    touched_fields = _validation_delta_touched_fields_8616(delta)
    allowed_fields = {
        "conditions",
        "control_flow_effects",
        "global_writes",
        "register_writes",
        "returns",
        "segmented_writes",
        "stack_writes",
    }
    if not touched_fields or touched_fields - allowed_fields:
        return False

    if not _stack_move_update_delta_accepted_8616(
        validation,
        _direct_stack_update_evidence_offsets_8616(codegen),
        allow_indexed=True,
    ):
        return False
    return _stack_move_global_delta_accepted_8616(
        codegen,
        validation,
        delta,
        global_materialized,
        global_spans,
    )


def _direct_stack_move_source_kind_from_evidence_8616(
    value: StructuredAstValue,
) -> DirectStackMoveSourceKind8616 | None:
    if isinstance(value, DirectStackMoveSourceKind8616):
        return value
    if isinstance(value, str):
        for kind in DirectStackMoveSourceKind8616:
            if value == kind.name or value == kind.value:
                return kind
    return None


def _direct_stack_move_evidence_offsets_8616(codegen: StructuredAstValue) -> frozenset[int]:
    offsets: set[int] = set()
    # Dynamic codegen compatibility boundary for direct stack move evidence from legacy postprocess.
    for evidence in _boundary_tuple_8616(getattr(codegen, "_inertia_direct_stack_move_evidence_8616", ()) or ()):
        if not isinstance(evidence, (tuple, list)):
            continue
        source_kind = None
        for item in tuple(evidence):
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                continue
            key, value = item
            if key == "source_kind":
                source_kind = _direct_stack_move_source_kind_from_evidence_8616(value)
            elif (key == "dst_offset" and isinstance(value, int)) or (key in {"source_offset", "source_index_offset"} and isinstance(value, int)):
                offsets.add(value)
        if source_kind is DirectStackMoveSourceKind8616.SIGNED_IDIV_REMAINDER:
            # The idiv path has additional helper/register fingerprint churn and
            # is accepted by its dedicated classifier below.
            continue
    return frozenset(offsets)


def _is_direct_stack_move_materialization_delta_8616(
    codegen: StructuredAstValue, validation: dict[str, StructuredAstValue]
) -> bool:
    # Dynamic codegen compatibility metadata recorded by lowering passes.
    stats = getattr(codegen, "_inertia_direct_stack_move_lowering_8616", None)
    if not isinstance(stats, dict) or int(stats.get("materialized_count", 0) or 0) <= 0:
        return False
    if _is_function_pointer_stack_overwrite_prune_delta_8616(codegen, validation):
        return True
    if _is_stack_offset_materialization_delta_8616(
        validation,
        _direct_stack_move_evidence_offsets_8616(codegen),
        allow_added_indexed_segmented_write=False,
    ):
        return True
    if _is_direct_stack_move_and_global_update_materialization_delta_8616(codegen, validation):
        return True
    return _is_direct_stack_move_global_precision_delta_8616(codegen, validation)


def _is_function_pointer_stack_overwrite_prune_delta_8616(
    codegen: StructuredAstValue, validation: dict[str, StructuredAstValue]
) -> bool:
    """Compatibility shim for validation-owned function-pointer prune deltas."""
    # Dynamic boundary: codegen carries optional lowering pass counters.
    stats = getattr(codegen, "_inertia_direct_stack_move_lowering_8616", None)
    if not isinstance(stats, dict):
        return False
    has_prune_counter = int(stats.get("unsupported_function_pointer_assignment_pruned_count", 0) or 0) > 0
    has_function_pointer_store_evidence = bool(_direct_stack_move_immediate_function_pointer_offsets_8616(codegen))
    return require_result_type_8616(
        direct_stack_move_function_pointer_prune_delta_8616(
            validation,
            _direct_stack_move_evidence_offsets_8616(codegen),
            has_prune_evidence=has_prune_counter or has_function_pointer_store_evidence,
        ),
        bool,
        owner="tail_validation.direct_stack_move_function_pointer_prune_delta_8616",
    )


def _direct_stack_move_immediate_function_pointer_offsets_8616(codegen: StructuredAstValue) -> frozenset[int]:
    """Return function-pointer offsets from dynamic codegen direct-stack evidence."""
    offsets: set[int] = set()
    for evidence in _boundary_tuple_8616(getattr(codegen, "_inertia_direct_stack_move_evidence_8616", ()) or ()):
        if not isinstance(evidence, (tuple, list)):
            continue
        source_kind = None
        source_value = None
        dst_offset = None
        for item in tuple(evidence):
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                continue
            key, value = item
            if key == "source_kind":
                source_kind = _direct_stack_move_source_kind_from_evidence_8616(value)
            elif key == "source_value" and isinstance(value, int):
                source_value = value
            elif key == "dst_offset" and isinstance(value, int):
                dst_offset = value
        if (
            source_kind is DirectStackMoveSourceKind8616.IMMEDIATE
            and isinstance(source_value, int)
            and source_value != 0
            and isinstance(dst_offset, int)
        ):
            offsets.add(dst_offset)
    return frozenset(offsets)


def _stack_move_update_delta_accepted_8616(
    validation: dict,
    evidence_offsets: StructuredAstValue,
    allow_indexed: bool = False,
) -> bool:
    """Return whether the stack-write portion is an evidenced stack-offset delta."""
    stack_validation = _validation_without_delta_fields_8616(
        validation,
        {"global_writes", "register_writes", "returns"},
    )
    if _is_stack_offset_materialization_delta_8616(
        stack_validation,
        evidence_offsets,
        allow_added_indexed_segmented_write=False,
    ):
        return True
    stack_validation = _validation_without_delta_fields_8616(
        validation,
        {"control_flow_effects", "global_writes", "register_writes", "returns"},
    )
    return bool(
        _is_stack_offset_materialization_delta_8616(
            stack_validation,
            evidence_offsets,
            allow_added_indexed_segmented_write=allow_indexed,
        )
    )


def _stack_move_global_delta_accepted_8616(
    codegen: StructuredAstValue,
    validation: dict,
    delta: dict,
    global_materialized: bool,
    global_spans: StructuredAstValue,
) -> bool:
    """Return whether the global/register/returns residue is evidenced."""
    global_delta = {
        field_name: field_delta
        for field_name, field_delta in delta.items()
        if field_name in {"global_writes", "register_writes", "returns"}
        and isinstance(field_delta, dict)
        and ((field_delta.get("added") or ()) or (field_delta.get("removed") or ()))
    }
    if not global_delta:
        return False
    global_validation = dict(validation)
    global_validation["delta"] = global_delta
    if global_materialized:
        return _is_direct_global_update_materialization_delta_8616(codegen, global_validation)
    if set(global_delta) != {"global_writes"}:
        return False
    field_delta = global_delta.get("global_writes")
    if not isinstance(field_delta, dict):
        return False
    tokens = _boundary_tuple_8616(field_delta.get("added") or ()) + _boundary_tuple_8616(
        field_delta.get("removed") or ()
    )
    return bool(tokens) and all(
        _global_addr_token_matches_direct_global_evidence_8616(token, global_spans) for token in tokens
    )


def _is_direct_stack_move_and_global_update_materialization_delta_8616(
    codegen: StructuredAstValue,
    validation: dict[str, StructuredAstValue],
) -> bool:
    if not isinstance(validation, dict):
        return False
    move_stats = getattr(codegen, "_inertia_direct_stack_move_lowering_8616", None)
    if not isinstance(move_stats, dict) or int(move_stats.get("materialized_count", 0) or 0) <= 0:
        return False
    global_stats = getattr(codegen, "_inertia_direct_global_update_lowering_8616", None)
    global_materialized = isinstance(global_stats, dict) and int(global_stats.get("materialized_count", 0) or 0) > 0
    global_spans = _direct_global_update_candidate_spans_8616(codegen)
    if not global_materialized and not global_spans:
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    touched_fields = _validation_delta_touched_fields_8616(delta)
    allowed_fields = {
        "conditions",
        "control_flow_effects",
        "global_writes",
        "register_writes",
        "returns",
        "segmented_writes",
        "stack_writes",
    }
    if not touched_fields or touched_fields - allowed_fields:
        return False

    evidence_offsets = _direct_stack_move_evidence_offsets_8616(codegen)
    if not validation_stack_write_delta_offsets_are_evidenced_8616(validation, evidence_offsets):
        return False

    if not _stack_move_update_delta_accepted_8616(validation, evidence_offsets):
        return False
    return _stack_move_global_delta_accepted_8616(
        codegen,
        validation,
        delta,
        global_materialized,
        global_spans,
    )


def _stack_move_precision_conditions_ok_8616(
    codegen: StructuredAstValue,
    delta: dict,
    touched_fields: set,
) -> tuple[bool, tuple[str, ...]]:
    """Return whether removed conditions are Cmp tokens over proven offsets."""
    if "conditions" not in touched_fields:
        return True, ()
    condition_delta = delta.get("conditions")
    if not isinstance(condition_delta, dict):
        return False, ()
    added_conditions = _boundary_tuple_8616(condition_delta.get("added") or ())
    removed_condition_values = _boundary_tuple_8616(condition_delta.get("removed") or ())
    if added_conditions or not removed_condition_values:
        return False, ()
    evidence_offsets = _direct_stack_move_evidence_offsets_8616(codegen)
    if not evidence_offsets:
        return False, ()
    removed_conditions = tuple(item for item in removed_condition_values if isinstance(item, str))
    if len(removed_conditions) != len(removed_condition_values):
        return False, ()
    if not all(item.startswith("Cmp") for item in removed_conditions):
        return False, ()
    if not all(validation_stack_offsets_in_token_8616(item) <= evidence_offsets for item in removed_conditions):
        return False, ()
    return True, removed_conditions


def _stack_move_precision_globals_ok_8616(
    delta: dict,
    global_spans: StructuredAstValue,
    touched_fields: set,
) -> tuple[bool, bool]:
    """Return whether global tokens match direct-global evidence; (ok, checked)."""
    global_delta = delta.get("global_writes")
    if isinstance(global_delta, dict):
        global_tokens = _boundary_tuple_8616(global_delta.get("added") or ()) + _boundary_tuple_8616(
            global_delta.get("removed") or ()
        )
        if not global_tokens:
            return False, False
        if not all(
            _global_addr_token_matches_direct_global_evidence_8616(token, global_spans) for token in global_tokens
        ):
            return False, False
        return True, True
    if "global_writes" in touched_fields:
        return False, False
    return True, False


def _stack_move_precision_control_ok_8616(
    delta: dict,
    global_spans: StructuredAstValue,
    touched_fields: set,
    removed_conditions: tuple[str, ...],
) -> tuple[bool, bool]:
    """Return whether control deltas are covered by direct-global evidence."""
    control_flow_delta = delta.get("control_flow_effects")
    if isinstance(control_flow_delta, dict):
        removed_ifbreaks = {f"ifbreak:{condition}" for condition in removed_conditions}
        removed_control = _boundary_tuple_8616(control_flow_delta.get("removed") or ())
        if removed_ifbreaks and not removed_ifbreaks <= {item for item in removed_control if isinstance(item, str)}:
            return False, False
        global_control_delta = {
            "added": _boundary_tuple_8616(control_flow_delta.get("added") or ()),
            "removed": tuple(item for item in removed_control if item not in removed_ifbreaks),
        }
        if not (
            _control_flow_delta_matches_direct_global_update_evidence_8616(global_control_delta, global_spans)
            or _control_flow_delta_is_covered_by_direct_global_update_evidence_8616(
                global_control_delta,
                global_spans,
            )
        ):
            return False, False
        return True, True
    if "control_flow_effects" in touched_fields or removed_conditions:
        return False, False
    return True, False


def _is_direct_stack_move_global_precision_delta_8616(
    codegen: StructuredAstValue, validation: dict[str, StructuredAstValue]
) -> bool:
    """Accept direct stack-move deltas that only reveal proven global write precision."""
    if not isinstance(validation, dict):
        return False
    stats = getattr(codegen, "_inertia_direct_stack_move_lowering_8616", None)
    if not isinstance(stats, dict) or int(stats.get("materialized_count", 0) or 0) <= 0:
        return False
    global_spans = _direct_global_update_candidate_spans_8616(codegen)
    if not global_spans:
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    touched_fields = _validation_delta_touched_fields_8616(delta)
    if not touched_fields or touched_fields - {"global_writes", "control_flow_effects", "conditions"}:
        return False
    conditions_ok, removed_conditions = _stack_move_precision_conditions_ok_8616(
        codegen, delta, touched_fields
    )
    if not conditions_ok:
        return False
    globals_ok, checked_global = _stack_move_precision_globals_ok_8616(
        delta, global_spans, touched_fields
    )
    if not globals_ok:
        return False
    control_ok, checked_control = _stack_move_precision_control_ok_8616(
        delta, global_spans, touched_fields, removed_conditions
    )
    if not control_ok:
        return False
    return checked_global or checked_control


def _is_conditional_continue_guard_repair_delta_8616(
    codegen: StructuredAstValue,
    validation: Mapping[str, StructuredAstValue],
) -> bool:
    """Compatibility shim for validation-owned conditional-continue delta policy."""
    # Dynamic codegen compatibility boundary for structuring materialization counters.
    stats = getattr(codegen, "_inertia_structuring_conditional_continue_stats_8616", None)
    # Dynamic codegen compatibility boundary for structuring materialization counters.
    materialized_count = int(getattr(stats, "materialized_count", 0) or 0)
    return require_result_type_8616(
        conditional_continue_guard_repair_delta_8616(materialized_count, validation),
        bool,
        owner="tail_validation.conditional_continue_guard_repair_delta_8616",
    )


def _is_switch_loop_exit_return_repair_delta_8616(
    codegen: StructuredAstValue,
    validation: Mapping[str, StructuredAstValue],
) -> bool:
    """Compatibility shim for validation-owned switch-loop exit-return delta policy."""
    # Dynamic codegen compatibility boundary for structuring materialization counters.
    stats = getattr(codegen, "_inertia_structuring_switch_loop_exit_return_stats_8616", None)
    # Dynamic codegen compatibility boundary for structuring materialization counters.
    materialized_count = int(getattr(stats, "materialized_count", 0) or 0)
    if materialized_count <= 0:
        # Dynamic codegen compatibility boundary for legacy materialization flag.
        legacy_materialized = bool(getattr(codegen, "_inertia_switch_loop_exit_return_materialized_8616", False))
    else:
        legacy_materialized = False
    if legacy_materialized:
        materialized_count = 1
    return require_result_type_8616(
        switch_loop_exit_return_repair_delta_8616(materialized_count, validation),
        bool,
        owner="tail_validation.switch_loop_exit_return_repair_delta_8616",
    )


def _direct_stack_move_has_signed_idiv_remainder_evidence_8616(codegen: StructuredAstValue) -> bool:
    stats = getattr(codegen, "_inertia_direct_stack_move_lowering_8616", None)
    if not isinstance(stats, dict) or int(stats.get("materialized_count", 0) or 0) <= 0:
        return False
    for evidence in _boundary_tuple_8616(getattr(codegen, "_inertia_direct_stack_move_evidence_8616", ()) or ()):
        if not isinstance(evidence, (tuple, list)):
            continue
        for item in tuple(evidence):
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                continue
            key, value = item
            if key == "source_kind" and (
                _direct_stack_move_source_kind_from_evidence_8616(value)
                is DirectStackMoveSourceKind8616.SIGNED_IDIV_REMAINDER
            ):
                return True
    return False


def _is_direct_stack_move_idiv_remainder_aux_delta_8616(validation: Mapping[str, StructuredAstValue]) -> bool:
    """Compatibility shim for validation-owned idiv-remainder auxiliary delta policy."""
    return require_result_type_8616(
        direct_stack_move_idiv_remainder_aux_delta_8616(validation),
        bool,
        owner="tail_validation.direct_stack_move_idiv_remainder_aux_delta_8616",
    )


def _validation_without_delta_fields_8616(
    validation: dict[str, StructuredAstValue], fields: set[str]
) -> dict[str, StructuredAstValue]:
    """Compatibility shim for validation-owned delta-field stripping."""
    return require_result_type_8616(
        validation_without_delta_fields_8616(validation, fields),
        dict,
        owner="tail_validation.validation_without_delta_fields_8616",
    )


def _is_direct_stack_move_idiv_remainder_materialization_delta_8616(
    codegen: StructuredAstValue, validation: dict[str, StructuredAstValue]
) -> bool:
    if not _direct_stack_move_has_signed_idiv_remainder_evidence_8616(codegen):
        return False
    if _is_direct_stack_move_idiv_remainder_aux_delta_8616(validation):
        return True
    stripped = _validation_without_delta_fields_8616(validation, {"helper_calls", "register_writes"})
    stripped_delta = stripped.get("delta")
    if not isinstance(stripped_delta, dict) or not stripped_delta:
        return False
    return _is_direct_stack_update_materialization_delta_8616(
        codegen, stripped
    ) and _is_direct_stack_move_idiv_remainder_aux_delta_8616(
        _validation_without_delta_fields_8616(validation, set(stripped_delta.keys()))
    )


def _helper_call_token_is_named_stack_probe_8616(project: StructuredAstValue, token: StructuredAstValue) -> bool:
    if not isinstance(token, str):
        return False
    if token.startswith("name:") and _calls._is_stack_probe_call_name_8616(token.removeprefix("name:")):
        return True
    addr = _helper_call_addr_token_8616(token)
    if not isinstance(addr, int):
        return False
    funcs = getattr(getattr(project, "kb", None), "functions", None) if project is not None else None
    if funcs is None:
        return False
    for candidate in (addr, addr & 0xFFFF):
        func = None
        with contextlib.suppress(Exception):
            func = funcs.function(addr=candidate, create=False)
        if func is not None and _calls._is_stack_probe_call_name_8616(getattr(func, "name", None)):
            return True
    return False


def _helper_call_token_is_stack_probe_evidenced_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, token: StructuredAstValue
) -> bool:
    if not isinstance(token, str):
        return False
    expected = _stack_probe_helper_call_fingerprints_8616(codegen)
    if token in expected:
        return True
    if _helper_call_token_is_named_stack_probe_8616(project, token):
        return True
    return _removed_helper_tokens_are_source_evidenced_stack_probe_helpers_8616(codegen, (token,))


_JCC_CONDITION_MATERIALIZATION_REMOVABLE_REG_WRITES_8616 = frozenset({"reg:ax"})
_TAIL_VALIDATION_CONTROL_CONDITION_PREFIXES_8616 = frozenset({"if", "ifbreak", "while", "dowhile", "for"})
_TAIL_VALIDATION_BODY_WRITE_PREFIXES_8616 = (
    "for-body-writes:",
    "while-body-writes:",
    "do-while-body-writes:",
    "if-body-writes:",
)


def _helper_delta_added_targets_are_function_callsite_evidenced_8616(
    function: StructuredAstValue, helper_delta: dict[str, StructuredAstValue]
) -> bool:
    added_helpers = _boundary_tuple_8616(helper_delta.get("added") or ())
    removed_helpers = _boundary_tuple_8616(helper_delta.get("removed") or ())
    if not added_helpers or removed_helpers:
        return False
    expected_targets: set[str] = set()
    for callsite_addr in _boundary_tuple_8616(sorted(getattr(function, "get_call_sites", lambda: ())() or ())):
        target = getattr(function, "get_call_target", lambda _addr: None)(callsite_addr)
        if not isinstance(target, int):
            continue
        expected_targets.add(f"addr:{target:#x}")
        expected_targets.add(f"addr:{target & 0xFFFF:#x}")
        if target >= 0x1000:
            expected_targets.add(f"addr:{target - 0x1000:#x}")
    return bool(expected_targets) and set(added_helpers).issubset(expected_targets)


def _normalize_validation_condition_token_8616(token: StructuredAstValue) -> str | None:
    if not isinstance(token, str) or not token:
        return None
    return require_optional_result_type_8616(
        normalize_condition_fingerprint_algebraic_8616(normalize_condition_fingerprint_string_8616(token)),
        str,
        owner="tail_validation.normalize_condition_fingerprint_algebraic_8616",
    )


def _condition_token_from_control_effect_8616(token: StructuredAstValue) -> str | None:
    if not isinstance(token, str) or ":" not in token:
        return None
    prefix, condition_token = token.split(":", 1)
    if prefix.endswith("-body-calls"):
        base_prefix = prefix[: -len("-body-calls")]
        if base_prefix not in _TAIL_VALIDATION_CONTROL_CONDITION_PREFIXES_8616:
            return None
        body_condition_token = _condition_token_from_body_calls_control_effect_8616(condition_token)
        if body_condition_token is None:
            return None
        condition_token = body_condition_token
    elif prefix not in _TAIL_VALIDATION_CONTROL_CONDITION_PREFIXES_8616:
        return None
    return _normalize_validation_condition_token_8616(condition_token)


def _condition_token_from_body_calls_control_effect_8616(payload: str) -> str | None:
    if not payload:
        return None
    paren_index = payload.find("(")
    call_marker_indexes = [index for marker in (":name:", ":addr:") if (index := payload.find(marker)) >= 0]
    first_call_marker = min(call_marker_indexes) if call_marker_indexes else -1
    if paren_index >= 0 and (first_call_marker < 0 or paren_index < first_call_marker):
        depth = 0
        for index, char in enumerate(payload):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return payload[: index + 1]
        return None
    if first_call_marker >= 0:
        return payload[:first_call_marker]
    return None


def _control_flow_body_write_delta_8616(
    control_delta: StructuredAstValue,
) -> dict[str, tuple[StructuredAstValue, ...]] | None:
    if not isinstance(control_delta, dict):
        return None
    added = _boundary_tuple_8616(
        token
        for token in _boundary_tuple_8616(control_delta.get("added") or ())
        if isinstance(token, str) and token.startswith(_TAIL_VALIDATION_BODY_WRITE_PREFIXES_8616)
    )
    removed = _boundary_tuple_8616(
        token
        for token in _boundary_tuple_8616(control_delta.get("removed") or ())
        if isinstance(token, str) and token.startswith(_TAIL_VALIDATION_BODY_WRITE_PREFIXES_8616)
    )
    if not added and not removed:
        return None
    return {"added": added, "removed": removed}


def _control_flow_without_body_write_delta_8616(control_delta: StructuredAstValue) -> StructuredAstValue:
    if not isinstance(control_delta, dict):
        return control_delta
    return {
        "added": _boundary_tuple_8616(
            token
            for token in _boundary_tuple_8616(control_delta.get("added") or ())
            if not (isinstance(token, str) and token.startswith(_TAIL_VALIDATION_BODY_WRITE_PREFIXES_8616))
        ),
        "removed": _boundary_tuple_8616(
            token
            for token in _boundary_tuple_8616(control_delta.get("removed") or ())
            if not (isinstance(token, str) and token.startswith(_TAIL_VALIDATION_BODY_WRITE_PREFIXES_8616))
        ),
    }


def _control_flow_without_neutral_jcc_loop_shell_delta_8616(control_delta: StructuredAstValue) -> StructuredAstValue:
    if not isinstance(control_delta, dict):
        return control_delta

    def _keep_removed_8616(token: StructuredAstValue) -> bool:
        if token == "return":
            return False
        if not isinstance(token, str):
            return True
        if token == "while:const:True":
            return False
        return not token.startswith("while-body-calls:const:True:")

    return {
        "added": _boundary_tuple_8616(control_delta.get("added") or ()),
        "removed": _boundary_tuple_8616(
            token for token in _boundary_tuple_8616(control_delta.get("removed") or ()) if _keep_removed_8616(token)
        ),
    }


def _condition_without_neutral_jcc_loop_shell_delta_8616(condition_delta: StructuredAstValue) -> StructuredAstValue:
    if not isinstance(condition_delta, dict):
        return condition_delta
    return {
        "added": _boundary_tuple_8616(condition_delta.get("added") or ()),
        "removed": _boundary_tuple_8616(
            token
            for token in _boundary_tuple_8616(condition_delta.get("removed") or ())
            if str(token) not in {"const:True", "const:1"}
        ),
    }


def _jcc_removed_helpers_are_consumed_pretest_carriers_8616(
    codegen: StructuredAstValue,
    helper_delta: StructuredAstValue,
    control_delta: StructuredAstValue,
) -> bool:
    if not isinstance(helper_delta, dict) or not isinstance(control_delta, dict):
        return False
    added_helpers = _boundary_tuple_8616(helper_delta.get("added") or ())
    removed_helpers = _boundary_tuple_8616(helper_delta.get("removed") or ())
    if added_helpers or not removed_helpers:
        return False
    stats = getattr(codegen, "_inertia_structuring_pretest_loop_guard_stats_8616", None)
    removed_carriers = int(getattr(stats, "call_return_carriers_removed_count", 0) or 0)
    if removed_carriers < len(removed_helpers):
        return False
    removed_control = _boundary_tuple_8616(control_delta.get("removed") or ())
    for helper in removed_helpers:
        if not isinstance(helper, str):
            return False
        expected_markers = (
            f"while-body-calls:const:True:{helper}",
            f"dowhile-body-calls:const:True:{helper}",
            f"do-while-body-calls:const:True:{helper}",
        )
        if not any(marker in removed_control for marker in expected_markers):
            return False
    return True


def _jcc_condition_validation_evidence_8616(
    codegen: StructuredAstValue,
) -> tuple[dict[str, str], ...]:
    evidence_items: list[dict[str, str]] = []
    for item in _boundary_tuple_8616(getattr(codegen, "_inertia_jcc_condition_validation_evidence_8616", ()) or ()):
        if not isinstance(item, dict):
            continue
        removed = _normalize_validation_condition_token_8616(item.get("removed"))
        added = _normalize_validation_condition_token_8616(item.get("added"))
        if not removed or not added or removed == added:
            continue
        evidence_items.append({"removed": removed, "added": added})
    return tuple(evidence_items)


def _jcc_condition_delta_is_evidenced_8616(
    codegen: StructuredAstValue, condition_delta: StructuredAstValue, control_delta: StructuredAstValue
) -> bool:
    normalized_delta = _normalized_jcc_condition_delta_sets_8616(condition_delta, control_delta)
    if normalized_delta is None:
        return False
    added_conditions, removed_conditions, added_control_conditions, removed_control_conditions = normalized_delta
    if not (added_conditions or removed_conditions or added_control_conditions or removed_control_conditions):
        return True

    evidence = _jcc_condition_validation_evidence_8616(codegen)
    if evidence:
        evidenced_added = {item["added"] for item in evidence}
        evidenced_removed = {item["removed"] for item in evidence}
        if not added_conditions - evidenced_added and not removed_conditions - evidenced_removed:  # noqa: SIM102
            if not added_control_conditions - evidenced_added and not removed_control_conditions - evidenced_removed:
                return True
    if _jcc_condition_delta_matches_decoded_fingerprints_8616(codegen, normalized_delta):
        return True
    return _jcc_condition_delta_matches_structuring_evidence_8616(codegen, normalized_delta)


def _normalized_delta_token_set_8616(
    field_delta: StructuredAstValue,
    key: str,
    normalize: Callable,
) -> set[str] | None:
    """Normalize one added/removed token set, or None on an unparseable token."""
    result: set[str] = set()
    if not isinstance(field_delta, dict):
        return result
    for token in _boundary_tuple_8616(field_delta.get(key) or ()):
        normalized = normalize(token)
        if normalized is None:
            return None
        result.add(normalized)
    return result


def _normalized_jcc_condition_delta_sets_8616(
    condition_delta: StructuredAstValue, control_delta: StructuredAstValue
) -> (
    tuple[
        set[str],
        set[str],
        set[str],
        set[str],
    ]
    | None
):
    added_conditions = _normalized_delta_token_set_8616(
        condition_delta, "added", _normalize_validation_condition_token_8616
    )
    if added_conditions is None:
        return None
    removed_conditions = _normalized_delta_token_set_8616(
        condition_delta, "removed", _normalize_validation_condition_token_8616
    )
    if removed_conditions is None:
        return None
    added_control_conditions = _normalized_delta_token_set_8616(
        control_delta, "added", _condition_token_from_control_effect_8616
    )
    if added_control_conditions is None:
        return None
    removed_control_conditions = _normalized_delta_token_set_8616(
        control_delta, "removed", _condition_token_from_control_effect_8616
    )
    if removed_control_conditions is None:
        return None
    return added_conditions, removed_conditions, added_control_conditions, removed_control_conditions


def _jcc_condition_delta_matches_structuring_evidence_8616(
    codegen: StructuredAstValue,
    normalized_delta: tuple[
        set[str],
        set[str],
        set[str],
        set[str],
    ],
) -> bool:
    added_conditions, removed_conditions, added_control_conditions, removed_control_conditions = normalized_delta
    for item in _boundary_tuple_8616(
        getattr(codegen, "_inertia_structuring_jcc_condition_validation_deltas_8616", ()) or ()
    ):
        if not isinstance(item, dict):
            continue
        candidate = _normalized_jcc_condition_delta_sets_8616(
            item.get("conditions"),
            item.get("control_flow_effects"),
        )
        if candidate is None:
            continue
        (
            candidate_added_conditions,
            candidate_removed_conditions,
            candidate_added_control_conditions,
            candidate_removed_control_conditions,
        ) = candidate
        if (
            added_conditions == candidate_added_conditions
            and removed_conditions == candidate_removed_conditions
            and added_control_conditions == candidate_added_control_conditions
            and removed_control_conditions == candidate_removed_control_conditions
        ):
            return True
    return False


def _jcc_condition_delta_matches_decoded_fingerprints_8616(
    codegen: StructuredAstValue,
    normalized_delta: tuple[
        set[str],
        set[str],
        set[str],
        set[str],
    ],
) -> bool:
    added_conditions, removed_conditions, added_control_conditions, removed_control_conditions = normalized_delta
    if not added_conditions or len(added_conditions) != len(removed_conditions):
        return False
    if added_control_conditions != added_conditions or removed_control_conditions != removed_conditions:
        return False
    decoded: set[str] = set()
    for token in _boundary_tuple_8616(getattr(codegen, "_inertia_jcc_decoded_condition_fingerprints_8616", ()) or ()):
        normalized = _normalize_validation_condition_token_8616(token)
        if normalized is not None:
            decoded.add(normalized)
    return not (not decoded or added_conditions - decoded)


def _jcc_condition_delta_is_complement_rewrite_8616(
    normalized_delta: tuple[
        set[str],
        set[str],
        set[str],
        set[str],
    ],
) -> bool:
    added_conditions, removed_conditions, added_control_conditions, removed_control_conditions = normalized_delta
    if not added_conditions:
        return False
    if added_control_conditions != added_conditions or not removed_control_conditions:
        return False
    if removed_conditions and len(added_conditions) != len(removed_conditions):
        return False
    if len(added_conditions) != len(removed_control_conditions):
        return False
    if removed_conditions and removed_control_conditions != removed_conditions:
        return False
    inverted_removed_control: set[str] = set()
    for condition in removed_control_conditions:
        inverted = invert_condition_fingerprint_string_8616(condition)
        if inverted is None:
            return False
        normalized = _normalize_validation_condition_token_8616(inverted)
        if normalized is None:
            return False
        inverted_removed_control.add(normalized)
    return added_conditions == inverted_removed_control


def _jcc_condition_field_deltas_ok_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    function: StructuredAstValue,
    validation: dict,
    delta: dict,
) -> bool:
    """Return whether all non-condition field deltas are proven benign."""
    return (
        _jcc_helper_delta_ok_8616(project, codegen, function, delta)
        and _jcc_register_delta_ok_8616(delta)
        and _jcc_global_delta_ok_8616(delta, validation)
        and _jcc_stack_delta_ok_8616(codegen, validation, delta)
    )


def _jcc_materialization_evidence_present_8616(
    codegen: StructuredAstValue,
    complement_rewrite: bool,
) -> bool:
    """Return whether any JCC condition materialization evidence exists."""
    return bool(
        int(getattr(codegen, "_inertia_semantic_condition_materialized_count", 0) or 0) > 0
        or int(getattr(codegen, "_inertia_structuring_jcc_condition_validation_accepts_8616", 0) or 0) > 0
        or _boundary_tuple_8616(getattr(codegen, "_inertia_jcc_decoded_condition_fingerprints_8616", ()) or ())
        or complement_rewrite
    )


def _jcc_body_write_evidence_gate_8616(
    codegen: StructuredAstValue,
    control_flow_delta: StructuredAstValue,
) -> tuple[StructuredAstValue, bool]:
    """Strip a proven body-write delta; return the reduced delta and verdict."""
    body_write_delta = _control_flow_body_write_delta_8616(control_flow_delta)
    if body_write_delta is None:
        return control_flow_delta, True
    evidence_offsets = frozenset(
        set(_direct_stack_move_evidence_offsets_8616(codegen))
        | set(_direct_stack_update_evidence_offsets_8616(codegen))
    )
    body_write_validation = {"delta": {"control_flow_effects": body_write_delta}}
    if not _is_stack_offset_materialization_delta_8616(
        body_write_validation,
        evidence_offsets,
        allow_added_indexed_segmented_write=True,
    ):
        return control_flow_delta, False
    return _control_flow_without_body_write_delta_8616(control_flow_delta), True


def _jcc_helper_delta_ok_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    function: StructuredAstValue,
    delta: dict,
) -> bool:
    """Return whether added/removed helper calls are evidenced."""
    helper_delta = delta.get("helper_calls")
    if not isinstance(helper_delta, dict):
        return True
    added_helpers = _boundary_tuple_8616(helper_delta.get("added") or ())
    removed_helpers = _boundary_tuple_8616(helper_delta.get("removed") or ())
    if removed_helpers and not _jcc_removed_helpers_are_consumed_pretest_carriers_8616(
        codegen,
        helper_delta,
        delta.get("control_flow_effects"),
    ):
        return False
    helper_evidenced = (
        all(_helper_call_token_is_stack_probe_evidenced_8616(project, codegen, token) for token in added_helpers)
        if added_helpers
        else True
    )
    if added_helpers and not helper_evidenced:
        helper_evidenced = _helper_delta_added_targets_are_function_callsite_evidenced_8616(
            function,
            helper_delta,
        )
    return not added_helpers or helper_evidenced


def _jcc_register_delta_ok_8616(delta: dict) -> bool:
    """Return whether register-write deltas only remove proven removable writes."""
    register_delta = delta.get("register_writes")
    if not isinstance(register_delta, dict):
        return True
    added_registers = _boundary_tuple_8616(register_delta.get("added") or ())
    removed_registers = _boundary_tuple_8616(register_delta.get("removed") or ())
    if added_registers:
        return False
    return not removed_registers or set(removed_registers).issubset(
        _JCC_CONDITION_MATERIALIZATION_REMOVABLE_REG_WRITES_8616
    )


def _jcc_global_delta_ok_8616(delta: dict, validation: dict) -> bool:
    """Return whether global-write deltas only add adjacent high-byte precision."""
    global_delta = delta.get("global_writes")
    if not isinstance(global_delta, dict):
        return True
    added_globals = _boundary_tuple_8616(global_delta.get("added") or ())
    removed_globals = _boundary_tuple_8616(global_delta.get("removed") or ())
    if removed_globals:
        return False
    return not added_globals or all(
        _is_adjacent_global_high_byte_precision_delta_8616(token, validation) for token in added_globals
    )


def _jcc_stack_delta_ok_8616(
    codegen: StructuredAstValue,
    validation: dict,
    delta: dict,
) -> bool:
    """Return whether stack-write deltas are covered by direct stack evidence."""
    stack_delta = delta.get("stack_writes")
    if not isinstance(stack_delta, dict):
        return True
    evidence_offsets = frozenset(
        set(_direct_stack_move_evidence_offsets_8616(codegen))
        | set(_direct_stack_update_evidence_offsets_8616(codegen))
    )
    return validation_stack_write_delta_offsets_are_evidenced_8616(validation, evidence_offsets)


def _is_jcc_condition_materialization_validation_delta_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    validation: dict[str, StructuredAstValue],
    *,
    function: StructuredAstValue | None = None,
) -> bool:
    if not isinstance(validation, dict):
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    condition_delta = _condition_without_neutral_jcc_loop_shell_delta_8616(delta.get("conditions"))
    control_flow_delta = _control_flow_without_neutral_jcc_loop_shell_delta_8616(delta.get("control_flow_effects"))
    normalized_delta = _normalized_jcc_condition_delta_sets_8616(
        condition_delta,
        control_flow_delta,
    )
    complement_rewrite = normalized_delta is not None and _jcc_condition_delta_is_complement_rewrite_8616(
        normalized_delta
    )
    if not _jcc_materialization_evidence_present_8616(codegen, complement_rewrite):
        return False
    returns_delta = delta.get("returns")
    empty_void_return_removed = False
    if isinstance(returns_delta, dict):
        return_added = _boundary_tuple_8616(returns_delta.get("added") or ())
        return_removed = _boundary_tuple_8616(returns_delta.get("removed") or ())
        empty_void_return_removed = not return_added and return_removed == ("none",)

    allowed_touched_fields = {
        "conditions",
        "control_flow_effects",
        "helper_calls",
        "global_writes",
        "register_writes",
        "stack_writes",
    }
    if empty_void_return_removed:
        allowed_touched_fields.add("returns")
    touched_fields = _validation_delta_touched_fields_8616(delta)
    if not touched_fields or touched_fields - allowed_touched_fields:
        return False

    control_delta_for_condition_evidence, body_write_ok = _jcc_body_write_evidence_gate_8616(
        codegen,
        control_flow_delta,
    )
    if not body_write_ok:
        return False

    if not _jcc_condition_delta_is_evidenced_8616(
        codegen,
        delta.get("conditions"),
        control_delta_for_condition_evidence,
    ) and not complement_rewrite:
        return False

    return _jcc_condition_field_deltas_ok_8616(project, codegen, function, validation, delta)


def _is_combined_jcc_callsite_stack_validation_delta_8616(
    project: StructuredAstValue,
    function: StructuredAstValue,
    codegen: StructuredAstValue,
    validation: dict[str, StructuredAstValue],
) -> bool:
    if not isinstance(validation, dict):
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    touched_fields = _validation_delta_touched_fields_8616(delta)
    if not {"conditions", "control_flow_effects"} & touched_fields:
        return False
    if not {"global_writes", "segmented_writes"} & touched_fields:
        return False
    jcc_validation = _validation_without_delta_fields_8616(
        validation,
        {"segmented_writes", "stack_writes", "returns"},
    )
    callsite_validation = _validation_without_delta_fields_8616(
        validation,
        {"conditions", "control_flow_effects", "helper_calls", "register_writes"},
    )
    return _is_jcc_condition_materialization_validation_delta_8616(
        project,
        codegen,
        jcc_validation,
        function=function,
    ) and _is_callsite_stack_argument_materialization_delta_8616(codegen, callsite_validation)


def _direct_stack_move_validation_delta_kind_8616(
    codegen: StructuredAstValue,
    validation: dict[str, StructuredAstValue],
) -> _PostprocessValidationDeltaKind8616 | None:
    if _is_direct_stack_move_materialization_delta_8616(
        codegen, validation
    ) or _is_direct_stack_move_idiv_remainder_materialization_delta_8616(codegen, validation):
        return _PostprocessValidationDeltaKind8616.DIRECT_STACK_MOVE_MATERIALIZATION
    if _is_callsite_stack_argument_materialization_delta_8616(codegen, validation):
        return _PostprocessValidationDeltaKind8616.CALLSITE_STACK_ARGUMENT_MATERIALIZATION
    return None


def _call_fingerprint_args_text_8616(token: StructuredAstValue) -> str | None:
    if not isinstance(token, str) or not token.startswith("call:"):
        return None
    open_idx = token.find("(")
    close_idx = token.rfind(")")
    if open_idx < 0 or close_idx < open_idx:
        return None
    return token[open_idx + 1 : close_idx]


def _strip_stack_arg_size_annotations_8616(token: StructuredAstValue) -> str | None:
    if not isinstance(token, str):
        return None
    return re.sub(r"(stack_arg:[A-Za-z_][A-Za-z0-9_]*):size\d+", r"\1", token)


def _has_direct_push_source_evidence_8616(codegen: StructuredAstValue) -> bool:
    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    if not isinstance(summary_map, dict):
        return False
    for summary in summary_map.values():
        push_sources = getattr(summary, "push_arg_sources", None)
        if not isinstance(push_sources, tuple):
            continue
        if any(isinstance(source, tuple) and source for source in push_sources):
            return True
    return False


def _stack_arg_slot_aliases_from_codegen_8616(
    codegen: StructuredAstValue,
) -> dict[tuple[str, int | None], str]:
    aliases: dict[tuple[str, int | None], str] = {}
    cfunc = getattr(codegen, "cfunc", None)
    for arg in _boundary_tuple_8616(getattr(cfunc, "arg_list", ()) or ()):
        variable = getattr(arg, "variable", None)
        if not isinstance(variable, SimStackVariable) or getattr(variable, "base", None) != "bp":
            continue
        offset = getattr(variable, "offset", None)
        if not isinstance(offset, int) or offset <= 0:
            continue
        name = getattr(arg, "name", None) or getattr(variable, "name", None)
        if not isinstance(name, str) or not name:
            continue
        size = getattr(variable, "size", None)
        size_value = int(size) if isinstance(size, int) and size > 0 else None
        slot = _stack_slot_fingerprint_from_slot_8616(offset, size_value)
        aliases[(name, size_value)] = slot
        aliases[(name, None)] = slot
    return aliases


_STACK_SLOT_WRITE_TOKEN_RE_8616 = re.compile(r"stack_slot:SS:BP[+-]0x[0-9a-fA-F]+:size\d+")


def _is_stack_arg_slot_alias_condition_delta_8616(
    codegen: StructuredAstValue, delta: dict[str, StructuredAstValue]
) -> bool:
    """Compatibility shim for validation-owned stack-arg alias deltas."""
    aliases = _stack_arg_slot_aliases_from_codegen_8616(codegen)
    return require_result_type_8616(
        callsite_stack_arg_slot_alias_condition_delta_8616(delta, aliases),
        bool,
        owner="tail_validation.callsite_stack_arg_slot_alias_condition_delta_8616",
    )


def _is_callsite_far_pointer_remnant_prune_delta_8616(
    codegen: StructuredAstValue, delta: dict[str, StructuredAstValue]
) -> bool:
    """Compatibility shim for validation-owned far-pointer remnant prune deltas."""
    # Dynamic boundary: codegen carries optional postprocess pass counters.
    pruned = int(getattr(codegen, "_inertia_callsite_pre_call_farptr_high_byte_remnants_pruned_8616", 0) or 0)
    return require_result_type_8616(
        callsite_far_pointer_remnant_prune_delta_8616(pruned, delta),
        bool,
        owner="tail_validation.callsite_far_pointer_remnant_prune_delta_8616",
    )


def _is_callsite_resolved_indirect_helper_stack_delta_8616(
    codegen: StructuredAstValue, delta: dict[str, StructuredAstValue]
) -> bool:
    """Compatibility shim for validation-owned resolved-indirect helper stack deltas."""
    if not callsite_resolved_indirect_helper_stack_delta_8616(delta):
        return False
    codegen._inertia_callsite_resolved_indirect_helper_stack_delta_accepts_8616 = (
        int(getattr(codegen, "_inertia_callsite_resolved_indirect_helper_stack_delta_accepts_8616", 0) or 0) + 1
    )
    return True


def _callsite_target_addr_evidence_8616(codegen: StructuredAstValue) -> frozenset[int]:
    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    if not isinstance(summary_map, dict):
        return frozenset()
    targets: set[int] = set()
    for summary in summary_map.values():
        target = getattr(summary, "target_addr", None)
        if isinstance(target, int):
            targets.add(target)
            targets.add(target & 0xFFFF)
    return frozenset(targets)


def _callsite_pruned_stack_write_tokens_8616(codegen: StructuredAstValue) -> frozenset[str]:
    tokens = getattr(codegen, "_inertia_callsite_pruned_stack_write_tokens_8616", ())
    if not isinstance(tokens, tuple):
        return frozenset()
    return frozenset(
        token for token in tokens if isinstance(token, str) and _STACK_SLOT_WRITE_TOKEN_RE_8616.fullmatch(token)
    )


def _is_callsite_mixed_helper_stack_control_delta_8616(
    codegen: StructuredAstValue, delta: dict[str, StructuredAstValue]
) -> bool:
    """Compatibility shim for validation-owned mixed helper/stack/control deltas."""
    target_evidence = _callsite_target_addr_evidence_8616(codegen)
    pruned_stack_tokens = _callsite_pruned_stack_write_tokens_8616(codegen)
    if not callsite_mixed_helper_stack_control_delta_8616(delta, target_evidence, pruned_stack_tokens):
        return False
    codegen._inertia_callsite_mixed_helper_stack_control_delta_accepts_8616 = (
        int(getattr(codegen, "_inertia_callsite_mixed_helper_stack_control_delta_accepts_8616", 0) or 0) + 1
    )
    return True


def _is_callsite_consumed_stack_store_prune_delta_8616(
    codegen: StructuredAstValue, delta: dict[str, StructuredAstValue]
) -> bool:
    """Compatibility shim for validation-owned consumed stack-store prune deltas."""
    # Dynamic boundary: codegen carries optional postprocess pass counters.
    pruned_count = int(getattr(codegen, "_inertia_consumed_segmented_stack_byte_arg_store_pruned_8616", 0) or 0)
    return require_result_type_8616(
        callsite_consumed_stack_store_prune_delta_8616(pruned_count, delta),
        bool,
        owner="tail_validation.callsite_consumed_stack_store_prune_delta_8616",
    )


def _is_callsite_helper_control_target_delta_8616(
    codegen: StructuredAstValue, delta: dict[str, StructuredAstValue]
) -> bool:
    """Compatibility shim for validation-owned callsite helper target deltas."""
    target_evidence = _callsite_target_addr_evidence_8616(codegen)
    if not callsite_helper_control_target_delta_8616(delta, target_evidence):
        return False
    codegen._inertia_callsite_helper_control_target_delta_accepts_8616 = (
        int(getattr(codegen, "_inertia_callsite_helper_control_target_delta_accepts_8616", 0) or 0) + 1
    )
    return True


def _debug_callsite_arg_delta_refusal_8616(reason: str, **fields: StructuredAstValue) -> None:
    """Emit the env-gated refusal diagnostic for callsite stack-arg deltas."""
    if not os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
        return
    logging.getLogger(__name__).warning(
        "callsite materialization validation delta refused reason=%s fields=%r",
        reason,
        fields,
    )


def _callsite_arg_materialization_evidence_8616(codegen: StructuredAstValue) -> bool:
    """Return whether any callsite-argument materialization evidence exists."""
    callsite_stats = getattr(codegen, "_inertia_callsite_materialization_stats", None)
    materialized_args = int(getattr(callsite_stats, "call_arg_materialized_count", 0) or 0)
    if materialized_args <= 0:
        stats = getattr(codegen, "_inertia_stack_probe_fact_stats", None)
        if isinstance(stats, dict):
            materialized_args = int(stats.get("call_arg_materialized_count", 0) or 0)
        if materialized_args <= 0 and isinstance(stats, dict):
            materialized_args = int(stats.get("stack_arg_materializations", 0) or 0)
    materialized_fnptr_branches = int(getattr(codegen, "_inertia_fnptr_branch_symbols_materialized_8616", 0) or 0)
    scalar_high_byte_pruned = int(
        getattr(codegen, "_inertia_callsite_pre_call_scalar_high_byte_remnants_pruned_8616", 0) or 0
    )
    return materialized_args > 0 or materialized_fnptr_branches > 0 or scalar_high_byte_pruned > 0


def _callsite_global_writes_delta_ok_8616(
    codegen: StructuredAstValue,
    delta: dict,
    validation: dict,
) -> bool:
    """Return whether added global writes are only adjacent high-byte precision."""
    global_delta = delta.get("global_writes")
    if not isinstance(global_delta, dict):
        _debug_callsite_arg_delta_refusal_8616("global_writes_not_dict")
        return False
    added_globals = _boundary_tuple_8616(global_delta.get("added") or ())
    removed_globals = _boundary_tuple_8616(global_delta.get("removed") or ())
    if removed_globals:
        _debug_callsite_arg_delta_refusal_8616("global_writes_removed", removed=removed_globals[:6])
        return False
    if added_globals and not all(
        _is_adjacent_global_high_byte_precision_delta_8616(token, validation) for token in added_globals
    ):
        _debug_callsite_arg_delta_refusal_8616("global_writes_not_adjacent_high_byte", added=added_globals[:6])
        return False
    return True


def _callsite_global_precision_delta_8616(
    codegen: StructuredAstValue,
    delta: dict,
    validation: dict,
    touched_fields: set,
) -> bool | None:
    """Classify global/segmented-only precision deltas; None when not applicable."""
    if not touched_fields or not touched_fields <= {"global_writes", "segmented_writes"}:
        return None
    global_delta = delta.get("global_writes")
    if isinstance(global_delta, dict) and not _callsite_global_writes_delta_ok_8616(
        codegen, delta, validation
    ):
        return False
    for field_name in (
        "helper_calls",
        "register_writes",
        "stack_writes",
        "returns",
        "conditions",
        "control_flow_effects",
    ):
        field_delta = delta.get(field_name)
        if not isinstance(field_delta, dict):
            continue
        if _boundary_tuple_8616(field_delta.get("added") or ()) or _boundary_tuple_8616(
            field_delta.get("removed") or ()
        ):
            _debug_callsite_arg_delta_refusal_8616("non_memory_precision_delta", field=field_name)
            return False
    codegen._inertia_callsite_stack_arg_validation_precision_delta_accepts = (
        int(getattr(codegen, "_inertia_callsite_stack_arg_validation_precision_delta_accepts", 0) or 0) + 1
    )
    return True


def _callsite_return_token_pair_ok_8616(
    codegen: StructuredAstValue,
    added_token: StructuredAstValue,
    removed_token: StructuredAstValue,
) -> bool:
    """Return whether one added/removed return token pair is a proven rewrite."""
    added_args = _call_fingerprint_args_text_8616(added_token)
    removed_args = _call_fingerprint_args_text_8616(removed_token)
    if not added_args or added_args != removed_args:
        added_without_stack_arg_sizes = _strip_stack_arg_size_annotations_8616(added_token)
        removed_without_stack_arg_sizes = _strip_stack_arg_size_annotations_8616(removed_token)
        if (
            added_without_stack_arg_sizes is not None
            and removed_without_stack_arg_sizes is not None
            and added_without_stack_arg_sizes == removed_without_stack_arg_sizes
            and _has_direct_push_source_evidence_8616(codegen)
        ):
            codegen._inertia_callsite_stack_arg_size_precision_delta_accepts_8616 = (
                int(getattr(codegen, "_inertia_callsite_stack_arg_size_precision_delta_accepts_8616", 0) or 0) + 1
            )
            return True
        _debug_callsite_arg_delta_refusal_8616("arg_text_mismatch", added=added_token, removed=removed_token)
        return False
    if "stack_slot:" not in added_args:
        _debug_callsite_arg_delta_refusal_8616("no_stack_slot", added=added_token, removed=removed_token)
        return False
    if not isinstance(added_token, str) or not isinstance(removed_token, str):
        _debug_callsite_arg_delta_refusal_8616(
            "token_not_str",
            added_type=type(added_token).__name__,
            removed_type=type(removed_token).__name__,
        )
        return False
    if not added_token.startswith("call:<indirect>("):
        _debug_callsite_arg_delta_refusal_8616("added_not_indirect", added=added_token)
        return False
    if not removed_token.startswith("call:addr:"):
        _debug_callsite_arg_delta_refusal_8616("removed_not_addr", removed=removed_token)
        return False
    return True


def _callsite_return_global_delta_ok_8616(
    codegen: StructuredAstValue,
    delta: dict,
    validation: dict,
    touched_fields: set,
) -> bool:
    """Check the returns/global-writes field gates for callsite arg deltas."""
    if not touched_fields or touched_fields - {"returns", "global_writes"}:
        helper_delta = delta.get("helper_calls")
        _debug_callsite_arg_delta_refusal_8616(
            "touched_fields",
            touched_fields=tuple(sorted(touched_fields)),
            helper_added=_boundary_tuple_8616((helper_delta or {}).get("added") or ())[:8]
            if isinstance(helper_delta, dict)
            else (),
            helper_removed=_boundary_tuple_8616((helper_delta or {}).get("removed") or ())[:8]
            if isinstance(helper_delta, dict)
            else (),
        )
        return False
    if "global_writes" in touched_fields and not _callsite_global_writes_delta_ok_8616(
        codegen, delta, validation
    ):
        return False
    if "returns" in touched_fields:
        returns_delta = delta.get("returns")
        if not isinstance(returns_delta, dict):
            _debug_callsite_arg_delta_refusal_8616("returns_not_dict")
            return False
        added = _boundary_tuple_8616(returns_delta.get("added") or ())
        removed = _boundary_tuple_8616(returns_delta.get("removed") or ())
        if not added or len(added) != len(removed):
            _debug_callsite_arg_delta_refusal_8616("returns_count", added=added[:6], removed=removed[:6])
            return False
        for added_token, removed_token in zip(added, removed, strict=False):
            if not _callsite_return_token_pair_ok_8616(codegen, added_token, removed_token):
                return False
    return True


def _is_callsite_stack_argument_materialization_delta_8616(
    codegen: StructuredAstValue, validation: dict[str, StructuredAstValue]
) -> bool:
    """Classify callsite stack-argument deltas using dynamic codegen evidence state."""

    if not isinstance(validation, dict):
        _debug_callsite_arg_delta_refusal_8616("validation_not_dict")
        return False
    if not _callsite_arg_materialization_evidence_8616(codegen):
        _debug_callsite_arg_delta_refusal_8616(
            "no_materialization_counter",
            callsite_stats=repr(getattr(codegen, "_inertia_callsite_materialization_stats", None)),
        )
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        _debug_callsite_arg_delta_refusal_8616("delta_not_dict", keys=tuple(validation.keys()))
        return False
    touched_fields = _validation_delta_touched_fields_8616(delta)
    for predicate, counter_attr in (
        (_is_stack_arg_slot_alias_condition_delta_8616, "_inertia_callsite_stack_arg_alias_delta_accepts_8616"),
        (
            _is_callsite_far_pointer_remnant_prune_delta_8616,
            "_inertia_callsite_farptr_high_byte_remnant_delta_accepts_8616",
        ),
        (_is_callsite_resolved_indirect_helper_stack_delta_8616, None),
        (_is_callsite_mixed_helper_stack_control_delta_8616, None),
        (_is_callsite_helper_control_target_delta_8616, None),
        (
            _is_callsite_consumed_stack_store_prune_delta_8616,
            "_inertia_callsite_consumed_stack_store_prune_delta_accepts_8616",
        ),
    ):
        if predicate(codegen, delta):
            if counter_attr is not None:
                _bump_postprocess_validation_accept_counter_8616(codegen, counter_attr)
            return True
    precision_accepted = _callsite_global_precision_delta_8616(codegen, delta, validation, touched_fields)
    if precision_accepted is not None:
        return precision_accepted
    return _callsite_return_global_delta_ok_8616(codegen, delta, validation, touched_fields)


def _stack_probe_helper_call_fingerprints_8616(codegen: StructuredAstValue) -> set[str]:
    expected: set[str] = {
        token
        for token in (getattr(codegen, "_inertia_stack_probe_helper_target_fingerprints_8616", ()) or ())
        if isinstance(token, str)
    }
    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    if not isinstance(summary_map, dict):
        return expected
    for summary in summary_map.values():
        if not bool(getattr(summary, "stack_probe_helper", False)):
            continue
        target = getattr(summary, "target_addr", None)
        if not isinstance(target, int):
            continue
        for candidate in (target, target & 0xFFFF):
            expected.add(f"addr:{candidate:#x}")
            expected.add(f"name:addr:{candidate:#x}")
    return expected


def _helper_call_addr_token_8616(token: StructuredAstValue) -> int | None:
    if not isinstance(token, str):
        return None
    prefix = "name:addr:" if token.startswith("name:addr:") else "addr:" if token.startswith("addr:") else None
    if prefix is None:
        return None
    value = token[len(prefix) :]
    with contextlib.suppress(ValueError):
        return int(value, 0)
    return None


def _removed_helper_tokens_are_named_stack_probe_helpers_8616(
    codegen: StructuredAstValue, removed: tuple[StructuredAstValue, ...]
) -> bool:
    project = getattr(codegen, "project", None)
    funcs = getattr(getattr(project, "kb", None), "functions", None) if project is not None else None
    if funcs is None or not removed:
        return False
    for token in removed:
        addr = _helper_call_addr_token_8616(token)
        if not isinstance(addr, int):
            return False
        func = None
        for candidate in (addr, addr & 0xFFFF):
            with contextlib.suppress(Exception):
                func = funcs.function(addr=candidate, create=False)
            if func is not None:
                break
        if func is None or not _calls._is_stack_probe_call_name_8616(getattr(func, "name", None)):
            return False
    return True


def _removed_helper_tokens_are_source_evidenced_stack_probe_helpers_8616(
    codegen: StructuredAstValue,
    removed: tuple[StructuredAstValue, ...],
) -> bool:
    return False


def _debug_probe_cleanup_refusal_8616(reason: str, **fields: StructuredAstValue) -> None:
    """Emit the env-gated refusal diagnostic for stack-probe cleanup deltas."""
    if not os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
        return
    logging.getLogger(__name__).warning(
        "stack probe helper cleanup validation delta refused reason=%s fields=%r",
        reason,
        fields,
    )


def _is_stack_probe_helper_cleanup_delta_8616(
    codegen: StructuredAstValue, validation: dict[str, StructuredAstValue]
) -> bool:
    if not isinstance(validation, dict):
        _debug_probe_cleanup_refusal_8616("validation_not_dict")
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        _debug_probe_cleanup_refusal_8616("delta_not_dict")
        return False
    if _validation_delta_touched_fields_8616(delta) != {"helper_calls"}:
        _debug_probe_cleanup_refusal_8616("touched_fields", touched=tuple(sorted(_validation_delta_touched_fields_8616(delta))))
        return False
    helper_delta = delta.get("helper_calls")
    if not isinstance(helper_delta, dict):
        _debug_probe_cleanup_refusal_8616("helper_not_dict")
        return False
    added = _boundary_tuple_8616(helper_delta.get("added") or ())
    removed = _boundary_tuple_8616(helper_delta.get("removed") or ())
    if added or not removed:
        _debug_probe_cleanup_refusal_8616("added_or_empty_removed", added=added[:6], removed=removed[:6])
        return False
    expected = _stack_probe_helper_call_fingerprints_8616(codegen)
    if not _has_stack_probe_cleanup_evidence_8616(
        codegen
    ) and _removed_helper_tokens_are_named_stack_probe_helpers_8616(codegen, removed):
        return True
    if not _has_stack_probe_cleanup_evidence_8616(codegen):
        _debug_probe_cleanup_refusal_8616("no_stack_probe_cleanup_evidence")
        return False
    if not expected:
        _debug_probe_cleanup_refusal_8616("no_expected_fingerprints", removed=removed[:6])
        return False
    if not all(isinstance(token, str) and token in expected for token in removed):
        _debug_probe_cleanup_refusal_8616("unexpected_removed", expected=tuple(sorted(expected))[:12], removed=removed[:6])
        return False
    return True


def _has_stack_probe_cleanup_evidence_8616(codegen: StructuredAstValue) -> bool:
    summary_map = getattr(codegen, "_inertia_callsite_summaries", None)
    if isinstance(summary_map, dict):
        for summary in summary_map.values():
            if bool(getattr(summary, "stack_probe_helper", False)):
                return True

    typed_facts = getattr(codegen, "_inertia_typed_stack_probe_return_facts", None)
    if isinstance(typed_facts, dict) and typed_facts:
        return True

    fact_stats = getattr(codegen, "_inertia_stack_probe_fact_stats", None)
    if isinstance(fact_stats, dict):
        if int(fact_stats.get("stack_probe_summaries", 0) or 0) > 0:
            return True
        if int(fact_stats.get("ss_stack_address_returns", 0) or 0) > 0:
            return True

    return False


def _return_chain_values_agree_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
) -> tuple[tuple[int, ...], StructuredAstValue] | None:
    """Return proven conditional/final AX values when CFG and codegen agree."""
    materialized_values = _boundary_tuple_8616(
        int(value) for value in getattr(codegen, "_inertia_return_chain_materialized_values_8616", ()) or ()
    )
    conditional_values = tuple(int(value) for value in _ordered_conditional_return_values_8616(project, codegen))
    if conditional_values != materialized_values:
        cfg_values = tuple(
            int(value) for _cond, value in _ordered_conditional_return_pairs_from_cfg_8616(project, codegen)
        )
        if cfg_values == materialized_values:
            conditional_values = cfg_values
    if conditional_values != materialized_values:
        return None
    final_value = _last_ax_return_value_8616(project, codegen)
    if final_value is None or int(getattr(codegen, "_inertia_return_chain_final_value_8616", -1)) != int(final_value):
        return None
    return conditional_values, final_value


def _return_chain_returns_delta_ok_8616(
    returns_delta: StructuredAstValue,
    conditional_values: tuple[int, ...],
    final_value: StructuredAstValue,
) -> bool:
    """Return whether the returns delta only adds/removes proven chain values."""
    if not isinstance(returns_delta, dict):
        return False
    added_returns = _boundary_set_8616(returns_delta.get("added") or ())
    removed_returns = _boundary_set_8616(returns_delta.get("removed") or ())
    expected_added = {f"const:{value}" for value in conditional_values}
    expected_added.add(f"const:{int(final_value)}")
    if added_returns - expected_added:
        return False
    allowed_removed_returns = {"CDirtyExpression", "none"}
    for value in (*conditional_values, int(final_value)):
        if int(value) < 0:
            allowed_removed_returns.add(f"const:{int(value) & 0xFFFF}")
    return not (removed_returns - allowed_removed_returns)


def _return_chain_tail_deltas_ok_8616(
    codegen: StructuredAstValue,
    delta: dict,
) -> bool:
    """Return whether condition/control/segmented deltas match the chain evidence."""
    materialized_condition_fps = _boundary_set_8616(
        getattr(codegen, "_inertia_return_chain_materialized_condition_fingerprints_8616", ()) or ()
    )
    return _return_chain_condition_control_deltas_ok_8616(
        delta,
        materialized_condition_fps,
    ) and _return_chain_segmented_delta_ok_8616(codegen, delta)


def _return_chain_condition_control_deltas_ok_8616(
    delta: dict,
    materialized_condition_fps: set,
) -> bool:
    """Return whether conditions/control deltas only touch materialized chain conditions."""
    condition_delta = delta.get("conditions")
    if isinstance(condition_delta, dict):
        added_conditions = _boundary_set_8616(condition_delta.get("added") or ())
        if not materialized_condition_fps or added_conditions - materialized_condition_fps:
            return False
    control_flow_delta = delta.get("control_flow_effects")
    if isinstance(control_flow_delta, dict):
        added_control = _boundary_set_8616(control_flow_delta.get("added") or ())
        expected_added_control = {f"if:{fp}" for fp in materialized_condition_fps}
        if added_control - expected_added_control:
            return False
    return True


def _return_chain_segmented_delta_ok_8616(
    codegen: StructuredAstValue,
    delta: dict,
) -> bool:
    """Return whether the segmented-writes delta is explained by callsite cleanup."""
    segmented_delta = delta.get("segmented_writes")
    if not isinstance(segmented_delta, dict):
        return True
    if _boundary_tuple_8616(segmented_delta.get("added") or ()):
        return False
    removed_segmented = _boundary_tuple_8616(segmented_delta.get("removed") or ())
    if not removed_segmented:
        return True
    callsite_stats = getattr(codegen, "_inertia_callsite_materialization_stats", None)
    consumed = int(getattr(callsite_stats, "consumed_outgoing_stack_placeholder_count", 0) or 0)
    arg_materialized = int(getattr(callsite_stats, "call_arg_materialized_count", 0) or 0)
    return consumed > 0 or arg_materialized > 0 or _has_stack_probe_cleanup_evidence_8616(codegen)


def _is_cfg_return_chain_callsite_materialization_delta_8616(
    project: StructuredAstValue,
    function: StructuredAstValue,
    codegen: StructuredAstValue,
    validation: dict[str, StructuredAstValue],
) -> bool:
    if not isinstance(validation, dict):
        return False
    if not (
        getattr(codegen, "_inertia_return_chain_flattened_8616", False)
        or getattr(codegen, "_inertia_return_chain_suffix_materialized_8616", False)
    ):
        return False
    stats = getattr(codegen, "_inertia_empty_return_branch_stats_8616", None)
    if not isinstance(stats, dict):
        return False
    # Refusals here can come from broader/full-chain attempts that correctly
    # refuse prefix calls.  The proof is the suffix materialization plus CFG
    # value/final-AX agreement below, not a zero-refusal diagnostic counter.
    if int(stats.get("materialized", 0) or 0) <= 0:
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    touched_fields = {
        key
        for key, field_delta in delta.items()
        if isinstance(field_delta, dict) and ((field_delta.get("added") or ()) or (field_delta.get("removed") or ()))
    }
    allowed_fields = {"returns", "segmented_writes", "conditions", "control_flow_effects"}
    if not touched_fields or touched_fields - allowed_fields:
        return False

    agreed = _return_chain_values_agree_8616(project, codegen)
    if agreed is None:
        return False
    conditional_values, final_value = agreed

    returns_delta = delta.get("returns")
    if not _return_chain_returns_delta_ok_8616(returns_delta, conditional_values, final_value):
        return False

    return _return_chain_tail_deltas_ok_8616(codegen, delta)


def _selector_return_stack_slots_from_arg_list_8616(
    project: StructuredAstValue,
    cfunc: StructuredAstValue,
    expected_returns: set[str],
) -> set[str]:
    """Collect raw stack-slot fingerprints for selector args on the cfunc."""
    raw_slots: set[str] = set()
    for arg in _boundary_tuple_8616(getattr(cfunc, "arg_list", ()) or ()):
        variable = getattr(arg, "variable", None)
        if not isinstance(variable, SimStackVariable) or getattr(variable, "base", None) != "bp":
            continue
        offset = getattr(variable, "offset", None)
        if not isinstance(offset, int) or offset <= 0:
            continue
        size = getattr(variable, "size", None)
        try:
            arg_fingerprint = _expr_fingerprint(arg, project)
        except Exception as ex:
            logging.getLogger(__name__).debug("selector-return arg fingerprint failed: %s", ex)
            continue
        if arg_fingerprint not in expected_returns:
            continue
        if isinstance(size, int) and size > 0:
            raw_slots.add(_stack_slot_fingerprint_from_slot_8616(offset, size))
        raw_slots.add(_stack_slot_fingerprint_from_slot_8616(offset, None))
    return raw_slots


def _selector_return_expected_raw_stack_slots_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, expected_returns: set[str]
) -> set[str]:
    """Map expected selector-return arguments back to their raw BP stack slots."""
    cfunc = getattr(codegen, "cfunc", None)
    if not expected_returns:
        return set()
    raw_slots: set[str] = set()
    selector_aliases = getattr(codegen, "_inertia_return_selector_raw_stack_slot_aliases_8616", None)
    if isinstance(selector_aliases, dict):
        for arg_fingerprint, slots in selector_aliases.items():
            if not isinstance(arg_fingerprint, str) or not any(arg_fingerprint in item for item in expected_returns):
                continue
            raw_slots.update(slot for slot in tuple(slots or ()) if isinstance(slot, str))
    if cfunc is None:
        return raw_slots
    raw_slots |= _selector_return_stack_slots_from_arg_list_8616(project, cfunc, expected_returns)
    return raw_slots


def _selector_return_aliases_for_expected_8616(
    expected: str,
    raw_slots: set[str],
) -> set[str]:
    """Expand one expected selector-return fingerprint into raw-slot aliases."""
    aliases: set[str] = set()
    if "stack_arg:" in expected:
        for raw_slot in raw_slots:
            for arg_token in tuple(expected.split("stack_arg:"))[1:]:
                arg_name = arg_token.split(",", 1)[0].split(")", 1)[0]
                if not arg_name:
                    continue
                stack_arg_token = f"stack_arg:{arg_name}"
                aliases.add(expected.replace(stack_arg_token, raw_slot))
    if expected.startswith("Shl(") and expected.endswith(",const:1)"):
        inner = expected[len("Shl(") : -len(",const:1)")]
        if inner.startswith("stack_arg:"):
            for raw_slot in raw_slots:
                aliases.add(f"Mul({raw_slot},const:2)")
                aliases.add(f"Add({inner},const:-1)")
    return aliases


def _selector_return_expected_raw_return_aliases_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, expected_returns: set[str]
) -> set[str]:
    raw_slots = _selector_return_expected_raw_stack_slots_8616(project, codegen, expected_returns)
    if not raw_slots:
        return set()
    aliases = set(raw_slots)
    for expected in expected_returns:
        if not isinstance(expected, str):
            continue
        aliases |= _selector_return_aliases_for_expected_8616(expected, raw_slots)
    return aliases


def _selector_return_current_condition_fingerprints_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> set[str]:
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None) if cfunc is not None else None
    if root is None:
        return set()
    fingerprints: set[str] = set()
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CIfElse):
            continue
        for cond, _body in _boundary_tuple_8616(node.condition_and_nodes or ()):
            try:
                fingerprints.add(_expr_fingerprint(cond, project))
            except Exception as ex:
                logging.getLogger(__name__).debug("selector-return current condition fingerprint failed: %s", ex)
    return fingerprints


def _cfg_return_expr_reject_8616(
    codegen: StructuredAstValue,
) -> Callable[..., bool]:
    """Return a refusal recorder for CFG selector-return delta classification."""

    def _reject(reason: _CfgReturnExprDeltaRefusal8616, **details: StructuredAstValue) -> bool:
        refusals = _boundary_list_8616(getattr(codegen, "_inertia_cfg_return_expr_delta_refusals_8616", ()) or ())
        refusals.append({"reason": reason, "details": details})
        codegen._inertia_cfg_return_expr_delta_refusals_8616 = tuple(refusals)
        if os.environ.get("INERTIA_DEBUG_RETURN_BRANCH"):
            logging.getLogger(__name__).warning(
                "[cfg-selector-return] validation-delta refused reason=%s details=%r",
                reason.value,
                details,
            )
        return False

    return _reject


def _check_return_chain_returns_delta_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    returns_delta: dict,
    expected_returns: set,
    full_return_chain_materialized: bool,
) -> bool:
    """Return whether the returns delta only reflects proven selector returns."""
    _reject = _cfg_return_expr_reject_8616(codegen)
    added_returns = (
        _boundary_set_8616(returns_delta.get("added") or ()) if isinstance(returns_delta, dict) else set()
    )
    removed_returns = (
        _boundary_set_8616(returns_delta.get("removed") or ()) if isinstance(returns_delta, dict) else set()
    )
    if not expected_returns or added_returns - expected_returns:
        return _reject(
            _CfgReturnExprDeltaRefusal8616.UNEXPECTED_ADDED_RETURNS,
            added=tuple(sorted(added_returns)),
            expected=tuple(sorted(expected_returns)),
        )
    expected_raw_return_aliases = _selector_return_expected_raw_return_aliases_8616(
        project, codegen, expected_returns
    )
    unexpected_removed = tuple(
        sorted(
            item
            for item in removed_returns
            if item not in {"CDirtyExpression", "none"}
            and not (full_return_chain_materialized and item == "reg:ax")
            and item not in expected_raw_return_aliases
            and "CDirtyExpression" not in item
            and not item.startswith(("Concat(", "Or("))
        )
    )
    if unexpected_removed:
        return _reject(
            _CfgReturnExprDeltaRefusal8616.UNEXPECTED_REMOVED_RETURNS,
            removed=unexpected_removed,
            expected_raw_stack_slots=tuple(sorted(expected_raw_return_aliases)),
            expected=tuple(sorted(expected_returns)),
        )
    return True


def _check_full_return_chain_deltas_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    delta: dict,
    validation: dict,
    returns_delta: StructuredAstValue,
    touched_fields: set,
    allowed_fields: set,
    expected_returns: set,
) -> bool:
    """Check segmented/condition/control/helper deltas for a full selector return chain."""
    _reject = _cfg_return_expr_reject_8616(codegen)
    selector_full_return_chain = bool(expected_returns) and bool(
        "returns" in touched_fields
        and isinstance(returns_delta, dict)
        and expected_returns <= _boundary_set_8616(returns_delta.get("added") or ())
    )
    segmented_delta = delta.get("segmented_writes")
    if isinstance(segmented_delta, dict):
        added_segmented = _boundary_tuple_8616(
            str(item) for item in _boundary_tuple_8616(segmented_delta.get("added", ()) or ())
        )
        removed_segmented = _boundary_tuple_8616(
            str(item) for item in _boundary_tuple_8616(segmented_delta.get("removed", ()) or ())
        )
        if added_segmented or any(
            not item.startswith("deref:Add(Mul(reg:ss,const:16),reg:sp,const:-") for item in removed_segmented
        ):
            return _reject(
                _CfgReturnExprDeltaRefusal8616.UNEXPECTED_FIELDS,
                touched_fields=tuple(sorted(touched_fields)),
                allowed_fields=tuple(sorted(allowed_fields)),
                segmented_writes=segmented_delta,
            )
    expected_conditions = _boundary_set_8616(
        getattr(codegen, "_inertia_return_chain_materialized_condition_fingerprints_8616", ()) or ()
    )
    expected_conditions |= _selector_return_current_condition_fingerprints_8616(project, codegen)
    condition_delta = delta.get("conditions")
    if isinstance(condition_delta, dict):
        added_conditions = _boundary_set_8616(condition_delta.get("added") or ())
        if not selector_full_return_chain and (not expected_conditions or added_conditions - expected_conditions):
            return _reject(
                _CfgReturnExprDeltaRefusal8616.UNEXPECTED_ADDED_CONDITIONS,
                added=tuple(sorted(added_conditions)),
                expected=tuple(sorted(expected_conditions)),
            )
    control_delta = delta.get("control_flow_effects")
    if isinstance(control_delta, dict):
        added_control = _boundary_set_8616(control_delta.get("added") or ())
        expected_control = {f"if:{fp}" for fp in expected_conditions}
        if not selector_full_return_chain and added_control - expected_control:
            return _reject(
                _CfgReturnExprDeltaRefusal8616.UNEXPECTED_ADDED_CONTROL,
                added=tuple(sorted(added_control)),
                expected=tuple(sorted(expected_control)),
            )
    helper_delta = delta.get("helper_calls")
    if not (
        isinstance(helper_delta, dict)
        and ((helper_delta.get("added") or ()) or (helper_delta.get("removed") or ()))
    ):
        return True
    if _boundary_tuple_8616(helper_delta.get("added") or ()):
        return _reject(
            _CfgReturnExprDeltaRefusal8616.UNEXPECTED_HELPER_DELTA,
            helper_delta=helper_delta,
        )
    helper_validation = dict(validation)
    helper_validation["delta"] = {"helper_calls": helper_delta}
    if not _is_stack_probe_helper_cleanup_delta_8616(codegen, helper_validation):
        return _reject(
            _CfgReturnExprDeltaRefusal8616.UNEXPECTED_HELPER_DELTA,
            helper_delta=helper_delta,
        )
    return True


def _is_cfg_return_expr_chain_materialization_delta_8616(
    project: StructuredAstValue,
    function: StructuredAstValue,
    codegen: StructuredAstValue,
    validation: dict[str, StructuredAstValue],
) -> bool:
    """Classify CFG selector-return deltas using dynamic codegen evidence state."""
    _ = function

    _reject = _cfg_return_expr_reject_8616(codegen)
    if not isinstance(validation, dict):
        return _reject(_CfgReturnExprDeltaRefusal8616.MISSING_DELTA, validation_type=type(validation).__name__)
    multi_arm_return_expressions = _boundary_tuple_8616(
        getattr(codegen, "_inertia_multi_arm_return_expressions_8616", ()) or ()
    )
    if not (
        getattr(codegen, "_inertia_return_expr_chain_materialized_8616", False)
        or multi_arm_return_expressions
    ):
        return _reject(_CfgReturnExprDeltaRefusal8616.MISSING_EVIDENCE)
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return _reject(_CfgReturnExprDeltaRefusal8616.MISSING_DELTA)
    touched_fields = {
        key
        for key, field_delta in delta.items()
        if isinstance(field_delta, dict) and ((field_delta.get("added") or ()) or (field_delta.get("removed") or ()))
    }
    allowed_fields = {"returns"}
    full_return_chain_materialized = bool(
        getattr(codegen, "_inertia_return_selector_materialized_8616", False)
        or multi_arm_return_expressions
    )
    if full_return_chain_materialized:
        allowed_fields = {"returns", "conditions", "control_flow_effects", "helper_calls", "segmented_writes"}
    if (
        not touched_fields
        or touched_fields - allowed_fields
        or (not full_return_chain_materialized and "returns" not in touched_fields)
    ):
        return _reject(
            _CfgReturnExprDeltaRefusal8616.UNEXPECTED_FIELDS,
            touched_fields=tuple(sorted(touched_fields)),
            allowed_fields=tuple(sorted(allowed_fields)),
            delta=delta if not touched_fields else None,
            semantic_failures=validation.get("semantic_failures") if not touched_fields else None,
            status=validation.get("status"),
        )
    returns_delta = delta.get("returns")
    if "returns" in touched_fields and not isinstance(returns_delta, dict):
        return _reject(_CfgReturnExprDeltaRefusal8616.MISSING_RETURNS_DELTA)
    expected_returns = _boundary_set_8616(
        getattr(codegen, "_inertia_return_expr_chain_materialized_return_fingerprints_8616", ()) or ()
    )
    expected_returns.update(
        _expr_fingerprint(expression, project)
        for expression in multi_arm_return_expressions
        if isinstance(expression, CExpression)
    )
    if "returns" in touched_fields and not _check_return_chain_returns_delta_8616(
        project,
        codegen,
        returns_delta,
        expected_returns,
        full_return_chain_materialized,
    ):
        return False
    if full_return_chain_materialized:
        return _check_full_return_chain_deltas_8616(
            project,
            codegen,
            delta,
            validation,
            returns_delta,
            touched_fields,
            allowed_fields,
            expected_returns,
        )
    return True



def _mask_accumulator_conditions_delta_ok_8616(
    delta: dict[str, StructuredAstValue],
    expected_conditions: set,
) -> bool:
    """Return whether the conditions delta only touches proven accumulator conditions."""
    condition_delta = delta.get("conditions")
    if not isinstance(condition_delta, dict):
        return True
    added_conditions = _boundary_set_8616(condition_delta.get("added") or ())
    if added_conditions - expected_conditions:
        return False
    removed_conditions = _boundary_set_8616(condition_delta.get("removed") or ())
    if removed_conditions and not (added_conditions & expected_conditions):
        return False
    return not (removed_conditions & expected_conditions)


def _mask_accumulator_control_delta_ok_8616(
    delta: dict[str, StructuredAstValue],
    expected_conditions: set,
) -> bool:
    """Return whether the control-flow delta only touches accumulator branches."""
    control_delta = delta.get("control_flow_effects")
    if not isinstance(control_delta, dict):
        return True
    added_control = _boundary_set_8616(control_delta.get("added") or ())
    expected_control = {f"if:{fp}" for fp in expected_conditions}
    expected_control.add("return")
    if added_control - expected_control:
        return False
    removed_control = _boundary_set_8616(control_delta.get("removed") or ())
    expected_branch_control = expected_control - {"return"}
    if removed_control and not (added_control & expected_branch_control):
        return False
    return not (removed_control & expected_control)


def _mask_accumulator_returns_delta_ok_8616(
    codegen: StructuredAstValue,
    delta: dict[str, StructuredAstValue],
) -> bool:
    """Return whether the returns delta only reflects the proven accumulator return."""
    returns_delta = delta.get("returns")
    if not isinstance(returns_delta, dict):
        return True
    added_returns = _boundary_set_8616(returns_delta.get("added") or ())
    removed_returns = _boundary_set_8616(returns_delta.get("removed") or ())
    expected_return = getattr(codegen, "_inertia_mask_accumulator_return_fingerprint_8616", None)
    if added_returns and expected_return is not None and added_returns - {expected_return}:
        return False
    return not any(
        item not in {"CDirtyExpression", "none"} and "CDirtyExpression" not in item and item != "CIndexedVariable"
        for item in removed_returns
    )


def _is_cfg_mask_accumulator_materialization_delta_8616(
    project: StructuredAstValue,
    function: StructuredAstValue,
    codegen: StructuredAstValue,
    validation: dict[str, StructuredAstValue],
) -> bool:
    if function is None or not isinstance(validation, dict):
        return False
    if not getattr(codegen, "_inertia_mask_accumulator_materialized_8616", False):
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    touched_fields = {
        key
        for key, field_delta in delta.items()
        if isinstance(field_delta, dict) and ((field_delta.get("added") or ()) or (field_delta.get("removed") or ()))
    }
    allowed_fields = {"returns", "conditions", "control_flow_effects", "helper_calls"}
    if not touched_fields or touched_fields - allowed_fields:
        return False
    expected_conditions = _boundary_set_8616(
        getattr(codegen, "_inertia_mask_accumulator_condition_fingerprints_8616", ()) or ()
    )
    if not expected_conditions:
        return False
    if not _mask_accumulator_conditions_delta_ok_8616(delta, expected_conditions):
        return False
    if not _mask_accumulator_control_delta_ok_8616(delta, expected_conditions):
        return False
    if not _mask_accumulator_returns_delta_ok_8616(codegen, delta):
        return False
    helper_delta = delta.get("helper_calls")
    return not (isinstance(helper_delta, dict) and _boundary_tuple_8616(helper_delta.get("added") or ()))


def _debug_call_recover_reject_8616(reason: str, **kwargs: StructuredAstValue) -> None:
    if not os.environ.get("INERTIA_DEBUG_CALL_RECOVERY"):
        return
    suffix = " ".join(f"{k}={v!r}" for k, v in kwargs.items())
    logging.getLogger(__name__).warning("[call-recover-accept] reject=%s %s", reason, suffix)


def _debug_call_recover_accept_8616(reason: str, **kwargs: StructuredAstValue) -> None:
    if not os.environ.get("INERTIA_DEBUG_CALL_RECOVERY"):
        return
    suffix = " ".join(f"{k}={v!r}" for k, v in kwargs.items())
    logging.getLogger(__name__).warning("[call-recover-accept] accepted=%s %s", reason, suffix)


def _helper_delta_touches_only_allowed_fields_8616(delta: dict[str, StructuredAstValue]) -> bool:
    allowed_fields = {"helper_calls"}
    touched_fields = {
        key
        for key, field_delta in delta.items()
        if isinstance(field_delta, dict) and ((field_delta.get("added") or ()) or (field_delta.get("removed") or ()))
    }
    if touched_fields and not (touched_fields - allowed_fields):
        return True
    _debug_call_recover_reject_8616(
        "touched-fields",
        touched=sorted(touched_fields),
        allowed=sorted(allowed_fields),
        delta=delta,
    )
    return False


def _classify_postprocess_validation_delta_8616(
    validation: dict[str, StructuredAstValue],
) -> _PostprocessValidationDeltaKind8616:
    """Map validation-owned delta policies to postprocess compatibility enum labels."""
    if name_only_helper_annotation_delta_8616(validation):
        return _PostprocessValidationDeltaKind8616.NAME_ONLY_HELPER_ANNOTATION
    return _PostprocessValidationDeltaKind8616.BLOCKING


def _postprocess_validation_has_source_evidenced_blocking_reason_8616(
    validation: Mapping[str, StructuredAstValue],
) -> bool:
    return False


def _has_recovered_source_calls_in_codegen_8616(
    project: StructuredAstValue, codegen: StructuredAstValue, function: StructuredAstValue
) -> bool:
    return False


def _present_call_names_from_cfunc_8616(cfunc: StructuredAstValue) -> set[str]:
    def _impl() -> set[str]:
        root = getattr(cfunc, "body", None) or getattr(cfunc, "statements", None) or cfunc
        present: set[str] = set()
        for node in _iter_c_nodes_deep_8616(root):
            if not isinstance(node, CFunctionCall):
                continue
            for raw in (
                node.callee_target,
                getattr(node.callee_func, "name", None),
                getattr(node, "callee", None),
            ):
                if isinstance(raw, str) and raw:
                    normalized = normalize_callee_name_8616(raw) or raw
                    if normalized and normalized != "aNchkstk":
                        present.add(normalized)
        return present

    return _impl()


def _normalized_kb_call_target_names_8616(project: StructuredAstValue, func_addr: int | None) -> list[str]:
    if not isinstance(func_addr, int):
        return []
    names: list[str] = []
    kb_fn = None
    with contextlib.suppress(Exception):
        kb_fn = project.kb.functions.function(addr=func_addr, create=False)
    if kb_fn is None:
        return names
    for callsite_addr in _boundary_tuple_8616(sorted(getattr(kb_fn, "get_call_sites", list)() or ())):
        target = getattr(kb_fn, "get_call_target", lambda _addr: None)(callsite_addr)
        if not isinstance(target, int):
            continue
        callee = project.kb.functions.function(addr=target, create=False)
        callee_name = normalize_callee_name_8616(getattr(callee, "name", None))
        if isinstance(callee_name, str) and callee_name and callee_name != "aNchkstk":
            names.append(callee_name)
    return names


def _actual_call_counts_from_cfunc_8616(cfunc: StructuredAstValue) -> dict[str, int]:
    root = getattr(cfunc, "body", None) or getattr(cfunc, "statements", None) or cfunc
    actual_counts: dict[str, int] = {}
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CFunctionCall):
            continue
        for raw in (
            node.callee_target,
            getattr(node.callee_func, "name", None),
            getattr(node, "callee", None),
        ):
            if not isinstance(raw, str) or not raw:
                continue
            normalized = normalize_callee_name_8616(raw) or raw
            if normalized in {"aNchkstk", "if", "for", "while", "switch", "return", "sizeof"}:
                continue
            actual_counts[normalized] = int(actual_counts.get(normalized, 0)) + 1
            break
    return actual_counts


def _expected_kb_call_score_from_cfunc_8616(
    project: StructuredAstValue, cfunc: StructuredAstValue, function: StructuredAstValue
) -> tuple[int, int]:
    if cfunc is None or function is None:
        return (0, 0)
    func_addr = getattr(function, "addr", None)
    expected_names = _normalized_kb_call_target_names_8616(project, func_addr)
    if not expected_names:
        return (0, 0)
    expected_counts: dict[str, int] = {}
    for name in expected_names:
        expected_counts[name] = int(expected_counts.get(name, 0)) + 1
    actual_counts = _actual_call_counts_from_cfunc_8616(cfunc)
    score = 0
    total = int(sum(expected_counts.values()))
    for name, needed in expected_counts.items():
        score += min(int(actual_counts.get(name, 0)), int(needed))
    return (score, total)


def _collect_annotation_stack_names_8616(
    project: StructuredAstValue,
    func_addr: int,
) -> tuple[dict[int, str], dict[int, str]]:
    """Collect arg/local display names from sidecar annotations for a function."""
    arg_name_by_offset: dict[int, str] = {}
    local_name_by_offset: dict[int, str] = {}
    with contextlib.suppress(Exception):
        function = project.kb.functions.function(addr=func_addr, create=False)
        info = getattr(function, "info", None)
        annotations = info.get(ANNOTATION_KEY) if isinstance(info, MutableMapping) else None
        stack_vars = annotations.get("stack_vars") if isinstance(annotations, dict) else None
        if isinstance(stack_vars, dict):
            arg_name_by_offset.update(
                {
                    bp_offset: name
                    for bp_offset, name in positive_stack_specs_8616(function)
                    if isinstance(name, str) and name
                }
            )
            for offset, spec in stack_vars.items():
                if not isinstance(offset, int):
                    continue
                name = spec if isinstance(spec, str) else None
                if isinstance(spec, dict):
                    spec_name = spec.get("name")
                    if isinstance(spec_name, str):
                        name = spec_name
                if isinstance(name, str) and name:
                    if offset > 0:
                        continue
                    canonical_offset = _canonical_stack_offset_8616(offset)
                    if isinstance(canonical_offset, int):
                        local_name_by_offset[canonical_offset] = name
    return arg_name_by_offset, local_name_by_offset


def _collect_prototype_arg_names_8616(
    prototype: StructuredAstValue,
    arg_name_by_offset: dict[int, str],
) -> None:
    """Seed argument names from the typed prototype when no earlier evidence exists."""
    proto_arg_names = _boundary_tuple_8616(getattr(prototype, "arg_names", ()) or ())
    proto_args = _boundary_tuple_8616(getattr(prototype, "args", ()) or ())
    if not (proto_arg_names and len(proto_arg_names) == len(proto_args)):
        return
    next_offset = 4
    for arg_name, arg_type in zip(proto_arg_names, proto_args, strict=False):
        if isinstance(arg_name, str) and arg_name and next_offset not in arg_name_by_offset:
            arg_name_by_offset[next_offset] = arg_name
        bits = getattr(arg_type, "size", None)
        try:
            width = int(bits // 8) if isinstance(bits, int) and bits > 0 else 2
        except Exception:
            width = 2
        if width <= 0:
            width = 2
        next_offset += max(2, width)


def _collect_arg_list_names_8616(
    codegen: StructuredAstValue,
    arg_list: StructuredAstValue,
    arg_name_by_offset: dict[int, str],
) -> None:
    """Seed argument names from the structured arg list for unmapped offsets."""
    for arg in arg_list:
        arg_var = getattr(arg, "variable", None)
        if not isinstance(arg_var, SimStackVariable):
            continue
        arg_offset = machine_bp_offset_for_stack_variable_8616(codegen, arg_var)
        if not isinstance(arg_offset, int):
            continue
        arg_name = getattr(arg, "name", None)
        arg_var_name = arg_var.name
        preferred_name = next(
            (
                name
                for name in (arg_name, arg_var_name)
                if isinstance(name, str) and name and not name.startswith("arg_")
            ),
            None,
        )
        if preferred_name is None and isinstance(arg_var_name, str) and arg_var_name:
            preferred_name = arg_var_name
        if preferred_name is None and isinstance(arg_name, str) and arg_name:
            preferred_name = arg_name
        if preferred_name is not None and arg_offset not in arg_name_by_offset:
            arg_name_by_offset[arg_offset] = preferred_name


def _install_live_stack_local_8616(
    codegen: StructuredAstValue,
    cfunc: StructuredAstValue,
    node: StructuredAstValue,
    var: StructuredAstValue,
    offset: int,
    arg_name_by_offset: dict[int, str],
) -> None:
    """Register a renamed stack carrier in the live local-variable maps."""
    if offset in arg_name_by_offset:
        return
    variables_in_use = getattr(cfunc, "variables_in_use", None)
    if isinstance(variables_in_use, dict) and var not in variables_in_use:
        variables_in_use[var] = node
    unified_locals = getattr(cfunc, "unified_local_vars", None)
    if not isinstance(unified_locals, dict):
        unified_locals = {}
        with contextlib.suppress(Exception):
            cfunc.unified_local_vars = unified_locals
    if isinstance(unified_locals, dict) and var not in unified_locals:
        unified_locals[var] = {(node, getattr(node, "variable_type", None))}
        codegen._inertia_stack_identifier_live_node_declarations_8616 = (
            int(getattr(codegen, "_inertia_stack_identifier_live_node_declarations_8616", 0) or 0) + 1
        )


def _rename_local_map_stack_var_8616(
    codegen: StructuredAstValue,
    var: StructuredAstValue,
    cvar: StructuredAstValue,
    arg_name_by_offset: dict[int, str],
    local_name_by_offset: dict[int, str],
    stack_name_pat: StructuredAstValue,
) -> None:
    """Rename one stack carrier entry in a local-variable map when evidence exists."""
    if var.__class__.__name__ != "SimStackVariable":
        return
    ident = getattr(var, "ident", None)
    if ident is None:
        try:
            var.ident = ""
        except Exception:
            return
    # Normalize unresolved stack carrier names to stable stack semantics.
    # This is typed/name materialization from stack offsets, not text cleanup.
    name = getattr(var, "name", None)
    offset = machine_bp_offset_for_stack_variable_8616(codegen, var)
    if not isinstance(offset, int):
        return
    new_name = arg_name_by_offset.get(offset) or local_name_by_offset.get(offset)
    if new_name is None and isinstance(name, str) and stack_name_pat.match(name):
        new_name = _stack_object_name(offset, codegen=codegen)
    if new_name is None:
        return
    try:
        var.name = new_name
    except Exception:
        return
    if cvar.__class__.__name__ == "CVariable":
        with contextlib.suppress(Exception):
            cvar.name = new_name


def _rename_stack_vars_in_local_maps_8616(
    codegen: StructuredAstValue,
    local_maps: list[StructuredAstValue],
    arg_name_by_offset: dict[int, str],
    local_name_by_offset: dict[int, str],
    stack_name_pat: StructuredAstValue,
) -> None:
    """Rename unresolved stack carriers in the cfunc local-variable maps."""
    for mapping in local_maps:
        for var, cvar in tuple(mapping.items()):
            _rename_local_map_stack_var_8616(
                codegen,
                var,
                cvar,
                arg_name_by_offset,
                local_name_by_offset,
                stack_name_pat,
            )


def _rename_stack_var_node_attr_8616(
    codegen: StructuredAstValue,
    cfunc: StructuredAstValue,
    node: StructuredAstValue,
    attr: str,
    arg_name_by_offset: dict[int, str],
    local_name_by_offset: dict[int, str],
    stack_name_pat: StructuredAstValue,
) -> None:
    """Rename one stack carrier attribute on a CVariable node when evidence exists."""
    var = getattr(node, attr, None)
    if var is None or var.__class__.__name__ != "SimStackVariable":
        return
    offset = machine_bp_offset_for_stack_variable_8616(codegen, var)
    if not isinstance(offset, int):
        return
    new_name = arg_name_by_offset.get(offset) or local_name_by_offset.get(offset)
    if new_name is None:
        current_name = getattr(node, "name", None) or getattr(var, "name", None)
        if isinstance(current_name, str) and stack_name_pat.match(current_name):
            new_name = _stack_object_name(offset, codegen=codegen)
    if new_name is None:
        return
    try:
        cast(Any, var).name = new_name
    except Exception:
        return
    with contextlib.suppress(Exception):
        cast(Any, node).name = new_name
    _install_live_stack_local_8616(codegen, cfunc, node, var, offset, arg_name_by_offset)


def _rename_stack_var_nodes_8616(
    codegen: StructuredAstValue,
    cfunc: StructuredAstValue,
    arg_name_by_offset: dict[int, str],
    local_name_by_offset: dict[int, str],
    stack_name_pat: StructuredAstValue,
) -> None:
    """Rename stack carriers on every CVariable node under the cfunc roots."""
    node_roots = [cfunc]
    statements_root = getattr(cfunc, "statements", None)
    if statements_root is not None:
        node_roots.append(statements_root)
    for root in node_roots:
        nodes = (root, *_iter_c_nodes_deep_8616(root))
        for node in nodes:
            if node.__class__.__name__ != "CVariable":
                continue
            for attr in ("variable", "unified_variable"):
                _rename_stack_var_node_attr_8616(
                    codegen,
                    cfunc,
                    node,
                    attr,
                    arg_name_by_offset,
                    local_name_by_offset,
                    stack_name_pat,
                )

def _normalize_stack_variable_identifiers_8616(codegen: StructuredAstValue) -> None:
    def _impl() -> None:
        cfunc = getattr(codegen, "cfunc", None)
        if cfunc is None:
            return
        arg_list = _boundary_tuple_8616(getattr(cfunc, "arg_list", ()) or ())
        arg_name_by_offset: dict[int, str] = {}
        local_name_by_offset: dict[int, str] = {}
        project = getattr(codegen, "project", None)
        func_addr = getattr(cfunc, "addr", None)
        if project is not None and isinstance(func_addr, int):
            arg_name_by_offset, local_name_by_offset = _collect_annotation_stack_names_8616(
                project,
                func_addr,
            )
        publish_stack_variable_projection_display_names_8616(codegen, local_name_by_offset)
        prototype = getattr(cfunc, "functy", None)
        _collect_prototype_arg_names_8616(prototype, arg_name_by_offset)
        _collect_arg_list_names_8616(codegen, arg_list, arg_name_by_offset)
        local_maps = []
        unified = getattr(cfunc, "unified_local_vars", None)
        if isinstance(unified, dict):
            local_maps.append(unified)
        vars_in_use = getattr(cfunc, "variables_in_use", None)
        if isinstance(vars_in_use, dict):
            local_maps.append(vars_in_use)
        stack_name_pat = re.compile(r"^(?:s_[0-9a-fA-F]+(?:_[0-9a-fA-F]+)*|arg_[0-9a-fA-F]+|local_[0-9a-fA-F]+)$")
        _rename_stack_vars_in_local_maps_8616(
            codegen,
            local_maps,
            arg_name_by_offset,
            local_name_by_offset,
            stack_name_pat,
        )
        _rename_stack_var_nodes_8616(
            codegen,
            cfunc,
            arg_name_by_offset,
            local_name_by_offset,
            stack_name_pat,
        )

    return _impl()


@dataclass(frozen=True, slots=True)
class CallsiteStackFactMaterializationResult8616:
    """Result of postprocess callsite stack-fact materialization."""

    attach_summaries_changed: bool
    stack_probe_facts_changed: bool
    prototypes_changed: bool
    stack_arguments_changed: bool

    @property
    def changed(self: StructuredAstValue) -> bool:
        """Return True when any callsite consumer changed the C AST or facts."""
        return bool(
            self.attach_summaries_changed
            or self.stack_probe_facts_changed
            or self.prototypes_changed
            or self.stack_arguments_changed
        )


def run_callsite_stack_fact_materialization_8616(
    project: StructuredAstValue,
    codegen: StructuredAstValue,
    guarded_rewrite_runner: Callable[[str, Callable[[], bool]], bool],
    stack_probe_fact_builder: Callable[[StructuredAstValue], StructuredAstValue],
) -> CallsiteStackFactMaterializationResult8616:
    """Run callsite stack-fact consumers behind dynamic codegen compatibility state.

    This owns the ordering of postprocess callsite consumers.  The supplied
    runner remains CLI-owned because it snapshots/restores the current C AST
    and reports function-context call-loss policy.
    """
    attach_changed = bool(
        guarded_rewrite_runner(
            "_attach_callsite_summaries_8616",
            lambda: _calls._attach_callsite_summaries_8616(project, codegen),
        )
    )
    stack_probe_changed = bool(
        guarded_rewrite_runner(
            "build_typed_stack_probe_return_facts_8616",
            lambda: bool(stack_probe_fact_builder(codegen)),
        )
    )
    prototypes_changed = bool(
        guarded_rewrite_runner(
            "_materialize_callsite_prototypes_8616",
            lambda: _calls._materialize_callsite_prototypes_8616(project, codegen),
        )
    )
    if _callsite_after_ss_lowering_rematerialization_unneeded_8616(codegen):
        codegen._inertia_callsite_stack_fact_stack_arguments_skipped_complete_8616 = (
            int(getattr(codegen, "_inertia_callsite_stack_fact_stack_arguments_skipped_complete_8616", 0) or 0) + 1
        )
        stack_arguments_changed = False
    else:
        stack_arguments_changed = bool(
            guarded_rewrite_runner(
                "_materialize_callsite_stack_arguments_8616",
                lambda: _materialize_callsite_stack_arguments_with_target_identity_8616(project, codegen),
            )
        )
    def _refresh_callsite_prototypes_after_args() -> bool:
        """Refresh legacy call prototypes and the lowering-owned declarations."""
        changed = bool(_calls._materialize_callsite_prototypes_8616(project, codegen))
        cfunc = getattr(codegen, "cfunc", None)
        if cfunc is None or not hasattr(cfunc, "functy"):
            return changed
        return bool(reconcile_callsite_interface_declarations_8616(project, codegen)) or changed

    prototypes_after_args_changed = bool(
        guarded_rewrite_runner(
            "_materialize_callsite_prototypes_after_args_8616",
            _refresh_callsite_prototypes_after_args,
        )
    )
    result = CallsiteStackFactMaterializationResult8616(
        attach_summaries_changed=attach_changed,
        stack_probe_facts_changed=stack_probe_changed,
        prototypes_changed=prototypes_changed or prototypes_after_args_changed,
        stack_arguments_changed=stack_arguments_changed,
    )
    with contextlib.suppress(Exception):
        codegen._inertia_callsite_stack_fact_materialization_8616 = {
            "attach_summaries_changed": result.attach_summaries_changed,
            "stack_probe_facts_changed": result.stack_probe_facts_changed,
            "prototypes_changed": result.prototypes_changed,
            "stack_arguments_changed": result.stack_arguments_changed,
            "changed": result.changed,
            "owner": "postprocess.stage",
        }
    return result


@dataclass(frozen=True, slots=True)
class LateAstCleanupResult8616:
    """Result of final AST-only cleanup after late materializers mutate codegen."""

    changed: bool
    adjacent_temporary_copy_changed: bool
    empty_noop_guard_changed: bool
    dead_condition_carrier_changed: bool
    affine_compound_assignment_identity_changed: bool

    @property
    def requires_dce_after_cleanup(self: StructuredAstValue) -> bool:
        """Return True when cleanup exposed a DCE follow-up."""
        return bool(self.adjacent_temporary_copy_changed)


@dataclass(frozen=True, slots=True)
class LateEmptyNoopGuardCleanupStats8616:
    """Record the closed evidence census for late semantically empty guard cleanup."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def changed(self) -> bool:
        """Return whether at least one classified no-op guard was removed."""
        return self.materialized_count > 0


def _collect_empty_noop_guard_prune_indices_8616(
    root: StructuredAstValue,
) -> tuple[int, int, int, dict[int, tuple[StructuredAstValue, set[int]]]]:
    """Collect outermost EMPTY_NOOP guard prune indices grouped by block."""
    seen_blocks: set[int] = set()
    blocks = [node for node in (root, *_iter_c_nodes_deep_8616(root)) if isinstance(node, CStatements)]
    raw_fact_count = 0
    normalized_fact_count = 0
    candidates: list[tuple[CStatements, int, CIfElse]] = []
    for block in blocks:
        block_id = id(block)
        if block_id in seen_blocks:
            continue
        seen_blocks.add(block_id)
        for index, statement in enumerate(_boundary_list_8616(block.statements or ())):
            if not isinstance(statement, CIfElse):
                continue
            raw_fact_count += 1
            candidate = _surplus_empty_guard_condition_8616(statement)
            if candidate is None:
                continue
            normalized_fact_count += 1
            _condition, kind = candidate
            if kind is _SurplusIfGuardKind8616.EMPTY_NOOP:
                candidates.append((block, index, statement))

    candidate_ids = {id(statement) for _block, _index, statement in candidates}
    nested_candidate_ids: set[int] = set()
    for _block, _index, statement in candidates:
        nested_candidate_ids.update(
            id(node)
            for node in _iter_c_nodes_deep_8616(statement)
            if id(node) in candidate_ids and node is not statement
        )
    classified = [
        (block, index)
        for block, index, statement in candidates
        if id(statement) not in nested_candidate_ids
    ]

    prune_by_block: dict[int, tuple[CStatements, set[int]]] = {}
    for block, index in classified:
        block_id = id(block)
        if block_id not in prune_by_block:
            prune_by_block[block_id] = (block, set())
        prune_by_block[block_id][1].add(index)
    return raw_fact_count, normalized_fact_count, len(classified), prune_by_block


def _prune_late_semantically_empty_noop_guards_8616(
    codegen: StructuredAstValue,
) -> LateEmptyNoopGuardCleanupStats8616:
    """Remove only side-effect-free empty branch shells exposed by evidence DCE.

    Structuring owns the semantic-empty classifier. This late compatibility
    consumer removes only ``EMPTY_NOOP`` guards whose condition has no call and
    whose true and false arms contain no semantic statements. It does not use
    rendered text, machine-branch counts, condition meaning, or JCC polarity.
    Empty-return and non-empty branch shapes remain untouched.
    """
    # Dynamic angr codegen boundary: the generated C function may be absent.
    cfunc = getattr(codegen, "cfunc", None)
    # Dynamic angr C-AST boundary: statement roots vary across codegen versions.
    root = getattr(cfunc, "statements", None) if cfunc is not None else None
    if root is None:
        stats = LateEmptyNoopGuardCleanupStats8616(0, 0, 0, 0, 0)
        codegen._inertia_late_empty_noop_guard_cleanup_stats_8616 = stats
        return stats

    raw_fact_count, normalized_fact_count, classified_fact_count, prune_by_block = (
        _collect_empty_noop_guard_prune_indices_8616(root)
    )

    materialized_count = 0
    for block, prune_indices in prune_by_block.values():
        old_statements = _boundary_list_8616(block.statements or ())
        block.statements = [
            statement
            for index, statement in enumerate(old_statements)
            if index not in prune_indices
        ]
        materialized_count += len(prune_indices)

    failure_count = classified_fact_count - materialized_count
    stats = LateEmptyNoopGuardCleanupStats8616(
        raw_fact_count=raw_fact_count,
        normalized_fact_count=normalized_fact_count,
        classified_fact_count=classified_fact_count,
        materialized_count=materialized_count,
        failure_count=failure_count,
    )
    codegen._inertia_late_empty_noop_guard_cleanup_stats_8616 = stats
    if classified_fact_count > 0 and materialized_count == 0:
        raise RuntimeError("classified late empty no-op guards were not materialized")
    return stats


def run_late_ast_cleanup_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> LateAstCleanupResult8616:
    """Run AST-only cleanup after late materialization or CLI orchestration.

    This is deliberately still owned by the X86_16 postprocess/optimization
    layer. The caller may be CLI orchestration, but cleanup is limited to
    structured C nodes: adjacent generated temporary carriers are folded into
    their immediate consumer, and semantically empty no-op branch shells exposed
    by evidence DCE are removed through Structuring's owned shape classifier. It
    does not inspect rendered C text, recover aliases, infer types, or repair
    semantics.
    """
    _ = project
    empty_noop_guard_stats = _prune_late_semantically_empty_noop_guards_8616(codegen)
    trivial_copy_changed = bool(prune_adjacent_temporary_copy_assignments_8616(codegen))
    dead_condition_carrier_stats = prune_unread_pure_condition_carriers_8616(codegen)
    affine_identity_stats = restore_affine_compound_assignment_identity_8616(codegen)
    return LateAstCleanupResult8616(
        changed=(
            empty_noop_guard_stats.changed
            or trivial_copy_changed
            or dead_condition_carrier_stats.changed
            or affine_identity_stats.changed
        ),
        adjacent_temporary_copy_changed=trivial_copy_changed,
        empty_noop_guard_changed=empty_noop_guard_stats.changed,
        dead_condition_carrier_changed=dead_condition_carrier_stats.changed,
        affine_compound_assignment_identity_changed=affine_identity_stats.changed,
    )


def finalize_late_ast_cleanup_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> LateAstCleanupResult8616:
    """Run final AST cleanup and mark codegen refresh requirements."""
    result = run_late_ast_cleanup_8616(project, codegen)
    if result.changed:
        codegen._inertia_codegen_decl_refresh_required_8616 = True
        codegen._inertia_force_codegen_regeneration_8616 = True
    with contextlib.suppress(Exception):
        codegen._inertia_late_ast_cleanup_finalize_8616 = {
            "changed": result.changed,
            "adjacent_temporary_copy_changed": result.adjacent_temporary_copy_changed,
            "empty_noop_guard_changed": result.empty_noop_guard_changed,
            "dead_condition_carrier_changed": result.dead_condition_carrier_changed,
            "requires_dce_after_cleanup": result.requires_dce_after_cleanup,
            "owner": "postprocess.stage",
        }
    return result


@dataclass(frozen=True, slots=True)
class PostSwitchCleanupResult8616:
    """Result of cleanup that runs after late SeqNode switch body mutation."""

    changed: bool
    consumed_stack_store_changed: bool
    adjacent_temporary_copy_changed: bool

    @property
    def requires_dce_after_cleanup(self: StructuredAstValue) -> bool:
        """Return True when cleanup exposed a DCE follow-up."""
        return bool(self.adjacent_temporary_copy_changed)


def run_post_switch_cleanup_after_seqnode_replacement_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> PostSwitchCleanupResult8616:
    """Run AST-only cleanup exposed by late typed switch replacement.

    The typed SeqNode switch mutator can create fresh case-body C nodes after
    normal postprocess has already run. This helper keeps the composition in
    the X86_16 postprocess/optimization layer: callsite cleanup consumes proven
    materialized call arguments, and adjacent temporary-copy pruning is a
    local optimization over structured C nodes. It does not inspect rendered C
    text or recover new semantics.
    """
    consumed_changed = bool(_calls.prune_consumed_segmented_stack_byte_arg_stores_8616(project, codegen))
    trivial_copy_changed = bool(prune_adjacent_temporary_copy_assignments_8616(codegen))
    return PostSwitchCleanupResult8616(
        changed=consumed_changed or trivial_copy_changed,
        consumed_stack_store_changed=consumed_changed,
        adjacent_temporary_copy_changed=trivial_copy_changed,
    )


def finalize_post_switch_cleanup_after_seqnode_replacement_8616(
    project: StructuredAstValue, codegen: StructuredAstValue
) -> PostSwitchCleanupResult8616:
    """Run post-switch cleanup and mark codegen refresh requirements.

    The cleanup itself belongs to postprocess/optimization.  The caller still
    owns any pipeline hard-error policy around follow-up DCE because that
    policy depends on function-level reporting context.
    """
    result = run_post_switch_cleanup_after_seqnode_replacement_8616(project, codegen)
    if result.changed:
        codegen._inertia_codegen_decl_refresh_required_8616 = True
        codegen._inertia_force_codegen_regeneration_8616 = True
    with contextlib.suppress(Exception):
        codegen._inertia_post_switch_cleanup_finalize_8616 = {
            "changed": result.changed,
            "consumed_stack_store_changed": result.consumed_stack_store_changed,
            "adjacent_temporary_copy_changed": result.adjacent_temporary_copy_changed,
            "requires_dce_after_cleanup": result.requires_dce_after_cleanup,
            "owner": "postprocess.stage",
        }
    return result


def _gate_transfer_alias_facts_once_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> None:
    """Transfer semantic alias facts from lifter to codegen exactly once."""
    if getattr(codegen, "_inertia_semantic_facts_transferred", False):
        return
    try:
        transfer_semantic_alias_facts_to_codegen_8616(project, codegen)
    except Exception as ex:
        codegen._inertia_semantic_facts_transfer_error = str(ex)
    finally:
        codegen._inertia_semantic_facts_transferred = True


def _gate_materialize_stack_facts_once_8616(codegen: StructuredAstValue) -> None:
    """Materialize stack accesses from alias facts exactly once."""
    if getattr(codegen, "_inertia_stack_lowered_from_facts", False):
        return
    alias_facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
    if isinstance(alias_facts, list) and alias_facts:
        try:
            lower_stack_accesses_from_alias_facts_8616(codegen, alias_facts)
        except Exception as ex:
            codegen._inertia_stack_lowering_error = str(ex)
    codegen._inertia_stack_lowered_from_facts = True


def _gate_transfer_typed_conditions_once_8616(project: StructuredAstValue, codegen: StructuredAstValue) -> None:
    """Transfer typed conditions to codegen exactly once at the invariant gate."""
    if getattr(codegen, "_inertia_typed_conditions_transferred", False):
        return
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None) if cfunc is not None else None
    if func_addr is not None:
        try:
            transfer_typed_conditions_to_codegen_8616(project, func_addr, codegen)
        except Exception as ex:
            logging.getLogger(__name__).debug(
                "Typed condition transfer failed at function=%#x stage=invariant-gate: %s",
                func_addr,
                ex,
            )
    codegen._inertia_typed_conditions_transferred = True


def _record_invariant_report_8616(codegen: StructuredAstValue, function: StructuredAstValue, report: StructuredAstValue) -> None:
    """Record the invariant report on the function info and codegen."""
    if function is not None:
        info = getattr(function, "info", None)
        if isinstance(info, MutableMapping):
            info["x86_16_pre_rewrite_invariant_report"] = report.to_dict()
    codegen._inertia_invariant_report = report
    codegen._inertia_invariant_checked = True


def _record_dead_setup_counters_8616(codegen: StructuredAstValue, function: StructuredAstValue) -> None:
    """Record dead-setup counters on the function info mapping."""
    if function is None:
        return
    info = getattr(function, "info", None)
    if not isinstance(info, MutableMapping):
        return
    info["x86_16_dead_setup"] = {
        "dead_setup_candidates": int(getattr(codegen, "dead_setup_candidates", 0)),
        "dead_setup_pruned": int(getattr(codegen, "dead_setup_pruned", 0)),
        "dead_setup_refused": int(getattr(codegen, "dead_setup_refused", 0)),
    }
    info["x86_16_loop_exit_guard"] = dict(getattr(codegen, "_inertia_loop_exit_guard_stats_8616", {}))


def _enforce_dead_setup_gate_8616(codegen: StructuredAstValue, function: StructuredAstValue) -> None:
    """Raise PipelineHardError when dead-setup artifacts escaped final C."""
    dead_setup_escaped = _count_dead_setup_escaped_8616(codegen)
    codegen.dead_setup_escaped = int(dead_setup_escaped)
    if function is not None:
        info = getattr(function, "info", None)
        if isinstance(info, MutableMapping):
            dead_setup_info = info.setdefault("x86_16_dead_setup", {})
            if isinstance(dead_setup_info, MutableMapping):
                dead_setup_info["dead_setup_escaped"] = int(dead_setup_escaped)
    if dead_setup_escaped <= 0:
        return
    raise PipelineHardError(
        "dead setup artifacts escaped final C",
        layer="codegen",
        function_addr=getattr(function, "addr", None),
        details={
            "dead_setup_candidates": int(getattr(codegen, "dead_setup_candidates", 0)),
            "dead_setup_pruned": int(getattr(codegen, "dead_setup_pruned", 0)),
            "dead_setup_refused": int(getattr(codegen, "dead_setup_refused", 0)),
            "dead_setup_escaped": int(dead_setup_escaped),
        },
    )


def _run_pipeline_contract_gate_8616(codegen: StructuredAstValue, function: StructuredAstValue) -> None:
    """Run the pipeline contract assertions with lane diagnostics."""
    try:
        assert_pipeline_contracts_8616(codegen)
    except Exception as ex:
        stack_lane = getattr(codegen, "_inertia_stack_lane", None)
        cond_lane = getattr(codegen, "_inertia_condition_lane", None)
        logging.getLogger(__name__).warning(
            "Pipeline contract gate failed at function=%#x stage=invariant-gate: %s "
            "stack_lane=%s condition_lane=%s",
            getattr(function, "addr", -1) or -1,
            ex,
            stack_lane.summary_line()
            if stack_lane is not None and hasattr(stack_lane, "summary_line")
            else stack_lane,
            cond_lane.summary_line() if cond_lane is not None and hasattr(cond_lane, "summary_line") else cond_lane,
        )
        raise


def _log_rewrite_gate_result_8616(codegen: StructuredAstValue, function: StructuredAstValue, report: StructuredAstValue) -> None:
    """Log the invariant gate verdict and mark codegen failure when blocked."""
    log = logging.getLogger(__name__)
    if report.rewrite_blocked:
        codegen._inertia_rewrite_failed = True
        codegen._inertia_rewrite_failure_pass = "invariant_gate"
        codegen._inertia_rewrite_failure_error = report.skip_reason
        formatted = format_invariant_report_8616(report)
        log.warning(
            "Pre-rewrite invariant gate BLOCKED rewrite for %#x (%s): %s",
            getattr(function, "addr", 0),
            getattr(function, "name", "?"),
            report.skip_reason,
        )
        log.warning("Invariant report:\n%s", formatted)
        return
    log.debug(
        "Pre-rewrite invariant gate passed for %#x (%s)",
        getattr(function, "addr", 0),
        getattr(function, "name", "?"),
    )

def _inertia_run_pre_rewrite_invariant_gate(
    project: StructuredAstValue, codegen: StructuredAstValue, function: StructuredAstValue
) -> None:
    """Run the pre-rewrite invariant checks and record results on codegen.

    AGENTS rule: rewrite must not hide bad alias/type/condition recovery.
    If invariants fail, rewrite is skipped and honest partial output is emitted.

    CRITICAL: transfer semantic alias facts from lifter/emulator to codegen
    BEFORE running invariants, so the invariant checks can see them.
    """
    _gate_transfer_alias_facts_once_8616(project, codegen)
    _gate_materialize_stack_facts_once_8616(codegen)
    _gate_transfer_typed_conditions_once_8616(project, codegen)

    # Repair statements wrapper before invariant check (last pass may have corrupted it)
    _repair_cfunc_statements_wrapper(codegen)

    c_text = ""
    with contextlib.suppress(Exception):
        c_text = getattr(codegen, "text", "") or getattr(codegen, "_text", "") or ""

    # ── Apply fact-based ss << 4 → variable name substitution ──
    # This is rewrite-layer cleanup using already-materialized alias facts.
    # DISABLED in normal path: text-based substitution violates AGENTS rule
    # "no text-based recovery".  Kept behind debug flag for emergency use.
    if c_text and getattr(codegen, "_inertia_allow_late_stack_text_bridge", False):
        try:
            c_text = apply_stack_variable_bindings_to_c_text(c_text, codegen)
        except Exception as ex:
            logging.getLogger(__name__).warning(
                "Late stack text bridge fallback failed at function=%#x stage=invariant-gate: %s",
                getattr(function, "addr", -1) or -1,
                ex,
            )

    report = validate_before_rewrite_8616(codegen, c_text=c_text, project=project)

    _record_invariant_report_8616(codegen, function, report)
    _record_dead_setup_counters_8616(codegen, function)
    _enforce_dead_setup_gate_8616(codegen, function)
    _run_pipeline_contract_gate_8616(codegen, function)
    _log_rewrite_gate_result_8616(codegen, function, report)



def _debug_decompile_validation_entry_8616(self: StructuredAstValue, func_addr: StructuredAstValue) -> None:
    """Emit the validation-path entry diagnostic."""
    import sys as _tv_sys3

    _tv_sys3.stderr.write(f"[dbg] _decompile_8616 ENTER validation path: addr={func_addr} id={id(self.codegen)}\n")
    _tv_sys3.stderr.flush()


def _debug_decompile_done_8616(self: StructuredAstValue, func_addr: StructuredAstValue) -> None:
    """Emit the validation-path completion diagnostic."""
    import sys as _tv_sys4

    tv_snap = getattr(self.codegen, "_inertia_tail_validation_snapshot", None)
    tv_stages = list(tv_snap) if isinstance(tv_snap, dict) else "NONE"
    project_tv_snap = getattr(self.project, "_inertia_last_tail_validation_snapshot", None)
    project_tv_stages = list(project_tv_snap) if isinstance(project_tv_snap, dict) else "NONE"
    _tv_sys4.stderr.write(
        f"[dbg] _decompile_8616 DONE: addr={func_addr} codegen_id={id(self.codegen)} "
        f"snapshot_stages={tv_stages} proj_fb_stages={project_tv_stages}\n"
    )
    _tv_sys4.stderr.flush()


def _run_decompile_core_8616(self: StructuredAstValue) -> float:
    """Run the original core decompile under profiling and span instrumentation."""
    _orig_decompiler_decompile = getattr(_decompile_8616, "_orig_decompiler_decompile", None)
    if _orig_decompiler_decompile is None:
        _orig_decompiler_decompile = Decompiler._decompile
        cast(Any, _decompile_8616)._orig_decompiler_decompile = _orig_decompiler_decompile
    core_started = time.perf_counter()
    self.project._inertia_decompiler_stage = "core"
    core_profile_path = os.environ.get("INERTIA_CORE_CPROFILE_PATH", "").strip()
    core_profiler: cProfile.Profile | None = cProfile.Profile() if core_profile_path else None
    if core_profiler is not None:
        core_profiler.enable()
    try:
        with span(
            "x86_16.decompile.core",
            function=getattr(getattr(self, "function", None) or getattr(self, "func", None), "addr", None),
        ):
            _orig_decompiler_decompile(self)
    finally:
        if core_profiler is not None:
            core_profiler.disable()
            core_profiler.dump_stats(core_profile_path)
    core_elapsed = time.perf_counter() - core_started
    return core_elapsed


def _debug_decompile_entry_8616(
    self: StructuredAstValue,
    func_addr: StructuredAstValue,
    func_name: StructuredAstValue,
    tv_enabled: bool,
) -> None:
    """Emit the env-gated entry diagnostic for the validation path."""
    if not os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
        return
    import sys as _tv_sys

    _tv_sys.stderr.write(
        f"[dbg] _decompile_8616: addr={func_addr} name={func_name} "
        f"codegen_is_none={self.codegen is None} tv_enabled={tv_enabled}\n"
    )
    _tv_sys.stderr.flush()


def _debug_prevalidation_pointer_surface_8616(self: StructuredAstValue, label: str) -> None:
    """Log pointer expressions while postprocess validation is prepared."""
    if os.environ.get("INERTIA_DEBUG_POINTER_MEMORY_IDIOMS") != "1":
        return
    try:
        pointer_text = str(self.codegen.cfunc.c_repr())
    except (AttributeError, TypeError):
        return
    logging.getLogger(__name__).warning(
        "[pointer-memory-prevalidation-surface] label=%s lines=%r",
        label,
        tuple(line.strip() for line in pointer_text.splitlines() if "[0]" in line or "SEG_U16" in line),
    )


def _run_no_tv_postprocess_path_8616(self: StructuredAstValue, core_elapsed: float) -> None:
    """Run the postprocess-only path when tail validation is disabled."""
    postprocess_started = time.perf_counter()
    changed = _postprocess_codegen_8616(self.project, self.codegen)
    postprocess_elapsed = time.perf_counter() - postprocess_started
    function = getattr(self, "function", None) or getattr(self, "func", None)
    if function is not None:
        info = getattr(function, "info", None)
        if isinstance(info, MutableMapping):
            postprocess_info = info.setdefault("x86_16_decompiler_postprocess", {})
            postprocess_info["core_elapsed"] = core_elapsed
            postprocess_info["elapsed"] = postprocess_elapsed
            postprocess_info["last_pass"] = getattr(self.codegen, "_inertia_last_postprocess_pass", None)
            postprocess_info["changed"] = bool(changed)
            postprocess_info["failed"] = bool(getattr(self.codegen, "_inertia_rewrite_failed", False))
            postprocess_info["failure_pass"] = getattr(self.codegen, "_inertia_rewrite_failure_pass", None)
            postprocess_info["failure_error"] = getattr(self.codegen, "_inertia_rewrite_failure_error", None)
            postprocess_info["validation_failed"] = bool(
                getattr(self.codegen, "_inertia_postprocess_validation_failed", False)
            )
            postprocess_info["validation_failure_pass"] = getattr(
                self.codegen, "_inertia_postprocess_validation_failure_pass", None
            )
            postprocess_info["validation_failure_error"] = getattr(
                self.codegen, "_inertia_postprocess_validation_failure_error", None
            )
            postprocess_info["pass_names"] = getattr(self.codegen, "_inertia_postprocess_passes", ())
    self.codegen._inertia_tail_validation_snapshot = None
    self.project._inertia_decompiler_stage = "postprocess_done"


def _run_pre_validation_prime_step_8616(
    name: str,
    operation: Callable[[], bool],
) -> bool:
    import sys as _tv_sys
    """Run one semantic priming owner and optionally report its exact cost."""
    started = time.perf_counter()
    step_changed = bool(operation())
    if timing_output_enabled():
        _tv_sys.stderr.write(
            f"[dbg] pre-validation prime: {name} "
            f"changed={step_changed} elapsed={time.perf_counter() - started:.3f}s\n"
        )
        _tv_sys.stderr.flush()
    return step_changed


def _measure_pre_validation_value_8616(
    name: str,
    operation: Callable[[], StructuredAstValue],
) -> StructuredAstValue:
    import sys as _tv_sys
    """Evaluate one rollback/validation value and optionally report its cost."""
    started = time.perf_counter()
    value = operation()
    if timing_output_enabled():
        _tv_sys.stderr.write(
            f"[dbg] pre-validation value: {name} "
            f"elapsed={time.perf_counter() - started:.3f}s\n"
        )
        _tv_sys.stderr.flush()
    return value


def _run_pre_validation_prime_8616(self: StructuredAstValue, func_addr: StructuredAstValue) -> None:
    """Run every semantic priming owner before the validation baseline."""
    with span("x86_16.decompile.pre_validation_prime", function=func_addr):
        _debug_prevalidation_pointer_surface_8616(self, "before-prime")
        _run_pre_validation_prime_step_8616(
            "stack_semantics",
            lambda: _prime_stack_semantics_before_validation_baseline_8616(self.project, self.codegen),
        )
        _debug_prevalidation_pointer_surface_8616(self, "after-stack-semantics")
        _run_pre_validation_prime_step_8616(
            "stack_prototype",
            lambda: _prime_stack_prototype_before_validation_baseline_8616(self.project, self.codegen),
        )
        _debug_prevalidation_pointer_surface_8616(self, "after-stack-prototype")
        _run_pre_validation_prime_step_8616(
            "callsite_summaries",
            lambda: _prime_callsite_summaries_before_validation_baseline_8616(self.project, self.codegen),
        )
        _debug_prevalidation_pointer_surface_8616(self, "after-callsites")
        _run_pre_validation_prime_step_8616(
            "return_shape",
            lambda: _prime_return_shape_before_validation_baseline_8616(self.project, self.codegen),
        )
        _debug_prevalidation_pointer_surface_8616(self, "after-return-shape")
        _run_pre_validation_prime_step_8616(
            "return_chains",
            lambda: _prime_return_chains_before_validation_baseline_8616(self.project, self.codegen),
        )
        _debug_prevalidation_pointer_surface_8616(self, "after-return-chains")
        _run_pre_validation_prime_step_8616(
            "typed_conditions",
            lambda: _prime_typed_conditions_before_validation_baseline_8616(self.project, self.codegen),
        )
        _debug_prevalidation_pointer_surface_8616(self, "after-typed-conditions")
        _repair_cfunc_statements_wrapper(self.codegen)
        _debug_prevalidation_pointer_surface_8616(self, "after-wrapper-repair")
        _run_pre_validation_prime_step_8616(
            "ir_segmented_load_carriers",
            lambda: materialize_ir_segmented_load_carriers_8616(self.codegen),
        )
        _run_pre_validation_prime_step_8616(
            "segment_global_lowering",
            lambda: _replay_segment_global_lowering_before_validation_baseline_8616(
                self.project,
                self.codegen,
            ),
        )
        _run_pre_validation_prime_step_8616(
            "ir_segmented_load_carriers_after_segment_globals",
            lambda: materialize_ir_segmented_load_carriers_8616(self.codegen),
        )
        _debug_prevalidation_pointer_surface_8616(self, "after-segmented-memory-replay")
        _run_pre_validation_prime_step_8616(
            "stack_word_loads_final",
            lambda: lower_stable_ss_linear_stack_dereferences_8616(
                self.codegen,
                project=self.project,
            ),
        )


def _collect_validation_baseline_8616(
    self: StructuredAstValue,
    func_addr: StructuredAstValue,
    validation_mode: str,
) -> tuple[StructuredAstValue, StructuredAstValue, StructuredAstValue, float]:
    """Collect the pre-postprocess baseline summaries and restore the snapshot."""
    baseline_cfunc_snapshot = _measure_pre_validation_value_8616(
        "baseline_cfunc_snapshot",
        lambda: _snapshot_codegen_cfunc(self.codegen),
    )
    baseline_metadata_snapshot = (
        _measure_pre_validation_value_8616(
            "baseline_metadata_snapshot",
            lambda: _snapshot_codegen_inertia_metadata_8616(self.codegen),
        )
        if baseline_cfunc_snapshot is not None
        else None
    )
    baseline_text_snapshot = (
        _snapshot_codegen_text_state_8616(self.codegen) if baseline_cfunc_snapshot is not None else None
    )
    baseline_project_function_snapshot = (
        _measure_pre_validation_value_8616(
            "baseline_project_function_snapshot",
            lambda: _snapshot_project_function_metadata_8616(self.project, func_addr),
        )
        if baseline_cfunc_snapshot is not None
        else None
    )
    before_fingerprint_started = time.perf_counter()
    with span("x86_16.decompile.validation.before_fingerprint", function=func_addr):
        before_fingerprint = _measure_pre_validation_value_8616(
            "before_fingerprint",
            lambda: fingerprint_x86_16_tail_validation_boundary(
                self.project,
                self.codegen,
                mode=validation_mode,
            ),
        )
    before_fingerprint_elapsed = time.perf_counter() - before_fingerprint_started
    before_collect_started = time.perf_counter()
    with span("x86_16.decompile.validation.before_summary", function=func_addr):
        before_summary = _structuring_tail_validation_baseline_summary_8616(
            self.codegen,
            mode=validation_mode,
            before_fingerprint=before_fingerprint,
        )
        annotate_current_span(reused_structuring_baseline=before_summary is not None)
        if before_summary is None:
            before_summary = _measure_pre_validation_value_8616(
                "before_summary",
                lambda: _collect_tail_validation_summary_with_baseline_canonicalization_8616(
                    self.project,
                    self.codegen,
                    mode=validation_mode,
                    boundary_fingerprint=before_fingerprint,
                ),
            )
    before_collect_elapsed = time.perf_counter() - before_collect_started
    self.codegen._inertia_postprocess_pre_validation_cost_ms_8616 = round(
        (before_fingerprint_elapsed + before_collect_elapsed) * 1000.0,
        3,
    )
    if baseline_cfunc_snapshot is not None:
        _measure_pre_validation_value_8616(
            "baseline_project_function_restore",
            lambda: _restore_project_function_metadata_8616(baseline_project_function_snapshot),
        )
        _measure_pre_validation_value_8616(
            "baseline_cfunc_restore",
            lambda: _restore_codegen_cfunc(self.codegen, baseline_cfunc_snapshot),
        )
        _measure_pre_validation_value_8616(
            "baseline_metadata_restore",
            lambda: _restore_codegen_inertia_metadata_8616(self.codegen, baseline_metadata_snapshot),
        )
        _measure_pre_validation_value_8616(
            "baseline_text_restore",
            lambda: _restore_codegen_text_state_8616(self.codegen, baseline_text_snapshot),
        )
    _debug_prevalidation_pointer_surface_8616(self, "after-baseline-restore")
    self.codegen._inertia_postprocess_pre_validation_summary = before_summary
    materialized_condition_storage_before = capture_materialized_condition_storage_surface_8616(self.codegen)
    return (
        before_fingerprint,
        before_summary,
        materialized_condition_storage_before,
        before_collect_elapsed,
    )


def _snapshot_pre_postprocess_state_8616(
    self: StructuredAstValue,
    func_addr: StructuredAstValue,
) -> tuple[StructuredAstValue, StructuredAstValue, StructuredAstValue, StructuredAstValue]:
    """Snapshot cfunc, metadata, text, and project-function state before postprocess."""
    # Snapshot pre-postprocess codegen for the semantic gate. In the
    # validation-enabled path, mutating postprocess is only safe when a
    # rejected result can be restored.
    pre_postprocess_cfunc_snapshot = _measure_pre_validation_value_8616(
        "pre_postprocess_cfunc_snapshot",
        lambda: _snapshot_codegen_cfunc(self.codegen),
    )
    pre_postprocess_metadata_snapshot = (
        _measure_pre_validation_value_8616(
            "pre_postprocess_metadata_snapshot",
            lambda: _snapshot_codegen_inertia_metadata_8616(self.codegen),
        )
        if pre_postprocess_cfunc_snapshot is not None
        else None
    )
    pre_postprocess_text_snapshot = (
        _snapshot_codegen_text_state_8616(self.codegen) if pre_postprocess_cfunc_snapshot is not None else None
    )
    pre_postprocess_project_function_snapshot = (
        _measure_pre_validation_value_8616(
            "pre_postprocess_project_function_snapshot",
            lambda: _snapshot_project_function_metadata_8616(self.project, func_addr),
        )
        if pre_postprocess_cfunc_snapshot is not None
        else None
    )
    return (
        pre_postprocess_cfunc_snapshot,
        pre_postprocess_metadata_snapshot,
        pre_postprocess_text_snapshot,
        pre_postprocess_project_function_snapshot,
    )


def _run_postprocess_guarded_8616(
    self: StructuredAstValue,
    func_addr: StructuredAstValue,
    pre_postprocess_cfunc_snapshot: StructuredAstValue,
    pre_postprocess_metadata_snapshot: StructuredAstValue,
    pre_postprocess_text_snapshot: StructuredAstValue,
    pre_postprocess_project_function_snapshot: StructuredAstValue,
) -> tuple[bool, float, Exception | None]:
    """Run the mutating postprocess under a snapshot guard and time it."""
    postprocess_started = time.perf_counter()
    postprocess_exception: Exception | None = None
    if pre_postprocess_cfunc_snapshot is None:
        changed = False
        self.codegen._inertia_postprocess_skipped_missing_snapshot = True
        snapshot_error = getattr(self.codegen, "_inertia_postprocess_snapshot_error", None)
        logging.getLogger(__name__).error(
            "86_16 validation postprocess skipped for function=%#x: pre-postprocess snapshot unavailable: %s",
            int(func_addr) if isinstance(func_addr, int) else -1,
            snapshot_error or "unknown",
        )
    else:
        try:
            with span("x86_16.decompile.postprocess", function=func_addr):
                changed = _postprocess_codegen_8616(self.project, self.codegen)
                annotate_current_span(
                    changed=bool(changed),
                    last_pass=getattr(self.codegen, "_inertia_last_postprocess_pass", None),
                )
        except Exception as ex:  # pragma: no cover - defensive stage-finalization path
            postprocess_exception = ex
            changed = False
            logging.getLogger(__name__).warning(
                "86_16 postprocess pipeline raised; restoring pre-postprocess snapshot for function=%#x: %s",
                int(func_addr) if isinstance(func_addr, int) else -1,
                ex,
                exc_info=True,
            )
            with contextlib.suppress(Exception):
                _restore_project_function_metadata_8616(pre_postprocess_project_function_snapshot)
                _restore_codegen_cfunc(self.codegen, pre_postprocess_cfunc_snapshot)
                _restore_codegen_inertia_metadata_8616(self.codegen, pre_postprocess_metadata_snapshot)
                _restore_codegen_text_state_8616(self.codegen, pre_postprocess_text_snapshot)
            self.codegen._inertia_postprocess_exception = repr(ex)
            self.codegen._inertia_postprocess_exception_pass = getattr(self.codegen, "_inertia_last_postprocess_pass", None)
    postprocess_elapsed = time.perf_counter() - postprocess_started
    return changed, postprocess_elapsed, postprocess_exception


def _reconcile_condition_storage_integrity_8616(
    self: StructuredAstValue,
    materialized_condition_storage_before: StructuredAstValue,
    changed: bool,
    pre_postprocess_cfunc_snapshot: StructuredAstValue,
    pre_postprocess_metadata_snapshot: StructuredAstValue,
    pre_postprocess_text_snapshot: StructuredAstValue,
    pre_postprocess_project_function_snapshot: StructuredAstValue,
) -> bool:
    """Compare condition-storage surfaces and roll back a drifting postprocess."""
    materialized_condition_storage_after = capture_materialized_condition_storage_surface_8616(self.codegen)
    materialized_condition_storage_integrity = compare_materialized_condition_storage_surfaces_8616(
        materialized_condition_storage_before,
        materialized_condition_storage_after,
    )
    if materialized_condition_storage_integrity.drifted:
        changed = False
    if not changed and pre_postprocess_cfunc_snapshot is not None:
        _restore_project_function_metadata_8616(pre_postprocess_project_function_snapshot)
        _restore_codegen_cfunc(self.codegen, pre_postprocess_cfunc_snapshot)
        _restore_codegen_inertia_metadata_8616(self.codegen, pre_postprocess_metadata_snapshot)
        _restore_codegen_text_state_8616(self.codegen, pre_postprocess_text_snapshot)
    record_materialized_condition_storage_failure_8616(
        self.codegen,
        materialized_condition_storage_integrity,
    )
    return changed


def _resolve_stage_function_8616(self: StructuredAstValue) -> StructuredAstValue:
    """Resolve the angr Function for this decompile, falling back to the CFG."""
    function = getattr(self, "function", None) or getattr(self, "func", None)
    if function is None and getattr(getattr(self, "codegen", None), "cfunc", None) is not None:
        addr = getattr(self.codegen.cfunc, "addr", None)
        kb_functions = getattr(getattr(self, "project", None), "kb", None)
        kb_functions = getattr(kb_functions, "functions", None)
        if isinstance(addr, int) and kb_functions is not None:
            with contextlib.suppress(Exception):
                function = kb_functions.function(addr, create=False)
    return function


def _collect_after_validation_summary_8616(
    self: StructuredAstValue,
    func_addr: StructuredAstValue,
    validation_mode: str,
    changed: bool,
    pre_postprocess_cfunc_snapshot: StructuredAstValue,
    before_fingerprint: StructuredAstValue,
    before_summary: StructuredAstValue,
) -> tuple[StructuredAstValue, StructuredAstValue, float]:
    """Collect the post boundary summary, reusing the baseline on identity restore."""
    if not changed and pre_postprocess_cfunc_snapshot is not None:
        with span("x86_16.decompile.validation.after_fingerprint", function=func_addr, identity_restore=True):
            after_fingerprint = before_fingerprint
        after_collect_started = time.perf_counter()
        with span("x86_16.decompile.validation.after_summary", function=func_addr, identity_restore=True):
            after_summary = before_summary
        after_collect_elapsed = time.perf_counter() - after_collect_started
    else:
        with span("x86_16.decompile.validation.after_fingerprint", function=func_addr):
            after_fingerprint = fingerprint_x86_16_tail_validation_boundary(
                self.project,
                self.codegen,
                mode=validation_mode,
            )
        after_collect_started = time.perf_counter()
        with span("x86_16.decompile.validation.after_summary", function=func_addr):
            after_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
                self.project,
                self.codegen,
                mode=validation_mode,
                boundary_fingerprint=after_fingerprint,
            )
        after_collect_elapsed = time.perf_counter() - after_collect_started
    return after_fingerprint, after_summary, after_collect_elapsed


def _build_postprocess_validation_8616(
    self: StructuredAstValue,
    function: StructuredAstValue,
    func_addr: StructuredAstValue,
    validation_mode: str,
    before_fingerprint: StructuredAstValue,
    after_fingerprint: StructuredAstValue,
    before_summary: StructuredAstValue,
    after_summary: StructuredAstValue,
    postprocess_exception: StructuredAstValue,
    before_collect_elapsed: float,
    after_collect_elapsed: float,
) -> tuple[dict, dict, int, bool]:
    """Build the cached postprocess validation result with forced-failure marks."""
    owner = getattr(function, "info", None) if function is not None else None
    validation_started = time.perf_counter()
    with span("x86_16.decompile.validation.compare", function=func_addr):
        validation = build_x86_16_tail_validation_cached_result(
            owner=owner if isinstance(owner, MutableMapping) else None,
            stage="postprocess",
            mode=validation_mode,
            before_fingerprint=before_fingerprint,
            after_fingerprint=after_fingerprint,
            before_summary=before_summary,
            after_summary=after_summary,
        )
    if postprocess_exception is not None:
        validation["changed"] = True
        validation["status"] = "changed"
        validation["summary_text"] = f"postprocess exception: {type(postprocess_exception).__name__}"
    callsite_stats = getattr(self.codegen, "_inertia_callsite_materialization_stats", None)
    callsite_mismatch_count = int(getattr(callsite_stats, "known_prototype_arg_mismatch_count", 0) or 0)
    if callsite_mismatch_count > 0:
        validation["changed"] = True
        validation["status"] = "changed"
        validation["summary_text"] = (
            f"callsite materialization failed: known prototype argument mismatch count={callsite_mismatch_count}"
        )
    postprocess_validation_failed = bool(getattr(self.codegen, "_inertia_postprocess_validation_failed", False))
    if postprocess_validation_failed:
        _mark_destructive_postprocess_validation_failure_8616(
            self.project,
            self.codegen,
            validation,
            pass_name=getattr(self.codegen, "_inertia_postprocess_validation_failure_pass", None),
            summary_text=getattr(self.codegen, "_inertia_postprocess_validation_failure_error", None),
        )
    validation_compare_elapsed = time.perf_counter() - validation_started
    validation_timings = {
        "collect_before_ms": round(before_collect_elapsed * 1000.0, 3),
        "collect_after_ms": round(after_collect_elapsed * 1000.0, 3),
        "compare_ms": round(validation_compare_elapsed * 1000.0, 3),
        "total_ms": round(
            (before_collect_elapsed + after_collect_elapsed + validation_compare_elapsed) * 1000.0, 3
        ),
    }
    validation["timings"] = validation_timings
    validation["verdict"] = build_x86_16_tail_validation_verdict("postprocess", validation)
    return validation, validation_timings, callsite_mismatch_count, postprocess_validation_failed


def _debug_decompile_summaries_8616(
    before_summary: StructuredAstValue,
    after_summary: StructuredAstValue,
) -> None:
    """Emit the env-gated before/after summary diagnostic."""
    if not os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
        return
    import sys as _tv_sys4

    _tv_sys4.stderr.write(
        "[dbg] _decompile_8616 summaries: "
        f"before_conditions={_boundary_tuple_8616(getattr(before_summary, 'conditions', ()) or ())!r} "
        f"after_conditions={_boundary_tuple_8616(getattr(after_summary, 'conditions', ()) or ())!r} "
        f"before_control={_boundary_tuple_8616(getattr(before_summary, 'control_flow_effects', ()) or ())!r} "
        f"after_control={_boundary_tuple_8616(getattr(after_summary, 'control_flow_effects', ()) or ())!r}\n"
    )
    _tv_sys4.stderr.flush()


def _record_postprocess_run_info_8616(
    self: StructuredAstValue,
    function: StructuredAstValue,
    core_elapsed: float,
    postprocess_elapsed: float,
    validation_timings: StructuredAstValue,
    validation: dict,
) -> StructuredAstValue:
    """Record per-function postprocess timings and failure fields; return info owner."""
    snapshot_function_info = None
    if function is not None:
        info = getattr(function, "info", None)
        if isinstance(info, MutableMapping):
            snapshot_function_info = info
            postprocess_info = info.setdefault("x86_16_decompiler_postprocess", {})
            postprocess_info["core_elapsed"] = core_elapsed
            postprocess_info["postprocess_elapsed"] = postprocess_elapsed
            postprocess_info["tail_validation_timings"] = validation_timings
            postprocess_info["last_pass"] = getattr(self.codegen, "_inertia_last_postprocess_pass", None)
            postprocess_info["rewrite_failed"] = bool(getattr(self.codegen, "_inertia_rewrite_failed", False))
            postprocess_info["rewrite_failure_pass"] = getattr(self.codegen, "_inertia_rewrite_failure_pass", None)
            postprocess_info["rewrite_failure_error"] = getattr(
                self.codegen, "_inertia_rewrite_failure_error", None
            )
            postprocess_info["validation_failed"] = bool(
                getattr(self.codegen, "_inertia_postprocess_validation_failed", False)
            )
            postprocess_info["validation_failure_pass"] = getattr(
                self.codegen,
                "_inertia_postprocess_validation_failure_pass",
                None,
            )
            postprocess_info["validation_failure_error"] = getattr(
                self.codegen,
                "_inertia_postprocess_validation_failure_error",
                None,
            )
            postprocess_info["regeneration_failed"] = bool(
                getattr(self.codegen, "_inertia_regeneration_failed", False)
            )
            postprocess_info["regeneration_failure_pass"] = getattr(
                self.codegen,
                "_inertia_regeneration_last_pass",
                None,
            )
            postprocess_info["regeneration_failure_error"] = getattr(
                self.codegen,
                "_inertia_regeneration_error",
                None,
            )
            postprocess_info["pass_names"] = getattr(self.codegen, "_inertia_postprocess_passes", ())
            postprocess_info["last_stage"] = getattr(self.project, "_inertia_decompiler_stage", None)
            postprocess_info["tail_validation_verdict"] = validation["verdict"]
            postprocess_info["tail_validation_cache_hit"] = bool(validation.get("cache_hit", False))
    return snapshot_function_info


def _persist_postprocess_validation_8616(
    self: StructuredAstValue,
    snapshot_function_info: StructuredAstValue,
    validation: dict,
    func_addr: StructuredAstValue,
    func_name: StructuredAstValue,
) -> None:
    """Persist the validation snapshot and emit the condition-trace diagnostics."""
    persist_x86_16_tail_validation_snapshot(
        function_info=snapshot_function_info,
        codegen=self.codegen,
        stage="postprocess",
        validation=validation,
    )
    record_tail_validation_condition_trace_8616(self.project, self.codegen, validation)
    materialized_condition_drift_detected_8616(self.project, self.codegen)
    dump_condition_trace_8616(self.project, self.codegen, label="postprocess")
    snapshot = getattr(self.codegen, "_inertia_tail_validation_snapshot", None)
    if isinstance(snapshot, dict):
        self.project._inertia_last_tail_validation_snapshot = dict(snapshot)
    if os.environ.get("INERTIA_DEBUG_TV_POSTPROCESS"):
        import sys as _tv_sys2

        snapshot_stages = list(snapshot) if isinstance(snapshot, dict) else "NONE"
        _tv_sys2.stderr.write(
            f"[dbg] _decompile_8616 persist: addr={func_addr} name={func_name} "
            f"snapshot_stages={snapshot_stages} codegen_id={id(self.codegen)}\n"
        )
        _tv_sys2.stderr.flush()


def _finalize_failed_postprocess_validation_8616(
    self: StructuredAstValue,
    *,
    validation: dict,
    log: StructuredAstValue,
    validation_mode: str,
    function: StructuredAstValue,
    snapshot_function_info: StructuredAstValue,
    before_fingerprint: StructuredAstValue,
    before_summary: StructuredAstValue,
    pre_postprocess_cfunc_snapshot: StructuredAstValue,
    pre_postprocess_metadata_snapshot: StructuredAstValue,
    validation_timings: StructuredAstValue,
    func_addr: StructuredAstValue,
    postprocess_exception: StructuredAstValue,
    callsite_mismatch_count: int,
    postprocess_validation_failed: bool,
) -> bool:
    """Handle a failed postprocess validation; return True when the caller must return."""
    _postprocess_ctx = {
        "validation_mode": validation_mode,
        "function": function,
        "snapshot_function_info": snapshot_function_info,
        "before_fingerprint": before_fingerprint,
        "before_summary": before_summary,
        "pre_postprocess_cfunc_snapshot": pre_postprocess_cfunc_snapshot,
        "pre_postprocess_metadata_snapshot": pre_postprocess_metadata_snapshot,
        "validation_timings": validation_timings,
        "func_addr": func_addr,
        "postprocess_exception": postprocess_exception,
        "callsite_mismatch_count": callsite_mismatch_count,
    }
    if postprocess_exception is not None or callsite_mismatch_count > 0 or postprocess_validation_failed:
        self.codegen._inertia_postprocess_validation_failed = True
        if not postprocess_validation_failed:
            self.codegen._inertia_postprocess_validation_failure_pass = getattr(
                self.codegen,
                "_inertia_last_postprocess_pass",
                None,
            )
            self.codegen._inertia_postprocess_validation_failure_error = (
                repr(postprocess_exception)
                if postprocess_exception is not None
                else f"known prototype argument mismatch count={callsite_mismatch_count}"
            )
        log.error(
            "Postprocess validation failed due to final invariant; refusing stable fallback: %s",
            validation["verdict"],
        )
        self.project._inertia_decompiler_stage = "postprocess_failed"
        return
    _should_return = _handle_failed_postprocess_validation_8616(
        self,
        validation=validation,
        log=log,
        context=_postprocess_ctx,
    )
    return _should_return

def _decompile_8616(self: StructuredAstValue) -> None:
    """Run the x86-16 core, structuring, postprocess, and validation pipeline."""

    def _impl() -> None:
        core_elapsed = _run_decompile_core_8616(self)
        cfunc = getattr(self.codegen, "cfunc", None)
        func_addr = getattr(cfunc, "addr", None) if cfunc is not None else None
        func_name = getattr(cfunc, "name", None) if cfunc is not None else None
        tv_enabled = bool(getattr(self.project, "_inertia_tail_validation_enabled", True))
        _debug_decompile_entry_8616(self, func_addr, func_name, tv_enabled)
        if self.project.arch.name != "86_16" or self.codegen is None:
            return
        stage_function = getattr(self, "function", None) or getattr(self, "func", None)
        if stage_function is not None:
            self.codegen._inertia_current_function_8616 = stage_function
        if not tv_enabled:
            _run_no_tv_postprocess_path_8616(self, core_elapsed)
            return
        validation_mode = "live_out"
        _debug_decompile_validation_entry_8616(self, func_addr)
        _run_pre_validation_prime_8616(self, func_addr)
        (
            before_fingerprint,
            before_summary,
            materialized_condition_storage_before,
            before_collect_elapsed,
        ) = _collect_validation_baseline_8616(self, func_addr, validation_mode)
        (
            pre_postprocess_cfunc_snapshot,
            pre_postprocess_metadata_snapshot,
            pre_postprocess_text_snapshot,
            pre_postprocess_project_function_snapshot,
        ) = _snapshot_pre_postprocess_state_8616(self, func_addr)
        changed, postprocess_elapsed, postprocess_exception = _run_postprocess_guarded_8616(
            self,
            func_addr,
            pre_postprocess_cfunc_snapshot,
            pre_postprocess_metadata_snapshot,
            pre_postprocess_text_snapshot,
            pre_postprocess_project_function_snapshot,
        )
        changed = _reconcile_condition_storage_integrity_8616(
            self,
            materialized_condition_storage_before,
            changed,
            pre_postprocess_cfunc_snapshot,
            pre_postprocess_metadata_snapshot,
            pre_postprocess_text_snapshot,
            pre_postprocess_project_function_snapshot,
        )
        function = _resolve_stage_function_8616(self)
        context = f"{getattr(function, 'addr', 'unknown')!r} {getattr(function, 'name', 'unknown')}"
        if changed:
            _regenerate_text_safely(self.codegen, context=context)
        record_ast_condition_trace_8616(self.project, self.codegen, stage="emitted_c")
        # ── Pre-rewrite invariant gate ──
        # Keep diagnostics available, but do not run mutating gate logic by default
        # in validated flow. Late-stage semantic mutation here can invalidate the
        # postprocess equivalence contract.
        if os.environ.get("INERTIA_ENABLE_PRE_REWRITE_INVARIANT_GATE", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }:
            _inertia_run_pre_rewrite_invariant_gate(self.project, self.codegen, function)
        _invalidate_tail_validation_derived_caches_8616(self.codegen)
        (
            after_fingerprint,
            after_summary,
            after_collect_elapsed,
        ) = _collect_after_validation_summary_8616(
            self,
            func_addr,
            validation_mode,
            changed,
            pre_postprocess_cfunc_snapshot,
            before_fingerprint,
            before_summary,
        )
        (
            validation,
            validation_timings,
            callsite_mismatch_count,
            postprocess_validation_failed,
        ) = _build_postprocess_validation_8616(
            self,
            function,
            func_addr,
            validation_mode,
            before_fingerprint,
            after_fingerprint,
            before_summary,
            after_summary,
            postprocess_exception,
            before_collect_elapsed,
            after_collect_elapsed,
        )
        _debug_decompile_summaries_8616(before_summary, after_summary)
        snapshot_function_info = _record_postprocess_run_info_8616(
            self,
            function,
            core_elapsed,
            postprocess_elapsed,
            validation_timings,
            validation,
        )
        _persist_postprocess_validation_8616(
            self,
            snapshot_function_info,
            validation,
            func_addr,
            func_name,
        )
        log = logging.getLogger(__name__)
        if not x86_16_tail_validation_result_passed(validation):
            if _finalize_failed_postprocess_validation_8616(
                self,
                validation=validation,
                log=log,
                validation_mode=validation_mode,
                function=function,
                snapshot_function_info=snapshot_function_info,
                before_fingerprint=before_fingerprint,
                before_summary=before_summary,
                pre_postprocess_cfunc_snapshot=pre_postprocess_cfunc_snapshot,
                pre_postprocess_metadata_snapshot=pre_postprocess_metadata_snapshot,
                validation_timings=validation_timings,
                func_addr=func_addr,
                postprocess_exception=postprocess_exception,
                callsite_mismatch_count=callsite_mismatch_count,
                postprocess_validation_failed=postprocess_validation_failed,
            ):
                return
        else:
            log.info("%s", validation["verdict"])
        self.project._inertia_decompiler_stage = "done"
        _debug_decompile_done_8616(self, func_addr)

    function = getattr(self, "function", None) or getattr(self, "func", None)
    with active_status_flag_lift_context_8616(self.project, function):
        return _impl()


def _handle_failed_postprocess_validation_8616(
    self: StructuredAstValue,
    *,
    validation: StructuredAstValue,
    log: StructuredAstValue,
    context: dict[str, StructuredAstValue],
) -> bool:
    validation_mode = str(context["validation_mode"])
    function = context.get("function")
    snapshot_function_info = context.get("snapshot_function_info")
    before_fingerprint = context.get("before_fingerprint")
    before_summary = context.get("before_summary")
    pre_postprocess_cfunc_snapshot = context.get("pre_postprocess_cfunc_snapshot")
    pre_postprocess_metadata_snapshot = context.get("pre_postprocess_metadata_snapshot")
    validation_timings = context.get("validation_timings")
    func_addr = context.get("func_addr")
    validation_verdict_text = _rescue_missing_source_calls_8616(
        self,
        validation=validation,
        validation_mode=validation_mode,
        snapshot_function_info=snapshot_function_info,
        before_fingerprint=before_fingerprint,
        before_summary=before_summary,
    )
    if _try_accept_failed_postprocess_validation_8616(
        self,
        validation=validation,
        validation_verdict_text=validation_verdict_text,
        function=function,
        snapshot_function_info=snapshot_function_info,
        pre_postprocess_cfunc_snapshot=pre_postprocess_cfunc_snapshot,
        func_addr=func_addr,
        log=log,
    ):
        return True
    _discard_failed_postprocess_result_8616(
        self,
        validation=validation,
        validation_verdict_text=validation_verdict_text,
        validation_mode=validation_mode,
        snapshot_function_info=snapshot_function_info,
        before_fingerprint=before_fingerprint,
        before_summary=before_summary,
        pre_postprocess_cfunc_snapshot=pre_postprocess_cfunc_snapshot,
        pre_postprocess_metadata_snapshot=pre_postprocess_metadata_snapshot,
        validation_timings=validation_timings,
        function=function,
        log=log,
    )
    return False


def _postprocess_stable_accept_8616(
    self: StructuredAstValue, validation: StructuredAstValue, snapshot_function_info: StructuredAstValue
) -> None:
    if os.environ.get("INERTIA_DEBUG_RETURN_BRANCH"):
        root = getattr(getattr(self.codegen, "cfunc", None), "statements", None)
        top_count = len(_boundary_tuple_8616(getattr(root, "statements", ()) or ())) if root is not None else 0
        if_count, return_count = _return_chain_counts_8616(self.codegen)
        logging.getLogger(__name__).warning(
            "[empty-return-branch] stable-accept before-regen top=%d ifs=%d returns=%d",
            top_count,
            if_count,
            return_count,
        )
    _regenerate_text_safely(self.codegen, context="postprocess:accepted-validation-delta")
    if os.environ.get("INERTIA_DEBUG_RETURN_BRANCH"):
        root = getattr(getattr(self.codegen, "cfunc", None), "statements", None)
        top_count = len(_boundary_tuple_8616(getattr(root, "statements", ()) or ())) if root is not None else 0
        if_count, return_count = _return_chain_counts_8616(self.codegen)
        text = getattr(self.codegen, "text", "") or ""
        logging.getLogger(__name__).warning(
            "[empty-return-branch] stable-accept after-regen top=%d ifs=%d returns=%d text_returns=%d text_len=%d",
            top_count,
            if_count,
            return_count,
            text.count("return "),
            len(text),
        )
    if bool(getattr(self.codegen, "_inertia_postprocess_destructive_discard_recovery_8616", False)):
        validation["verdict"] = build_x86_16_tail_validation_verdict("postprocess", validation)
        persist_x86_16_tail_validation_snapshot(
            function_info=snapshot_function_info,
            codegen=self.codegen,
            stage="postprocess",
            validation=validation,
        )
        return
    validation["changed"] = False
    validation["status"] = "stable"
    validation["summary_text"] = "no observable whole-tail changes"
    validation.pop("delta", None)
    validation["verdict"] = build_x86_16_tail_validation_verdict("postprocess", validation)
    persist_x86_16_tail_validation_snapshot(
        function_info=snapshot_function_info,
        codegen=self.codegen,
        stage="postprocess",
        validation=validation,
    )
    snapshot = getattr(self.codegen, "_inertia_tail_validation_snapshot", None)
    if isinstance(snapshot, dict):
        postprocess_entry = snapshot.get("postprocess")
        if isinstance(postprocess_entry, dict):
            postprocess_entry.pop("delta", None)
            postprocess_entry["changed"] = False
            postprocess_entry["status"] = "stable"
            postprocess_entry["summary_text"] = "no observable whole-tail changes"
        self.project._inertia_last_tail_validation_snapshot = dict(snapshot)


def _rescue_missing_source_calls_8616(
    self: StructuredAstValue,
    *,
    validation: StructuredAstValue,
    validation_mode: str,
    snapshot_function_info: StructuredAstValue,
    before_fingerprint: StructuredAstValue,
    before_summary: StructuredAstValue,
) -> str:
    return str(validation.get("verdict") or validation.get("summary_text") or "")


def _bump_postprocess_validation_accept_counter_8616(codegen: StructuredAstValue, attr: str) -> None:
    """Increment a validation-acceptance counter on the dynamic codegen surface."""
    setattr(codegen, attr, int(getattr(codegen, attr, 0) or 0) + 1)


def _postprocess_validation_accept_arms_8616(
    self: StructuredAstValue,
    *,
    function: StructuredAstValue,
    validation: dict[str, StructuredAstValue],
) -> tuple:
    """Return the ordered uniform validation-delta acceptance arms.

    Each entry is ``(predicate, log_message, counter_attr)``; the first arm whose
    predicate proves the delta benign is accepted in evaluation order.
    """
    codegen = self.codegen
    project = self.project
    return (
        (
            lambda: _is_direct_callsite_helper_and_return_delta_8616(project, function, codegen, validation),
            "Postprocess validation helper-call/return delta accepted from CFG evidence",
            None,
        ),
        (
            lambda: _is_proven_surplus_empty_guard_cleanup_delta_8616(codegen, validation),
            "Postprocess validation surplus empty-guard cleanup accepted from Structuring branch-count evidence",
            "_inertia_surplus_empty_guard_validation_accepts_8616",
        ),
        (
            lambda: _is_cfg_return_chain_callsite_materialization_delta_8616(project, function, codegen, validation),
            "Postprocess validation CFG return-chain/callsite delta accepted from consumed evidence",
            None,
        ),
        (
            lambda: _is_cfg_return_expr_chain_materialization_delta_8616(project, function, codegen, validation),
            "Postprocess validation CFG return-expression delta accepted from consumed evidence",
            None,
        ),
        (
            lambda: _is_default_scalar_void_return_classification_delta_8616(codegen, validation),
            "Postprocess validation default-scalar void return classification accepted",
            "_inertia_default_scalar_void_return_validation_accepts_8616",
        ),
        (
            lambda: _is_unobserved_default_scalar_synthetic_return_delta_8616(function, validation),
            "Postprocess validation unobserved default-scalar synthetic return accepted",
            "_inertia_unobserved_default_scalar_synthetic_return_validation_accepts_8616",
        ),
        (
            lambda: _is_exposed_nonvoid_stack_arg_scalar_return_delta_8616(function, validation),
            "Postprocess validation exposed nonvoid stack-arg scalar return accepted",
            "_inertia_exposed_nonvoid_stack_arg_scalar_return_validation_accepts_8616",
        ),
        (
            lambda: _is_cfg_mask_accumulator_materialization_delta_8616(project, function, codegen, validation),
            "Postprocess validation CFG mask-accumulator delta accepted from consumed evidence",
            None,
        ),
        (
            lambda: _is_jcc_call_return_condition_rebinding_delta_8616(codegen, validation),
            "Postprocess validation JCC call-return condition delta accepted from consumed evidence",
            "_inertia_jcc_call_return_condition_validation_accepts",
        ),
        (
            lambda: _is_combined_jcc_callsite_stack_validation_delta_8616(project, function, codegen, validation),
            "Postprocess validation combined JCC/callsite delta accepted from consumed evidence",
            "_inertia_combined_jcc_callsite_validation_accepts_8616",
        ),
        (
            lambda: _is_jcc_condition_materialization_validation_delta_8616(
                project, codegen, validation, function=function
            ),
            "Postprocess validation JCC condition materialization delta accepted from consumed evidence",
            "_inertia_jcc_condition_materialization_validation_accepts",
        ),
        (
            lambda: _is_conditional_continue_guard_repair_delta_8616(codegen, validation),
            "Postprocess validation conditional-continue guard repair delta accepted from consumed evidence",
            None,
        ),
        (
            lambda: _is_stack_prototype_width_reconciliation_delta_8616(codegen, validation),
            "Postprocess validation stack-prototype width reconciliation accepted from typed push-source evidence",
            None,
        ),
        (
            lambda: _is_segmented_stack_slot_size_precision_delta_8616(validation),
            "Postprocess validation segmented stack-slot size precision delta accepted",
            "_inertia_segmented_stack_slot_size_precision_validation_accepts",
        ),
        (
            lambda: _is_direct_global_update_materialization_delta_8616(codegen, validation),
            "Postprocess validation direct global update materialization delta accepted from consumed evidence",
            "_inertia_direct_global_update_validation_accepts_8616",
        ),
        (
            lambda: _is_direct_stack_update_materialization_delta_8616(codegen, validation),
            "Postprocess validation direct stack update materialization delta accepted from consumed evidence",
            "_inertia_direct_stack_update_validation_accepts_8616",
        ),
        (
            lambda: _is_callsite_stack_argument_materialization_delta_8616(codegen, validation),
            "Postprocess validation callsite stack-argument materialization delta accepted from consumed evidence",
            "_inertia_callsite_stack_arg_validation_accepts_8616",
        ),
        (
            lambda: _is_direct_stack_move_materialization_delta_8616(codegen, validation)
            or _is_direct_stack_move_idiv_remainder_materialization_delta_8616(codegen, validation),
            "Postprocess validation direct stack move materialization delta accepted from consumed evidence",
            "_inertia_direct_stack_move_validation_accepts_8616",
        ),
        (
            lambda: _is_direct_callsite_helper_delta_only_8616(project, function, validation),
            "Postprocess validation helper-call delta accepted from direct callsite evidence",
            None,
        ),
    )


def _accept_exit_goto_repair_delta_8616(
    self: StructuredAstValue,
    *,
    validation: dict[str, StructuredAstValue],
    snapshot_function_info: StructuredAstValue,
    log: StructuredAstValue,
) -> bool:
    """Accept the exit-goto canonicalization delta when no unresolved gotos remain."""
    if _postprocess_has_unresolved_gotos_8616(self.codegen):
        log.warning(
            "Postprocess validation changed but unresolved function-exit gotos remain: %s",
            validation.get("verdict"),
        )
        return False
    log.warning(
        "Postprocess validation changed but accepting unresolved-exit-goto canonicalization: %s",
        validation.get("verdict"),
    )
    _postprocess_stable_accept_8616(self, validation, snapshot_function_info)
    return True

def _try_accept_failed_postprocess_validation_8616(
    self: StructuredAstValue,
    *,
    validation: dict[str, StructuredAstValue],
    validation_verdict_text: str,
    function: StructuredAstValue,
    snapshot_function_info: StructuredAstValue,
    pre_postprocess_cfunc_snapshot: StructuredAstValue,
    func_addr: StructuredAstValue,
    log: logging.Logger,
) -> bool:
    """Accept only an evidenced validation delta for the supplied function."""
    def _impl() -> bool:
        allow_validation_override = str(
            os.environ.get("INERTIA_ALLOW_POSTPROCESS_VALIDATION_OVERRIDE", "")
        ).strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        uniform_arms = _postprocess_validation_accept_arms_8616(
            self,
            function=function,
            validation=validation,
        )
        for predicate, message, counter_attr in uniform_arms:
            if not predicate():
                continue
            log.warning("%s: %s", message, validation.get("verdict"))
            if counter_attr is not None:
                _bump_postprocess_validation_accept_counter_8616(self.codegen, counter_attr)
            _postprocess_stable_accept_8616(self, validation, snapshot_function_info)
            return True
        if _postprocess_exit_goto_repair_delta_8616(validation):
            return _accept_exit_goto_repair_delta_8616(
                self,
                validation=validation,
                snapshot_function_info=snapshot_function_info,
                log=log,
            )
        if _is_switch_loop_exit_return_repair_delta_8616(self.codegen, validation):
            log.warning(
                "Postprocess validation switch loop-exit return delta accepted from CFG evidence: %s",
                validation.get("verdict"),
            )
            _postprocess_stable_accept_8616(self, validation, snapshot_function_info)
            return True
        if (
            _postprocess_validation_has_source_evidenced_blocking_reason_8616(validation)
            and pre_postprocess_cfunc_snapshot is not None
        ):
            post_score, post_total = _expected_kb_call_score_from_cfunc_8616(
                self.project,
                getattr(self.codegen, "cfunc", None),
                function,
            )
            pre_score, pre_total = _expected_kb_call_score_from_cfunc_8616(
                self.project,
                pre_postprocess_cfunc_snapshot,
                function,
            )
            if allow_validation_override and post_total > 0 and post_score >= pre_score:
                log.warning(
                    "Postprocess validation changed but keeping stronger KB call-target coverage "
                    "(post=%d/%d pre=%d/%d): %s",
                    post_score,
                    post_total,
                    pre_score,
                    pre_total,
                    validation.get("verdict"),
                )
                _postprocess_stable_accept_8616(self, validation, snapshot_function_info)
                self.project._inertia_decompiler_stage = "done"
                import sys as _tv_sys4

                tv_snap = getattr(self.codegen, "_inertia_tail_validation_snapshot", None)
                tv_stages = list(tv_snap) if isinstance(tv_snap, dict) else "NONE"
                project_tv_snap = getattr(self.project, "_inertia_last_tail_validation_snapshot", None)
                project_tv_stages = list(project_tv_snap) if isinstance(project_tv_snap, dict) else "NONE"
                _tv_sys4.stderr.write(
                    f"[dbg] _decompile_8616 DONE: addr={func_addr} codegen_id={id(self.codegen)} "
                    f"snapshot_stages={tv_stages} proj_fb_stages={project_tv_stages}\n"
                )
                _tv_sys4.stderr.flush()
                return True
        return False

    return _impl()


def _salvage_signed_idiv_stack_move_after_discard_8616(
    self: StructuredAstValue,
    *,
    validation_mode: str,
    snapshot_function_info: StructuredAstValue,
    function: StructuredAstValue,
    log: StructuredAstValue,
) -> bool:
    cfunc_snapshot = _snapshot_codegen_cfunc(self.codegen)
    if cfunc_snapshot is None:
        return False
    metadata_snapshot = _snapshot_codegen_inertia_metadata_8616(self.codegen)
    try:
        before_fingerprint = fingerprint_x86_16_tail_validation_boundary(
            self.project,
            self.codegen,
            mode=validation_mode,
        )
        before_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
            self.project,
            self.codegen,
            mode=validation_mode,
            boundary_fingerprint=before_fingerprint,
        )
        changed = materialize_direct_stack_mov_instructions_8616(
            self.codegen,
            project=self.project,
            function=function,
            allow_stack_slot_fallback=True,
            source_kinds=frozenset({DirectStackMoveSourceKind8616.SIGNED_IDIV_REMAINDER}),
        )
        if not changed:
            return False
        _regenerate_text_safely(self.codegen, context="postprocess:discard-signed-idiv-stack-move-salvage")
        after_fingerprint = fingerprint_x86_16_tail_validation_boundary(
            self.project,
            self.codegen,
            mode=validation_mode,
        )
        after_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
            self.project,
            self.codegen,
            mode=validation_mode,
            boundary_fingerprint=after_fingerprint,
        )
        validation = build_x86_16_tail_validation_cached_result(
            owner=snapshot_function_info,
            stage="postprocess",
            mode=validation_mode,
            before_fingerprint=before_fingerprint,
            after_fingerprint=after_fingerprint,
            before_summary=before_summary,
            after_summary=after_summary,
        )
        accepted_direct_stack_idiv_delta = _is_direct_stack_move_idiv_remainder_materialization_delta_8616(
            self.codegen,
            validation,
        )
        if bool(validation.get("changed")) and not accepted_direct_stack_idiv_delta:
            _restore_codegen_cfunc(self.codegen, cfunc_snapshot)
            _restore_codegen_inertia_metadata_8616(self.codegen, metadata_snapshot)
            _invalidate_tail_validation_derived_caches_8616(self.codegen)
            log.warning(
                "Rejected isolated signed-idiv stack move after postprocess discard: %s",
                build_x86_16_tail_validation_verdict("postprocess", validation),
            )
            return False
        if accepted_direct_stack_idiv_delta:
            log.warning(
                "Accepted isolated signed-idiv stack move after postprocess discard "
                "with artifact-only validation delta: %s",
                build_x86_16_tail_validation_verdict("postprocess", validation),
            )
            _postprocess_stable_accept_8616(self, validation, snapshot_function_info)
        else:
            validation["verdict"] = build_x86_16_tail_validation_verdict("postprocess", validation)
            persist_x86_16_tail_validation_snapshot(
                function_info=snapshot_function_info,
                codegen=self.codegen,
                stage="postprocess",
                validation=validation,
            )
        self.codegen._inertia_direct_stack_idiv_salvaged_after_discard_8616 = True
        log.warning("Accepted isolated signed-idiv stack move after postprocess discard")
        return True
    except Exception as ex:
        _restore_codegen_cfunc(self.codegen, cfunc_snapshot)
        _restore_codegen_inertia_metadata_8616(self.codegen, metadata_snapshot)
        _invalidate_tail_validation_derived_caches_8616(self.codegen)
        log.debug("Signed-idiv stack move salvage after postprocess discard failed: %s", ex, exc_info=True)
        return False


def _salvage_dce_after_discard_8616(
    self: StructuredAstValue,
    *,
    validation_mode: str,
    snapshot_function_info: StructuredAstValue,
    log: StructuredAstValue,
) -> bool:
    cfunc_snapshot = _snapshot_codegen_cfunc(self.codegen)
    if cfunc_snapshot is None:
        return False
    metadata_snapshot = _snapshot_codegen_inertia_metadata_8616(self.codegen)
    try:
        before_fingerprint = fingerprint_x86_16_tail_validation_boundary(
            self.project,
            self.codegen,
            mode=validation_mode,
        )
        before_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
            self.project,
            self.codegen,
            mode=validation_mode,
            boundary_fingerprint=before_fingerprint,
        )
        changed = _dead_code_elimination_8616(self.codegen)
        changed = _simplify._inline_single_assignment_virtual_expressions_8616(self.codegen) or changed
        changed = normalize_multi_statement_braces_8616(self.codegen) or changed
        changed = apply_affine_compound_assignment_identity_8616(self.codegen) or changed
        if not changed:
            return False
        _regenerate_text_safely(self.codegen, context="postprocess:discard-dce-salvage")
        after_fingerprint = fingerprint_x86_16_tail_validation_boundary(
            self.project,
            self.codegen,
            mode=validation_mode,
        )
        after_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
            self.project,
            self.codegen,
            mode=validation_mode,
            boundary_fingerprint=after_fingerprint,
        )
        validation = build_x86_16_tail_validation_cached_result(
            owner=snapshot_function_info,
            stage="postprocess",
            mode=validation_mode,
            before_fingerprint=before_fingerprint,
            after_fingerprint=after_fingerprint,
            before_summary=before_summary,
            after_summary=after_summary,
        )
        if bool(validation.get("changed")):
            _restore_codegen_cfunc(self.codegen, cfunc_snapshot)
            _restore_codegen_inertia_metadata_8616(self.codegen, metadata_snapshot)
            _invalidate_tail_validation_derived_caches_8616(self.codegen)
            log.warning(
                "Rejected isolated cleanup after postprocess discard: %s",
                build_x86_16_tail_validation_verdict("postprocess", validation),
            )
            return False
        validation["verdict"] = build_x86_16_tail_validation_verdict("postprocess", validation)
        persist_x86_16_tail_validation_snapshot(
            function_info=snapshot_function_info,
            codegen=self.codegen,
            stage="postprocess",
            validation=validation,
        )
        self.codegen._inertia_dce_salvaged_after_discard_8616 = True
        log.warning("Accepted isolated cleanup after postprocess discard")
        return True
    except Exception as ex:
        _restore_codegen_cfunc(self.codegen, cfunc_snapshot)
        _restore_codegen_inertia_metadata_8616(self.codegen, metadata_snapshot)
        _invalidate_tail_validation_derived_caches_8616(self.codegen)
        log.debug("DCE salvage after postprocess discard failed: %s", ex, exc_info=True)
        return False


def _salvage_direct_stack_move_after_discard_8616(
    self: StructuredAstValue,
    *,
    validation_mode: str,
    snapshot_function_info: StructuredAstValue,
    function: StructuredAstValue,
    log: logging.Logger,
) -> bool:
    cfunc_snapshot = _snapshot_codegen_cfunc(self.codegen)
    if cfunc_snapshot is None:
        return False
    metadata_snapshot = _snapshot_codegen_inertia_metadata_8616(self.codegen)
    try:
        before_fingerprint = fingerprint_x86_16_tail_validation_boundary(
            self.project,
            self.codegen,
            mode=validation_mode,
        )
        before_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
            self.project,
            self.codegen,
            mode=validation_mode,
            boundary_fingerprint=before_fingerprint,
        )
        changed = materialize_direct_stack_mov_instructions_8616(
            self.codegen,
            project=self.project,
            function=function,
            allow_stack_slot_fallback=True,
            source_kinds=_NON_IDIV_DIRECT_STACK_MOVE_SOURCE_KINDS_8616,
        )
        changed = _repair_hoisted_jcc_target_copies_from_evidence_pass_8616(self.project, self.codegen) or changed
        if not changed:
            log.warning(
                "No isolated direct stack move salvage after postprocess discard: stats=%r evidence=%r",
                getattr(self.codegen, "_inertia_direct_stack_move_lowering_8616", None),
                getattr(self.codegen, "_inertia_direct_stack_move_evidence_8616", None),
            )
            return False
        _regenerate_text_safely(self.codegen, context="postprocess:discard-direct-stack-move-salvage")
        after_fingerprint = fingerprint_x86_16_tail_validation_boundary(
            self.project,
            self.codegen,
            mode=validation_mode,
        )
        after_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
            self.project,
            self.codegen,
            mode=validation_mode,
            boundary_fingerprint=after_fingerprint,
        )
        validation = build_x86_16_tail_validation_cached_result(
            owner=snapshot_function_info,
            stage="postprocess",
            mode=validation_mode,
            before_fingerprint=before_fingerprint,
            after_fingerprint=after_fingerprint,
            before_summary=before_summary,
            after_summary=after_summary,
        )
        accepted_delta = _is_direct_stack_move_materialization_delta_8616(
            self.codegen,
            validation,
        ) or _is_jcc_condition_materialization_validation_delta_8616(
            self.project,
            self.codegen,
            validation,
            function=function,
        )
        if bool(validation.get("changed")) and not accepted_delta:
            _restore_codegen_cfunc(self.codegen, cfunc_snapshot)
            _restore_codegen_inertia_metadata_8616(self.codegen, metadata_snapshot)
            _invalidate_tail_validation_derived_caches_8616(self.codegen)
            log.warning(
                "Rejected isolated direct stack move after postprocess discard: %s",
                build_x86_16_tail_validation_verdict("postprocess", validation),
            )
            return False
        if accepted_delta:
            log.warning(
                "Accepted isolated direct stack move after postprocess discard with validation delta: %s",
                build_x86_16_tail_validation_verdict("postprocess", validation),
            )
            _postprocess_stable_accept_8616(self, validation, snapshot_function_info)
        else:
            validation["verdict"] = build_x86_16_tail_validation_verdict("postprocess", validation)
            persist_x86_16_tail_validation_snapshot(
                function_info=snapshot_function_info,
                codegen=self.codegen,
                stage="postprocess",
                validation=validation,
            )
        self.codegen._inertia_direct_stack_move_salvaged_after_discard_8616 = True
        log.warning("Accepted isolated direct stack move after postprocess discard")
        return True
    except Exception as ex:
        _restore_codegen_cfunc(self.codegen, cfunc_snapshot)
        _restore_codegen_inertia_metadata_8616(self.codegen, metadata_snapshot)
        _invalidate_tail_validation_derived_caches_8616(self.codegen)
        log.warning("Direct stack move salvage after postprocess discard failed: %s", ex)
        log.debug("Direct stack move salvage after postprocess discard failed: %s", ex, exc_info=True)
        return False


def _salvage_direct_stack_update_after_discard_8616(
    self: StructuredAstValue,
    *,
    validation_mode: str,
    snapshot_function_info: StructuredAstValue,
    function: StructuredAstValue,
    log: StructuredAstValue,
) -> bool:
    cfunc_snapshot = _snapshot_codegen_cfunc(self.codegen)
    if cfunc_snapshot is None:
        return False
    metadata_snapshot = _snapshot_codegen_inertia_metadata_8616(self.codegen)
    try:
        before_fingerprint = fingerprint_x86_16_tail_validation_boundary(
            self.project,
            self.codegen,
            mode=validation_mode,
        )
        before_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
            self.project,
            self.codegen,
            mode=validation_mode,
            boundary_fingerprint=before_fingerprint,
        )
        changed = materialize_direct_stack_incdec_instructions_8616(
            self.codegen,
            project=self.project,
            function=function,
        )
        if not changed:
            return False
        _regenerate_text_safely(self.codegen, context="postprocess:discard-direct-stack-update-salvage")
        after_fingerprint = fingerprint_x86_16_tail_validation_boundary(
            self.project,
            self.codegen,
            mode=validation_mode,
        )
        after_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
            self.project,
            self.codegen,
            mode=validation_mode,
            boundary_fingerprint=after_fingerprint,
        )
        validation = build_x86_16_tail_validation_cached_result(
            owner=snapshot_function_info,
            stage="postprocess",
            mode=validation_mode,
            before_fingerprint=before_fingerprint,
            after_fingerprint=after_fingerprint,
            before_summary=before_summary,
            after_summary=after_summary,
        )
        accepted_delta = _is_direct_stack_update_materialization_delta_8616(self.codegen, validation)
        if bool(validation.get("changed")) and not accepted_delta:
            _restore_codegen_cfunc(self.codegen, cfunc_snapshot)
            _restore_codegen_inertia_metadata_8616(self.codegen, metadata_snapshot)
            _invalidate_tail_validation_derived_caches_8616(self.codegen)
            log.warning(
                "Rejected isolated direct stack update after postprocess discard: %s",
                build_x86_16_tail_validation_verdict("postprocess", validation),
            )
            return False
        if accepted_delta:
            log.warning(
                "Accepted isolated direct stack update after postprocess discard with validation delta: %s",
                build_x86_16_tail_validation_verdict("postprocess", validation),
            )
            _postprocess_stable_accept_8616(self, validation, snapshot_function_info)
        else:
            validation["verdict"] = build_x86_16_tail_validation_verdict("postprocess", validation)
            persist_x86_16_tail_validation_snapshot(
                function_info=snapshot_function_info,
                codegen=self.codegen,
                stage="postprocess",
                validation=validation,
            )
        self.codegen._inertia_direct_stack_update_salvaged_after_discard_8616 = True
        log.warning("Accepted isolated direct stack update after postprocess discard")
        return True
    except Exception as ex:
        _restore_codegen_cfunc(self.codegen, cfunc_snapshot)
        _restore_codegen_inertia_metadata_8616(self.codegen, metadata_snapshot)
        _invalidate_tail_validation_derived_caches_8616(self.codegen)
        log.debug("Direct stack update salvage after postprocess discard failed: %s", ex, exc_info=True)
        return False


def _salvage_direct_global_update_after_discard_8616(
    self: StructuredAstValue,
    *,
    validation_mode: str,
    snapshot_function_info: StructuredAstValue,
    function: StructuredAstValue,
    log: StructuredAstValue,
) -> bool:
    cfunc_snapshot = _snapshot_codegen_cfunc(self.codegen)
    if cfunc_snapshot is None:
        return False
    metadata_snapshot = _snapshot_codegen_inertia_metadata_8616(self.codegen)
    try:
        before_fingerprint = fingerprint_x86_16_tail_validation_boundary(
            self.project,
            self.codegen,
            mode=validation_mode,
        )
        before_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
            self.project,
            self.codegen,
            mode=validation_mode,
            boundary_fingerprint=before_fingerprint,
        )
        changed = materialize_direct_global_incdec_instructions_8616(
            self.codegen,
            project=self.project,
            function=function,
        )
        if not changed:
            return False
        _regenerate_text_safely(self.codegen, context="postprocess:discard-direct-global-update-salvage")
        after_fingerprint = fingerprint_x86_16_tail_validation_boundary(
            self.project,
            self.codegen,
            mode=validation_mode,
        )
        after_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
            self.project,
            self.codegen,
            mode=validation_mode,
            boundary_fingerprint=after_fingerprint,
        )
        validation = build_x86_16_tail_validation_cached_result(
            owner=snapshot_function_info,
            stage="postprocess",
            mode=validation_mode,
            before_fingerprint=before_fingerprint,
            after_fingerprint=after_fingerprint,
            before_summary=before_summary,
            after_summary=after_summary,
        )
        accepted_delta = _is_direct_global_update_materialization_delta_8616(self.codegen, validation)
        if bool(validation.get("changed")) and not accepted_delta:
            _restore_codegen_cfunc(self.codegen, cfunc_snapshot)
            _restore_codegen_inertia_metadata_8616(self.codegen, metadata_snapshot)
            _invalidate_tail_validation_derived_caches_8616(self.codegen)
            log.warning(
                "Rejected isolated direct global update after postprocess discard: %s",
                build_x86_16_tail_validation_verdict("postprocess", validation),
            )
            return False
        if accepted_delta:
            log.warning(
                "Accepted isolated direct global update after postprocess discard with validation delta: %s",
                build_x86_16_tail_validation_verdict("postprocess", validation),
            )
            _postprocess_stable_accept_8616(self, validation, snapshot_function_info)
        else:
            validation["verdict"] = build_x86_16_tail_validation_verdict("postprocess", validation)
            persist_x86_16_tail_validation_snapshot(
                function_info=snapshot_function_info,
                codegen=self.codegen,
                stage="postprocess",
                validation=validation,
            )
        self.codegen._inertia_direct_global_update_salvaged_after_discard_8616 = True
        log.warning("Accepted isolated direct global update after postprocess discard")
        return True
    except Exception as ex:
        _restore_codegen_cfunc(self.codegen, cfunc_snapshot)
        _restore_codegen_inertia_metadata_8616(self.codegen, metadata_snapshot)
        _invalidate_tail_validation_derived_caches_8616(self.codegen)
        log.debug("Direct global update salvage after postprocess discard failed: %s", ex, exc_info=True)
        return False


def _salvage_segmented_global_materialization_after_discard_8616(
    self: StructuredAstValue,
    *,
    validation_mode: str,
    snapshot_function_info: StructuredAstValue,
    function: StructuredAstValue,
    log: StructuredAstValue,
) -> bool:
    cfunc_snapshot = _snapshot_codegen_cfunc(self.codegen)
    if cfunc_snapshot is None:
        return False
    metadata_snapshot = _snapshot_codegen_inertia_metadata_8616(self.codegen)
    try:
        before_fingerprint = fingerprint_x86_16_tail_validation_boundary(
            self.project,
            self.codegen,
            mode=validation_mode,
        )
        before_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
            self.project,
            self.codegen,
            mode=validation_mode,
            boundary_fingerprint=before_fingerprint,
        )
        cfunc = getattr(self.codegen, "cfunc", None)
        cod_metadata = _cod_metadata_for_codegen_function_8616(self.project, getattr(cfunc, "addr", None))
        synthetic_globals = getattr(self.codegen, "_inertia_synthetic_globals", None)
        if not isinstance(synthetic_globals, dict):
            synthetic_globals = getattr(self.project, "_inertia_synthetic_globals", None)
        if not isinstance(synthetic_globals, dict):
            synthetic_globals = None
        changed = False
        changed = (
            materialize_named_segmented_global_loads_8616(
                self.project,
                self.codegen,
                synthetic_globals,
                cod_metadata=cod_metadata,
            )
            or changed
        )
        changed = (
            materialize_direct_global_symbol_stores_8616(
                self.project,
                self.codegen,
                synthetic_globals,
                cod_metadata=cod_metadata,
            )
            or changed
        )
        changed = (
            materialize_indexed_segmented_global_loads_8616(
                self.project,
                self.codegen,
                cod_metadata=cod_metadata,
            )
            or changed
        )
        if not changed:
            return False
        _regenerate_text_safely(self.codegen, context="postprocess:discard-segmented-global-salvage")
        after_fingerprint = fingerprint_x86_16_tail_validation_boundary(
            self.project,
            self.codegen,
            mode=validation_mode,
        )
        after_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
            self.project,
            self.codegen,
            mode=validation_mode,
            boundary_fingerprint=after_fingerprint,
        )
        validation = build_x86_16_tail_validation_cached_result(
            owner=snapshot_function_info,
            stage="postprocess",
            mode=validation_mode,
            before_fingerprint=before_fingerprint,
            after_fingerprint=after_fingerprint,
            before_summary=before_summary,
            after_summary=after_summary,
        )
        accepted_delta = _is_segmented_global_symbol_materialization_delta_8616(
            self.project,
            self.codegen,
            validation=validation,
        )
        if bool(validation.get("changed")) and not accepted_delta:
            _restore_codegen_cfunc(self.codegen, cfunc_snapshot)
            _restore_codegen_inertia_metadata_8616(self.codegen, metadata_snapshot)
            _invalidate_tail_validation_derived_caches_8616(self.codegen)
            log.warning(
                "Rejected isolated segmented global materialization after postprocess discard: %s",
                build_x86_16_tail_validation_verdict("postprocess", validation),
            )
            return False
        if accepted_delta:
            log.warning(
                "Accepted isolated segmented global materialization after postprocess discard "
                "with validation delta: %s",
                build_x86_16_tail_validation_verdict("postprocess", validation),
            )
            _postprocess_stable_accept_8616(self, validation, snapshot_function_info)
        else:
            validation["verdict"] = build_x86_16_tail_validation_verdict("postprocess", validation)
            persist_x86_16_tail_validation_snapshot(
                function_info=snapshot_function_info,
                codegen=self.codegen,
                stage="postprocess",
                validation=validation,
            )
        self.codegen._inertia_segmented_global_materialization_salvaged_after_discard_8616 = True
        log.warning("Accepted isolated segmented global materialization after postprocess discard")
        return True
    except Exception as ex:
        _restore_codegen_cfunc(self.codegen, cfunc_snapshot)
        _restore_codegen_inertia_metadata_8616(self.codegen, metadata_snapshot)
        _invalidate_tail_validation_derived_caches_8616(self.codegen)
        log.debug("Segmented global materialization salvage after postprocess discard failed: %s", ex, exc_info=True)
        return False


def _salvage_callsite_stack_args_after_discard_8616(
    self: StructuredAstValue,
    *,
    validation_mode: str,
    snapshot_function_info: StructuredAstValue,
    function: StructuredAstValue,
    log: StructuredAstValue,
) -> bool:
    """Refuse Rewrite salvage once Structuring owns call-argument lowering."""
    if bool(getattr(self.codegen, "_inertia_callsite_stack_arguments_structuring_pass_ran_8616", False)):
        return False
    cfunc_snapshot = _snapshot_codegen_cfunc(self.codegen)
    if cfunc_snapshot is None:
        return False
    metadata_snapshot = _snapshot_codegen_inertia_metadata_8616(self.codegen)
    try:
        before_fingerprint = fingerprint_x86_16_tail_validation_boundary(
            self.project,
            self.codegen,
            mode=validation_mode,
        )
        before_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
            self.project,
            self.codegen,
            mode=validation_mode,
            boundary_fingerprint=before_fingerprint,
        )
        changed = bool(
            _materialize_callsite_stack_arguments_with_target_identity_8616(
                self.project,
                self.codegen,
            )
        )
        if not changed:
            return False
        _regenerate_text_safely(self.codegen, context="postprocess:discard-callsite-arg-salvage")
        after_fingerprint = fingerprint_x86_16_tail_validation_boundary(
            self.project,
            self.codegen,
            mode=validation_mode,
        )
        after_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
            self.project,
            self.codegen,
            mode=validation_mode,
            boundary_fingerprint=after_fingerprint,
        )
        validation = build_x86_16_tail_validation_cached_result(
            owner=snapshot_function_info,
            stage="postprocess",
            mode=validation_mode,
            before_fingerprint=before_fingerprint,
            after_fingerprint=after_fingerprint,
            before_summary=before_summary,
            after_summary=after_summary,
        )
        accepted_callsite_delta = _is_callsite_stack_argument_materialization_delta_8616(
            self.codegen,
            validation,
        )
        if bool(validation.get("changed")) and not accepted_callsite_delta:
            _restore_codegen_cfunc(self.codegen, cfunc_snapshot)
            _restore_codegen_inertia_metadata_8616(self.codegen, metadata_snapshot)
            _invalidate_tail_validation_derived_caches_8616(self.codegen)
            log.warning(
                "Rejected isolated callsite stack-argument materialization after postprocess discard: %s",
                build_x86_16_tail_validation_verdict("postprocess", validation),
            )
            return False
        if accepted_callsite_delta:
            log.warning(
                "Accepted isolated callsite stack-argument materialization after postprocess discard "
                "with validation delta: %s",
                build_x86_16_tail_validation_verdict("postprocess", validation),
            )
            _postprocess_stable_accept_8616(self, validation, snapshot_function_info)
        else:
            validation["verdict"] = build_x86_16_tail_validation_verdict("postprocess", validation)
            persist_x86_16_tail_validation_snapshot(
                function_info=snapshot_function_info,
                codegen=self.codegen,
                stage="postprocess",
                validation=validation,
            )
        self.codegen._inertia_callsite_stack_args_salvaged_after_discard_8616 = True
        log.warning("Accepted isolated callsite stack-argument materialization after postprocess discard")
        return True
    except Exception as ex:
        _restore_codegen_cfunc(self.codegen, cfunc_snapshot)
        _restore_codegen_inertia_metadata_8616(self.codegen, metadata_snapshot)
        _invalidate_tail_validation_derived_caches_8616(self.codegen)
        log.debug("Callsite stack-argument salvage after postprocess discard failed: %s", ex, exc_info=True)
        return False


def _salvage_flag_cleanup_after_discard_8616(
    self: StructuredAstValue,
    *,
    validation_mode: str,
    snapshot_function_info: StructuredAstValue,
    function: StructuredAstValue,
    log: StructuredAstValue,
) -> bool:
    cfunc_snapshot = _snapshot_codegen_cfunc(self.codegen)
    if cfunc_snapshot is None:
        return False
    metadata_snapshot = _snapshot_codegen_inertia_metadata_8616(self.codegen)
    try:
        before_fingerprint = fingerprint_x86_16_tail_validation_boundary(
            self.project,
            self.codegen,
            mode=validation_mode,
        )
        before_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
            self.project,
            self.codegen,
            mode=validation_mode,
            boundary_fingerprint=before_fingerprint,
        )
        changed = False
        changed = bool(_flags._prune_unused_flag_assignments_8616(self.project, self.codegen)) or changed
        changed = bool(_flags._prune_overwritten_flag_assignments_8616(self.project, self.codegen)) or changed
        changed = bool(_dead_code_elimination_after_flag_prune_8616(self.codegen)) or changed
        if not changed:
            return False
        _regenerate_text_safely(self.codegen, context="postprocess:discard-flag-cleanup-salvage")
        after_fingerprint = fingerprint_x86_16_tail_validation_boundary(
            self.project,
            self.codegen,
            mode=validation_mode,
        )
        after_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
            self.project,
            self.codegen,
            mode=validation_mode,
            boundary_fingerprint=after_fingerprint,
        )
        validation = build_x86_16_tail_validation_cached_result(
            owner=snapshot_function_info,
            stage="postprocess",
            mode=validation_mode,
            before_fingerprint=before_fingerprint,
            after_fingerprint=after_fingerprint,
            before_summary=before_summary,
            after_summary=after_summary,
        )
        if bool(validation.get("changed")):
            _restore_codegen_cfunc(self.codegen, cfunc_snapshot)
            _restore_codegen_inertia_metadata_8616(self.codegen, metadata_snapshot)
            _invalidate_tail_validation_derived_caches_8616(self.codegen)
            log.warning(
                "Rejected isolated flag cleanup after postprocess discard: %s",
                build_x86_16_tail_validation_verdict("postprocess", validation),
            )
            return False
        validation["verdict"] = build_x86_16_tail_validation_verdict("postprocess", validation)
        persist_x86_16_tail_validation_snapshot(
            function_info=snapshot_function_info,
            codegen=self.codegen,
            stage="postprocess",
            validation=validation,
        )
        self.codegen._inertia_flag_cleanup_salvaged_after_discard_8616 = True
        log.warning("Accepted isolated flag cleanup after postprocess discard")
        return True
    except Exception as ex:
        _restore_codegen_cfunc(self.codegen, cfunc_snapshot)
        _restore_codegen_inertia_metadata_8616(self.codegen, metadata_snapshot)
        _invalidate_tail_validation_derived_caches_8616(self.codegen)
        log.debug("Flag cleanup salvage after postprocess discard failed: %s", ex, exc_info=True)
        return False


def _log_discard_validation_debug_8616(
    function: StructuredAstValue,
    validation: dict[str, StructuredAstValue],
    log: StructuredAstValue,
) -> None:
    """Emit the env-gated postprocess validation diagnostic for a discard."""
    delta = validation.get("delta") if isinstance(validation, dict) else None
    log.warning(
        "[postprocess-validation] final function=%#x verdict=%s delta=%s "
        "semantic_failures=%s stack_delta=%s before=%s after=%s "
        "def_use_before=%s def_use_after=%s",
        getattr(function, "addr", -1) if function is not None else -1,
        validation.get("verdict"),
        delta,
        validation.get("semantic_failures"),
        (delta or {}).get("stack_writes"),
        (validation.get("before") or {}).get("stack_writes"),
        (validation.get("after") or {}).get("stack_writes"),
        (validation.get("before") or {}).get("def_use_issues"),
        (validation.get("after") or {}).get("def_use_issues"),
    )


@dataclass
class _DiscardSalvageResult8616:
    """Salvage outcomes collected while rebuilding the pre-postprocess C."""

    direct_stack_updates: bool = False
    direct_global_updates: bool = False
    signed_idiv: bool = False
    direct_stack_moves: bool = False
    callsite_args: bool = False


def _collect_discard_salvages_8616(
    self: StructuredAstValue,
    *,
    validation_mode: str,
    snapshot_function_info: StructuredAstValue,
    destructive_discard_delta: bool,
    destructive_salvage_family: StructuredAstValue,
    function: StructuredAstValue,
    log: StructuredAstValue,
) -> _DiscardSalvageResult8616:
    """Run the bounded salvage passes allowed after a postprocess discard."""
    salvages = _DiscardSalvageResult8616()
    if self.codegen._inertia_structuring_validation_failed:
        log.warning(
            "Skipped postprocess rollback salvage because Structuring validation already failed"
        )
        return salvages
    if not destructive_discard_delta:
        salvages.direct_stack_updates = _salvage_direct_stack_update_after_discard_8616(
            self,
            validation_mode=validation_mode,
            snapshot_function_info=snapshot_function_info,
            function=function,
            log=log,
        )
        salvages.direct_global_updates = _salvage_direct_global_update_after_discard_8616(
            self,
            validation_mode=validation_mode,
            snapshot_function_info=snapshot_function_info,
            function=function,
            log=log,
        )
        _salvage_segmented_global_materialization_after_discard_8616(
            self,
            validation_mode=validation_mode,
            snapshot_function_info=snapshot_function_info,
            function=function,
            log=log,
        )
        salvages.signed_idiv = _salvage_signed_idiv_stack_move_after_discard_8616(
            self,
            validation_mode=validation_mode,
            snapshot_function_info=snapshot_function_info,
            function=function,
            log=log,
        )
        salvages.direct_stack_moves = _salvage_direct_stack_move_after_discard_8616(
            self,
            validation_mode=validation_mode,
            snapshot_function_info=snapshot_function_info,
            function=function,
            log=log,
        )
        salvages.callsite_args = _salvage_callsite_stack_args_after_discard_8616(
            self,
            validation_mode=validation_mode,
            snapshot_function_info=snapshot_function_info,
            function=function,
            log=log,
        )
        _salvage_flag_cleanup_after_discard_8616(
            self,
            validation_mode=validation_mode,
            snapshot_function_info=snapshot_function_info,
            function=function,
            log=log,
        )
        _salvage_dce_after_discard_8616(
            self,
            validation_mode=validation_mode,
            snapshot_function_info=snapshot_function_info,
            log=log,
        )
        return salvages
    if _postprocess_destructive_salvage_family_allowed_8616(
        destructive_salvage_family,
        _PostprocessDestructiveSalvageFamily8616.DIRECT_STACK_UPDATE,
    ):
        salvages.direct_stack_updates = _salvage_direct_stack_update_after_discard_8616(
            self,
            validation_mode=validation_mode,
            snapshot_function_info=snapshot_function_info,
            function=function,
            log=log,
        )
    else:
        assert destructive_salvage_family is not None
        log.warning(
            "Skipped direct stack update salvage after destructive postprocess validation delta: family=%s",
            destructive_salvage_family.value,
        )
    if _postprocess_destructive_salvage_family_allowed_8616(
        destructive_salvage_family,
        _PostprocessDestructiveSalvageFamily8616.DIRECT_STACK_MOVE,
    ):
        salvages.signed_idiv = _salvage_signed_idiv_stack_move_after_discard_8616(
            self,
            validation_mode=validation_mode,
            snapshot_function_info=snapshot_function_info,
            function=function,
            log=log,
        )
        salvages.direct_stack_moves = _salvage_direct_stack_move_after_discard_8616(
            self,
            validation_mode=validation_mode,
            snapshot_function_info=snapshot_function_info,
            function=function,
            log=log,
        )
    else:
        assert destructive_salvage_family is not None
        log.warning(
            "Skipped direct stack move salvage after destructive postprocess validation delta: family=%s",
            destructive_salvage_family.value,
        )
    _salvage_dce_after_discard_8616(
        self,
        validation_mode=validation_mode,
        snapshot_function_info=snapshot_function_info,
        log=log,
    )
    log.warning("Skipped unsafe rollback salvage after destructive postprocess validation delta")
    return salvages


def _apply_destructive_discard_identity_gate_8616(
    self: StructuredAstValue,
    restored_validation: dict[str, StructuredAstValue],
    destructive_discard_delta: bool,
) -> None:
    """Require a final-C identity proof when the discard delta was destructive."""
    if not destructive_discard_delta:
        return
    if x86_16_tail_validation_result_passed(restored_validation):
        self.codegen._inertia_postprocess_final_c_identity_proven_8616 = True
        restored_validation["destructive_discard_identity_proven"] = True
    elif not bool(getattr(self.codegen, "_inertia_postprocess_final_c_identity_proven_8616", False)):
        restored_validation["changed"] = True
        restored_validation["status"] = "changed"
        restored_validation["summary_text"] = "destructive postprocess rollback requires final C identity proof"
        restored_validation["destructive_discard_requires_identity_proof"] = True


def _accept_salvaged_restored_validation_8616(
    restored_validation: dict[str, StructuredAstValue],
    salvage_key: str,
) -> None:
    """Mark a salvaged restored validation as semantically stable."""
    restored_validation["changed"] = False
    restored_validation["status"] = "stable"
    restored_validation["summary_text"] = "no observable whole-tail changes"
    restored_validation.pop("delta", None)
    restored_validation[salvage_key] = True


def _discard_failed_postprocess_result_8616(
    self: StructuredAstValue,
    *,
    validation: dict[str, StructuredAstValue],
    validation_verdict_text: str,
    validation_mode: str,
    snapshot_function_info: StructuredAstValue,
    before_fingerprint: StructuredAstValue,
    before_summary: StructuredAstValue,
    pre_postprocess_cfunc_snapshot: StructuredAstValue | None,
    pre_postprocess_metadata_snapshot: StructuredAstValue,
    validation_timings: StructuredAstValue,
    function: StructuredAstValue,
    log: StructuredAstValue,
) -> None:
    if os.environ.get("INERTIA_DEBUG_POSTPROCESS_VALIDATION"):
        _log_discard_validation_debug_8616(function, validation, log)
    if pre_postprocess_cfunc_snapshot is None:
        self.codegen._inertia_postprocess_discard_failed_no_snapshot = True
        log.error(
            "Postprocess validation changed but no pre-postprocess snapshot is available; cannot discard changed C: %s "
            "(last_pass=%s failure_pass=%s)",
            validation["verdict"],
            getattr(self.codegen, "_inertia_last_postprocess_pass", None),
            getattr(self.codegen, "_inertia_postprocess_validation_failure_pass", None),
        )
        return
    log.warning(
        "Postprocess validation changed — discarding postprocessed C, emitting pre-postprocess C: %s "
        "(last_pass=%s failure_pass=%s)",
        validation["verdict"],
        getattr(self.codegen, "_inertia_last_postprocess_pass", None),
        getattr(self.codegen, "_inertia_postprocess_validation_failure_pass", None),
    )
    dump_path = os.environ.get("INERTIA_DEBUG_POSTPROCESS_DISCARD_TEXT_FILE")
    if dump_path:
        with contextlib.suppress(Exception):
            _regenerate_text_safely(self.codegen, context="postprocess:discard-debug-dump")
            with open(dump_path, "w", encoding="utf-8") as fp:
                fp.write(getattr(self.codegen, "text", "") or "")
    destructive_discard_delta = _validation_delta_removes_stack_or_control_effects_8616(validation)
    destructive_salvage_family = _postprocess_destructive_salvage_family_for_pass_8616(
        _postprocess_validation_failed_pass_name_8616(self.codegen)
    )
    _restore_codegen_cfunc(self.codegen, pre_postprocess_cfunc_snapshot)
    _restore_codegen_inertia_metadata_8616(self.codegen, pre_postprocess_metadata_snapshot)
    self.codegen._inertia_postprocess_destructive_discard_recovery_8616 = destructive_discard_delta
    _invalidate_tail_validation_derived_caches_8616(self.codegen)
    _regenerate_text_safely(self.codegen, context="postprocess:discard-restore-baseline")
    salvages = _collect_discard_salvages_8616(
        self,
        validation_mode=validation_mode,
        snapshot_function_info=snapshot_function_info,
        destructive_discard_delta=destructive_discard_delta,
        destructive_salvage_family=destructive_salvage_family,
        function=function,
        log=log,
    )
    self.codegen._inertia_postprocess_discarded = True
    self.codegen._inertia_postprocess_discard_verdict = validation_verdict_text
    restored_after_summary = _collect_tail_validation_summary_with_baseline_canonicalization_8616(
        self.project,
        self.codegen,
        mode=validation_mode,
        force_baseline_canonicalization=True,
    )
    # Rollback validation must use the freshly collected summaries. The
    # comparison cache is keyed by boundary fingerprints, and this path exists
    # specifically because a rejected postprocess result polluted the live AST;
    # reusing a stale changed comparison here would make a successful restore
    # still look failed.
    restored_validation = {
        **compare_x86_16_tail_validation_summaries(before_summary, restored_after_summary),
        "mode": validation_mode,
    }
    restored_validation["timings"] = validation_timings
    _apply_destructive_discard_identity_gate_8616(self, restored_validation, destructive_discard_delta)
    salvage_overrides = (
        (
            "direct_stack_global_update_salvage_after_discard",
            salvages.direct_stack_updates
            and salvages.direct_global_updates
            and _is_direct_stack_and_global_update_materialization_delta_8616(
                self.codegen,
                restored_validation,
            ),
        ),
        (
            "signed_idiv_salvage_after_discard",
            salvages.signed_idiv
            and _is_direct_stack_move_idiv_remainder_materialization_delta_8616(
                self.codegen,
                restored_validation,
            ),
        ),
        (
            "direct_stack_update_salvage_after_discard",
            salvages.direct_stack_updates
            and _is_direct_stack_update_materialization_delta_8616(
                self.codegen,
                restored_validation,
            ),
        ),
        (
            "direct_global_update_salvage_after_discard",
            salvages.direct_global_updates
            and _is_direct_global_update_materialization_delta_8616(
                self.codegen,
                restored_validation,
            ),
        ),
        (
            "direct_stack_move_salvage_after_discard",
            salvages.direct_stack_moves
            and (
                _is_direct_stack_move_materialization_delta_8616(
                    self.codegen,
                    restored_validation,
                )
                or _is_jcc_condition_materialization_validation_delta_8616(
                    self.project,
                    self.codegen,
                    restored_validation,
                    function=function,
                )
            ),
        ),
        (
            "callsite_arg_salvage_after_discard",
            not destructive_discard_delta
            and salvages.callsite_args
            and _is_callsite_stack_argument_materialization_delta_8616(
                self.codegen,
                restored_validation,
            ),
        ),
    )
    for salvage_key, accepted in salvage_overrides:
        if accepted:
            _accept_salvaged_restored_validation_8616(restored_validation, salvage_key)
    restored_validation["verdict"] = build_x86_16_tail_validation_verdict("postprocess", restored_validation)
    persist_x86_16_tail_validation_snapshot(
        function_info=snapshot_function_info,
        codegen=self.codegen,
        stage="postprocess",
        validation=restored_validation,
    )
    if x86_16_tail_validation_result_passed(restored_validation):
        self.codegen._inertia_postprocess_validation_failed = False
        self.codegen._inertia_postprocess_validation_failure_pass = None
        self.codegen._inertia_postprocess_validation_failure_error = None
    snapshot = getattr(self.codegen, "_inertia_tail_validation_snapshot", None)
    if isinstance(snapshot, dict):
        self.project._inertia_last_tail_validation_snapshot = dict(snapshot)
    self.codegen._inertia_postprocess_destructive_discard_recovery_8616 = False
    log.info("%s", restored_validation["verdict"])


def _decompiler_wrapper_chain_contains_8616(root: StructuredAstValue, wrapper_name: str) -> bool:
    """Return whether a dynamic angr decompiler wrapper is already in the call chain."""
    seen: set[int] = set()
    current = root
    while callable(current) and id(current) not in seen:
        seen.add(id(current))
        if getattr(current, "__name__", "") == wrapper_name:
            return True
        current = getattr(current, "_orig_decompiler_decompile", None)
    return False


def apply_x86_16_decompiler_postprocess() -> None:
    """Install the x86-16 decompiler postprocess wrapper once per process."""
    if _decompiler_wrapper_chain_contains_8616(Decompiler._decompile, "_decompile_8616"):
        return
    cast(Any, _decompile_8616)._orig_decompiler_decompile = Decompiler._decompile
    Decompiler._decompile = _decompile_8616
