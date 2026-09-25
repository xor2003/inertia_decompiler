"""Decompiler structuring stage wiring for the 16-bit pipeline.

Layer: Structuring.
Responsibility: sequence structuring-owned CFG, condition, and AST materialization passes.
Dynamic boundary: this module wraps angr decompiler and codegen compatibility objects; owned
Inertia contracts still use typed dot-access objects in their owning layers.
"""

from __future__ import annotations

import contextlib
import logging
import os
import sys
import time
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, MutableMapping
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, cast

from angr.analyses.decompiler.decompiler import Decompiler
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CExpression,
    CFunctionCall,
    CIfElse,
    CStatements,
    CTypeCast,
    CUnaryOp,
)
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeShort

from inertia_decompiler.cli_access_profiles import build_access_trait_evidence_profiles, infer_induction_summary
from inertia_decompiler.runtime_support import timing_output_enabled
from inertia_decompiler.telemetry import annotate_current_span, span

from . import confidence_and_assumptions as _confidence
from . import decompiler_postprocess_simplify as _simplify
from . import function_interface_surface as _interface_surface
from . import ir_confidence_markers as _ir_confidence
from . import segment_function_summary as _segment_function_summary
from . import segmented_memory_reasoning as _segmented_mem
from . import string_codegen_override as _string_codegen_override
from . import string_instruction_artifact as _string_instruction_artifact
from . import string_instruction_lowering as _string_instruction_lowering
from . import structuring_cfg_ownership as _cfg_ownership
from . import structuring_codegen as _codegen
from . import structuring_cross_entry as _cross_entry
from . import structuring_diagnostics as _diagnostics
from . import structuring_grouped_pass as _grouped_structuring
from . import type_array_matching as _array_match
from . import type_equivalence_classes as _type_equiv
from . import type_structure_merging as _struct_merge
from .alias import indexed_address_projection as _indexed_address_aliases
from .alias import segment_stack_restore as _segment_stack_restore
from .alias import stack_memory_ssa as _stack_memory_ssa
from .c_ast_utils import (
    _c_ast_cycle_path_8616,
    _iter_c_nodes_deep_8616,
    _same_c_expression_8616,
)
from .callsite_summary import CallerReturnUseVerdict8616
from .condition_trace import record_ast_condition_trace_8616
from .ir import indexed_address_pipeline as _indexed_address_ir
from .ir import segment_contract as _segment_contract
from .ir import segment_state as _segment_state
from .ir import string_effects as _string_effects
from .ir import vex_import as _vex_ir
from .ir.condition_ir import ConditionIR
from .ir.core import AddressStatus, IRAddress, IRValue
from .lowering.call_argument_carrier_liveness import (
    call_argument_requires_typed_rematerialization_8616,
    call_argument_setup_is_proven_dead_8616,
)
from .lowering.call_cleanup_carriers import (
    prune_consumed_call_cleanup_carriers_8616,
)
from .lowering.call_return_frame_arguments import prune_exact_call_return_frame_arguments_8616
from .lowering.call_return_selectors import replay_call_return_switch_selectors_8616
from .lowering.callee_pointer_evidence import (
    callee_pointer_argument_is_proven_8616,
)
from .lowering.callee_saved_frame import CalleeSavedFramePruneRecord8616
from .lowering.callsite_prototype_declarations import (
    canonicalize_callsite_target_identities_8616,
)
from .lowering.callsite_segment_provenance import attach_callsite_segment_address_provenance_8616
from .lowering.carry_borrow_bit_values import lower_carry_borrow_bit_values_8616
from .lowering.condition_argument_type_facts import (
    proven_recorded_wide_condition_stack_pair_8616,
    record_wide_condition_argument_type_evidence_8616,
)
from .lowering.condition_scalar_types import apply_condition_scalar_types_8616
from .lowering.condition_transfer import transfer_typed_conditions_to_codegen_8616
from .lowering.dead_register_carriers import prune_unread_stack_lowered_register_carriers_8616
from .lowering.direct_stack_replay import (
    DirectStackReplayGeneration8616,
    advance_direct_stack_consumer_generation_8616,
    begin_direct_stack_consumer_generation_scope_8616,
    direct_stack_replay_scheduling_generation_8616,
    end_direct_stack_consumer_generation_scope_8616,
)
from .lowering.explicit_char_types import materialize_explicit_scalar_char_types_8616
from .lowering.fact_transfer import transfer_semantic_alias_facts_to_codegen_8616
from .lowering.far_return_boundary_carriers import (
    consume_terminal_far_return_boundary_carriers_8616,
)
from .lowering.gp_register_state import lower_architectural_gp_register_state_8616
from .lowering.indexed_address_collector_parity import (
    collect_indexed_address_collector_parity_8616,
)
from .lowering.indexed_global_evidence import IndexedSegmentedGlobalEvidence8616
from .lowering.pointer_memory_idioms import (
    PointerMemoryIdiomCallbacks8616,
    PointerMemoryIdiomMaterializationFact8616,
    PointerSwapSpliceStats8616,
    materialize_pointer_memory_idioms_from_evidence_8616,
    pointer_memory_loop_validation_delta_is_precision_only_8616,
    pointer_swap_validation_delta_is_precision_only_8616,
    splice_proven_pointer_swap_statements_8616,
)
from .lowering.positive_bp_arguments import materialize_positive_bp_arguments_8616
from .lowering.real_mode_linear import (
    DirectStackMoveFact8616,
    DirectStackMoveSourceKind8616,
    lower_stable_ss_linear_stack_dereferences_8616,
    materialize_direct_global_incdec_instructions_8616,
    materialize_direct_stack_incdec_instructions_8616,
    materialize_direct_stack_mov_instructions_8616,
    materialize_proven_control_stack_escape_8616,
    prune_callee_saved_stack_spills_8616,
    prune_frame_prologue_stack_assignments_8616,
    prune_materialized_call_push_stack_assignments_8616,
)
from .lowering.register_indirect_call_targets import materialize_register_indirect_call_target_types_8616
from .lowering.register_local_declarations import (
    materialize_typed_register_locals_8616 as finalize_typed_register_locals_8616,
)
from .lowering.return_liveness_replay import replay_return_liveness_lowering_8616
from .lowering.return_type_evidence import proven_function_result_observation_8616
from .lowering.segment_global_materialization import (
    cod_metadata_for_codegen_8616,
    run_segment_global_materialization_8616,
)
from .lowering.segment_stack_restore_carriers import prune_proven_segment_stack_restore_carriers_8616
from .lowering.segmented_global_loads import (
    DwordGlobalZeroTestMaterializationRecord8616,
    IndexedGlobalReadCarrierMaterializationRecord8616,
    IndexedSegmentedGlobalMaterializationRecord8616,
)
from .lowering.segmented_memory_lowering import (
    apply_runtime_segment_lowering_8616,
    lower_runtime_ss_segment_helpers_to_stack_8616,
    runtime_segment_push_source_cvar_8616,
)
from .lowering.signed_global_declarations import materialize_signed_global_declarations_8616
from .lowering.software_interrupt_calls import materialize_software_interrupt_calls_8616
from .lowering.software_interrupt_status_outputs import (
    materialize_software_interrupt_status_outputs_8616,
)
from .lowering.stack_lowering_from_facts import lower_stack_accesses_from_alias_facts_8616
from .lowering.stack_memory_ssa import lower_x86_16_stack_memory_ssa_alias_artifact
from .lowering.stack_probe_callsite_lowering import replay_fixed_stack_probe_callsite_artifacts_8616
from .lowering.stack_prototype_materialization import (
    materialize_annotated_stack_prototype_8616,
    reconcile_callsite_interface_declarations_8616,
)
from .lowering.structured_intrinsics import (
    lower_structured_insert_intrinsics_8616,
    prune_unused_structured_insert_intrinsics_8616,
)
from .lowering.terminal_call_return_types import (
    CalleeResultContract8616 as TerminalCallResultContract8616,
)
from .lowering.terminal_call_return_types import (
    apply_terminal_call_return_type_evidence_8616,
    callee_result_contract_8616,
)
from .lowering.terminal_return_render_projection import (
    project_terminal_return_renderability_8616,
)
from .lowering.unobserved_call_results import lower_unobserved_call_result_assignments_8616
from .lowering.unobserved_returns import neutralize_unobserved_unresolved_returns_8616
from .lowering.wide_call_output_assignments import lower_wide_call_output_stack_assignments_8616
from .lowering.wide_stack_pair_evidence import proven_wide_stack_ir_pair_8616
from .pipeline.errors import PipelineHardError
from .pipeline.render_authority import mark_cfunction_ast_render_authority_8616
from .semantics.call_stack_effect_pipeline import apply_x86_16_call_stack_effects_8616
from .structuring import condition_materialization as _structuring_conditions
from .structuring import condition_refresh as _condition_refresh
from .structuring import terminal_register_values as _terminal_register_values
from .structuring.boolean_condition_ites import normalize_boolean_condition_ites_8616
from .structuring.branch_return_expressions import (
    recover_branch_target_return_expression_8616,
)
from .structuring.call_argument_joins import materialize_call_argument_joins_8616
from .structuring.call_return_conditions import materialize_call_return_conditions_8616
from .structuring.canonical_for_loops import recover_canonical_for_loops_8616
from .structuring.condition_lowering import lower_ir_value_to_c_expr_8616
from .structuring.condition_provenance import (
    replay_codegen_structured_condition_segment_provenance_8616,
)
from .structuring.direct_stack_move_branches import (
    finalize_direct_stack_move_branch_ownership_8616,
    materialize_direct_stack_move_branch_ownership_8616,
    place_direct_stack_move_assignment_8616,
)
from .structuring.direct_stack_move_linear_prefixes import (
    place_direct_stack_move_linear_prefix_assignment_8616,
)
from .structuring.direct_stack_move_loop_entries import (
    materialize_direct_stack_move_loop_entry_ownership_8616,
    place_direct_stack_move_loop_entry_assignment_8616,
)
from .structuring.direct_stack_move_loop_tail_replay import (
    materialize_direct_stack_move_loop_tail_ownership_8616,
)
from .structuring.direct_stack_move_loops import (
    place_direct_stack_move_loop_tail_assignment_8616,
)
from .structuring.guard_decisions import (
    VoidTailCallGuardDecision8616 as _VoidTailCallGuardDecision8616,
)
from .structuring.identical_return_guards import (
    collapse_pure_identical_return_guards_8616,
)
from .structuring.loop_body_repair import (
    prune_redundant_loop_break_carriers_8616,
    repair_conditional_continue_guards_from_evidence_8616,
    repair_hoisted_jcc_target_copies_from_evidence_8616,
    repair_pretest_loop_break_guards_from_evidence_8616,
    repair_switch_loop_exit_returns_from_evidence_8616,
    repair_synthetic_internal_calls_from_evidence_8616,
)
from .structuring.loop_break_jcc import (
    loop_branch_guard_facts_8616,
    loop_header_duplicate_guard_removal_facts_8616,
)
from .structuring.loop_carried_terminal_returns import materialize_loop_carried_terminal_return_8616
from .structuring.loop_exit_return_guards import (
    default_loop_exit_return_guard_callbacks_8616,
    repair_loop_exit_return_guards_8616,
)
from .structuring.pass_effects import (
    StructuringLoweringReplayImpact8616,
    structuring_lowering_replay_impact_after_changes_8616,
    structuring_return_closure_requires_segment_replay_8616,
)
from .structuring.return_chain_integrity import (
    install_materialized_return_chain_integrity_guard_8616,
    require_materialized_return_chain_integrity_8616,
)
from .structuring.return_chains import (
    TerminalCallResultReturnCallbacks8616,
    TerminalCallResultReturnStatus8616,
    collapse_surplus_identical_assignment_arms_8616,
    materialize_terminal_call_result_return_8616,
)
from .structuring.shared_call_occurrence_finalization import finalize_shared_call_occurrences_8616
from .structuring.software_interrupt_returns import (
    materialize_software_interrupt_terminal_results_8616,
)
from .structuring.stored_call_return_early_exit import materialize_stored_call_return_early_exit_8616
from .structuring.switch_loop_tail_breaks import (
    SwitchLoopTailBreakResult8616,
    materialize_switch_loop_tail_breaks_8616,
)
from .structuring.tagged_terminal_return_values import (
    materialize_tagged_terminal_return_values_8616,
)
from .structuring.wide_stack_return_predicates import (
    materialize_wide_stack_return_predicate_8616,
    wide_stack_return_predicate_validation_delta_is_proven_8616,
)
from .tail_validation import (
    X86_16TailValidationSummary,
    build_x86_16_tail_validation_cached_result,
    build_x86_16_tail_validation_verdict,
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
    dword_global_zero_test_precision_delta_8616,
    fingerprint_x86_16_tail_validation_boundary,
    format_x86_16_tail_validation_diff,
    indexed_global_read_carrier_precision_delta_8616,
    indexed_segmented_global_precision_delta_8616,
    loop_exit_return_guard_repair_delta_8616,
    loop_header_duplicate_guard_removal_delta_8616,
    persist_x86_16_tail_validation_snapshot,
    x86_16_tail_validation_result_passed,
)
from .tail_validation_frame_spills import callee_saved_frame_prune_delta_8616
from .validation.callsite_completeness import (
    TailValidationCallsiteSummary8616,
    classify_callsite_completeness_delta_8616,
)
from .validation_condition_closure_delta import validate_condition_closure_delta_8616
from .validation_condition_precision import condition_precision_validation_delta_8616
from .validation_identical_return_guards import (
    consume_identical_return_guard_validation_delta_8616,
)
from .validation_semantic_failures import TailSemanticFailureScope8616
from .validation_switch_loop_tail_breaks import (
    consume_switch_loop_tail_break_validation_delta_8616,
)
from .validation_terminal_returns import terminal_return_value_validation_delta_8616
from .widening.carry_borrow_pipeline import apply_carry_borrow_widening_pipeline_8616
from .widening.segmented_load_widening import apply_segmented_load_widening_8616
from .widening.stack_memory_objects import apply_x86_16_stack_memory_object_widening_8616
from .widening.stack_subview_projection import materialize_contained_stack_subviews_8616
from .widening.widening_copyprop_8616 import _widening_copy_propagation_8616
from .widening.word_projection_recomposition import materialize_word_projection_recompositions_8616

# angr project/codegen objects are plugin surfaces whose compatibility
# metadata is attached dynamically across angr versions. Keep that boundary
# explicit here; owned Inertia facts passed through it remain typed contracts.


class _GuardedDceResult8616(Protocol):
    """Minimal result contract returned by the CLI guarded-DCE callback."""

    changed: bool
type AngrProjectSurface = Any
type AngrCodegenSurface = Any
type AngrDecompilerSurface = Any
type AngrConditionProcessorSurface = Any
type ClaripyConditionSurface = Any
type AngrCFuncNodeSurface = Any

__all__ = [
    "DECOMPILER_STRUCTURING_PASSES",
    "DecompilerStructuringPassSpec",
    "DirectInstructionMaterializationResult8616",
    "LateTypedSwitchReplacementFinalizeResult8616",
    "SeqNodeSwitchReplayFinalizeResult8616",
    "_build_decompiler_structuring_passes",
    "active_structuring_function_8616",
    "apply_typed_edge_switch_ast_replacement_if_enabled_8616",
    "apply_x86_16_decompiler_structuring",
    "describe_x86_16_decompiler_structuring_stage",
    "finalize_seqnode_switch_replay_after_replacement_8616",
    "finalize_shared_call_occurrences_8616",
    "finalize_typed_edge_switch_replacement_if_enabled_8616",
    "prepare_typed_edge_switch_artifacts_8616",
    "prune_redundant_loop_break_carriers_after_lowering_8616",
    "record_typed_edge_switch_replacement_diagnostics_8616",
    "recover_structuring_canonical_for_loops_8616",
    "replay_seqnode_switch_condition_materialization_after_replacement_8616",
    "replay_seqnode_switch_segment_lowering_after_replacement_8616",
    "replay_typed_edge_switch_segment_lowering_after_replacement_8616",
    "run_direct_instruction_materialization_8616",
    "run_structuring_condition_cleanup_8616",
    "seqnode_switch_replacement_changed_for_codegen_8616",
    "typed_edge_switch_ast_replacement_changed_for_codegen_8616",
]


@dataclass(frozen=True, slots=True)
class DecompilerStructuringPassSpec:
    """Configuration for a single decompiler structuring pass."""

    name: str
    func: Callable[..., bool]
    needs_project: bool
    lowering_replay_impact: StructuringLoweringReplayImpact8616 = (
        StructuringLoweringReplayImpact8616.FULL_AST
    )


@dataclass(frozen=True, slots=True)
class LateTypedSwitchReplacementFinalizeResult8616:
    """Result of late typed-switch AST replacement finalization."""

    replacement_changed: bool
    segment_replay_changed: bool

    @property
    def changed(self) -> bool:
        """Return True when replacement or replay changed the C AST."""
        return self.replacement_changed or self.segment_replay_changed


@dataclass(frozen=True, slots=True)
class SeqNodeSwitchReplayFinalizeResult8616:
    """Result of late SeqNode switch replay finalization."""

    segment_replay_changed: bool
    segment_dce_changed: bool
    post_dce_segment_replay_changed: bool
    post_dce_segment_dce_changed: bool
    condition_replay_changed: bool
    condition_dce_changed: bool
    post_condition_segment_replay_changed: bool
    post_condition_segment_dce_changed: bool
    word_projection_replay_changed: bool
    word_projection_dce_changed: bool
    selector_replay_changed: bool

    @property
    def changed(self) -> bool:
        """Return True when replay or its guarded DCE callback changed the C AST."""
        return bool(
            self.segment_replay_changed
            or self.segment_dce_changed
            or self.post_dce_segment_replay_changed
            or self.post_dce_segment_dce_changed
            or self.condition_replay_changed
            or self.condition_dce_changed
            or self.post_condition_segment_replay_changed
            or self.post_condition_segment_dce_changed
            or self.word_projection_replay_changed
            or self.word_projection_dce_changed
            or self.selector_replay_changed
        )


@dataclass(frozen=True, slots=True)
class DirectInstructionMaterializationResult8616:
    """Result of direct stack/global instruction materialization sequencing."""

    direct_stack_mov_changed: bool
    direct_stack_incdec_changed: bool
    direct_global_incdec_changed: bool
    callee_saved_spill_prune_changed: bool
    control_stack_escape_changed: bool

    @property
    def changed(self) -> bool:
        """Return True when any direct instruction materializer changed the C AST."""
        return (
            self.direct_stack_mov_changed
            or self.direct_stack_incdec_changed
            or self.direct_global_incdec_changed
            or self.callee_saved_spill_prune_changed
            or self.control_stack_escape_changed
        )


class StructuringPassValidationSkipReason8616(Enum):
    """Evidence-based reasons for skipping expensive per-pass validation."""

    LARGE_FUNCTION_BLOCK_COUNT = "large_function_block_count"
    LARGE_FUNCTION_BYTE_SIZE = "large_function_byte_size"


_STRUCTURING_PASS_VALIDATION_LARGE_BLOCK_THRESHOLD_8616 = 40
_STRUCTURING_PASS_VALIDATION_LARGE_BYTE_THRESHOLD_8616 = 0x160


def _install_function_interface_surface_reporting_only_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> bool:
    """Install render-time interface comments without marking structuring changed.

    The interface surface wraps ``render_text`` to prepend comments from
    already-recovered function-state facts.  That is reporting metadata, not an
    AST or semantic structuring mutation, so the structuring runner must not
    treat successful installation as ``last_pass`` evidence.
    """
    _interface_surface.apply_x86_16_function_interface_surface(project, codegen)
    return False


def _run_structuring_widening_copy_propagation_8616(codegen: AngrCodegenSurface) -> bool:
    """Consume alias-proven copies before structuring interprets conditions."""
    subviews_changed = materialize_contained_stack_subviews_8616(codegen)
    copies_changed = _widening_copy_propagation_8616(codegen, enable_nested=True)
    return bool(subviews_changed or copies_changed)


def _run_structuring_codegen_with_lowering_replay_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
) -> bool:
    """Regenerate C and replay every proof consumer invalidated by this rebuild."""
    regenerated = bool(_codegen.apply_structuring_codegen_8616(codegen))
    changed = regenerated
    if regenerated:
        changed = bool(_apply_structuring_direct_stack_materialization_8616(project, codegen)) or changed
        changed = bool(_prime_structuring_segment_global_semantics_8616(project, codegen)) or changed
    changed = bool(_replay_materialized_call_stack_metadata_8616(project, codegen)) or changed
    if regenerated:
        condition_refresh = _condition_refresh.refresh_structuring_condition_semantics_8616(
            project,
            codegen,
        )
        if condition_refresh.requires_broad_lowering_replay:
            raise PipelineHardError("typed condition refresh remained unclosed after structuring codegen")
        changed = condition_refresh.changed or changed
    return bool(prune_unread_stack_lowered_register_carriers_8616(codegen)) or changed


def _build_decompiler_structuring_passes() -> tuple[DecompilerStructuringPassSpec, ...]:
    """Build the deterministic core pass sequence for 16-bit structuring."""
    return (
        DecompilerStructuringPassSpec(
            "_cross_entry_cfg_grouping_8616",
            _cross_entry.apply_x86_16_cross_entry_grouping,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_condition_evidence_transfer_8616",
            _condition_evidence_transfer_8616,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_region_based_structuring_8616",
            _grouped_structuring.apply_grouped_region_based_structuring,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_simplify_structured_expressions_8616",
            _simplify._simplify_structured_expressions_8616,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_induction_summary_artifact_8616",
            _induction_summary_artifact_8616,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_structuring_codegen_8616",
            _run_structuring_codegen_with_lowering_replay_8616,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_loop_exit_return_guard_repair_8616",
            _repair_structuring_loop_exit_return_guards_8616,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_unconsumed_loop_break_jcc_materialization_8616",
            _materialize_structuring_unconsumed_loop_break_jcc_8616,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_conditional_continue_guard_repair_8616",
            _repair_structuring_conditional_continue_guards_8616,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_pretest_loop_break_guard_repair_8616",
            _repair_structuring_pretest_loop_break_guards_8616,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_canonical_for_loop_recovery_8616",
            recover_structuring_canonical_for_loops_8616,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_hoisted_jcc_target_copy_repair_8616",
            _repair_structuring_hoisted_jcc_target_copies_8616,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_switch_loop_exit_return_repair_8616",
            _repair_structuring_switch_loop_exit_returns_8616,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_switch_loop_tail_break_collapse_8616",
            _collapse_structuring_switch_loop_tail_breaks_8616,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_void_tail_call_guard_repair_8616",
            _materialize_structuring_void_tail_call_guard_8616,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_vex_ir_artifact_8616",
            _vex_ir.apply_x86_16_vex_ir_artifact,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_indexed_address_ir_evidence_8616",
            _indexed_address_ir.apply_x86_16_indexed_address_evidence_8616,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_call_stack_effect_semantics_8616",
            apply_x86_16_call_stack_effects_8616,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_indexed_address_alias_evidence_8616",
            _indexed_address_aliases.apply_x86_16_indexed_address_aliases_8616,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_stack_memory_ssa_alias_artifact_8616",
            _stack_memory_ssa.apply_x86_16_stack_memory_ssa_alias_artifact,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_carry_borrow_widening_artifact_8616", apply_carry_borrow_widening_pipeline_8616, True
        ),
        DecompilerStructuringPassSpec(
            "_stack_memory_object_widening_artifact", apply_x86_16_stack_memory_object_widening_8616, True
        ),
        DecompilerStructuringPassSpec(
            "_widening_copy_propagation_8616",
            _run_structuring_widening_copy_propagation_8616,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_segment_stack_restore_artifact_8616",
            _segment_stack_restore.apply_x86_16_segment_stack_restore_artifact,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_segment_stack_restore_carriers_8616",
            prune_proven_segment_stack_restore_carriers_8616,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_far_return_boundary_carriers_8616",
            consume_terminal_far_return_boundary_carriers_8616,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_segment_state_artifact_8616",
            _segment_state.apply_x86_16_segment_state_artifact,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_segment_function_contract_8616",
            _segment_contract.apply_x86_16_segment_function_contract,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_segment_function_summary_8616",
            _segment_function_summary.apply_x86_16_segment_function_summary,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_string_instruction_artifact_8616",
            _string_instruction_artifact.apply_x86_16_string_instruction_artifact,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_typed_string_effect_artifact_8616",
            _string_effects.apply_x86_16_typed_string_effect_artifact,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_string_instruction_lowering_8616",
            _string_instruction_lowering.apply_x86_16_string_instruction_lowering,
            True,
        ),
        DecompilerStructuringPassSpec(
            "_string_codegen_override_8616",
            _string_codegen_override.apply_x86_16_string_codegen_override,
            True,
        ),
        # Phase 3: Segmented Memory Association Reasoning
        DecompilerStructuringPassSpec(
            "_segmented_memory_reasoning_8616",
            _segmented_mem.apply_x86_16_segmented_memory_reasoning,
            False,
        ),
        # Phase 2: Type Inference and Recovery
        DecompilerStructuringPassSpec(
            "_type_equivalence_classes_8616",
            _type_equiv.apply_x86_16_type_equivalence_classes,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_array_expression_matching_8616",
            _array_match.apply_x86_16_array_expression_matching,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_structure_field_merging_8616",
            _struct_merge.apply_x86_16_structure_field_merging,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_unobserved_return_lowering_8616",
            neutralize_unobserved_unresolved_returns_8616,
            True,
            StructuringLoweringReplayImpact8616.RETURN_LIVENESS_ONLY,
        ),
        # Phase 4: Robustness & Diagnostics
        DecompilerStructuringPassSpec(
            "_structuring_diagnostics_8616",
            _diagnostics.apply_x86_16_structuring_diagnostics,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_ir_confidence_markers_8616",
            _ir_confidence.apply_x86_16_ir_confidence_markers,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_confidence_and_assumptions_8616",
            _confidence.apply_x86_16_confidence_and_assumptions,
            False,
        ),
        DecompilerStructuringPassSpec(
            "_function_interface_surface_8616",
            _install_function_interface_surface_reporting_only_8616,
            True,
        ),
    )


def _condition_evidence_transfer_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> bool:
    """Collect typed condition and edge evidence before region structuring.

    Region structuring consumes ``ConditionEdgeEvidence`` to recognize
    edge-guard switch cascades.  The collection belongs before structuring; the
    matching condition materialization also belongs here so the production
    order matches tail-validation priming.  Delaying materialization until the
    late refresh lets downstream structuring see a different guard surface from
    the validation baseline.
    """
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if not isinstance(func_addr, int):
        return False
    transferred = 0
    if not getattr(codegen, "_inertia_typed_conditions_transferred", False):
        transferred = int(transfer_typed_conditions_to_codegen_8616(project, func_addr, codegen) or 0)
        codegen._inertia_typed_conditions_transferred = True
    current_root = getattr(codegen.cfunc, "statements", None)
    current_surface = _structuring_conditions.structuring_condition_surface_token_8616(codegen)
    materialization_is_current = bool(
        getattr(codegen, "_inertia_structuring_conditions_materialized_after_transfer_8616", False)
        and getattr(codegen, "_inertia_structuring_conditions_materialized_root_8616", None) is current_root
        and getattr(codegen, "_inertia_structuring_conditions_materialized_surface_8616", None) == current_surface
    )
    materialization_changed = False
    if not materialization_is_current:
        materialization_changed = bool(
            _structuring_conditions.apply_structuring_condition_materialization_8616(project, codegen)
        )
    edge_evidence = getattr(codegen, "_inertia_condition_edge_evidence", None)
    if isinstance(edge_evidence, (list, tuple)) and edge_evidence:
        codegen._inertia_condition_edge_evidence_for_structuring_8616 = tuple(edge_evidence)
    codegen._inertia_condition_evidence_transfer_8616 = {
        "condition_count": transferred,
        "edge_evidence_count": len(edge_evidence) if isinstance(edge_evidence, (list, tuple)) else 0,
        "materialization_changed": materialization_changed,
        "owner": "structuring.condition_evidence_transfer",
    }
    codegen._inertia_structuring_conditions_materialized_after_transfer_8616 = True
    codegen._inertia_structuring_conditions_materialized_root_8616 = current_root
    codegen._inertia_structuring_conditions_materialized_surface_8616 = (
        _structuring_conditions.structuring_condition_surface_token_8616(codegen)
    )
    return materialization_changed


def prepare_typed_edge_switch_artifacts_8616(codegen: AngrCodegenSurface, *, force: bool = False) -> None:
    """Prepare typed switch artifacts for diagnostics or guarded replacement.

    This is structuring orchestration, not semantic recovery: condition
    evidence must already exist on the codegen/project, and grouped
    structuring plus replacement-safety analysis only materialize structured
    facts for later guarded C AST replacement. Replacement orchestration uses
    ``force`` instead of mutating process-global diagnostic configuration.
    """
    if not force and os.environ.get("INERTIA_ENABLE_TYPED_SWITCH_AST_ARTIFACTS") != "1":
        return
    if getattr(codegen, "_inertia_grouped_structuring_stats_8616", None) is not None:
        return
    try:
        edge_evidence = getattr(codegen, "_inertia_condition_edge_evidence", None)
        if not isinstance(edge_evidence, (list, tuple)) or not edge_evidence:
            backup_edge_evidence = getattr(codegen, "_inertia_condition_edge_evidence_for_structuring_8616", None)
            if isinstance(backup_edge_evidence, (list, tuple)) and backup_edge_evidence:
                codegen._inertia_condition_edge_evidence = tuple(backup_edge_evidence)
                edge_evidence = backup_edge_evidence
        if not isinstance(edge_evidence, (list, tuple)) or not edge_evidence:
            project = getattr(codegen, "project", None)
            func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
            if project is not None and isinstance(func_addr, int):
                transfer_typed_conditions_to_codegen_8616(project, func_addr, codegen)
        _grouped_structuring.GroupedRegionBasedStructuringPass()(codegen)
        _codegen.evaluate_typed_edge_switch_replacement_safety_8616(codegen)
    except Exception as ex:
        codegen._inertia_grouped_structuring_error_8616 = {
            "type": type(ex).__name__,
            "message": str(ex),
        }


def _switch_replacement_refusal_8616(
    codegen: AngrCodegenSurface,
    attempted_count: int,
    reason: str,
    refused_count: int,
    extra: dict[str, object] | None = None,
) -> bool:
    """Record a refused typed-switch replacement payload and return False."""
    payload: dict[str, object] = {
        "attempted_count": attempted_count,
        "changed": False,
        "refusal_reasons": (reason,),
        "refused_count": refused_count,
        "replaced_count": 0,
        "owner": "structuring.stage",
    }
    if extra:
        payload.update(extra)
    codegen._inertia_typed_edge_switch_ast_replacement_8616 = payload
    return False


def _commit_validated_switch_replacement_8616(
    project: AngrProjectSurface | None,
    codegen: AngrCodegenSurface,
    root: AngrCFuncNodeSurface,
    original_statements: list[object] | None,
    before_summary: X86_16TailValidationSummary | None,
    result: _codegen.TypedEdgeSwitchAstReplacementResult8616,
) -> bool:
    """Keep a changed switch replacement only when tail validation stays stable."""
    if project is None or root is None or original_statements is None or before_summary is None:
        if (
            root is not None
            and isinstance(getattr(root, "statements", None), list)
            and original_statements is not None
        ):
            root.statements[:] = original_statements
        return _switch_replacement_refusal_8616(
            codegen,
            int(result.attempted_count),
            "tail_validation_unavailable",
            int(result.replaced_count or result.refused_count or 1),
        )
    try:
        after_fingerprint = fingerprint_x86_16_tail_validation_boundary(project, codegen, mode="live_out")
        after_summary = collect_x86_16_tail_validation_summary(
            project,
            codegen,
            mode="live_out",
            boundary_fingerprint=after_fingerprint,
        )
        validation = compare_x86_16_tail_validation_summaries(before_summary, after_summary)
    except Exception as ex:
        root.statements[:] = original_statements
        return _switch_replacement_refusal_8616(
            codegen,
            int(result.attempted_count),
            f"tail_validation_after_failed:{type(ex).__name__}",
            int(result.replaced_count or result.refused_count or 1),
        )
    if bool(validation.get("changed", False)):
        root.statements[:] = original_statements
        return _switch_replacement_refusal_8616(
            codegen,
            int(result.attempted_count),
            "tail_validation_changed",
            int(result.replaced_count or result.refused_count or 1),
            {
                "tail_validation_status": validation.get("status"),
                "tail_validation_summary": format_x86_16_tail_validation_diff(validation),
            },
        )
    replacement_payload = getattr(codegen, "_inertia_typed_edge_switch_ast_replacement_8616", None)
    if isinstance(replacement_payload, dict):
        replacement_payload["tail_validation_status"] = validation.get("status", "stable")
    codegen._inertia_codegen_decl_refresh_required_8616 = True
    codegen._inertia_force_codegen_regeneration_8616 = True
    return True


def apply_typed_edge_switch_ast_replacement_if_enabled_8616(codegen: AngrCodegenSurface) -> bool:
    """Apply typed switch C AST replacement behind opt-in and tail validation.

    The mutation primitive belongs to structuring codegen. This stage-level
    wrapper owns the late opt-in gate and validation-stable rollback boundary
    so CLI fallback orchestration does not need direct imports from the
    structuring implementation.
    """
    if os.environ.get("INERTIA_ENABLE_TYPED_SWITCH_AST_REPLACEMENT") != "1":
        return False
    prepare_typed_edge_switch_artifacts_8616(codegen, force=True)
    project = getattr(codegen, "project", None)
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None) if cfunc is not None else None
    original_statements = None
    before_summary = None
    if project is not None and root is not None and isinstance(getattr(root, "statements", None), list):
        original_statements = list(root.statements)
        try:
            before_fingerprint = fingerprint_x86_16_tail_validation_boundary(project, codegen, mode="live_out")
            before_summary = collect_x86_16_tail_validation_summary(
                project,
                codegen,
                mode="live_out",
                boundary_fingerprint=before_fingerprint,
            )
        except Exception as ex:
            return _switch_replacement_refusal_8616(
                codegen, 0, f"tail_validation_baseline_failed:{type(ex).__name__}", 1
            )
    try:
        result = _codegen.replace_typed_edge_switch_ast_8616(codegen)
    except Exception as ex:
        return _switch_replacement_refusal_8616(codegen, 0, f"{type(ex).__name__}: {ex}", 1)
    if not result.changed:
        return False
    return _commit_validated_switch_replacement_8616(
        project,
        codegen,
        root,
        original_statements,
        before_summary,
        result,
    )


def record_typed_edge_switch_replacement_diagnostics_8616(codegen: AngrCodegenSurface) -> None:
    """Refresh typed-switch diagnostic payloads through the structuring stage."""
    prepare_typed_edge_switch_artifacts_8616(codegen)
    _codegen._record_typed_edge_switch_lowering_status_8616(codegen)
    _codegen.evaluate_typed_edge_switch_replacement_safety_8616(codegen)


def seqnode_switch_replacement_changed_for_codegen_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> bool:
    """Return whether the current C function has a changed SeqNode switch replacement."""
    seqnode_replacements = getattr(project, "_inertia_typed_switch_seqnode_replacement_8616", None)
    current_cfunc_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    return any(
        isinstance(record, dict)
        and bool(record.get("changed", False))
        and (not isinstance(current_cfunc_addr, int) or record.get("function_addr") == current_cfunc_addr)
        for record in (seqnode_replacements if isinstance(seqnode_replacements, list) else ())
    )


def typed_edge_switch_ast_replacement_changed_for_codegen_8616(codegen: AngrCodegenSurface) -> bool:
    """Return whether typed edge-switch C AST replacement changed this codegen."""
    payload = getattr(codegen, "_inertia_typed_edge_switch_ast_replacement_8616", None)
    return isinstance(payload, dict) and bool(payload.get("changed", False))


def _replay_segment_global_lowering_after_switch_replacement_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
    synthetic_globals: object,
    *,
    cod_metadata: object | None = None,
) -> bool:
    """Replay condition provenance before late segment/global lowering."""
    provenance_changed = replay_codegen_structured_condition_segment_provenance_8616(codegen).changed
    lowering_changed = run_segment_global_materialization_8616(
        project,
        codegen,
        synthetic_globals,
        cod_metadata=cod_metadata,
        include_runtime_segment=True,
    ).changed
    return bool(provenance_changed or lowering_changed)


def prune_redundant_loop_break_carriers_after_lowering_8616(codegen: AngrCodegenSurface) -> bool:
    """Prune proven duplicate loop guards after globals have stable identities.

    The implementation remains in Structuring because it changes loop control
    flow. This stage wrapper makes the required Lowering-before-Structuring
    replay order explicit for callers that regenerate an angr C AST late.
    """
    return bool(prune_redundant_loop_break_carriers_8616(codegen))


def _replay_materialized_call_stack_metadata_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
) -> bool:
    """Replay typed PUSH and caller-cleanup consumption after AST rebuilds."""
    changed = bool(
        prune_materialized_call_push_stack_assignments_8616(
            project,
            codegen,
        )
    )
    changed = bool(prune_consumed_call_cleanup_carriers_8616(project, codegen)) or changed
    return bool(prune_unread_stack_lowered_register_carriers_8616(codegen)) or changed


def run_direct_instruction_materialization_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
    *,
    function: object | None = None,
    include_direct_stack_mov: bool = True,
    include_direct_stack_incdec: bool = True,
    include_direct_global_incdec: bool = True,
    allow_stack_slot_fallback: bool = True,
    source_kinds: frozenset[DirectStackMoveSourceKind8616] | None = None,
    materialize_stack_reloads: bool = True,
    include_callee_saved_spill_prune: bool = True,
    enforce_direct_stack_branch_contract: bool = False,
) -> DirectInstructionMaterializationResult8616:
    """Run direct stack/global instruction materializers in stage-owned order."""
    current_function = function if function is not None else _current_structuring_function_8616(project, codegen)
    _bind_direct_stack_move_branch_ownership_8616(
        project,
        codegen,
        current_function,
    )
    callee_saved_spill_prune_changed = bool(
        include_callee_saved_spill_prune
        and prune_callee_saved_stack_spills_8616(
            codegen,
            project,
            function=current_function,
        )
    )
    control_stack_escape_changed = materialize_proven_control_stack_escape_8616(
        codegen,
        project,
        function=current_function,
    )
    direct_stack_mov_changed = False
    if include_direct_stack_mov:
        direct_stack_mov_changed = bool(
            materialize_direct_stack_mov_instructions_8616(
                codegen,
                project=project,
                function=current_function,
                allow_stack_slot_fallback=allow_stack_slot_fallback,
                source_kinds=source_kinds,
                materialize_reloads=materialize_stack_reloads,
            )
        )
    direct_stack_incdec_changed = False
    if include_direct_stack_incdec:
        direct_stack_incdec_changed = bool(
            materialize_direct_stack_incdec_instructions_8616(
                codegen,
                project=project,
                function=current_function,
            )
        )
    direct_global_incdec_changed = False
    if include_direct_global_incdec:
        direct_global_incdec_changed = bool(
            materialize_direct_global_incdec_instructions_8616(
                codegen,
                project=project,
                function=current_function,
            )
        )
        codegen._inertia_direct_global_incdec_materialization_structuring_pass_ran_8616 = True
    if current_function is not None:
        branch_materializer = (
            finalize_direct_stack_move_branch_ownership_8616
            if enforce_direct_stack_branch_contract
            else materialize_direct_stack_move_branch_ownership_8616
        )
        direct_stack_mov_changed = (
            branch_materializer(
                project,
                codegen,
                current_function,
            )
            or direct_stack_mov_changed
        )
        direct_stack_mov_changed = (
            materialize_direct_stack_move_loop_entry_ownership_8616(
                project,
                codegen,
                current_function,
            )
            or direct_stack_mov_changed
        )
    result = DirectInstructionMaterializationResult8616(
        direct_stack_mov_changed=direct_stack_mov_changed,
        direct_stack_incdec_changed=direct_stack_incdec_changed,
        direct_global_incdec_changed=direct_global_incdec_changed,
        callee_saved_spill_prune_changed=callee_saved_spill_prune_changed,
        control_stack_escape_changed=control_stack_escape_changed,
    )
    if result.changed:
        codegen._inertia_direct_instruction_materialization_8616 = {
            "direct_stack_mov_changed": result.direct_stack_mov_changed,
            "direct_stack_incdec_changed": result.direct_stack_incdec_changed,
            "direct_global_incdec_changed": result.direct_global_incdec_changed,
            "callee_saved_spill_prune_changed": result.callee_saved_spill_prune_changed,
            "changed": result.changed,
            "owner": "structuring.stage",
        }
    return result


def replay_typed_edge_switch_segment_lowering_after_replacement_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
    synthetic_globals: object,
    *,
    cod_metadata: object | None = None,
) -> bool:
    """Replay segment/global lowering after typed edge-switch AST replacement."""
    if not typed_edge_switch_ast_replacement_changed_for_codegen_8616(codegen):
        return False
    changed = _replay_segment_global_lowering_after_switch_replacement_8616(
        project,
        codegen,
        synthetic_globals,
        cod_metadata=cod_metadata,
    )
    if changed:
        codegen._inertia_typed_edge_switch_segment_replay_changed_8616 = (
            int(getattr(codegen, "_inertia_typed_edge_switch_segment_replay_changed_8616", 0) or 0) + 1
        )
    return changed


def finalize_typed_edge_switch_replacement_if_enabled_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
    synthetic_globals: object,
    *,
    cod_metadata: object | None = None,
) -> LateTypedSwitchReplacementFinalizeResult8616:
    """Apply late typed-switch replacement and replay stage-owned lowering.

    This finalizes the typed edge-switch replacement lifecycle owned by the
    structuring stage.  It does not decide whether CLI should regenerate or
    preserve rendered text; it only mutates the C AST through stage-owned
    replacement/replay helpers and reports what changed.
    """
    replacement_changed = apply_typed_edge_switch_ast_replacement_if_enabled_8616(codegen)
    segment_replay_changed = False
    if replacement_changed:
        segment_replay_changed = replay_typed_edge_switch_segment_lowering_after_replacement_8616(
            project,
            codegen,
            synthetic_globals,
            cod_metadata=cod_metadata,
        )
    if segment_replay_changed:
        codegen._inertia_codegen_decl_refresh_required_8616 = True
        codegen._inertia_force_codegen_regeneration_8616 = True
    result = LateTypedSwitchReplacementFinalizeResult8616(
        replacement_changed=bool(replacement_changed),
        segment_replay_changed=bool(segment_replay_changed),
    )
    with contextlib.suppress(Exception):
        codegen._inertia_late_typed_switch_finalize_8616 = {
            "replacement_changed": result.replacement_changed,
            "segment_replay_changed": result.segment_replay_changed,
            "changed": result.changed,
            "owner": "structuring.stage",
        }
    return result


def replay_seqnode_switch_segment_lowering_after_replacement_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
    synthetic_globals: object,
    *,
    cod_metadata: object | None = None,
) -> bool:
    """Replay segment/global lowering exposed by late SeqNode switch replacement."""
    if not seqnode_switch_replacement_changed_for_codegen_8616(project, codegen):
        return False
    changed = _replay_segment_global_lowering_after_switch_replacement_8616(
        project,
        codegen,
        synthetic_globals,
        cod_metadata=cod_metadata,
    )
    if changed:
        codegen._inertia_seqnode_switch_segment_replay_changed_8616 = (
            int(getattr(codegen, "_inertia_seqnode_switch_segment_replay_changed_8616", 0) or 0) + 1
        )
    return changed


def replay_seqnode_switch_condition_materialization_after_replacement_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
) -> bool:
    """Replay proven condition materialization for late SeqNode switch bodies.

    The structuring stage owns the SeqNode-replacement gate and typed condition
    transfer/materialization.  Late flag-expression cleanup is delegated
    through the structuring condition facade so CLI keeps only the call-loss
    guarded DCE policy.
    """
    if not seqnode_switch_replacement_changed_for_codegen_8616(project, codegen):
        return False
    changed = False
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if isinstance(func_addr, int):
        transfer_typed_conditions_to_codegen_8616(project, func_addr, codegen)
    changed |= bool(_structuring_conditions.apply_structuring_condition_replay_cleanup_8616(project, codegen))
    if changed:
        codegen._inertia_seqnode_switch_condition_replay_changed_8616 = (
            int(getattr(codegen, "_inertia_seqnode_switch_condition_replay_changed_8616", 0) or 0) + 1
        )
    return changed


def _dce_result_changed_8616(result: object) -> bool:
    """Read the CLI-owned guarded-DCE callback result without importing CLI types."""
    typed_result = cast(_GuardedDceResult8616, result)
    try:
        return bool(typed_result.changed)
    except AttributeError as exc:
        raise TypeError("guarded-DCE callback must return an object with a boolean changed field") from exc


def finalize_seqnode_switch_replay_after_replacement_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
    synthetic_globals: object,
    guarded_dce_runner: Callable[[str], object],
    *,
    cod_metadata: object | None = None,
) -> SeqNodeSwitchReplayFinalizeResult8616:
    """Finalize SeqNode switch replay sequencing after late AST replacement.

    The structuring stage owns replay order for segment/global lowering,
    condition materialization, Widening projection folding, and the existing
    Types/Lowering selector identity owner. The supplied DCE callback remains
    CLI-owned because it raises pipeline hard errors with function-context
    policy when a replay-triggered cleanup would lose call expressions.
    """
    segment_replay_changed = replay_seqnode_switch_segment_lowering_after_replacement_8616(
        project,
        codegen,
        synthetic_globals,
        cod_metadata=cod_metadata,
    )
    segment_dce_changed = False
    post_dce_segment_replay_changed = False
    post_dce_segment_dce_changed = False
    if segment_replay_changed:
        segment_dce_changed = _dce_result_changed_8616(
            guarded_dce_runner("SeqNode switch segment replay DCE removed call expressions")
        )
        if segment_dce_changed:
            post_dce_segment_replay_changed = replay_seqnode_switch_segment_lowering_after_replacement_8616(
                project,
                codegen,
                synthetic_globals,
                cod_metadata=cod_metadata,
            )
            if post_dce_segment_replay_changed:
                post_dce_segment_dce_changed = _dce_result_changed_8616(
                    guarded_dce_runner("SeqNode switch post-DCE segment replay removed call expressions")
                )

    condition_replay_changed = replay_seqnode_switch_condition_materialization_after_replacement_8616(
        project,
        codegen,
    )
    condition_dce_changed = False
    post_condition_segment_replay_changed = False
    post_condition_segment_dce_changed = False
    if condition_replay_changed:
        condition_dce_changed = _dce_result_changed_8616(
            guarded_dce_runner("SeqNode switch condition replay DCE removed call expressions")
        )
        post_condition_segment_replay_changed = replay_seqnode_switch_segment_lowering_after_replacement_8616(
            project,
            codegen,
            synthetic_globals,
            cod_metadata=cod_metadata,
        )
        if post_condition_segment_replay_changed:
            post_condition_segment_dce_changed = _dce_result_changed_8616(
                guarded_dce_runner("SeqNode switch post-condition segment replay DCE removed call expressions")
            )

    replacement_changed = seqnode_switch_replacement_changed_for_codegen_8616(project, codegen)
    word_projection_replay_changed = False
    word_projection_dce_changed = False
    if replacement_changed:
        word_projection_replay_changed = materialize_word_projection_recompositions_8616(codegen)
        if word_projection_replay_changed:
            word_projection_dce_changed = _dce_result_changed_8616(
                guarded_dce_runner("SeqNode switch Widening replay DCE removed call expressions")
            )

    selector_replay_changed = False
    if replacement_changed:
        selector_replay_changed = replay_call_return_switch_selectors_8616(codegen)

    result = SeqNodeSwitchReplayFinalizeResult8616(
        segment_replay_changed=bool(segment_replay_changed),
        segment_dce_changed=bool(segment_dce_changed),
        post_dce_segment_replay_changed=bool(post_dce_segment_replay_changed),
        post_dce_segment_dce_changed=bool(post_dce_segment_dce_changed),
        condition_replay_changed=bool(condition_replay_changed),
        condition_dce_changed=bool(condition_dce_changed),
        post_condition_segment_replay_changed=bool(post_condition_segment_replay_changed),
        post_condition_segment_dce_changed=bool(post_condition_segment_dce_changed),
        word_projection_replay_changed=bool(word_projection_replay_changed),
        word_projection_dce_changed=bool(word_projection_dce_changed),
        selector_replay_changed=bool(selector_replay_changed),
    )
    if result.changed:
        codegen._inertia_codegen_decl_refresh_required_8616 = True
        codegen._inertia_force_codegen_regeneration_8616 = True
    with contextlib.suppress(Exception):
        codegen._inertia_seqnode_switch_replay_finalize_8616 = {
            "segment_replay_changed": result.segment_replay_changed,
            "segment_dce_changed": result.segment_dce_changed,
            "post_dce_segment_replay_changed": result.post_dce_segment_replay_changed,
            "post_dce_segment_dce_changed": result.post_dce_segment_dce_changed,
            "condition_replay_changed": result.condition_replay_changed,
            "condition_dce_changed": result.condition_dce_changed,
            "post_condition_segment_replay_changed": result.post_condition_segment_replay_changed,
            "post_condition_segment_dce_changed": result.post_condition_segment_dce_changed,
            "word_projection_replay_changed": result.word_projection_replay_changed,
            "word_projection_dce_changed": result.word_projection_dce_changed,
            "selector_replay_changed": result.selector_replay_changed,
            "changed": result.changed,
            "owner": "structuring.stage",
        }
    return result


def _induction_summary_artifact_8616(codegen: AngrCodegenSurface) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    project = getattr(codegen, "project", None)
    if cfunc is None or project is None:
        return False
    traits_cache = getattr(project, "_inertia_access_traits", None)
    if not isinstance(traits_cache, dict):
        codegen._inertia_induction_summaries = ()
        return False
    traits = traits_cache.get(getattr(cfunc, "addr", None))
    if not isinstance(traits, dict):
        codegen._inertia_induction_summaries = ()
        return False

    summaries = []
    for _base_key, profile in sorted(
        build_access_trait_evidence_profiles(traits).items(), key=lambda item: repr(item[0])
    ):
        summary = infer_induction_summary(profile)
        if summary is not None:
            summaries.append(summary)
    codegen._inertia_induction_summaries = tuple(summaries)
    return False


def _materialize_structuring_selector_return_branches_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> bool:
    """Temporary structuring-owned entry point for CFG-proven selector returns.

    The implementation still lives in the legacy postprocess module while the
    proof helpers are migrated, but the semantic transformation belongs before
    the structuring validation snapshot.  Keeping this call here prevents
    postprocess from being the first layer that repairs switch/selector return
    meaning.
    """
    from . import decompiler_postprocess_stage as _postprocess_stage

    # Dynamic angr boundary: partially initialized codegen fixtures and failed
    # core decompilations may not publish a structured statement root.
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None or not hasattr(cfunc, "statements"):
        return False
    codegen._inertia_selector_return_structuring_pass_ran_8616 = True
    return_chain_integrity = require_materialized_return_chain_integrity_8616(
        codegen,
        context="structuring:selector-return-preflight",
    )
    if return_chain_integrity.active:
        return False
    return bool(
        _postprocess_stage._materialize_cfg_selector_return_branches_8616(
            project,
            codegen,
            branch_target_return_expr=recover_branch_target_return_expression_8616,
        )
    )


@dataclass
class _TerminalGraphCallbacks8616:
    """Adapted angr function-graph surface for terminal call-result proofs."""

    project: AngrProjectSurface
    graph: object
    nodes_by_addr: dict[int, list[object]]

    def load_block(self, block_addr: int, block_size: int) -> object | None:
        """Load one exact-size block through angr's dynamic project factory."""
        factory = getattr(self.project, "factory", None)
        block_builder = getattr(factory, "block", None)
        if not callable(block_builder):
            return None
        return cast(object, block_builder(block_addr, size=block_size))

    def successor_addrs(self, block_addr: int) -> tuple[int, ...]:
        """Return exact in-function successor addresses or raise on ambiguity."""
        candidates = tuple(self.nodes_by_addr.get(block_addr, ()))
        successor_reader = getattr(self.graph, "successors", None)
        if len(candidates) != 1 or not callable(successor_reader):
            raise ValueError(f"ambiguous Structuring graph node at {block_addr:#x}")
        raw_successors = successor_reader(candidates[0])
        if not isinstance(raw_successors, Iterable):
            raise ValueError(f"missing Structuring successors at {block_addr:#x}")
        successors = tuple(raw_successors)
        successor_addrs: list[int] = []
        for successor in successors:
            successor_addr = getattr(successor, "addr", None)
            if not isinstance(successor_addr, int):
                raise ValueError(f"missing Structuring successor address at {block_addr:#x}")
            successor_addrs.append(successor_addr)
        return tuple(successor_addrs)

    @staticmethod
    def branch_target_imm(insn: object) -> int | None:
        """Read one direct branch target through the Capstone operand boundary."""
        raw_operands = getattr(insn, "operands", ())
        operands = tuple(raw_operands) if isinstance(raw_operands, Iterable) else ()
        if not operands:
            return None
        first_operand = operands[0]
        if int(getattr(first_operand, "type", -1)) != 2:
            return None
        return int(getattr(first_operand, "imm", 0))

    @staticmethod
    def call_result_contract(call: CFunctionCall) -> TerminalCallResultContract8616:
        """Consume the Types/Lowering-owned callee result verdict."""
        return callee_result_contract_8616(call.callee_func)


def _terminal_graph_census_8616(
    function: object,
) -> tuple[object, dict[int, list[object]], list[tuple[int, int]]]:
    """Normalize the angr function graph into node map and block ranges."""
    graph = getattr(function, "graph", None)
    nodes_view = getattr(graph, "nodes", ()) if graph is not None else ()
    try:
        raw_nodes = nodes_view() if callable(nodes_view) else nodes_view
        nodes = tuple(raw_nodes) if isinstance(raw_nodes, Iterable) else ()
    except Exception:
        nodes = ()
    nodes_by_addr: dict[int, list[object]] = {}
    block_ranges: list[tuple[int, int]] = []
    for node in nodes:
        node_addr = getattr(node, "addr", None)
        node_size = getattr(node, "size", None)
        if not isinstance(node_addr, int) or not isinstance(node_size, int) or node_size <= 0:
            continue
        nodes_by_addr.setdefault(node_addr, []).append(node)
        block_ranges.append((node_addr, node_size))
    return graph, nodes_by_addr, block_ranges


def _terminal_call_result_return_callbacks_8616(
    project: AngrProjectSurface,
    function: object,
) -> TerminalCallResultReturnCallbacks8616:
    """Adapt the exact active angr function graph to the typed Structuring proof."""
    # Dynamic boundary: networkx and angr Function/BlockNode objects are
    # third-party surfaces. Normalize them once before the owning proof runs.
    graph, nodes_by_addr, block_ranges = _terminal_graph_census_8616(function)
    surface = _TerminalGraphCallbacks8616(project, graph, nodes_by_addr)
    return TerminalCallResultReturnCallbacks8616(
        iter_c_nodes_deep=_iter_c_nodes_deep_8616,
        function_block_ranges=lambda: tuple(block_ranges),
        load_block=surface.load_block,
        successor_addrs=surface.successor_addrs,
        branch_target_imm=surface.branch_target_imm,
        call_result_contract=surface.call_result_contract,
    )


def _materialize_structuring_terminal_call_result_return_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
) -> bool:
    """Materialize one caller-observed terminal call result at Structuring."""
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None)
    function_addr = getattr(cfunc, "addr", None)
    active_function = getattr(project, "_inertia_active_structuring_function_8616", None)
    caller_use = CallerReturnUseVerdict8616.UNKNOWN
    if isinstance(function_addr, int):
        observation = proven_function_result_observation_8616(project, function_addr)
        if observation is not None:
            caller_use = observation
    if root is None or active_function is None:
        return False
    return_type_result = apply_terminal_call_return_type_evidence_8616(
        project,
        active_function,
    )
    if return_type_result.evidence.materialized_count > 0:
        materialize_annotated_stack_prototype_8616(project, codegen)
    callbacks = _terminal_call_result_return_callbacks_8616(
        project,
        active_function,
    )
    interrupt_result_changed = materialize_software_interrupt_terminal_results_8616(
        root,
        codegen,
        callbacks,
    )
    interrupt_replay_changed = False
    if interrupt_result_changed:
        interrupt_replay_changed = bool(materialize_software_interrupt_calls_8616(codegen))
        interrupt_replay_changed = (
            bool(materialize_software_interrupt_status_outputs_8616(codegen))
            or interrupt_replay_changed
        )
    terminal_call_stats = materialize_terminal_call_result_return_8616(
        root,
        codegen,
        caller_use=caller_use,
        callbacks=callbacks,
    )
    codegen._inertia_terminal_call_result_return_stats_8616 = terminal_call_stats
    return (
        interrupt_result_changed
        or interrupt_replay_changed
        or terminal_call_stats.status is TerminalCallResultReturnStatus8616.MATERIALIZED
    )


def _materialize_structuring_wide_stack_return_predicate_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
) -> bool:
    """Materialize a complete pure wide comparison/return CFG atomically."""
    from . import decompiler_postprocess_stage as _postprocess_stage

    raw_conditions = getattr(codegen, "_inertia_typed_conditions", ())
    if not isinstance(raw_conditions, (list, tuple)):
        return False
    conditions = tuple(
        condition
        for condition in raw_conditions
        if isinstance(condition, ConditionIR)
    )
    if len(conditions) < 2:
        return False

    def prove_pair(high_value: IRValue, low_value: IRValue) -> bool:
        """Consume exact Widening evidence for one adjacent stack pair."""
        high_expression = lower_ir_value_to_c_expr_8616(
            high_value,
            project,
            codegen,
        )
        low_expression = lower_ir_value_to_c_expr_8616(
            low_value,
            project,
            codegen,
        )
        proven = bool(
            proven_wide_stack_ir_pair_8616(
                high_value,
                low_value,
                high_expression,
                low_expression,
            )
            or proven_recorded_wide_condition_stack_pair_8616(
                codegen,
                high_value,
                low_value,
            )
        )
        return proven

    def materialize_condition(condition: ConditionIR) -> CExpression | None:
        """Lower one graph-proven wide leaf and record its argument types."""
        expression = _structuring_conditions.materialize_condition_ir_expression_8616(
            project,
            codegen,
            condition,
        )
        if expression is not None:
            record_wide_condition_argument_type_evidence_8616(codegen, condition)
        return expression

    result = materialize_wide_stack_return_predicate_8616(
        codegen,
        conditions,
        _structuring_conditions.condition_chain_successors_8616(project, codegen),
        prove_pair,
        lambda target: recover_branch_target_return_expression_8616(
            project,
            codegen,
            target,
        ),
        _same_c_expression_8616,
        materialize_condition,
        effects_are_safe=not _postprocess_stage._selector_function_has_unsafe_effects_8616(
            project,
            codegen,
        ),
    )
    if (
        result.stats.classified_fact_count > 0
        and result.stats.materialized_count == 0
    ):
        raise PipelineHardError(
            "classified wide-stack return predicate was not materialized"
        )
    return bool(result.changed)


def _materialize_structuring_return_chains_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
    *,
    materialize_wide_return_predicate: bool = True,
) -> bool:
    """Materialize CFG-proven return chains and redundant assignment diamonds.

    This is semantic control-flow materialization and must run before the
    structuring validation snapshot. New proofs and AST mutations belong in
    ``structuring/return_chains.py``. The remaining legacy postprocess callbacks
    are dynamic angr/codegen adapters and migration debt; postprocess must never
    become the first layer that makes these semantics visible.
    """
    from . import decompiler_postprocess_stage as _postprocess_stage

    codegen._inertia_return_chains_structuring_pass_ran_8616 = True
    changed = _materialize_structuring_terminal_call_result_return_8616(project, codegen)
    stored_return_result = materialize_stored_call_return_early_exit_8616(project, codegen)
    changed = stored_return_result.changed or changed
    terminal_value_result = _terminal_register_values.materialize_linear_terminal_return_value_8616(
        project,
        codegen,
        _current_structuring_function_8616(project, codegen),
        recover_proven_value=_postprocess_stage._linear_terminal_ax_return_expr_8616,
        expressions_equivalent=_same_c_expression_8616,
    )
    codegen._inertia_terminal_return_value_materialization_result_8616 = terminal_value_result
    changed = terminal_value_result.changed or changed
    cfunc = getattr(codegen, "cfunc", None)
    root = getattr(cfunc, "statements", None)
    tagged_return_result = materialize_tagged_terminal_return_values_8616(
        project,
        codegen,
        _current_structuring_function_8616(project, codegen),
        expressions_equivalent=_same_c_expression_8616,
    )
    changed = tagged_return_result.changed or changed
    changed = bool(_postprocess_stage._materialize_missing_terminal_ax_return_8616(project, codegen)) or changed
    codegen._inertia_missing_terminal_ax_return_structuring_pass_ran_8616 = True
    changed = bool(_postprocess_stage._materialize_empty_if_return_branches_8616(project, codegen)) or changed
    changed = bool(_postprocess_stage._materialize_cfg_mask_accumulator_8616(project, codegen)) or changed
    codegen._inertia_cfg_mask_accumulator_structuring_pass_ran_8616 = True
    changed = bool(_postprocess_stage._materialize_stack_byte_pair_return_pass_8616(project, codegen)) or changed
    codegen._inertia_stack_byte_pair_return_structuring_pass_ran_8616 = True
    if root is not None:
        identical_arm_stats = collapse_surplus_identical_assignment_arms_8616(
            root,
            project,
            branch_count=_postprocess_stage._real_conditional_branch_count_for_codegen_8616(
                project,
                codegen,
            ),
            expression_callbacks=_postprocess_stage._expression_fingerprint_callbacks_8616(),
            branch_callbacks=_postprocess_stage._condition_branch_tag_callbacks_8616(
                project,
            ),
        )
        codegen._inertia_identical_assignment_arm_collapse_stats_8616 = (
            identical_arm_stats
        )
        codegen._inertia_identical_assignment_arm_structuring_pass_ran_8616 = True
        changed = identical_arm_stats.materialized_count > 0 or changed
    if materialize_wide_return_predicate:
        changed = bool(
            _materialize_structuring_wide_stack_return_predicate_8616(project, codegen)
        ) or changed
    return changed


def _materialize_structuring_void_tail_call_guard_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> bool:
    """Structuring-owned repair for CFG-proven void tail-call guards.

    The implementation currently reuses legacy CFG return-expression helpers
    from the postprocess module, but the transformation is intentionally wired
    before structuring validation so postprocess is not the first semantic owner.
    """
    from . import decompiler_postprocess_stage as _postprocess_stage

    codegen._inertia_void_tail_call_guard_structuring_pass_ran_8616 = True
    return bool(_postprocess_stage._materialize_void_tail_call_guard_from_cfg_8616(project, codegen))


def _repair_structuring_loop_exit_return_guards_8616(codegen: AngrCodegenSurface) -> bool:
    """Run structuring-owned loop-exit return guard repair before validation."""
    codegen._inertia_loop_exit_guard_structuring_pass_ran_8616 = True
    return bool(repair_loop_exit_return_guards_8616(codegen, default_loop_exit_return_guard_callbacks_8616()))


def _repair_structuring_unresolved_function_exit_gotos_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> bool:
    """Run structuring-owned unresolved function-exit goto repair before validation."""
    from . import decompiler_postprocess as _postprocess

    changed = bool(_postprocess._repair_unresolved_function_exit_gotos_8616(project, codegen))
    codegen._inertia_unresolved_exit_goto_structuring_pass_ran_8616 = True
    return changed


def _materialize_structuring_pointer_arg_indirect_loads_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> bool:
    """Orchestrate Types/Lowering-owned pointer-argument materialization."""
    try:
        target = str(project._inertia_c_target or "portable-flat")
    except AttributeError:
        target = "portable-flat"
    try:
        changed = bool(apply_runtime_segment_lowering_8616(codegen, target=target))
        changed = bool(apply_segmented_load_widening_8616(codegen)) or changed
        changed = bool(materialize_register_indirect_call_target_types_8616(codegen)) or changed
        if os.environ.get("INERTIA_DEBUG_POINTER_MEMORY_IDIOMS") == "1":
            try:
                facts = codegen._inertia_near_pointer_argument_facts_8616
            except AttributeError:
                facts = ()
            try:
                stats = codegen._inertia_near_pointer_argument_stats_8616
            except AttributeError:
                stats = None
            try:
                segment_stats = codegen._inertia_segment_access_lowering_stats_8616
            except AttributeError:
                segment_stats = None
            logging.getLogger(__name__).warning(
                "[pointer-argument-lowering] changed=%r facts=%r stats=%r segment_stats=%r",
                changed,
                facts,
                stats,
                segment_stats,
            )
        return changed
    finally:
        codegen._inertia_pointer_arg_indirect_structuring_pass_ran_8616 = True


def _materialize_structuring_callsite_prototypes_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> bool:
    """Materialize typed call targets, identities, shared calls, and prototypes.

    Existing calls are bound and split before missing-target recovery so a
    rebased renderer name cannot manufacture a duplicate call. Newly recovered
    calls are rebound before prototype materialization.
    """
    from . import decompiler_postprocess_calls as _calls

    try:
        _calls._bind_callee_pointer_argument_classifier_8616(
            project,
            callee_pointer_argument_is_proven_8616,
        )
        changed = bool(_calls._attach_callsite_summaries_8616(project, codegen))
        changed = bool(_codegen.split_distinct_condition_call_occurrences_8616(codegen)) or changed
        recovered = bool(_calls._recover_missing_direct_calls_from_evidence_8616(project, codegen))
        changed = recovered or changed
        if recovered:
            changed = bool(_calls._attach_callsite_summaries_8616(project, codegen)) or changed
            changed = bool(_codegen.split_distinct_condition_call_occurrences_8616(codegen)) or changed
        changed = bool(_calls._materialize_callsite_prototypes_8616(project, codegen)) or changed
        return changed
    finally:
        codegen._inertia_call_target_structuring_pass_ran_8616 = True
        codegen._inertia_callsite_prototypes_structuring_pass_ran_8616 = True


def _close_final_structuring_callsites_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
) -> bool:
    """Materialize late-published typed callsites once at the final boundary."""
    try:
        inventory = codegen._inertia_callsite_summary_inventory_8616
    except AttributeError:
        return False
    if not isinstance(inventory, dict) or not inventory:
        return False
    from .lowering.consumed_stack_address_setup import prune_consumed_stack_address_setup_8616

    changed = _materialize_structuring_callsite_prototypes_8616(project, codegen)
    return prune_consumed_stack_address_setup_8616(project, codegen, codegen.cfunc.statements, inventory) or changed


def _bind_structuring_callsite_consumers_8616(codegen: AngrCodegenSurface) -> None:
    """Bind Types/Lowering replay services before any Structuring mode diverges."""
    from . import decompiler_postprocess_calls as _calls
    from .callsite_pointer_values import bind_near_pointer_argument_value_lowerer_8616
    from .lowering.near_pointer_argument_values import materialize_near_pointer_argument_value_8616

    bind_near_pointer_argument_value_lowerer_8616(codegen, materialize_near_pointer_argument_value_8616)
    _calls._bind_call_target_identity_consumer_8616(codegen, canonicalize_callsite_target_identities_8616)
    _calls._bind_call_argument_rematerialization_classifier_8616(
        codegen,
        call_argument_requires_typed_rematerialization_8616,
    )
    _calls._bind_call_argument_setup_liveness_classifier_8616(
        codegen,
        call_argument_setup_is_proven_dead_8616,
    )
    _calls._bind_callsite_argument_replay_consumer_8616(
        codegen,
        _replay_structuring_callsite_arguments_after_regeneration_8616,
    )
    _calls._bind_fixed_stack_probe_frame_lowerer_8616(
        codegen,
        replay_fixed_stack_probe_callsite_artifacts_8616,
    )
    _calls._bind_call_return_frame_argument_lowerer_8616(
        codegen,
        lambda project, codegen: prune_exact_call_return_frame_arguments_8616(
            project,
            codegen,
        ).changed,
    )
    _calls._bind_function_result_observation_provider_8616(
        codegen,
        proven_function_result_observation_8616,
    )
    _calls._bind_segment_address_provenance_attacher_8616(codegen, attach_callsite_segment_address_provenance_8616)
    _calls._bind_segment_push_source_lowerer_8616(codegen, runtime_segment_push_source_cvar_8616)


def _replay_structuring_callsite_arguments_after_regeneration_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
    *,
    preserve_setup: bool = False,
) -> bool:
    """Reconsume typed callsite facts after core replaces the structured AST."""
    from . import decompiler_postprocess_calls as _calls

    _bind_structuring_callsite_consumers_8616(codegen)
    controls = _calls._ensure_callsite_materialization_controls_8616(codegen)
    previous_consumed_prune = controls._inertia_callsite_disable_consumed_arg_store_prune_8616
    previous_probe_prune = controls._inertia_callsite_disable_stack_probe_setup_prune_8616
    if preserve_setup:
        controls._inertia_callsite_disable_consumed_arg_store_prune_8616 = True
        controls._inertia_callsite_disable_stack_probe_setup_prune_8616 = True
    try:
        changed = bool(
            _calls.replay_callsite_stack_arguments_after_regeneration_8616(
                project,
                codegen,
            )
        )
        return finalize_shared_call_occurrences_8616(project, codegen) or changed
    finally:
        controls._inertia_callsite_disable_consumed_arg_store_prune_8616 = previous_consumed_prune
        controls._inertia_callsite_disable_stack_probe_setup_prune_8616 = previous_probe_prune


def _materialize_structuring_callsite_stack_arguments_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> bool:
    """Consume existing typed callsite facts before Structuring validation.

    Call-target discovery remains a frontend responsibility. This bridge
    consumes stack-argument facts but never discovers or guesses calls.
    Exact PUSH effects consumed by materialized arguments are pruned here so
    the Lowering result is part of the Structuring baseline, not a Rewrite
    semantic delta. Stack-probe setup pruning remains disabled because it uses
    a separate compatibility proof.
    """
    from . import decompiler_postprocess_calls as _calls

    _bind_structuring_callsite_consumers_8616(codegen)
    controls = _calls._ensure_callsite_materialization_controls_8616(codegen)
    previous_stack_probe_setup_prune = controls._inertia_callsite_disable_stack_probe_setup_prune_8616
    controls._inertia_callsite_disable_stack_probe_setup_prune_8616 = True
    try:
        changed = bool(
            _calls._materialize_callsite_stack_arguments_8616(
                project,
                codegen,
            )
        )
        argument_join_changed = materialize_call_argument_joins_8616(project, codegen)
        changed = argument_join_changed or changed
        if argument_join_changed:
            changed = bool(
                prune_materialized_call_push_stack_assignments_8616(
                    project,
                    codegen,
                )
            ) or changed
        changed = bool(_calls._replay_call_target_identity_consumer_8616(project, codegen)) or changed
        return finalize_shared_call_occurrences_8616(project, codegen) or changed
    finally:
        controls._inertia_callsite_disable_stack_probe_setup_prune_8616 = previous_stack_probe_setup_prune
        codegen._inertia_callsite_stack_arguments_structuring_pass_ran_8616 = True


def _repair_structuring_synthetic_internal_calls_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> bool:
    """Prune no-summary internal-target calls using structuring CFG evidence."""
    changed = repair_synthetic_internal_calls_from_evidence_8616(project, codegen)
    codegen._inertia_synthetic_internal_call_structuring_pass_ran_8616 = True
    return bool(changed)


def _materialize_structuring_stdlib_call_chains_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> bool:
    """Run structuring-owned call-chain materialization before validation."""
    from . import decompiler_postprocess_calls as _calls

    try:
        return bool(_calls._materialize_stdlib_call_chains_8616(project, codegen))
    finally:
        codegen._inertia_stdlib_call_chains_structuring_pass_ran_8616 = True


def _materialize_structuring_loop_idioms_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> bool:
    """Run structuring-owned loop idiom materializers before validation.

    These passes still reuse legacy instruction/CFG proof helpers while their
    evidence builders are split out, but the transformations materialize loop
    state and therefore belong before the structuring validation snapshot.
    """
    from . import decompiler_postprocess_stage as _postprocess_stage

    try:
        changed = bool(_postprocess_stage._materialize_global_byte_index_sum_loop_8616(project, codegen))
        return changed
    finally:
        codegen._inertia_loop_idiom_structuring_pass_ran_8616 = True


def _materialize_structuring_unconsumed_loop_break_jcc_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> bool:
    """Run Structuring-owned loop-break JCC materialization exactly once.

    The C AST repair now lives in ``structuring.loop_break_jcc``.  The remaining
    dynamic JCC proof callbacks are still supplied by the legacy postprocess
    module until those proof helpers are split, but execution belongs before the
    structuring validation snapshot.
    """
    from . import decompiler_postprocess_stage as _postprocess_stage

    try:
        return bool(_postprocess_stage._materialize_unconsumed_loop_break_jcc_8616(project, codegen))
    finally:
        codegen._inertia_unconsumed_loop_break_jcc_structuring_pass_ran_8616 = True


def _repair_structuring_switch_loop_exit_returns_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> bool:
    """Run structuring-owned switch loop-exit return repair before validation."""
    codegen._inertia_switch_loop_exit_return_structuring_pass_ran_8616 = True
    return bool(repair_switch_loop_exit_returns_from_evidence_8616(project, codegen))


def _collapse_structuring_switch_loop_tail_breaks_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
) -> bool:
    """Collapse exact switch exits after condition and return materialization."""
    del project
    result = materialize_switch_loop_tail_breaks_8616(codegen.cfunc.statements)
    codegen._inertia_structuring_switch_loop_tail_break_result_8616 = result
    return bool(result.changed)


def _materialize_structuring_return_shape_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
) -> bool:
    """Consume structuring-proven return shape and its AST form before validation.

    The legacy classifier remains in the postprocess compatibility module while
    its proof helpers are migrated. Structuring invokes it immediately after
    CFG-backed exit-return repair, then materializes void returns while retaining
    call side effects, so rewrite is not the first layer to change the function
    interface or return statement shape.
    """
    from . import decompiler_postprocess as _postprocess

    changed = bool(_postprocess._classify_return_shape_8616(project, codegen))
    void_returns_changed = bool(_postprocess._prune_void_function_return_values_8616(project, codegen))
    return void_returns_changed or changed


def _repair_structuring_conditional_continue_guards_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> bool:
    """Run structuring-owned conditional-continue guard repair before validation."""
    codegen._inertia_conditional_continue_guard_structuring_pass_ran_8616 = True
    return bool(repair_conditional_continue_guards_from_evidence_8616(project, codegen))


def _repair_structuring_pretest_loop_break_guards_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> bool:
    """Run structuring-owned pretest loop-break guard repair before validation."""
    codegen._inertia_pretest_loop_break_guard_structuring_pass_ran_8616 = True
    return bool(repair_pretest_loop_break_guards_from_evidence_8616(project, codegen))


def recover_structuring_canonical_for_loops_8616(codegen: AngrCodegenSurface) -> bool:
    """Replay Structuring-owned canonical loop recovery on a live C AST."""
    return bool(recover_canonical_for_loops_8616(codegen))


def _repair_structuring_hoisted_jcc_target_copies_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> bool:
    """Run structuring-owned hoisted JCC target-copy repair before validation."""
    codegen._inertia_hoisted_jcc_target_copy_structuring_pass_ran_8616 = True
    return bool(repair_hoisted_jcc_target_copies_from_evidence_8616(project, codegen))


DECOMPILER_STRUCTURING_PASSES: tuple[DecompilerStructuringPassSpec, ...] = _build_decompiler_structuring_passes()


@contextlib.contextmanager
def _guard_condition_processor_multibit_bool_predicates_8616(project: AngrProjectSurface) -> Iterator[None]:
    """Normalize multi-bit AIL branch predicates to explicit nonzero Bool ASTs.

    angr's condition processor may return a BV for Register/Load/VirtualVariable
    leaves even when the caller requests ``must_bool=True``. x86 conditional
    branch semantics are explicit nonzero tests for such values, so structuring
    must see a Bool predicate instead of asserting later in short-circuit
    recovery.
    """
    try:
        from angr.analyses.decompiler.condition_processor import ConditionProcessor
    except Exception:
        yield
        return

    condition_processor_cls = cast(Any, ConditionProcessor)
    orig = condition_processor_cls.claripy_ast_from_ail_condition
    if getattr(orig, "_inertia_8616_multibit_bool_guard", False):
        yield
        return

    tally = _MultibitBoolTally8616()

    def _claripy_ast_from_ail_condition_8616(
        self: AngrConditionProcessorSurface,
        condition: object,
        *,
        nobool: bool = False,
        must_bool: bool = False,
        ins_addr: int = 0,
    ) -> ClaripyConditionSurface:
        return _multibit_bool_ast_from_ail_8616(
            self,
            condition,
            orig,
            tally,
            nobool=nobool,
            must_bool=must_bool,
            ins_addr=ins_addr,
        )

    cast(Any, _claripy_ast_from_ail_condition_8616)._inertia_8616_multibit_bool_guard = True
    condition_processor_cls.claripy_ast_from_ail_condition = _claripy_ast_from_ail_condition_8616
    try:
        yield
    finally:
        condition_processor_cls.claripy_ast_from_ail_condition = orig
        if tally.normalized_count:
            current = int(getattr(project, "_inertia_condition_predicate_multibit_bool_normalized", 0) or 0)
            project._inertia_condition_predicate_multibit_bool_normalized = current + tally.normalized_count
        if tally.refused_count:
            current = int(getattr(project, "_inertia_condition_predicate_multibit_bool_refused", 0) or 0)
            project._inertia_condition_predicate_multibit_bool_refused = current + tally.refused_count


@dataclass
class _MultibitBoolTally8616:
    """Mutable normalization/refusal counts for the bool-predicate monkeypatch."""

    normalized_count: int = 0
    refused_count: int = 0


def _multibit_bool_ast_from_ail_8616(
    self: AngrConditionProcessorSurface,
    condition: object,
    orig: Callable[..., ClaripyConditionSurface],
    tally: _MultibitBoolTally8616,
    *,
    nobool: bool = False,
    must_bool: bool = False,
    ins_addr: int = 0,
) -> ClaripyConditionSurface:
    """Return a Bool predicate for multi-bit AIL branch conditions."""
    import claripy

    from .structuring.symbolic_ite import convert_symbolic_ite_8616

    result = convert_symbolic_ite_8616(self, condition, must_bool=must_bool)
    if result is None:
        result = orig(self, condition, nobool=nobool, must_bool=must_bool, ins_addr=ins_addr)
    if must_bool and isinstance(result, claripy.ast.Bool):
        from .structuring.symbolic_condition_origin import preserve_symbolic_condition_origin_8616

        return preserve_symbolic_condition_origin_8616(self, condition, result)
    if not must_bool or isinstance(result, claripy.ast.Bool):
        return result
    if isinstance(result, claripy.ast.BV):
        size = int(result.size())
        if size > 0:
            tally.normalized_count += 1
            return result != claripy.BVV(0, size)
    tally.refused_count += 1
    return result


def _semantic_validation_pass_names_8616() -> tuple[str, ...]:
    return (
        "_simplify_structured_expressions_8616",
        "_segmented_memory_reasoning_8616",
        "_array_expression_matching_8616",
        "_structuring_codegen_8616",
        "_canonical_for_loop_recovery_8616",
        "_widening_copy_propagation_8616",
    )


def _function_complexity_for_structuring_validation_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> tuple[int, int]:
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    try:
        functions = getattr(getattr(project, "kb", None), "functions", None)
        function = (
            functions.function(func_addr, create=False)
            if functions is not None and isinstance(func_addr, int) and func_addr >= 0
            else None
        )
        if function is None:
            return 0, 0
        info = getattr(function, "info", None)
        if isinstance(info, MutableMapping):
            cached = info.get("_inertia_function_complexity")
            if isinstance(cached, MutableMapping):
                blocks = cached.get("blocks")
                bytes_ = cached.get("bytes")
                if isinstance(blocks, int) and isinstance(bytes_, int):
                    return max(0, blocks), max(0, bytes_)
        local_blocks = tuple((getattr(function, "_local_blocks", {}) or {}).values())
        blocks = local_blocks or tuple(getattr(function, "blocks", ()) or ())
        if blocks:
            block_count = 0
            byte_count = 0
            for block in blocks:
                block_addr = getattr(block, "addr", None)
                if isinstance(block_addr, int):
                    block_count += 1
                byte_count += int(
                    getattr(block, "size", 0)
                    or len(getattr(block, "bytes", b"") or b"")
                    or len(getattr(block, "bytestr", b"") or b"")
                )
            return block_count, byte_count
        return len(getattr(function, "block_addrs_set", ()) or ()), 0
    except Exception:
        return 0, 0


def _structuring_pass_validation_skip_reason_8616(
    project: AngrProjectSurface, codegen: AngrCodegenSurface
) -> StructuringPassValidationSkipReason8616 | None:
    blocks, bytes_ = _function_complexity_for_structuring_validation_8616(project, codegen)
    if blocks >= _STRUCTURING_PASS_VALIDATION_LARGE_BLOCK_THRESHOLD_8616:
        return StructuringPassValidationSkipReason8616.LARGE_FUNCTION_BLOCK_COUNT
    if bytes_ >= _STRUCTURING_PASS_VALIDATION_LARGE_BYTE_THRESHOLD_8616:
        return StructuringPassValidationSkipReason8616.LARGE_FUNCTION_BYTE_SIZE
    return None


def _large_function_for_structuring_pass_validation_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> bool:
    return _structuring_pass_validation_skip_reason_8616(project, codegen) is not None


def _current_structuring_function_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> object | None:
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if not isinstance(func_addr, int):
        return None
    candidate_addrs: list[int] = []
    if _structuring_project_maps_addr_8616(project, func_addr):
        candidate_addrs.append(func_addr)
    original_delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(original_delta, int) and original_delta:
        candidate_addrs.extend((func_addr - original_delta, func_addr + original_delta))
    candidate_addrs.append(func_addr)
    active_function = getattr(project, "_inertia_active_structuring_function_8616", None)
    active_addr = getattr(active_function, "addr", None)
    if isinstance(active_addr, int) and active_addr in candidate_addrs:
        return active_function
    functions = getattr(getattr(project, "kb", None), "functions", None)
    if functions is None:
        return None
    seen: set[int] = set()
    for candidate_addr in candidate_addrs:
        if candidate_addr in seen or candidate_addr < 0:
            continue
        seen.add(candidate_addr)
        with contextlib.suppress(Exception):
            function = functions.function(addr=candidate_addr, create=False)
            if function is not None:
                return cast(object, function)
    return None


@contextlib.contextmanager
def active_structuring_function_8616(
    project: AngrProjectSurface,
    function: object,
) -> Iterator[None]:
    """Expose the exact active angr function to Structuring for one analysis."""
    attribute = "_inertia_active_structuring_function_8616"
    had_previous = hasattr(project, attribute)
    previous = getattr(project, attribute, None)
    setattr(project, attribute, function)
    try:
        yield
    finally:
        if had_previous:
            setattr(project, attribute, previous)
        else:
            with contextlib.suppress(Exception):
                delattr(project, attribute)


def _structuring_project_maps_addr_8616(project: AngrProjectSurface, addr: int) -> bool:
    """Return whether an address belongs to the active angr loader mapping."""
    loader = getattr(project, "loader", None)
    main_object = getattr(loader, "main_object", None)
    min_addr = getattr(main_object, "min_addr", None)
    max_addr = getattr(main_object, "max_addr", None)
    return isinstance(min_addr, int) and isinstance(max_addr, int) and min_addr <= addr <= max_addr


def _bind_direct_stack_move_branch_ownership_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
    function: object | None,
) -> None:
    """Bind Structuring-owned direct-stack-move placement to an angr codegen."""
    if function is None:
        return
    cast(Any, codegen)._inertia_direct_stack_move_ownership_replayed_8616 = False

    def replay() -> bool:
        """Reapply proven control-flow ownership after a lowering replay."""
        generation_before = direct_stack_replay_scheduling_generation_8616(
            codegen,
            function,
        )
        stable_generation = getattr(
            codegen,
            "_inertia_direct_stack_ownership_replay_stable_generation_8616",
            None,
        )
        if (
            isinstance(stable_generation, DirectStackReplayGeneration8616)
            and stable_generation == generation_before
        ):
            codegen._inertia_direct_stack_ownership_replay_skip_count_8616 = (
                int(
                    getattr(
                        codegen,
                        "_inertia_direct_stack_ownership_replay_skip_count_8616",
                        0,
                    )
                    or 0
                )
                + 1
            )
            cast(Any, codegen)._inertia_direct_stack_move_ownership_replayed_8616 = True
            return False
        branch_changed = materialize_direct_stack_move_branch_ownership_8616(
            project,
            codegen,
            function,
        )
        loop_entry_changed = materialize_direct_stack_move_loop_entry_ownership_8616(
            project,
            codegen,
            function,
        )
        loop_tail_changed = materialize_direct_stack_move_loop_tail_ownership_8616(
            project,
            codegen,
            function,
        )
        cast(Any, codegen)._inertia_direct_stack_move_ownership_replayed_8616 = True
        ownership_changed = bool(
            branch_changed or loop_entry_changed or loop_tail_changed
        )
        codegen._inertia_direct_stack_ownership_replay_stable_generation_8616 = (
            generation_before if not ownership_changed else None
        )
        if timing_output_enabled() and os.environ.get("INERTIA_TAIL_VALIDATION_STDERR_JSON") != "1":
            print(
                f"[{time.strftime('%H:%M:%S')}] direct-stack ownership replay: "
                f"branch={branch_changed} loop_entry={loop_entry_changed} loop_tail={loop_tail_changed}",
                file=sys.stderr,
                flush=True,
            )
        return ownership_changed

    cast(Any, codegen)._inertia_direct_stack_move_branch_ownership_replay_8616 = replay

    def place(
        move_fact: DirectStackMoveFact8616,
        assignment: CAssignment,
    ) -> bool:
        """Place one Lowering-built stack move at its structured CFG owner."""
        return bool(
            place_direct_stack_move_linear_prefix_assignment_8616(
                project,
                codegen,
                function,
                move_fact,
                assignment,
            )
            or place_direct_stack_move_assignment_8616(
                project,
                codegen,
                function,
                move_fact,
                assignment,
            )
            or place_direct_stack_move_loop_entry_assignment_8616(
                project,
                codegen,
                function,
                move_fact,
                assignment,
            )
            or place_direct_stack_move_loop_tail_assignment_8616(
                project,
                codegen,
                function,
                move_fact,
                assignment,
            )
        )

    cast(Any, codegen)._inertia_direct_stack_move_branch_placement_service_8616 = place


def _apply_structuring_direct_stack_materialization_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> bool:
    """Prune frame scaffolding, then materialize direct effects before validation."""
    from .structuring.instruction_fragment_placement import apply_instruction_fragment_placement_8616

    started = time.perf_counter()
    function = _current_structuring_function_8616(project, codegen)
    if not getattr(codegen, "_inertia_typed_conditions_transferred", False):
        func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
        if isinstance(func_addr, int):
            transfer_typed_conditions_to_codegen_8616(project, func_addr, codegen)
        codegen._inertia_typed_conditions_transferred = True
    _bind_direct_stack_move_branch_ownership_8616(project, codegen, function)
    fragment_placement_changed = apply_instruction_fragment_placement_8616(project, codegen)
    component_started = time.perf_counter()
    control_stack_escape_changed = materialize_proven_control_stack_escape_8616(
        codegen,
        project,
        function=function,
    )
    callee_saved_changed = prune_callee_saved_stack_spills_8616(
        codegen,
        project,
        function=function,
    )
    callee_saved_elapsed = time.perf_counter() - component_started
    changed = fragment_placement_changed or control_stack_escape_changed or callee_saved_changed
    component_started = time.perf_counter()
    mov_changed = materialize_direct_stack_mov_instructions_8616(
        codegen,
        project=project,
        function=function,
        allow_stack_slot_fallback=True,
    )
    mov_elapsed = time.perf_counter() - component_started
    changed = mov_changed or changed
    component_started = time.perf_counter()
    incdec_changed = materialize_direct_stack_incdec_instructions_8616(
        codegen,
        project=project,
        function=function,
    )
    incdec_elapsed = time.perf_counter() - component_started
    changed = incdec_changed or changed
    component_started = time.perf_counter()
    global_incdec_changed = materialize_direct_global_incdec_instructions_8616(
        codegen,
        project=project,
        function=function,
    )
    global_incdec_elapsed = time.perf_counter() - component_started
    changed = global_incdec_changed or changed
    codegen._inertia_direct_global_incdec_materialization_structuring_pass_ran_8616 = True
    branch_changed = False
    loop_entry_changed = False
    ownership_replayed = bool(
        getattr(codegen, "_inertia_direct_stack_move_ownership_replayed_8616", False)
    )
    if function is not None and not ownership_replayed:
        branch_changed = materialize_direct_stack_move_branch_ownership_8616(
            project,
            codegen,
            function,
        )
        changed = branch_changed or changed
        loop_entry_changed = materialize_direct_stack_move_loop_entry_ownership_8616(
            project,
            codegen,
            function,
        )
        changed = loop_entry_changed or changed
    codegen._inertia_direct_stack_materialization_structuring_pass_ran_8616 = True
    if changed:
        codegen._inertia_codegen_decl_refresh_required_8616 = True
    if timing_output_enabled() and os.environ.get("INERTIA_TAIL_VALIDATION_STDERR_JSON") != "1":
        print(
            f"[{time.strftime('%H:%M:%S')}] structuring direct-stack replay: "
            f"changed={bool(changed)} callee_saved={bool(callee_saved_changed)} "
            f"mov={bool(mov_changed)} incdec={bool(incdec_changed)} "
            f"global_incdec={bool(global_incdec_changed)} branch={bool(branch_changed)} "
            f"loop_entry={bool(loop_entry_changed)} "
            f"components=callee_saved:{callee_saved_elapsed:.3f},"
            f"mov:{mov_elapsed:.3f},incdec:{incdec_elapsed:.3f},"
            f"global_incdec:{global_incdec_elapsed:.3f} "
            f"({time.perf_counter() - started:.3f}s)",
            file=sys.stderr,
            flush=True,
        )
    return bool(changed)


def _prime_structuring_segment_global_semantics_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
) -> bool:
    """Consume proven segment/global facts before Structuring validation."""
    collect_indexed_address_collector_parity_8616(project, codegen)
    # Synthetic-global maps are dynamic metadata on the angr project/codegen boundary.
    synthetic_globals = getattr(codegen, "_inertia_synthetic_globals", None)
    if not isinstance(synthetic_globals, dict):
        synthetic_globals = getattr(project, "_inertia_synthetic_globals", None)
    if not isinstance(synthetic_globals, dict):
        synthetic_globals = None
    result = run_segment_global_materialization_8616(
        project,
        codegen,
        synthetic_globals,
        include_runtime_segment=True,
        cod_metadata=cod_metadata_for_codegen_8616(project, codegen),
    )
    codegen._inertia_segment_global_structuring_prime_ran_8616 = True
    if result.changed:
        codegen._inertia_codegen_decl_refresh_required_8616 = True
    return bool(result.changed)


def _replay_structuring_lowering_before_validation_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
) -> bool:
    """Replay proof-consuming Lowering after Structuring rebuilds C subtrees.

    Structuring may clone condition calls or regenerate their argument
    expressions after the first Types/Lowering pass. Bind callsite identity
    before arguments, then rebind conditions after every subtree-rebuilding
    Lowering consumer has run.
    """
    changed = materialize_annotated_stack_prototype_8616(project, codegen)
    changed = bool(_materialize_structuring_callsite_prototypes_8616(project, codegen)) or changed
    changed = materialize_call_return_conditions_8616(project, codegen) or changed
    changed = bool(_materialize_structuring_callsite_stack_arguments_8616(project, codegen)) or changed
    changed = lower_unobserved_call_result_assignments_8616(codegen) or changed
    changed = replay_call_return_switch_selectors_8616(codegen) or changed
    changed = bool(_materialize_structuring_pointer_arg_indirect_loads_8616(project, codegen)) or changed
    changed = bool(_materialize_structuring_stdlib_call_chains_8616(project, codegen)) or changed
    # Callsite replay can recreate BP-indexed pointer helpers from exact PUSH
    # evidence. Re-run the SS owner before global lowering so those addresses
    # cannot retain a stale DS carrier through Structuring validation.
    changed = bool(_apply_structuring_stable_stack_semantics_8616(project, codegen)) or changed
    advance_direct_stack_consumer_generation_8616(codegen)
    changed = bool(_apply_structuring_direct_stack_materialization_8616(project, codegen)) or changed
    changed = bool(materialize_software_interrupt_calls_8616(codegen)) or changed
    changed = bool(materialize_software_interrupt_status_outputs_8616(codegen)) or changed
    changed = lower_unobserved_call_result_assignments_8616(codegen) or changed
    changed = bool(_prime_structuring_segment_global_semantics_8616(project, codegen)) or changed
    function = _current_structuring_function_8616(project, codegen)
    changed = bool(
        prune_frame_prologue_stack_assignments_8616(project, codegen, function=function)
    ) or changed
    changed = bool(_replay_materialized_call_stack_metadata_8616(project, codegen)) or changed
    changed = bool(prune_unused_structured_insert_intrinsics_8616(codegen)) or changed
    changed = bool(lower_structured_insert_intrinsics_8616(codegen)) or changed
    changed = bool(materialize_signed_global_declarations_8616(project, codegen)) or changed
    changed = materialize_loop_carried_terminal_return_8616(project, codegen).changed or changed
    changed = bool(apply_condition_scalar_types_8616(project, codegen)) or changed
    changed = materialize_explicit_scalar_char_types_8616(codegen) or changed
    changed = materialize_call_return_conditions_8616(project, codegen) or changed
    changed = finalize_typed_register_locals_8616(codegen).changed or changed
    return changed


def _apply_structuring_stable_stack_semantics_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> bool:
    """Orchestrate IR, Alias, and Lowering owners before C structuring."""

    @contextlib.contextmanager
    def _timed_owner(owner: str) -> Iterator[None]:
        """Expose one semantic owner's inclusive cost in the existing timing mode."""
        started = time.perf_counter()
        try:
            yield
        finally:
            if timing_output_enabled() and os.environ.get("INERTIA_TAIL_VALIDATION_STDERR_JSON") != "1":
                print(
                    f"[{time.strftime('%H:%M:%S')}] structuring semantic owner: {owner} "
                    f"({time.perf_counter() - started:.3f}s)",
                    file=sys.stderr,
                    flush=True,
                )

    changed = False
    with _timed_owner("vex_ir"):
        _vex_ir.apply_x86_16_vex_ir_artifact(project, codegen)
    with _timed_owner("indexed_address_ir"):
        _indexed_address_ir.apply_x86_16_indexed_address_evidence_8616(project, codegen)
    with _timed_owner("call_stack_effects"):
        apply_x86_16_call_stack_effects_8616(project, codegen)
    with _timed_owner("indexed_address_aliases"):
        _indexed_address_aliases.apply_x86_16_indexed_address_aliases_8616(project, codegen)
    with _timed_owner("stack_memory_ssa_alias"):
        _stack_memory_ssa.apply_x86_16_stack_memory_ssa_alias_artifact(project, codegen)
    with _timed_owner("carry_borrow_widening"):
        apply_carry_borrow_widening_pipeline_8616(project, codegen)
    with _timed_owner("cfg_execution_ownership"):
        codegen._inertia_cfg_execution_ownership_8616 = _cfg_ownership.build_cfg_ownership_artifact(codegen)
    with _timed_owner("stack_memory_object_widening"):
        apply_x86_16_stack_memory_object_widening_8616(project, codegen)
    before_materialized = int(getattr(codegen, "_inertia_semantic_stack_materialized_count", 0) or 0)
    with _timed_owner("stack_memory_ssa_lowering"):
        memory_ssa_lowering = lower_x86_16_stack_memory_ssa_alias_artifact(codegen)
    with _timed_owner("wide_call_output_lowering"):
        wide_call_output_lowering = (
            lower_wide_call_output_stack_assignments_8616(codegen)
            if memory_ssa_lowering is not None
            else None
        )
    if wide_call_output_lowering is not None:
        changed = bool(wide_call_output_lowering.stats.changed_count) or changed
    with _timed_owner("carry_borrow_bit_lowering"):
        changed = lower_carry_borrow_bit_values_8616(codegen) or changed
    if memory_ssa_lowering is None:
        with _timed_owner("semantic_alias_transfer"):
            transfer_semantic_alias_facts_to_codegen_8616(project, codegen)
        # Dynamic boundary: legacy codegen carries transferred Alias facts as optional metadata.
        alias_facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
        if isinstance(alias_facts, list) and alias_facts:
            with _timed_owner("alias_fact_stack_lowering"):
                lower_stack_accesses_from_alias_facts_8616(codegen, alias_facts)
    after_materialized = int(getattr(codegen, "_inertia_semantic_stack_materialized_count", 0) or 0)
    changed = changed or after_materialized > before_materialized
    with _timed_owner("positive_bp_argument_interface"):
        changed = bool(materialize_positive_bp_arguments_8616(project, codegen)) or changed
    with _timed_owner("runtime_ss_segment_helper_lowering"):
        changed = bool(lower_runtime_ss_segment_helpers_to_stack_8616(codegen, project=project)) or changed
    with _timed_owner("stable_ss_linear_lowering"):
        changed = bool(lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project)) or changed
    with _timed_owner("dead_register_carrier_prune"):
        changed = bool(prune_unread_stack_lowered_register_carriers_8616(codegen)) or changed
    with _timed_owner("terminal_return_render_projection"):
        render_projection = project_terminal_return_renderability_8616(codegen)
        cast(Any, codegen)._inertia_terminal_return_render_projection_8616 = render_projection
        changed = render_projection.changed or changed
    codegen._inertia_stable_stack_semantics_structuring_pass_ran_8616 = True
    if changed:
        codegen._inertia_codegen_decl_refresh_required_8616 = True
    return changed


def _apply_structuring_pointer_memory_idioms_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> bool:
    """Run lowering-owned pointer-memory idiom materialization before validation."""
    from . import decompiler_postprocess_stage as _postprocess_stage

    callbacks = PointerMemoryIdiomCallbacks8616(
        linear_function_insns=_postprocess_stage._linear_function_insns_for_codegen_8616,
        word_pair_pointer_accumulation_loop=_postprocess_stage._materialize_word_pair_pointer_accumulation_loop_8616,
        word_pointer_first_gt_loop=_postprocess_stage._materialize_word_pointer_first_gt_loop_8616,
        word_pointer_rotate3=_postprocess_stage._materialize_word_pointer_rotate3_8616,
        pointer_swap=lambda project, codegen, insns, index_by_addr: _postprocess_stage._materialize_pointer_swap_8616(
            project,
            codegen,
            insns,
            index_by_addr,
            splice_pointer_swap=splice_proven_pointer_swap_statements_8616,
        ),
    )
    try:
        changed = materialize_pointer_memory_idioms_from_evidence_8616(project, codegen, callbacks)
        if changed:
            codegen._inertia_codegen_decl_refresh_required_8616 = True
            codegen._inertia_force_codegen_regeneration_8616 = True
        return bool(changed)
    finally:
        codegen._inertia_pointer_memory_idiom_lowering_pass_ran_8616 = True


def _replay_structuring_gp_state_after_late_cleanup_8616(
    codegen: AngrCodegenSurface,
) -> bool:
    """Rebind typed GP projections after late Structuring cleanup mutates C AST."""
    try:
        replay_count = codegen._inertia_structuring_gp_state_cleanup_replay_count_8616
    except AttributeError:
        replay_count = 0
    codegen._inertia_structuring_gp_state_cleanup_replay_count_8616 = (
        int(replay_count or 0) + 1
    )
    return lower_architectural_gp_register_state_8616(codegen)


def _prime_validation_pipeline_prefix_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> bool:
    """Run the proven Structuring consumers up to the return-shape replay."""
    changed = False
    _vex_ir.apply_x86_16_vex_ir_artifact(project, codegen)
    _indexed_address_ir.apply_x86_16_indexed_address_evidence_8616(project, codegen)
    apply_x86_16_call_stack_effects_8616(project, codegen)
    _indexed_address_aliases.apply_x86_16_indexed_address_aliases_8616(project, codegen)
    _stack_memory_ssa.apply_x86_16_stack_memory_ssa_alias_artifact(project, codegen)
    _segment_stack_restore.apply_x86_16_segment_stack_restore_artifact(project, codegen)
    _segment_stack_restore.apply_x86_16_stack_register_restore_artifact_8616(
        project,
        codegen,
    )
    changed = bool(prune_proven_segment_stack_restore_carriers_8616(project, codegen)) or changed
    _segment_state.apply_x86_16_segment_state_artifact(project, codegen)
    _segment_contract.apply_x86_16_segment_function_contract(project, codegen)
    _segment_function_summary.apply_x86_16_segment_function_summary(project, codegen)
    from .lowering.real_mode_linear import (
        lower_stable_ds_es_linear_global_dereferences_8616,
    )

    changed = bool(_apply_structuring_stable_stack_semantics_8616(project, codegen))
    changed = bool(_apply_structuring_direct_stack_materialization_8616(project, codegen)) or changed
    changed = bool(_prime_structuring_segment_global_semantics_8616(project, codegen)) or changed
    if changed:
        codegen._inertia_codegen_decl_refresh_required_8616 = True
    lower_stable_ds_es_linear_global_dereferences_8616(codegen, project=project)
    _segmented_mem.apply_x86_16_segmented_memory_reasoning(codegen)
    # Keep structuring-tail validation stable: if priming already applied
    # SS stack lowering and alias-fact lowering, skip re-running it in the
    # structuring body to avoid representation-only drift.
    codegen._inertia_ss_stack_lowered = True
    if not getattr(codegen, "_inertia_typed_conditions_transferred", False):
        func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
        if isinstance(func_addr, int):
            transfer_typed_conditions_to_codegen_8616(project, func_addr, codegen)
        codegen._inertia_typed_conditions_transferred = True
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if isinstance(func_addr, int):
        changed = bool(_materialize_structuring_wide_stack_return_predicate_8616(project, codegen)) or changed
        changed = bool(run_structuring_condition_cleanup_8616(project, codegen, func_addr)) or changed
    else:
        _structuring_conditions.apply_structuring_condition_materialization_8616(project, codegen)
    changed = materialize_annotated_stack_prototype_8616(project, codegen) or changed
    changed = bool(_materialize_structuring_pointer_arg_indirect_loads_8616(project, codegen)) or changed
    changed = bool(_materialize_structuring_callsite_prototypes_8616(project, codegen)) or changed
    changed = materialize_call_return_conditions_8616(project, codegen) or changed
    changed = bool(_materialize_structuring_callsite_stack_arguments_8616(project, codegen)) or changed
    # Callsite lowering publishes return-use evidence consumed by JCC
    # condition materialization; replay conditions only after that contract exists.
    changed = bool(_structuring_conditions.apply_structuring_condition_materialization_8616(project, codegen)) or changed
    changed = materialize_call_return_conditions_8616(project, codegen) or changed
    changed = bool(_materialize_structuring_selector_return_branches_8616(project, codegen)) or changed
    changed = bool(
        _materialize_structuring_return_chains_8616(
            project,
            codegen,
            materialize_wide_return_predicate=False,
        )
    ) or changed
    # Call lowering may rebuild condition/loop subtrees from an older angr
    # tree. Replay already-proven direct stack effects before establishing
    # the Structuring validation baseline.
    advance_direct_stack_consumer_generation_8616(codegen)
    changed = bool(_apply_structuring_direct_stack_materialization_8616(project, codegen)) or changed
    changed = bool(_prime_structuring_segment_global_semantics_8616(project, codegen)) or changed
    changed = bool(_repair_structuring_synthetic_internal_calls_8616(project, codegen)) or changed
    changed = bool(_materialize_structuring_stdlib_call_chains_8616(project, codegen)) or changed
    changed = bool(reconcile_callsite_interface_declarations_8616(project, codegen)) or changed
    # Pointer-memory idioms are Types/Lowering facts. Materialize them
    # before loop Structuring and its per-pass validation baselines. The
    # post-Structuring replay remains an idempotence guard for rebuilt ASTs.
    changed = bool(_apply_structuring_pointer_memory_idioms_8616(project, codegen)) or changed
    changed = bool(_materialize_structuring_loop_idioms_8616(project, codegen)) or changed
    changed = bool(_repair_structuring_loop_exit_return_guards_8616(codegen)) or changed
    changed = bool(_repair_structuring_unresolved_function_exit_gotos_8616(project, codegen)) or changed
    changed = bool(_materialize_structuring_unconsumed_loop_break_jcc_8616(project, codegen)) or changed
    changed = bool(_repair_structuring_conditional_continue_guards_8616(project, codegen)) or changed
    changed = bool(_repair_structuring_pretest_loop_break_guards_8616(project, codegen)) or changed
    changed = bool(_repair_structuring_hoisted_jcc_target_copies_8616(project, codegen)) or changed
    changed = bool(_materialize_structuring_return_shape_8616(project, codegen)) or changed
    return changed


def _prime_terminal_return_shape_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
    terminal_call_return_changed: bool,
) -> bool:
    """Replay return-shape materialization only when terminal call-result changed."""
    if not terminal_call_return_changed:
        return False
    return bool(_materialize_structuring_return_shape_8616(project, codegen))


def _prime_return_closure_segment_replay_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
    switch_exit_changed: bool,
    terminal_call_return_changed: bool,
    terminal_return_shape_changed: bool,
) -> bool:
    """Replay segment/global semantics when the return closure mutated the AST."""
    if not structuring_return_closure_requires_segment_replay_8616(
        switch_exit_changed=switch_exit_changed,
        terminal_call_return_changed=terminal_call_return_changed,
        terminal_return_shape_changed=terminal_return_shape_changed,
    ):
        return False
    return bool(_prime_structuring_segment_global_semantics_8616(project, codegen))


def _prime_validation_pipeline_suffix_8616(
    project: AngrProjectSurface, codegen: AngrCodegenSurface, changed: bool
) -> bool:
    """Run the post-return-closure carriers, refresh, and publish phases."""
    changed = bool(prune_unread_stack_lowered_register_carriers_8616(codegen)) or changed
    # Loop, return, callsite, and Lowering replay above may replace C AST
    # subtrees after the early condition cleanup. Refresh exact owned
    # condition facts last so the validation baseline cannot retain stale
    # register carriers or pre-materialization guard expressions.
    changed = bool(_replay_structuring_lowering_after_condition_refresh_8616(project, codegen)) or changed
    # The refresh above may rebuild a condition from its typed CFG fact and
    # reintroduce pre-lowering stack or segment carriers. Match the
    # per-pass finalizer's refresh-then-Lowering order before fingerprinting.
    # The final Lowering replay can create a proven wide stack owner after
    # the preceding condition refresh. Rebind typed conditions once more
    # so their 16-bit projections consume that owner before fingerprinting.
    changed = bool(_replay_structuring_lowering_after_condition_refresh_8616(project, codegen)) or changed
    # Alias-backed copy propagation is Widening, not a semantic Structuring
    # delta. The declared pass remains an idempotent replay after the final
    # proof-consuming Lowering pass.
    changed = bool(_run_structuring_widening_copy_propagation_8616(codegen)) or changed
    changed = bool(prune_unread_stack_lowered_register_carriers_8616(codegen)) or changed
    # Later Structuring passes may replace the C AST while retaining the
    # selector-return marker. Reassert the exact CFG-proven projection last,
    # before validation captures the authoritative Structuring baseline.
    changed = bool(_materialize_structuring_selector_return_branches_8616(project, codegen)) or changed
    late_flag_cleanup = _structuring_conditions.prune_dead_flag_assignments_after_structuring_8616(
        project,
        codegen,
    )
    changed = late_flag_cleanup.changed or changed
    # The late FLAGS owner can retain or restore angr's pointer-shaped
    # high-byte register views inside packed-FLAGS expressions. Reconsume
    # those typed GP projections before the validation baseline is frozen.
    changed = _replay_structuring_gp_state_after_late_cleanup_8616(codegen) or changed
    # The terminal far-return frame pop is machine return semantics; its
    # structured CS carrier must leave the AST before the validation
    # baseline is frozen. Subtree rebuilds are re-pruned by the pass-table
    # copy of the same evidence-owned consumer.
    changed = (
        bool(consume_terminal_far_return_boundary_carriers_8616(project, codegen)) or changed
    )
    # Publish the callsite materialization contract before any per-pass
    # validation baseline is captured. Rebased direct slices can otherwise
    # expose complete generated calls while leaving validation with only
    # stale missing-callsite carriers.
    callsite_stats = getattr(codegen, "_inertia_callsite_materialization_stats", None)
    if callsite_stats is not None:
        codegen._inertia_callsite_materialization_complete_8616 = bool(
            int(getattr(callsite_stats, "classified_fact_count", 0) or 0) <= int(
                getattr(callsite_stats, "materialized_count", 0) or 0
            )
            and int(getattr(callsite_stats, "failure_count", 0) or 0) == 0
        )
    if changed:
        codegen._inertia_codegen_decl_refresh_required_8616 = True

    return changed


def _prime_structuring_validation_semantics_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> bool:
    """Prime proven Structuring consumers and report every resulting AST change."""
    if getattr(codegen, "_inertia_structuring_validation_semantics_primed", False):
        return False
    consumer_generation_scope = begin_direct_stack_consumer_generation_scope_8616(
        codegen
    )
    try:
        changed = _prime_validation_pipeline_prefix_8616(project, codegen)
        # Structuring passes above may rebuild subtrees from angr nodes that
        # predate typed segmented-global materialization. Replay the owning
        # Lowering stage before establishing the validation baseline.
        changed |= bool(_replay_structuring_lowering_before_validation_8616(project, codegen))
        switch_exit_changed = bool(
            _repair_structuring_switch_loop_exit_returns_8616(project, codegen)
        )
        changed |= switch_exit_changed
        terminal_call_return_changed = bool(
            _materialize_structuring_terminal_call_result_return_8616(
                project,
                codegen,
            )
        )
        changed |= terminal_call_return_changed
        terminal_return_shape_changed = _prime_terminal_return_shape_8616(
            project, codegen, terminal_call_return_changed
        )
        changed |= terminal_return_shape_changed
        # Final return/prototype shaping may rebuild expressions from an older
        # angr subtree after the general Lowering replay. Consume any recreated
        # segmented-global expressions at their owning Types/Lowering layer
        # before establishing the Structuring validation baseline.
        changed |= _prime_return_closure_segment_replay_8616(
            project,
            codegen,
            switch_exit_changed,
            terminal_call_return_changed,
            terminal_return_shape_changed,
        )
        changed = _prime_validation_pipeline_suffix_8616(project, codegen, changed)
        if changed:
            codegen._inertia_codegen_decl_refresh_required_8616 = True
    except PipelineHardError:
        raise
    except Exception as ex:
        changed = True
        log = logging.getLogger(__name__)
        report = log.warning if os.environ.get("INERTIA_DEBUG_POINTER_MEMORY_IDIOMS") == "1" else log.debug
        report(
            "Structuring validation semantic priming failed function=%#x: %s",
            int(cast(Any, codegen).cfunc.addr),
            ex,
        )
    finally:
        end_direct_stack_consumer_generation_scope_8616(
            codegen,
            consumer_generation_scope,
        )
        codegen._inertia_structuring_validation_semantics_primed = True
    return changed


def _refresh_structuring_condition_semantics_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
) -> _condition_refresh.StructuringConditionRefreshResult8616:
    """Delegate condition refresh to its typed, closed Structuring owner."""
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if not isinstance(func_addr, int):
        return _condition_refresh.StructuringConditionRefreshResult8616.stable()
    try:
        return _condition_refresh.refresh_structuring_condition_semantics_8616(
            project,
            codegen,
        )
    except PipelineHardError:
        raise
    except Exception as ex:
        logging.getLogger(__name__).debug(
            "Structuring condition semantic refresh failed function=%#x: %s",
            func_addr,
            ex,
        )
        return _condition_refresh.StructuringConditionRefreshResult8616.unclosed()


def _replay_structuring_lowering_after_condition_refresh_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
) -> bool:
    """Replay Lowering only when condition materialization changed the AST."""
    result = _refresh_structuring_condition_semantics_8616(project, codegen)
    lowering_changed = (
        bool(_replay_structuring_lowering_before_validation_8616(project, codegen))
        if result.requires_broad_lowering_replay
        else False
    )
    return lowering_changed or result.changed


def run_structuring_condition_cleanup_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface, func_addr: int) -> bool:
    """Transfer proven condition facts and run condition cleanup sequencing.

    This is the public stage-owned boundary for the condition cleanup sequence
    historically spelled out in CLI rewrite pass lists.  It transfers
    ``ConditionIR`` facts, then delegates materialization and legacy flag
    cleanup through ``structuring.condition_materialization``.
    """
    transferred = 0
    if not getattr(codegen, "_inertia_typed_conditions_transferred", False):
        transferred = int(transfer_typed_conditions_to_codegen_8616(project, func_addr, codegen) or 0)
        codegen._inertia_typed_conditions_transferred = True
    cleanup = _structuring_conditions.cleanup_structuring_conditions_after_replay_8616(project, codegen)
    try:
        codegen._inertia_condition_cleanup_structuring_pass_ran_8616 = True
        codegen._inertia_structuring_condition_cleanup_8616 = {
            "transferred_count": transferred,
            "typed_conditions_changed": cleanup.materialization.typed_conditions_changed,
            "decoded_jcc_changed": cleanup.materialization.decoded_jcc_changed,
            "flag_condition_pairs_changed": cleanup.flag_condition_pairs_changed,
            "flag_bit_values_changed": cleanup.flag_bit_values_changed,
            "interval_guards_changed": cleanup.interval_guards_changed,
            "unused_flag_assignments_pruned": cleanup.unused_flag_assignments_pruned,
            "overwritten_flag_assignments_pruned": cleanup.overwritten_flag_assignments_pruned,
            "changed": cleanup.changed,
            "owner": "structuring.stage",
        }
    except Exception:
        pass
    return bool(cleanup.changed)


def _regenerate_structuring_text_safely_8616(codegen: AngrCodegenSurface, *, context: str) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    render_text = getattr(codegen, "render_text", None)
    if cfunc is None or not callable(render_text):
        return False
    try:
        rendered = render_text(cfunc)
        if isinstance(rendered, tuple):
            rendered = rendered[0] if rendered and isinstance(rendered[0], str) else ""
        if isinstance(rendered, str) and rendered.strip():
            codegen.text = rendered
            mark_cfunction_ast_render_authority_8616(codegen)
            codegen._inertia_structuring_text_regenerated_8616 = (
                int(getattr(codegen, "_inertia_structuring_text_regenerated_8616", 0) or 0) + 1
            )
            codegen._inertia_structuring_text_regeneration_context_8616 = context
            return True
    except Exception as exc:
        codegen._inertia_structuring_text_regeneration_failed_8616 = True
        codegen._inertia_structuring_text_regeneration_error_8616 = str(exc)
    return False


def _is_structuring_call_chain_materialization_delta_8616(
    codegen: AngrCodegenSurface,
    validation: dict[str, object],
) -> bool:
    """Accept a typed call-chain rebuild that replaces missing callsite carriers.

    Structuring can rebuild a guarded call chain after lowering has already
    classified its callsites. Tail validation sees old ``missing-callsite``
    placeholders disappear and proven callees appear; it may also see a
    neutral condition shell replaced by a call-return condition. This is safe
    only when the relevant materializer reports complete evidence consumption
    and every helper added by the AST rebuild corresponds to an old carrier.
    The predicate deliberately does not infer meaning from rendered C text.
    """
    if not isinstance(validation, dict):
        return False
    gate = _call_chain_evidence_gate_8616(codegen)
    if gate is None:
        return False
    call_return_materialization_proven, call_return_stats = gate
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    touched = {
        key
        for key, field in delta.items()
        if isinstance(field, dict) and ((field.get("added") or ()) or (field.get("removed") or ()))
    }
    if touched - {"conditions", "helper_calls", "register_writes", "control_flow_effects"}:
        return False
    register_delta = delta.get("register_writes")
    if _call_chain_store_bridge_accept_8616(
        codegen,
        register_delta,
        touched,
        call_return_materialization_proven,
        call_return_stats,
    ):
        return True
    helpers = _call_chain_helper_deltas_8616(delta)
    if helpers is None:
        return False
    added_helpers, _removed_helpers = helpers
    if not _call_chain_condition_gate_8616(delta, added_helpers, call_return_materialization_proven):
        return False
    return _call_chain_residual_gate_8616(delta, register_delta, call_return_materialization_proven)


def _call_chain_evidence_gate_8616(
    codegen: AngrCodegenSurface,
) -> tuple[bool, object] | None:
    """Return (call-return-proven, stats) when the materialization evidence is complete."""
    call_return_stats = getattr(codegen, "_inertia_call_return_condition_stats_8616", None)
    call_return_materialization_proven = (
        int(getattr(call_return_stats, "classified_fact_count", 0) or 0) > 0
        and int(getattr(call_return_stats, "materialized_count", 0) or 0)
        >= int(getattr(call_return_stats, "classified_fact_count", 0) or 0)
        and int(getattr(call_return_stats, "failure_count", 0) or 0) == 0
    )
    stats = getattr(codegen, "_inertia_callsite_materialization_stats", None)
    if stats is not None:
        classified = int(getattr(stats, "classified_fact_count", 0) or 0)
        materialized = int(getattr(stats, "materialized_count", 0) or 0)
        failures = int(getattr(stats, "failure_count", 0) or 0)
        if (classified <= 0 or materialized < classified or failures != 0) and not call_return_materialization_proven:
            return None
    else:
        summaries = getattr(codegen, "_inertia_callsite_summaries", None)
        if not (
            isinstance(summaries, dict)
            and summaries
            and bool(getattr(codegen, "_inertia_callsite_stack_arguments_structuring_pass_ran_8616", False))
        ) and not call_return_materialization_proven:
            return None
    return call_return_materialization_proven, call_return_stats


def _call_chain_store_bridge_accept_8616(
    codegen: AngrCodegenSurface,
    register_delta: object,
    touched: set[str],
    call_return_materialization_proven: bool,
    call_return_stats: object,
) -> bool:
    """Accept a pure register-writes delta covered by proven store-bridge carriers."""
    store_bridge_count = int(getattr(call_return_stats, "store_bridge_materialized_count", 0) or 0)
    return_registers = tuple(getattr(call_return_stats, "store_bridge_return_registers", ()) or ())
    if not (
        call_return_materialization_proven
        and store_bridge_count > 0
        and touched == {"register_writes"}
        and isinstance(register_delta, dict)
        and not tuple(register_delta.get("added") or ())
    ):
        return False
    project = getattr(codegen, "project", None)
    arch = getattr(project, "arch", None)
    registers = getattr(arch, "registers", None)
    allowed_register_tokens = _return_register_alias_tokens_8616(registers, return_registers)
    removed_registers = tuple(register_delta.get("removed") or ())
    return bool(removed_registers) and set(removed_registers) <= allowed_register_tokens


def _return_register_alias_tokens_8616(registers: object, return_registers: tuple[object, ...]) -> set[str]:
    """Return reg: token aliases covering each proven store-bridge return register."""
    allowed: set[str] = set()
    if not isinstance(registers, dict):
        return allowed
    for return_register in return_registers:
        register = registers.get(return_register)
        if not isinstance(register, tuple) or len(register) < 2:
            continue
        offset, width = register[:2]
        if not isinstance(offset, int) or not isinstance(width, int):
            continue
        allowed.update(
            f"reg:{name.lower()}"
            for name, alias in registers.items()
            if isinstance(name, str)
            and isinstance(alias, tuple)
            and len(alias) >= 2
            and alias[0] == offset
            and isinstance(alias[1], int)
            and alias[1] >= width
        )
    return allowed


def _call_chain_target_token_8616(item: str, prefix: str) -> str:
    """Normalize one helper token to its lowercase call target."""
    value = item[len(prefix) :]
    if value.startswith("addr:"):
        value = value[len("addr:") :]
    value = value.split(":", 1)[0]
    return value.lower()


def _call_chain_helper_deltas_8616(
    delta: dict[str, object],
) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    """Return added/removed helper tokens only for a carrier-rebuild shape."""
    helper_delta = delta.get("helper_calls")
    if not isinstance(helper_delta, dict):
        return None
    added_helpers = tuple(str(item) for item in tuple(helper_delta.get("added") or ()))
    removed_helpers = tuple(str(item) for item in tuple(helper_delta.get("removed") or ()))
    if not added_helpers or not removed_helpers:
        return None
    if not all(item.startswith("addr:") for item in added_helpers):
        return None
    if not all(item.startswith("missing-callsite:addr:") for item in removed_helpers):
        return None
    if Counter(_call_chain_target_token_8616(item, "addr:") for item in added_helpers) != Counter(
        _call_chain_target_token_8616(item, "missing-callsite:") for item in removed_helpers
    ):
        return None
    return added_helpers, removed_helpers


def _call_chain_condition_gate_8616(
    delta: dict[str, object],
    added_helpers: tuple[str, ...],
    call_return_materialization_proven: bool,
) -> bool:
    """Gate added call conditions against the proven helper-target multiset."""
    if not call_return_materialization_proven:
        return True
    condition_delta = delta.get("conditions")
    if not isinstance(condition_delta, dict):
        return False
    added_conditions = tuple(str(item) for item in tuple(condition_delta.get("added") or ()))
    removed_conditions = tuple(str(item) for item in tuple(condition_delta.get("removed") or ()))
    if not (added_conditions or removed_conditions):
        return True
    if not added_conditions:
        return False
    helper_targets = Counter(_call_chain_target_token_8616(item, "addr:") for item in added_helpers)
    condition_targets: Counter[str] = Counter()
    for condition in added_conditions:
        for helper_target in helper_targets:
            marker = f"call:addr:{helper_target}"
            occurrences = condition.count(marker)
            condition_targets[helper_target] += occurrences
        if not any(condition.count(f"call:addr:{target}") for target in helper_targets):
            return False
    if condition_targets != helper_targets:
        return False
    return not any(
        condition not in {"CmpNE(const:1,const:0)", "CmpNE(const:True,const:0)"}
        for condition in removed_conditions
    )


def _call_chain_residual_gate_8616(
    delta: dict[str, object],
    register_delta: object,
    call_return_materialization_proven: bool,
) -> bool:
    """Gate residual register/control-flow effects for the call-chain rebuild."""
    if isinstance(register_delta, dict):
        if tuple(register_delta.get("added") or ()):
            return False
        if set(register_delta.get("removed") or ()) - {"reg:ax"}:
            return False
    control_delta = delta.get("control_flow_effects")
    if isinstance(control_delta, dict):
        effects: tuple[object, ...] = tuple(control_delta.get("added") or ()) + tuple(control_delta.get("removed") or ())
        allowed_prefixes = (
            "for-body-calls:",
            "if-body-calls:",
            "if-else-body-calls:",
            "if:",
        ) if call_return_materialization_proven else ("if-else-body-calls:",)
        if not effects or not all(isinstance(item, str) and item.startswith(allowed_prefixes) for item in effects):
            return False
    return True


def _accept_structuring_delta_8616(validation: dict[str, object], spec_name: str) -> bool:
    """Mark a validation delta as accepted-stable and return True."""
    validation["changed"] = False
    validation["status"] = "stable"
    validation["summary_text"] = "no observable whole-tail changes"
    validation.pop("delta", None)
    validation["verdict"] = build_x86_16_tail_validation_verdict(
        f"structuring:{spec_name}", validation
    )
    return True


def _bump_validation_accept_8616(codegen: AngrCodegenSurface, name: str) -> None:
    """Increment a dynamic codegen boundary validation-accept counter."""
    setattr(codegen, name, int(getattr(codegen, name, 0) or 0) + 1)


def _append_validation_delta_8616(
    codegen: AngrCodegenSurface, name: str, entry: dict[str, object]
) -> None:
    """Append one accepted-delta record to a dynamic codegen boundary tuple."""
    previous = getattr(codegen, name, ()) or ()
    accepted = list(previous)
    accepted.append(entry)
    setattr(codegen, name, tuple(accepted))


_VOID_TAIL_CALL_ALLOWED_PREFIXES_8616 = ("if-body-calls:", "if-else-body-calls:else:")


def _void_tail_call_targets_8616(effect: str) -> tuple[int, ...]:
    """Extract addr:0x call targets from one allowed control-flow effect string."""
    if not effect.startswith(_VOID_TAIL_CALL_ALLOWED_PREFIXES_8616):
        return ()
    targets: list[int] = []
    offset = 0
    token = "addr:0x"
    while True:
        pos = effect.find(token, offset)
        if pos < 0:
            break
        start = pos + len(token)
        end = start
        while end < len(effect) and effect[end].lower() in "0123456789abcdef":
            end += 1
        if end > start:
            targets.append(int(effect[start:end], 16))
        offset = end
    return tuple(targets)


def _void_tail_call_target_multiset_8616(effects: tuple[str, ...]) -> Counter[int]:
    """Return the call-target multiset for a list of effects, empty on disallowed shapes."""
    targets: Counter[int] = Counter()
    for effect in effects:
        effect_targets = _void_tail_call_targets_8616(effect)
        if not effect_targets:
            return Counter()
        targets.update(effect_targets)
    return targets


def _void_tail_call_suffix_diamond_delta_8616(
    added: tuple[str, ...], removed: tuple[str, ...]
) -> bool:
    """Return whether added/removed call effects share the same target multiset."""
    added_targets = _void_tail_call_target_multiset_8616(added)
    removed_targets = _void_tail_call_target_multiset_8616(removed)
    return bool(added_targets) and added_targets == removed_targets


def _void_tail_call_guard_structuring_delta_8616(
    codegen: AngrCodegenSurface, validation: dict[str, object]
) -> bool:
    """Return whether the delta matches a proven void tail-call guard materialization."""
    if int(getattr(codegen, "_inertia_void_tail_call_guard_materialized_8616", 0) or 0) <= 0:
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    for field_name in (
        "conditions",
        "global_writes",
        "helper_calls",
        "register_writes",
        "returns",
        "segmented_writes",
        "stack_writes",
    ):
        field_delta = delta.get(field_name)
        if not isinstance(field_delta, dict):
            continue
        if tuple(field_delta.get("added", ()) or ()) or tuple(field_delta.get("removed", ()) or ()):
            return False
    control_delta = delta.get("control_flow_effects")
    if not isinstance(control_delta, dict):
        return False
    added = tuple(str(item) for item in tuple(control_delta.get("added", ()) or ()))
    removed = tuple(str(item) for item in tuple(control_delta.get("removed", ()) or ()))
    if not added or not removed:
        return False
    decision = getattr(codegen, "_inertia_void_tail_call_guard_decision_8616", None)
    if decision == _VoidTailCallGuardDecision8616.MATERIALIZE_SUFFIX_DIAMOND.value:
        return _void_tail_call_suffix_diamond_delta_8616(added, removed)

    if not all(item.startswith("if-body-calls:") for item in added):
        return False
    allowed_removed_prefixes = ("if-else-body-calls:else:",)
    allowed_removed_exact = {"if:else"}
    return all(
        item in allowed_removed_exact or item.startswith(allowed_removed_prefixes)
        for item in removed
    )


def _accept_callsite_completeness_delta_8616(
    codegen: AngrCodegenSurface,
    validation: dict[str, object],
    spec_name: str,
    before_summary: TailValidationCallsiteSummary8616 | None,
    after_summary: TailValidationCallsiteSummary8616 | None,
) -> bool:
    """Classify the callsite completeness delta and accept it when complete."""
    if before_summary is None or after_summary is None:
        return False
    completeness = classify_callsite_completeness_delta_8616(
        before_summary,
        after_summary,
        validation,
    )
    codegen._inertia_structuring_callsite_completeness_delta_8616 = completeness
    validation["callsite_completeness_delta"] = completeness.as_dict()
    if not completeness.accepted:
        return False
    return _accept_structuring_delta_8616(validation, spec_name)


def _accept_identical_return_guard_delta_8616(
    codegen: AngrCodegenSurface, validation: dict[str, object], spec_name: str
) -> bool:
    """Consume the identical-return-guard collapse result and accept a clean delta."""
    identical_return_result = getattr(
        codegen, "_inertia_identical_return_guard_collapse_result_8616", None
    )
    identical_return_validation = consume_identical_return_guard_validation_delta_8616(
        identical_return_result,
        validation,
    )
    codegen._inertia_identical_return_guard_validation_result_8616 = identical_return_validation
    if not (
        identical_return_validation.accepted
        and not identical_return_validation.residual_changed
    ):
        return False
    validation["verdict"] = build_x86_16_tail_validation_verdict(
        f"structuring:{spec_name}",
        validation,
    )
    return True


def _accept_frame_prune_delta_8616(
    codegen: AngrCodegenSurface, validation: dict[str, object], spec_name: str
) -> bool:
    """Accept a callee-saved frame prune delta when the record proves it."""
    frame_prune_record = getattr(
        codegen, "_inertia_callee_saved_frame_prune_record_8616", None
    )
    if not callee_saved_frame_prune_delta_8616(
        frame_prune_record
        if isinstance(frame_prune_record, CalleeSavedFramePruneRecord8616)
        else None,
        validation,
    ):
        return False
    _bump_validation_accept_8616(
        codegen, "_inertia_structuring_callee_saved_frame_validation_accepts_8616"
    )
    return _accept_structuring_delta_8616(validation, spec_name)


def _accept_switch_tail_delta_8616(
    codegen: AngrCodegenSurface, validation: dict[str, object], spec_name: str
) -> bool:
    """Consume the switch loop-tail break result and accept a clean delta."""
    switch_tail_result = getattr(
        codegen, "_inertia_structuring_switch_loop_tail_break_result_8616", None
    )
    switch_tail_validation = consume_switch_loop_tail_break_validation_delta_8616(
        switch_tail_result
        if isinstance(switch_tail_result, SwitchLoopTailBreakResult8616)
        else None,
        validation,
    )
    if not switch_tail_validation.accepted:
        return False
    _bump_validation_accept_8616(
        codegen, "_inertia_structuring_switch_loop_tail_break_validation_accepts_8616"
    )
    if not switch_tail_validation.residual_changed:
        validation["summary_text"] = "no observable whole-tail changes"
        validation.pop("delta", None)
        validation["verdict"] = build_x86_16_tail_validation_verdict(
            f"structuring:{spec_name}", validation
        )
        return True
    validation["verdict"] = build_x86_16_tail_validation_verdict(
        f"structuring:{spec_name}", validation
    )
    return False


def _codegen_function_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> object:
    """Resolve the angr function for the current codegen boundary, if available."""
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    functions = getattr(getattr(project, "kb", None), "functions", None)
    if not isinstance(func_addr, int) or functions is None:
        return None
    with contextlib.suppress(Exception):
        return functions.function(addr=func_addr, create=False)
    return None


def _accept_terminal_return_delta_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
    validation: dict[str, object],
    spec_name: str,
) -> bool:
    """Consume the terminal return-value materialization result and accept its delta."""
    terminal_return_materialization = getattr(
        codegen, "_inertia_terminal_return_value_materialization_result_8616", None
    )
    if not isinstance(
        terminal_return_materialization,
        _terminal_register_values.TerminalReturnValueMaterializationResult8616,
    ):
        terminal_return_materialization = None
    terminal_return_validation = terminal_return_value_validation_delta_8616(
        project,
        codegen,
        terminal_return_materialization,
        validation,
    )
    codegen._inertia_terminal_return_value_validation_result_8616 = terminal_return_validation
    if not terminal_return_validation.accepted:
        return False
    _bump_validation_accept_8616(
        codegen, "_inertia_structuring_terminal_return_validation_accepts_8616"
    )
    return _accept_structuring_delta_8616(validation, spec_name)


def _accept_selector_return_delta_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
    validation: dict[str, object],
    spec_name: str,
    is_selector_delta: Callable[..., bool],
) -> bool:
    """Accept a selector-return expression-chain materialization delta."""
    if not is_selector_delta(project, None, codegen, validation):
        return False
    _bump_validation_accept_8616(
        codegen, "_inertia_structuring_selector_return_validation_accepts_8616"
    )
    delta = validation.get("delta")
    if isinstance(delta, dict):
        _append_validation_delta_8616(
            codegen,
            "_inertia_structuring_selector_return_validation_deltas_8616",
            {
                "conditions": delta.get("conditions"),
                "control_flow_effects": delta.get("control_flow_effects"),
                "helper_calls": delta.get("helper_calls"),
                "returns": delta.get("returns"),
                "stage": f"structuring:{spec_name}",
            },
        )
    return _accept_structuring_delta_8616(validation, spec_name)


def _accept_call_chain_delta_8616(
    codegen: AngrCodegenSurface, validation: dict[str, object], spec_name: str
) -> bool:
    """Accept a structuring call-chain materialization delta."""
    if not _is_structuring_call_chain_materialization_delta_8616(codegen, validation):
        return False
    _bump_validation_accept_8616(
        codegen, "_inertia_structuring_call_chain_validation_accepts_8616"
    )
    return _accept_structuring_delta_8616(validation, spec_name)


def _accept_wide_stack_predicate_delta_8616(
    codegen: AngrCodegenSurface, validation: dict[str, object], spec_name: str
) -> bool:
    """Accept a proven wide-stack return-predicate delta."""
    wide_predicate_result = getattr(
        codegen,
        "_inertia_wide_stack_return_predicate_result_8616",
        None,
    )
    if not wide_stack_return_predicate_validation_delta_is_proven_8616(
        wide_predicate_result,
        validation,
    ):
        return False
    _bump_validation_accept_8616(
        codegen, "_inertia_structuring_wide_stack_predicate_validation_accepts_8616"
    )
    return _accept_structuring_delta_8616(validation, spec_name)


def _accept_dword_zero_test_delta_8616(
    codegen: AngrCodegenSurface, validation: dict[str, object], spec_name: str
) -> bool:
    """Accept the dword global zero-test materialization delta when proven."""
    record = getattr(codegen, "_inertia_dword_global_zero_test_materialization_record_8616", None)
    if not (
        isinstance(record, DwordGlobalZeroTestMaterializationRecord8616)
        and dword_global_zero_test_precision_delta_8616(
            record.materialized_count,
            record.evidence,
            validation,
        )
    ):
        return False
    _bump_validation_accept_8616(
        codegen, "_inertia_structuring_dword_zero_test_validation_accepts_8616"
    )
    return _accept_structuring_delta_8616(validation, spec_name)


def _accept_indexed_read_delta_8616(
    codegen: AngrCodegenSurface, validation: dict[str, object], spec_name: str
) -> bool:
    """Accept the indexed global-read carrier materialization delta when proven."""
    record = getattr(codegen, "_inertia_indexed_global_read_carrier_record_8616", None)
    if not (
        isinstance(record, IndexedGlobalReadCarrierMaterializationRecord8616)
        and indexed_global_read_carrier_precision_delta_8616(record, validation)
    ):
        return False
    _bump_validation_accept_8616(
        codegen, "_inertia_structuring_indexed_global_read_validation_accepts_8616"
    )
    return _accept_structuring_delta_8616(validation, spec_name)


def _accept_indexed_global_delta_8616(
    codegen: AngrCodegenSurface, validation: dict[str, object], spec_name: str
) -> bool:
    """Accept the indexed segmented-global materialization delta when proven."""
    record = getattr(codegen, "_inertia_indexed_global_materialization_record_8616", None)
    accepted = (
        isinstance(record, IndexedSegmentedGlobalMaterializationRecord8616)
        and all(isinstance(item, IndexedSegmentedGlobalEvidence8616) for item in record.evidence)
        and indexed_segmented_global_precision_delta_8616(
            record.materialized_count,
            record.evidence,
            validation,
        )
    )
    if os.environ.get("INERTIA_DEBUG_SEGMENTED_GLOBAL_LOADS"):
        logging.getLogger(__name__).warning(
            "[structuring-indexed-validation] accepted=%s record=%r delta=%r",
            accepted,
            record,
            validation.get("delta"),
        )
    if not accepted:
        return False
    _bump_validation_accept_8616(
        codegen, "_inertia_structuring_indexed_global_validation_accepts_8616"
    )
    return _accept_structuring_delta_8616(validation, spec_name)


def _accept_pointer_swap_delta_8616(
    codegen: AngrCodegenSurface, validation: dict[str, object], spec_name: str
) -> bool:
    """Accept the pointer-swap splice delta when it is precision-only."""
    stats = getattr(codegen, "_inertia_pointer_swap_splice_stats_8616", None)
    if not (
        isinstance(stats, PointerSwapSpliceStats8616)
        and pointer_swap_validation_delta_is_precision_only_8616(stats, validation)
    ):
        return False
    codegen._inertia_structuring_pointer_swap_validation_accepts_8616 = 1
    return _accept_structuring_delta_8616(validation, spec_name)


def _pointer_memory_arm_8616(
    codegen: AngrCodegenSurface, validation: dict[str, object], spec_name: str
) -> bool | None:
    """Return accept for a proven pointer-memory idiom delta, refuse on segmented writes."""
    facts = getattr(codegen, "_inertia_pointer_memory_idiom_facts_8616", ())
    fact = (
        facts[0]
        if isinstance(facts, tuple)
        and len(facts) == 1
        and isinstance(facts[0], PointerMemoryIdiomMaterializationFact8616)
        else None
    )
    if fact is None:
        return None
    delta = validation.get("delta")
    segmented_delta = delta.get("segmented_writes") if isinstance(delta, dict) else None
    segmented_changed = isinstance(segmented_delta, dict) and bool(
        segmented_delta.get("added") or segmented_delta.get("removed")
    )
    if pointer_memory_loop_validation_delta_is_precision_only_8616(fact, validation):
        codegen._inertia_structuring_pointer_memory_validation_accepts_8616 = 1
        return _accept_structuring_delta_8616(validation, spec_name)
    if segmented_changed:
        return False
    return None


def _accept_void_tail_call_guard_delta_8616(
    codegen: AngrCodegenSurface, validation: dict[str, object], spec_name: str
) -> bool:
    """Accept a proven void tail-call guard materialization delta."""
    if not _void_tail_call_guard_structuring_delta_8616(codegen, validation):
        return False
    _bump_validation_accept_8616(
        codegen, "_inertia_structuring_void_tail_call_guard_validation_accepts_8616"
    )
    delta = validation.get("delta")
    if isinstance(delta, dict):
        _append_validation_delta_8616(
            codegen,
            "_inertia_structuring_void_tail_call_guard_validation_deltas_8616",
            {
                "control_flow_effects": delta.get("control_flow_effects"),
                "stage": f"structuring:{spec_name}",
            },
        )
    return _accept_structuring_delta_8616(validation, spec_name)


def _accept_loop_header_guard_delta_8616(
    codegen: AngrCodegenSurface, validation: dict[str, object], spec_name: str
) -> bool:
    """Accept a loop-header duplicate-guard removal delta for gated passes."""
    facts = (
        loop_header_duplicate_guard_removal_facts_8616(codegen)
        if spec_name in {"_unconsumed_loop_break_jcc_materialization_8616", "final"}
        else ()
    )
    if not loop_header_duplicate_guard_removal_delta_8616(facts, validation):
        return False
    _bump_validation_accept_8616(
        codegen, "_inertia_structuring_loop_header_duplicate_guard_validation_accepts_8616"
    )
    return _accept_structuring_delta_8616(validation, spec_name)


def _accept_loop_exit_guard_delta_8616(
    codegen: AngrCodegenSurface, validation: dict[str, object], spec_name: str
) -> bool:
    """Accept a loop-exit return-guard repair delta when repaired guards exist."""
    stats = getattr(codegen, "_inertia_loop_exit_guard_stats_8616", None)
    repaired = int(stats.get("repaired", 0) or 0) if isinstance(stats, dict) else 0
    if not (repaired > 0 and loop_exit_return_guard_repair_delta_8616(repaired, validation)):
        return False
    _bump_validation_accept_8616(
        codegen, "_inertia_structuring_loop_exit_return_guard_validation_accepts_8616"
    )
    return _accept_structuring_delta_8616(validation, spec_name)


def _accept_stack_move_update_delta_8616(
    codegen: AngrCodegenSurface,
    validation: dict[str, object],
    spec_name: str,
    is_move_delta: Callable[..., bool],
    is_update_delta: Callable[..., bool],
) -> bool:
    """Accept a direct stack move/update materialization delta."""
    move_accepted = is_move_delta(codegen, validation)
    update_accepted = is_update_delta(codegen, validation)
    if os.environ.get("INERTIA_DEBUG_STACK_NOISE"):
        logging.getLogger(__name__).warning(
            "[structuring-stack-validation] move=%s update=%s stats=%r evidence=%r delta=%r",
            move_accepted,
            update_accepted,
            getattr(codegen, "_inertia_direct_stack_move_lowering_8616", None),
            getattr(codegen, "_inertia_direct_stack_move_evidence_8616", None),
            validation.get("delta"),
        )
    if not (move_accepted or update_accepted):
        return False
    if move_accepted:
        _bump_validation_accept_8616(
            codegen, "_inertia_structuring_direct_stack_move_validation_accepts_8616"
        )
    if update_accepted:
        _bump_validation_accept_8616(
            codegen, "_inertia_structuring_direct_stack_update_validation_accepts_8616"
        )
    delta = validation.get("delta")
    if isinstance(delta, dict):
        entry = {
            "conditions": delta.get("conditions"),
            "control_flow_effects": delta.get("control_flow_effects"),
            "segmented_writes": delta.get("segmented_writes"),
            "stack_writes": delta.get("stack_writes"),
            "stage": f"structuring:{spec_name}",
        }
        previous = getattr(
            codegen,
            "_inertia_structuring_direct_stack_move_validation_deltas_8616"
            if move_accepted
            else "_inertia_structuring_direct_stack_update_validation_deltas_8616",
            (),
        )
        accepted = (*previous, entry) if previous else (entry,)
        if move_accepted:
            codegen._inertia_structuring_direct_stack_move_validation_deltas_8616 = accepted
        if update_accepted:
            codegen._inertia_structuring_direct_stack_update_validation_deltas_8616 = accepted
    return _accept_structuring_delta_8616(validation, spec_name)


def _accept_precision_closure_delta_8616(
    codegen: AngrCodegenSurface, validation: dict[str, object], spec_name: str
) -> bool:
    """Accept a condition-precision or closure-complete validation delta."""
    precision_result = condition_precision_validation_delta_8616(codegen, validation)
    closure = getattr(codegen, "_inertia_structuring_condition_evidence_closure_8616", None)
    closure_result = validate_condition_closure_delta_8616(closure, validation)
    codegen._inertia_structuring_condition_closure_validation_result_8616 = closure_result
    closure_complete = (
        closure is not None and bool(closure.required_keys) and closure.complete
    )
    if not (
        (precision_result.accepted and closure_complete)
        or (spec_name == "final" and closure_result.accepted)
    ):
        return False
    if precision_result.accepted:
        codegen._inertia_structuring_condition_precision_validation_accepts_8616 = 1
    if closure_result.accepted:
        codegen._inertia_structuring_condition_closure_validation_accepts_8616 = 1
    return _accept_structuring_delta_8616(validation, spec_name)


def _accept_jcc_condition_delta_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
    validation: dict[str, object],
    function: object,
    spec_name: str,
    is_jcc_delta: Callable[..., bool],
) -> bool:
    """Accept a JCC condition materialization delta when proven."""
    if not is_jcc_delta(
        project,
        codegen,
        validation,
        function=function,
    ):
        return False
    _bump_validation_accept_8616(
        codegen, "_inertia_structuring_jcc_condition_validation_accepts_8616"
    )
    delta = validation.get("delta")
    if isinstance(delta, dict):
        _append_validation_delta_8616(
            codegen,
            "_inertia_structuring_jcc_condition_validation_deltas_8616",
            {
                "conditions": delta.get("conditions"),
                "control_flow_effects": delta.get("control_flow_effects"),
                "stage": f"structuring:{spec_name}",
            },
        )
    return _accept_structuring_delta_8616(validation, spec_name)


def _postprocess_delta_predicates_8616(
    codegen: AngrCodegenSurface,
    validation: dict[str, object],
    spec_name: str,
) -> tuple[Callable[..., bool], ...] | None:
    """Debug-log the loop-guard context and import postprocess delta predicates."""
    if os.environ.get("INERTIA_DEBUG_LOOP_GUARD_VALIDATION") == "1":
        logging.getLogger(__name__).warning(
            "[structuring-loop-guard-validation] pass=%s branch_facts=%r "
            "removal_facts=%r delta=%r semantic_failures=%r callsite_completeness=%r",
            spec_name,
            loop_branch_guard_facts_8616(codegen),
            loop_header_duplicate_guard_removal_facts_8616(codegen),
            validation.get("delta"),
            validation.get("semantic_failures"),
            validation.get("callsite_completeness_delta"),
        )
    try:
        from .decompiler_postprocess_stage import (
            _is_cfg_return_expr_chain_materialization_delta_8616,
            _is_direct_stack_move_materialization_delta_8616,
            _is_direct_stack_update_materialization_delta_8616,
            _is_jcc_condition_materialization_validation_delta_8616,
        )
    except Exception:
        return None
    return (
        _is_cfg_return_expr_chain_materialization_delta_8616,
        _is_direct_stack_move_materialization_delta_8616,
        _is_direct_stack_update_materialization_delta_8616,
        _is_jcc_condition_materialization_validation_delta_8616,
    )


def _accept_result_consumption_deltas_8616(
    codegen: AngrCodegenSurface, validation: dict[str, object], spec_name: str
) -> bool:
    """Accept deltas proven by consumed structuring results."""
    return (
        _accept_identical_return_guard_delta_8616(codegen, validation, spec_name)
        or _accept_frame_prune_delta_8616(codegen, validation, spec_name)
        or _accept_switch_tail_delta_8616(codegen, validation, spec_name)
    )


def _accept_materialization_deltas_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
    validation: dict[str, object],
    spec_name: str,
    is_selector_delta: Callable[..., bool],
) -> bool:
    """Accept deltas proven by materialization records and predicates."""
    return (
        _accept_terminal_return_delta_8616(project, codegen, validation, spec_name)
        or _accept_selector_return_delta_8616(
            project, codegen, validation, spec_name, is_selector_delta
        )
        or _accept_call_chain_delta_8616(codegen, validation, spec_name)
        or _accept_wide_stack_predicate_delta_8616(codegen, validation, spec_name)
    )


def _accept_indexed_write_deltas_8616(
    codegen: AngrCodegenSurface, validation: dict[str, object], spec_name: str
) -> bool | None:
    """Accept indexed/pointer write deltas; None keeps the ladder running."""
    if _accept_dword_zero_test_delta_8616(codegen, validation, spec_name):
        return True
    if _accept_indexed_read_delta_8616(codegen, validation, spec_name):
        return True
    if _accept_indexed_global_delta_8616(codegen, validation, spec_name):
        return True
    if _accept_pointer_swap_delta_8616(codegen, validation, spec_name):
        return True
    return _pointer_memory_arm_8616(codegen, validation, spec_name)


def _accept_loop_repair_deltas_8616(
    codegen: AngrCodegenSurface, validation: dict[str, object], spec_name: str
) -> bool:
    """Accept deltas proven by void tail-call and loop-guard repairs."""
    return (
        _accept_void_tail_call_guard_delta_8616(codegen, validation, spec_name)
        or _accept_loop_header_guard_delta_8616(codegen, validation, spec_name)
        or _accept_loop_exit_guard_delta_8616(codegen, validation, spec_name)
    )


def _accept_residual_deltas_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
    validation: dict[str, object],
    function: object,
    spec_name: str,
    is_move_delta: Callable[..., bool],
    is_update_delta: Callable[..., bool],
    is_jcc_delta: Callable[..., bool],
) -> bool:
    """Accept stack-update, condition-closure, or JCC materialization deltas."""
    if _accept_stack_move_update_delta_8616(
        codegen, validation, spec_name, is_move_delta, is_update_delta
    ):
        return True
    if _accept_precision_closure_delta_8616(codegen, validation, spec_name):
        return True
    return _accept_jcc_condition_delta_8616(
        project, codegen, validation, function, spec_name, is_jcc_delta
    )


def _try_accept_structuring_validation_delta_from_evidence_8616(
    project: AngrProjectSurface,
    codegen: AngrCodegenSurface,
    validation: dict[str, object],
    *,
    spec_name: str,
    before_summary: TailValidationCallsiteSummary8616 | None = None,
    after_summary: TailValidationCallsiteSummary8616 | None = None,
) -> bool:
    """Accept a structuring delta only through an existing consumed-evidence validator."""
    if not isinstance(validation, dict) or x86_16_tail_validation_result_passed(validation):
        return False
    if _accept_callsite_completeness_delta_8616(
        codegen, validation, spec_name, before_summary, after_summary
    ):
        return True
    predicates = _postprocess_delta_predicates_8616(codegen, validation, spec_name)
    if predicates is None:
        return False
    is_cfg_return_delta, is_move_delta, is_update_delta, is_jcc_delta = predicates

    if _accept_result_consumption_deltas_8616(codegen, validation, spec_name):
        return True
    function = _codegen_function_8616(project, codegen)
    if _accept_materialization_deltas_8616(
        project, codegen, validation, spec_name, is_cfg_return_delta
    ):
        return True
    indexed_verdict = _accept_indexed_write_deltas_8616(codegen, validation, spec_name)
    if indexed_verdict is not None:
        return indexed_verdict
    if _accept_loop_repair_deltas_8616(codegen, validation, spec_name):
        return True
    return _accept_residual_deltas_8616(
        project,
        codegen,
        validation,
        function,
        spec_name,
        is_move_delta,
        is_update_delta,
        is_jcc_delta,
    )


def _maybe_validate_structuring_pass_8616(
    project: AngrProjectSurface, codegen: AngrCodegenSurface, spec_name: str
) -> Callable[[bool], None] | None:
    if not bool(getattr(project, "_inertia_tail_validation_enabled", True)):
        return None
    validate_all = os.environ.get("INERTIA_VALIDATE_ALL_STRUCTURING_PASSES") == "1"
    skip_reason = _structuring_pass_validation_skip_reason_8616(project, codegen)
    if not validate_all and skip_reason is not None:
        codegen._inertia_structuring_pass_validation_skipped_large_function_8616 = True
        codegen._inertia_structuring_pass_validation_skip_reason_8616 = skip_reason
        return None
    if not validate_all and spec_name not in _semantic_validation_pass_names_8616():
        return None

    mode = "live_out"
    _prime_structuring_validation_semantics_8616(project, codegen)
    _ensure_structuring_typed_conditions_transferred_8616(project, codegen)
    _materialize_structuring_selector_return_branches_8616(project, codegen)
    before_fingerprint = fingerprint_x86_16_tail_validation_boundary(project, codegen, mode=mode)
    before_summary = collect_x86_16_tail_validation_summary(
        project,
        codegen,
        mode=mode,
        boundary_fingerprint=before_fingerprint,
    )
    return _StructuringPassValidation8616(
        project,
        codegen,
        spec_name,
        mode,
        before_fingerprint,
        before_summary,
    ).finalize


@dataclass
class _StructuringPassValidation8616:
    """Per-pass tail-validation closure bound to its captured baseline."""

    project: AngrProjectSurface
    codegen: AngrCodegenSurface
    spec_name: str
    mode: str
    before_fingerprint: str
    before_summary: X86_16TailValidationSummary

    def finalize(self, pass_changed: bool) -> None:
        """Close the per-pass tail-validation comparison and publish its result."""
        # Only a reported AST mutation needs closure. Semantic no-op passes are
        # still validated, but cannot invalidate the already-primed surface.
        if pass_changed:
            self._replay_changed_pass_repairs()
        after_fingerprint = fingerprint_x86_16_tail_validation_boundary(
            self.project, self.codegen, mode=self.mode
        )
        after_summary = collect_x86_16_tail_validation_summary(
            self.project,
            self.codegen,
            mode=self.mode,
            boundary_fingerprint=after_fingerprint,
        )
        validation = build_x86_16_tail_validation_cached_result(
            owner=None,
            stage=f"structuring:{self.spec_name}",
            mode=self.mode,
            before_fingerprint=self.before_fingerprint,
            after_fingerprint=after_fingerprint,
            before_summary=self.before_summary,
            after_summary=after_summary,
            semantic_failure_scope=TailSemanticFailureScope8616.INTRODUCED,
        )
        validation["verdict"] = build_x86_16_tail_validation_verdict(
            f"structuring:{self.spec_name}", validation
        )
        self._publish(validation, after_summary)

    def _replay_changed_pass_repairs(self) -> None:
        """Re-run proof-consuming repairs after a reported AST mutation."""
        if self.spec_name == "_unconsumed_loop_break_jcc_materialization_8616":
            _materialize_structuring_unconsumed_loop_break_jcc_8616(
                self.project,
                self.codegen,
            )
        _replay_structuring_lowering_after_condition_refresh_8616(self.project, self.codegen)
        _repair_structuring_switch_loop_exit_returns_8616(self.project, self.codegen)
        _materialize_structuring_selector_return_branches_8616(self.project, self.codegen)

    def _publish(
        self,
        validation: dict[str, object],
        after_summary: TailValidationCallsiteSummary8616 | None,
    ) -> None:
        """Attempt evidence acceptance, store the result, and mark failures."""
        codegen = self.codegen
        existing = getattr(codegen, "_inertia_structuring_pass_validation", None)
        if not isinstance(existing, dict):
            existing = {}
            codegen._inertia_structuring_pass_validation = existing
        if _try_accept_structuring_validation_delta_from_evidence_8616(
            self.project,
            codegen,
            validation,
            spec_name=self.spec_name,
            before_summary=self.before_summary,
            after_summary=after_summary,
        ):
            logging.getLogger(__name__).warning(
                "structuring pass validation delta accepted from consumed evidence function=%#x pass=%s verdict=%s",
                getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
                self.spec_name,
                validation.get("verdict"),
            )
        existing[self.spec_name] = validation
        if x86_16_tail_validation_result_passed(validation):
            return
        if os.environ.get("INERTIA_DEBUG_TV_SUMMARY") == "1":
            logging.getLogger(__name__).warning(
                "structuring validation details function=%#x pass=%s delta=%r semantic_failures=%r",
                getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
                self.spec_name,
                validation.get("delta"),
                validation.get("semantic_failures"),
            )
        logging.getLogger(__name__).warning(
            "structuring pass validation changed function=%#x pass=%s verdict=%s",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            self.spec_name,
            validation.get("verdict"),
        )
        codegen._inertia_structuring_validation_failed = True
        codegen._inertia_structuring_validation_failure_pass = self.spec_name
        codegen._inertia_structuring_validation_failure_error = (
            validation.get("summary_text") or f"tail-validation status={validation.get('status', 'unknown')}"
        )


def _decompiler_structuring_passes_for_function(
    project: AngrProjectSurface, codegen: AngrCodegenSurface
) -> tuple[DecompilerStructuringPassSpec, ...]:
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if func_addr is None:
        return DECOMPILER_STRUCTURING_PASSES

    func = project.kb.functions.function(addr=func_addr, create=False)
    if func is None:
        return DECOMPILER_STRUCTURING_PASSES

    info = getattr(func, "info", None)
    if not isinstance(info, dict):
        return DECOMPILER_STRUCTURING_PASSES

    profile = info.get("x86_16_decompilation_profile", {})
    if isinstance(profile, dict) and profile.get("wrapper_like"):
        return DECOMPILER_STRUCTURING_PASSES

    return DECOMPILER_STRUCTURING_PASSES


def describe_x86_16_decompiler_structuring_stage() -> tuple[tuple[str, bool], ...]:
    """Return the configured 16-bit structuring pass names and project needs."""
    return tuple((spec.name, spec.needs_project) for spec in DECOMPILER_STRUCTURING_PASSES)


@dataclass
class _NotShiftConditionRestore8616:
    """Rewrite ``~(x) >> k`` conditions back to ``(x >> k) == 0`` comparisons."""

    codegen: AngrCodegenSurface

    @staticmethod
    def _unwrap(expr: object) -> object:
        while isinstance(expr, CTypeCast):
            expr = getattr(expr, "expr", None)
        return expr

    def _constant_int(self, expr: object) -> int | None:
        expr = self._unwrap(expr)
        value = getattr(expr, "value", None)
        return int(value) if isinstance(value, int) else None

    def _restore_expr(self, expr: object) -> tuple[object, bool]:
        expr = self._unwrap(expr)
        if isinstance(expr, CBinaryOp):
            return self._restore_binop(expr)
        if isinstance(expr, CUnaryOp):
            operand, operand_changed = self._restore_expr(expr.operand)
            if operand_changed:
                cast(Any, expr).operand = operand
            return expr, operand_changed
        if isinstance(expr, CTypeCast):
            inner, inner_changed = self._restore_expr(expr.expr)
            if inner_changed:
                cast(Any, expr).expr = inner
            return expr, inner_changed
        return expr, False

    def _restore_binop(self, expr: CBinaryOp) -> tuple[object, bool]:
        lhs, lhs_changed = self._restore_expr(expr.lhs)
        rhs, rhs_changed = self._restore_expr(expr.rhs)
        if lhs_changed:
            expr.lhs = lhs
        if rhs_changed:
            expr.rhs = rhs
        if expr.op in {"Shr", "Sar"}:
            restored = self._restored_not_shift(expr)
            if restored is not None:
                return restored, True
        return expr, lhs_changed or rhs_changed

    def _restored_not_shift(self, expr: CBinaryOp) -> CBinaryOp | None:
        lhs_node = self._unwrap(expr.lhs)
        shift = self._constant_int(expr.rhs)
        if not (
            isinstance(lhs_node, CUnaryOp)
            and lhs_node.op == "Not"
            and isinstance(shift, int)
            and shift > 0
        ):
            return None
        restored_shift = CBinaryOp(
            expr.op,
            lhs_node.operand,
            expr.rhs,
            codegen=self.codegen,
            tags=expr.tags,
        )
        return CBinaryOp(
            "CmpEQ",
            restored_shift,
            CConstant(0, SimTypeShort(False), codegen=self.codegen),
            codegen=self.codegen,
            tags=lhs_node.tags or expr.tags,
        )

    def _visit(self, node: object) -> bool:
        changed = self._visit_condition_attrs(node)
        changed = self._visit_condition_pairs(node) or changed
        changed = self._visit_children(node) or changed
        return changed

    def _visit_condition_attrs(self, node: object) -> bool:
        changed = False
        for attr in ("condition", "cond"):
            condition = getattr(node, attr, None)
            if condition is None:
                continue
            new_condition, condition_changed = self._restore_expr(condition)
            if condition_changed:
                setattr(node, attr, new_condition)
                changed = True
        return changed

    def _visit_condition_pairs(self, node: object) -> bool:
        pairs = getattr(node, "condition_and_nodes", None)
        if not pairs:
            return False
        new_pairs = []
        pair_changed = False
        child_changed = False
        for condition, body in pairs:
            new_condition, condition_changed = self._restore_expr(condition)
            pair_changed = pair_changed or condition_changed
            if body is not None:
                child_changed = self._visit(body) or child_changed
            new_pairs.append((new_condition, body))
        if pair_changed:
            cast(Any, node).condition_and_nodes = new_pairs
        return pair_changed or child_changed

    def _visit_children(self, node: object) -> bool:
        changed = False
        for attr in ("body", "else_node"):
            child = getattr(node, attr, None)
            if child is not None:
                changed = self._visit(child) or changed
        if isinstance(node, CStatements):
            for statement in tuple(node.statements or ()):
                changed = self._visit(statement) or changed
        elif isinstance(node, CIfElse):
            else_node = node.else_node
            if else_node is not None:
                changed = self._visit(else_node) or changed
        return changed


def _restore_not_shift_conditions_structuring_8616(codegen: AngrCodegenSurface) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    roots = []
    seen_roots: set[int] = set()
    for attr in ("body", "statements", "stmt"):
        root = getattr(cfunc, attr, None)
        if root is None or id(root) in seen_roots:
            continue
        roots.append(root)
        seen_roots.add(id(root))
    if not roots:
        return False

    restore = _NotShiftConditionRestore8616(codegen)
    changed = False
    for root in roots:
        changed = restore._visit(root) or changed
    if changed:
        codegen._inertia_not_shift_condition_restored_count_8616 = (
            int(getattr(codegen, "_inertia_not_shift_condition_restored_count_8616", 0) or 0) + 1
        )
        codegen._inertia_codegen_decl_refresh_required_8616 = True
        codegen._inertia_force_codegen_regeneration_8616 = True
    return changed


@dataclass
class _StructuringCodegenRun8616:
    """One structuring-codegen run: gates, pass loop, and cycle tracking."""

    project: AngrProjectSurface
    codegen: AngrCodegenSurface
    func_addr: object
    cycle_at_entry: tuple[str, ...]
    known_cycle_path: tuple[str, ...] | None = None
    changed: bool = False
    last_changed_pass: str | None = None
    lowering_replay_impact: StructuringLoweringReplayImpact8616 = (
        StructuringLoweringReplayImpact8616.NONE
    )
    last_spec_changed: bool = False

    def run(self) -> bool:
        """Run the gated structuring pipeline and report AST change."""
        if not self._alias_gate():
            return False
        if not self._stack_lowering_gate():
            return False
        if not self._contract_gate():
            return False
        self._reset_state()
        codegen = self.codegen
        pass_specs = _decompiler_structuring_passes_for_function(self.project, codegen)
        codegen._inertia_structuring_passes = tuple(spec.name for spec in pass_specs)
        structuring_start = time.perf_counter()
        for spec in pass_specs:
            if not self._run_one_pass(spec, structuring_start):
                break
            if self.last_spec_changed:
                self.changed = True
                self.last_changed_pass = spec.name
                self.lowering_replay_impact = self.lowering_replay_impact.merged(
                    spec.lowering_replay_impact
                )
                codegen._inertia_last_structuring_pass = spec.name
        codegen._inertia_structuring_changed = self.changed
        codegen._inertia_structuring_lowering_replay_impact_8616 = self.lowering_replay_impact
        self.project._inertia_decompiler_stage = "structuring"
        return self.changed

    def _alias_gate(self) -> bool:
        """Block structuring when the SS stack alias surface is incomplete."""
        codegen = self.codegen
        if self.cycle_at_entry:
            logging.getLogger(__name__).warning(
                "structuring entered with cyclic C AST function=%#x path=%s",
                self.func_addr if isinstance(self.func_addr, int) else -1,
                " -> ".join(self.cycle_at_entry),
            )
        try:
            with span("x86_16.structuring.codegen.alias_complete", function=self.func_addr):
                _assert_alias_complete_8616(codegen)
        except PipelineHardError as ex:
            codegen._inertia_structuring_failed = True
            codegen._inertia_structuring_failure_pass = "alias_completeness_gate"
            codegen._inertia_structuring_failure_error = str(ex)
            logging.getLogger(__name__).warning(
                "structuring blocked by incomplete SS alias function=%#x: %s",
                getattr(getattr(codegen, "cfunc", None), "addr", 0),
                ex,
            )
            return False
        return True

    def _stack_lowering_gate(self) -> bool:
        """Lower SS stack facts into variables before structuring runs."""
        codegen = self.codegen
        if getattr(codegen, "_inertia_ss_stack_lowered", False):
            return True
        try:
            with span("x86_16.structuring.codegen.stack_lowering", function=self.func_addr):
                changed = bool(_apply_structuring_stable_stack_semantics_8616(self.project, codegen))
                alias_facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
                annotate_current_span(
                    changed=bool(changed),
                    alias_facts=len(alias_facts) if isinstance(alias_facts, list) else 0,
                    materialized=int(getattr(codegen, "_inertia_semantic_stack_materialized_count", 0) or 0),
                )
                if changed:
                    codegen._inertia_codegen_decl_refresh_required_8616 = True
        except PipelineHardError:
            raise
        except Exception as ex:
            codegen._inertia_structuring_failed = True
            codegen._inertia_structuring_failure_pass = "stack_alias_materialization_and_ss_linear_lowering"
            codegen._inertia_structuring_failure_error = f"{type(ex).__name__}: {ex}"
            logging.getLogger(__name__).warning(
                "stack lowering from facts failed function=%#x stage=%s: %s: %s",
                getattr(getattr(codegen, "cfunc", None), "addr", 0),
                "stack_alias_materialization_and_ss_linear_lowering",
                type(ex).__name__,
                ex,
            )
            return False
        codegen._inertia_ss_stack_lowered = True
        cycle_after_stack = _c_ast_cycle_path_8616(
            getattr(getattr(codegen, "cfunc", None), "statements", None)
        )
        self.known_cycle_path = cycle_after_stack
        if cycle_after_stack and not self.cycle_at_entry:
            logging.getLogger(__name__).warning(
                "structuring stack lowering introduced C AST cycle function=%#x path=%s",
                self.func_addr if isinstance(self.func_addr, int) else -1,
                " -> ".join(cycle_after_stack),
            )
        return True

    def _contract_gate(self) -> bool:
        """Enforce the pipeline classified-vs-materialized hard contract."""
        # ── Hard contract gate: classified > 0 && materialized == 0 → PipelineHardError ──
        # PipelineHardError MUST propagate — never silently caught.
        # Only non-fatal errors (import, attribute) are logged and cause structuring abort.
        from .pipeline.contracts import assert_pipeline_contracts_8616

        codegen = self.codegen
        try:
            with span("x86_16.structuring.codegen.contracts", function=self.func_addr):
                assert_pipeline_contracts_8616(codegen)
        except PipelineHardError:
            raise
        except Exception as e:
            codegen._inertia_structuring_failed = True
            codegen._inertia_structuring_failure_pass = "pipeline_contracts"
            codegen._inertia_structuring_failure_error = str(e)
            logging.getLogger(__name__).warning(
                "Pipeline contract gate setup error in %s: %s",
                getattr(codegen, "cfunc", None) or "unknown",
                e,
            )
            return False
        return True

    def _reset_state(self) -> None:
        codegen = self.codegen
        codegen._inertia_structuring_failed = False
        codegen._inertia_structuring_failure_pass = None
        codegen._inertia_structuring_failure_error = None
        codegen._inertia_structuring_validation_failed = False
        codegen._inertia_structuring_validation_failure_pass = None
        codegen._inertia_structuring_validation_failure_error = None
        codegen._inertia_last_structuring_pass = None

    def _run_one_pass(self, spec: DecompilerStructuringPassSpec, structuring_start: float) -> bool:
        """Run one pass under validation; return False when the loop must break."""
        codegen = self.codegen
        self.last_spec_changed = False
        try:
            spec_changed = self._execute_pass(spec, structuring_start)
        except PipelineHardError:
            raise
        except Exception as ex:
            codegen._inertia_structuring_failed = True
            codegen._inertia_structuring_failure_pass = spec.name
            codegen._inertia_structuring_failure_error = str(ex)
            logging.getLogger(__name__).warning(
                "Skipping 86_16 structuring pass %s after %s: %s",
                spec.name,
                self.last_changed_pass or "no earlier structuring",
                ex,
                exc_info=True,
            )
            return False
        self.last_spec_changed = bool(spec_changed)
        return True

    def _execute_pass(self, spec: DecompilerStructuringPassSpec, structuring_start: float) -> bool:
        """Execute one structuring pass body with validation and cycle tracking."""
        project = self.project
        codegen = self.codegen
        cycle_before_pass = self.known_cycle_path
        project._inertia_decompiler_stage = f"structuring:{spec.name}"
        # Structuring must remain semantics-preserving under tail validation.
        # Expression simplification is allowed in postprocess; in structuring it
        # can rewrite boundary-visible conditions (e.g. 32-bit compare forms),
        # so keep this step analysis-only here.
        if spec.name == "_simplify_structured_expressions_8616":
            return False
        pass_started = time.perf_counter()
        if timing_output_enabled() and os.environ.get("INERTIA_TAIL_VALIDATION_STDERR_JSON") != "1":
            sys.stderr.write(
                f"[{time.strftime('%H:%M:%S')}] structuring pass: {spec.name} (+{time.perf_counter() - structuring_start:.1f}s)\n"
            )
            sys.stderr.flush()
        spec_changed = self._run_pass_body(spec)
        cycle_after_pass = _c_ast_cycle_path_8616(
            getattr(getattr(codegen, "cfunc", None), "statements", None)
        )
        self.known_cycle_path = cycle_after_pass
        if timing_output_enabled() and os.environ.get("INERTIA_TAIL_VALIDATION_STDERR_JSON") != "1":
            sys.stderr.write(
                f"[{time.strftime('%H:%M:%S')}] structuring pass done: {spec.name} "
                f"changed={bool(spec_changed)} elapsed={time.perf_counter() - pass_started:.3f}s\n"
            )
            sys.stderr.flush()
        if cycle_after_pass and not cycle_before_pass:
            logging.getLogger(__name__).warning(
                "structuring pass introduced C AST cycle function=%#x pass=%s path=%s",
                self.func_addr if isinstance(self.func_addr, int) else -1,
                spec.name,
                " -> ".join(cycle_after_pass),
            )
        return bool(spec_changed)

    def _run_pass_body(self, spec: DecompilerStructuringPassSpec) -> bool:
        """Invoke the pass under its span and per-pass validation closure."""
        codegen = self.codegen
        with span(f"x86_16.structuring.pass.{spec.name}", function=self.func_addr):
            finalize_validation = _maybe_validate_structuring_pass_8616(
                self.project, codegen, spec.name
            )
            spec_changed = spec.func(self.project, codegen) if spec.needs_project else spec.func(codegen)
            annotate_current_span(changed=bool(spec_changed))
            if finalize_validation is not None:  # noqa: SIM102
                if spec_changed or spec.name in _semantic_validation_pass_names_8616():
                    # Validation is meaningful only when this pass changed the AST.
                    # For non-semantic no-op passes, semantic output is unchanged;
                    # skipping validation keeps speed while preserving correctness.
                    with span(
                        f"x86_16.structuring.pass_validation.{spec.name}",
                        function=self.func_addr,
                    ):
                        finalize_validation(bool(spec_changed))
                        annotate_current_span(
                            failed=bool(getattr(codegen, "_inertia_structuring_validation_failed", False))
                        )
        return bool(spec_changed)


def _structuring_codegen_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> bool:
    if getattr(codegen, "cfunc", None) is None:
        return False
    if not bool(getattr(project, "_inertia_structuring_enabled", True)):
        codegen._inertia_structuring_passes = ()
        codegen._inertia_structuring_changed = False
        codegen._inertia_structuring_failed = False
        codegen._inertia_last_structuring_pass = None
        return False

    # Alias-completeness gate: structuring cannot run with provisional SS stack.
    # AGENTS rule #1: SS:BP+offset → stack slot → variable, never guess.
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    cycle_at_entry = _c_ast_cycle_path_8616(getattr(getattr(codegen, "cfunc", None), "statements", None))
    run = _StructuringCodegenRun8616(
        project,
        codegen,
        func_addr,
        cycle_at_entry,
        known_cycle_path=cycle_at_entry,
    )
    return run.run()


def _ensure_structuring_typed_conditions_transferred_8616(project: AngrProjectSurface, codegen: AngrCodegenSurface) -> None:
    """Make typed condition evidence available before validation baselines.

    Tail validation compares C surfaces at the structuring boundary.  Typed
    condition transfer is evidence attachment, not a structuring mutation, so it
    must happen before the baseline snapshot.  Otherwise validation reports a
    false guard delta when the same AST is fingerprinted first without decoded
    branch evidence and later with it.
    """
    if getattr(codegen, "_inertia_typed_conditions_transferred", False):
        return
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if isinstance(func_addr, int):
        with contextlib.suppress(Exception):
            transfer_typed_conditions_to_codegen_8616(project, func_addr, codegen)
    codegen._inertia_typed_conditions_transferred = True


def _ensure_decompiler_prototype_8616(self: AngrDecompilerSurface) -> None:
    """Install a fallback prototype when angr left the function untyped."""
    func = getattr(self, "func", None) or getattr(self, "function", None)
    if func is None:
        return
    prototype = getattr(func, "prototype", None)
    needs_fallback = (
        prototype is None or not hasattr(prototype, "returnty") or getattr(prototype, "returnty", None) is None
    )
    if not needs_fallback:
        return
    arch = getattr(getattr(self, "project", None), "arch", None)
    fallback = SimTypeFunction([], SimTypeBottom())
    if arch is not None:
        fallback = fallback.with_arch(arch)
    func.prototype = fallback


def _run_angr_core_decompile_8616(self: AngrDecompilerSurface) -> float:
    """Run angr's core decompiler under the bool-predicate guard; return elapsed."""
    orig = getattr(_decompile_structuring_8616, "_orig_decompiler_decompile", None)
    if orig is None:
        orig = Decompiler._decompile
        cast(Any, _decompile_structuring_8616)._orig_decompiler_decompile = orig
    structuring_started = time.perf_counter()
    self.project._inertia_decompiler_stage = "core"
    _ensure_decompiler_prototype_8616(self)
    with span(
        "x86_16.structuring.angr_core",
        function=getattr(getattr(self, "function", None) or getattr(self, "func", None), "addr", None),
    ), _guard_condition_processor_multibit_bool_predicates_8616(self.project):
        orig(self)
    return time.perf_counter() - structuring_started


def _populate_structuring_info_8616(
    self: AngrDecompilerSurface,
    info: MutableMapping[str, object],
    structuring_elapsed: float,
    changed: bool,
    tail_validation: dict[str, object] | None = None,
) -> object:
    """Publish the common per-function structuring diagnostics payload."""
    structuring_info = cast(
        dict[str, object], info.setdefault("x86_16_decompiler_structuring", {})
    )
    structuring_info["elapsed"] = structuring_elapsed
    if tail_validation is not None:
        structuring_info["tail_validation_timings"] = tail_validation["timings"]
    structuring_info["last_pass"] = getattr(self.codegen, "_inertia_last_structuring_pass", None)
    structuring_info["changed"] = bool(changed)
    structuring_info["failed"] = bool(getattr(self.codegen, "_inertia_structuring_failed", False))
    structuring_info["failure_pass"] = getattr(self.codegen, "_inertia_structuring_failure_pass", None)
    structuring_info["failure_error"] = getattr(
        self.codegen, "_inertia_structuring_failure_error", None
    )
    structuring_info["validation_failed"] = bool(
        getattr(self.codegen, "_inertia_structuring_validation_failed", False)
    )
    structuring_info["validation_failure_pass"] = getattr(
        self.codegen, "_inertia_structuring_validation_failure_pass", None
    )
    structuring_info["validation_failure_error"] = getattr(
        self.codegen, "_inertia_structuring_validation_failure_error", None
    )
    structuring_info["pass_names"] = getattr(self.codegen, "_inertia_structuring_passes", ())
    structuring_info["last_stage"] = getattr(self.project, "_inertia_decompiler_stage", None)
    if tail_validation is not None:
        structuring_info["tail_validation_verdict"] = tail_validation["verdict"]
        structuring_info["tail_validation_cache_hit"] = tail_validation["cache_hit"]
    structuring_info["struct_merging_stats"] = getattr(
        self.codegen, "_inertia_struct_merging_stats", None
    )
    structuring_info["struct_merging_changed"] = bool(
        getattr(self.codegen, "_inertia_struct_merging_changed", False)
    )
    return structuring_info


def _decompile_structuring_unvalidated_8616(
    self: AngrDecompilerSurface, structuring_elapsed: float
) -> None:
    """Run structuring without tail validation and publish diagnostics."""
    changed = _structuring_codegen_8616(self.project, self.codegen)
    changed = _restore_not_shift_conditions_structuring_8616(self.codegen) or changed
    changed = _apply_structuring_pointer_memory_idioms_8616(self.project, self.codegen) or changed
    changed = finalize_shared_call_occurrences_8616(self.project, self.codegen) or changed
    changed = _materialize_structuring_selector_return_branches_8616(
        self.project,
        self.codegen,
    ) or changed
    identical_return_guards = collapse_pure_identical_return_guards_8616(
        getattr(self.codegen.cfunc, "statements", None)
    )
    self.codegen._inertia_identical_return_guard_collapse_result_8616 = (
        identical_return_guards
    )
    changed = identical_return_guards.changed or changed
    changed = (
        bool(_run_structuring_widening_copy_propagation_8616(self.codegen))
        or changed
    )
    changed = (
        bool(prune_unread_stack_lowered_register_carriers_8616(self.codegen))
        or changed
    )
    late_flag_cleanup = (
        _structuring_conditions.prune_dead_flag_assignments_after_structuring_8616(
            self.project,
            self.codegen,
        )
    )
    changed = late_flag_cleanup.changed or changed
    function = getattr(self, "function", None) or getattr(self, "func", None)
    if function is not None:
        info = getattr(function, "info", None)
        if isinstance(info, MutableMapping):
            _populate_structuring_info_8616(self, info, structuring_elapsed, changed)
    self.codegen._inertia_tail_validation_snapshot = None
    self.project._inertia_decompiler_stage = "structuring_done"


@dataclass
class _ValidatedStructuringFlags8616:
    """Named per-phase change flags consumed by the lowering-replay policy."""

    selector_return: bool = False
    return_chains: bool = False
    loop_exit_guard: bool = False
    unresolved_exit_goto: bool = False
    unconsumed_loop_break_jcc: bool = False
    conditional_continue: bool = False
    pretest_loop_guard: bool = False
    canonical_for: bool = False
    hoisted_jcc_target_copy: bool = False
    void_tail_call_guard: bool = False
    return_shape: bool = False
    condition_broad_replay: bool = False
    restored_not_shift: bool = False
    pointer_memory: bool = False
    shared_call: bool = False
    terminal_call_return: bool = False
    final_condition_broad_replay: bool = False
    final_loop_break_jcc: bool = False
    boolean_ite: bool = False



def _validated_codegen_run_8616(
    self: AngrDecompilerSurface,
    func_addr: object,
    prime_changed: bool,
) -> tuple[bool, StructuringLoweringReplayImpact8616]:
    """Run structuring codegen and report the pass-declared lowering replay impact."""
    with span("x86_16.structuring.codegen", function=func_addr):
        changed = bool(_structuring_codegen_8616(self.project, self.codegen)) or prime_changed
        annotate_current_span(
            changed=bool(changed),
            last_pass=getattr(self.codegen, "_inertia_last_structuring_pass", None),
        )
    lowering_replay_impact = getattr(
        self.codegen,
        "_inertia_structuring_lowering_replay_impact_8616",
        StructuringLoweringReplayImpact8616.FULL_AST,
    )
    return changed, lowering_replay_impact

def _validated_guard_repair_phases_8616(
    self: AngrDecompilerSurface,
    func_addr: object,
    changed: bool,
    flags: _ValidatedStructuringFlags8616,
) -> bool:
    """Run the selector/return/loop-guard repair spans and accumulate changes."""
    with span("x86_16.structuring.selector_return", function=func_addr):
        flags.selector_return = bool(
            _materialize_structuring_selector_return_branches_8616(
                self.project,
                self.codegen,
            )
        )
        changed = flags.selector_return or changed
        annotate_current_span(changed=flags.selector_return)
    with span("x86_16.structuring.return_chains", function=func_addr):
        flags.return_chains = bool(
            _materialize_structuring_return_chains_8616(
                self.project,
                self.codegen,
                materialize_wide_return_predicate=False,
            )
        )
        changed = flags.return_chains or changed
        annotate_current_span(changed=flags.return_chains)
    with span("x86_16.structuring.loop_exit_return_guards", function=func_addr):
        flags.loop_exit_guard = bool(
            _repair_structuring_loop_exit_return_guards_8616(self.codegen)
        )
        changed = flags.loop_exit_guard or changed
        annotate_current_span(changed=flags.loop_exit_guard)
    with span("x86_16.structuring.unresolved_exit_gotos", function=func_addr):
        flags.unresolved_exit_goto = bool(
            _repair_structuring_unresolved_function_exit_gotos_8616(
                self.project,
                self.codegen,
            )
        )
        changed = flags.unresolved_exit_goto or changed
        annotate_current_span(changed=flags.unresolved_exit_goto)
    with span("x86_16.structuring.unconsumed_loop_break_jcc", function=func_addr):
        flags.unconsumed_loop_break_jcc = bool(
            _materialize_structuring_unconsumed_loop_break_jcc_8616(
                self.project,
                self.codegen,
            )
        )
        changed = flags.unconsumed_loop_break_jcc or changed
        annotate_current_span(changed=flags.unconsumed_loop_break_jcc)
    with span("x86_16.structuring.conditional_continue", function=func_addr):
        flags.conditional_continue = bool(
            _repair_structuring_conditional_continue_guards_8616(
                self.project,
                self.codegen,
            )
        )
        changed = flags.conditional_continue or changed
        annotate_current_span(changed=flags.conditional_continue)
    with span("x86_16.structuring.pretest_loop_break", function=func_addr):
        flags.pretest_loop_guard = bool(
            _repair_structuring_pretest_loop_break_guards_8616(
                self.project,
                self.codegen,
            )
        )
        changed = flags.pretest_loop_guard or changed
        annotate_current_span(changed=flags.pretest_loop_guard)
    return changed

def _validated_jcc_repair_phases_8616(
    self: AngrDecompilerSurface,
    func_addr: object,
    changed: bool,
    flags: _ValidatedStructuringFlags8616,
) -> bool:
    """Run the canonical-for/JCC/return-shape/void-tail-call repair spans."""
    with span("x86_16.structuring.canonical_for_loops", function=func_addr):
        flags.canonical_for = bool(
            recover_structuring_canonical_for_loops_8616(self.codegen)
        )
        changed = flags.canonical_for or changed
        annotate_current_span(changed=flags.canonical_for)
    with span("x86_16.structuring.hoisted_jcc_target_copy", function=func_addr):
        flags.hoisted_jcc_target_copy = bool(
            _repair_structuring_hoisted_jcc_target_copies_8616(
                self.project,
                self.codegen,
            )
        )
        changed = flags.hoisted_jcc_target_copy or changed
        annotate_current_span(changed=flags.hoisted_jcc_target_copy)
    with span("x86_16.structuring.return_shape", function=func_addr):
        flags.return_shape = bool(
            _materialize_structuring_return_shape_8616(
                self.project,
                self.codegen,
            )
        )
        changed = flags.return_shape or changed
        annotate_current_span(changed=flags.return_shape)
    with span("x86_16.structuring.void_tail_call_guard", function=func_addr):
        flags.void_tail_call_guard = bool(
            _materialize_structuring_void_tail_call_guard_8616(
                self.project,
                self.codegen,
            )
        )
        changed = flags.void_tail_call_guard or changed
        annotate_current_span(changed=flags.void_tail_call_guard)
    return changed

def _validated_refresh_cleanup_phases_8616(
    self: AngrDecompilerSurface,
    func_addr: object,
    changed: bool,
    flags: _ValidatedStructuringFlags8616,
) -> bool:
    """Run condition refresh, pointer-memory, and shared-call cleanup spans."""
    with span("x86_16.structuring.condition_refresh", function=func_addr):
        condition_refresh_result = _refresh_structuring_condition_semantics_8616(
            self.project,
            self.codegen,
        )
        condition_refresh_changed = condition_refresh_result.changed
        flags.condition_broad_replay = bool(
            condition_refresh_result.requires_broad_lowering_replay
        )
        flags.restored_not_shift = bool(
            _restore_not_shift_conditions_structuring_8616(self.codegen)
        )
        changed = bool(condition_refresh_changed or flags.restored_not_shift) or changed
        annotate_current_span(
            changed=bool(condition_refresh_changed),
            not_shift_restored=flags.restored_not_shift,
        )
        record_ast_condition_trace_8616(self.project, self.codegen, stage="structured")
    with span("x86_16.structuring.pointer_memory_lowering", function=func_addr):
        flags.pointer_memory = bool(
            _apply_structuring_pointer_memory_idioms_8616(self.project, self.codegen)
        )
        changed = flags.pointer_memory or changed
        annotate_current_span(changed=flags.pointer_memory)
        if os.environ.get("INERTIA_DEBUG_POINTER_MEMORY_IDIOMS") == "1":
            try:
                pointer_text = str(self.codegen.cfunc.c_repr())
            except (AttributeError, TypeError):
                pointer_text = ""
            logging.getLogger(__name__).warning(
                "[pointer-memory-structuring-final] lines=%r",
                tuple(
                    line.strip()
                    for line in pointer_text.splitlines()
                    if "[0]" in line or "SEG_U16" in line
                ),
            )
    with span("x86_16.structuring.shared_call_occurrences", function=func_addr):
        flags.shared_call = bool(
            finalize_shared_call_occurrences_8616(
                self.project,
                self.codegen,
            )
        )
        changed = flags.shared_call or changed
        annotate_current_span(changed=flags.shared_call)
    return changed

def _regenerate_if_structuring_changed_8616(
    codegen: AngrCodegenSurface, func_addr: object, changed: bool
) -> None:
    """Regenerate rendered text only when a pass mutated the structured AST."""
    if changed:
        with span("x86_16.structuring.regenerate_text", function=func_addr):
            regenerated = _regenerate_structuring_text_safely_8616(
                codegen,
                context="structuring:post-codegen-ast-mutation",
            )
            annotate_current_span(regenerated=bool(regenerated))


def _post_regen_narrow_lowering_replay_8616(
    post_codegen_lowering_replay_impact: StructuringLoweringReplayImpact8616,
    codegen: AngrCodegenSurface,
) -> bool:
    """Run the narrower-than-full post-regeneration lowering replay arms."""
    if (
        post_codegen_lowering_replay_impact
        is StructuringLoweringReplayImpact8616.RETURN_LIVENESS_ONLY
    ):
        return bool(replay_return_liveness_lowering_8616(codegen).changed)
    return False


def _materialize_terminal_call_result_return_delta_8616(
    project: AngrProjectSurface, codegen: AngrCodegenSurface
) -> tuple[bool, bool]:
    """Materialize terminal call-result returns; return (flag, combined changed)."""
    terminal_call_return = bool(
        _materialize_structuring_terminal_call_result_return_8616(
            project,
            codegen,
        )
    )
    terminal_call_return_shape_changed = (
        _materialize_structuring_return_shape_8616(
            project,
            codegen,
        )
        if terminal_call_return
        else False
    )
    annotate_current_span(
        changed=terminal_call_return,
        return_shape_changed=bool(terminal_call_return_shape_changed),
    )
    return terminal_call_return, bool(
        terminal_call_return or terminal_call_return_shape_changed
    )


def _final_lowering_boundary_changed_8616(flags: _ValidatedStructuringFlags8616) -> bool:
    """Return whether any final boundary flag requires the last lowering replay."""
    return bool(
        flags.terminal_call_return
        or flags.final_loop_break_jcc
        or flags.final_condition_broad_replay
        or flags.boolean_ite
    )


def _validated_terminal_mid_phases_8616(
    self: AngrDecompilerSurface,
    func_addr: object,
    changed: bool,
    flags: _ValidatedStructuringFlags8616,
) -> bool:
    """Run the final condition-refresh, loop-break closure, and ite spans."""
    with span("x86_16.structuring.final_condition_refresh", function=func_addr):
        final_condition_result = _refresh_structuring_condition_semantics_8616(
            self.project,
            self.codegen,
        )
        final_condition_changed = final_condition_result.changed
        flags.final_condition_broad_replay = bool(
            final_condition_result.requires_broad_lowering_replay
        )
        changed = final_condition_changed or changed
        record_ast_condition_trace_8616(self.project, self.codegen, stage="structured-final")
    with span("x86_16.structuring.final_loop_break_jcc_closure", function=func_addr):
        flags.final_loop_break_jcc = bool(
            _materialize_structuring_unconsumed_loop_break_jcc_8616(
                self.project,
                self.codegen,
            )
        )
        changed = flags.final_loop_break_jcc or changed
        annotate_current_span(changed=flags.final_loop_break_jcc)
    with span("x86_16.structuring.boolean_condition_ites", function=func_addr):
        boolean_ite_stats = normalize_boolean_condition_ites_8616(self.codegen)
        flags.boolean_ite = bool(boolean_ite_stats.changed)
        changed = flags.boolean_ite or changed
        annotate_current_span(
            raw_fact_count=boolean_ite_stats.raw_fact_count,
            classified_fact_count=boolean_ite_stats.classified_fact_count,
            materialized_count=boolean_ite_stats.materialized_count,
            failure_count=boolean_ite_stats.failure_count,
        )
    return changed

def _validated_selector_phases_8616(
    self: AngrDecompilerSurface,
    func_addr: object,
    changed: bool,
) -> bool:
    """Run the final switch-exit and wide-stack predicate spans."""
    with span("x86_16.structuring.final_switch_loop_exit_return", function=func_addr):
        final_switch_exit_changed = _repair_structuring_switch_loop_exit_returns_8616(
            self.project,
            self.codegen,
        )
        changed = bool(final_switch_exit_changed) or changed
        annotate_current_span(changed=bool(final_switch_exit_changed))
    with span("x86_16.structuring.final_wide_stack_predicate", function=func_addr):
        final_wide_predicate_changed = _materialize_structuring_wide_stack_return_predicate_8616(
            self.project,
            self.codegen,
        )
        changed = bool(final_wide_predicate_changed) or changed
        annotate_current_span(changed=bool(final_wide_predicate_changed))
    return changed

def _validated_callsite_closure_phases_8616(
    self: AngrDecompilerSurface,
    func_addr: object,
    changed: bool,
) -> bool:
    """Run the identical-return-guard collapse and callsite closure spans."""
    with span("x86_16.structuring.identical_return_guards", function=func_addr):
        identical_return_guards = collapse_pure_identical_return_guards_8616(
            getattr(self.codegen.cfunc, "statements", None)
        )
        self.codegen._inertia_identical_return_guard_collapse_result_8616 = (
            identical_return_guards
        )
        changed = identical_return_guards.changed or changed
        widening_replay_changed = _run_structuring_widening_copy_propagation_8616(
            self.codegen
        )
        changed = bool(widening_replay_changed) or changed
        dead_carrier_changed = prune_unread_stack_lowered_register_carriers_8616(
            self.codegen
        )
        changed = bool(dead_carrier_changed) or changed
        late_flag_cleanup = (
            _structuring_conditions.prune_dead_flag_assignments_after_structuring_8616(
                self.project,
                self.codegen,
            )
        )
        changed = late_flag_cleanup.changed or changed
        # Widening replay, carrier pruning, and FLAGS cleanup can rebuild
        # raw AL/AH-style views after the earlier typed GP replay. Close
        # the same Lowering contract immediately before validation.
        final_gp_state_changed = (
            _replay_structuring_gp_state_after_late_cleanup_8616(self.codegen)
        )
        changed = bool(final_gp_state_changed) or changed
        annotate_current_span(
            raw_fact_count=identical_return_guards.stats.raw_fact_count,
            materialized_count=identical_return_guards.stats.materialized_count,
            failure_count=identical_return_guards.stats.failure_count,
            widening_changed=bool(widening_replay_changed),
            carrier_changed=bool(dead_carrier_changed),
            flags_changed=late_flag_cleanup.changed,
            gp_state_changed=bool(final_gp_state_changed),
        )
    with span("x86_16.structuring.final_callsite_closure", function=func_addr):
        final_callsite_changed = _close_final_structuring_callsites_8616(
            self.project,
            self.codegen,
        )
        changed = bool(final_callsite_changed) or changed
        annotate_current_span(changed=bool(final_callsite_changed))
    return changed

def _finalize_shared_call_ownership_8616(
    self: AngrDecompilerSurface, codegen: AngrCodegenSurface
) -> bool:
    """Close shared-call ownership and rerun pointer-memory; return its delta."""
    final_shared_call_changed = finalize_shared_call_occurrences_8616(
        self.project,
        codegen,
    )
    annotate_current_span(changed=bool(final_shared_call_changed))
    if final_shared_call_changed:
        regenerated = _regenerate_structuring_text_safely_8616(
            codegen,
            context="structuring:shared-call-occurrence-normalization",
        )
        annotate_current_span(regenerated=bool(regenerated))
    final_pointer_memory_changed = _apply_structuring_pointer_memory_idioms_8616(
        self.project, codegen
    )
    annotate_current_span(pointer_memory_changed=bool(final_pointer_memory_changed))
    return bool(final_pointer_memory_changed)

def _validated_decompile_function_8616(self: AngrDecompilerSurface) -> object:
    """Resolve the angr function for diagnostics, with a kb fallback."""
    function = getattr(self, "function", None) or getattr(self, "func", None)
    if function is None and getattr(getattr(self, "codegen", None), "cfunc", None) is not None:
        addr = getattr(self.codegen.cfunc, "addr", None)
        kb_functions = getattr(getattr(self, "project", None), "kb", None)
        kb_functions = getattr(kb_functions, "functions", None)
        if isinstance(addr, int) and kb_functions is not None:
            with contextlib.suppress(Exception):
                function = kb_functions.function(addr, create=False)
    return function

@dataclass
class _StructuringValidationBaseline8616:
    """Tail-validation baseline captured before the structuring pass pipeline."""

    prime_changed: bool
    before_fingerprint: str
    before_summary: X86_16TailValidationSummary
    before_collect_elapsed: float


def _structuring_validation_baseline_8616(
    self: AngrDecompilerSurface,
    codegen: AngrCodegenSurface,
    func_addr: object,
    validation_mode: str,
) -> _StructuringValidationBaseline8616:
    """Prime validation semantics and capture the pre-structuring baseline."""
    with span("x86_16.structuring.validation_prime", function=func_addr):
        prime_changed = bool(_prime_structuring_validation_semantics_8616(self.project, codegen))
        annotate_current_span(changed=prime_changed)
        _ensure_structuring_typed_conditions_transferred_8616(self.project, codegen)
    with span("x86_16.structuring.validation.before_fingerprint", function=func_addr):
        before_fingerprint = fingerprint_x86_16_tail_validation_boundary(
            self.project, codegen, mode=validation_mode
        )
    before_collect_started = time.perf_counter()
    with span("x86_16.structuring.validation.before_summary", function=func_addr):
        before_summary = collect_x86_16_tail_validation_summary(
            self.project,
            codegen,
            mode=validation_mode,
            boundary_fingerprint=before_fingerprint,
        )
    return _StructuringValidationBaseline8616(
        prime_changed=prime_changed,
        before_fingerprint=before_fingerprint,
        before_summary=before_summary,
        before_collect_elapsed=time.perf_counter() - before_collect_started,
    )


def _validated_structuring_publish_8616(
    self: AngrDecompilerSurface,
    func_addr: object,
    validation_mode: str,
    baseline: _StructuringValidationBaseline8616,
    after_fingerprint: str,
    structuring_elapsed: float,
    changed: bool,
) -> None:
    """Collect the after snapshot, run final tail validation, and publish results."""
    codegen = self.codegen
    before_fingerprint = baseline.before_fingerprint
    before_summary = baseline.before_summary
    before_collect_elapsed = baseline.before_collect_elapsed
    after_collect_started = time.perf_counter()
    with span("x86_16.structuring.validation.after_summary", function=func_addr):
        after_summary = collect_x86_16_tail_validation_summary(
            self.project,
            codegen,
            mode=validation_mode,
            boundary_fingerprint=after_fingerprint,
        )
    after_collect_elapsed = time.perf_counter() - after_collect_started
    codegen._inertia_structuring_tail_validation_artifacts_8616 = {
        "mode": validation_mode,
        "before_fingerprint": before_fingerprint,
        "before_summary": before_summary,
        "after_fingerprint": after_fingerprint,
        "after_summary": after_summary,
    }
    function = _validated_decompile_function_8616(self)
    owner = getattr(function, "info", None) if function is not None else None
    validation_started = time.perf_counter()
    with span("x86_16.structuring.validation.compare", function=func_addr):
        validation = build_x86_16_tail_validation_cached_result(
            owner=owner if isinstance(owner, MutableMapping) else None,
            stage="structuring",
            mode=validation_mode,
            before_fingerprint=before_fingerprint,
            after_fingerprint=after_fingerprint,
            before_summary=before_summary,
            after_summary=after_summary,
            semantic_failure_scope=TailSemanticFailureScope8616.INTRODUCED,
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
    validation["verdict"] = build_x86_16_tail_validation_verdict("structuring", validation)
    log = logging.getLogger(__name__)
    if os.environ.get("INERTIA_DEBUG_CALL_MATERIALIZATION"):
        log.warning(
            "[structuring-tail-validation] function=%#x status=%r changed=%r "
            "cache_hit=%r delta=%r semantic_failures=%r",
            func_addr if isinstance(func_addr, int) else -1,
            validation.get("status"),
            validation.get("changed"),
            validation.get("cache_hit"),
            validation.get("delta"),
            validation.get("semantic_failures"),
        )
    if _try_accept_structuring_validation_delta_from_evidence_8616(
        self.project,
        codegen,
        validation,
        spec_name="final",
        before_summary=before_summary,
        after_summary=after_summary,
    ):
        log.warning(
            "structuring final validation delta accepted from consumed evidence function=%#x verdict=%s",
            getattr(getattr(codegen, "cfunc", None), "addr", -1) or -1,
            validation.get("verdict"),
        )
    final_validation_failed = not x86_16_tail_validation_result_passed(validation)
    codegen._inertia_structuring_validation_failed = final_validation_failed
    codegen._inertia_structuring_validation_failure_pass = "final" if final_validation_failed else None
    codegen._inertia_structuring_validation_failure_error = (
        validation.get("summary_text") or f"tail-validation status={validation.get('status', 'unknown')}"
        if final_validation_failed
        else None
    )
    if function is not None:
        info = getattr(function, "info", None)
        if isinstance(info, MutableMapping):
            _populate_structuring_info_8616(
                self,
                info,
                structuring_elapsed,
                changed,
                tail_validation={
                    "timings": validation_timings,
                    "verdict": validation["verdict"],
                    "cache_hit": bool(validation.get("cache_hit", False)),
                },
            )
            persist_x86_16_tail_validation_snapshot(
                function_info=info,
                codegen=codegen,
                stage="structuring",
                validation=validation,
            )
    if not x86_16_tail_validation_result_passed(validation):
        log.warning("%s", validation["verdict"])
    else:
        log.info("%s", validation["verdict"])
    self.project._inertia_decompiler_stage = "structuring_done"

def _decompile_structuring_8616(self: AngrDecompilerSurface) -> None:
    structuring_elapsed = _run_angr_core_decompile_8616(self)
    if self.project.arch.name != "86_16" or self.codegen is None:
        return
    install_materialized_return_chain_integrity_guard_8616(self.codegen)
    clinic = getattr(self, "clinic", None)
    if clinic is not None:
        self.codegen._clinic = clinic
    _bind_structuring_callsite_consumers_8616(self.codegen)
    if not bool(getattr(self.project, "_inertia_tail_validation_enabled", True)):
        _decompile_structuring_unvalidated_8616(self, structuring_elapsed)
        return

    codegen = self.codegen
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    validation_mode = "live_out"
    baseline = _structuring_validation_baseline_8616(self, codegen, func_addr, validation_mode)
    flags = _ValidatedStructuringFlags8616()
    changed, lowering_replay_impact = _validated_codegen_run_8616(
        self, func_addr, baseline.prime_changed
    )
    if lowering_replay_impact == StructuringLoweringReplayImpact8616.FULL_AST:
        with span("x86_16.structuring.direct_stack_materialization", function=func_addr):
            direct_stack_changed = _apply_structuring_direct_stack_materialization_8616(
                self.project,
                codegen,
            )
            changed |= bool(direct_stack_changed)
            annotate_current_span(changed=bool(direct_stack_changed))
        with span("x86_16.structuring.segment_global_after_direct_stack", function=func_addr):
            segment_global_changed = _prime_structuring_segment_global_semantics_8616(
                self.project,
                codegen,
            )
            changed |= bool(segment_global_changed)
            annotate_current_span(changed=bool(segment_global_changed))
    changed = _validated_guard_repair_phases_8616(self, func_addr, changed, flags)
    changed = _validated_jcc_repair_phases_8616(self, func_addr, changed, flags)
    changed = _validated_refresh_cleanup_phases_8616(self, func_addr, changed, flags)
    post_codegen_lowering_replay_impact = (
        structuring_lowering_replay_impact_after_changes_8616(
            lowering_replay_impact,
            return_liveness_changed=flags.return_shape,
            full_ast_changes=(
                flags.selector_return,
                flags.return_chains,
                flags.loop_exit_guard,
                flags.unresolved_exit_goto,
                flags.unconsumed_loop_break_jcc,
                flags.conditional_continue,
                flags.pretest_loop_guard,
                flags.canonical_for,
                flags.hoisted_jcc_target_copy,
                flags.void_tail_call_guard,
                flags.condition_broad_replay,
                flags.restored_not_shift,
                flags.pointer_memory,
                flags.shared_call,
            ),
        )
    )
    _regenerate_if_structuring_changed_8616(codegen, func_addr, changed)
    with span("x86_16.structuring.post_regeneration_lowering_replay", function=func_addr):
        post_regeneration_lowering_changed = (
            _replay_structuring_lowering_before_validation_8616(self.project, codegen)
            if post_codegen_lowering_replay_impact is StructuringLoweringReplayImpact8616.FULL_AST
            else _post_regen_narrow_lowering_replay_8616(
                post_codegen_lowering_replay_impact, codegen
            )
        )
        changed |= bool(post_regeneration_lowering_changed)
        annotate_current_span(
            changed=bool(post_regeneration_lowering_changed),
            replay_impact=post_codegen_lowering_replay_impact.name,
        )
    with span("x86_16.structuring.terminal_call_result_return", function=func_addr):
        flags.terminal_call_return, terminal_call_return_delta = (
            _materialize_terminal_call_result_return_delta_8616(self.project, codegen)
        )
        changed |= terminal_call_return_delta
    changed = _validated_terminal_mid_phases_8616(self, func_addr, changed, flags)
    with span("x86_16.structuring.final_lowering_replay", function=func_addr):
        final_lowering_changed = (
            _replay_structuring_lowering_before_validation_8616(self.project, self.codegen)
            if _final_lowering_boundary_changed_8616(flags)
            else False
        )
        changed |= bool(final_lowering_changed)
        annotate_current_span(changed=bool(final_lowering_changed))
    changed = _validated_selector_phases_8616(self, func_addr, changed)
    with span("x86_16.structuring.final_selector_return_projection", function=func_addr):
        final_selector_return_changed = _materialize_structuring_selector_return_branches_8616(
            self.project,
            codegen,
        )
        changed |= bool(final_selector_return_changed)
        annotate_current_span(changed=bool(final_selector_return_changed))
    changed = _validated_callsite_closure_phases_8616(self, func_addr, changed)
    with span("x86_16.structuring.final_shared_call_ownership", function=func_addr):
        changed |= _finalize_shared_call_ownership_8616(self, codegen)
    with span("x86_16.structuring.return_chain_integrity", function=func_addr):
        return_chain_integrity = require_materialized_return_chain_integrity_8616(
            codegen,
            context="structuring:final-ast",
        )
        annotate_current_span(verdict=return_chain_integrity.verdict.value)
    with span("x86_16.structuring.validation.after_fingerprint", function=func_addr):
        after_fingerprint = fingerprint_x86_16_tail_validation_boundary(
            self.project, codegen, mode=validation_mode
        )
    _validated_structuring_publish_8616(
        self,
        func_addr,
        validation_mode,
        baseline,
        after_fingerprint,
        structuring_elapsed,
        changed,
    )


@dataclass
class _SsAliasCensus8616:
    """SS-space tallies from the module alias fact cache."""

    has_ss: bool = False
    has_ss_stable: bool = False
    has_ss_failure: bool = False
    first_ss_failure_reason: object = None


def _ss_alias_census_8616(facts: list[object]) -> _SsAliasCensus8616:
    """Census SS-space alias facts, skipping provisional SP-relative failures."""
    from .alias.alias_model_impl import AliasFailure, AliasStorageFacts

    census = _SsAliasCensus8616()
    for fact in facts:
        if isinstance(fact, AliasFailure):
            if fact.space in {"ss", "SS"}:
                census.has_ss = True
                address = fact.address
                if isinstance(address, IRAddress) and address.status == AddressStatus.PROVISIONAL:
                    continue
                census.has_ss_failure = True
                if census.first_ss_failure_reason is None:
                    census.first_ss_failure_reason = fact.reason
        elif isinstance(fact, AliasStorageFacts) and fact.domain.space == "stack":
            census.has_ss = True
            census.has_ss_stable = True
    return census


def _assert_alias_complete_8616(codegen: AngrCodegenSurface) -> None:
    """Block structuring when SS stack alias facts are incomplete.

    AGENTS rule #1: SS:BP+offset → stack slot → variable, never guess.
    AGENTS rule #8: validation must be honest — unreviewed SS is not safe.

    Consults the module-level alias fact cache populated during VEX lifting
    (access._inertia_module_alias_fact_cache).  Returns without error when
    no SS accesses are present (e.g. pure register / DS-only functions).

    Raises PipelineHardError if any proven SS access lacks stable stack alias.
    """
    from .access import _inertia_module_alias_fact_cache
    from .pipeline.errors import PipelineHardError

    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None) if cfunc is not None else None
    if not isinstance(func_addr, int):
        return

    facts = _inertia_module_alias_fact_cache.get(func_addr, None)
    if not isinstance(facts, list):
        return  # No facts recorded for this function — likely not yet lifted with typed IR.

    census = _ss_alias_census_8616(facts)
    if not census.has_ss:
        return  # No SS accesses — nothing to block.

    # Only block when SS accesses exist but NONE are successfully classified.
    # Provisional SP-relative AliasFailures (push/pop/ret) are expected and
    # should not prevent structuring when BP-relative stack accesses are resolved.
    if not census.has_ss_stable and census.has_ss_failure:
        raise PipelineHardError(
            f"structuring before stable stack alias: {census.first_ss_failure_reason}",
            layer="structuring",
        )


def _decompiler_wrapper_chain_contains_8616(root: object, wrapper_name: str) -> bool:
    """Return whether an angr decompiler wrapper is already in the call chain."""
    seen: set[int] = set()
    current = root
    while callable(current) and id(current) not in seen:
        seen.add(id(current))
        if getattr(current, "__name__", "") == wrapper_name:
            return True
        current = getattr(current, "_orig_decompiler_decompile", None)
    return False


def apply_x86_16_decompiler_structuring() -> None:
    """Install the 16-bit structuring wrapper around angr's decompiler."""
    current = Decompiler._decompile
    if _decompiler_wrapper_chain_contains_8616(current, "_decompile_structuring_8616"):
        return
    if getattr(current, "__name__", "") == "_decompile_8616":
        postprocess_original = getattr(current, "_orig_decompiler_decompile", None)
        cast(Any, _decompile_structuring_8616)._orig_decompiler_decompile = postprocess_original or current
        cast(Any, current)._orig_decompiler_decompile = _decompile_structuring_8616
        return
    cast(Any, _decompile_structuring_8616)._orig_decompiler_decompile = current
    Decompiler._decompile = _decompile_structuring_8616
