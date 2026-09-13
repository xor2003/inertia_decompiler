"""Typed inventory for postprocess quarantine.

Layer: Rewrite/Postprocess cleanup.
Responsibility: owns diagnostic inventory for late postprocess migration debt.

Postprocess is a late rewrite layer.  This module makes remaining postprocess
semantic materialization visible without changing execution order.  New agents
should use this inventory to identify migration debt, then move proof
production to IR, alias, lowering, or structuring before deleting the late
consumer.

Ownership rule:
- This module is diagnostic-only.
- It should remain empty of new debt classes; new semantic pass debt should be
  added in the owning layer where the proof is introduced, with explicit
  deprecation status and owner assignment.
- Once pass debt is migrated, this quarantine should shrink and eventually become
  an archival checklist, not an execution dependency.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .decompiler_postprocess_stage import DECOMPILER_POSTPROCESS_PASSES

__all__ = [
    "DecompilerPostprocessPassInventoryItem",
    "DecompilerPostprocessPassInventoryViolation",
    "DecompilerPostprocessPassKind8616",
    "DecompilerPostprocessPassMigrationStatus8616",
    "describe_x86_16_decompiler_postprocess_inventory_8616",
    "validate_x86_16_decompiler_postprocess_inventory_8616",
]


class DecompilerPostprocessPassKind8616(StrEnum):
    """Ownership class for a postprocess pass."""

    CLEANUP = "cleanup"
    FORMATTING = "formatting"
    DCE_WITH_EVIDENCE = "dce-with-evidence"
    SEMANTIC_MATERIALIZATION = "semantic-materialization"


class DecompilerPostprocessPassMigrationStatus8616(StrEnum):
    """Migration state for a postprocess quarantine inventory row."""

    ACTIVE_POSTPROCESS_DEBT = "active-postprocess-debt"
    GUARDED_COMPATIBILITY_FALLBACK = "guarded-compatibility-fallback"


@dataclass(frozen=True, slots=True)
class DecompilerPostprocessPassInventoryItem:
    """Typed ownership inventory row for postprocess quarantine."""

    name: str
    kind: DecompilerPostprocessPassKind8616
    owner: str
    migration_status: DecompilerPostprocessPassMigrationStatus8616
    required_evidence_counters: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DecompilerPostprocessPassInventoryViolation:
    """Structured postprocess inventory contract violation."""

    name: str
    reason: str


_DYNAMIC_POSTPROCESS_PASS_NAMES_8616 = (
    "_apply_typed_conditions_to_codegen_8616",
)

_POSTPROCESS_SEMANTIC_MATERIALIZATION_PASS_NAMES_8616 = frozenset(
    {
        "_apply_typed_conditions_to_codegen_8616",
        "_rewrite_decoded_jcc_conditions_8616",
        "_rewrite_decoded_jcc_conditions_after_calls_8616",
        "_rewrite_flag_condition_pairs_8616",
        "_rewrite_flag_bit_value_uses_8616",
        "_fix_interval_guard_conditions_8616",
        "_materialize_stable_stack_semantics_early_8616",
        "_materialize_stable_stack_semantics_postprocess_8616",
        "_materialize_stable_stack_semantics_final_8616",
        "_materialize_pointer_arg_indirect_loads_8616",
        "_materialize_pointer_arg_indirect_loads_final_8616",
        "_materialize_pointer_memory_idioms_8616",
        "_materialize_callsite_prototypes_8616",
        "_recover_missing_direct_calls_from_evidence_early_8616",
        "_materialize_callsite_stack_arguments_8616",
        "_materialize_recovered_callsite_stack_arguments_8616",
        "_materialize_stdlib_call_chains_8616",
        "_materialize_stack_byte_pair_return_8616",
        "_materialize_global_byte_index_sum_loop_8616",
        "_materialize_direct_stack_mov_instructions_8616",
        "_materialize_direct_stack_mov_instructions_final_8616",
        "_materialize_direct_stack_incdec_instructions_8616",
        "_materialize_direct_stack_incdec_instructions_final_8616",
        "_materialize_direct_global_incdec_instructions_8616",
        "_materialize_direct_global_incdec_instructions_final_8616",
        "_materialize_unconsumed_loop_break_jcc_8616",
        "_repair_conditional_continue_guards_from_evidence_8616",
        "_repair_conditional_continue_guards_after_loop_break_8616",
        "_materialize_cfg_selector_return_branches_early_8616",
        "_materialize_cfg_selector_return_branches_8616",
        "_materialize_cfg_mask_accumulator_8616",
        "_materialize_callsite_stack_arguments_after_ss_lowering_8616",
        "_materialize_callsite_stack_arguments_final_8616",
        "_recover_missing_direct_calls_from_evidence_8616",
        "_recover_missing_direct_calls_final_8616",
        "_materialize_missing_terminal_ax_return_8616",
        "_materialize_empty_if_return_branches_8616",
        "_materialize_empty_if_return_branches_final_8616",
        "_repair_loop_exit_return_guards_8616",
        "_repair_unresolved_function_exit_gotos_8616",
        "_repair_hoisted_jcc_target_copies_from_evidence_8616",
        "_repair_hoisted_jcc_target_copies_after_direct_stack_mov_8616",
        "_repair_hoisted_jcc_target_copies_after_calls_8616",
        "_repair_hoisted_jcc_target_copies_after_direct_stack_mov_final_8616",
        "_repair_switch_loop_exit_returns_from_evidence_8616",
        "_repair_switch_loop_exit_returns_from_evidence_final_8616",
    }
)

_POSTPROCESS_PASS_OWNER_8616 = {
    "_materialize_ir_segmented_load_carriers_8616": "Types/Lowering IR segmented-load carrier owner",
    "_apply_typed_conditions_to_codegen_8616": "Step 8: move ConditionIR guard materialization to structuring",
    "_rewrite_decoded_jcc_conditions_8616": "Step 8: move decoded JCC guard materialization to structuring",
    "_rewrite_decoded_jcc_conditions_after_calls_8616": "Step 8: move decoded JCC guard materialization to structuring",
    "_rewrite_flag_condition_pairs_8616": "Step 8: move flag-condition pair recovery to condition semantics",
    "_rewrite_flag_bit_value_uses_8616": "Step 8: move flag-bit value recovery to condition semantics",
    "_fix_interval_guard_conditions_8616": "Step 8: move interval guard recovery to condition semantics",
    "_materialize_unconsumed_loop_break_jcc_8616": "Step 6/8: move loop-exit JCC materialization to structuring",
    "_repair_switch_loop_exit_returns_from_evidence_8616": (
        "Step 6: move switch loop-exit return recovery to structuring"
    ),
    "_repair_switch_loop_exit_returns_from_evidence_final_8616": (
        "Step 6: move switch loop-exit return recovery to structuring"
    ),
}

_POSTPROCESS_GUARDED_FALLBACK_PASS_NAMES_8616 = frozenset(
    {
        "_apply_typed_conditions_to_codegen_8616",
        "_rewrite_decoded_jcc_conditions_8616",
        "_rewrite_decoded_jcc_conditions_after_calls_8616",
        "_rewrite_flag_condition_pairs_8616",
        "_rewrite_flag_bit_value_uses_8616",
        "_fix_interval_guard_conditions_8616",
        "_materialize_stable_stack_semantics_early_8616",
        "_materialize_stable_stack_semantics_postprocess_8616",
        "_materialize_stable_stack_semantics_final_8616",
        "_materialize_pointer_arg_indirect_loads_8616",
        "_materialize_pointer_arg_indirect_loads_final_8616",
        "_materialize_pointer_memory_idioms_8616",
        "_materialize_callsite_prototypes_8616",
        "_recover_missing_direct_calls_from_evidence_early_8616",
        "_recover_missing_direct_calls_from_evidence_8616",
        "_recover_missing_direct_calls_final_8616",
        "_materialize_callsite_stack_arguments_8616",
        "_materialize_callsite_stack_arguments_final_8616",
        "_materialize_callsite_stack_arguments_after_ss_lowering_8616",
        "_materialize_recovered_callsite_stack_arguments_8616",
        "_materialize_stdlib_call_chains_8616",
        "_materialize_stack_byte_pair_return_8616",
        "_materialize_global_byte_index_sum_loop_8616",
        "_materialize_direct_stack_mov_instructions_8616",
        "_materialize_direct_stack_mov_instructions_final_8616",
        "_materialize_direct_stack_incdec_instructions_8616",
        "_materialize_direct_stack_incdec_instructions_final_8616",
        "_materialize_direct_global_incdec_instructions_8616",
        "_materialize_direct_global_incdec_instructions_final_8616",
        "_materialize_unconsumed_loop_break_jcc_8616",
        "_repair_conditional_continue_guards_from_evidence_8616",
        "_repair_conditional_continue_guards_after_loop_break_8616",
        "_repair_pretest_loop_break_guards_from_evidence_8616",
        "_repair_pretest_loop_break_guards_after_direct_stack_incdec_8616",
        "_repair_pretest_loop_break_guards_after_loop_break_8616",
        "_repair_pretest_loop_break_guards_after_direct_stack_incdec_final_8616",
        "_repair_hoisted_jcc_target_copies_from_evidence_8616",
        "_repair_hoisted_jcc_target_copies_after_direct_stack_mov_8616",
        "_repair_hoisted_jcc_target_copies_after_calls_8616",
        "_repair_hoisted_jcc_target_copies_after_direct_stack_mov_final_8616",
        "_repair_switch_loop_exit_returns_from_evidence_8616",
        "_repair_switch_loop_exit_returns_from_evidence_final_8616",
        "_repair_loop_exit_return_guards_8616",
        "_repair_unresolved_function_exit_gotos_8616",
        "_materialize_cfg_selector_return_branches_early_8616",
        "_materialize_cfg_mask_accumulator_8616",
        "_materialize_cfg_selector_return_branches_8616",
        "_materialize_missing_terminal_ax_return_8616",
        "_materialize_empty_if_return_branches_8616",
        "_materialize_empty_if_return_branches_final_8616",
        "_materialize_void_tail_call_guard_from_cfg_8616",
        "_materialize_void_tail_call_guard_from_cfg_final_8616",
    }
)

_POSTPROCESS_FORMATTING_PREFIXES_8616 = (
    "_normalize_",
    "_simplify_",
)

_POSTPROCESS_SEMANTIC_PREFIXES_8616 = (
    "_materialize_",
    "_recover_",
    "_repair_",
    "_rewrite_flag_",
    "_fix_interval_guard_",
)

_SEMANTIC_EVIDENCE_COUNTERS_8616 = (
    "raw_fact_count",
    "normalized_fact_count",
    "classified_fact_count",
    "materialized_count",
    "failure_count",
)


def _semantic_owner_by_name_8616(name: str) -> str:
    if "jcc" in name or "condition" in name or "flag" in name or "interval_guard" in name:
        return "Step 8: move condition/flag recovery to semantics and structuring"
    if "callsite" in name or "call" in name or "prototype" in name or "stdlib" in name:
        return "Step 9: move call target, argument, prototype, and return effects before rendering"
    if "stack" in name or "bp_" in name:
        return "Step 5: move stack and argument identity to alias/lowering before postprocess"
    if "global" in name or "pointer_memory" in name or "pointer_arg_indirect" in name:
        return "Step 7: move segmented global, array, and pointer-memory recovery to lowering"
    if "loop" in name or "cfg" in name or "continue" in name or "goto" in name or "return_branch" in name:
        return "Step 6: move loop-carried state and CFG repair to structuring"
    if "terminal_ax_return" in name or "empty_if_return" in name:
        return "Step 9: move return-effect recovery before rendering"
    return "Step 4: classified semantic materialization debt pending owner split"


def _postprocess_pass_kind_8616(name: str) -> DecompilerPostprocessPassKind8616:
    if name in _POSTPROCESS_SEMANTIC_MATERIALIZATION_PASS_NAMES_8616:
        return DecompilerPostprocessPassKind8616.SEMANTIC_MATERIALIZATION
    if "dead_code_elimination" in name or name.startswith("optimization:"):
        return DecompilerPostprocessPassKind8616.DCE_WITH_EVIDENCE
    if name.startswith(_POSTPROCESS_FORMATTING_PREFIXES_8616):
        return DecompilerPostprocessPassKind8616.FORMATTING
    if name.startswith(_POSTPROCESS_SEMANTIC_PREFIXES_8616):
        return DecompilerPostprocessPassKind8616.SEMANTIC_MATERIALIZATION
    return DecompilerPostprocessPassKind8616.CLEANUP


def _postprocess_pass_owner_8616(name: str, kind: DecompilerPostprocessPassKind8616) -> str:
    if name in _POSTPROCESS_PASS_OWNER_8616:
        return _POSTPROCESS_PASS_OWNER_8616[name]
    if kind is DecompilerPostprocessPassKind8616.SEMANTIC_MATERIALIZATION:
        return _semantic_owner_by_name_8616(name)
    if kind is DecompilerPostprocessPassKind8616.DCE_WITH_EVIDENCE:
        return "postprocess.optimization.dce with consumed evidence"
    if kind is DecompilerPostprocessPassKind8616.FORMATTING:
        return "rewrite cleanup/formatting only"
    return "postprocess orchestration/cleanup"


def _postprocess_required_evidence_counters_8616(kind: DecompilerPostprocessPassKind8616) -> tuple[str, ...]:
    if kind is DecompilerPostprocessPassKind8616.SEMANTIC_MATERIALIZATION:
        return _SEMANTIC_EVIDENCE_COUNTERS_8616
    return ()


def _postprocess_migration_status_8616(name: str) -> DecompilerPostprocessPassMigrationStatus8616:
    """Return the quarantine migration state for a postprocess pass name."""
    if name in _POSTPROCESS_GUARDED_FALLBACK_PASS_NAMES_8616:
        return DecompilerPostprocessPassMigrationStatus8616.GUARDED_COMPATIBILITY_FALLBACK
    return DecompilerPostprocessPassMigrationStatus8616.ACTIVE_POSTPROCESS_DEBT


def describe_x86_16_decompiler_postprocess_inventory_8616() -> tuple[DecompilerPostprocessPassInventoryItem, ...]:
    """Return typed postprocess pass ownership inventory for quarantine checks."""
    names = (*_DYNAMIC_POSTPROCESS_PASS_NAMES_8616, *(spec.name for spec in DECOMPILER_POSTPROCESS_PASSES))
    items: list[DecompilerPostprocessPassInventoryItem] = []
    for name in names:
        kind = _postprocess_pass_kind_8616(name)
        items.append(
            DecompilerPostprocessPassInventoryItem(
                name=name,
                kind=kind,
                owner=_postprocess_pass_owner_8616(name, kind),
                migration_status=_postprocess_migration_status_8616(name),
                required_evidence_counters=_postprocess_required_evidence_counters_8616(kind),
            )
        )
    return tuple(items)


def validate_x86_16_decompiler_postprocess_inventory_8616() -> tuple[DecompilerPostprocessPassInventoryViolation, ...]:
    """Validate the postprocess quarantine inventory contract."""
    inventory = describe_x86_16_decompiler_postprocess_inventory_8616()
    violations: list[DecompilerPostprocessPassInventoryViolation] = []
    seen_names: set[str] = set()
    for item in inventory:
        if item.name in seen_names:
            violations.append(
                DecompilerPostprocessPassInventoryViolation(
                    name=item.name,
                    reason="duplicate-pass-name",
                )
            )
        seen_names.add(item.name)
        if (
            item.name.startswith(_POSTPROCESS_SEMANTIC_PREFIXES_8616)
            and item.kind is not DecompilerPostprocessPassKind8616.SEMANTIC_MATERIALIZATION
        ):
            violations.append(
                DecompilerPostprocessPassInventoryViolation(
                    name=item.name,
                    reason="semantic-looking-name-not-semantic",
                )
            )
        if item.kind is DecompilerPostprocessPassKind8616.SEMANTIC_MATERIALIZATION:
            if item.required_evidence_counters != _SEMANTIC_EVIDENCE_COUNTERS_8616:
                violations.append(
                    DecompilerPostprocessPassInventoryViolation(
                        name=item.name,
                        reason="semantic-pass-missing-evidence-counters",
                    )
                )
            if "owning semantic/alias/lowering/structuring layer" in item.owner or item.owner.startswith("Step 4:"):
                violations.append(
                    DecompilerPostprocessPassInventoryViolation(
                        name=item.name,
                        reason="semantic-pass-generic-owner",
                    )
                )
        elif item.required_evidence_counters:
            violations.append(
                DecompilerPostprocessPassInventoryViolation(
                    name=item.name,
                    reason="nonsemantic-pass-has-evidence-counters",
                )
            )
    return tuple(violations)
