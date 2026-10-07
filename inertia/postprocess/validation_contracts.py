"""Typed contracts for postprocess validation and recovery policy.

Layer: Rewrite/Postprocess cleanup.
Responsibility: own validation verdict kinds, refusal reasons, salvage families,
and immutable complexity/evidence records used by the guarded pass driver.
Consumes already-proven IR, alias, widening, typed, and structuring facts. Do
not recover new semantics, storage identity, types, call signatures, control
flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, MutableMapping
from dataclasses import dataclass
from enum import Enum
from typing import Self

from inertia.structuring.guard_decisions import VoidTailCallGuardDecision8616

__all__ = [
    "CfgReturnExprDeltaRefusal8616",
    "DirectGlobalSymbolRef8616",
    "PostprocessDestructiveSalvageFamily8616",
    "PostprocessFunctionComplexity8616",
    "PostprocessPassRefusalReason8616",
    "PostprocessValidationBlockingReason8616",
    "PostprocessValidationDeltaKind8616",
    "TerminalStackArgDecision8616",
    "VoidEmptyReturnGuardDecision8616",
    "VoidTailCallGuardDecision8616",
    "postprocess_validation_blocking_reasons_8616",
    "record_postprocess_validation_blocking_reason_8616",
]


class PostprocessValidationDeltaKind8616(Enum):
    """Classify an observed postprocess validation delta."""

    BLOCKING = "blocking"
    NAME_ONLY_HELPER_ANNOTATION = "name_only_helper_annotation"
    JCC_CALL_RETURN_CONDITION_REBINDING = "jcc_call_return_condition_rebinding"
    JCC_CONDITION_MATERIALIZATION = "jcc_condition_materialization"
    DIRECT_GLOBAL_UPDATE_MATERIALIZATION = "direct_global_update_materialization"
    GLOBAL_BYTE_SUM_LOOP_MATERIALIZATION = "global_byte_sum_loop_materialization"
    DIRECT_STACK_UPDATE_MATERIALIZATION = "direct_stack_update_materialization"
    DIRECT_STACK_MOVE_MATERIALIZATION = "direct_stack_move_materialization"
    DIRECT_STACK_MOVE_UPDATE_MATERIALIZATION = "direct_stack_move_update_materialization"
    UNREACHABLE_AFTER_RETURN_PRUNE = "unreachable_after_return_prune"
    CALLSITE_STACK_ARGUMENT_MATERIALIZATION = "callsite_stack_argument_materialization"
    STACK_PROTOTYPE_WIDTH_RECONCILIATION = "stack_prototype_width_reconciliation"
    STACK_PROBE_HELPER_CLEANUP = "stack_probe_helper_cleanup"
    MISSING_TERMINAL_AX_RETURN = "missing_terminal_ax_return"
    CFG_RETURN_CHAIN_MATERIALIZATION = "cfg_return_chain_materialization"
    CFG_RETURN_EXPR_CHAIN_MATERIALIZATION = "cfg_return_expr_chain_materialization"
    DEFAULT_SCALAR_VOID_RETURN_CLASSIFICATION = "default_scalar_void_return_classification"
    UNOBSERVED_DEFAULT_SCALAR_SYNTHETIC_RETURN = "unobserved_default_scalar_synthetic_return"
    EXPOSED_NONVOID_STACK_ARG_SCALAR_RETURN = "exposed_nonvoid_stack_arg_scalar_return"
    CFG_VOID_TAIL_CALL_GUARD_MATERIALIZATION = "cfg_void_tail_call_guard_materialization"
    PROVEN_SURPLUS_EMPTY_GUARD_CLEANUP = "proven_surplus_empty_guard_cleanup"
    CONDITIONAL_CONTINUE_GUARD_REPAIR = "conditional_continue_guard_repair"
    SWITCH_LOOP_EXIT_RETURN_REPAIR = "switch_loop_exit_return_repair"


class PostprocessValidationBlockingReason8616(Enum):
    """Explain why validation must reject a postprocess delta."""

    MISSING_SOURCE_EVIDENCED_CALLS = "missing_source_evidenced_calls"
    MISSING_SOURCE_EVIDENCED_CALL_MULTIPLICITY = "missing_source_evidenced_call_multiplicity"
    SOURCE_EVIDENCED_ARGUMENT_CLASS_MISMATCH = "source_evidenced_argument_class_mismatch"
    SOURCE_EVIDENCED_CALL_ORDER_MISMATCH = "source_evidenced_call_order_mismatch"
    SOURCE_EVIDENCED_LOOP_STRUCTURE_MISSING = "source_evidenced_loop_structure_missing"
    SOURCE_EVIDENCED_LOOP_CALL_HOISTED = "source_evidenced_loop_call_hoisted"
    UNREACHABLE_CALL_AFTER_RETURN = "unreachable_call_after_return"
    SOURCE_EVIDENCED_SIDE_EFFECT_FLOOR_NOT_MET = "source_evidenced_side_effect_floor_not_met"
    DESTRUCTIVE_POSTPROCESS_VALIDATION_DELTA = "destructive_postprocess_validation_delta"

    @classmethod
    def coerce(cls, value: object) -> Self | None:
        """Convert stored validation-reason values into the typed enum."""
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            try:
                return cls(value)
            except ValueError:
                return None
        return None


def postprocess_validation_blocking_reasons_8616(
    validation: Mapping[str, object],
) -> tuple[PostprocessValidationBlockingReason8616, ...]:
    """Read unique typed blocking reasons from one validation result."""
    raw_reasons = validation.get("postprocess_validation_blocking_reasons")
    if raw_reasons is None:
        return ()
    if isinstance(raw_reasons, (str, PostprocessValidationBlockingReason8616)):
        raw_items = (raw_reasons,)
    elif isinstance(raw_reasons, Iterable):
        raw_items = tuple(raw_reasons)
    else:
        return ()
    reasons: list[PostprocessValidationBlockingReason8616] = []
    for raw in raw_items:
        reason = PostprocessValidationBlockingReason8616.coerce(raw)
        if reason is not None and reason not in reasons:
            reasons.append(reason)
    return tuple(reasons)


def record_postprocess_validation_blocking_reason_8616(
    validation: MutableMapping[str, object],
    reason: PostprocessValidationBlockingReason8616,
) -> None:
    """Append one typed blocking reason without duplicating stored values."""
    reasons = list(postprocess_validation_blocking_reasons_8616(validation))
    if reason not in reasons:
        reasons.append(reason)
    validation["postprocess_validation_blocking_reasons"] = tuple(
        item.value for item in reasons
    )


class PostprocessDestructiveSalvageFamily8616(Enum):
    """Identify the only salvage family allowed after destructive rejection."""

    DIRECT_STACK_UPDATE = "direct_stack_update"
    DIRECT_STACK_MOVE = "direct_stack_move"
    UNKNOWN = "unknown"


class CfgReturnExprDeltaRefusal8616(Enum):
    """Explain refusal of a CFG return-expression validation delta."""

    MISSING_EVIDENCE = "missing_evidence"
    MISSING_DELTA = "missing_delta"
    UNEXPECTED_FIELDS = "unexpected_fields"
    MISSING_RETURNS_DELTA = "missing_returns_delta"
    UNEXPECTED_ADDED_RETURNS = "unexpected_added_returns"
    UNEXPECTED_REMOVED_RETURNS = "unexpected_removed_returns"
    UNEXPECTED_ADDED_CONDITIONS = "unexpected_added_conditions"
    UNEXPECTED_ADDED_CONTROL = "unexpected_added_control"
    UNEXPECTED_HELPER_DELTA = "unexpected_helper_delta"


class VoidEmptyReturnGuardDecision8616(Enum):
    """Classify an empty-return guard pruning decision."""

    PRUNE = "prune"
    KEEP_NOT_VOID = "keep_not_void"
    KEEP_NO_BRANCH_PROOF = "keep_no_branch_proof"
    KEEP_WITHIN_BRANCH_BUDGET = "keep_within_branch_budget"
    KEEP_BRANCH_BACKED_CONDITION = "keep_branch_backed_condition"
    KEEP_NOT_EMPTY_RETURN_GUARD = "keep_not_empty_return_guard"


class PostprocessPassRefusalReason8616(Enum):
    """Explain why the guarded driver refused to execute a pass."""

    LARGE_FUNCTION_LOCAL_VALIDATION_UNAVAILABLE = "large_function_local_validation_unavailable"
    VERY_LARGE_FUNCTION_LOCAL_VALIDATION_UNAVAILABLE = "very_large_function_local_validation_unavailable"


class TerminalStackArgDecision8616(Enum):
    """Classify terminal stack-argument declaration materialization."""

    EXISTING_ARG = "existing_arg"
    EXISTING_STACK_SLOT = "existing_stack_slot"
    MATERIALIZED_ARG = "materialized_arg"
    MATERIALIZED_STACK_SLOT = "materialized_stack_slot"
    FALLBACK = "fallback"


@dataclass(frozen=True, slots=True)
class PostprocessFunctionComplexity8616:
    """Bounded function-size facts used by postprocess validation policy."""

    block_count: int = 0
    byte_count: int = 0
    source: str = "missing"

    @property
    def is_expensive_for_local_validation(self) -> bool:
        """Return whether bounded per-pass validation exceeds the local budget."""
        return bool(
            self.block_count >= 40
            or self.byte_count >= 640
            or (self.block_count >= 36 and self.byte_count >= 360)
        )


@dataclass(frozen=True, slots=True)
class DirectGlobalSymbolRef8616:
    """Describe one direct global symbol projection used by postprocess."""

    name: str
    relative_disp: int
    width: int
    max_relative_disp: int
