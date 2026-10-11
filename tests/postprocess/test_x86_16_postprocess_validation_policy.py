"""Tests for typed postprocess validation contracts and static pass policy."""

from __future__ import annotations

from inertia.lowering.real_mode_linear import DirectStackMoveSourceKind8616
from inertia.postprocess.pass_validation_policy import (
    CALL_RECOVERY_VALIDATION_PASS_NAMES_8616,
    DIRECT_GLOBAL_UPDATE_VALIDATION_PASS_NAMES_8616,
    DIRECT_STACK_MOVE_VALIDATION_PASS_NAMES_8616,
    JCC_REWRITE_VALIDATION_PASS_NAMES_8616,
    LOCAL_PROOF_REQUIRED_POSTPROCESS_PASS_NAMES_8616,
    MANDATORY_VALIDATION_PASS_NAMES_8616,
    NON_IDIV_DIRECT_STACK_MOVE_SOURCE_KINDS_8616,
    OPTIMIZATION_VALIDATION_PASS_NAMES_8616,
    PASS_LOCAL_REJECT_CONTINUE_PASS_NAMES_8616,
    PASS_REJECT_BUDGET_ELIGIBLE_NAMES_8616,
)
from inertia.postprocess.validation_contracts import (
    DirectGlobalSymbolRef8616,
    PostprocessFunctionComplexity8616,
    PostprocessValidationBlockingReason8616,
    VoidTailCallGuardDecision8616,
)
from inertia.structuring.guard_decisions import (
    VoidTailCallGuardDecision8616 as StructuringVoidTailCallGuardDecision8616,
)


def test_validation_blocking_reason_coerce_is_typed_and_refuses_unknown_values() -> None:
    """Stored diagnostics narrow to the enum without inventing unknown states."""
    reason = PostprocessValidationBlockingReason8616.MISSING_SOURCE_EVIDENCED_CALLS

    assert PostprocessValidationBlockingReason8616.coerce(reason) is reason
    assert PostprocessValidationBlockingReason8616.coerce(reason.value) is reason
    assert PostprocessValidationBlockingReason8616.coerce("unknown") is None
    assert PostprocessValidationBlockingReason8616.coerce(1) is None


def test_void_tail_call_guard_decision_has_one_structuring_owner() -> None:
    """The postprocess compatibility export is the Structuring-owned enum."""
    assert VoidTailCallGuardDecision8616 is StructuringVoidTailCallGuardDecision8616


def test_function_complexity_uses_the_owned_local_validation_thresholds() -> None:
    """The immutable complexity contract keeps all three expensive boundaries."""
    assert not PostprocessFunctionComplexity8616(block_count=35, byte_count=639).is_expensive_for_local_validation
    assert PostprocessFunctionComplexity8616(block_count=40).is_expensive_for_local_validation
    assert PostprocessFunctionComplexity8616(byte_count=640).is_expensive_for_local_validation
    assert PostprocessFunctionComplexity8616(block_count=36, byte_count=360).is_expensive_for_local_validation


def test_direct_global_symbol_reference_is_immutable() -> None:
    """Direct-global policy evidence is a stable value contract."""
    ref = DirectGlobalSymbolRef8616(name="g_1234", relative_disp=2, width=2, max_relative_disp=3)

    assert (ref.name, ref.relative_disp, ref.width, ref.max_relative_disp) == ("g_1234", 2, 2, 3)


def test_all_optimization_passes_require_local_and_mandatory_validation() -> None:
    """Adding an optimization automatically keeps it inside both validation gates."""
    assert OPTIMIZATION_VALIDATION_PASS_NAMES_8616
    assert OPTIMIZATION_VALIDATION_PASS_NAMES_8616 <= LOCAL_PROOF_REQUIRED_POSTPROCESS_PASS_NAMES_8616
    assert OPTIMIZATION_VALIDATION_PASS_NAMES_8616 <= MANDATORY_VALIDATION_PASS_NAMES_8616


def test_reject_budget_excludes_high_risk_semantic_pass_families() -> None:
    """Budgeted continuation never covers call, global, stack-move, or JCC repair."""
    excluded = (
        CALL_RECOVERY_VALIDATION_PASS_NAMES_8616
        | DIRECT_GLOBAL_UPDATE_VALIDATION_PASS_NAMES_8616
        | DIRECT_STACK_MOVE_VALIDATION_PASS_NAMES_8616
        | JCC_REWRITE_VALIDATION_PASS_NAMES_8616
    )

    assert PASS_REJECT_BUDGET_ELIGIBLE_NAMES_8616.isdisjoint(excluded)


def test_unused_global_declaration_prune_restores_on_validation_rejection() -> None:
    """Declaration-only cleanup may be discarded without rejecting valid C."""
    pass_name = "_prune_unused_unnamed_memory_declarations_8616"

    assert pass_name in PASS_LOCAL_REJECT_CONTINUE_PASS_NAMES_8616
    assert pass_name in PASS_REJECT_BUDGET_ELIGIBLE_NAMES_8616
    assert pass_name not in MANDATORY_VALIDATION_PASS_NAMES_8616
    assert pass_name not in LOCAL_PROOF_REQUIRED_POSTPROCESS_PASS_NAMES_8616


def test_non_idiv_stack_move_policy_excludes_only_signed_remainder() -> None:
    """The special signed-IDIV remainder path stays outside generic move policy."""
    assert DirectStackMoveSourceKind8616.SIGNED_IDIV_REMAINDER not in NON_IDIV_DIRECT_STACK_MOVE_SOURCE_KINDS_8616
    assert frozenset(
        kind
        for kind in DirectStackMoveSourceKind8616
        if kind is not DirectStackMoveSourceKind8616.SIGNED_IDIV_REMAINDER
    ) == NON_IDIV_DIRECT_STACK_MOVE_SOURCE_KINDS_8616


from types import SimpleNamespace

import pytest

import inertia.postprocess.decompiler_postprocess_stage as post_stage
from inertia.validation.tail_validation import (
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
    x86_16_tail_validation_result_passed,
)
from tests.ir.test_declared_entry_scoped_view import native_scope as native_scope
from tests.validation.test_declared_entry_tail import attached as attached


@pytest.mark.parametrize("outcome", ["conditional", "refused", "changed", "damaged", "semantic_failure", "premise_failure"])
def test_rollback_identity_retains_only_preserved_conditional_result(attached, outcome):
    """Same-scope equality permits restoration without laundering its premise."""
    project, codegen = attached
    summary = collect_x86_16_tail_validation_summary(project, codegen)
    result = compare_x86_16_tail_validation_summaries(summary, summary)
    receipt = result["entry_premise"]
    result.update(status=outcome if outcome in {"refused", "changed"} else "conditional", changed=outcome == "changed")
    if outcome == "damaged":
        receipt["sha256"] = "0" * 64
    elif outcome == "semantic_failure":
        result["semantic_failures"] = ["retained failure"]
    elif outcome == "premise_failure":
        result["premise_failure"] = "entry_premise_missing_or_invalid"
    owner = SimpleNamespace(codegen=codegen)
    post_stage._apply_destructive_discard_identity_gate_8616(owner, result, True)
    assert bool(getattr(codegen, "_inertia_postprocess_final_c_identity_proven_8616", False)) == (outcome == "conditional")
    assert result["entry_premise"] is receipt
    assert result["status"] == ("conditional" if outcome == "conditional" else "changed")
    assert not x86_16_tail_validation_result_passed(result)


def test_unconditional_stable_result_still_preserves_local_behavior():
    """Local acceptance does not change existing unconditional success."""
    result = {"status": "stable", "changed": False}
    assert post_stage.x86_16_tail_validation_result_preserves_behavior(result)
    assert x86_16_tail_validation_result_passed(result)
