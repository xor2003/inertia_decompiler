"""Tests for typed guarded postprocess transaction policy."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import inertia.postprocess.decompiler_postprocess_stage as stage

from inertia.postprocess.pass_transaction import (
    PostprocessMutationGeneration8616,
    PostprocessMutationWitnessCache8616,
    PostprocessPassPreflightAction8616,
    PostprocessPassPreflightInput8616,
    PostprocessPassTransactionState8616,
    decide_postprocess_pass_preflight_8616,
)
from inertia.validation.tail_validation import X86_16TailValidationSummary


def _summary() -> X86_16TailValidationSummary:
    """Build one complete immutable validation baseline."""
    return X86_16TailValidationSummary((), (), (), (), (), (), (), ())


def _request(
    pass_name: str,
    *,
    validation_enabled: bool = True,
    per_pass_validation_enabled: bool = False,
    large_function_skip: bool = False,
    force_per_pass_requested: bool = False,
    optional_reject_budget: int = 0,
    optional_reject_count: int = 0,
    local_evidence_present: bool | None = None,
) -> PostprocessPassPreflightInput8616:
    return PostprocessPassPreflightInput8616(
        pass_name=pass_name,
        validation_enabled=validation_enabled,
        per_pass_validation_enabled=per_pass_validation_enabled,
        large_function_skip=large_function_skip,
        force_per_pass_requested=force_per_pass_requested,
        optional_reject_budget=optional_reject_budget,
        optional_reject_count=optional_reject_count,
        local_evidence_present=local_evidence_present,
    )


def test_ordinary_pass_executes_without_snapshot_or_validation() -> None:
    decision = decide_postprocess_pass_preflight_8616(_request("ordinary_cleanup"))

    assert decision.action is PostprocessPassPreflightAction8616.EXECUTE
    assert decision.requires_snapshot is False
    assert decision.enforce_pass_validation is False


def test_mandatory_pass_enforces_validation_on_bounded_function() -> None:
    decision = decide_postprocess_pass_preflight_8616(
        _request("_apply_annotations_8616", local_evidence_present=True)
    )

    assert decision.action is PostprocessPassPreflightAction8616.EXECUTE
    assert decision.force_pass_validation is True
    assert decision.requires_snapshot is True
    assert decision.enforce_pass_validation is True


def test_force_request_enforces_mandatory_validation_on_large_function() -> None:
    decision = decide_postprocess_pass_preflight_8616(
        _request(
            "_apply_annotations_8616",
            large_function_skip=True,
            force_per_pass_requested=True,
        )
    )

    assert decision.action is PostprocessPassPreflightAction8616.EXECUTE
    assert decision.force_pass_validation is True
    assert decision.requires_snapshot is True
    assert decision.enforce_pass_validation is True


def test_large_function_local_proof_is_probed_then_refused() -> None:
    request = _request(
        "_apply_word_global_types_8616",
        large_function_skip=True,
    )

    probe = decide_postprocess_pass_preflight_8616(request)
    refused = decide_postprocess_pass_preflight_8616(
        request.with_local_evidence(False)
    )
    allowed = decide_postprocess_pass_preflight_8616(
        request.with_local_evidence(True)
    )

    assert probe.action is PostprocessPassPreflightAction8616.PROBE_LOCAL_EVIDENCE
    assert refused.action is PostprocessPassPreflightAction8616.REFUSE_LOCAL_PROOF
    assert allowed.action is PostprocessPassPreflightAction8616.EXECUTE


def test_optional_reject_budget_is_probed_then_skipped() -> None:
    request = _request(
        "_apply_annotations_8616",
        optional_reject_budget=2,
        optional_reject_count=2,
    )

    probe = decide_postprocess_pass_preflight_8616(request)
    skipped = decide_postprocess_pass_preflight_8616(
        request.with_local_evidence(False)
    )

    assert probe.action is PostprocessPassPreflightAction8616.PROBE_LOCAL_EVIDENCE
    assert skipped.action is PostprocessPassPreflightAction8616.SKIP_REJECT_BUDGET


def test_optimization_pass_always_keeps_snapshot_and_validation() -> None:
    decision = decide_postprocess_pass_preflight_8616(
        _request("optimization:adjacent_temporary_copy_prune", large_function_skip=True)
    )

    assert decision.action is PostprocessPassPreflightAction8616.EXECUTE
    assert decision.is_optimization_pass is True
    assert decision.requires_snapshot is True
    assert decision.enforce_pass_validation is True


def test_transaction_state_owns_baseline_cycle_and_accepted_change() -> None:
    baseline = _summary()
    accepted = replace(baseline, register_writes=("ax",))
    state = PostprocessPassTransactionState8616(
        baseline_summary=baseline,
        known_cycle_path=None,
    )

    state.replace_baseline(accepted)
    state.record_cycle_path(("root", "child"))
    state.accept_change("cleanup")

    assert state.baseline_summary is accepted
    assert baseline.register_writes == ()
    assert state.known_cycle_path == ("root", "child")
    assert state.accepted_changed is True
    assert state.last_changed_pass == "cleanup"
    assert state.mutation_generation() == PostprocessMutationGeneration8616(
        value=1,
        last_changed_pass="cleanup",
    )


def test_completion_publishes_only_accepted_transaction_mutations() -> None:
    """Close every stage path with one typed immutable consumer generation."""
    project = SimpleNamespace()
    codegen = SimpleNamespace()
    state = PostprocessPassTransactionState8616(
        baseline_summary=None,
        known_cycle_path=None,
    )

    assert stage._postprocess_set_completion_state_8616(project, codegen, state) is False
    assert codegen._inertia_postprocess_mutation_generation_8616 == (
        PostprocessMutationGeneration8616(0, None)
    )

    state.accept_change("witnessed-change")
    state.accept_change("validated-change")
    assert stage._postprocess_set_completion_state_8616(project, codegen, state) is True
    assert codegen._inertia_postprocess_mutation_generation_8616 == (
        PostprocessMutationGeneration8616(2, "validated-change")
    )


def test_rejected_or_restored_state_does_not_advance_generation() -> None:
    """Keep rollback bookkeeping outside the accepted mutation generation."""
    state = PostprocessPassTransactionState8616(
        baseline_summary=_summary(),
        known_cycle_path=None,
    )

    state.record_cycle_path(("root", "changed"))
    state.replace_baseline(_summary())
    state.record_cycle_path(("root", "restored"))

    assert state.mutation_generation() == PostprocessMutationGeneration8616(0, None)


def test_mutation_witness_reuses_only_until_explicit_invalidation() -> None:
    cache = PostprocessMutationWitnessCache8616[str]()
    builds = 0

    def _build() -> str:
        nonlocal builds
        builds += 1
        return f"generation-{builds}"

    assert cache.current_or_build(_build) == "generation-1"
    cache.record("generation-1-after")
    assert cache.current_or_build(_build) == "generation-1-after"
    cache.invalidate()
    assert cache.current_or_build(_build) == "generation-2"

    stats = cache.stats()
    assert stats.closed
    assert stats.lookup_count == 3
    assert stats.rebuild_count == 2
    assert stats.reuse_count == 1
    assert stats.record_count == 1
    assert stats.invalidation_count == 1
