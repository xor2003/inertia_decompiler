"""Function-owned maturity, refusal transport and detached-claim boundaries."""

from types import SimpleNamespace

import pytest

from inertia.ir.function_lifecycle import (
    FunctionLifecycle8616,
    FunctionLifecycleState8616,
    FunctionStageEvidence8616,
    FunctionStageFailure8616,
    FunctionStageReadiness8616,
    FunctionStageVerdict8616,
    bind_function_lifecycle_8616,
    bind_function_lifecycle_source_8616,
    existing_function_lifecycle_state_8616,
    observe_function_source_refusal_8616,
)
from inertia.ir.function_readiness_contracts import FUNCTION_LIFECYCLE_STAGES_8616, FunctionLifecycleStage8616

pytestmark = pytest.mark.decompiler


def test_source_change_observation_does_not_create_lifecycle() -> None:
    """A failed lookup cannot manufacture producer state or a new generation."""
    project = SimpleNamespace()
    observe_function_source_refusal_8616(
        project, 0x1000, FunctionStageFailure8616.SOURCE_REVISION_CHANGED,
    )
    assert existing_function_lifecycle_state_8616(project, 0x1000) is None


def _checked_prefix(state: FunctionLifecycleState8616) -> None:
    """Provide checked consumer observations through the canonical stage order."""
    for stage in FUNCTION_LIFECYCLE_STAGES_8616:
        state.observe(FunctionStageReadiness8616(0x1000, stage, FunctionStageVerdict8616.CURRENT))


def test_changed_producer_revokes_descendant_maturity_without_erasing_history() -> None:
    """Replacing an early producer cannot retain cached late-stage success."""
    state = FunctionLifecycleState8616()
    for stage in FUNCTION_LIFECYCLE_STAGES_8616:
        state.record(FunctionStageEvidence8616(stage, None, (stage.value,), (), "original"))
    _checked_prefix(state)
    assert state.maturity is FunctionLifecycleStage8616.REWRITE
    state.record(FunctionStageEvidence8616(FunctionLifecycleStage8616.ALIAS, None, ("new",), (), "new"))
    assert state.maturity is FunctionLifecycleStage8616.IR
    assert FunctionLifecycleStage8616.REWRITE in state.publications
    assert FunctionLifecycleStage8616.REWRITE not in state.evaluations


def test_shared_projections_transport_a_typed_source_refusal() -> None:
    """An observed source failure revokes maturity in every bound projection."""
    project = SimpleNamespace()
    raw, ssa = FunctionLifecycle8616(), FunctionLifecycle8616()
    bind_function_lifecycle_8616(project, 0x1000, raw)
    bind_function_lifecycle_8616(project, 0x1000, ssa)
    assert raw.state is ssa.state
    _checked_prefix(raw.state)
    raw.state.observe(FunctionStageReadiness8616(
        0x1000, FunctionLifecycleStage8616.REWRITE, FunctionStageVerdict8616.STALE,
        FunctionLifecycleStage8616.IR, FunctionStageFailure8616.SOURCE_REVISION_CHANGED,
    ))
    assert ssa.state.maturity is None
    assert raw.to_dict() == ssa.to_dict()
    refusal = ssa.state.evaluations[FunctionLifecycleStage8616.REWRITE]
    assert refusal.failure is FunctionStageFailure8616.SOURCE_REVISION_CHANGED


def test_binding_a_detached_projection_cannot_import_its_maturity() -> None:
    """Restored or copied lifecycle claims never establish runtime authority."""
    detached = FunctionLifecycle8616()
    _checked_prefix(detached.state)
    assert detached.state.maturity is FunctionLifecycleStage8616.REWRITE
    project = SimpleNamespace()
    bind_function_lifecycle_8616(project, 0x1000, detached)
    assert detached.state.maturity is None
    assert not detached.state.publications
    assert detached.state is existing_function_lifecycle_state_8616(project, 0x1000)


def test_missing_lifecycle_lookup_does_not_create_state() -> None:
    """Read-only diagnostics must not create a function state or project ledger."""
    project = SimpleNamespace()
    assert existing_function_lifecycle_state_8616(project, 0x1000) is None
    assert vars(project) == {}


def test_pipeline_consumes_the_canonical_ir_stage_contracts() -> None:
    """Pipeline verdicts and IR diagnostics must use the same enum and records."""
    from inertia.pipeline import function_readiness

    assert function_readiness.FunctionStageVerdict8616 is FunctionStageVerdict8616
    assert function_readiness.FunctionStageEvidence8616 is FunctionStageEvidence8616


def test_accepted_new_ir_body_revokes_previous_runtime_publications() -> None:
    """Old projections cannot borrow a new generation's eventual maturity."""
    project = SimpleNamespace()
    old, new = FunctionLifecycle8616(), FunctionLifecycle8616()
    bind_function_lifecycle_source_8616(project, 0x1000, old, None, "old_body")
    old.state.record(FunctionStageEvidence8616(
        FunctionLifecycleStage8616.REWRITE, None, ("old_output",), (), "original",
    ))
    _checked_prefix(old.state)
    bind_function_lifecycle_source_8616(project, 0x1000, new, None, "new_body")
    assert old.state is not new.state
    assert old.state.maturity is None
    assert old.state.publications
    assert old.state.ir_body_digest == "old_body"
    assert new.state.ir_body_digest == "new_body"
    _checked_prefix(new.state)
    assert new.state.maturity is FunctionLifecycleStage8616.REWRITE
    assert old.state.maturity is None
    assert old.state.evaluations[FunctionLifecycleStage8616.REWRITE].failure is FunctionStageFailure8616.UPSTREAM_EVIDENCE_CHANGED



def test_projection_handle_cannot_change_its_owning_function() -> None:
    """Sharing a copied handle across unrelated functions is an explicit defect."""
    project = SimpleNamespace()
    handle = FunctionLifecycle8616()
    bind_function_lifecycle_8616(project, 0x1000, handle)
    with pytest.raises(ValueError, match="owning function"):
        bind_function_lifecycle_8616(project, 0x2000, handle)
    assert handle.function_addr == 0x1000
    assert existing_function_lifecycle_state_8616(project, 0x2000) is None
