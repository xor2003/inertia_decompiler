"""Native controller routing with typed stubs, without claiming semantic proof."""
from __future__ import annotations

from pathlib import Path

import pytest
from recursive_proof_fixtures.image_bound_inputs import make_inputs

from tools.dosunit.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.recursive_proofs import real16_image_bound_native_proof as owner
from tools.dosunit.recursive_proofs.loaded_byte_native_transition import (
    LoadedTransitionReason,
    LoadedTransitionResult,
)
from tools.dosunit.recursive_proofs.real16_image_bound_domain import (
    BoundDomainReason,
    ImageBoundReal16Domain,
)
from tools.dosunit.recursive_proofs.real16_image_bound_domain_consumer import BoundDomainConsumption


@pytest.mark.parametrize("boundary", ["before", "transition", "after"])
@pytest.mark.parametrize("deadline", [True, False])
def test_native_controller_retains_child_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str, deadline: bool,
) -> None:
    """The complete ledger survives a child refusal at either temporal boundary."""
    inputs = make_inputs(tmp_path)
    failure = FactCounters(2, 2, 2, 1, 1)
    success = FactCounters(1, 1, 1, 1, 0)
    receipt = ImageBoundReal16Domain(
        ProofStatus.UNKNOWN, BoundDomainReason.SOURCE, inputs.system, "controller-test",
        (), None, (), failure, proposal_hash="controller-test-proposal",
    )
    consumed = 0
    transitions: list[LoadedTransitionResult] = []
    consumers: list[BoundDomainConsumption] = []

    def model_stub() -> str:
        return "controller-test-model"

    def consume_stub(*args: object, **kwargs: object) -> BoundDomainConsumption:
        nonlocal consumed
        consumed += 1
        refused = (boundary == "before" and consumed == 1) or (boundary == "after" and consumed == 2)
        reason = BoundDomainReason.DEADLINE if deadline else BoundDomainReason.SOURCE
        child = BoundDomainConsumption(
            ProofStatus.UNKNOWN if refused else ProofStatus.PROVED,
            reason if refused else BoundDomainReason.DISCHARGED, (),
            failure if refused else success, "typed domain refusal",
        )
        consumers.append(child)
        return child

    def transition_stub(*args: object, **kwargs: object) -> LoadedTransitionResult:
        refused = boundary == "transition"
        reason = LoadedTransitionReason.DEADLINE if deadline else LoadedTransitionReason.LOWERING
        child = LoadedTransitionResult(
            ProofStatus.UNKNOWN if refused else ProofStatus.PROVED,
            reason if refused else LoadedTransitionReason.DISCHARGED, inputs.initialized,
            (), failure if refused else success, detail="typed transition refusal",
        )
        transitions.append(child)
        return child

    monkeypatch.setattr(owner, "image_bound_native_model_hash", model_stub)
    monkeypatch.setattr(owner, "consume_image_bound_real16_domain", consume_stub)
    monkeypatch.setattr(owner, "check_loaded_native_transition", transition_stub)
    report = owner.prove_image_bound_real16_native_relations(receipt, *inputs)
    expected = owner.ImageBoundNativeReason.TRANSITION if boundary == "transition" else owner.ImageBoundNativeReason.PREREQUISITE
    if deadline:
        expected = owner.ImageBoundNativeReason.DEADLINE
    assert report.status is ProofStatus.UNKNOWN and report.reason is expected
    assert report.transitions == tuple(transitions)
    assert report.consumers == tuple(consumers)
    assert len(report.required) == 4 + len(inputs.system.steps)
    assert report.counters.raw_fact_count == len(report.required)
    assert report.counters.failure_count > 0
    assert report.facts[-1].status is ProofStatus.UNKNOWN
    assert not report.binary_equivalence_proved
