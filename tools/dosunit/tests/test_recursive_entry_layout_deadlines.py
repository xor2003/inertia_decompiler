"""Typed layout exceptions retain their cause at the entry controller boundary."""
from __future__ import annotations

from pathlib import Path

import pytest
from tools.dosunit.tests.recursive_proof_fixtures.image_bound_inputs import make_inputs

from tools.dosunit.contracts.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.recursive_proofs import real16_entry_frame as owner
from tools.dosunit.recursive_proofs.real16_image_bound_domain import (
    BoundDomainReason,
    ImageBoundReal16Domain,
)
from tools.dosunit.recursive_proofs.real16_image_bound_domain_consumer import BoundDomainConsumption
from tools.dosunit.recursive_proofs.recursive_joint_admission import JointRefusal
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointReason


@pytest.mark.parametrize("deadline", [True, False])
def test_entry_retains_typed_layout_refusal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                          deadline: bool) -> None:
    """A layout deadline remains a resource refusal with no entry-side promotion."""
    inputs = make_inputs(tmp_path)
    counts = FactCounters(1, 1, 1, 1, 0)
    receipt = ImageBoundReal16Domain(ProofStatus.UNKNOWN, BoundDomainReason.SOURCE, inputs.system,
        "controller-test", (), None, (), counts, proposal_hash="controller-test-proposal")
    consumption = BoundDomainConsumption(ProofStatus.PROVED, BoundDomainReason.DISCHARGED, (), counts)

    def consume_stub(*args: object, **kwargs: object) -> BoundDomainConsumption:
        return consumption

    def model_stub() -> str:
        return "controller-test-model"

    def layout_stub(*args: object, **kwargs: object) -> None:
        raise JointRefusal(JointReason.DEADLINE if deadline else JointReason.LAYOUT, "typed layout refusal")

    monkeypatch.setattr(owner, "consume_image_bound_real16_domain", consume_stub)
    monkeypatch.setattr(owner, "entry_frame_model_hash", model_stub)
    monkeypatch.setattr(owner, "derive_joint_frame_layout", layout_stub)
    report = owner.prove_real16_entry_frame(receipt, *inputs)
    assert report.status is ProofStatus.UNKNOWN
    assert report.reason is (owner.EntryFrameReason.DEADLINE if deadline else owner.EntryFrameReason.PREREQUISITE)
    assert report.consumers == (consumption,) and not report.sides
    assert report.counters.raw_fact_count == len(owner.EntryFrameObligation)
    assert report.counters.materialized_count == 2 and report.counters.failure_count > 0
    assert report.facts[-1].obligation is owner.EntryFrameObligation.LAYOUT
    assert report.facts[-1].status is ProofStatus.UNKNOWN
    assert report.detail == "typed layout refusal" and not report.binary_equivalence_proved
