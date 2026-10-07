"""Typed receipt-consumer child causes remain explicit without granting proof."""
from __future__ import annotations

from pathlib import Path

import pytest
from tools.dosunit.tests.recursive_proof_fixtures.image_bound_inputs import make_inputs

from tools.dosunit.contracts.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.recursive_proofs import real16_image_bound_domain_consumer as owner
from tools.dosunit.recursive_proofs.loaded_byte_native_transition import LoadedTransitionReason, _TransitionRefusal
from tools.dosunit.recursive_proofs.real16_image_bound_domain import BoundDomainReason, ImageBoundReal16Domain
from tools.dosunit.recursive_proofs.real16_native_effect_binding import NativeBindingReason, _NativeRefusal
from tools.dosunit.recursive_proofs.recursive_joint_admission import JointRefusal
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointReason


@pytest.mark.parametrize("child", ["transition", "native", "joint"])
@pytest.mark.parametrize("deadline", [True, False])
def test_receipt_consumer_retains_child_deadline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                child: str, deadline: bool) -> None:
    """Child exceptions keep cause and all required facts; none grants a proof."""
    inputs = make_inputs(tmp_path)
    success = FactCounters(1, 1, 1, 1, 0)
    receipt = ImageBoundReal16Domain(ProofStatus.UNKNOWN, BoundDomainReason.SOURCE,
        inputs.system, "controller-only", (), None, (), success, proposal_hash="controller-only")
    refusals = {
        "transition": _TransitionRefusal(LoadedTransitionReason.DEADLINE if deadline else LoadedTransitionReason.DOMAIN,
                                          "typed transition child refusal"),
        "native": _NativeRefusal(NativeBindingReason.DEADLINE if deadline else NativeBindingReason.MANIFEST,
                                  "typed native child refusal"),
        "joint": JointRefusal(JointReason.DEADLINE if deadline else JointReason.LAYOUT,
                               "typed joint child refusal"),
    }
    refusal = refusals[child]
    causes = {"transition": BoundDomainReason.STATE, "native": BoundDomainReason.SOURCE,
              "joint": BoundDomainReason.JOINT}

    def refuse(run: owner._BoundRun, received: ImageBoundReal16Domain,
               facts: list[owner.DomainConsumptionFact]) -> None:
        assert run.system is inputs.system and received is receipt
        facts.append(owner.DomainConsumptionFact(owner.DomainConsumptionObligation.RECEIPT, ProofStatus.PROVED))
        raise refusal

    monkeypatch.setattr(owner, "_verify_prerequisites", refuse)
    outcome = owner.consume_image_bound_real16_domain(receipt, *inputs)
    assert outcome.status is ProofStatus.UNKNOWN
    assert outcome.reason is (BoundDomainReason.DEADLINE if deadline else causes[child])
    assert outcome.detail == str(refusal)
    assert tuple(row.obligation for row in outcome.facts) == (
        owner.DomainConsumptionObligation.RECEIPT, owner.DomainConsumptionObligation.CONTENT)
    assert outcome.facts[-1].status is ProofStatus.UNKNOWN
    count = len(owner.DomainConsumptionObligation)
    assert outcome.counters == FactCounters(count, count, count, 2, count - 1)
