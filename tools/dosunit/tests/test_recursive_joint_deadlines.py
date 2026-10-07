"""Controller-only typed refusal routing; stub successes are not semantic proof."""
from __future__ import annotations

import time
from dataclasses import replace
from pathlib import Path

import pytest
from tools.dosunit.tests.recursive_proof_fixtures.image_bound_inputs import make_inputs

from tools.dosunit.contracts.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.recursive_proofs import real16_image_bound_joint_proof as owner
from tools.dosunit.recursive_proofs import recursive_joint_admission as admission
from tools.dosunit.recursive_proofs.loaded_byte_relation import LoadedRelationLimits
from tools.dosunit.recursive_proofs.real16_code_prefix_proof import (
    CodePrefixReason,
    Real16CodePrefixProof,
)
from tools.dosunit.recursive_proofs.real16_entry_frame import EntryFrameReason, Real16EntryFrameProof
from tools.dosunit.recursive_proofs.real16_image_bound_domain import (
    BoundDomainReason,
    ImageBoundReal16Domain,
)
from tools.dosunit.recursive_proofs.real16_image_bound_native_proof import (
    ImageBoundNativeProof,
    ImageBoundNativeReason,
)
from tools.dosunit.recursive_proofs.recursive_joint_admission import admit_joint_system
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointModelRequirement, JointReason
from tools.dosunit.recursive_proofs.stack.recursive_stack_proofs import (
    StackInvariantProof,
    StackObligation,
    StackProofReason,
)


def test_structural_layout_does_not_admit_symbolic_dispatch(tmp_path: Path) -> None:
    """Layout evidence is available without granting an unproved control edge."""
    inputs = make_inputs(tmp_path)
    step = next(item for item in inputs.system.steps if item.successors)
    symbolic = dict(step.original)
    symbolic[inputs.system.control_field] = {"op": "input", "name": "unproved_target", "width": 32}
    altered = replace(step, original=symbolic)
    system = replace(inputs.system, steps=tuple(
        altered if item.node == step.node else item for item in inputs.system.steps
    ))
    # This is a structural layout oracle, not a dispatch certificate. The
    # binary-derived CALL retains its selector-dependent full-width target.
    expected = admission.derive_joint_frame_layout(inputs.system)
    assert admission.derive_joint_frame_layout(system) == expected
    with pytest.raises(admission.JointRefusal) as refused:
        admit_joint_system(system)
    assert refused.value.reason is JointReason.DISPATCH


def test_structural_layout_rejects_undeclared_successors(tmp_path: Path) -> None:
    """Separating solver dispatch never relaxes the declared graph closure."""
    inputs = make_inputs(tmp_path)
    step = next(item for item in inputs.system.steps if item.successors)
    missing = replace(step.node, delta=0x123456)
    altered = replace(step, successors=(missing,))
    system = replace(inputs.system, steps=tuple(
        altered if item.node == step.node else item for item in inputs.system.steps
    ))
    with pytest.raises(admission.JointRefusal) as refused:
        admission.derive_joint_frame_layout(system)
    assert refused.value.reason is JointReason.DISPATCH


@pytest.mark.parametrize("boundary", ["entry", "native", "frame"])
@pytest.mark.parametrize("deadline", [True, False])
def test_joint_retains_child_deadline_and_partial_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str, deadline: bool,
) -> None:
    """Typed resource refusals survive composition without admitting partial work.

    Real binary-derived joint inputs supply the denominator and stack layout.
    Earlier solver results are typed stubs solely to reach each controller
    boundary. These tests establish accounting/routing, never a positive proof.
    """
    inputs = make_inputs(tmp_path)
    counts = FactCounters(2, 2, 2, 1, 1)
    success = FactCounters(1, 1, 1, 1, 0)
    receipt = ImageBoundReal16Domain(
        ProofStatus.UNKNOWN, BoundDomainReason.SOURCE, inputs.system, "controller-test",
        (), None, (), counts, proposal_hash="controller-test-proposal",
    )
    limits = LoadedRelationLimits(deadline=time.monotonic() + 60)
    run = owner._JointRun(
        receipt, inputs.system, inputs.loads, inputs.initialized, inputs.bootstrap,
        inputs.requests, limits, owner._requirements(inputs.system),
        replace(inputs.system.contract, model_hash="controller-test"), "controller-test",
    )
    entry_reason = EntryFrameReason.DEADLINE if deadline else EntryFrameReason.UNKNOWN
    native_reason = ImageBoundNativeReason.DEADLINE if deadline else ImageBoundNativeReason.TRANSITION
    stack_reason = StackProofReason.DEADLINE if deadline else StackProofReason.UNKNOWN
    entry = Real16EntryFrameProof(
        ProofStatus.UNKNOWN if boundary == "entry" else ProofStatus.PROVED,
        entry_reason if boundary == "entry" else EntryFrameReason.DISCHARGED,
        receipt.proposal_hash, "controller-test", (), counts if boundary == "entry" else success,
        (), (), "typed entry refusal",
    )
    native = ImageBoundNativeProof(
        ProofStatus.UNKNOWN if boundary == "native" else ProofStatus.PROVED,
        native_reason if boundary == "native" else ImageBoundNativeReason.DISCHARGED,
        "controller-test", (), (), counts if boundary == "native" else success,
        (), (), detail="typed native refusal",
    )
    frame = StackInvariantProof(
        StackObligation.BODY, ProofStatus.UNKNOWN, stack_reason, counts, 0,
        admission.derive_joint_frame_layout(inputs.system), "typed frame refusal",
    )
    prefix = Real16CodePrefixProof(
        ProofStatus.PROVED, CodePrefixReason.PRESERVED, "controller-test", (), (), success,
    )

    def consume(self: owner._JointRun, key: str) -> bool:
        self.current = key
        self.fact(key, ProofStatus.PROVED, counters=success)
        return True

    def prefix_stub(*args: object, **kwargs: object) -> Real16CodePrefixProof:
        return prefix

    def entry_stub(*args: object, **kwargs: object) -> Real16EntryFrameProof:
        return entry

    def native_stub(*args: object, **kwargs: object) -> ImageBoundNativeProof:
        return native

    def frame_stub(*args: object, **kwargs: object) -> StackInvariantProof:
        return frame

    def address_stub(_run: owner._JointRun) -> None:
        return None

    monkeypatch.setattr(owner._JointRun, "consume", consume)
    monkeypatch.setattr(owner, "prove_real16_code_prefixes", prefix_stub)
    monkeypatch.setattr(owner, "_address_prerequisites", address_stub)
    monkeypatch.setattr(owner, "_code_prerequisite", address_stub)
    monkeypatch.setattr(owner, "_control_prerequisite", address_stub)
    monkeypatch.setattr(owner, "prove_real16_entry_frame", entry_stub)
    monkeypatch.setattr(owner, "prove_image_bound_real16_native_relations", native_stub)
    monkeypatch.setattr(owner, "prove_stack_step", frame_stub)
    report = owner._prove(run)
    assert report.status is ProofStatus.UNKNOWN
    assert report.reason is (JointReason.DEADLINE if deadline else JointReason.UNKNOWN)
    assert report.remaining == tuple(JointModelRequirement)
    assert not report.binary_equivalence_proved
    assert len(report.proof.verdicts) == len(run.required)
    assert run.evidence[-1].counters == counts
    assert report.entry is entry
    assert report.native is (None if boundary == "entry" else native)
    assert report.frames == ((frame,) if boundary == "frame" else ())
