"""Controller refusals must keep loaded-code initiation in the joint denominator."""
from __future__ import annotations

import time
from dataclasses import replace
from pathlib import Path

import pytest
from recursive_proof_fixtures.image_bound_inputs import make_inputs

from tools.dosunit.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.recursive_proofs import real16_fetched_code_invariant as code_owner
from tools.dosunit.recursive_proofs import real16_image_bound_joint_proof as owner
from tools.dosunit.recursive_proofs.loaded_byte_native_transition import LoadedTransitionReason, _TransitionRefusal
from tools.dosunit.recursive_proofs.loaded_byte_relation import LoadedRelationLimits
from tools.dosunit.recursive_proofs.real16_code_prefix_proof import CodePrefixReason, Real16CodePrefixProof
from tools.dosunit.recursive_proofs.real16_fetched_code_invariant import (
    FetchedCodeReason,
    Real16FetchedCodeInvariant,
)
from tools.dosunit.recursive_proofs.real16_image_bound_domain import BoundDomainReason, ImageBoundReal16Domain
from tools.dosunit.recursive_proofs.real16_native_effect_binding import NativeBindingReason, _NativeRefusal
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointModelRequirement, JointReason


@pytest.mark.parametrize("reason", [FetchedCodeReason.DEADLINE, FetchedCodeReason.SOURCE, FetchedCodeReason.PRESERVED])
def test_joint_refuses_missing_code_initialization_before_induction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reason: FetchedCodeReason,
) -> None:
    """Even a PROVED label cannot grant closure with an incomplete code ledger."""
    inputs = make_inputs(tmp_path)
    counts = FactCounters(4, 4, 4, 1, 3)
    receipt = ImageBoundReal16Domain(ProofStatus.UNKNOWN, BoundDomainReason.SOURCE,
        inputs.system, "controller", (), None, (), counts, proposal_hash="controller")
    run = owner._JointRun(receipt, inputs.system, inputs.loads, inputs.initialized,
        inputs.bootstrap, inputs.requests, LoadedRelationLimits(deadline=time.monotonic() + 60),
        owner._requirements(inputs.system), replace(inputs.system.contract, model_hash="controller"), "controller")
    prefix = Real16CodePrefixProof(ProofStatus.PROVED, CodePrefixReason.PRESERVED,
        "controller", (), (), FactCounters(1, 1, 1, 1, 0))
    child = Real16FetchedCodeInvariant(ProofStatus.PROVED if reason is FetchedCodeReason.PRESERVED else ProofStatus.UNKNOWN,
        reason, "controller", "controller", (), (), (), counts, "incomplete loaded code")

    def consume(self: owner._JointRun, key: str) -> bool:
        self.current = key
        self.fact(key, ProofStatus.PROVED)
        return True

    def prefix_stub(*args: object, **kwargs: object) -> Real16CodePrefixProof:
        return prefix

    def code_stub(*args: object, **kwargs: object) -> Real16FetchedCodeInvariant:
        return child

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("induction ran after missing loaded-code evidence")

    monkeypatch.setattr(owner._JointRun, "consume", consume)
    monkeypatch.setattr(owner, "prove_real16_code_prefixes", prefix_stub)
    monkeypatch.setattr(owner, "check_fetched_code_invariant", code_stub, raising=False)
    monkeypatch.setattr(owner, "_address_prerequisites", forbidden)
    report = owner._prove(run)
    assert report.reason is (JointReason.DEADLINE if reason is FetchedCodeReason.DEADLINE else JointReason.UNKNOWN)
    assert report.status is ProofStatus.UNKNOWN and not report.binary_equivalence_proved
    assert report.code_memory is child
    assert report.remaining == tuple(JointModelRequirement)
    assert report.entry is None and report.native is None and not report.frames
    expected = {
        "before", "all_native_code_prefixes", "all_loaded_code_invariants", "all_native_operand_scope",
        "all_native_physical_access_bounds", "all_native_control_coordinates", "actual_entry_frame",
        "all_native_transitions", "complete_domain_scoped_dispatch", "complete_address_model",
        "complete_normal_outcome_scope", "complete_dispatch_and_atomic_lockstep_progress",
        "after", "model", "physical_scope", "component",
    }
    expected.update(f"frame:{side}:{step.node.key()}"
                    for step in inputs.system.steps for side in ("original", "candidate"))
    rows = report.proof.verdicts
    assert {row.id.key for row in rows} == expected
    assert len(rows) == len(expected)
    assert all(row.id.kind == "image_bound_recursive" for row in rows)
    outcome = next(row for row in rows if row.id.key == "complete_normal_outcome_scope")
    assert outcome.status is ProofStatus.UNKNOWN and not outcome.attempted
    assert run.evidence[-1].counters == counts


@pytest.mark.parametrize("boundary", ["initialization", "source"])
@pytest.mark.parametrize("deadline", [True, False])
def test_code_invariant_retains_nested_deadline_causes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str, deadline: bool,
) -> None:
    """Specific intake refusals retain typed reasons and all unattempted rows."""
    inputs = make_inputs(tmp_path)
    source = Real16CodePrefixProof(ProofStatus.UNKNOWN, CodePrefixReason.SOURCE,
        "controller", (), (), FactCounters(1, 1, 1, 0, 1))
    if boundary == "initialization":
        refusal = _TransitionRefusal(LoadedTransitionReason.DEADLINE if deadline
            else LoadedTransitionReason.INITIALIZATION, "typed nested initialization refusal")
        expected = FetchedCodeReason.INITIALIZATION
    else:
        refusal = _NativeRefusal(NativeBindingReason.DEADLINE if deadline
            else NativeBindingReason.LOAD, "typed nested source refusal")
        expected = FetchedCodeReason.SOURCE

    def refuse(*args: object, **kwargs: object) -> None:
        raise refusal

    monkeypatch.setattr(code_owner, "_establish", refuse)
    report = code_owner.check_fetched_code_invariant(source, *inputs)
    assert report.reason is (FetchedCodeReason.DEADLINE if deadline else expected)
    assert report.status is ProofStatus.UNKNOWN and not report.complete
    assert len(report.required) == 11 + sum(len(rows) for rows in inputs.requests)
    assert report.counters.failure_count == len(report.required)
    assert report.facts == () and report.domains == ()
