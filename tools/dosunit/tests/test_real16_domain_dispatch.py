"""Source-bound dispatch controls never infer execution from graph declarations."""
from __future__ import annotations

import time
from dataclasses import replace
from pathlib import Path

import pytest
import z3
from tools.dosunit.tests.recursive_proof_fixtures.image_bound_inputs import make_inputs

from tools.dosunit.contracts.proof_contracts import ProofStatus
from tools.dosunit.recursive_proofs import real16_domain_dispatch as owner
from tools.dosunit.recursive_proofs.loaded_byte_relation import LoadedRelationLimits
from tools.dosunit.recursive_proofs.real16_domain_dispatch import (
    DomainDispatchObligation,
    DomainDispatchReason,
    prove_real16_domain_dispatch,
)
from tools.dosunit.recursive_proofs.real16_image_bound_domain import prove_image_bound_real16_domain
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointStepKind


def test_actual_dispatch_closes_every_full_width_edge(tmp_path: Path) -> None:
    """Actual binary effects prove all declared edges in the established domain."""
    inputs = make_inputs(tmp_path)
    receipt = prove_image_bound_real16_domain(*inputs)
    proof = prove_real16_domain_dispatch(receipt, *inputs)
    assert proof.complete, (proof.reason, proof.detail)
    assert len(proof.facts) == len(proof.required)
    assert proof.counters.failure_count == 0
    expected = 2 * sum(len(step.successors) for step in inputs.system.steps)
    assert sum(fact.obligation is DomainDispatchObligation.EDGE for fact in proof.facts) == expected


@pytest.mark.parametrize("corruption", ["omit", "extra"])
def test_source_valid_domain_does_not_prove_wrong_dispatch(tmp_path: Path, corruption: str) -> None:
    """Source and scalar facts can be valid while dispatch metadata is false."""
    inputs = make_inputs(tmp_path)
    step = next(item for item in inputs.system.steps
                if item.kind is JointStepKind.BRANCH and len(item.successors) == 2)
    successors = step.successors[:1] if corruption == "omit" else (*step.successors, inputs.system.root)
    altered = replace(step, successors=successors)
    system = replace(inputs.system, steps=tuple(
        altered if item.node == step.node else item for item in inputs.system.steps
    ))
    receipt = prove_image_bound_real16_domain(system, *inputs[1:])
    assert receipt.status is ProofStatus.PROVED, receipt
    proof = prove_real16_domain_dispatch(receipt, system, *inputs[1:])
    assert not proof.complete and proof.counters.failure_count > 0
    if corruption == "omit":
        assert proof.status is ProofStatus.COUNTEREXAMPLE
    else:
        assert proof.reason is DomainDispatchReason.VACUOUS
    assert proof.counters.raw_fact_count == len(proof.required)


def test_dispatch_refuses_stale_receipt_and_expired_original_deadline(tmp_path: Path) -> None:
    """No stale domain or replenished nested time can establish progress."""
    inputs = make_inputs(tmp_path)
    receipt = prove_image_bound_real16_domain(*inputs)
    stale = replace(receipt, facts=receipt.facts[:-1])
    proof = prove_real16_domain_dispatch(stale, *inputs)
    assert not proof.complete and proof.reason is DomainDispatchReason.SOURCE
    expired = LoadedRelationLimits(deadline=time.monotonic() - 1)
    proof = prove_real16_domain_dispatch(receipt, *inputs, limits=expired)
    assert not proof.complete and proof.reason is DomainDispatchReason.DEADLINE
    assert proof.counters.failure_count == len(proof.required)


def test_dispatch_rechecks_mutable_effect_after_solver_work(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Successful solver facts cannot transfer across mutable source-effect edits."""
    inputs = make_inputs(tmp_path)
    receipt = prove_image_bound_real16_domain(*inputs)
    query = owner._DispatchRun.query
    changed = False

    def mutate(self, obligation, key, equation, *, witness=False):
        nonlocal changed
        result = query(self, obligation, key, equation, witness=witness)
        if not changed:
            changed = True
            inputs.system.steps[0].original["ax"] = {"op": "const", "width": 16, "value": "0x7"}
        return result

    monkeypatch.setattr(owner._DispatchRun, "query", mutate)
    proof = prove_real16_domain_dispatch(receipt, *inputs)
    assert changed and not proof.complete
    assert proof.reason is DomainDispatchReason.SOURCE
    assert any(fact.status is ProofStatus.PROVED for fact in proof.facts)
    assert proof.consumers[-1].status is ProofStatus.UNKNOWN


def test_dispatch_nonvacuity_and_unknown_keep_full_denominator(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Neither an impossible premise nor solver UNKNOWN can grant progress."""
    inputs = make_inputs(tmp_path)
    receipt = prove_image_bound_real16_domain(*inputs)
    required = owner._requirements(inputs.system)
    limits = LoadedRelationLimits(deadline=time.monotonic() + 30)
    run = owner._DispatchRun(receipt, inputs.system, limits, required, "controller-only")
    reason = run.query(DomainDispatchObligation.CUTPOINT, "original:impossible", z3.BoolVal(False), witness=True)
    assert reason is DomainDispatchReason.VACUOUS
    assert not run.report(reason).complete

    def unknown(self, *args):
        return z3.unknown

    monkeypatch.setattr(z3.Solver, "check", unknown)
    proof = prove_real16_domain_dispatch(receipt, *inputs)
    assert not proof.complete and proof.reason is DomainDispatchReason.UNKNOWN
    assert proof.counters.failure_count > 0 and proof.counters.raw_fact_count == len(proof.required)
