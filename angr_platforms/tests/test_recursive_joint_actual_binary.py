"""Actual matched recursive component controls for the image-bound joint proof.

Layer: test support.
Responsibility: require the actual-MZ recursive induction to discharge only
source-bound obligations, keeping typed refusal on forged or timed-out inputs.
"""
from __future__ import annotations

import time
from dataclasses import replace
from pathlib import Path

import pytest
from recursive_proof_fixtures.image_bound_inputs import make_inputs

from tools.dosunit.proof_contracts import ObligationVerdict, ProofStatus
from tools.dosunit.recursive_proofs import real16_image_bound_joint_proof as joint_owner
from tools.dosunit.recursive_proofs.loaded_byte_relation import LoadedRelationLimits
from tools.dosunit.recursive_proofs.real16_bound_control_scope import prove_bound_real16_control_scope
from tools.dosunit.recursive_proofs.real16_bound_operand_scope import prove_bound_real16_operand_scope
from tools.dosunit.recursive_proofs.real16_code_prefix_proof import prove_real16_code_prefixes
from tools.dosunit.recursive_proofs.real16_image_bound_domain import prove_image_bound_real16_domain
from tools.dosunit.recursive_proofs.real16_image_bound_joint_proof import (
    ImageBoundReal16JointProof,
    check_image_bound_real16_joint,
)
from tools.dosunit.recursive_proofs.real16_physical_access_bounds import prove_real16_physical_access_bounds
from tools.dosunit.recursive_proofs.recursive_joint_contracts import (
    EnvironmentScopeMember,
    JointModelRequirement,
    JointReason,
    JointSystem,
    Real16EnvironmentScope,
)


def _closed_machine(system: JointSystem) -> Real16EnvironmentScope:
    """Declare the harness-closed machine bound to this proposal's binaries."""
    return Real16EnvironmentScope(tuple(EnvironmentScopeMember), system.contract.original_hash,
                                  system.contract.candidate_hash, "test-harness-closed-machine")


def _verdict(proof: ImageBoundReal16JointProof, key: str) -> ObligationVerdict:
    """Return the shared obligation verdict for one joint evidence row."""
    matches = [verdict for verdict in proof.proof.verdicts if verdict.id.key == key]
    assert len(matches) == 1
    return matches[0]


def test_actual_matched_recursive_component_closes_under_declared_scope(tmp_path: Path) -> None:
    """Full induction closes conditionally: every declared machine exclusion
    reaches the shared verdict surface bound to both binary hashes, never as
    unconditional proof."""
    inputs = make_inputs(tmp_path)
    premise = _closed_machine(inputs.system)
    inputs = inputs._replace(system=replace(inputs.system, environment_scope=premise))
    receipt = prove_image_bound_real16_domain(*inputs)
    assert receipt.status is ProofStatus.PROVED, receipt
    proof = check_image_bound_real16_joint(receipt, *inputs)
    assert proof.status is ProofStatus.CONDITIONAL and proof.reason is JointReason.CONDITIONAL_MODEL, (proof.reason, proof.detail)
    assert proof.proof.status is ProofStatus.CONDITIONAL
    assert proof.outcomes is not None and proof.outcomes.complete
    assert proof.outcomes.premise is premise
    scope = _verdict(proof, "complete_normal_outcome_scope")
    assert scope.status is ProofStatus.CONDITIONAL
    assert len(scope.assumptions) == len(EnvironmentScopeMember)
    for member in EnvironmentScopeMember:
        row = next((text for text in scope.assumptions if text.startswith(member.value)), None)
        assert row is not None, (member, scope.assumptions)
        assert premise.original_hash in row and premise.candidate_hash in row
    aggregate = _verdict(proof, "physical_scope")
    assert aggregate.status is ProofStatus.CONDITIONAL
    assert set(aggregate.assumptions) == set(scope.assumptions)
    assert proof.entry is not None and proof.entry.status is ProofStatus.PROVED
    assert proof.native is not None and proof.native.status is ProofStatus.PROVED
    assert proof.prefixes is not None and proof.prefixes.status is ProofStatus.PROVED
    assert proof.operands is not None and proof.operands.status is ProofStatus.PROVED
    assert proof.addresses is not None and proof.addresses.status is ProofStatus.PROVED
    assert proof.controls is not None and proof.controls.complete
    assert proof.dispatch is not None and proof.dispatch.complete
    assert proof.outcomes is not None and proof.outcomes.complete
    assert all(block.complete for block in proof.prefixes.blocks)
    assert len(proof.frames) == 2 * len(inputs.system.steps)
    assert all(frame.status is ProofStatus.PROVED for frame in proof.frames)
    assert JointModelRequirement.CALLER_ENTRY not in proof.remaining
    assert proof.code_memory is not None and proof.code_memory.complete
    assert JointModelRequirement.CODE_MEMORY not in proof.remaining
    assert proof.address_model is not None and proof.address_model.complete
    assert JointModelRequirement.ADDRESS_MODEL not in proof.remaining
    assert JointModelRequirement.FAULT_DOMAIN not in proof.remaining
    assert JointModelRequirement.ENVIRONMENT not in proof.remaining
    assert not proof.remaining and not proof.binary_equivalence_proved
    assert len(proof.consumers) == 2

def test_missing_environment_premise_keeps_environment_scope_open(tmp_path: Path) -> None:
    """Without a declared typed premise, synchronous faults close but
    the asynchronous environment obligation remains a visible assumption."""
    inputs = make_inputs(tmp_path)
    receipt = prove_image_bound_real16_domain(*inputs)
    assert receipt.status is ProofStatus.PROVED, receipt
    proof = check_image_bound_real16_joint(receipt, *inputs)
    assert proof.status is ProofStatus.CONDITIONAL and proof.reason is JointReason.CONDITIONAL_MODEL, proof
    assert proof.outcomes is not None and proof.outcomes.synchronous_closed and not proof.outcomes.complete
    assert proof.outcomes.premise is None
    assert JointModelRequirement.FAULT_DOMAIN not in proof.remaining
    assert JointModelRequirement.ENVIRONMENT in proof.remaining
    assert len(proof.remaining) == 1 and not proof.binary_equivalence_proved
    scope = _verdict(proof, "complete_normal_outcome_scope")
    assert scope.status is ProofStatus.CONDITIONAL
    assert scope.assumptions == (JointModelRequirement.ENVIRONMENT.value,)
    aggregate = _verdict(proof, "physical_scope")
    assert aggregate.status is ProofStatus.CONDITIONAL
    assert JointModelRequirement.ENVIRONMENT.value in aggregate.assumptions

def test_joint_proof_retains_complete_denominator_on_missing_entry_evidence(tmp_path: Path) -> None:
    """An incomplete source/domain receipt cannot enter native or frame solvers."""
    inputs = make_inputs(tmp_path)
    receipt = prove_image_bound_real16_domain(*inputs)
    assert receipt.status is ProofStatus.PROVED, receipt
    corrupted = replace(receipt, facts=receipt.facts[:-1])
    refused = check_image_bound_real16_joint(corrupted, *inputs)
    assert refused.status is ProofStatus.UNKNOWN and refused.reason is JointReason.ADMISSION, refused
    assert refused.entry is None and refused.native is None and (refused.prefixes is None) and (not refused.frames)
    assert len(refused.proof.verdicts) == 16 + 2 * len(inputs.system.steps)
    assert refused.remaining == tuple(JointModelRequirement)
    expired = check_image_bound_real16_joint(receipt, *inputs, timeout_ms=0)
    assert expired.status is ProofStatus.UNKNOWN and expired.reason is JointReason.DEADLINE, expired
    assert not expired.consumers and (not expired.frames)

@pytest.mark.parametrize('child', ['operand', 'physical', 'prefix', 'control'])
def test_unproved_address_child_prevents_induction(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, child: str) -> None:
    """An actual typed timeout child cannot become a conditional recursive premise."""
    inputs = make_inputs(tmp_path)
    receipt = prove_image_bound_real16_domain(*inputs)
    factories = {'operand': prove_bound_real16_operand_scope, 'physical': prove_real16_physical_access_bounds, 'prefix': prove_real16_code_prefixes}
    if child == 'control':
        source = prove_real16_code_prefixes(receipt, *inputs)
        refused_child = prove_bound_real16_control_scope(source, *inputs,
            limits=LoadedRelationLimits(deadline=time.monotonic() - 1))
    else:
        factory = factories[child]
        refused_child = factory(receipt, *inputs, timeout_ms=0)
    assert refused_child.status is ProofStatus.UNKNOWN and refused_child.counters.failure_count

    def refused(*args: object, **kwargs: object) -> object:
        return refused_child
    names = {'operand': 'prove_bound_real16_operand_scope', 'physical': 'prove_real16_physical_access_bounds', 'prefix': 'prove_real16_code_prefixes', 'control': 'prove_bound_real16_control_scope'}
    name = names[child]
    monkeypatch.setattr(joint_owner, name, refused, raising=False)
    report = check_image_bound_real16_joint(receipt, *inputs)
    assert report.status is ProofStatus.UNKNOWN and report.reason is JointReason.DEADLINE
    assert not report.frames and report.entry is None and (report.native is None)
    assert len(report.proof.verdicts) == 16 + 2 * len(inputs.system.steps)
