"""Actual binary source/domain connection refuses stale or unconnected effects.

Layer: test support.
Responsibility: provide independent binary-derived image, effect and request fixtures.
"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import NamedTuple

import capstone
import pytest
from tools.dosunit.tests.recursive_proof_fixtures.entry_domain_inputs import DEFAULT_BOOTSTRAP, _setup

from tools.dosunit.contracts.model import canonical_json_bytes
from tools.dosunit.contracts.proof_contracts import ProofStatus
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import BoundReal16Load
from tools.dosunit.recursive_proofs.loaded_byte_relation_proof import LoadedRelationProof
from tools.dosunit.recursive_proofs.real16_entry_domain import native_effect_hash
from tools.dosunit.recursive_proofs.real16_image_bound_domain import (
    BoundDomainReason,
    prove_image_bound_real16_domain,
)
from tools.dosunit.recursive_proofs.real16_image_bound_domain_consumer import (
    consume_image_bound_real16_domain,
)
from tools.dosunit.recursive_proofs.real16_image_bound_native_proof import (
    ImageBoundNativeReason,
    prove_image_bound_real16_native_relations,
)
from tools.dosunit.recursive_proofs.real16_native_effect_binding import NativeBlockRequest
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointSystem
from tools.dosunit.contracts.register_state_relations import MachineState


class Inputs(NamedTuple):
    """Independent test inputs, preserving immutable proposal/source identities."""

    system: JointSystem
    loads: tuple[BoundReal16Load, BoundReal16Load]
    initialized: LoadedRelationProof
    bootstrap: tuple[MachineState, MachineState]
    requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]]


def _proposal(load: BoundReal16Load, address: int, state: MachineState) -> NativeBlockRequest:
    """Use binary control groups to propose an extent; the binder rechecks it."""
    chunks = load.binding.snapshot.chunks
    start, data = next((start, data) for start, data in chunks if start <= address < start + len(data))
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    extent = 0
    for instruction in decoder.disasm(data[address - start:], address):
        extent += instruction.size
        if any(group in instruction.groups for group in (capstone.CS_GRP_JUMP, capstone.CS_GRP_CALL, capstone.CS_GRP_RET)):
            return NativeBlockRequest(address, extent, native_effect_hash(state), canonical_json_bytes(state))
    raise AssertionError("test body has no complete binary control transfer")


@pytest.fixture
def inputs(tmp_path: Path) -> Inputs:
    """Actual initialized MZ pairs and joint effects are separate proof inputs."""
    return make_inputs(tmp_path)


def make_inputs(tmp_path: Path, *, bootstrap_code: bytes = DEFAULT_BOOTSTRAP) -> Inputs:
    """Build shared explicit binary fixtures for source/domain/frame controls."""
    loads, initialized, bootstrap, _, system = _setup(tmp_path, bootstrap_code=bootstrap_code)
    requests = []
    for side in range(2):
        rows = [_proposal(loads[side], step.original_address if side == 0 else step.candidate_address,
                          step.original if side == 0 else step.candidate) for step in system.steps]
        rows.append(_proposal(loads[side], loads[side].binding.entry, bootstrap[side]))
        requests.append(tuple(rows))
    return Inputs(system, loads, initialized, bootstrap, (requests[0], requests[1]))


def test_actual_joint_effects_and_bootstrap_connect_to_derived_domain(inputs: Inputs) -> None:
    """Full source facts and scalar facts connect without a callee assumption."""
    report = prove_image_bound_real16_domain(*inputs)
    assert report.status is ProofStatus.PROVED and report.reason is BoundDomainReason.DISCHARGED, report
    assert report.domain is not None and report.domain.status is ProofStatus.PROVED
    assert len(report.sources) == 2 and all(source.status is ProofStatus.PROVED for source in report.sources)
    assert report.counters.failure_count == 0 and report.counters.materialized_count == 7
    assert not report.binary_equivalence_proved


def test_unconnected_complete_effect_cannot_reuse_valid_source_inputs(inputs: Inputs) -> None:
    """A complete but fabricated native state cannot borrow another block's receipt."""
    step = inputs.system.steps[0]
    changed = dict(step.original)
    changed["ax"] = {"op": "const", "width": 16, "value": "0x7"}
    system = replace(inputs.system, steps=(replace(step, original=changed), *inputs.system.steps[1:]))
    report = prove_image_bound_real16_domain(system, *inputs[1:])
    assert report.status is ProofStatus.UNKNOWN and report.reason is BoundDomainReason.LINK, report
    assert report.domain is None and report.counters.failure_count > 0


@pytest.mark.parametrize("corruption", ["image", "manifest"])
def test_wrong_executable_or_missing_joint_node_refuses_before_source_proof(inputs: Inputs, corruption: str) -> None:
    """Graph metadata cannot impersonate an image or silently drop an obligation."""
    if corruption == "image":
        system = replace(inputs.system, contract=replace(inputs.system.contract, original_hash="0" * 64))
        expected = BoundDomainReason.IMAGE
    else:
        system = replace(inputs.system, steps=inputs.system.steps[:-1])
        expected = BoundDomainReason.JOINT
    report = prove_image_bound_real16_domain(system, *inputs[1:])
    assert report.status is ProofStatus.UNKNOWN and report.reason is expected, report
    assert not report.sources and report.domain is None


def test_combined_original_deadline_is_not_replenished(inputs: Inputs) -> None:
    """No source or scalar producer runs after the shared budget is exhausted."""
    report = prove_image_bound_real16_domain(*inputs, timeout_ms=0)
    assert report.status is ProofStatus.UNKNOWN and report.reason is BoundDomainReason.DEADLINE, report
    assert not report.sources and report.domain is None


def test_saved_prerequisite_refuses_changed_content_and_incomplete_receipts(inputs: Inputs) -> None:
    """A saved binary receipt cannot authorize changed effects, frames or evidence."""
    receipt = prove_image_bound_real16_domain(*inputs)
    assert receipt.status is ProofStatus.PROVED, receipt
    accepted = consume_image_bound_real16_domain(receipt, *inputs)
    assert accepted.status is ProofStatus.PROVED and accepted.counters.failure_count == 0, accepted
    step = inputs.system.steps[0]
    changed_system = replace(inputs.system, steps=(replace(step, original_hash="0" * 64), *inputs.system.steps[1:]))
    refused = consume_image_bound_real16_domain(receipt, changed_system, *inputs[1:])
    assert refused.status is ProofStatus.UNKNOWN and refused.reason is BoundDomainReason.CONTENT, refused

    changed = dict(step.original)
    changed["ax"] = {"op": "const", "width": 16, "value": "0x7"}
    changed_system = replace(inputs.system, steps=(replace(step, original=changed), *inputs.system.steps[1:]))
    refused = consume_image_bound_real16_domain(receipt, changed_system, *inputs[1:])
    assert refused.status is ProofStatus.UNKNOWN and refused.reason is BoundDomainReason.CONTENT, refused
    refused = consume_image_bound_real16_domain(replace(receipt, model_hash="0" * 64), *inputs)
    assert refused.status is ProofStatus.UNKNOWN and refused.reason is BoundDomainReason.MODEL, refused
    for corrupted in (replace(receipt, facts=receipt.facts[:-1]),
                      replace(receipt, facts=(*receipt.facts[:-1], receipt.facts[0])),
                      replace(receipt, counters=replace(receipt.counters, failure_count=1)),
                      replace(receipt, sources=receipt.sources[:1])):
        refused = consume_image_bound_real16_domain(corrupted, *inputs)
        assert refused.status is ProofStatus.UNKNOWN and refused.counters.failure_count > 0, refused
    source = receipt.sources[0]
    for corrupted_source in (replace(source, facts=source.facts[:-1]),
                             replace(source, snapshot_hash="0" * 64),
                             replace(source, model_hash="0" * 64),
                             replace(source, blocks=source.blocks[:-1])):
        corrupted = replace(receipt, sources=(corrupted_source, receipt.sources[1]))
        refused = consume_image_bound_real16_domain(corrupted, *inputs)
        assert refused.status is ProofStatus.UNKNOWN and refused.reason is BoundDomainReason.SOURCE, refused
    assert receipt.domain is not None
    domain = replace(receipt.domain, facts=receipt.domain.facts[:-1])
    refused = consume_image_bound_real16_domain(replace(receipt, domain=domain), *inputs)
    assert refused.status is ProofStatus.UNKNOWN, refused
    assert consume_image_bound_real16_domain(receipt, *inputs, timeout_ms=0).reason is BoundDomainReason.DEADLINE
    # The receipt aliases these owned legacy dictionaries. Its immutable seal
    # must still retain the original fact identity when that shared tree changes.
    step.original["ax"] = changed["ax"]
    refused = consume_image_bound_real16_domain(receipt, *inputs)
    assert refused.status is ProofStatus.UNKNOWN and refused.reason is BoundDomainReason.CONTENT, refused


def test_verified_source_domain_receipt_connects_every_full_native_relation(inputs: Inputs) -> None:
    """Loaded binary effects authorize all local outputs without binary promotion."""
    receipt = prove_image_bound_real16_domain(*inputs)
    assert receipt.status is ProofStatus.PROVED, receipt
    proof = prove_image_bound_real16_native_relations(receipt, *inputs)
    assert proof.status is ProofStatus.PROVED and proof.reason is ImageBoundNativeReason.DISCHARGED, proof
    assert len(proof.transitions) == len(inputs.system.steps) + 1
    assert len(proof.consumers) == 2 and all(child.status is ProofStatus.PROVED for child in proof.consumers)
    assert proof.counters.failure_count == 0 and proof.counters.materialized_count == len(inputs.system.steps) + 4
    assert all(set(child.required_outputs) == set(inputs.system.required_outputs) for child in proof.transitions)
    assert not proof.binary_equivalence_proved and proof.remaining
    step = inputs.system.steps[0]
    changed = replace(inputs.system, steps=(replace(step, original_hash="0" * 64), *inputs.system.steps[1:]))
    refused = prove_image_bound_real16_native_relations(receipt, changed, *inputs[1:])
    assert refused.status is ProofStatus.UNKNOWN and refused.reason is ImageBoundNativeReason.PREREQUISITE, refused
    assert not refused.transitions and refused.counters.failure_count > 0
    expired = prove_image_bound_real16_native_relations(receipt, *inputs, timeout_ms=0)
    assert expired.status is ProofStatus.UNKNOWN and expired.reason is ImageBoundNativeReason.DEADLINE
    assert not expired.consumers and not expired.transitions


def test_saved_prerequisite_rejects_changed_scalar_contract(inputs: Inputs) -> None:
    """A cached two-byte invariant cannot authorize a stronger alignment claim."""
    receipt = prove_image_bound_real16_domain(*inputs)
    assert receipt.status is ProofStatus.PROVED and receipt.domain is not None, receipt
    for altered in (replace(receipt.domain.domain, alignment=4),
                    replace(receipt.domain.domain, ss=receipt.domain.domain.ss ^ 1),
                    replace(receipt.domain.domain, cs=receipt.domain.domain.cs ^ 1)):
        domain = replace(receipt.domain, domain=altered)
        refused = consume_image_bound_real16_domain(replace(receipt, domain=domain), *inputs)
        assert refused.status is ProofStatus.UNKNOWN and refused.reason is BoundDomainReason.DOMAIN, refused
