"""Focused tests for staged actual-MZ normal-outcome scope and the joint proof tail.

The premise tests cover the declared ``Real16EnvironmentScope`` contract: the
closed machine is an explicit caller premise content-bound to both binaries
inside the joint proposal identity, not something byte scans can prove.
Missing and forged premises keep ENVIRONMENT open; a changed premise
invalidates retained receipts through the proposal hash. Byte-level tests
cover the source-proved synchronous scope, including the parent AAM0
divide-fault negative against the native binding.
"""
from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest
from recursive_proof_fixtures.image_bound_inputs import Inputs, make_inputs
from test_dosunit_tool import _mz_exe

from tools.dosunit.model import canonical_json_bytes
from tools.dosunit.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.real16_call_contracts import initial_state
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import bind_real16_mz
from tools.dosunit.recursive_proofs.loaded_byte_relation import LoadedRelationLimits
from tools.dosunit.recursive_proofs.real16_image_bound_domain import (
    ImageBoundReal16Domain,
    prove_image_bound_real16_domain,
)
from tools.dosunit.recursive_proofs.real16_native_effect_binding import (
    NativeBindingReason,
    NativeBlockRequest,
    Real16NativeBinding,
    bind_real16_native_effects,
)
from tools.dosunit.recursive_proofs.real16_normal_outcome_scope import (
    OutcomeScopeFact,
    OutcomeScopeObligation,
    OutcomeScopeReason,
    Real16NormalOutcomeScope,
    _byte_normal_scope,
    outcome_scope_model_hash,
    prove_real16_normal_outcome_scope,
)
from tools.dosunit.recursive_proofs.real16_physical_access_bounds import (
    PhysicalAccessReason,
    Real16PhysicalAccessBounds,
    prove_real16_physical_access_bounds,
)
from tools.dosunit.recursive_proofs.recursive_joint_contracts import (
    EnvironmentScopeMember,
    JointSystem,
    Real16EnvironmentScope,
)
from tools.dosunit.recursive_proofs.recursive_joint_identity import joint_proposal_hash


def _premise(system: JointSystem, original_hash: str | None = None,
             candidate_hash: str | None = None) -> Real16EnvironmentScope:
    """Declare the full closed-machine premise bound to this proposal's binaries."""
    contract = system.contract
    return Real16EnvironmentScope(tuple(EnvironmentScopeMember),
                                  original_hash if original_hash is not None else contract.original_hash,
                                  candidate_hash if candidate_hash is not None else contract.candidate_hash,
                                  "test-harness-closed-machine")


def _inputs(tmp_path: Path, premise: bool = True) -> Inputs:
    """Build fixture inputs, optionally carrying the declared machine premise."""
    inputs = make_inputs(tmp_path)
    if premise:
        system = replace(inputs.system, environment_scope=_premise(inputs.system))
        return inputs._replace(system=system)
    return inputs


def _scope(tmp_path: Path, *, premise: bool = True,
           ) -> tuple[Inputs, ImageBoundReal16Domain, Real16PhysicalAccessBounds,
                      Real16NormalOutcomeScope]:
    """Prove the staged outcome scope over the actual-MZ joint fixture."""
    inputs = _inputs(tmp_path, premise)
    receipt = prove_image_bound_real16_domain(*inputs)
    assert receipt.status is ProofStatus.PROVED, receipt
    bounds = prove_real16_physical_access_bounds(receipt, *inputs)
    assert bounds.status is ProofStatus.PROVED, bounds
    scope = prove_real16_normal_outcome_scope(receipt, *inputs, bounds)
    return inputs, receipt, bounds, scope


ScopeCase = tuple[Inputs, ImageBoundReal16Domain, Real16PhysicalAccessBounds, Real16NormalOutcomeScope]


@pytest.fixture(scope="module")
def shared_scope(tmp_path_factory: pytest.TempPathFactory) -> ScopeCase:
    """Prove the unchanged binary pair once; corruption tests use replacements."""
    return _scope(tmp_path_factory.mktemp("normal-outcome-scope"))


@pytest.fixture
def scope_case(shared_scope: ScopeCase) -> Iterator[ScopeCase]:
    """Require each consumer to preserve the shared source and proof evidence."""
    before = repr(shared_scope)
    yield shared_scope
    assert repr(shared_scope) == before


def _binding_for(tmp_path: Path, code: bytes) -> Real16NativeBinding:
    """Bind injected actual MZ bytes through the production admission path."""
    exe = tmp_path / "adversarial.exe"
    exe.write_bytes(_mz_exe(bytes(0x200) + code))
    load = bind_real16_mz(exe.read_bytes(), load_segment=0x1000)
    seed = canonical_json_bytes(initial_state())
    request = NativeBlockRequest(0x10200, len(code), hashlib.sha256(seed).hexdigest(), seed)
    return bind_real16_native_effects(load, (request,), timeout_ms=15000)


def test_actual_mz_outcome_scope_discharges_under_declared_premise(scope_case: ScopeCase) -> None:
    """Every admitted transition on both sides plus entry proves the synchronous
    scope and the typed premise closes the declared asynchronous scope."""
    inputs, receipt, _bounds, scope = scope_case
    assert scope.status is ProofStatus.PROVED and scope.reason is OutcomeScopeReason.DISCHARGED, scope
    assert scope.complete and scope.synchronous_closed and scope.counters.failure_count == 0
    assert scope.premise is inputs.system.environment_scope
    assert scope.model_hash == outcome_scope_model_hash() and scope.proposal_hash == receipt.proposal_hash
    expected = {(side, request.address)
                for side, members in enumerate(inputs.requests) for request in members}
    expected |= {(0, inputs.loads[0].binding.entry), (1, inputs.loads[1].binding.entry)}
    assert {(block.side, block.address) for block in scope.blocks} == expected
    assert len(scope.facts) == len(scope.required)
    assert {fact.obligation for fact in scope.facts} == set(OutcomeScopeObligation)
    assert all(fact.status is ProofStatus.PROVED for fact in scope.facts)
    assert len(scope.consumers) == 2 and all(child.status is ProofStatus.PROVED for child in scope.consumers)
    assert scope.omissions and not scope.binary_equivalence_proved
    declared = scope.declared_scope_assumptions
    assert len(declared) == len(EnvironmentScopeMember)
    premise = inputs.system.environment_scope
    for member in EnvironmentScopeMember:
        row = next((text for text in declared if text.startswith(member.value)), None)
        assert row is not None and premise.original_hash in row and premise.candidate_hash in row


def test_missing_environment_premise_keeps_declared_scope_open(tmp_path: Path) -> None:
    """No typed premise means synchronous fault evidence closes but the
    asynchronous machine scope stays an open, visible obligation."""
    _inputs_args, _receipt, _bounds, scope = _scope(tmp_path, premise=False)
    assert scope.status is ProofStatus.UNKNOWN and scope.reason is OutcomeScopeReason.PREMISE, scope
    assert scope.synchronous_closed and not scope.complete
    assert scope.premise is None
    premise = next(fact for fact in scope.facts if fact.obligation is OutcomeScopeObligation.PREMISE)
    assert premise.status is ProofStatus.UNKNOWN and "no declared" in premise.detail


@pytest.mark.parametrize("field", ("original_hash", "candidate_hash"))
def test_forged_environment_premise_stays_open(tmp_path: Path, field: str) -> None:
    """A premise bound to different binary hashes cannot close ENVIRONMENT."""
    forged = hashlib.sha256(b"forged").hexdigest()
    inputs = make_inputs(tmp_path)
    premise = _premise(inputs.system, **{field: forged})
    inputs = inputs._replace(system=replace(inputs.system, environment_scope=premise))
    receipt = prove_image_bound_real16_domain(*inputs)
    assert receipt.status is ProofStatus.PROVED, receipt
    bounds = prove_real16_physical_access_bounds(receipt, *inputs)
    assert bounds.status is ProofStatus.PROVED, bounds
    scope = prove_real16_normal_outcome_scope(receipt, *inputs, bounds)
    assert scope.reason is OutcomeScopeReason.PREMISE and not scope.complete, scope
    premise_fact = next(fact for fact in scope.facts if fact.obligation is OutcomeScopeObligation.PREMISE)
    assert "different binaries" in premise_fact.detail


def test_changed_environment_premise_invalidates_retained_receipts(tmp_path: Path) -> None:
    """A premise carried by the proposal hash: removing it invalidates evidence."""
    inputs = _inputs(tmp_path)
    receipt = prove_image_bound_real16_domain(*inputs)
    assert receipt.status is ProofStatus.PROVED, receipt
    stale_inputs = inputs._replace(system=replace(inputs.system, environment_scope=None))
    assert joint_proposal_hash(stale_inputs.system, stale_inputs.bootstrap) != receipt.proposal_hash
    stale_bounds = prove_real16_physical_access_bounds(receipt, *stale_inputs)
    scope = prove_real16_normal_outcome_scope(receipt, *stale_inputs, stale_bounds)
    assert scope.reason is OutcomeScopeReason.RECEIPT and not scope.complete, scope
    assert scope.facts and scope.facts[0].status is ProofStatus.UNKNOWN


def test_environment_premise_enters_proposal_identity(tmp_path: Path) -> None:
    """The declared premise is part of the content-bound joint proposal hash."""
    inputs = make_inputs(tmp_path)
    open_system = inputs.system
    closed_system = replace(open_system, environment_scope=_premise(open_system))
    assert joint_proposal_hash(open_system, inputs.bootstrap) \
        != joint_proposal_hash(closed_system, inputs.bootstrap)


@pytest.mark.parametrize("members", [
    (),
    (EnvironmentScopeMember.NO_ASYNC_DELIVERY,),
    (EnvironmentScopeMember.NO_HOST_SERVICES,),
    tuple(EnvironmentScopeMember)[:-1],
    (*tuple(EnvironmentScopeMember), EnvironmentScopeMember.NO_HOST_SERVICES),
])
def test_premise_intake_requires_every_member_once(
        members: tuple[EnvironmentScopeMember, ...]) -> None:
    """A partial or duplicated declaration can never stand in for the scope."""
    bound = "a" * 64, "b" * 64
    with pytest.raises(ValueError):
        Real16EnvironmentScope(members, *bound)


def test_premise_intake_rejects_unbound_content() -> None:
    """The typed premise contract refuses non-hash binary bindings."""
    contract_hash = hashlib.sha256(b"x").hexdigest()
    with pytest.raises(ValueError):
        Real16EnvironmentScope(tuple(EnvironmentScopeMember), "", contract_hash)
    with pytest.raises(ValueError):
        Real16EnvironmentScope(tuple(EnvironmentScopeMember), contract_hash, "zz")


def test_complete_premise_intake_remains_accepted() -> None:
    """The full typed declaration binds to two 64-hex binary hashes."""
    scope = Real16EnvironmentScope(tuple(EnvironmentScopeMember), "a" * 64, "b" * 64)
    assert set(scope.members) == set(EnvironmentScopeMember)


def test_duplicate_scope_fact_cannot_hide_unknown_evidence() -> None:
    """Ledger projection validates raw identities before statuses (parent red)."""
    key = (OutcomeScopeObligation.BLOCK, "0:0x1100")
    good = OutcomeScopeFact(*key, ProofStatus.PROVED)
    scope = Real16NormalOutcomeScope(
        ProofStatus.UNKNOWN, OutcomeScopeReason.PREMISE, "m" * 8, "p" * 8,
        None, (key,), (), (good,), (), (), FactCounters(1, 1, 1, 1, 0))
    assert scope.synchronous_closed
    forged = replace(scope, facts=(replace(good, status=ProofStatus.UNKNOWN), good))
    assert not forged.synchronous_closed and not forged.complete


@pytest.mark.parametrize("counts", [
    (1, 1, 5, 1, 0), (0, 1, 1, 1, 0), (1, 0, 1, 1, 0),
    (2, 1, 1, 1, 0), (1, 2, 1, 1, 0),
])
def test_counter_inconsistent_scope_ledger_cannot_close(counts: tuple[int, ...]) -> None:
    """Counters disagreeing with retained statuses reject both closures."""
    key = (OutcomeScopeObligation.BLOCK, "0:0x1100")
    good = OutcomeScopeFact(*key, ProofStatus.PROVED)
    premise = Real16EnvironmentScope(tuple(EnvironmentScopeMember), "a" * 64, "b" * 64)
    scope = Real16NormalOutcomeScope(
        ProofStatus.PROVED, OutcomeScopeReason.DISCHARGED, "m" * 8, "p" * 8,
        premise, (key,), (), (good,), (), (), FactCounters(*counts))
    assert not scope.synchronous_closed and not scope.complete


@pytest.mark.parametrize(("code", "reason"), [
    (bytes.fromhex("cd21"), OutcomeScopeReason.ENVIRONMENT),   # int 0x21
    (bytes.fromhex("cc"), OutcomeScopeReason.ENVIRONMENT),     # int3
    (bytes.fromhex("cd03"), OutcomeScopeReason.ENVIRONMENT),   # int 3
    (bytes.fromhex("e460"), OutcomeScopeReason.ENVIRONMENT),   # in al,0x60
    (bytes.fromhex("e560"), OutcomeScopeReason.ENVIRONMENT),   # in ax,0x60
    (bytes.fromhex("e660"), OutcomeScopeReason.ENVIRONMENT),   # out 0x60,al
    (bytes.fromhex("ec"), OutcomeScopeReason.ENVIRONMENT),     # in al,dx
    (bytes.fromhex("ed"), OutcomeScopeReason.ENVIRONMENT),     # in ax,dx
    (bytes.fromhex("ee"), OutcomeScopeReason.ENVIRONMENT),     # out dx,al
    (bytes.fromhex("ef"), OutcomeScopeReason.ENVIRONMENT),     # out dx,ax
    (bytes.fromhex("f4"), OutcomeScopeReason.ENVIRONMENT),     # hlt
    (bytes.fromhex("fa"), OutcomeScopeReason.ENVIRONMENT),     # cli
    (bytes.fromhex("fb"), OutcomeScopeReason.ENVIRONMENT),     # sti
    (bytes.fromhex("0f01e0"), OutcomeScopeReason.ENVIRONMENT), # smsw ax
    (bytes.fromhex("0f0108"), OutcomeScopeReason.ENVIRONMENT), # sidt [bx+si]
    (bytes.fromhex("0f0118"), OutcomeScopeReason.ENVIRONMENT), # sgdt [bx+si]
    (bytes.fromhex("db"), OutcomeScopeReason.SOURCE),          # incomplete decode
])
def test_byte_level_environment_classifier_refuses_injected_bytes(
        code: bytes, reason: OutcomeScopeReason) -> None:
    """Fresh byte classification, not lifter output, owns synchronous admission."""
    refused, _detail = _byte_normal_scope(code, 0x1100)
    assert refused is reason


def test_byte_level_classifier_accepts_normal_integer_bytes() -> None:
    """Ordinary modeled integer control bytes carry no environment event."""
    assert _byte_normal_scope(bytes.fromhex("89d8c3"), 0x1100) == (None, "")


@pytest.mark.parametrize(("code", "reason"), [
    (bytes.fromhex("d400"), NativeBindingReason.FAULT),  # aam 0 -> #DE (parent negative)
    (bytes.fromhex("ce"), NativeBindingReason.FAULT),    # into -> external scope
    (bytes.fromhex("f1"), NativeBindingReason.FAULT),    # int1 -> external scope
    (bytes.fromhex("f7f1"), NativeBindingReason.FAULT),  # div cx -> signal exit
    (bytes.fromhex("62c0"), NativeBindingReason.DECODE), # bound ax,ax -> decode gap
    (bytes.fromhex("f090"), NativeBindingReason.DECODE), # lock nop -> invalid LOCK
    (bytes.fromhex("0f0b"), NativeBindingReason.DECODE), # ud2 -> no VEX block
])
def test_native_binding_refuses_architectural_faults(tmp_path: Path, code: bytes,
                                                   reason: NativeBindingReason) -> None:
    """The binding refuses faults it cannot model instead of endorsing them."""
    report = _binding_for(tmp_path, code + b"\xc3")
    assert report.status is ProofStatus.UNKNOWN, (code.hex(), report)
    assert report.reason is reason, (code.hex(), report.reason, report.detail)


def test_native_binding_refuses_aam_zero_divide_fault(tmp_path: Path) -> None:
    """Preserve the exact parent counterexample: AAM 0 must refuse FAULT."""
    report = _binding_for(tmp_path, b"\xd4\x00\xc3")
    assert report.status is ProofStatus.UNKNOWN and report.reason is NativeBindingReason.FAULT, report


def test_forged_or_stale_receipt_cannot_open_the_outcome_scope(scope_case: ScopeCase) -> None:
    """Receipt forgery refuses before any admitted row is attempted."""
    inputs, receipt, bounds, _scope_obj = scope_case
    for corrupted in (replace(receipt, facts=receipt.facts[:-1]),
                      replace(receipt, model_hash="0" * 64),
                      replace(receipt, proposal_hash="0" * 64),
                      replace(receipt, sources=receipt.sources[:1])):
        refused = prove_real16_normal_outcome_scope(corrupted, *inputs, bounds)
        assert refused.status is ProofStatus.UNKNOWN, refused
        assert refused.reason is OutcomeScopeReason.RECEIPT and not refused.blocks


def test_unproved_or_stale_bounds_cannot_close_access_geometry(scope_case: ScopeCase) -> None:
    """The outcome scope never substitutes its own byte claims for bound rows."""
    inputs, receipt, bounds, _scope_obj = scope_case
    for corrupted in (replace(bounds, model_hash="0" * 64),
                      replace(bounds, proposal_hash="0" * 64),
                      replace(bounds, blocks=bounds.blocks[:-1])):
        refused = prove_real16_normal_outcome_scope(receipt, *inputs, corrupted)
        assert refused.status is ProofStatus.UNKNOWN, refused
        assert refused.reason is OutcomeScopeReason.BOUNDS
    expired = prove_real16_physical_access_bounds(receipt, *inputs, timeout_ms=0)
    assert expired.reason is PhysicalAccessReason.DEADLINE
    refused = prove_real16_normal_outcome_scope(receipt, *inputs, expired)
    assert refused.status is ProofStatus.UNKNOWN and refused.reason is OutcomeScopeReason.BOUNDS


def test_removed_request_row_leaves_the_denominator_open(scope_case: ScopeCase) -> None:
    """Dropping an admitted request row cannot shrink the required ledger."""
    inputs, receipt, bounds, _scope_obj = scope_case
    requests = (inputs.requests[0][1:], inputs.requests[1])
    refused = prove_real16_normal_outcome_scope(receipt, inputs.system, inputs.loads,
        inputs.initialized, inputs.bootstrap, requests, bounds)
    assert refused.status is ProofStatus.UNKNOWN and not refused.complete, refused
    assert refused.counters.failure_count > 0


def test_outcome_scope_shares_the_original_deadline(scope_case: ScopeCase) -> None:
    """A zero remaining budget retains the complete required denominator."""
    inputs, receipt, bounds, _scope_obj = scope_case
    refused = prove_real16_normal_outcome_scope(receipt, *inputs, bounds,
                                                timeout_ms=0, limits=LoadedRelationLimits())
    assert refused.status is ProofStatus.UNKNOWN and refused.reason is OutcomeScopeReason.DEADLINE
    assert refused.counters.failure_count > 0 and not refused.blocks
    block_rows = [key for obligation, key in refused.required
                  if obligation is OutcomeScopeObligation.BLOCK]
    assert len(block_rows) == 2 * (len(inputs.system.steps) + 1)


def test_outcome_scope_counters_account_for_every_required_row(scope_case: ScopeCase) -> None:
    """Materialized facts equal the frozen denominator; failures are zero."""
    _inputs_args, _receipt, _bounds, scope = scope_case
    counters = scope.counters
    assert counters.raw_fact_count == counters.normalized_fact_count \
        == counters.classified_fact_count == len(scope.required)
    assert counters.materialized_count == len(scope.required) and counters.failure_count == 0
    assert isinstance(counters, FactCounters)
