"""Source-bound address closure accepts exact evidence and rejects corruption.

Layer: integration tests.
Responsibility: exercise private same-run address composition with actual MZ
children; immutable module fixtures bound setup cost without mutating evidence.
"""
from __future__ import annotations

import sys
import time
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import NamedTuple

import pytest
from inertia.frontend.x86_16.control_coordinates import ControlAddressDomain
from tools.dosunit.tests.recursive_proof_fixtures.image_bound_inputs import Inputs, make_inputs

from tools.dosunit.contracts.model import canonical_json_bytes
from tools.dosunit.contracts.proof_contracts import ProofStatus
from tools.dosunit.recursive_proofs import real16_address_model_closure as closure_owner
from tools.dosunit.recursive_proofs.loaded_byte_relation import LoadedRelationLimits

# Resolved post-relocation by the parent:
from tools.dosunit.recursive_proofs.real16_address_model_closure import (
    AddressModelClosure,
    AddressModelObligation,
    AddressModelReason,
    _check_address_model_closure,
)
from tools.dosunit.recursive_proofs.real16_bound_control_scope import BoundReal16ControlScope
from tools.dosunit.recursive_proofs.real16_bound_operand_scope import BoundReal16OperandScope
from tools.dosunit.recursive_proofs.real16_code_prefix_proof import Real16CodePrefixProof
from tools.dosunit.recursive_proofs.real16_domain_dispatch import (
    DomainDispatchObligation,
    Real16DomainDispatchProof,
)
from tools.dosunit.recursive_proofs.real16_entry_domain import native_effect_hash
from tools.dosunit.recursive_proofs.real16_entry_frame import Real16EntryFrameProof
from tools.dosunit.recursive_proofs.real16_fetched_code_intake import PrefixIntakeReason
from tools.dosunit.recursive_proofs.real16_image_bound_domain import (
    ImageBoundReal16Domain,
    prove_image_bound_real16_domain,
)
from tools.dosunit.recursive_proofs.real16_image_bound_joint_proof import (
    ImageBoundReal16JointProof,
    check_image_bound_real16_joint,
)
from tools.dosunit.recursive_proofs.real16_native_effect_binding import NativeBlockRequest
from tools.dosunit.recursive_proofs.real16_physical_access_bounds import (
    PHYSICAL_MODEL_LIMIT,
    Real16PhysicalAccessBounds,
)
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointModelRequirement
from tools.dosunit.recursive_proofs.recursive_joint_identity import joint_proposal_hash
from tools.dosunit.recursive_proofs.stack.recursive_stack_clauses import StackClauseKind
from tools.dosunit.recursive_proofs.stack.recursive_stack_proofs import (
    StackInvariantProof,
    StackObligation,
)


class Evidence(NamedTuple):
    """One actual joint run plus every child the compositor consumes."""

    inputs: Inputs
    receipt: ImageBoundReal16Domain
    proof: ImageBoundReal16JointProof


def _evidence(tmp_path: Path) -> Evidence:
    """Produce real child certificates from the actual-MZ joint fixture."""
    inputs = make_inputs(tmp_path)
    receipt = prove_image_bound_real16_domain(*inputs)
    assert receipt.status is ProofStatus.PROVED, receipt
    proof = check_image_bound_real16_joint(receipt, *inputs)
    assert proof.entry is not None and proof.prefixes is not None
    assert proof.operands is not None and proof.addresses is not None
    assert proof.controls is not None and proof.dispatch is not None
    return Evidence(inputs, receipt, proof)


@pytest.fixture(scope="module")
def shared_evidence(tmp_path_factory: pytest.TempPathFactory) -> Evidence:
    """Build one unchanged real-MZ proof per worker for independent mutations."""
    return _evidence(tmp_path_factory.mktemp("address-evidence"))


@pytest.fixture(autouse=True)
def reuse_unchanged_evidence(monkeypatch: pytest.MonkeyPatch, shared_evidence: Evidence) -> Iterator[None]:
    """Reuse setup while checking every test leaves joint effects unchanged."""
    inputs = shared_evidence.inputs
    before = joint_proposal_hash(inputs.system, inputs.bootstrap)
    receipt_before = repr(shared_evidence)
    monkeypatch.setattr(sys.modules[__name__], "_evidence", lambda path: shared_evidence)
    yield
    assert joint_proposal_hash(inputs.system, inputs.bootstrap) == before
    assert repr(shared_evidence) == receipt_before


def _close(evidence: Evidence, *, receipt: ImageBoundReal16Domain | None = None,
           requests: tuple[tuple[NativeBlockRequest, ...],
                           tuple[NativeBlockRequest, ...]] | None = None,
           prefixes: Real16CodePrefixProof | None = None,
           operands: BoundReal16OperandScope | None = None,
           addresses: Real16PhysicalAccessBounds | None = None,
           controls: BoundReal16ControlScope | None = None,
           frames: tuple[StackInvariantProof, ...] | None = None,
           dispatch: Real16DomainDispatchProof | None = None,
           entry: Real16EntryFrameProof | None = None,
           limits: LoadedRelationLimits | None = None) -> AddressModelClosure:
    """Call the compositor with the real children unless a control overrides."""
    inputs, proof = evidence.inputs, evidence.proof
    assert proof.prefixes is not None and proof.operands is not None
    assert proof.addresses is not None and proof.entry is not None
    assert proof.controls is not None and proof.dispatch is not None
    return _check_address_model_closure(
        inputs.system, receipt if receipt is not None else evidence.receipt,
        inputs.loads, inputs.initialized, inputs.bootstrap,
        requests if requests is not None else inputs.requests,
        prefixes if prefixes is not None else proof.prefixes,
        operands if operands is not None else proof.operands,
        addresses if addresses is not None else proof.addresses,
        controls if controls is not None else proof.controls,
        frames if frames is not None else proof.frames,
        dispatch if dispatch is not None else proof.dispatch,
        entry if entry is not None else proof.entry,
        limits=limits)


def _reason(result: AddressModelClosure, expected: AddressModelReason) -> None:
    """Require the typed refusal and a certificate that never promotes."""
    assert result.reason is expected, (result.reason, result.detail)
    assert result.status is ProofStatus.UNKNOWN and not result.complete
    assert not result.binary_equivalence_proved
    assert result.counters.failure_count > 0


def test_address_model_closure_green_on_actual_joint_evidence(tmp_path: Path) -> None:
    """Complete real evidence closes the ledger and retains its consumption."""
    result = _close(_evidence(tmp_path))
    if not result.complete:
        # A genuinely incomplete child (e.g. an unpinned-selector countermodel
        # upstream) must yield the exact typed reason, never a forced pass.
        pytest.fail(f"expected closed ledger, got {result.reason.value}: {result.detail}")
    assert result.reason is AddressModelReason.CLOSED
    assert result.consumptions and all(item.complete for item in result.consumptions)
    assert len(result.terminal_addresses) == 2
    assert all(0 <= terminal < PHYSICAL_MODEL_LIMIT for terminal in result.terminal_addresses)
    assert all(fact.status is ProofStatus.PROVED for fact in result.facts)
    assert len(result.facts) == len(AddressModelObligation)


@pytest.mark.parametrize("corruption", ("facts", "model_hash", "sources", "domain"))
def test_forged_or_stale_receipt_refuses(tmp_path: Path, corruption: str) -> None:
    """A saved PROVED label cannot substitute for authoritative consumption."""
    evidence = _evidence(tmp_path)
    receipt = evidence.receipt
    if corruption == "facts":
        forged = replace(receipt, facts=receipt.facts[:-1])
    elif corruption == "model_hash":
        forged = replace(receipt, model_hash="0" * 64)
    elif corruption == "sources":
        forged = replace(receipt, sources=receipt.sources[:1])
    else:
        assert receipt.domain is not None
        forged = replace(receipt, domain=replace(receipt.domain, facts=receipt.domain.facts[:-1]))
    _reason(_close(evidence, receipt=forged), AddressModelReason.RECEIPT)


@pytest.mark.parametrize("mutation", ("drop_step", "duplicate", "drop_entry", "effect"))
def test_request_manifest_drift_refuses(tmp_path: Path, mutation: str) -> None:
    """The (address, effect_hash) pair denominator rejects missing/extra rows."""
    evidence = _evidence(tmp_path)
    requests = evidence.inputs.requests
    if mutation == "drop_step":
        drifted = (requests[0][:-1], requests[1])
    elif mutation == "duplicate":
        drifted = ((*requests[0], requests[0][0]), requests[1])
    elif mutation == "drop_entry":
        drifted = (requests[0][:-1], requests[1][:-1])
        # Both sides must lose their entry rows for the pair sets to differ.
    else:
        row = requests[0][0]
        bootstrap = evidence.inputs.bootstrap[0]
        drifted = ((NativeBlockRequest(row.address, row.size,
                                       native_effect_hash(bootstrap),
                                       canonical_json_bytes(bootstrap)),
                    *requests[0][1:]), requests[1])
    _reason(_close(evidence, requests=drifted), AddressModelReason.RECEIPT)


@pytest.mark.parametrize("mutation", ("missing", "extra", "resized", "coordinate"))
def test_fetch_block_denominator_refuses(tmp_path: Path, mutation: str) -> None:
    """Prefix blocks must be the exact ordered request manifest, nothing else."""
    evidence = _evidence(tmp_path)
    prefixes = evidence.proof.prefixes
    if mutation == "missing":
        forged = replace(prefixes, blocks=prefixes.blocks[:-1])
    elif mutation == "extra":
        forged = replace(prefixes, blocks=(*prefixes.blocks, prefixes.blocks[0]))
    elif mutation == "resized":
        forged = replace(prefixes, blocks=(replace(prefixes.blocks[0],
                                                 size=prefixes.blocks[0].size + 1),
                                         *prefixes.blocks[1:]))
    else:
        scope = replace(prefixes.blocks[0].fetch_scope,
                        coordinate_domain=ControlAddressDomain.ARCHITECTURAL_OFFSET)
        forged = replace(prefixes, blocks=(replace(prefixes.blocks[0], fetch_scope=scope),
                                         *prefixes.blocks[1:]))
    _reason(_close(evidence, prefixes=forged), AddressModelReason.FETCH)


@pytest.mark.parametrize("mutation", ("missing", "consumption", "status", "byte_hash", "collected"))
def test_operand_denominator_rebinding_refuses(tmp_path: Path, mutation: str) -> None:
    """Operand blocks rebind to requests and to the bytes both decoders saw."""
    evidence = _evidence(tmp_path)
    operands = evidence.proof.operands
    if mutation == "missing":
        forged = replace(operands, blocks=operands.blocks[:-1])
    elif mutation == "consumption":
        forged = replace(operands, consumption=None)
    elif mutation == "status":
        bound = operands.blocks[0]
        forged = replace(operands, blocks=(replace(bound, proof=replace(bound.proof,
                                                                      status=ProofStatus.UNKNOWN)),
                                         *operands.blocks[1:]))
    elif mutation == "byte_hash":
        bound = operands.blocks[0]
        proof = replace(bound.proof, collected=replace(bound.proof.collected, byte_hash="0" * 64))
        forged = replace(operands, blocks=(replace(bound, proof=proof), *operands.blocks[1:]))
    else:
        index = next(index for index, block in enumerate(operands.blocks)
                     if block.proof.collected.facts)
        bound = operands.blocks[index]
        assert bound.proof.collected.facts
        proof = replace(bound.proof, collected=replace(bound.proof.collected,
                                                       facts=bound.proof.collected.facts[:-1]))
        blocks = list(operands.blocks)
        blocks[index] = replace(bound, proof=proof)
        forged = replace(operands, blocks=tuple(blocks))
    _reason(_close(evidence, operands=forged), AddressModelReason.OPERAND)


@pytest.mark.parametrize("mutation", ("missing", "extra", "limit", "proposal", "byte_hash", "omissions"))
def test_physical_certificate_rebinding_refuses(tmp_path: Path, mutation: str) -> None:
    """Physical blocks rebind to requests, raw ledgers and this run's proposal."""
    evidence = _evidence(tmp_path)
    addresses = evidence.proof.addresses
    if mutation == "missing":
        forged = replace(addresses, blocks=addresses.blocks[:-1])
    elif mutation == "extra":
        forged = replace(addresses, blocks=(*addresses.blocks, addresses.blocks[0]))
    elif mutation == "limit":
        forged = replace(addresses, model_limit=PHYSICAL_MODEL_LIMIT + 1)
    elif mutation == "proposal":
        forged = replace(addresses, proposal_hash="0" * 64)
    elif mutation == "byte_hash":
        forged = replace(addresses, blocks=(replace(addresses.blocks[0], byte_hash="0" * 64),
                                          *addresses.blocks[1:]))
    else:
        forged = replace(addresses, omissions=addresses.omissions[:-1])
    _reason(_close(evidence, addresses=forged), AddressModelReason.BOUNDS)


@pytest.mark.parametrize("mutation", ("shuffled", "missing", "status", "return_target", "continuation"))
def test_frame_manifest_refuses(tmp_path: Path, mutation: str) -> None:
    """Frame rows bind to kind, side order, clause manifest and continuation."""
    evidence = _evidence(tmp_path)
    frames = evidence.proof.frames
    if mutation == "shuffled":
        forged_frames = (*frames[1:], frames[0])
    elif mutation == "missing":
        forged_frames = frames[:-1]
    elif mutation == "status":
        forged_frames = (replace(frames[0], status=ProofStatus.UNKNOWN), *frames[1:])
    elif mutation == "return_target":
        pop = next(frame for frame in frames if frame.obligation is StackObligation.POP)
        index = frames.index(pop)
        narrowed = replace(pop, required_clauses=tuple(
            kind for kind in pop.required_clauses if kind is not StackClauseKind.RETURN_TARGET))
        forged_frames = (*frames[:index], narrowed, *frames[index + 1:])
    else:
        push = next(frame for frame in frames if frame.obligation is StackObligation.PUSH)
        index = frames.index(push)
        forged_frames = (*frames[:index],
                         replace(push, expected_continuation=None), *frames[index + 1:])
    _reason(_close(evidence, frames=forged_frames), AddressModelReason.FRAME)


@pytest.mark.parametrize("mutation", ("missing", "extra", "resized", "intake_missing",
                                      "intake_stale", "model"))
def test_bound_control_scope_refuses(tmp_path: Path, mutation: str) -> None:
    """Bound controls rebind to the exact request denominator and intakes."""
    evidence = _evidence(tmp_path)
    controls = evidence.proof.controls
    assert controls is not None
    bound = controls.blocks[0]
    if mutation == "missing":
        forged = replace(controls, blocks=controls.blocks[:-1])
    elif mutation == "extra":
        forged = replace(controls, blocks=(*controls.blocks, controls.blocks[0]))
    elif mutation == "resized":
        forged = replace(controls, blocks=(replace(bound, size=bound.size + 1),
                                         *controls.blocks[1:]))
    elif mutation == "intake_missing":
        forged = replace(controls, intakes=controls.intakes[:1])
    elif mutation == "intake_stale":
        forged = replace(controls, intakes=(replace(controls.intakes[0],
                                                    reason=PrefixIntakeReason.MODEL),
                                            *controls.intakes[1:]))
    else:
        forged = replace(controls, model_hash="0" * 64)
    _reason(_close(evidence, controls=forged), AddressModelReason.CONTROL)


@pytest.mark.parametrize("mutation", ("status", "counterexample", "source_hash",
                                      "entry_hash", "foreign_domain"))
def test_bound_control_inner_proof_refuses(tmp_path: Path, mutation: str) -> None:
    """Each native scope proof rebinds bytes, entry state and scalar domain."""
    evidence = _evidence(tmp_path)
    controls = evidence.proof.controls
    assert controls is not None
    if mutation == "foreign_domain":
        index = next(index for index, block in enumerate(controls.blocks)
                     if block.proof.domain is not None)
        scoped = controls.blocks[index]
        assert scoped.proof.domain is not None
        foreign = replace(scoped.proof.domain, cs=(scoped.proof.domain.cs + 1) & 0xFFFF)
        proof = replace(scoped.proof, domain=foreign)
    else:
        index = 0
        proof = controls.blocks[0].proof
        if mutation == "status":
            proof = replace(proof, status=ProofStatus.UNKNOWN)
        elif mutation == "counterexample":
            proof = replace(proof, status=ProofStatus.COUNTEREXAMPLE)
        elif mutation == "source_hash":
            proof = replace(proof, source_sha256="0" * 64)
        else:
            proof = replace(proof, entry_sha256="0" * 64)
    forged = replace(controls, blocks=(*controls.blocks[:index],
                                       replace(controls.blocks[index], proof=proof),
                                       *controls.blocks[index + 1:]))
    _reason(_close(evidence, controls=forged), AddressModelReason.CONTROL)


@pytest.mark.parametrize("mutation", ("missing_fact", "duplicate_fact", "dropped_required",
                                      "foreign_required", "stale_proposal", "stale_model",
                                      "counterexample", "incomplete_consumer",
                                      "dropped_consumer"))
def test_domain_dispatch_receipt_refuses(tmp_path: Path, mutation: str) -> None:
    """The retained dispatch ledger must equal this system's denominator."""
    evidence = _evidence(tmp_path)
    dispatch = evidence.proof.dispatch
    assert dispatch is not None
    if mutation == "missing_fact":
        forged = replace(dispatch, facts=dispatch.facts[:-1])
    elif mutation == "duplicate_fact":
        forged = replace(dispatch, facts=(*dispatch.facts, dispatch.facts[0]))
    elif mutation == "dropped_required":
        forged = replace(dispatch, required=dispatch.required[:-1])
    elif mutation == "foreign_required":
        obligation, key = dispatch.required[-1]
        forged = replace(dispatch, required=(*dispatch.required[:-1],
                                             (obligation, f"{key}:foreign")))
    elif mutation == "stale_proposal":
        forged = replace(dispatch, proposal_hash="0" * 64)
    elif mutation == "stale_model":
        forged = replace(dispatch, model_hash="0" * 64)
    elif mutation == "counterexample":
        index = next(index for index, fact in enumerate(dispatch.facts)
                     if fact.obligation is DomainDispatchObligation.COVERAGE)
        forged = replace(dispatch, facts=(*dispatch.facts[:index],
                                          replace(dispatch.facts[index],
                                                  status=ProofStatus.COUNTEREXAMPLE),
                                          *dispatch.facts[index + 1:]))
    elif mutation == "incomplete_consumer":
        forged = replace(dispatch, consumers=(replace(dispatch.consumers[0],
                                                    status=ProofStatus.UNKNOWN),
                                              *dispatch.consumers[1:]))
    else:
        forged = replace(dispatch, consumers=dispatch.consumers[:1])
    _reason(_close(evidence, dispatch=forged), AddressModelReason.DISPATCH)


@pytest.mark.parametrize("mutation", ("caller", "effect_hash", "status", "sides"))
def test_terminal_and_root_rebinding_refuses(tmp_path: Path, mutation: str) -> None:
    """Terminal rows rebind to receipt sources, bootstrap effects and the domain."""
    evidence = _evidence(tmp_path)
    entry = evidence.proof.entry
    if mutation == "caller":
        side = replace(entry.sides[0], caller_address=entry.sides[0].caller_address + 2)
        forged = replace(entry, sides=(side, entry.sides[1]))
    elif mutation == "effect_hash":
        side = replace(entry.sides[0], effect_hash="0" * 64)
        forged = replace(entry, sides=(side, entry.sides[1]))
    elif mutation == "status":
        forged = replace(entry, status=ProofStatus.UNKNOWN)
    else:
        forged = replace(entry, sides=entry.sides[:1])
    _reason(_close(evidence, entry=forged), AddressModelReason.TERMINAL)


def test_stale_child_model_identity_refuses(tmp_path: Path) -> None:
    """A child certificate whose seal no longer matches its owner fails MODEL."""
    evidence = _evidence(tmp_path)
    forged = replace(evidence.proof.prefixes, model_hash="0" * 64)
    _reason(_close(evidence, prefixes=forged), AddressModelReason.MODEL)


def test_exhausted_deadline_refuses_with_ledger(tmp_path: Path) -> None:
    """An elapsed shared deadline yields DEADLINE, never a partial closure."""
    evidence = _evidence(tmp_path)
    result = _close(evidence, limits=LoadedRelationLimits(deadline=time.monotonic() - 1))
    _reason(result, AddressModelReason.DEADLINE)
    assert result.counters.materialized_count == len(result.facts)


def test_closure_never_discharges_fault_or_environment(tmp_path: Path) -> None:
    """Fault evidence comes from the separate outcome child, never address scope."""
    evidence = _evidence(tmp_path)
    result = _close(evidence)
    if result.complete:
        assert not result.binary_equivalence_proved
    remaining = set(evidence.proof.remaining)
    assert evidence.proof.outcomes is not None and evidence.proof.outcomes.synchronous_closed
    assert JointModelRequirement.FAULT_DOMAIN not in remaining
    rows = [row for row in evidence.proof.proof.verdicts if row.id.key == "complete_normal_outcome_scope"]
    assert len(rows) == 1 and rows[0].status is ProofStatus.CONDITIONAL
    assert JointModelRequirement.ENVIRONMENT in remaining


def test_operand_discharged_fact_ledger_is_required(tmp_path: Path) -> None:
    """A proved collection cannot replace missing or contradicted scope facts."""
    evidence = _evidence(tmp_path)
    operands = evidence.proof.operands
    assert operands is not None
    bound = operands.blocks[0]
    proof = bound.proof
    assert closure_owner._operand_ledger_complete(proof)
    variants = (
        replace(proof, facts=()),
        replace(proof, facts=proof.facts[:-1]),
        replace(proof, facts=(*proof.facts, proof.facts[0])),
        replace(proof, facts=(replace(proof.facts[0], status=ProofStatus.COUNTEREXAMPLE),
                              *proof.facts[1:])),
        replace(proof, facts=(replace(proof.facts[0], deadline_exhausted=True),
                              *proof.facts[1:])),
    )
    for forged in variants:
        assert not closure_owner._operand_ledger_complete(forged)
        changed = replace(operands, blocks=(replace(bound, proof=forged), *operands.blocks[1:]))
        _reason(_close(evidence, operands=changed), AddressModelReason.OPERAND)


def test_operand_source_cannot_borrow_another_domain(tmp_path: Path) -> None:
    """Equal decoded bytes cannot transfer scope from a stale proposal/domain."""
    evidence = _evidence(tmp_path)
    operands = evidence.proof.operands
    assert operands is not None
    source = operands.source
    variants = (
        replace(source, receipt=None),
        replace(source, requests=((), ())),
        replace(source, proposal_hash="0" * 64),
        replace(source, model_hash="0" * 64),
    )
    for forged in variants:
        _reason(_close(evidence, operands=replace(operands, source=forged)),
                AddressModelReason.OPERAND)
