"""Layer: dosunit image-bound recursive prerequisite consumption (staging).

Responsibility: revalidate exact ledgers, immutable loads, proposal content and
model identities before downstream native induction uses a saved certificate.
Successful consumption closes prerequisites only, never recursive equivalence.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, replace
from enum import StrEnum

from tools.dosunit.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import BoundReal16Load, ImageBindingRefusal
from tools.dosunit.recursive_proofs.loaded_byte_native_transition import (
    LoadedTransitionReason,
    _consume_domain,
    _TransitionRefusal,
    _TransitionRun,
)
from tools.dosunit.recursive_proofs.loaded_byte_relation import (
    LoadedRelationLimits,
    LoadedRelationReason,
    LoadedRelationRefusal,
)
from tools.dosunit.recursive_proofs.loaded_byte_relation_proof import LoadedRelationProof
from tools.dosunit.recursive_proofs.real16_entry_domain import native_effect_hash
from tools.dosunit.recursive_proofs.real16_entry_domain_proof import propose_entry_scalar_domain
from tools.dosunit.recursive_proofs.real16_image_bound_domain import (
    BoundDomainObligation,
    BoundDomainReason,
    ImageBoundReal16Domain,
    _admit,
    _BoundRun,
    _linked,
    image_bound_domain_model_hash,
)
from tools.dosunit.recursive_proofs.real16_native_effect_binding import (
    NativeBindingReason,
    NativeBlockRequest,
    _BindingRun,
    _block_bytes,
    _NativeRefusal,
    native_binding_model_hash,
)
from tools.dosunit.recursive_proofs.recursive_joint_admission import JointRefusal
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointReason, JointSystem
from tools.dosunit.recursive_proofs.recursive_joint_identity import joint_proposal_hash
from tools.dosunit.register_state_relations import MachineState


class DomainConsumptionObligation(StrEnum):
    """Every receipt consumer premise remains required on early refusal."""

    RECEIPT = "complete_image_bound_prerequisite_receipt"
    CONTENT = "unchanged_complete_joint_proposal"
    ORIGINAL = "unchanged_original_binary_source_receipt"
    CANDIDATE = "unchanged_candidate_binary_source_receipt"
    DOMAIN = "complete_derived_domain_receipt"
    MODEL = "unchanged_complete_consumer_model"


@dataclass(frozen=True, slots=True)
class DomainConsumptionFact:
    """One exact attempted receipt check, retaining failures in the denominator."""

    obligation: DomainConsumptionObligation
    status: ProofStatus


@dataclass(frozen=True, slots=True)
class BoundDomainConsumption:
    """Current prerequisite validity, without any whole-program promotion."""

    status: ProofStatus
    reason: BoundDomainReason
    facts: tuple[DomainConsumptionFact, ...]
    counters: FactCounters
    detail: str = ""

    @property
    def complete(self) -> bool:
        """Require the exact six current provenance facts, once each, without gaps."""
        ids = tuple(row.obligation for row in self.facts)
        count = len(DomainConsumptionObligation)
        return (self.status is ProofStatus.PROVED and self.reason is BoundDomainReason.DISCHARGED
                and len(ids) == count and len(set(ids)) == count
                and set(ids) == set(DomainConsumptionObligation)
                and all(row.status is ProofStatus.PROVED for row in self.facts)
                and self.counters == FactCounters(count, count, count, count, 0))


class _ReceiptRefusal(Exception):
    """Name an incomplete saved prerequisite without widening child exceptions."""

    def __init__(self, reason: BoundDomainReason, detail: str) -> None:
        """Retain the owned boundary reason and its exact cause description."""
        self.reason = reason
        self.detail = detail
        super().__init__(detail)


def _source_valid(run: _BoundRun, side: int, current_native_model: str) -> bool:
    """Recheck one source against this invocation's fresh, explicitly passed model.

    File, snapshot, effect and manifest checks stay independent for each side.
    The consumer separately refreshes its complete model after both checks.
    """
    load = run.loads[side]
    source = run.sources[side]
    load.verify(limits=run.limits)
    expected = _BindingRun(load, run.requests[side], run.limits, model_hash=source.model_hash,
                           blocks=list(source.blocks), facts=list(source.facts)).report(source.reason)
    complete = (source.status is ProofStatus.PROVED and expected.status is ProofStatus.PROVED
                and source.counters == expected.counters and source.requests == run.requests[side])
    bound = (source.model_hash == current_native_model and source.file_hash == load.binding.file_sha256
             and source.snapshot_hash == load.binding.snapshot.sparse_byte_sha256)
    if not complete or not bound:
        return False
    binding = _BindingRun(load, run.requests[side], run.limits)
    for row, block in zip(run.requests[side], source.blocks, strict=True):
        run.remaining_ms()
        if (block.address != row.address or block.size != row.size or block.effect_hash != row.effect_hash
                or block.byte_hash != hashlib.sha256(_block_bytes(binding, row)).hexdigest()):
            return False
    return _linked(run, side)


def _receipt_valid(receipt: ImageBoundReal16Domain) -> bool:
    """Require the authoritative seven facts exactly once with complete counters."""
    ids = tuple(fact.obligation for fact in receipt.facts)
    count = len(BoundDomainObligation)
    complete = len(ids) == count and set(ids) == set(BoundDomainObligation)
    valid = (receipt.status is ProofStatus.PROVED and receipt.reason is BoundDomainReason.DISCHARGED
             and complete and all(fact.status is ProofStatus.PROVED for fact in receipt.facts))
    return (valid and receipt.counters == FactCounters(count, count, count, count, 0)
            and len(receipt.sources) == 2 and receipt.domain is not None)


def _domain_valid(run: _BoundRun, root: int) -> None:
    """Rebind the complete derived scalar proof to the current source effects."""
    domain = run.domain
    if domain is None:
        raise ValueError("complete prerequisite receipt must retain its derived scalar proof")
    expected_domain = propose_entry_scalar_domain(run.loads[0])
    if domain.domain != expected_domain:
        raise _ReceiptRefusal(BoundDomainReason.DOMAIN, "derived scalar contract differs from the actual producer inputs")
    effects = (*tuple((step.original, step.candidate) for step in run.system.steps), run.bootstrap)
    expected_effects = tuple((native_effect_hash(a), native_effect_hash(b)) for a, b in effects)
    file_hashes = tuple(load.binding.file_sha256 for load in run.loads)
    if (domain.root_address != root or domain.effects != expected_effects
            or (domain.original_file_hash, domain.candidate_file_hash) != file_hashes):
        raise _ReceiptRefusal(BoundDomainReason.DOMAIN, "derived proof refers to different effects or files")
    guard = _TransitionRun(run.initialized, run.limits, 262144, 128, domain=domain)
    for a, b in effects:
        run.remaining_ms()
        _consume_domain(guard, a, b)


def _verify_prerequisites(run: _BoundRun, receipt: ImageBoundReal16Domain,
                          facts: list[DomainConsumptionFact]) -> None:
    """Check the six consumption premises in the authoritative manifest order."""
    run.remaining_ms()
    if not _receipt_valid(receipt):
        raise _ReceiptRefusal(BoundDomainReason.STATE, "image-bound receipt is incomplete")
    facts.append(DomainConsumptionFact(DomainConsumptionObligation.RECEIPT, ProofStatus.PROVED))
    root = _admit(run)
    if not receipt.proposal_hash or receipt.proposal_hash != joint_proposal_hash(run.system, run.bootstrap):
        raise _ReceiptRefusal(BoundDomainReason.CONTENT, "joint proposal content differs from receipt")
    facts.append(DomainConsumptionFact(DomainConsumptionObligation.CONTENT, ProofStatus.PROVED))
    # Both sides belong to this one consumption boundary. Keep only a local
    # value; the final complete-model check independently reads fresh sources.
    current_native_model = native_binding_model_hash()
    run.remaining_ms()
    for side, current in enumerate((DomainConsumptionObligation.ORIGINAL, DomainConsumptionObligation.CANDIDATE)):
        if not _source_valid(run, side, current_native_model):
            raise _ReceiptRefusal(BoundDomainReason.SOURCE, "independent source receipt changed or incomplete")
        facts.append(DomainConsumptionFact(current, ProofStatus.PROVED))
    _domain_valid(run, root)
    facts.append(DomainConsumptionFact(DomainConsumptionObligation.DOMAIN, ProofStatus.PROVED))
    if receipt.model_hash != image_bound_domain_model_hash():
        raise _ReceiptRefusal(BoundDomainReason.MODEL, "complete prerequisite/consumer model changed")
    run.remaining_ms()
    facts.append(DomainConsumptionFact(DomainConsumptionObligation.MODEL, ProofStatus.PROVED))


def consume_image_bound_real16_domain(
    receipt: ImageBoundReal16Domain, system: JointSystem, loads: tuple[BoundReal16Load, BoundReal16Load],
    initialized: LoadedRelationProof, bootstrap: tuple[MachineState, MachineState],
    requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]],
    *, timeout_ms: int = 10000, limits: LoadedRelationLimits | None = None,
) -> BoundDomainConsumption:
    """Accept complete current prerequisites without repeating their SMT proofs.

    The producer is an owned trusted proof boundary. This consumer prevents stale
    or incomplete receipts, including edits through their mutable effect trees,
    from transferring that producer's result to different downstream inputs.
    All validation shares one original deadline; no nested budget is replenished.
    """
    if type(timeout_ms) is not int or timeout_ms < 0:
        raise ValueError("receipt consumption requires a nonnegative millisecond budget")
    selected = limits if limits is not None else LoadedRelationLimits()
    deadline = time.monotonic() + timeout_ms / 1000
    if selected.deadline >= 0:
        deadline = min(deadline, selected.deadline)
    run = _BoundRun(system, loads, initialized, bootstrap, requests, replace(selected, deadline=deadline),
                    sources=list(receipt.sources), domain=receipt.domain)
    facts: list[DomainConsumptionFact] = []
    reason, detail = BoundDomainReason.DISCHARGED, ""
    try:
        _verify_prerequisites(run, receipt, facts)
    except _ReceiptRefusal as refusal:
        reason, detail = refusal.reason, refusal.detail
    except _TransitionRefusal as refusal:
        reason = BoundDomainReason.DEADLINE if refusal.reason is LoadedTransitionReason.DEADLINE else BoundDomainReason.STATE
        detail = refusal.detail
    except _NativeRefusal as refusal:
        reason = BoundDomainReason.DEADLINE if refusal.reason is NativeBindingReason.DEADLINE else BoundDomainReason.SOURCE
        detail = refusal.detail
    except JointRefusal as refusal:
        reason = BoundDomainReason.DEADLINE if refusal.reason is JointReason.DEADLINE else BoundDomainReason.JOINT
        detail = refusal.detail
    except ImageBindingRefusal as refusal:
        reason, detail = BoundDomainReason.IMAGE, refusal.detail
    except LoadedRelationRefusal as refusal:
        reason = BoundDomainReason.DEADLINE if refusal.reason is LoadedRelationReason.DEADLINE else BoundDomainReason.IMAGE
        detail = refusal.detail
    if reason is not BoundDomainReason.DISCHARGED:
        current = tuple(DomainConsumptionObligation)[len(facts)]
        facts.append(DomainConsumptionFact(current, ProofStatus.UNKNOWN))
    count = len(DomainConsumptionObligation)
    failed = count - sum(fact.status is ProofStatus.PROVED for fact in facts)
    status = ProofStatus.PROVED if failed == 0 else ProofStatus.UNKNOWN
    return BoundDomainConsumption(status, reason, tuple(facts), FactCounters(count, count, count, len(facts), failed), detail)
