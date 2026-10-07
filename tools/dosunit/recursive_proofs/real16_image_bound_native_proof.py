"""Layer: dosunit image-bound full-state native relation proof (staging).

Responsibility: consume independently decoded source/domain prerequisites and
check startup plus every admitted recursive transition over the initialized
full-array relation. Local transitions do not close recursive frame, fault,
environment or final-observer obligations and never grant binary equivalence.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path

from tools.dosunit.contracts.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.contracts.register_state_relations import MachineState
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import BoundReal16Load
from tools.dosunit.recursive_proofs.loaded_byte_native_transition import (
    LoadedTransitionReason,
    LoadedTransitionResult,
    check_loaded_native_transition,
)
from tools.dosunit.recursive_proofs.loaded_byte_relation import (
    LoadedRelationLimits,
    LoadedRelationReason,
    LoadedRelationRefusal,
)
from tools.dosunit.recursive_proofs.loaded_byte_relation_proof import LoadedRelationProof
from tools.dosunit.recursive_proofs.real16_image_bound_domain import (
    BoundDomainReason,
    ImageBoundReal16Domain,
    image_bound_domain_model_hash,
)
from tools.dosunit.recursive_proofs.real16_image_bound_domain_consumer import (
    BoundDomainConsumption,
    consume_image_bound_real16_domain,
)
from tools.dosunit.recursive_proofs.real16_native_effect_binding import NativeBlockRequest
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointModelRequirement, JointSystem


class ImageBoundNativeReason(StrEnum):
    """Full native relation success or the exact failed prerequisite boundary."""

    DISCHARGED = "image_bound_all_native_relations_discharged"
    PREREQUISITE = "image_bound_native_prerequisite_refused"
    TRANSITION = "image_bound_native_transition_unproved"
    MODEL = "image_bound_native_proof_model_changed"
    DEADLINE = "image_bound_native_original_deadline_exhausted"


class ImageBoundNativeObligation(StrEnum):
    """Native transitions and both temporal receipt checks remain separate."""

    BEFORE = "current_prerequisite_before_native_proof"
    TRANSITION = "complete_initialized_native_transition"
    AFTER = "current_prerequisite_after_native_proof"
    MODEL = "stable_native_relation_proof_model"


@dataclass(frozen=True, slots=True)
class ImageBoundNativeFact:
    """One attempted full relation or prerequisite with its stable native key."""

    obligation: ImageBoundNativeObligation
    key: str
    status: ProofStatus


@dataclass(frozen=True, slots=True)
class ImageBoundNativeProof:
    """Exact local native relation results without recursive proof promotion."""

    status: ProofStatus
    reason: ImageBoundNativeReason
    model_hash: str
    required: tuple[tuple[ImageBoundNativeObligation, str], ...]
    facts: tuple[ImageBoundNativeFact, ...]
    counters: FactCounters
    consumers: tuple[BoundDomainConsumption, ...]
    transitions: tuple[LoadedTransitionResult, ...]
    remaining: tuple[JointModelRequirement, ...] = tuple(JointModelRequirement)
    detail: str = ""

    @property
    def binary_equivalence_proved(self) -> bool:
        """Frame/dispatch/progress and physical outcome composition remain open."""
        return False


def image_bound_native_model_hash() -> str:
    """Seal the complete decoder/domain/consumer and native relation wrapper."""
    digest = hashlib.sha256(Path(__file__).read_bytes())
    digest.update(image_bound_domain_model_hash().encode("ascii"))
    return digest.hexdigest()


@dataclass(slots=True)
class _NativeProofRun:
    """One shared deadline with a fixed manifest and retained partial children."""

    receipt: ImageBoundReal16Domain
    system: JointSystem
    loads: tuple[BoundReal16Load, BoundReal16Load]
    initialized: LoadedRelationProof
    bootstrap: tuple[MachineState, MachineState]
    requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]]
    limits: LoadedRelationLimits
    required: tuple[tuple[ImageBoundNativeObligation, str], ...]
    model_hash: str = ""
    facts: list[ImageBoundNativeFact] = field(default_factory=list)
    consumers: list[BoundDomainConsumption] = field(default_factory=list)
    transitions: list[LoadedTransitionResult] = field(default_factory=list)

    def remaining_ms(self) -> int:
        """Charge receipt checks, all solver work and hashing to one deadline."""
        self.limits.check_time()
        remaining = int((self.limits.deadline - time.monotonic()) * 1000)
        if remaining <= 0:
            raise LoadedRelationRefusal(LoadedRelationReason.DEADLINE, "native relation original deadline exhausted")
        return remaining

    def consume(self, key: ImageBoundNativeObligation) -> bool:
        """Revalidate saved evidence at both boundaries, retaining its refusal."""
        child = consume_image_bound_real16_domain(self.receipt, self.system, self.loads,
            self.initialized, self.bootstrap, self.requests, timeout_ms=self.remaining_ms(), limits=self.limits)
        self.consumers.append(child)
        self.facts.append(ImageBoundNativeFact(key, key.value, child.status))
        return child.status is ProofStatus.PROVED

    def report(self, reason: ImageBoundNativeReason, detail: str = "") -> ImageBoundNativeProof:
        """Account every required transition even when an earlier check refuses."""
        ids = [(fact.obligation, fact.key) for fact in self.facts]
        failed = sum(fact.status is not ProofStatus.PROVED for fact in self.facts)
        failed += len(set(self.required) - set(ids)) + len(set(ids) - set(self.required)) + len(ids) - len(set(ids))
        count = len(self.required)
        proved = failed == 0 and reason is ImageBoundNativeReason.DISCHARGED
        return ImageBoundNativeProof(ProofStatus.PROVED if proved else ProofStatus.UNKNOWN, reason,
            self.model_hash, self.required, tuple(self.facts), FactCounters(count, count, count, len(self.facts), failed),
            tuple(self.consumers), tuple(self.transitions), detail=detail)


def _prove(run: _NativeProofRun) -> ImageBoundNativeProof:
    """Check independently linked startup and every native cutpoint without assumptions."""
    if not run.consume(ImageBoundNativeObligation.BEFORE):
        consumption = run.consumers[-1]
        reason = ImageBoundNativeReason.DEADLINE if consumption.reason is BoundDomainReason.DEADLINE else ImageBoundNativeReason.PREREQUISITE
        return run.report(reason, consumption.detail)
    run.model_hash = image_bound_native_model_hash()
    effects = (("bootstrap", *run.bootstrap), *tuple((step.node.key(), step.original, step.candidate)
                                                    for step in run.system.steps))
    for key, a, b in effects:
        child = check_loaded_native_transition(a, b, run.initialized, timeout_ms=run.remaining_ms(),
                                               limits=run.limits, domain=run.receipt.domain)
        run.transitions.append(child)
        run.facts.append(ImageBoundNativeFact(ImageBoundNativeObligation.TRANSITION, key, child.status))
        if child.status is not ProofStatus.PROVED:
            reason = ImageBoundNativeReason.DEADLINE if child.reason is LoadedTransitionReason.DEADLINE else ImageBoundNativeReason.TRANSITION
            return run.report(reason, f"{key}: {child.reason.value}: {child.detail}")
    if not run.consume(ImageBoundNativeObligation.AFTER):
        consumption = run.consumers[-1]
        reason = ImageBoundNativeReason.DEADLINE if consumption.reason is BoundDomainReason.DEADLINE else ImageBoundNativeReason.PREREQUISITE
        return run.report(reason, consumption.detail)
    stable = run.model_hash == image_bound_native_model_hash()
    run.remaining_ms()
    key = ImageBoundNativeObligation.MODEL
    run.facts.append(ImageBoundNativeFact(key, key.value, ProofStatus.PROVED if stable else ProofStatus.UNKNOWN))
    return run.report(ImageBoundNativeReason.DISCHARGED if stable else ImageBoundNativeReason.MODEL)


def prove_image_bound_real16_native_relations(
    receipt: ImageBoundReal16Domain, system: JointSystem, loads: tuple[BoundReal16Load, BoundReal16Load],
    initialized: LoadedRelationProof, bootstrap: tuple[MachineState, MachineState],
    requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]],
    *, timeout_ms: int = 60000, limits: LoadedRelationLimits | None = None,
) -> ImageBoundNativeProof:
    """Consume verified image effects and prove all local full-state transitions.

    This closes the connection from immutable images to initialized memory and
    scalar premises. It supplies local results for joint induction; it cannot
    establish recursive frame initiation or replace any physical/fault/service
    obligation. Missing children stay in a complete immutable required manifest.
    """
    if type(timeout_ms) is not int or timeout_ms < 0:
        raise ValueError("native relation proof requires a nonnegative millisecond budget")
    if not 0 < len(system.steps) <= 4096:
        raise ValueError("native relation proposal requires one through4096 admitted transitions")
    selected = limits if limits is not None else LoadedRelationLimits()
    deadline = time.monotonic() + timeout_ms / 1000
    if selected.deadline >= 0:
        deadline = min(deadline, selected.deadline)
    before, transition, after, model = ImageBoundNativeObligation
    required = ((before, before.value), (transition, "bootstrap"),
                *tuple((transition, step.node.key()) for step in system.steps),
                (after, after.value), (model, model.value))
    run = _NativeProofRun(receipt, system, loads, initialized, bootstrap, requests,
                          replace(selected, deadline=deadline), required)
    try:
        return _prove(run)
    except LoadedRelationRefusal as refusal:
        key = next((key for key in required if key not in {(fact.obligation, fact.key) for fact in run.facts}), required[-1])
        run.facts.append(ImageBoundNativeFact(*key, ProofStatus.UNKNOWN))
        return run.report(ImageBoundNativeReason.DEADLINE, refusal.detail)
