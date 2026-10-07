"""Layer: dosunit image-bound recursive entry prerequisites (staging).

Responsibility: connect complete joint proposals, immutable binary effects and
loader/bootstrap-derived scalar invariants within one deadline. Discharged
prerequisites do not close recursive caller frames, fault domains or services.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path

from tools.dosunit.compare.real16_call_contracts import initial_state
from tools.dosunit.contracts.model import canonical_json_bytes
from tools.dosunit.contracts.proof_contracts import Architecture, FactCounters, ProofStatus
from tools.dosunit.contracts.register_state_relations import MachineState
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import BoundReal16Load
from tools.dosunit.recursive_proofs.loaded_byte_native_transition import (
    _check_states,
    _consume_initialized,
    _TransitionRefusal,
    _TransitionRun,
)
from tools.dosunit.recursive_proofs.loaded_byte_relation import (
    LoadedRelationLimits,
    LoadedRelationReason,
    LoadedRelationRefusal,
)
from tools.dosunit.recursive_proofs.loaded_byte_relation_proof import LoadedRelationProof
from tools.dosunit.recursive_proofs.real16_entry_domain import (
    Real16DomainProof,
    entry_domain_model_hash,
    native_effect_hash,
)
from tools.dosunit.recursive_proofs.real16_entry_domain_proof import prove_real16_entry_domain
from tools.dosunit.recursive_proofs.real16_native_effect_binding import (
    NativeBlockKind,
    NativeBlockRequest,
    Real16NativeBinding,
    bind_real16_native_effects,
    native_binding_model_hash,
)
from tools.dosunit.recursive_proofs.recursive_joint_admission import JointRefusal, derive_joint_frame_layout
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointReason, JointStepKind, JointSystem
from tools.dosunit.recursive_proofs.recursive_joint_identity import joint_proposal_hash


class BoundDomainReason(StrEnum):
    """The exact image/effect/domain connection discharged or still unproved."""

    DISCHARGED = "image_bound_entry_prerequisites_discharged"
    JOINT = "image_bound_joint_proposal_incomplete"
    IMAGE = "image_bound_executable_or_initialization_mismatch"
    SOURCE = "image_bound_independent_effect_binding_unproved"
    LINK = "image_bound_native_effect_linkage_missing"
    DOMAIN = "image_bound_entry_scalar_domain_unproved"
    MODEL = "image_bound_prerequisite_model_changed"
    DEADLINE = "image_bound_original_deadline_exhausted"
    RESOURCE = "image_bound_native_state_budget_exceeded"
    STATE = "image_bound_native_state_or_initialization_refused"
    CONTENT = "image_bound_joint_content_changed"


class BoundDomainObligation(StrEnum):
    """Every required prerequisite remains in the ledger on early refusals."""

    JOINT = "complete_joint_structure_and_frame_layout"
    ORIGINAL_SOURCE = "original_independent_source_binding"
    CANDIDATE_SOURCE = "candidate_independent_source_binding"
    ORIGINAL_LINK = "original_bootstrap_and_all_joint_effects_linked"
    CANDIDATE_LINK = "candidate_bootstrap_and_all_joint_effects_linked"
    DOMAIN = "loader_bootstrap_scalar_domain"
    MODEL = "stable_combined_prerequisite_model"


@dataclass(frozen=True, slots=True)
class BoundDomainFact:
    """One attempted prerequisite, including retained non-results."""

    obligation: BoundDomainObligation
    status: ProofStatus
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ImageBoundReal16Domain:
    """Connected source/domain evidence, never complete binary equivalence."""

    status: ProofStatus
    reason: BoundDomainReason
    system: JointSystem
    model_hash: str
    sources: tuple[Real16NativeBinding, ...]
    domain: Real16DomainProof | None
    facts: tuple[BoundDomainFact, ...]
    counters: FactCounters
    detail: str = ""
    proposal_hash: str = ""

    @property
    def binary_equivalence_proved(self) -> bool:
        """Recursive frame/control/progress/fault/environment closure is separate."""
        return False


def image_bound_domain_model_hash() -> str:
    """Bind the shared wrapper, current source lifter and scalar theorem owners."""
    paths = (Path(__file__), Path(__file__).with_name("recursive_joint_identity.py"),
             Path(__file__).with_name("recursive_joint_admission.py"),
             Path(__file__).with_name("real16_image_bound_domain_consumer.py"))
    values = [*(hashlib.sha256(path.read_bytes()).hexdigest() for path in paths),
              native_binding_model_hash(), entry_domain_model_hash()]
    return hashlib.sha256(canonical_json_bytes(values)).hexdigest()


@dataclass(slots=True)
class _BoundRun:
    """One deadline, retained nested evidence and a fixed seven-fact ledger."""

    system: JointSystem
    loads: tuple[BoundReal16Load, BoundReal16Load]
    initialized: LoadedRelationProof
    bootstrap: tuple[MachineState, MachineState]
    requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]]
    limits: LoadedRelationLimits
    model_hash: str = ""
    proposal_hash: str = ""
    sources: list[Real16NativeBinding] = field(default_factory=list)
    domain: Real16DomainProof | None = None
    facts: list[BoundDomainFact] = field(default_factory=list)
    current: BoundDomainObligation = BoundDomainObligation.JOINT

    def remaining_ms(self) -> int:
        """Charge loading, source equality and scalar checks to the same deadline."""
        self.limits.check_time()
        remaining = int((self.limits.deadline - time.monotonic()) * 1000)
        if remaining <= 0:
            raise LoadedRelationRefusal(LoadedRelationReason.DEADLINE, "combined native/domain deadline exhausted")
        return remaining

    def report(self, reason: BoundDomainReason, detail: str = "") -> ImageBoundReal16Domain:
        """Every missing, repeated or unproved prerequisite remains a failure."""
        required = set(BoundDomainObligation)
        ids = [fact.obligation for fact in self.facts]
        failed = sum(fact.status is not ProofStatus.PROVED for fact in self.facts)
        failed += len(required - set(ids)) + len(set(ids) - required) + len(ids) - len(set(ids))
        complete = failed == 0 and len(self.sources) == 2 and self.domain is not None
        proved = complete and reason is BoundDomainReason.DISCHARGED
        count = len(required)
        return ImageBoundReal16Domain(ProofStatus.PROVED if proved else ProofStatus.UNKNOWN, reason,
            self.system, self.model_hash, tuple(self.sources), self.domain, tuple(self.facts),
            FactCounters(count, count, count, len(self.facts), failed), detail, self.proposal_hash)


def _admit(run: _BoundRun) -> int:
    """Require full state/initialization before hashing any recursive effect."""
    run.remaining_ms()
    guard = _TransitionRun(run.initialized, run.limits, 262144, 128)
    if _consume_initialized(guard) is not Architecture.REAL16:
        raise JointRefusal(JointReason.OUTPUTS, "combined domain requires real16 initialized memory")
    if run.system.initial_state is not None:
        _check_states(initial_state(), run.system.initial_state, run.system.initial_state)
        guard.guard(run.system.initial_state)
    for pair in (*tuple((step.original, step.candidate) for step in run.system.steps), run.bootstrap):
        _check_states(initial_state(), *pair)
        for state in pair:
            guard.guard(state)
    derive_joint_frame_layout(run.system)
    roots = [step for step in run.system.steps if step.node == run.system.root]
    if len(roots) != 1:
        raise ValueError("admitted joint system must retain exactly one root")
    address = roots[0].original_address
    if not isinstance(address, int) or isinstance(address, bool):
        raise JointRefusal(JointReason.LAYOUT, "joint root requires a typed physical coordinate")
    return address


def _linked(run: _BoundRun, side: int) -> bool:
    """Require exact source coordinates/hashes for startup and every joint node."""
    actual = {(row.address, row.effect_hash) for row in run.requests[side]}
    entry = (run.loads[side].binding.entry, native_effect_hash(run.bootstrap[side]))
    expected = {(step.original_address, native_effect_hash(step.original)) if side == 0
                else (step.candidate_address, native_effect_hash(step.candidate)) for step in run.system.steps}
    expected.add(entry)
    if len(actual) != len(run.requests[side]) or actual != expected:
        return False
    kinds = {JointStepKind.BRANCH: NativeBlockKind.BRANCH, JointStepKind.CALL: NativeBlockKind.CALL,
             JointStepKind.RETURN: NativeBlockKind.RETURN}
    bound = {block.address: block.kind for block in run.sources[side].blocks}
    return all(step.kind in kinds and bound.get(step.original_address if side == 0 else step.candidate_address) is kinds[step.kind]
               for step in run.system.steps)


def _prove(run: _BoundRun) -> ImageBoundReal16Domain:
    """Connect independently checked sources before consuming scalar initiation."""
    root = _admit(run)
    run.proposal_hash = joint_proposal_hash(run.system, run.bootstrap)
    a, b = run.loads
    if (run.system.contract.original_hash != a.binding.file_sha256
            or run.system.contract.candidate_hash != b.binding.file_sha256):
        run.facts.append(BoundDomainFact(run.current, ProofStatus.UNKNOWN, "joint executable identity differs"))
        return run.report(BoundDomainReason.IMAGE)
    run.facts.append(BoundDomainFact(run.current, ProofStatus.PROVED))
    run.model_hash = image_bound_domain_model_hash()
    source_keys = (BoundDomainObligation.ORIGINAL_SOURCE, BoundDomainObligation.CANDIDATE_SOURCE)
    link_keys = (BoundDomainObligation.ORIGINAL_LINK, BoundDomainObligation.CANDIDATE_LINK)
    for side in range(2):
        run.current = source_keys[side]
        source = bind_real16_native_effects(run.loads[side], run.requests[side],
                                            timeout_ms=run.remaining_ms(), limits=run.limits)
        run.sources.append(source)
        run.facts.append(BoundDomainFact(run.current, source.status, source.detail))
        if source.status is not ProofStatus.PROVED:
            return run.report(BoundDomainReason.SOURCE, source.reason.value)
        run.current = link_keys[side]
        linked = _linked(run, side)
        run.facts.append(BoundDomainFact(run.current, ProofStatus.PROVED if linked else ProofStatus.UNKNOWN))
        if not linked:
            return run.report(BoundDomainReason.LINK)
    run.current = BoundDomainObligation.DOMAIN
    effects = (*tuple((step.original, step.candidate) for step in run.system.steps), run.bootstrap)
    run.domain = prove_real16_entry_domain(run.loads, run.initialized, run.bootstrap, effects, root,
                                          timeout_ms=run.remaining_ms(), limits=run.limits)
    run.facts.append(BoundDomainFact(run.current, run.domain.status, run.domain.detail))
    if run.domain.status is not ProofStatus.PROVED:
        return run.report(BoundDomainReason.DOMAIN, run.domain.reason.value)
    run.current = BoundDomainObligation.MODEL
    stable = image_bound_domain_model_hash() == run.model_hash
    unchanged = joint_proposal_hash(run.system, run.bootstrap) == run.proposal_hash
    run.remaining_ms()
    run.facts.append(BoundDomainFact(run.current, ProofStatus.PROVED if stable and unchanged else ProofStatus.UNKNOWN))
    reason = BoundDomainReason.DISCHARGED if stable and unchanged else BoundDomainReason.MODEL
    if not unchanged:
        reason = BoundDomainReason.CONTENT
    return run.report(reason)


def prove_image_bound_real16_domain(system: JointSystem, loads: tuple[BoundReal16Load, BoundReal16Load],
                                    initialized: LoadedRelationProof, bootstrap: tuple[MachineState, MachineState],
                                    requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]],
                                    *, timeout_ms: int = 30000,
                                    limits: LoadedRelationLimits | None = None) -> ImageBoundReal16Domain:
    """Prove connected binary effects and entry invariants within one total budget.

    This refuses unsupported/missing source or scalar evidence. It retains all
    nested facts and does not discharge the remaining recursive physical,
    frame, progress or service obligations by assuming them true.
    """
    if type(timeout_ms) is not int or timeout_ms < 0:
        raise ValueError("image-bound domain requires a nonnegative millisecond budget")
    selected = limits if limits is not None else LoadedRelationLimits()
    deadline = time.monotonic() + timeout_ms / 1000
    if selected.deadline >= 0:
        deadline = min(deadline, selected.deadline)
    run = _BoundRun(system, loads, initialized, bootstrap, requests, replace(selected, deadline=deadline))
    try:
        return _prove(run)
    except JointRefusal as refusal:
        reason, detail = BoundDomainReason.JOINT, refusal.detail
    except _TransitionRefusal as refusal:
        reason, detail = BoundDomainReason.STATE, f"{refusal.reason.value}: {refusal.detail}"
    except LoadedRelationRefusal as refusal:
        reason = BoundDomainReason.DEADLINE if refusal.reason is LoadedRelationReason.DEADLINE else BoundDomainReason.IMAGE
        detail = refusal.detail
    run.facts.append(BoundDomainFact(run.current, ProofStatus.UNKNOWN, detail))
    return run.report(reason, detail)
