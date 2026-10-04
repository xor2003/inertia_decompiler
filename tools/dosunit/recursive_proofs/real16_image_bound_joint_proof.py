"""Layer: dosunit image-bound matched recursive induction (staging).

Responsibility: compose actual caller-frame initiation, every initialized full
native transition and both sides' finite frame preservation into acyclic
obligations. Original operand coordinates, segment scope, physical data-byte
bounds and the per-transition outcome closure are mandatory children. Complete
atomic dispatch gives lockstep progress without assuming recursive summaries.
Fault scope closes only from proved synchronous evidence; environment scope
closes only under the caller-declared typed premise; both stay explicit when
absent and prevent whole-binary promotion.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field, replace
from pathlib import Path

from tools.dosunit.proof_contracts import (
    ContractIdentity,
    FactCounters,
    Obligation,
    ObligationEvidence,
    ObligationId,
    ObligationReport,
    ProofStatus,
    evaluate_obligations,
)
from tools.dosunit.recursive_proofs import recursive_joint_admission as _admission_owner
from tools.dosunit.recursive_proofs import recursive_joint_contracts as _contracts_owner
from tools.dosunit.recursive_proofs import recursive_static_control as _static_control_owner
from tools.dosunit.recursive_proofs import stack as _stack_owners
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import BoundReal16Load
from tools.dosunit.recursive_proofs.loaded_byte_relation import LoadedRelationLimits, LoadedRelationRefusal
from tools.dosunit.recursive_proofs.loaded_byte_relation_proof import LoadedRelationProof
from tools.dosunit.recursive_proofs.native_model_hash_snapshot import native_model_hash_snapshot
from tools.dosunit.recursive_proofs.real16_address_model_closure import (
    AddressModelClosure,
    AddressModelReason,
    _check_address_model_closure,
    address_model_model_hash,
)
from tools.dosunit.recursive_proofs.real16_bound_control_scope import (
    BoundControlReason,
    BoundReal16ControlScope,
    bound_control_model_hash,
    prove_bound_real16_control_scope,
)
from tools.dosunit.recursive_proofs.real16_bound_operand_scope import (
    BoundOperandReason,
    BoundReal16OperandScope,
    bound_operand_model_hash,
    prove_bound_real16_operand_scope,
)
from tools.dosunit.recursive_proofs.real16_code_prefix_proof import (
    CodePrefixReason,
    Real16CodePrefixProof,
    code_prefix_model_hash,
    prove_real16_code_prefixes,
)
from tools.dosunit.recursive_proofs.real16_domain_dispatch import (
    DomainDispatchReason,
    Real16DomainDispatchProof,
    domain_dispatch_model_hash,
    prove_real16_domain_dispatch,
)
from tools.dosunit.recursive_proofs.real16_entry_frame import (
    EntryFrameReason,
    Real16EntryFrameProof,
    entry_frame_model_hash,
    prove_real16_entry_frame,
)
from tools.dosunit.recursive_proofs.real16_fetched_code_invariant import (
    FetchedCodeReason,
    Real16FetchedCodeInvariant,
    check_fetched_code_invariant,
    fetched_code_model_hash,
)
from tools.dosunit.recursive_proofs.real16_image_bound_domain import BoundDomainReason, ImageBoundReal16Domain
from tools.dosunit.recursive_proofs.real16_image_bound_domain_consumer import (
    BoundDomainConsumption,
    consume_image_bound_real16_domain,
)
from tools.dosunit.recursive_proofs.real16_image_bound_native_proof import (
    ImageBoundNativeProof,
    ImageBoundNativeReason,
    image_bound_native_model_hash,
    prove_image_bound_real16_native_relations,
)
from tools.dosunit.recursive_proofs.real16_native_effect_binding import NativeBlockRequest
from tools.dosunit.recursive_proofs.real16_normal_outcome_scope import (
    OutcomeScopeReason,
    Real16NormalOutcomeScope,
    outcome_scope_model_hash,
    prove_real16_normal_outcome_scope,
)
from tools.dosunit.recursive_proofs.real16_physical_access_bounds import (
    PhysicalAccessReason,
    Real16PhysicalAccessBounds,
    physical_access_model_hash,
    prove_real16_physical_access_bounds,
)
from tools.dosunit.recursive_proofs.recursive_call_continuation import (
    CallSide,
    consume_call_frame,
    request_call_continuation,
)
from tools.dosunit.recursive_proofs.recursive_joint_admission import JointRefusal, derive_joint_frame_layout
from tools.dosunit.recursive_proofs.recursive_joint_contracts import (
    JointModelRequirement,
    JointReason,
    JointStepKind,
    JointSystem,
)
from tools.dosunit.recursive_proofs.stack.recursive_stack_proofs import (
    StackInvariantProof,
    StackObligation,
    prove_stack_step,
)
from tools.dosunit.register_state_relations import MachineState


@dataclass(frozen=True, slots=True)
class ImageBoundReal16JointProof:
    """A composed matched-component theorem with explicit unclosed model scope."""

    status: ProofStatus
    reason: JointReason
    proof: ObligationReport
    proposal_hash: str
    model_hash: str
    consumers: tuple[BoundDomainConsumption, ...]
    entry: Real16EntryFrameProof | None
    native: ImageBoundNativeProof | None
    prefixes: Real16CodePrefixProof | None
    operands: BoundReal16OperandScope | None
    addresses: Real16PhysicalAccessBounds | None
    frames: tuple[StackInvariantProof, ...]
    remaining: tuple[JointModelRequirement, ...]
    detail: str = ""
    code_memory: Real16FetchedCodeInvariant | None = None
    controls: BoundReal16ControlScope | None = None
    dispatch: Real16DomainDispatchProof | None = None
    address_model: AddressModelClosure | None = None
    outcomes: Real16NormalOutcomeScope | None = None

    @property
    def binary_equivalence_proved(self) -> bool:
        """Reachability, final observers and matched regions stay unclosed."""
        return False


def image_bound_joint_model_hash() -> str:
    """Seal every actual frame refinement owner and both connected producers."""
    with native_model_hash_snapshot():
        return _joint_model_hash()


def _joint_model_hash() -> str:
    """Read the dependency graph inside one fresh native-fingerprint capture."""
    owners = (_admission_owner, _contracts_owner, _static_control_owner)
    paths = [Path(__file__), *(Path(str(owner.__file__)) for owner in owners)]
    stack_dir = Path(str(next(iter(_stack_owners.__path__))))
    paths.extend(sorted(stack_dir.glob("recursive_stack_*.py")))
    digest = hashlib.sha256(entry_frame_model_hash().encode("ascii"))
    digest.update(image_bound_native_model_hash().encode("ascii"))
    digest.update(code_prefix_model_hash().encode("ascii"))
    digest.update(fetched_code_model_hash().encode("ascii"))
    digest.update(bound_operand_model_hash().encode("ascii"))
    digest.update(physical_access_model_hash().encode("ascii"))
    digest.update(bound_control_model_hash().encode("ascii"))
    digest.update(domain_dispatch_model_hash().encode("ascii"))
    digest.update(address_model_model_hash().encode("ascii"))
    digest.update(outcome_scope_model_hash().encode("ascii"))
    for path in paths:
        digest.update(path.name.encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _id(key: str) -> ObligationId:
    """Use labels only for obligation accounting, never semantic correspondence."""
    return ObligationId("image_bound_recursive", key)


def _requirements(system: JointSystem) -> tuple[Obligation, ...]:
    """Freeze the entire required denominator before any proof can refuse."""
    keys = ["before", "all_native_code_prefixes", "all_loaded_code_invariants", "all_native_operand_scope",
            "all_native_physical_access_bounds", "all_native_control_coordinates", "actual_entry_frame", "all_native_transitions"]
    keys.extend(f"frame:{side}:{step.node.key()}" for step in system.steps for side in ("original", "candidate"))
    keys.extend(("complete_domain_scoped_dispatch", "complete_address_model", "complete_normal_outcome_scope",
                 "complete_dispatch_and_atomic_lockstep_progress", "after", "model", "physical_scope"))
    required = tuple(Obligation(_id(key)) for key in keys)
    return (*required, Obligation(_id("component"), tuple(item.id for item in required)))


@dataclass(slots=True)
class _JointRun:
    """One deadline and closed required graph, retaining all native child evidence."""

    receipt: ImageBoundReal16Domain
    system: JointSystem
    loads: tuple[BoundReal16Load, BoundReal16Load]
    initialized: LoadedRelationProof
    bootstrap: tuple[MachineState, MachineState]
    requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]]
    limits: LoadedRelationLimits
    required: tuple[Obligation, ...]
    contract: ContractIdentity
    model_hash: str
    current: str = "before"
    evidence: list[ObligationEvidence] = field(default_factory=list)
    consumers: list[BoundDomainConsumption] = field(default_factory=list)
    entry: Real16EntryFrameProof | None = None
    native: ImageBoundNativeProof | None = None
    prefixes: Real16CodePrefixProof | None = None
    operands: BoundReal16OperandScope | None = None
    addresses: Real16PhysicalAccessBounds | None = None
    frames: list[StackInvariantProof] = field(default_factory=list)
    code_memory: Real16FetchedCodeInvariant | None = None
    controls: BoundReal16ControlScope | None = None
    dispatch: Real16DomainDispatchProof | None = None
    address_model: AddressModelClosure | None = None
    outcomes: Real16NormalOutcomeScope | None = None

    def remaining_requirements(self) -> tuple[JointModelRequirement, ...]:
        """Derive local model gaps once for report and conditional assumptions."""
        closed = {JointModelRequirement.CALLER_ENTRY}
        if self.code_memory is not None and self.code_memory.complete:
            closed.add(JointModelRequirement.CODE_MEMORY)
        if self.address_model is not None and self.address_model.complete:
            closed.add(JointModelRequirement.ADDRESS_MODEL)
        if self.outcomes is not None and self.outcomes.synchronous_closed:
            closed.add(JointModelRequirement.FAULT_DOMAIN)
        if self.outcomes is not None and self.outcomes.complete:
            closed.add(JointModelRequirement.ENVIRONMENT)
        return tuple(item for item in JointModelRequirement if item not in closed)

    def remaining_ms(self) -> int:
        """Never replenish time during source, entry, native or frame queries."""
        self.limits.check_time()
        return max(0, int((self.limits.deadline - time.monotonic()) * 1000))

    def fact(self, key: str, status: ProofStatus, *, counters: FactCounters | None = None,
             assumptions: tuple[str, ...] = (), dependencies: tuple[ObligationId, ...] = ()) -> None:
        """Retain the exact content/model contract and every child's work counters."""
        counts = counters if counters is not None else FactCounters(1, 1, 1, 1, int(status is not ProofStatus.PROVED and not assumptions))
        self.evidence.append(ObligationEvidence(_id(key), self.contract, status, method="byte_bound_atomic_joint_induction",
            counters=counts, assumptions=assumptions, dependencies=dependencies))

    def consume(self, key: str) -> bool:
        """Require current source/domain evidence at both induction boundaries."""
        self.current = key
        child = consume_image_bound_real16_domain(self.receipt, self.system, self.loads, self.initialized,
            self.bootstrap, self.requests, timeout_ms=self.remaining_ms(), limits=self.limits)
        self.consumers.append(child)
        self.fact(key, child.status, counters=child.counters)
        return child.status is ProofStatus.PROVED

    def report(self, reason: JointReason, detail: str = "") -> ImageBoundReal16JointProof:
        """Only the complete composed theorem can close established model gaps."""
        proof = evaluate_obligations(self.contract, self.required, self.evidence)
        discharged = reason is JointReason.DISCHARGED and proof.status is ProofStatus.PROVED
        conditional = reason is JointReason.CONDITIONAL_MODEL and proof.status is ProofStatus.CONDITIONAL
        remaining = self.remaining_requirements() if discharged or conditional else tuple(JointModelRequirement)
        status = (ProofStatus.PROVED if discharged else
                  ProofStatus.CONDITIONAL if conditional else ProofStatus.UNKNOWN)
        return ImageBoundReal16JointProof(status, reason, proof, self.receipt.proposal_hash,
            self.model_hash, tuple(self.consumers), self.entry, self.native, self.prefixes,
            self.operands, self.addresses, tuple(self.frames), remaining, detail,
            self.code_memory, self.controls, self.dispatch, self.address_model, self.outcomes)


def _code_prerequisite(run: _JointRun) -> ImageBoundReal16JointProof | None:
    """Require absolute loader initiation and every code-preservation witness."""
    if run.prefixes is None:
        raise ValueError("loaded-code composition requires a prefix producer result")
    run.current = "all_loaded_code_invariants"
    child = check_fetched_code_invariant(run.prefixes, run.system, run.loads, run.initialized,
        run.bootstrap, run.requests, timeout_ms=run.remaining_ms(), limits=run.limits)
    run.code_memory = child
    run.fact(run.current, ProofStatus.PROVED if child.complete else ProofStatus.UNKNOWN, counters=child.counters)
    if not child.complete:
        reason = JointReason.DEADLINE if child.reason is FetchedCodeReason.DEADLINE else JointReason.UNKNOWN
        return run.report(reason, f"{child.reason.value}: {child.detail}")
    return None


def _address_prerequisites(run: _JointRun) -> ImageBoundReal16JointProof | None:
    """Require both independent data-address children before recursive induction."""
    run.current = "all_native_operand_scope"
    run.operands = prove_bound_real16_operand_scope(run.receipt, run.system, run.loads, run.initialized,
        run.bootstrap, run.requests, timeout_ms=run.remaining_ms(), limits=run.limits)
    run.fact(run.current, run.operands.status, counters=run.operands.counters)
    if run.operands.status is not ProofStatus.PROVED or run.operands.counters.failure_count:
        reason = JointReason.DEADLINE if run.operands.reason is BoundOperandReason.DEADLINE else JointReason.UNKNOWN
        return run.report(reason, f"{run.operands.reason.value}: {run.operands.detail}")
    run.current = "all_native_physical_access_bounds"
    run.addresses = prove_real16_physical_access_bounds(run.receipt, run.system, run.loads, run.initialized,
        run.bootstrap, run.requests, timeout_ms=run.remaining_ms(), limits=run.limits)
    run.fact(run.current, run.addresses.status, counters=run.addresses.counters)
    if run.addresses.status is not ProofStatus.PROVED or run.addresses.counters.failure_count:
        reason = JointReason.DEADLINE if run.addresses.reason is PhysicalAccessReason.DEADLINE else JointReason.UNKNOWN
        return run.report(reason, f"{run.addresses.reason.value}: {run.addresses.detail}")
    return None


def _control_prerequisite(run: _JointRun) -> ImageBoundReal16JointProof | None:
    """Require architectural target correspondence before consuming dispatch."""
    if run.prefixes is None:
        raise ValueError("native control composition requires complete source prefixes")
    run.current = "all_native_control_coordinates"
    child = prove_bound_real16_control_scope(run.prefixes, run.system, run.loads, run.initialized,
        run.bootstrap, run.requests, limits=run.limits)
    run.controls = child
    run.fact(run.current, ProofStatus.PROVED if child.complete else ProofStatus.UNKNOWN, counters=child.counters)
    if not child.complete:
        reason = JointReason.DEADLINE if child.reason is BoundControlReason.DEADLINE else JointReason.UNKNOWN
        return run.report(reason, f"{child.reason.value}: {child.detail}")
    return None


def _frames(run: _JointRun) -> ImageBoundReal16JointProof | None:
    """Discharge every native frame effect under the actually established invariant."""
    layout = derive_joint_frame_layout(run.system)
    kinds = {JointStepKind.BRANCH: StackObligation.BODY, JointStepKind.CALL: StackObligation.PUSH,
             JointStepKind.RETURN: StackObligation.POP}
    for step in run.system.steps:
        for side, state in ((CallSide.ORIGINAL, step.original), (CallSide.CANDIDATE, step.candidate)):
            run.current = f"frame:{side.value}:{step.node.key()}"
            request = request_call_continuation(run.system, step, side)
            child = prove_stack_step(state, layout, kinds[step.kind], timeout_ms=run.remaining_ms(), deadline=run.limits.deadline,
                                     expected_continuation=request.address if request is not None else None)
            run.frames.append(child)
            consumed = consume_call_frame(child, layout, request)
            run.fact(run.current, consumed.status, counters=consumed.counters)
            if consumed.status is not ProofStatus.PROVED:
                return run.report(consumed.reason, f"{run.current}: {child.reason.value}: {child.detail}")
    return None


def _induction_prerequisites(run: _JointRun) -> ImageBoundReal16JointProof | None:
    """Require retained continuation frames and exact source-bound dispatch."""
    failed = _frames(run)
    if failed is not None:
        return failed
    run.current = "complete_domain_scoped_dispatch"
    run.dispatch = prove_real16_domain_dispatch(run.receipt, run.system, run.loads, run.initialized,
        run.bootstrap, run.requests, timeout_ms=run.remaining_ms(), limits=run.limits)
    run.fact(run.current, run.dispatch.status, counters=run.dispatch.counters)
    if not run.dispatch.complete:
        reason = JointReason.DEADLINE if run.dispatch.reason is DomainDispatchReason.DEADLINE else JointReason.UNKNOWN
        return run.report(reason, f"{run.dispatch.reason.value}: {run.dispatch.detail}")
    return _address_model_prerequisite(run)


def _address_model_prerequisite(run: _JointRun) -> ImageBoundReal16JointProof | None:
    """Consume frame evidence privately from this exact joint invocation."""
    run.current = "complete_address_model"
    if any(child is None for child in (run.prefixes, run.operands, run.addresses,
                                      run.controls, run.dispatch, run.entry)):
        raise ValueError("address closure requires all same-run joint prerequisites")
    assert run.prefixes is not None and run.operands is not None and run.addresses is not None
    assert run.controls is not None and run.dispatch is not None and run.entry is not None
    run.address_model = _check_address_model_closure(
        run.system, run.receipt, run.loads, run.initialized, run.bootstrap,
        run.requests, run.prefixes, run.operands, run.addresses, run.controls,
        tuple(run.frames), run.dispatch, run.entry,
        timeout_ms=run.remaining_ms(), limits=run.limits,
    )
    run.fact(run.current, run.address_model.status, counters=run.address_model.counters)
    if not run.address_model.complete:
        reason = JointReason.DEADLINE if run.address_model.reason is AddressModelReason.DEADLINE else JointReason.UNKNOWN
        return run.report(reason, f"{run.address_model.reason.value}: {run.address_model.detail}")
    return None


def _outcome_scope_prerequisite(run: _JointRun) -> ImageBoundReal16JointProof | None:
    """Require proved synchronous outcome scope; the premise may stay open.

    An absent or unbound declared environment premise keeps ENVIRONMENT open
    as a visible conditional assumption. A bound premise closes it only as
    declared-domain evidence: each exclusion stays an explicit assumption,
    so the row is CONDITIONAL either way and never silently unconditional.
    """
    run.current = "complete_normal_outcome_scope"
    if run.addresses is None:
        raise ValueError("normal-outcome closure requires proved access bounds")
    run.outcomes = prove_real16_normal_outcome_scope(run.receipt, run.system, run.loads,
        run.initialized, run.bootstrap, run.requests, run.addresses,
        timeout_ms=run.remaining_ms(), limits=run.limits)
    status = run.outcomes.status
    assumptions: tuple[str, ...] = ()
    if run.outcomes.synchronous_closed:
        status = ProofStatus.CONDITIONAL
        assumptions = (run.outcomes.declared_scope_assumptions
                       or (JointModelRequirement.ENVIRONMENT.value,))
    run.fact(run.current, status, counters=run.outcomes.counters, assumptions=assumptions)
    if not run.outcomes.synchronous_closed:
        reason = JointReason.DEADLINE if run.outcomes.reason is OutcomeScopeReason.DEADLINE else JointReason.UNKNOWN
        return run.report(reason, f"{run.outcomes.reason.value}: {run.outcomes.detail}")
    return None


def _seal(run: _JointRun) -> ImageBoundReal16JointProof:
    """Revalidate the receipt, seal the model and close only proved scope."""
    if not run.consume("after"):
        child = run.consumers[-1]
        reason = JointReason.DEADLINE if child.reason is BoundDomainReason.DEADLINE else JointReason.ADMISSION
        return run.report(reason, child.detail)
    run.current = "model"
    stable = run.model_hash == image_bound_joint_model_hash()
    run.remaining_ms()
    run.fact(run.current, ProofStatus.PROVED if stable else ProofStatus.UNKNOWN)
    if not stable:
        return run.report(JointReason.UNKNOWN, "joint semantic model changed")
    remaining = tuple(item.value for item in run.remaining_requirements())
    declared = run.outcomes.declared_scope_assumptions if run.outcomes is not None else ()
    assumptions = remaining + declared
    run.fact("physical_scope", ProofStatus.CONDITIONAL if assumptions else ProofStatus.PROVED,
             assumptions=assumptions)
    dependencies = run.required[-1].dependencies
    run.fact("component", ProofStatus.PROVED, dependencies=dependencies)
    return run.report(JointReason.CONDITIONAL_MODEL if assumptions else JointReason.DISCHARGED)


def _prove(run: _JointRun) -> ImageBoundReal16JointProof:
    """Anchor synchronized induction in actual entry bytes instead of an assumed frame."""
    if not run.consume("before"):
        child = run.consumers[-1]
        reason = JointReason.DEADLINE if child.reason is BoundDomainReason.DEADLINE else JointReason.ADMISSION
        return run.report(reason, child.detail)
    run.current = "all_native_code_prefixes"
    run.prefixes = prove_real16_code_prefixes(run.receipt, run.system, run.loads, run.initialized,
        run.bootstrap, run.requests, timeout_ms=run.remaining_ms(), limits=run.limits)
    run.fact(run.current, run.prefixes.status, counters=run.prefixes.counters)
    if run.prefixes.status is not ProofStatus.PROVED or run.prefixes.counters.failure_count:
        reason = JointReason.DEADLINE if run.prefixes.reason is CodePrefixReason.DEADLINE else JointReason.UNKNOWN
        return run.report(reason, f"{run.prefixes.reason.value}: {run.prefixes.detail}")
    for prerequisite in (_code_prerequisite, _address_prerequisites, _control_prerequisite):
        failed = prerequisite(run)
        if failed is not None:
            return failed
    run.current = "actual_entry_frame"
    run.entry = prove_real16_entry_frame(run.receipt, run.system, run.loads, run.initialized,
        run.bootstrap, run.requests, timeout_ms=run.remaining_ms(), limits=run.limits)
    run.fact(run.current, run.entry.status, counters=run.entry.counters)
    if run.entry.status is not ProofStatus.PROVED:
        reason = JointReason.DEADLINE if run.entry.reason is EntryFrameReason.DEADLINE else JointReason.UNKNOWN
        return run.report(reason, f"{run.entry.reason.value}: {run.entry.detail}")
    run.current = "all_native_transitions"
    run.native = prove_image_bound_real16_native_relations(run.receipt, run.system, run.loads, run.initialized,
        run.bootstrap, run.requests, timeout_ms=run.remaining_ms(), limits=run.limits)
    run.fact(run.current, run.native.status, counters=run.native.counters)
    if run.native.status is not ProofStatus.PROVED:
        reason = JointReason.DEADLINE if run.native.reason is ImageBoundNativeReason.DEADLINE else JointReason.UNKNOWN
        return run.report(reason, f"{run.native.reason.value}: {run.native.detail}")
    failed = _induction_prerequisites(run)
    if failed is not None:
        return failed
    failed = _outcome_scope_prerequisite(run)
    if failed is not None:
        return failed
    # Source-bound finite blocks, proved scalar initiation/preservation, exact
    # dispatch and retained per-CALL frame facts carry both sides between
    # cutpoints. No declared graph edge or recursive callee summary is assumed.
    run.fact("complete_dispatch_and_atomic_lockstep_progress", ProofStatus.PROVED)
    return _seal(run)


def check_image_bound_real16_joint(receipt: ImageBoundReal16Domain, system: JointSystem,
                                   loads: tuple[BoundReal16Load, BoundReal16Load], initialized: LoadedRelationProof,
                                   bootstrap: tuple[MachineState, MachineState],
                                   requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]],
                                   *, timeout_ms: int = 120000,
                                   limits: LoadedRelationLimits | None = None) -> ImageBoundReal16JointProof:
    """Compose every matched recursive premise, keeping physical scope conditional."""
    if type(timeout_ms) is not int or timeout_ms < 0 or len(system.steps) > 4095:
        raise ValueError("joint proof requires a finite budget and bounded near-word component")
    selected = limits if limits is not None else LoadedRelationLimits()
    deadline = time.monotonic() + timeout_ms / 1000
    if selected.deadline >= 0:
        deadline = min(deadline, selected.deadline)
    model_hash = image_bound_joint_model_hash()
    contract = replace(system.contract, model_hash=model_hash)
    run = _JointRun(receipt, system, loads, initialized, bootstrap, requests, replace(selected, deadline=deadline),
                   _requirements(system), contract, model_hash)
    try:
        return _prove(run)
    except LoadedRelationRefusal as refusal:
        run.fact(run.current, ProofStatus.UNKNOWN)
        return run.report(JointReason.DEADLINE, refusal.detail)
    except JointRefusal as refusal:
        run.fact(run.current, ProofStatus.UNKNOWN)
        return run.report(refusal.reason, refusal.detail)
