"""Layer: dosunit PE32 image-bound matched recursive induction.

Responsibility: compose immutable file/byte/mapping binding, independent
byte-bound effect admission, the declared entry/stack access domain and the
existing full-state transition/frame theorems into one acyclic obligation
ledger. Caller entry beyond the declared domain, unbounded recursion-depth
physical backing, faults, imports and environment remain named requirements;
a conditional report names its assumptions and never grants whole-binary
equivalence.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path

import z3

from tools.dosunit import (
    binary_environment,
    flat32_call_contracts,
    flat32_call_lowering,
    flat32_pe_loader,
    flat32_replay,
    ssa_provenance,
)
from tools.dosunit import straightline_ssa as S
from tools.dosunit.flat32_call_contracts import CallCompositionRefusal
from tools.dosunit.model import canonical_json_bytes
from tools.dosunit.proof_contracts import (
    Architecture,
    ContractIdentity,
    FactCounters,
    Obligation,
    ObligationEvidence,
    ObligationId,
    ObligationReport,
    ProofStatus,
    evaluate_obligations,
)
from tools.dosunit.recursive_proofs import (
    flat32_image_bound_domain,
    flat32_native_effect_binding,
    flat32_pe_component,
    loaded_byte_image_binding,
    loaded_byte_native_transition,
    loaded_byte_relation,
    loaded_byte_relation_proof,
    real16_entry_domain,
    real16_native_effect_binding,
    recursive_call_continuation,
    recursive_joint_admission,
    recursive_joint_contracts,
    recursive_joint_identity,
    recursive_joint_proof,
    recursive_static_control,
)
from tools.dosunit.recursive_proofs.flat32_image_bound_domain import (
    Flat32AccessDomain,
    Flat32DomainReason,
    ImageBoundFlat32Domain,
    flat32_domain_model_hash,
    prove_image_bound_flat32_domain,
)
from tools.dosunit.recursive_proofs.flat32_native_effect_binding import (
    Flat32BindingReason,
    Flat32NativeBinding,
    Flat32NativeBlockRequest,
    bind_flat32_native_effects,
    flat32_native_binding_model_hash,
)
from tools.dosunit.recursive_proofs.flat32_pe_component import Flat32ProposalRefusal
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import (
    BoundFlat32Load,
    ImageBindingReason,
    ImageBindingRefusal,
)
from tools.dosunit.recursive_proofs.loaded_byte_native_transition import (
    _check_states,
    _consume_initialized,
    _native_initial,
    _TransitionRefusal,
    _TransitionRun,
)
from tools.dosunit.recursive_proofs.loaded_byte_relation import (
    LoadedRelationLimits,
    LoadedRelationReason,
    LoadedRelationRefusal,
)
from tools.dosunit.recursive_proofs.loaded_byte_relation_proof import LoadedRelationProof
from tools.dosunit.recursive_proofs.native_model_hash_snapshot import (
    native_model_snapshot_owner_hash,
)
from tools.dosunit.recursive_proofs.real16_entry_domain import native_effect_hash
from tools.dosunit.recursive_proofs.real16_native_effect_binding import NativeBlockKind
from tools.dosunit.recursive_proofs.recursive_call_continuation import (
    CallSide,
    consume_call_frame,
    request_call_continuation,
)
from tools.dosunit.recursive_proofs.recursive_joint_admission import (
    JointRefusal,
    derive_joint_frame_layout,
)
from tools.dosunit.recursive_proofs.recursive_joint_contracts import (
    JointComponentReport,
    JointReason,
    JointStepKind,
    JointSystem,
)
from tools.dosunit.recursive_proofs.recursive_joint_identity import joint_proposal_hash
from tools.dosunit.recursive_proofs.recursive_joint_proof import check_joint_system
from tools.dosunit.recursive_proofs.stack import recursive_stack_domains as stack_domains
from tools.dosunit.recursive_proofs.stack.recursive_stack_domains import StackWordLayout
from tools.dosunit.recursive_proofs.stack.recursive_stack_proofs import StackInvariantProof
from tools.dosunit.register_state_relations import MachineState


class Flat32ModelRequirement(StrEnum):
    """Unclosed physical/domain obligations; none may silently become a pass."""

    CALLER_ENTRY = "caller_frame_and_entry_domain"
    DEPTH_BACKING = "unbounded_recursive_depth_physical_backing"
    FAULT_DOMAIN = "normal_and_fault_outcomes"
    CODE_MEMORY = "immutable_code_and_physical_alias_domain"
    ADDRESS_MODEL = "physical_address_wrap_and_segment_operand_scope"
    ENVIRONMENT = "external_and_asynchronous_event_scope"


@dataclass(frozen=True, slots=True)
class ImageBoundFlat32JointProof:
    """A composed PE32 matched-component theorem with explicit unclosed scope."""

    status: ProofStatus
    reason: JointReason
    proof: ObligationReport
    proposal_hash: str
    model_hash: str
    domain: ImageBoundFlat32Domain | None
    sources: tuple[Flat32NativeBinding, ...]
    joint: JointComponentReport | None
    frames: tuple[StackInvariantProof, ...]
    remaining: tuple[Flat32ModelRequirement, ...]
    detail: str = ""

    @property
    def binary_equivalence_proved(self) -> bool:
        """Caller, depth, fault and environment scope remain independently unclosed."""
        return False


def flat32_joint_model_hash() -> str:
    """Seal this composer and every native/domain/joint owner it consumes.

    This is a complete composite fingerprint, not the real16 native leaf: it
    is always recomputed and never joined to an enclosing snapshot traversal.
    The domain and binding identities it binds are likewise complete owner
    hashes, each computed against its own dependency set.
    """
    owners = (flat32_pe_component, flat32_image_bound_domain, flat32_native_effect_binding,
              loaded_byte_image_binding, loaded_byte_native_transition, loaded_byte_relation,
              loaded_byte_relation_proof, recursive_joint_admission, recursive_joint_contracts,
              recursive_joint_identity, recursive_joint_proof, recursive_static_control,
              recursive_call_continuation, real16_entry_domain, real16_native_effect_binding,
              flat32_call_contracts, flat32_call_lowering, flat32_pe_loader, flat32_replay,
              binary_environment)
    description = {"version": "flat32-image-bound-joint-v1", "z3": z3.get_version_string(),
                   "self": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   "domain": flat32_domain_model_hash(), "binding": flat32_native_binding_model_hash(),
                   "sources": [hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
                               for module in owners if module.__file__ is not None],
                   "stack_owners": [hashlib.sha256(path.read_bytes()).hexdigest()
                                    for path in sorted(
                                        Path(stack_domains.__file__ or "").parent.glob(
                                            "recursive_stack_*.py"))],
                   "snapshot_owner": native_model_snapshot_owner_hash(),
                   "semantic": ssa_provenance._semantic_hash(),
                   "registers": S._ssa_register_widths()}
    return hashlib.sha256(canonical_json_bytes(description)).hexdigest()


def _id(key: str) -> ObligationId:
    """Use labels only for obligation accounting, never semantic correspondence."""
    return ObligationId("flat32_image_bound_recursive", key)


def _requirements(system: JointSystem) -> tuple[Obligation, ...]:
    """Freeze the entire required denominator before any proof can refuse."""
    keys = ["before", "joint_structure", "original_source", "candidate_source",
            "image_bound_entry_access_domain", "frame:entry"]
    keys.extend(f"transition:{step.node.key()}" for step in system.steps)
    keys.extend(f"frame:{side}:{step.node.key()}" for step in system.steps for side in ("original", "candidate"))
    keys.extend(("complete_dispatch_and_atomic_lockstep_progress", "after", "model", "physical_scope"))
    required = tuple(Obligation(_id(key)) for key in keys)
    return (*required, Obligation(_id("component"), tuple(item.id for item in required)))


@dataclass(slots=True)
class _Flat32JointRun:
    """One deadline and closed required graph, retaining all child evidence."""

    system: JointSystem
    loads: tuple[BoundFlat32Load, BoundFlat32Load]
    initialized: LoadedRelationProof
    requests: tuple[tuple[Flat32NativeBlockRequest, ...], tuple[Flat32NativeBlockRequest, ...]]
    bootstrap: tuple[MachineState, MachineState]
    access: Flat32AccessDomain
    limits: LoadedRelationLimits
    required: tuple[Obligation, ...]
    contract: ContractIdentity
    model_hash: str
    proposal_hash: str
    current: str = "before"
    layout: StackWordLayout | None = None
    evidence: list[ObligationEvidence] = field(default_factory=list)
    domain: ImageBoundFlat32Domain | None = None
    sources: list[Flat32NativeBinding] = field(default_factory=list)
    joint: JointComponentReport | None = None

    def remaining_ms(self) -> int:
        """Never replenish time during source, domain, transition or model checks."""
        self.limits.check_time()
        return max(0, int((self.limits.deadline - time.monotonic()) * 1000))

    def fact(self, key: str, status: ProofStatus, *, counters: FactCounters | None = None,
             assumptions: tuple[str, ...] = (), dependencies: tuple[ObligationId, ...] = ()) -> None:
        """Retain the exact content/model contract and every child's work counters."""
        counts = counters if counters is not None else FactCounters(
            1, 1, 1, 1, int(status is not ProofStatus.PROVED and not assumptions))
        self.evidence.append(ObligationEvidence(_id(key), self.contract, status,
            method="flat32_byte_bound_atomic_joint_induction", counters=counts,
            assumptions=assumptions, dependencies=dependencies))

    def report(self, reason: JointReason, detail: str = "") -> ImageBoundFlat32JointProof:
        """Only the complete composed theorem retains named model requirements."""
        proof = evaluate_obligations(self.contract, self.required, self.evidence)
        complete = reason is JointReason.CONDITIONAL_MODEL and proof.status is ProofStatus.CONDITIONAL
        return ImageBoundFlat32JointProof(
            ProofStatus.CONDITIONAL if complete else ProofStatus.UNKNOWN, reason, proof,
            self.proposal_hash, self.model_hash, self.domain, tuple(self.sources), self.joint,
            () if self.joint is None else self.joint.frames, tuple(Flat32ModelRequirement), detail)


def _linked(run: _Flat32JointRun, side: int) -> str | None:
    """Return None only when every joint node matches its byte-bound request."""
    actual = {(row.address, row.effect_hash) for row in run.requests[side]}
    expected = {(step.original_address if side == 0 else step.candidate_address,
                 native_effect_hash(step.original if side == 0 else step.candidate))
                for step in run.system.steps}
    if len(actual) != len(run.requests[side]) or actual != expected:
        return "joint step coordinates or effects diverge from the byte-bound requests"
    kinds = {JointStepKind.BRANCH: NativeBlockKind.BRANCH, JointStepKind.CALL: NativeBlockKind.CALL,
             JointStepKind.RETURN: NativeBlockKind.RETURN}
    bound = {block.address: block.kind for block in run.sources[side].blocks}
    for step in run.system.steps:
        address = step.original_address if side == 0 else step.candidate_address
        if step.kind not in kinds or bound.get(address) is not kinds[step.kind]:
            return f"joint step at {address:#x} has a kind diverging from the byte-bound block"
    return None


def _admit(run: _Flat32JointRun) -> None:
    """Require full state/initialization and immutable loads before any fact."""
    guard = _TransitionRun(run.initialized, run.limits, 262144, 128)
    if _consume_initialized(guard) is not Architecture.FLAT32:
        raise JointRefusal(JointReason.OUTPUTS, "flat32 joint requires flat32 initialized memory")
    proposal = run.initialized.proposal
    if (proposal.original.sparse_byte_sha256 != run.loads[0].binding.snapshot.sparse_byte_sha256
            or proposal.candidate.sparse_byte_sha256 != run.loads[1].binding.snapshot.sparse_byte_sha256):
        raise ImageBindingRefusal(ImageBindingReason.CHANGED,
                                  "initialized relation does not bind these loaded images")
    for load in run.loads:
        load.verify(limits=run.limits)
    if run.system.initial_state is None:
        raise JointRefusal(JointReason.OUTPUTS, "flat32 joint requires a complete entry identity state")
    baseline = _native_initial(Architecture.FLAT32)
    states = [run.system.initial_state, *run.bootstrap]
    for step in run.system.steps:
        states.extend((step.original, step.candidate))
    for state in states:
        _check_states(baseline, state, state)
        guard.guard(state)
    if run.system.contract.architecture is not Architecture.FLAT32:
        raise JointRefusal(JointReason.LAYOUT, "joint contract is not flat32")
    if (run.system.contract.original_hash != run.loads[0].binding.file_sha256
            or run.system.contract.candidate_hash != run.loads[1].binding.file_sha256):
        raise JointRefusal(JointReason.LAYOUT, "joint executable identity differs from immutable loads")
    run.layout = derive_joint_frame_layout(run.system)


def _frame_facts(run: _Flat32JointRun, joint: JointComponentReport) -> JointReason | None:
    """Consume entry and per-step frame proofs with their call continuations."""
    if run.layout is None:
        raise ValueError("frame facts require the admitted layout")
    frames = joint.frames
    if not frames:
        run.fact("frame:entry", ProofStatus.UNKNOWN)
        return JointReason.UNKNOWN
    entry = consume_call_frame(frames[0], run.layout, None)
    run.fact("frame:entry", entry.status, counters=entry.counters)
    if entry.status is not ProofStatus.PROVED:
        return entry.reason
    cursor = 1
    for step in run.system.steps:
        for name, side in (("original", CallSide.ORIGINAL), ("candidate", CallSide.CANDIDATE)):
            key = f"frame:{name}:{step.node.key()}"
            run.current = key
            if cursor >= len(frames):
                run.fact(key, ProofStatus.UNKNOWN)
                return JointReason.UNKNOWN
            frame = frames[cursor]
            cursor += 1
            try:
                request = request_call_continuation(run.system, step, side)
            except ValueError as refusal:
                run.fact(key, ProofStatus.UNKNOWN)
                run.current = key
                raise JointRefusal(JointReason.MANIFEST, str(refusal)) from refusal
            consumed = consume_call_frame(frame, run.layout, request)
            run.fact(key, consumed.status, counters=consumed.counters)
            if consumed.status is not ProofStatus.PROVED:
                return consumed.reason
    return None


def _bind_sources(run: _Flat32JointRun) -> ImageBoundFlat32JointProof | None:
    """Admit both native sources and retain each refusal with its counters."""
    for side, key in enumerate(("original_source", "candidate_source")):
        run.current = key
        source = bind_flat32_native_effects(run.loads[side], run.requests[side],
                                          timeout_ms=run.remaining_ms(), limits=run.limits)
        run.sources.append(source)
        mismatch = _linked(run, side) if source.status is ProofStatus.PROVED else None
        if source.status is ProofStatus.PROVED and mismatch is None:
            run.fact(key, ProofStatus.PROVED, counters=source.counters)
            continue
        run.fact(key, ProofStatus.UNKNOWN,
                 counters=replace(source.counters, failure_count=source.counters.failure_count + 1))
        if source.status is not ProofStatus.PROVED:
            reason = JointReason.DEADLINE if source.reason is Flat32BindingReason.DEADLINE else JointReason.ADMISSION
            return run.report(reason, f"{key}: {source.reason.value}: {source.detail}")
        return run.report(JointReason.ADMISSION, f"{key}: {mismatch}")
    return None


def _transition_facts(run: _Flat32JointRun, joint: JointComponentReport) -> ImageBoundFlat32JointProof | None:
    """Account for every required transition, refusing missing or unproved rows."""
    by_node = {row.node: row for row in joint.steps}
    for step in run.system.steps:
        run.current = f"transition:{step.node.key()}"
        row = by_node.get(step.node)
        status = row.status if row is not None and row.attempted else ProofStatus.UNKNOWN
        run.fact(run.current, status)
        if status is not ProofStatus.PROVED:
            reason = JointReason.DEADLINE if row is not None and row.reason is JointReason.DEADLINE else JointReason.UNKNOWN
            if row is not None and row.reason is JointReason.COUNTERMODEL:
                reason = JointReason.COUNTERMODEL
            return run.report(reason, f"{run.current}: {row.reason.value if row is not None else 'missing'}")
    return None


def _prove(run: _Flat32JointRun) -> ImageBoundFlat32JointProof:
    """Anchor PE-bound induction in actual file, mapping and source premises."""
    _admit(run)
    run.fact("before", ProofStatus.PROVED)
    run.current = "joint_structure"
    run.fact(run.current, ProofStatus.PROVED)
    source_refusal = _bind_sources(run)
    if source_refusal is not None:
        return source_refusal
    run.current = "image_bound_entry_access_domain"
    run.domain = prove_image_bound_flat32_domain(run.system, run.loads, run.initialized, run.access,
                                                 timeout_ms=run.remaining_ms(), limits=run.limits)
    run.fact(run.current, run.domain.status, counters=run.domain.counters)
    if run.domain.status is not ProofStatus.PROVED:
        reason = JointReason.DEADLINE if run.domain.reason is Flat32DomainReason.DEADLINE else JointReason.UNKNOWN
        return run.report(reason, f"{run.domain.reason.value}: {run.domain.detail}")
    # The existing checker owns every transition and frame discharge under the
    # same deadline; a CONDITIONAL result names physical scope, never success.
    joint = check_joint_system(run.system, timeout_ms=run.remaining_ms())
    run.joint = joint
    transition_refusal = _transition_facts(run, joint)
    if transition_refusal is not None:
        return transition_refusal
    frame_reason = _frame_facts(run, joint)
    if frame_reason is not None:
        reason = frame_reason if frame_reason in {JointReason.DEADLINE, JointReason.COUNTERMODEL,
                                                  JointReason.CALL_CONTINUATION} else JointReason.UNKNOWN
        return run.report(reason, f"{run.current}: frame evidence not discharged")
    if (joint.status is not ProofStatus.CONDITIONAL or joint.reason is not JointReason.CONDITIONAL_MODEL
            or joint.proof.counters.failure_count != 0):
        return run.report(JointReason.UNKNOWN, f"joint report did not discharge: {joint.reason.value}")
    run.fact("complete_dispatch_and_atomic_lockstep_progress", ProofStatus.PROVED)
    run.current = "after"
    for load in run.loads:
        load.verify(limits=run.limits)
    if joint_proposal_hash(run.system, run.bootstrap) != run.proposal_hash:
        run.fact(run.current, ProofStatus.UNKNOWN)
        return run.report(JointReason.UNKNOWN, "joint proposal content changed during proof")
    run.fact(run.current, ProofStatus.PROVED)
    run.current = "model"
    stable = run.model_hash == flat32_joint_model_hash()
    run.remaining_ms()
    run.fact(run.current, ProofStatus.PROVED if stable else ProofStatus.UNKNOWN)
    if not stable:
        return run.report(JointReason.UNKNOWN, "flat32 joint semantic model changed")
    remaining = tuple(item.value for item in Flat32ModelRequirement)
    run.fact("physical_scope", ProofStatus.CONDITIONAL, assumptions=remaining)
    dependencies = run.required[-1].dependencies
    run.fact("component", ProofStatus.PROVED, dependencies=dependencies)
    return run.report(JointReason.CONDITIONAL_MODEL)


def check_image_bound_flat32_joint(system: JointSystem,
                                   loads: tuple[BoundFlat32Load, BoundFlat32Load],
                                   initialized: LoadedRelationProof,
                                   requests: tuple[tuple[Flat32NativeBlockRequest, ...],
                                                   tuple[Flat32NativeBlockRequest, ...]],
                                   bootstrap: tuple[MachineState, MachineState],
                                   access: Flat32AccessDomain, *,
                                   timeout_ms: int = 120000,
                                   limits: LoadedRelationLimits | None = None) -> ImageBoundFlat32JointProof:
    """Compose every matched PE32 recursive premise, keeping physical scope conditional.

    Immutable file bytes, loader mappings, initialized-byte relation and the
    declared entry/stack domain are all bound before and after the proof. The
    existing joint checker discharges transitions and frames; this adapter adds
    the PE image premises and keeps caller entry, unbounded-depth backing,
    faults, imports and environment as named requirements.
    """
    if type(timeout_ms) is not int or timeout_ms < 0 or len(system.steps) > 4095:
        raise ValueError("flat32 joint proof requires a finite budget and bounded component")
    if not isinstance(access, Flat32AccessDomain):
        raise ValueError("flat32 joint proof requires a typed declared access domain")
    selected = limits if limits is not None else LoadedRelationLimits()
    deadline = time.monotonic() + timeout_ms / 1000
    if selected.deadline >= 0:
        deadline = min(deadline, selected.deadline)
    model_hash = flat32_joint_model_hash()
    proposal_hash = joint_proposal_hash(system, bootstrap)
    contract = replace(system.contract, model_hash=model_hash)
    run = _Flat32JointRun(system, loads, initialized, requests, bootstrap, access,
                          replace(selected, deadline=deadline), _requirements(system),
                          contract, model_hash, proposal_hash)
    try:
        return _prove(run)
    except JointRefusal as refusal:
        run.fact(run.current, ProofStatus.UNKNOWN)
        return run.report(refusal.reason, refusal.detail)
    except ImageBindingRefusal as refusal:
        run.fact(run.current, ProofStatus.UNKNOWN)
        return run.report(JointReason.ADMISSION, refusal.detail)
    except Flat32ProposalRefusal as refusal:
        run.fact(run.current, ProofStatus.UNKNOWN)
        return run.report(JointReason.MANIFEST, refusal.detail)
    except _TransitionRefusal as refusal:
        run.fact(run.current, ProofStatus.UNKNOWN)
        return run.report(JointReason.OUTPUTS, refusal.detail)
    except CallCompositionRefusal as refusal:
        run.fact(run.current, ProofStatus.UNKNOWN)
        return run.report(JointReason.LAYOUT, str(refusal))
    except LoadedRelationRefusal as refusal:
        run.fact(run.current, ProofStatus.UNKNOWN)
        reason = JointReason.DEADLINE if refusal.reason is LoadedRelationReason.DEADLINE else JointReason.UNKNOWN
        return run.report(reason, refusal.detail)


__all__ = [
    "Flat32ModelRequirement",
    "ImageBoundFlat32JointProof",
    "check_image_bound_flat32_joint",
    "flat32_joint_model_hash",
]
