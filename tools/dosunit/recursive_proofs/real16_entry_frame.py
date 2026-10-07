"""Layer: dosunit binary-derived recursive caller-frame initiation (staging).

Responsibility: derive the expected saved caller word from independently bound
bootstrap CALL bytes and prove the actual loader/bootstrap establishes the
finite near-word frame invariant for every background state. Neither a caller
frame premise nor a recursive callee postcondition is assumed. Local initiation
does not discharge frame preservation, faults, services or binary equivalence.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import cast

import z3

from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.real16_call_contracts import initial_state, materialize_function
from tools.dosunit.contracts.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.contracts.register_state_relations import MachineState
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import BoundReal16Load
from tools.dosunit.recursive_proofs.loaded_byte_relation import LoadedRelationLimits, LoadedRelationRefusal
from tools.dosunit.recursive_proofs.loaded_byte_relation_proof import LoadedRelationProof
from tools.dosunit.recursive_proofs.real16_entry_domain import native_effect_hash
from tools.dosunit.recursive_proofs.real16_entry_domain_proof import _registers
from tools.dosunit.recursive_proofs.real16_image_bound_domain import (
    BoundDomainReason,
    ImageBoundReal16Domain,
    image_bound_domain_model_hash,
)
from tools.dosunit.recursive_proofs.real16_image_bound_domain_consumer import (
    BoundDomainConsumption,
    consume_image_bound_real16_domain,
)
from tools.dosunit.recursive_proofs.real16_native_effect_binding import NativeBlockKind, NativeBlockRequest
from tools.dosunit.recursive_proofs.recursive_joint_admission import JointRefusal, derive_joint_frame_layout
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointReason, JointSystem
from tools.dosunit.recursive_proofs.stack.recursive_stack_clauses import (
    StackClause,
    StackClauseBatch,
    StackClauseKind,
    StackClauseReason,
    check_stack_clauses,
)
from tools.dosunit.recursive_proofs.stack.recursive_stack_domains import StackWordDomain, StackWordLayout
from tools.dosunit.recursive_proofs.stack.recursive_stack_proofs import _state_exprs


class EntryFrameReason(StrEnum):
    """Exact caller-frame establishment result without component promotion."""

    DISCHARGED = "real16_loader_bootstrap_caller_frame_established"
    PREREQUISITE = "real16_caller_frame_prerequisite_refused"
    BOOTSTRAP = "real16_caller_frame_bootstrap_call_missing"
    COUNTERMODEL = "real16_caller_frame_native_countermodel"
    UNKNOWN = "real16_caller_frame_solver_unknown"
    MODEL = "real16_caller_frame_model_changed"
    DEADLINE = "real16_caller_frame_original_deadline_exhausted"


class EntryFrameObligation(StrEnum):
    """Both actual entry frames remain required even after an early refusal."""

    BEFORE = "current_entry_frame_prerequisites_before"
    LAYOUT = "complete_structural_near_word_frame_layout"
    ORIGINAL = "actual_original_bootstrap_frame"
    CANDIDATE = "actual_candidate_bootstrap_frame"
    AFTER = "current_entry_frame_prerequisites_after"
    MODEL = "stable_entry_frame_semantic_model"


@dataclass(frozen=True, slots=True)
class EntryFrameSide:
    """Actual bootstrap effect and independent complete frame clause results."""

    effect_hash: str
    caller_address: int
    layout: StackWordLayout
    clauses: StackClauseBatch


@dataclass(frozen=True, slots=True)
class EntryFrameFact:
    """One attempted initiation premise with typed non-result or success."""

    obligation: EntryFrameObligation
    status: ProofStatus


@dataclass(frozen=True, slots=True)
class Real16EntryFrameProof:
    """Connected native initiation evidence, never complete recursive equality."""

    status: ProofStatus
    reason: EntryFrameReason
    proposal_hash: str
    model_hash: str
    facts: tuple[EntryFrameFact, ...]
    counters: FactCounters
    consumers: tuple[BoundDomainConsumption, ...]
    sides: tuple[EntryFrameSide, ...]
    detail: str = ""

    @property
    def binary_equivalence_proved(self) -> bool:
        """Preservation and whole-component physical/outcome closure remain open."""
        return False


def entry_frame_model_hash() -> str:
    """Bind initiation and the authoritative finite frame/solver owners."""
    stage = Path(__file__).parent
    paths = (Path(__file__), stage / 'stack' / "recursive_stack_domains.py",
             stage / 'stack' / "recursive_stack_clauses.py")
    digest = hashlib.sha256(image_bound_domain_model_hash().encode("ascii"))
    for path in paths:
        digest.update(path.read_bytes())
    return digest.hexdigest()


def bootstrap_frame_clauses(load: BoundReal16Load, state: MachineState, layout: StackWordLayout,
                            caller_address: int, *, deadline: float) -> tuple[StackClause, ...]:
    """Propose the frame from actual outputs without assuming any saved word.

    Ghost root offset is introduced as the actual post-bootstrap SP; rank and
    initialized frontier are zero. The caller word comes from independently
    decoded fallthrough, so replacing output memory cannot make this tautological.
    The theorem is unrestricted in all uninitialized memory and other registers.
    """
    if not layout.segmented or layout.offset_bits != 16 or layout.word_bits != 16:
        raise ValueError("entry frame requires the admitted segmented near-word layout")
    initial = initial_state()
    entry = dict(initial)
    for name, value in _registers(load).items():
        if name != "ip":
            entry[name] = {"op": "const", "width": 16, "value": hex(value)}
    entry["control_ip"] = {"op": "const", "width": 32, "value": hex(load.binding.entry)}
    document = materialize_function("frame:bootstrap", state)
    composed = S._compose_block_outputs(document, document["outputs"], entry, compose_stats={"deadline": deadline})
    inputs = S._z3_inputs(materialize_function("frame:inputs", initial), materialize_function("frame:post", composed), z3)
    post = _state_exprs(composed, inputs)
    if not all(isinstance(post[name], z3.BitVecRef) and cast(z3.BitVecRef, post[name]).size() == 16
               for name in ("sp", "ss", "cs")):
        raise ValueError("complete native bootstrap requires scalar SP/SS/CS outputs")
    memory = post["memory"]
    if not isinstance(memory, z3.ArrayRef):
        raise ValueError("complete native bootstrap requires its actual output memory")
    registers = _registers(load)
    caller_word = z3.BitVecVal((caller_address - (registers["cs"] << 4)) & 0xFFFF, 16)
    domain = StackWordDomain(layout, cast(z3.BitVecRef, post["sp"]), z3.BitVecVal(0, layout.rank_bits),
        z3.BitVecVal(0, layout.rank_bits + 1), caller_word,
        cast(z3.BitVecRef, post["ss"]), cast(z3.BitVecRef, post["cs"]))
    index = z3.BitVec("actual_bootstrap_arbitrary_slot", layout.rank_bits)
    # Z3 equality annotations include False for unrelated Python operands;
    # validated native bitvector/scalar pairs produce native Boolean terms.
    return (StackClause(StackClauseKind.POINTER, cast(z3.BoolRef, (cast(z3.BitVecRef, post["sp"]) & 1) == 0)),
            StackClause(StackClauseKind.BOUNDS, domain.bounds(domain.rank, domain.allocated)),
            StackClause(StackClauseKind.SLOT, domain.slot_clause(memory, index, domain.allocated)),
            StackClause(StackClauseKind.ROOT_FRAME, domain.root_frame_clause(memory, domain.allocated)),
            StackClause(StackClauseKind.STACK_SELECTOR, cast(z3.BoolRef, post["ss"] == registers["ss"])),
            StackClause(StackClauseKind.CODE_SELECTOR, cast(z3.BoolRef, post["cs"] == registers["cs"])))


@dataclass(slots=True)
class _EntryRun:
    """One deadline with complete initiation accounting and retained children."""

    receipt: ImageBoundReal16Domain
    system: JointSystem
    loads: tuple[BoundReal16Load, BoundReal16Load]
    initialized: LoadedRelationProof
    bootstrap: tuple[MachineState, MachineState]
    requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]]
    limits: LoadedRelationLimits
    current: EntryFrameObligation = EntryFrameObligation.BEFORE
    model_hash: str = ""
    facts: list[EntryFrameFact] = field(default_factory=list)
    consumers: list[BoundDomainConsumption] = field(default_factory=list)
    sides: list[EntryFrameSide] = field(default_factory=list)

    def remaining_ms(self) -> int:
        """Reuse the original budget across consumers, composition and SMT."""
        self.limits.check_time()
        return max(0, int((self.limits.deadline - time.monotonic()) * 1000))

    def consume(self, key: EntryFrameObligation) -> bool:
        """Accept current independently bound evidence before or after native work."""
        self.current = key
        child = consume_image_bound_real16_domain(self.receipt, self.system, self.loads, self.initialized,
            self.bootstrap, self.requests, timeout_ms=self.remaining_ms(), limits=self.limits)
        self.consumers.append(child)
        self.facts.append(EntryFrameFact(key, child.status))
        return child.status is ProofStatus.PROVED

    def report(self, reason: EntryFrameReason, detail: str = "") -> Real16EntryFrameProof:
        """All unattempted sides and scope facts remain failures on refusal."""
        ids = [fact.obligation for fact in self.facts]
        required = set(EntryFrameObligation)
        failed = sum(fact.status is not ProofStatus.PROVED for fact in self.facts)
        failed += len(required - set(ids)) + len(set(ids) - required) + len(ids) - len(set(ids))
        count = len(required)
        status = ProofStatus.PROVED if failed == 0 and reason is EntryFrameReason.DISCHARGED else ProofStatus.UNKNOWN
        return Real16EntryFrameProof(status, reason, self.receipt.proposal_hash, self.model_hash, tuple(self.facts),
            FactCounters(count, count, count, len(self.facts), failed), tuple(self.consumers), tuple(self.sides), detail)


def _prove(run: _EntryRun) -> Real16EntryFrameProof:
    """Derive both saved entry frames from actual bootstrap bytes and effects."""
    if not run.consume(EntryFrameObligation.BEFORE):
        consumption = run.consumers[-1]
        reason = EntryFrameReason.DEADLINE if consumption.reason is BoundDomainReason.DEADLINE else EntryFrameReason.PREREQUISITE
        return run.report(reason, consumption.detail)
    run.model_hash = entry_frame_model_hash()
    run.current = EntryFrameObligation.LAYOUT
    layout = derive_joint_frame_layout(run.system)
    run.facts.append(EntryFrameFact(run.current, ProofStatus.PROVED))
    for side, run.current in enumerate((EntryFrameObligation.ORIGINAL, EntryFrameObligation.CANDIDATE)):
        entry = run.loads[side].binding.entry
        blocks = [block for block in run.receipt.sources[side].blocks if block.address == entry]
        if len(blocks) != 1 or blocks[0].kind is not NativeBlockKind.CALL:
            run.facts.append(EntryFrameFact(run.current, ProofStatus.UNKNOWN))
            return run.report(EntryFrameReason.BOOTSTRAP, "no unique independently decoded bootstrap CALL")
        caller = entry + blocks[0].size
        clauses = bootstrap_frame_clauses(run.loads[side], run.bootstrap[side], layout, caller, deadline=run.limits.deadline)
        # No caller-frame or memory premise enters this solver. The initialized
        # loader memory is a subset of the arbitrary background being checked.
        batch = check_stack_clauses(clauses, z3.Solver(), deadline=run.limits.deadline)
        run.sides.append(EntryFrameSide(native_effect_hash(run.bootstrap[side]), caller, layout, batch))
        run.facts.append(EntryFrameFact(run.current, ProofStatus.PROVED if batch.proved else ProofStatus.UNKNOWN))
        if not batch.proved:
            reason = EntryFrameReason.COUNTERMODEL if batch.model is not None else EntryFrameReason.UNKNOWN
            if batch.evidence[-1].reason is StackClauseReason.DEADLINE:
                reason = EntryFrameReason.DEADLINE
            return run.report(reason, batch.evidence[-1].detail)
    if not run.consume(EntryFrameObligation.AFTER):
        consumption = run.consumers[-1]
        reason = EntryFrameReason.DEADLINE if consumption.reason is BoundDomainReason.DEADLINE else EntryFrameReason.PREREQUISITE
        return run.report(reason, consumption.detail)
    run.current = EntryFrameObligation.MODEL
    stable = entry_frame_model_hash() == run.model_hash
    run.remaining_ms()
    run.facts.append(EntryFrameFact(run.current, ProofStatus.PROVED if stable else ProofStatus.UNKNOWN))
    return run.report(EntryFrameReason.DISCHARGED if stable else EntryFrameReason.MODEL)


def prove_real16_entry_frame(receipt: ImageBoundReal16Domain, system: JointSystem,
                            loads: tuple[BoundReal16Load, BoundReal16Load], initialized: LoadedRelationProof,
                            bootstrap: tuple[MachineState, MachineState],
                            requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]],
                            *, timeout_ms: int = 60000,
                            limits: LoadedRelationLimits | None = None) -> Real16EntryFrameProof:
    """Prove initiation without borrowing the proposed caller-frame invariant."""
    if type(timeout_ms) is not int or timeout_ms < 0:
        raise ValueError("entry frame requires a nonnegative millisecond budget")
    selected = limits if limits is not None else LoadedRelationLimits()
    deadline = time.monotonic() + timeout_ms / 1000
    if selected.deadline >= 0:
        deadline = min(deadline, selected.deadline)
    run = _EntryRun(receipt, system, loads, initialized, bootstrap, requests, replace(selected, deadline=deadline))
    try:
        return _prove(run)
    except LoadedRelationRefusal as refusal:
        run.facts.append(EntryFrameFact(run.current, ProofStatus.UNKNOWN))
        return run.report(EntryFrameReason.DEADLINE, refusal.detail)
    except JointRefusal as refusal:
        run.facts.append(EntryFrameFact(run.current, ProofStatus.UNKNOWN))
        reason = EntryFrameReason.DEADLINE if refusal.reason is JointReason.DEADLINE else EntryFrameReason.PREREQUISITE
        return run.report(reason, refusal.detail)
    except S.LowerFailure as refusal:
        run.facts.append(EntryFrameFact(run.current, ProofStatus.UNKNOWN))
        reason = EntryFrameReason.DEADLINE if time.monotonic() >= run.limits.deadline else EntryFrameReason.UNKNOWN
        return run.report(reason, f"{refusal.reason}: {refusal.message}")
