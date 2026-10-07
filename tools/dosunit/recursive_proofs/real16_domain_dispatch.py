"""Layer: dosunit source-bound real16 dispatch proof.

Responsibility: prove exact full-width successor sets under a consumed scalar
domain and a nonempty execution cutpoint, retaining every feasible edge. Graph
metadata supplies conclusions only; return closure belongs to frame proofs.
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
from tools.dosunit.compare.real16_call_contracts import materialize_function
from tools.dosunit.contracts.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.contracts.register_state_relations import MachineState
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import BoundReal16Load
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
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointStepKind, JointSystem
from tools.dosunit.recursive_proofs.stack.recursive_stack_proofs import _state_exprs


class DomainDispatchReason(StrEnum):
    """A complete domain-scoped theorem or an explicit failed boundary."""

    PROVED = "domain_dispatch_proved"
    SOURCE = "domain_dispatch_source_or_domain_changed"
    MODEL = "domain_dispatch_model_changed"
    VACUOUS = "domain_dispatch_cutpoint_or_edge_infeasible"
    COUNTERMODEL = "domain_dispatch_undeclared_destination"
    UNKNOWN = "domain_dispatch_solver_unknown"
    DEADLINE = "domain_dispatch_original_deadline_exhausted"


class DomainDispatchObligation(StrEnum):
    """Separate source intake, nonvacuity, coverage and individual edge facts."""

    BEFORE = "current_source_and_domain_before"
    CUTPOINT = "execution_cutpoint_nonempty"
    COVERAGE = "full_dword_destination_set"
    EDGE = "declared_edge_feasible"
    AFTER = "current_source_and_domain_after"
    MODEL = "dispatch_model_unchanged"


@dataclass(frozen=True, slots=True)
class DomainDispatchFact:
    """One exact obligation result, retaining solver models and refusals."""

    obligation: DomainDispatchObligation
    key: str
    status: ProofStatus
    detail: str = ""


@dataclass(frozen=True, slots=True)
class Real16DomainDispatchProof:
    """Complete source-bound dispatch evidence without a return/frame theorem."""

    status: ProofStatus
    reason: DomainDispatchReason
    proposal_hash: str
    model_hash: str
    required: tuple[tuple[DomainDispatchObligation, str], ...]
    facts: tuple[DomainDispatchFact, ...]
    consumers: tuple[BoundDomainConsumption, ...]
    counters: FactCounters
    detail: str = ""

    @property
    def complete(self) -> bool:
        """Only a discharged fixed denominator grants dispatch evidence."""
        return self.status is ProofStatus.PROVED and self.counters.failure_count == 0


def domain_dispatch_model_hash() -> str:
    """Seal this verifier, its domain consumer and the actual SSA encoder."""
    digest = hashlib.sha256(image_bound_domain_model_hash().encode("ascii"))
    digest.update(z3.get_version_string().encode("ascii"))
    digest.update(Path(__file__).read_bytes())
    return digest.hexdigest()


def _requirements(system: JointSystem) -> tuple[tuple[DomainDispatchObligation, str], ...]:
    """Freeze every side/cutpoint/edge before any intake or solver can refuse."""
    rows = [(DomainDispatchObligation.BEFORE, "before")]
    for step in system.steps:
        if step.kind is JointStepKind.RETURN:
            continue
        for side in ("original", "candidate"):
            key = f"{side}:{step.node.key()}"
            rows.extend(((DomainDispatchObligation.CUTPOINT, key), (DomainDispatchObligation.COVERAGE, key)))
            rows.extend((DomainDispatchObligation.EDGE, f"{key}:{target.key()}") for target in step.successors)
    rows.extend(((DomainDispatchObligation.AFTER, "after"), (DomainDispatchObligation.MODEL, "model")))
    return tuple(rows)


@dataclass(slots=True)
class _DispatchRun:
    """One original budget, immutable denominator and all attempted evidence."""

    receipt: ImageBoundReal16Domain
    system: JointSystem
    limits: LoadedRelationLimits
    required: tuple[tuple[DomainDispatchObligation, str], ...]
    model_hash: str
    facts: list[DomainDispatchFact] = field(default_factory=list)
    consumers: list[BoundDomainConsumption] = field(default_factory=list)

    def query(self, obligation: DomainDispatchObligation, key: str, equation: z3.BoolRef,
              *, witness: bool = False) -> DomainDispatchReason:
        """Use SAT witnesses and universal UNSAT checks without replenishing time."""
        self.limits.check_time()
        remaining = int((self.limits.deadline - time.monotonic()) * 1000)
        if remaining <= 0:
            raise LoadedRelationRefusal(LoadedRelationReason.DEADLINE, "dispatch original deadline exhausted")
        solver = z3.Solver()
        solver.set(timeout=remaining)
        solver.add(equation if witness else z3.Not(equation))
        outcome = solver.check()
        self.limits.check_time()
        expected = z3.sat if witness else z3.unsat
        status, reason, detail = ProofStatus.PROVED, DomainDispatchReason.PROVED, ""
        if outcome == z3.unknown:
            status, reason, detail = ProofStatus.UNKNOWN, DomainDispatchReason.UNKNOWN, solver.reason_unknown()
        elif outcome != expected:
            status = ProofStatus.UNKNOWN if witness else ProofStatus.COUNTEREXAMPLE
            reason = DomainDispatchReason.VACUOUS if witness else DomainDispatchReason.COUNTERMODEL
            detail = "required cutpoint/edge is infeasible" if witness else str(solver.model())
        self.facts.append(DomainDispatchFact(obligation, key, status, detail))
        return reason

    def report(self, reason: DomainDispatchReason, detail: str = "") -> Real16DomainDispatchProof:
        """Missing, duplicated and failed facts keep the full failure denominator."""
        identities = [(fact.obligation, fact.key) for fact in self.facts]
        required = set(self.required)
        failed = sum(fact.status is not ProofStatus.PROVED for fact in self.facts)
        failed += len(required - set(identities)) + len(identities) - len(set(identities))
        failed += len(set(identities) - required) + len(self.required) - len(required)
        proved = reason is DomainDispatchReason.PROVED and failed == 0
        status = ProofStatus.PROVED if proved else ProofStatus.UNKNOWN
        if any(fact.status is ProofStatus.COUNTEREXAMPLE for fact in self.facts):
            status = ProofStatus.COUNTEREXAMPLE
        count = len(self.required)
        return Real16DomainDispatchProof(status, reason, self.receipt.proposal_hash, self.model_hash,
            self.required, tuple(self.facts), tuple(self.consumers),
            FactCounters(count, count, count, len(self.facts), failed), detail)


def _prove_edges(run: _DispatchRun) -> DomainDispatchReason:
    """Prove conclusions from the established scalar and exact current cutpoint."""
    if run.receipt.domain is None or run.system.initial_state is None:
        return DomainDispatchReason.SOURCE
    initial = run.system.initial_state
    before = materialize_function("dispatch:inputs", initial)
    by_node = {step.node: step for step in run.system.steps}
    scalar = run.receipt.domain.domain
    for step in run.system.steps:
        if step.kind is JointStepKind.RETURN:
            continue
        for side, state in (("original", step.original), ("candidate", step.candidate)):
            head = step.original_address if side == "original" else step.candidate_address
            targets = tuple(by_node[target].original_address if side == "original"
                            else by_node[target].candidate_address for target in step.successors)
            run.limits.check_time()
            inputs = S._z3_inputs(before, materialize_function("dispatch:post", state), z3)
            pre, post = _state_exprs(initial, inputs), _state_exprs(state, inputs)
            premise = cast(z3.BoolRef, z3.And(scalar.predicate(pre), pre[run.system.control_field] == head))
            key = f"{side}:{step.node.key()}"
            reason = run.query(DomainDispatchObligation.CUTPOINT, key, premise, witness=True)
            if reason is not DomainDispatchReason.PROVED:
                return reason
            control = post[run.system.control_field]
            matches = [control == address for address in targets]
            conclusion = cast(z3.BoolRef, z3.Implies(premise, z3.Or(*matches)))
            reason = run.query(DomainDispatchObligation.COVERAGE, key, conclusion)
            if reason is not DomainDispatchReason.PROVED:
                return reason
            for target, match in zip(step.successors, matches, strict=True):
                reason = run.query(DomainDispatchObligation.EDGE, f"{key}:{target.key()}",
                                   cast(z3.BoolRef, z3.And(premise, match)), witness=True)
                if reason is not DomainDispatchReason.PROVED:
                    return reason
    return DomainDispatchReason.PROVED


def prove_real16_domain_dispatch(receipt: ImageBoundReal16Domain, system: JointSystem,
    loads: tuple[BoundReal16Load, BoundReal16Load], initialized: LoadedRelationProof,
    bootstrap: tuple[MachineState, MachineState],
    requests: tuple[tuple[NativeBlockRequest, ...], tuple[NativeBlockRequest, ...]],
    *, timeout_ms: int = 30000, limits: LoadedRelationLimits | None = None,
) -> Real16DomainDispatchProof:
    """Consume current source/domain evidence and prove every static native edge."""
    if type(timeout_ms) is not int or timeout_ms < 0 or len(system.steps) > 4095:
        raise ValueError("dispatch proof requires a nonnegative integer budget")
    selected = limits if limits is not None else LoadedRelationLimits()
    deadline = time.monotonic() + timeout_ms / 1000
    if selected.deadline >= 0:
        deadline = min(deadline, selected.deadline)
    run = _DispatchRun(receipt, system, replace(selected, deadline=deadline), _requirements(system), "")
    try:
        run.limits.check_time()
        run.model_hash = domain_dispatch_model_hash()
        for obligation, key in ((DomainDispatchObligation.BEFORE, "before"), (DomainDispatchObligation.AFTER, "after")):
            consumed = consume_image_bound_real16_domain(receipt, system, loads, initialized, bootstrap, requests,
                timeout_ms=max(0, int((deadline - time.monotonic()) * 1000)), limits=run.limits)
            run.consumers.append(consumed)
            run.facts.append(DomainDispatchFact(obligation, key, consumed.status, consumed.detail))
            if consumed.status is not ProofStatus.PROVED:
                reason = DomainDispatchReason.DEADLINE if consumed.reason is BoundDomainReason.DEADLINE else DomainDispatchReason.SOURCE
                return run.report(reason, consumed.detail)
            if obligation is DomainDispatchObligation.BEFORE:
                reason = _prove_edges(run)
                if reason is not DomainDispatchReason.PROVED:
                    return run.report(reason, run.facts[-1].detail if run.facts else "")
        stable = run.model_hash == domain_dispatch_model_hash()
        run.limits.check_time()
        run.facts.append(DomainDispatchFact(DomainDispatchObligation.MODEL, "model",
                                           ProofStatus.PROVED if stable else ProofStatus.UNKNOWN))
        return run.report(DomainDispatchReason.PROVED if stable else DomainDispatchReason.MODEL)
    except LoadedRelationRefusal as refusal:
        reason = DomainDispatchReason.DEADLINE if refusal.reason is LoadedRelationReason.DEADLINE else DomainDispatchReason.SOURCE
        return run.report(reason, refusal.detail)
    except S.LowerFailure as refusal:
        return run.report(DomainDispatchReason.UNKNOWN, f"{refusal.reason}: {refusal.message}")
