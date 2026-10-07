"""Layer: dosunit joint recursive induction checker (staging).

Responsibility: discharge every native full-state transition and both sides'
frame obligations using one deadline, then compose an acyclic proof report.
Lockstep progress uses complete atomic steps, never recursive callee summaries.
Unclosed physical model conditions remain mandatory conditional evidence.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from typing import Any

from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.real16_call_contracts import materialize_function
from tools.dosunit.contracts.proof_contracts import (
    FactCounters,
    Obligation,
    ObligationEvidence,
    ObligationId,
    ProofStatus,
    evaluate_obligations,
    proof_status_from_legacy,
)
from tools.dosunit.contracts.register_state_relations import MachineState
from tools.dosunit.recursive_proofs.recursive_call_continuation import (
    CallContinuationRequest,
    CallSide,
    consume_call_frame,
    request_call_continuation,
)
from tools.dosunit.recursive_proofs.recursive_joint_admission import JointRefusal, admit_joint_system
from tools.dosunit.recursive_proofs.recursive_joint_contracts import (
    JointComponentReport,
    JointModelRequirement,
    JointReason,
    JointStepEvidence,
    JointStepKind,
    JointSystem,
)
from tools.dosunit.recursive_proofs.stack.recursive_stack_domains import StackWordLayout
from tools.dosunit.recursive_proofs.stack.recursive_stack_proofs import (
    StackInvariantProof,
    StackObligation,
    prove_stack_step,
)


@dataclass(slots=True)
class _JointRun:
    """Own one shared deadline and all retained partial proof evidence."""

    system: JointSystem
    deadline: float
    required: list[Obligation] = field(default_factory=list)
    evidence: list[ObligationEvidence] = field(default_factory=list)
    steps: list[JointStepEvidence] = field(default_factory=list)
    frames: list[StackInvariantProof] = field(default_factory=list)

    def remaining_ms(self) -> int:
        """Expose only the original budget remainder, never replenish it."""
        return max(0, int((self.deadline - time.monotonic()) * 1000))

    def fact(self, key: str, status: ProofStatus, *, assumptions: tuple[str, ...] = (),
             counters: FactCounters | None = None) -> None:
        """Retain each required result with the exact binary/model contract."""
        identity = ObligationId("joint_recursive", key)
        self.required.append(Obligation(identity))
        closed = counters or FactCounters(1, 1, 1, 1, int(status is not ProofStatus.PROVED and not assumptions))
        self.evidence.append(ObligationEvidence(identity, self.system.contract, status,
                                                method="native_full_state_induction", assumptions=assumptions,
                                                counters=closed))

    def report(self, status: ProofStatus, reason: JointReason, detail: str = "") -> JointComponentReport:
        """Preserve partial work without overstating raw solver countermodels."""
        proof = evaluate_obligations(self.system.contract, self.required, self.evidence)
        return JointComponentReport(status, reason, proof, tuple(self.steps), tuple(JointModelRequirement),
                                    detail, tuple(self.frames))

    def expired(self) -> JointComponentReport:
        """Record one explicit failed budget fact and preserve all prior work."""
        self.fact("budget", ProofStatus.UNKNOWN)
        return self.report(ProofStatus.UNKNOWN, JointReason.DEADLINE)


def check_joint_system(system: JointSystem, *, timeout_ms: int = 60000) -> JointComponentReport:
    """Check all required modeled facts while refusing whole-binary promotion.

    The strict identity relation is preserved by every matched atomic step.
    Complete dispatch and independently proved frame closure permit lockstep
    induction through cycles without assumed recursive callee postconditions.
    Caller-entry, physical memory, fault and environment scope still require
    independent closure before any whole-function acceptance.
    """
    run = _JointRun(system, time.monotonic() + max(timeout_ms, 0) / 1000)
    if run.remaining_ms() <= 0:
        return run.expired()
    try:
        layout = admit_joint_system(system, deadline=run.deadline)
    except JointRefusal as exc:
        run.fact("admission", ProofStatus.UNKNOWN)
        return run.report(ProofStatus.UNKNOWN, exc.reason, exc.detail)
    if run.remaining_ms() <= 0:
        return run.expired()
    run.fact("complete_manifest_and_dispatch", ProofStatus.PROVED)
    failed = _check_transitions(run)
    if failed is None:
        failed = _check_frames(run, layout)
    if failed is not None:
        return failed
    return _aggregate(run)


def _check_transitions(run: _JointRun) -> JointComponentReport | None:
    """Check every full output set and preserve arbitrary-cutpoint SAT evidence."""
    for step in run.system.steps:
        remaining = run.remaining_ms()
        if remaining <= 0:
            return run.expired()
        checked = S._compare_functions(strict_state_document("joint:original", step.original),
                                       strict_state_document("joint:candidate", step.candidate), timeout_ms=remaining)
        status = proof_status_from_legacy(checked.get("status")) or ProofStatus.UNKNOWN
        if checked.get("skipped_layout_outputs"):
            status = ProofStatus.UNKNOWN
        reason = JointReason.DISCHARGED if status is ProofStatus.PROVED else JointReason.UNKNOWN
        if status is ProofStatus.COUNTEREXAMPLE:
            reason = JointReason.COUNTERMODEL
        if run.remaining_ms() <= 0:
            status, reason = ProofStatus.UNKNOWN, JointReason.DEADLINE
        run.steps.append(JointStepEvidence(step.node, status, reason, True,
                                           int(checked.get("solver_time_ms", 0)),
                                           mismatches=tuple(checked.get("mismatches", ()))))
        run.fact(f"state:{step.node.key()}", status)
        if status is not ProofStatus.PROVED:
            return run.report(ProofStatus.UNKNOWN, reason)
    return None


def _check_frames(run: _JointRun, layout: StackWordLayout) -> JointComponentReport | None:
    """Prove initiation and both native frame effects at every cutpoint."""
    baseline = run.system.initial_state
    if baseline is None:
        raise ValueError("admitted system must retain its complete initial state")
    obligations: list[tuple[str, MachineState, StackObligation, CallContinuationRequest | None]] = [
        ("entry", baseline, StackObligation.INITIATION, None)]
    kinds = {JointStepKind.BRANCH: StackObligation.BODY,
             JointStepKind.CALL: StackObligation.PUSH, JointStepKind.RETURN: StackObligation.POP}
    for step in run.system.steps:
        obligations.extend((f"{side.value}:{step.node.key()}", state, kinds[step.kind],
                            request_call_continuation(run.system, step, side))
                           for side, state in ((CallSide.ORIGINAL, step.original), (CallSide.CANDIDATE, step.candidate)))
    for key, state, kind, request in obligations:
        remaining = run.remaining_ms()
        if remaining <= 0:
            return run.expired()
        frame = prove_stack_step(_frame_state(run.system, state), layout, kind,
                                 timeout_ms=remaining, deadline=run.deadline,
                                 expected_continuation=request.address if request is not None else None)
        run.frames.append(frame)
        consumed = consume_call_frame(frame, layout, request)
        run.fact(f"frame:{key}:{kind.value}", consumed.status, counters=consumed.counters)
        if consumed.status is not ProofStatus.PROVED:
            # Local frame SAT deliberately remains UNKNOWN until reachable
            # binary replay/domain closure. Its typed reason retains the raw
            # countermodel; the aggregate must not call it solver uncertainty.
            return run.report(ProofStatus.UNKNOWN, consumed.reason, frame.detail)
    return None


def _aggregate(run: _JointRun) -> JointComponentReport:
    """Consume all proved modeled facts and the mandatory unclosed scope fact."""
    run.fact("identity_entry_and_atomic_lockstep_progress", ProofStatus.PROVED)
    run.fact("physical_model_closure", ProofStatus.CONDITIONAL,
             assumptions=tuple(item.value for item in JointModelRequirement))
    dependencies = tuple(item.id for item in run.required)
    aggregate = ObligationId("joint_recursive", "component")
    run.required.append(Obligation(aggregate, dependencies))
    run.evidence.append(ObligationEvidence(aggregate, run.system.contract, ProofStatus.PROVED,
                                          method="closed_joint_induction", dependencies=dependencies,
                                          counters=FactCounters(1, 1, 1, 1, 0)))
    result = run.report(ProofStatus.CONDITIONAL, JointReason.CONDITIONAL_MODEL)
    if result.proof.status is not ProofStatus.CONDITIONAL:
        return replace(result, status=ProofStatus.UNKNOWN, reason=JointReason.UNKNOWN,
                       detail="joint evidence failed the shared contract/counter/dependency evaluator")
    return result


def _frame_state(system: JointSystem, state: MachineState) -> MachineState:
    """Expose full loaded flat32 IP to the existing native frame theorem.

    This is an explicit derived projection for the frame-only checker. The
    complete transition proof above still compares both legacy EIP and IP.
    """
    if system.control_field == "control_ip":
        return state
    result = dict(state)
    result["eip"] = state[system.control_field]
    return result


def strict_state_document(identity: str, state: MachineState) -> dict[str, Any]:
    """Transport every native output through the legacy solver without IP omission.

    The legacy pair builder omits an output named ``ip`` whenever its terms
    look like code addresses. Rename only its output label at this solver
    boundary, retaining exactly the same term, width, assignments and inputs.
    This is a bijective output-label projection, not relocation normalization
    or a change to native state. Every other output retains its native label.
    """
    document = materialize_function(identity, state)
    if "joint_native_ip" in state:
        raise ValueError("strict solver output label collides with native state")
    outputs = document["outputs"]
    if "ip" in outputs:
        outputs["joint_native_ip"] = outputs.pop("ip")
    return document
