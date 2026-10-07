"""Layer: dosunit per-call continuation proof consumption.

Responsibility: derive each admitted side's loaded continuation and require
the complete native PUSH certificate to prove that particular saved word.
Global return-target membership cannot discharge this per-call contract.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum

from tools.dosunit.contracts.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.recursive_proofs.recursive_joint_contracts import (
    JointNodeId,
    JointReason,
    JointStepKind,
    JointStepPair,
    JointSystem,
)
from tools.dosunit.recursive_proofs.stack.recursive_stack_clauses import StackClauseReason, required_stack_clauses
from tools.dosunit.recursive_proofs.stack.recursive_stack_domains import StackWordLayout
from tools.dosunit.recursive_proofs.stack.recursive_stack_proofs import (
    StackInvariantProof,
    StackObligation,
    StackProofReason,
)


class CallSide(StrEnum):
    """Choose an owned coordinate projection independently on each side."""

    ORIGINAL = "original"
    CANDIDATE = "candidate"


@dataclass(frozen=True, slots=True)
class CallContinuationRequest:
    """An admitted metadata proposal; only native frame discharge proves it."""

    side: CallSide
    caller: JointNodeId
    destination: JointNodeId
    address: int

    def accepts(self, frame: StackInvariantProof, layout: StackWordLayout) -> bool:
        """Reject different words, missing clauses and malformed proved labels."""
        required = required_stack_clauses(layout, StackObligation.PUSH, expected_continuation=self.address)
        scope = (frame.obligation is StackObligation.PUSH and frame.layout == layout
                 and frame.expected_continuation == self.address)
        manifest = frame.required_clauses == required and tuple(row.kind for row in frame.clauses) == required
        facts = all(row.status is ProofStatus.PROVED and row.reason is StackClauseReason.DISCHARGED
                    and row.attempted for row in frame.clauses)
        return (scope and manifest and facts and frame.status is ProofStatus.PROVED
                and frame.reason is StackProofReason.PROVED
                and frame.counters.failure_count == 0 and frame.counters.materialized_count >= len(required))


@dataclass(frozen=True, slots=True)
class FrameConsumption:
    """Contextual frame verdict, retaining native failure counts and causes."""

    status: ProofStatus
    reason: JointReason
    counters: FactCounters


def consume_call_frame(frame: StackInvariantProof, layout: StackWordLayout,
                        request: CallContinuationRequest | None) -> FrameConsumption:
    """Keep a missing per-call theorem distinct from an actual native SAT."""
    if frame.status is ProofStatus.PROVED:
        if request is not None and not request.accepts(frame, layout):
            counters = replace(frame.counters, failure_count=frame.counters.failure_count + 1)
            return FrameConsumption(ProofStatus.UNKNOWN, JointReason.CALL_CONTINUATION, counters)
        return FrameConsumption(ProofStatus.PROVED, JointReason.DISCHARGED, frame.counters)
    reasons = {StackProofReason.COUNTERMODEL: JointReason.COUNTERMODEL,
               StackProofReason.DEADLINE: JointReason.DEADLINE}
    return FrameConsumption(ProofStatus.UNKNOWN, reasons.get(frame.reason, JointReason.UNKNOWN), frame.counters)


def request_call_continuation(system: JointSystem, step: JointStepPair,
                              side: CallSide) -> CallContinuationRequest | None:
    """Project an admitted node's address without assuming side symmetry."""
    if step.kind is not JointStepKind.CALL:
        return None
    targets = {row.node: row for row in system.steps}
    if step.continuation is None or step.continuation not in targets:
        raise ValueError("admitted CALL must retain its continuation head")
    target = targets[step.continuation]
    address = target.original_address if side is CallSide.ORIGINAL else target.candidate_address
    return CallContinuationRequest(side, step.node, step.continuation, address)
