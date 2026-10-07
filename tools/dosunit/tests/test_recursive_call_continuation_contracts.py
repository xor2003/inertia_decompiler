"""Exact per-call requests and complete evidence must survive refusal boundaries."""
from __future__ import annotations

from dataclasses import replace

import pytest

from tools.dosunit.contracts.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.recursive_proofs.recursive_call_components import FunctionId
from tools.dosunit.recursive_proofs.recursive_call_continuation import (
    CallContinuationRequest,
    CallSide,
    consume_call_frame,
)
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointNodeId, JointReason
from tools.dosunit.recursive_proofs.stack.recursive_stack_clauses import (
    StackClauseEvidence,
    StackClauseKind,
    StackClauseReason,
    required_stack_clauses,
)
from tools.dosunit.recursive_proofs.stack.recursive_stack_domains import StackWordLayout
from tools.dosunit.recursive_proofs.stack.recursive_stack_proofs import (
    StackInvariantProof,
    StackObligation,
    StackProofReason,
    prove_stack_step,
)


@pytest.fixture(params=[True, False], ids=["segmented16", "flat32"])
def layout(request: pytest.FixtureRequest) -> StackWordLayout:
    segmented = request.param
    bits = 16 if segmented else 32
    return StackWordLayout(bits, bits, segmented, (0x120A, 0x120F), ((0x1200, 0x1210),))


def test_original_deadline_retains_requested_word_and_full_manifest(layout: StackWordLayout) -> None:
    """No encoding/query is needed to retain every unattempted obligation."""
    result = prove_stack_step({}, layout, StackObligation.PUSH, timeout_ms=0, expected_continuation=0x120A)
    assert result.status is ProofStatus.UNKNOWN and result.reason is StackProofReason.DEADLINE
    assert result.expected_continuation == 0x120A
    assert StackClauseKind.CALL_CONTINUATION in result.required_clauses
    assert len(result.required_clauses) == (7 if layout.segmented else 5)
    assert not result.clauses and result.counters.failure_count > 0
    generic = prove_stack_step({}, layout, StackObligation.PUSH, timeout_ms=0)
    assert generic.expected_continuation is None
    assert StackClauseKind.CALL_CONTINUATION not in generic.required_clauses


@pytest.mark.parametrize("obligation", [StackObligation.INITIATION, StackObligation.BODY, StackObligation.POP])
def test_other_obligations_cannot_claim_a_call_binding(layout: StackWordLayout, obligation: StackObligation) -> None:
    with pytest.raises(ValueError):
        prove_stack_step({}, layout, obligation, timeout_ms=0, expected_continuation=0x120A)


@pytest.mark.parametrize("value", [True, "0x120a", 0x120A + 0.0])
def test_loaded_continuation_requires_an_integer(layout: StackWordLayout, value) -> None:
    with pytest.raises(TypeError):
        prove_stack_step({}, layout, StackObligation.PUSH, timeout_ms=0, expected_continuation=value)


def test_unadmitted_word_is_an_api_refusal(layout: StackWordLayout) -> None:
    with pytest.raises(ValueError):
        prove_stack_step({}, layout, StackObligation.PUSH, timeout_ms=0, expected_continuation=0x120B)


def _complete_mock(layout: StackWordLayout) -> StackInvariantProof:
    """Use a typed producer mock solely to test the contextual intake boundary."""
    required = required_stack_clauses(layout, StackObligation.PUSH, expected_continuation=0x120A)
    clauses = tuple(StackClauseEvidence(kind, ProofStatus.PROVED, StackClauseReason.DISCHARGED, True, 0)
                    for kind in required)
    count = len(required) + 1
    return StackInvariantProof(StackObligation.PUSH, ProofStatus.PROVED, StackProofReason.PROVED,
        FactCounters(count, count, count, count, 0), 0, layout, clauses=clauses,
        required_clauses=required, expected_continuation=0x120A)


@pytest.mark.parametrize("corruption", ["none", "different_word", "missing", "duplicate", "unknown", "unattempted", "reason", "counters"])
def test_proved_label_cannot_replace_complete_per_call_evidence(layout: StackWordLayout, corruption: str) -> None:
    """The global set still admits the different word; this request refuses it."""
    member = FunctionId("call-intake")
    request = CallContinuationRequest(CallSide.ORIGINAL, JointNodeId(member, 0), JointNodeId(member, 10), 0x120A)
    frame = _complete_mock(layout)
    assert consume_call_frame(frame, layout, request).status is ProofStatus.PROVED
    if corruption == "none":
        frame = replace(frame, expected_continuation=None)
    elif corruption == "different_word":
        frame = replace(frame, expected_continuation=0x120F)
    elif corruption == "missing":
        frame = replace(frame, clauses=frame.clauses[:-1])
    elif corruption == "duplicate":
        frame = replace(frame, clauses=(*frame.clauses[:-1], frame.clauses[0]))
    elif corruption == "unknown":
        frame = replace(frame, clauses=(*frame.clauses[:-1], replace(frame.clauses[-1], status=ProofStatus.UNKNOWN)))
    elif corruption == "unattempted":
        frame = replace(frame, clauses=(*frame.clauses[:-1], replace(frame.clauses[-1], attempted=False)))
    elif corruption == "reason":
        frame = replace(frame, reason=StackProofReason.UNKNOWN)
    else:
        frame = replace(frame, counters=replace(frame.counters, materialized_count=0))
    result = consume_call_frame(frame, layout, request)
    assert result.status is ProofStatus.UNKNOWN and result.reason is JointReason.CALL_CONTINUATION
    assert result.counters.failure_count > 0
