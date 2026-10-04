"""Entry controller refusal routing; typed successful stubs are not source proof."""
from __future__ import annotations

from pathlib import Path

import pytest
import z3
from recursive_proof_fixtures.image_bound_inputs import make_inputs

from tools.dosunit.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.recursive_proofs import real16_entry_frame as owner
from tools.dosunit.recursive_proofs.real16_image_bound_domain import (
    BoundDomainReason,
    ImageBoundReal16Domain,
)
from tools.dosunit.recursive_proofs.real16_image_bound_domain_consumer import BoundDomainConsumption
from tools.dosunit.recursive_proofs.real16_native_effect_binding import (
    NativeBindingReason,
    NativeBlockBinding,
    NativeBlockKind,
    Real16NativeBinding,
)
from tools.dosunit.recursive_proofs.stack.recursive_stack_clauses import (
    StackClause,
    StackClauseBatch,
    StackClauseEvidence,
    StackClauseKind,
    StackClauseReason,
)


@pytest.mark.parametrize("boundary", ["before", "clause", "after"])
@pytest.mark.parametrize("deadline", [True, False])
def test_entry_controller_retains_child_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, boundary: str, deadline: bool,
) -> None:
    """Resource causes and partial sides survive without changing their denominator."""
    inputs = make_inputs(tmp_path)
    failure = FactCounters(2, 2, 2, 1, 1)
    success = FactCounters(1, 1, 1, 1, 0)
    sources: list[Real16NativeBinding] = []
    for side in range(2):
        load = inputs.loads[side].binding
        request = next(row for row in inputs.requests[side] if row.address == load.entry)
        block = NativeBlockBinding(request.address, request.size, "controller-only", request.effect_hash,
                                   NativeBlockKind.CALL, request.effect_hash)
        sources.append(Real16NativeBinding(
            ProofStatus.PROVED, NativeBindingReason.DISCHARGED, load.file_sha256,
            load.snapshot.sparse_byte_sha256, "controller-only", inputs.requests[side], (block,), (), success,
        ))
    receipt = ImageBoundReal16Domain(
        ProofStatus.UNKNOWN, BoundDomainReason.SOURCE, inputs.system, "controller-only",
        tuple(sources), None, (), failure, proposal_hash="controller-only-proposal",
    )
    consumers: list[BoundDomainConsumption] = []
    batches: list[StackClauseBatch] = []
    consumed = 0

    def model_stub() -> str:
        return "controller-only-model"

    def consume_stub(*args: object, **kwargs: object) -> BoundDomainConsumption:
        nonlocal consumed
        consumed += 1
        refused = (boundary == "before" and consumed == 1) or (boundary == "after" and consumed == 2)
        reason = BoundDomainReason.DEADLINE if deadline else BoundDomainReason.SOURCE
        child = BoundDomainConsumption(
            ProofStatus.UNKNOWN if refused else ProofStatus.PROVED,
            reason if refused else BoundDomainReason.DISCHARGED, (),
            failure if refused else success, "typed domain refusal",
        )
        consumers.append(child)
        return child

    def clauses_stub(*args: object, **kwargs: object) -> tuple[StackClause, ...]:
        return (StackClause(StackClauseKind.POINTER, z3.BoolVal(True)),)

    def batch_stub(*args: object, **kwargs: object) -> StackClauseBatch:
        refused = boundary == "clause"
        reason = StackClauseReason.DEADLINE if deadline else StackClauseReason.UNKNOWN
        row = StackClauseEvidence(
            StackClauseKind.POINTER, ProofStatus.UNKNOWN if refused else ProofStatus.PROVED,
            reason if refused else StackClauseReason.DISCHARGED, not (refused and deadline), 0,
            "typed clause refusal",
        )
        batch = StackClauseBatch((StackClauseKind.POINTER,), (row,))
        batches.append(batch)
        return batch

    monkeypatch.setattr(owner, "entry_frame_model_hash", model_stub)
    monkeypatch.setattr(owner, "consume_image_bound_real16_domain", consume_stub)
    monkeypatch.setattr(owner, "bootstrap_frame_clauses", clauses_stub)
    monkeypatch.setattr(owner, "check_stack_clauses", batch_stub)
    report = owner.prove_real16_entry_frame(receipt, *inputs)
    expected = owner.EntryFrameReason.UNKNOWN if boundary == "clause" else owner.EntryFrameReason.PREREQUISITE
    if deadline:
        expected = owner.EntryFrameReason.DEADLINE
    assert report.status is ProofStatus.UNKNOWN and report.reason is expected
    assert report.consumers == tuple(consumers)
    assert tuple(side.clauses for side in report.sides) == tuple(batches)
    assert report.counters.raw_fact_count == len(owner.EntryFrameObligation)
    assert report.counters.failure_count > 0
    assert report.facts[-1].status is ProofStatus.UNKNOWN
    assert not report.binary_equivalence_proved
