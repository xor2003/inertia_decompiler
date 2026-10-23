"""Checked register correspondence for complete native loop transitions.

Layer: dosunit relational loop proofs.
Responsibility: propose invertible register coordinates from entry SSA, then
prove initiation, all continuing edges and identity at returns/entry backedges.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any

from tools.comparator.services import proof_owners
from tools.comparator.verdict import Status
from tools.dosunit.compare.flat32_call_contracts import CallCompositionRefusal, _initial_state, _register_widths
from tools.dosunit.compare.flat32_constant_registers import constant_register_projection
from tools.dosunit.compare.flat32_dead_flags import dead_flag_projection, dead_register_projection
from tools.dosunit.compare.flat32_frame_invariants import frame_invariant_projection
from tools.dosunit.compare.flat32_narrow_registers import narrow_register_projection
from tools.dosunit.compare.flat32_region_attempts import compare_attempt
from tools.dosunit.compare.flat32_relation_evidence import attempt_record
from tools.dosunit.contracts.register_affine_relations import RegisterRelation, propose_entry_relation
from tools.dosunit.contracts.register_cycle_proposals import propose_entry_cycles
from tools.dosunit.contracts.register_state_relations import (
    IDENTITY_RELATION,
    RegisterRelationReason,
    RegisterRelationRefusal,
    propose_entry_swaps,
)
from tools.dosunit.ssa.composition import compose_block_outputs


@dataclass(frozen=True, slots=True)
class LoopRelationComparison:
    """The selected complete attempt with every earlier failed proposal retained."""

    status: Status
    compared: dict[str, Any]
    verdicts: list[dict[str, Any]]
    candidate_ssa: dict[str, Any]
    relation: RegisterRelation
    attempts: list[dict[str, Any]]
    proposal_reason: RegisterRelationReason | None = None
    projected_oracle: dict[str, Any] | None = None
    constant_invariants: list[dict[str, Any]] = field(default_factory=list)
    dead_flags: dict[str, Any] = field(default_factory=dict)
    narrow_registers: dict[str, Any] = field(default_factory=dict)
    frame_invariants: dict[str, Any] = field(default_factory=dict)
    dead_registers: dict[str, Any] = field(default_factory=dict)


def compare_loop_relations(
    oracle_ssa: dict[str, Any], candidate_ssa: dict[str, Any],
    lower_candidate: Callable[[RegisterRelation], dict[str, Any]], *, deadline: float,
    candidate_normalization: Mapping[int, int] | None,
    try_register_proposals: bool = True,
) -> LoopRelationComparison:
    """Compare identity, verified constants, then other register relations.

    Synthesis never grants a verdict. The candidate lowerer must apply the
    proposed relation only at interior inputs and continuing outputs; entry
    inputs, final outputs and entry backedges retain identity. Memory, flags,
    segments and control still participate in every solver obligation.
    """
    owners = proof_owners()
    adapter, catalog, verdict = owners.model, owners.catalog, owners.verdict
    status, compared, verdicts = compare_attempt(
        oracle_ssa, candidate_ssa, deadline, adapter, catalog, verdict,
        candidate_normalization=candidate_normalization,
    )
    count = len(oracle_ssa['functions'])
    attempts = [attempt_record(IDENTITY_RELATION, status, compared, verdicts, count)]
    selected: RegisterRelation = IDENTITY_RELATION
    if status in {Status.PASSED, Status.CONDITIONAL}:
        return LoopRelationComparison(status, compared, verdicts, candidate_ssa, selected, attempts)
    # Constants proved from entry and every incoming edge directly discharge
    # scratch-coordinate mismatches; try them before unrelated projections.
    projection = constant_register_projection(oracle_ssa, candidate_ssa, deadline=deadline)
    if projection is not None:
        projected_original, projected_candidate, evidence = projection
        projected_status, projected_compare, projected_verdicts = compare_attempt(
            projected_original, projected_candidate, deadline, adapter, catalog, verdict,
            candidate_normalization=candidate_normalization,
        )
        record = attempt_record(IDENTITY_RELATION, projected_status, projected_compare, projected_verdicts, count)
        record["constant_register_invariants"] = evidence
        if projected_status in {Status.PASSED, Status.CONDITIONAL}:
            attempts.append(record)
            return LoopRelationComparison(
                projected_status, projected_compare, projected_verdicts, projected_candidate, selected, attempts,
                projected_oracle=projected_original, constant_invariants=evidence,
            )
        attempts[0]["constant_projection_attempt"] = record
    dead_projection = dead_flag_projection(
        oracle_ssa, candidate_ssa, deadline=deadline, candidate_normalization=candidate_normalization,
    )
    if dead_projection is not None:
        projected_original, projected_candidate, evidence_flags = dead_projection
        projected_status, projected_compare, projected_verdicts = compare_attempt(
            projected_original, projected_candidate, deadline, adapter, catalog, verdict,
            candidate_normalization=candidate_normalization,
        )
        record = attempt_record(IDENTITY_RELATION, projected_status, projected_compare, projected_verdicts, count)
        record["dead_flag_projection"] = evidence_flags
        if projected_status in {Status.PASSED, Status.CONDITIONAL}:
            attempts.append(record)
            return LoopRelationComparison(
                projected_status, projected_compare, projected_verdicts, projected_candidate, selected, attempts,
                projected_oracle=projected_original, dead_flags=evidence_flags,
            )
        attempts[0]["dead_flag_projection_attempt"] = record
    interior = _compare_interior_projections(
        oracle_ssa, candidate_ssa, dead_projection, attempts,
        deadline=deadline, candidate_normalization=candidate_normalization,
    )
    if interior is not None:
        return interior
    baseline = LoopRelationComparison(status, compared, verdicts, candidate_ssa, selected, attempts)
    if try_register_proposals:
        baseline = _compare_register_proposals(
            oracle_ssa, candidate_ssa, lower_candidate, baseline,
            deadline=deadline, candidate_normalization=candidate_normalization,
        )
    return _compare_dead_registers(
        oracle_ssa, candidate_ssa, baseline,
        deadline=deadline, candidate_normalization=candidate_normalization,
    )



def _compare_dead_registers(
    oracle_ssa: dict[str, Any], candidate_ssa: dict[str, Any], baseline: LoopRelationComparison,
    *, deadline: float, candidate_normalization: Mapping[int, int] | None,
) -> LoopRelationComparison:
    """Try broader liveness only after established proof strategies have failed."""
    if baseline.status in {Status.PASSED, Status.CONDITIONAL}:
        return baseline
    owners = proof_owners()
    adapter, catalog, verdict = owners.model, owners.catalog, owners.verdict
    count = len(oracle_ssa["functions"])
    selected = IDENTITY_RELATION
    dead_registers = dead_register_projection(
        oracle_ssa, candidate_ssa, deadline=deadline, candidate_normalization=candidate_normalization,
    )
    if dead_registers is not None:
        original, candidate, evidence = dead_registers
        status, compared, verdicts = compare_attempt(
            original, candidate, deadline, adapter, catalog, verdict,
            candidate_normalization=candidate_normalization,
        )
        record = attempt_record(selected, status, compared, verdicts, count)
        record["dead_register_projection"] = evidence
        baseline.attempts[0]["dead_register_projection_attempt"] = record
        if status in {Status.PASSED, Status.CONDITIONAL}:
            baseline.attempts.append(record)
            return LoopRelationComparison(
                status, compared, verdicts, candidate, selected, baseline.attempts,
                projected_oracle=original, dead_registers=evidence,
            )
    return baseline


def _compare_interior_projections(
    oracle_ssa: dict[str, Any], candidate_ssa: dict[str, Any],
    dead_projection: tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None,
    attempts: list[dict[str, Any]], *, deadline: float,
    candidate_normalization: Mapping[int, int] | None,
) -> LoopRelationComparison | None:
    """Try proved interior frame/bit relations, retaining unsuccessful evidence."""
    owners = proof_owners()
    adapter, catalog, verdict = owners.model, owners.catalog, owners.verdict
    count = len(oracle_ssa["functions"])
    selected = IDENTITY_RELATION
    narrow_source = dead_projection[:2] if dead_projection is not None else (oracle_ssa, candidate_ssa)
    # Frame invariants are proved in literal coordinates even when another
    # comparison attempt was offered a relocation premise. Tagged/re-written
    # SSA is still rejected by the frame proof owner.
    frame = frame_invariant_projection(*narrow_source, deadline=deadline)
    if frame is not None:
        frame_original, frame_candidate, frame_evidence = frame
        frame_status, frame_compare, frame_verdicts = compare_attempt(
            frame_original, frame_candidate, deadline, adapter, catalog, verdict,
        )
        frame_evidence["comparison_coordinates"] = "literal"
        frame_evidence["requested_normalization_used"] = False
        # The public caller still publishes its requested relocation premise.
        # Keep that declared domain conditional even though this check is stronger.
        if frame_status == Status.PASSED and candidate_normalization:
            frame_status = Status.CONDITIONAL
        record = attempt_record(IDENTITY_RELATION, frame_status, frame_compare, frame_verdicts, count)
        record["frame_invariants"] = frame_evidence
        attempts[0]["frame_invariant_attempt"] = record
        if frame_status in {Status.PASSED, Status.CONDITIONAL}:
            attempts.append(record)
            return LoopRelationComparison(
                frame_status, frame_compare, frame_verdicts, frame_candidate, selected, attempts,
                projected_oracle=frame_original, frame_invariants=frame_evidence,
                dead_flags=dead_projection[2] if dead_projection is not None else {},
            )
    # Do not transport a literal frame invariant into normalized bit proofs.
    # Such a composed relation needs its own preservation obligations.
    if candidate_normalization:
        frame = None
    if frame is not None:
        narrow_source = frame[:2]
    narrow = narrow_register_projection(
        *narrow_source, deadline=deadline, candidate_normalization=candidate_normalization,
    )
    if narrow is not None:
        narrow_original, narrow_candidate, narrow_evidence = narrow
        narrow_status, narrow_compare, narrow_verdicts = compare_attempt(
            narrow_original, narrow_candidate, deadline, adapter, catalog, verdict,
            candidate_normalization=candidate_normalization,
        )
        record = attempt_record(IDENTITY_RELATION, narrow_status, narrow_compare, narrow_verdicts, count)
        record["narrow_register_projection"] = narrow_evidence
        record["frame_invariants"] = frame[2] if frame is not None else {}
        attempts[0]["narrow_projection_attempt"] = record
        if narrow_status in {Status.PASSED, Status.CONDITIONAL}:
            attempts.append(record)
            return LoopRelationComparison(
                narrow_status, narrow_compare, narrow_verdicts, narrow_candidate, selected, attempts,
                projected_oracle=narrow_original, narrow_registers=narrow_evidence,
                frame_invariants=frame[2] if frame is not None else {},
                dead_flags=dead_projection[2] if dead_projection is not None else {},
            )
    return None



def _compare_register_proposals(
    oracle_ssa: dict[str, Any], candidate_ssa: dict[str, Any],
    lower_candidate: Callable[[RegisterRelation], dict[str, Any]],
    baseline: LoopRelationComparison, *, deadline: float,
    candidate_normalization: Mapping[int, int] | None,
) -> LoopRelationComparison:
    """Check bounded coordinate proposals using the same full projection pipeline."""
    adapter = proof_owners().model
    initial = _initial_state(_register_widths())
    original_entry, rebuilt_entry = oracle_ssa["functions"][0], candidate_ssa["functions"][0]
    original = compose_block_outputs(original_entry, original_entry["outputs"], initial)
    rebuilt = compose_block_outputs(rebuilt_entry, rebuilt_entry["outputs"], initial)
    eligible = {name: width for name, width in adapter.REG32.values() if name in adapter.GPRS and name != "esp"}
    proposal = propose_entry_relation(original, rebuilt, eligible)
    proposals: list[RegisterRelation] = []
    if proposal.relation is not None and not proposal.relation.is_identity:
        proposals.append(proposal.relation)
    proposals.extend(relation for relation in propose_entry_swaps(original, rebuilt, eligible)
                     if relation not in proposals)
    proposals.extend(relation for relation in propose_entry_cycles(
        original, rebuilt, eligible, candidate_normalization,
    ) if relation not in proposals)
    attempts = baseline.attempts
    selected = replace(baseline, proposal_reason=proposal.reason)
    for relation in proposals:
        try:
            related = lower_candidate(relation)
            checked = compare_loop_relations(
                oracle_ssa, related, lower_candidate, deadline=deadline,
                candidate_normalization=candidate_normalization, try_register_proposals=False,
            )
            record = attempt_record(relation, checked.status, checked.compared, checked.verdicts,
                                    len(oracle_ssa["functions"]))
            record["composed_relation_attempts"] = checked.attempts
            attempts.append(record)
            selected = replace(checked, relation=relation, attempts=attempts, proposal_reason=proposal.reason)
            if selected.status in {Status.PASSED, Status.CONDITIONAL}:
                return selected
        except (CallCompositionRefusal, RegisterRelationRefusal) as error:
            attempts.append(attempt_record(relation, Status.REFUSED, {"reason": str(error)}, [],
                                           len(oracle_ssa["functions"])))
    return selected
