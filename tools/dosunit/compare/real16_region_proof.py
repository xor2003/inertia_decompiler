"""Closed real16 relational induction modulo finite CFG reblocking.

Layer: dosunit whole-function proof.
Responsibility: consume complete binary SSA and finite paired graph proposals,
prove every full-state superblock transition with Z3, and retain dependency,
control-relation, progress and missing-obligation evidence in a typed report.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any

from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.memory_invariant_obligations import (
    MemoryInvariantObligation,
    MemoryInvariantProof,
    prove_fixed_point,
)
from tools.dosunit.compare.memory_invariant_proposals import MemoryInvariantProposalReason
from tools.dosunit.compare.memory_relation_proposals import MemoryProposalReason
from tools.dosunit.compare.paired_region_graph import (
    RegionExitKind,
    RegionGraphRefusal,
)
from tools.dosunit.compare.real16_call_contracts import (
    ComposeSession,
    FunctionCtx,
    Real16CallLimits,
    Real16CallRefusal,
    initial_state,
    materialize_function,
)
from tools.dosunit.compare.real16_call_evidence import (
    check_lowering_refusals,
    dependencies_for,
    group_lookup,
    reachable_call_ids,
)
from tools.dosunit.compare.real16_loop_invariants import loop_entry_domain
from tools.dosunit.compare.real16_memory_relations import MemoryRetryResult, try_entry_memory_relations
from tools.dosunit.compare.real16_region_transitions import compose_region, region_nodes, related_outputs
from tools.dosunit.compare.region_pairing import (
    RegionLayout,
    RegionPairingDiagnostics,
    RegionPairingEvidence,
    propose_region_pairings,
)
from tools.dosunit.contracts.cutpoint_state_relations import CutpointRelation, CutpointStateRelation
from tools.dosunit.contracts.memory_state_invariants import MemoryInvariant, MemoryInvariantRefusal
from tools.dosunit.contracts.memory_state_relations import MemoryRelationRefusal
from tools.dosunit.contracts.proof_contracts import FactCounters, ProofStatus, proof_status_from_legacy
from tools.dosunit.contracts.proof_scope import ProofScope, admit_scope_status
from tools.dosunit.contracts.register_affine_relations import (
    RegisterAffineRelation,
    StateRelationProposal,
    propose_entry_relation,
)
from tools.dosunit.contracts.register_state_relations import (
    IDENTITY_RELATION,
    RegisterPermutation,
    RegisterRelationReason,
    RegisterRelationRefusal,
)


class RegionProofReason(StrEnum):
    """The discharged relation or exact class of outstanding obligation."""

    PROVED = "paired_region_transitions_proved"
    REGISTERS = "paired_register_region_transitions_proved"
    AFFINE = "paired_affine_region_transitions_proved"
    MEMORY = "paired_memory_region_transitions_proved"
    GRAPH = "paired_region_graph_unproved"
    DOMAIN = "paired_region_entry_unproved"
    TRANSITION = "paired_region_transition_unproved"
    ADMISSION = "paired_region_admission_refused"


class RegionObligation(StrEnum):
    """State-relation proof obligations carried by a paired transition."""

    INITIATION = "initiation"
    PRESERVATION = "preservation"
    EXIT = "exit"
    INVARIANT_INITIATION = "memory_invariant_initiation"
    INVARIANT_PRESERVATION = "memory_invariant_preservation"


@dataclass(frozen=True, slots=True)
class RegionTransitionProof:
    """One paired cutpoint with finite progress and full-state solver evidence."""

    index: int
    oracle_members: tuple[int, ...]
    candidate_members: tuple[int, ...]
    status: ProofStatus
    diagnostics: dict[str, Any]
    obligations: tuple[RegionObligation, ...] = ()
    invariant_proof: MemoryInvariantProof | None = None
    state_status: ProofStatus | None = None


@dataclass(frozen=True, slots=True)
class RegionRelationAttempt:
    """One proposed relation and every checked transition, including refusals."""

    relation: CutpointRelation
    status: ProofStatus
    transitions: tuple[RegionTransitionProof, ...]
    counters: FactCounters
    invariant: MemoryInvariant | None = None
    graph_evidence: RegionPairingEvidence | None = None
    pairs: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True, slots=True)
class RegionProof:
    """Complete induction accounting and explicit control/register relations."""

    status: ProofStatus
    reason: RegionProofReason
    transitions: tuple[RegionTransitionProof, ...]
    counters: FactCounters
    dependencies: tuple[dict[str, Any], ...] = ()
    entry_domain: tuple[int, int] | None = None
    detail: str = ""
    relation: CutpointRelation = IDENTITY_RELATION
    attempts: tuple[RegionRelationAttempt, ...] = ()
    proposal_reason: RegisterRelationReason | None = None
    graph_evidence: RegionPairingEvidence | None = None
    memory_proposal_reason: MemoryProposalReason | None = None
    invariant: MemoryInvariant | None = None
    invariant_proposal_reason: MemoryInvariantProposalReason | None = None
    graph_search: RegionPairingDiagnostics | None = None


def _common_domain(left: FunctionCtx, right: FunctionCtx) -> tuple[int, int]:
    """Require a nonempty selector interval admitted by both physical entries."""
    original, rebuilt = loop_entry_domain(left), loop_entry_domain(right)
    minimum = max(original.minimum_cs, rebuilt.minimum_cs)
    maximum = min(original.maximum_cs, rebuilt.maximum_cs)
    if minimum > maximum:
        raise Real16CallRefusal("code_entry_relation_empty")
    return minimum, maximum


def _tokens(partition: RegionLayout, ordered: tuple[int, ...]) -> dict[int, int]:
    """Bind physical region heads to their paired transition index."""
    return {partition.regions[region].members[0]: index for index, region in enumerate(ordered)}


def _compare_rows(
    left_contexts: dict[str, FunctionCtx], left: FunctionCtx, left_partition: RegionLayout,
    right_contexts: dict[str, FunctionCtx], right: FunctionCtx, right_partition: RegionLayout,
    pairs: tuple[tuple[int, int], ...], domain: tuple[int, int],
    sessions: tuple[ComposeSession, ComposeSession], timeout_ms: int,
    relation: CutpointRelation = IDENTITY_RELATION,
    *, invariant: MemoryInvariant | None = None,
) -> tuple[RegionTransitionProof, ...]:
    """Prove initiation, interior preservation and final state identity."""
    left_tokens = _tokens(left_partition, tuple(original for original, _ in pairs))
    right_tokens = _tokens(right_partition, tuple(rebuilt for _, rebuilt in pairs))
    constraints = [{"name": "cs", "kind": "unsigned_range", "min": domain[0], "max": domain[1]}]
    limits = sessions[0].limits
    rows: list[RegionTransitionProof] = []
    for index, (original, rebuilt) in enumerate(pairs):
        left_region, right_region = left_partition.regions[original], right_partition.regions[rebuilt]
        oracle_incoming = invariant.apply(initial_state()) if index and invariant is not None else None
        left_state = compose_region(sessions[0], left_contexts, left, left_region, incoming=oracle_incoming)
        incoming = relation.candidate_inputs(oracle_incoming if oracle_incoming is not None else initial_state()) if index else None
        right_state = compose_region(sessions[1], right_contexts, right, right_region, incoming=incoming)
        left_output = related_outputs(left_state, left_region, left_tokens, sessions[0].remaining_ms(timeout_ms))
        right_output = related_outputs(right_state, right_region, right_tokens, sessions[1].remaining_ms(timeout_ms))
        if right_region.kind is not RegionExitKind.RETURN:
            right_output = relation.continuing_outputs(right_output, control_field="paired_control",
                                                      reenters_entry=right.entry_linear in right_region.exits)
        invariant_proof = None
        if invariant is not None and left_region.kind is not RegionExitKind.RETURN:
            obligation = MemoryInvariantObligation.PRESERVATION if index else MemoryInvariantObligation.INITIATION
            invariant_proof = prove_fixed_point(
                invariant, left_output, obligation, timeout_ms=sessions[0].remaining_ms(timeout_ms),
                control_field="paired_control", reenters_entry=left.entry_linear in left_region.exits,
                constraints=constraints,
            )
        left_summary = materialize_function(f"oracle:{index}", left_output)
        right_summary = materialize_function(f"candidate:{index}", right_output)
        gate = S._ssa_solver_gate(
            left_summary, right_summary, max_solver_assignments=limits.max_solver_assignments,
            max_solver_inputs=limits.max_solver_inputs, max_solver_memory_stores=limits.max_solver_memory_stores,
        )
        compared: dict[str, Any] = gate if gate is not None else S._compare_functions(
            left_summary, right_summary, timeout_ms=sessions[0].remaining_ms(timeout_ms), input_constraints=constraints,
        )
        status = proof_status_from_legacy(compared.get("status")) or ProofStatus.UNKNOWN
        status = admit_scope_status(status, ProofScope.CUTPOINT_SIMULATION)
        if status is not ProofStatus.PROVED or compared.get("skipped_layout_outputs"):
            status = ProofStatus.UNKNOWN
        state_status = status
        if invariant_proof is not None and invariant_proof.status is not ProofStatus.PROVED:
            status = ProofStatus.UNKNOWN
        obligations: tuple[RegionObligation, ...] = (RegionObligation.INITIATION,) if index == 0 else (RegionObligation.PRESERVATION,)
        if right_region.kind is RegionExitKind.RETURN:
            obligations += (RegionObligation.EXIT,)
        if invariant_proof is not None:
            obligations += (RegionObligation.INVARIANT_PRESERVATION if index else RegionObligation.INVARIANT_INITIATION,)
        rows.append(RegionTransitionProof(index, left_region.members, right_region.members, status, compared,
                                          obligations, invariant_proof, state_status))
    S._compose_deadline_check(sessions[0].stats)
    S._compose_deadline_check(sessions[1].stats)
    return tuple(rows)


def _attempt(relation: CutpointRelation, rows: tuple[RegionTransitionProof, ...],
             invariant: MemoryInvariant | None = None) -> RegionRelationAttempt:
    """Account for every required transition independently of rejected proposals."""
    failures = sum((row.state_status if row.state_status is not None else row.status) is not ProofStatus.PROVED for row in rows)
    failures += sum(row.invariant_proof is not None and row.invariant_proof.status is not ProofStatus.PROVED for row in rows)
    count = len(rows) + sum(row.invariant_proof is not None for row in rows)
    return RegionRelationAttempt(relation, ProofStatus.PROVED if count and not failures else ProofStatus.UNKNOWN,
                                 rows, FactCounters(count, count, count, count, failures), invariant)


def _register_proposal(
    left_contexts: dict[str, FunctionCtx], left: FunctionCtx, left_partition: RegionLayout,
    right_contexts: dict[str, FunctionCtx], right: FunctionCtx, right_partition: RegionLayout,
    pairs: tuple[tuple[int, int], ...], sessions: tuple[ComposeSession, ComposeSession],
) -> StateRelationProposal:
    """Derive one unique register proposal from actual entry-region SSA effects."""
    original = compose_region(sessions[0], left_contexts, left, left_partition.regions[pairs[0][0]])
    rebuilt = compose_region(sessions[1], right_contexts, right, right_partition.regions[pairs[0][1]])
    eligible = {"ax", "bx", "cx", "dx", "si", "di", "bp", *S.HIGH_HALF_REGS}
    widths = {name: width for name, width in S._ssa_register_widths().items() if name in eligible}
    return propose_entry_relation(original, rebuilt, widths)


type RegionInputs = tuple[dict[str, FunctionCtx], FunctionCtx, RegionLayout]


def _prove_memory_relations(
    original_inputs: RegionInputs, rebuilt_inputs: RegionInputs,
    pairs: tuple[tuple[int, int], ...], domain: tuple[int, int],
    sessions: tuple[ComposeSession, ComposeSession], timeout_ms: int,
    attempts: list[RegionRelationAttempt],
) -> MemoryRetryResult:
    """Prove finite memory proposals, retaining every completed failed attempt."""
    left_contexts, left, left_partition = original_inputs
    right_contexts, right, right_partition = rebuilt_inputs
    original = compose_region(sessions[0], left_contexts, left, left_partition.regions[pairs[0][0]])
    rebuilt = compose_region(sessions[1], right_contexts, right, right_partition.regions[pairs[0][1]])
    def compare(relation: CutpointStateRelation, invariant: MemoryInvariant | None) -> RegionRelationAttempt:
        """Retain full-state proof and every independently discharged invariant fact."""
        rows = _compare_rows(left_contexts, left, left_partition, right_contexts, right, right_partition,
                             pairs, domain, sessions, timeout_ms, relation, invariant=invariant)
        return _attempt(relation, rows, invariant)
    return try_entry_memory_relations(original, rebuilt, attempts, compare)


def _proved_reason(selected: RegionRelationAttempt) -> RegionProofReason:
    """Describe the discharged state coordinates independently of graph shape."""
    proved_reason = RegionProofReason.PROVED if selected.relation.is_identity else RegionProofReason.REGISTERS
    if isinstance(selected.relation, RegisterAffineRelation) and not selected.relation.is_identity:
        proved_reason = RegionProofReason.AFFINE
    if isinstance(selected.relation, CutpointStateRelation) and not selected.relation.is_identity:
        proved_reason = RegionProofReason.MEMORY
    return proved_reason


def compare_real16_regions(
    oracle: dict[str, Any], candidate: dict[str, Any], function: str, *,
    candidate_function: str | None = None, limits: Real16CallLimits | None = None,
    timeout_ms: int = 30000,
) -> RegionProof:
    """Prove finite reblocking and checked register cutpoint correspondence.

    Related cutpoints follow an explicit loaded PC correspondence and may use
    one uniquely proposed invertible register relation. Entry inputs and final outputs
    retain identity; every interior relation must preserve through full-state
    transitions, including flags, segments, memory, I/O and branch destinations.
    Every transition has finite nonzero progress on each side, so the paired
    steps preserve termination/divergence without iteration unrolling. Stored
    code addresses and stack layouts require separate proved relations. Rejected
    relation attempts remain visible; structural entry matching is never proof.
    """
    bound = limits or Real16CallLimits()
    timeout_ms = max(timeout_ms, 1)
    attempts: list[RegionRelationAttempt] = []
    proposal_reason: RegisterRelationReason | None = None
    graph_evidence: RegionPairingEvidence | None = None
    memory_proposal_reason: MemoryProposalReason | None = None
    invariant_proposal_reason: MemoryInvariantProposalReason | None = None
    graph_search: RegionPairingDiagnostics | None = None
    try:
        left_contexts, left = group_lookup(oracle, function)
        right_contexts, right = group_lookup(candidate, candidate_function or function)
        check_lowering_refusals(oracle, reachable_call_ids(left_contexts, left) | {left.function_id})
        check_lowering_refusals(candidate, reachable_call_ids(right_contexts, right) | {right.function_id})
        domain = _common_domain(left, right)
        sessions = (ComposeSession.with_deadline(bound, timeout_ms), ComposeSession.with_deadline(bound, timeout_ms))
        search = propose_region_pairings(
            region_nodes(left, sessions[0]), region_nodes(right, sessions[1]),
            left.entry_linear, right.entry_linear,
            deadline_seconds=sessions[0].remaining_ms(timeout_ms) / 1000.0,
        )
        graph_search = search.evidence()
        if not search.candidates:
            return RegionProof(ProofStatus.UNKNOWN, RegionProofReason.GRAPH, (),
                               FactCounters(1, 1, 1, 1, 1), graph_search=graph_search)
        for graph in search.candidates:
            attempt_start = len(attempts)
            graph_evidence = graph.evidence
            left_partition, right_partition, pairs = graph.oracle, graph.candidate, graph.pairs
            rows = _compare_rows(left_contexts, left, left_partition, right_contexts, right, right_partition,
                                 pairs, domain, sessions, timeout_ms)
            attempts.append(_attempt(RegisterPermutation(), rows))
            if attempts[-1].status is not ProofStatus.PROVED:
                proposal = _register_proposal(left_contexts, left, left_partition, right_contexts, right, right_partition,
                                             pairs, sessions)
                proposal_reason = proposal.reason
                if proposal.relation is not None and not proposal.relation.is_identity:
                    rows = _compare_rows(left_contexts, left, left_partition, right_contexts, right, right_partition,
                                         pairs, domain, sessions, timeout_ms, proposal.relation)
                    attempts.append(_attempt(proposal.relation, rows))
            if attempts[-1].status is not ProofStatus.PROVED:
                memory_retry = _prove_memory_relations(
                    (left_contexts, left, left_partition), (right_contexts, right, right_partition),
                    pairs, domain, sessions, timeout_ms, attempts,
                )
                memory_proposal_reason = memory_retry.memory_reason
                invariant_proposal_reason = memory_retry.invariant_reason
            attempts[attempt_start:] = [replace(attempt, graph_evidence=graph.evidence, pairs=graph.pairs)
                                        for attempt in attempts[attempt_start:]]
            if attempts[-1].status is ProofStatus.PROVED:
                break
        dependencies = ({"side": "oracle", **dependencies_for(oracle, function)},
                        {"side": "candidate", **dependencies_for(candidate, candidate_function or function)})
    except RegionGraphRefusal as error:
        return RegionProof(ProofStatus.UNKNOWN, RegionProofReason.GRAPH, (), FactCounters(1, 1, 1, 1, 1),
                           detail=error.reason.value, attempts=tuple(attempts), graph_search=graph_search)
    except (Real16CallRefusal, S.LowerFailure, RegisterRelationRefusal, MemoryRelationRefusal, MemoryInvariantRefusal) as error:
        return RegionProof(ProofStatus.UNKNOWN, RegionProofReason.ADMISSION, (), FactCounters(1, 1, 1, 1, 1),
                           detail=str(error), attempts=tuple(attempts), proposal_reason=proposal_reason,
                           graph_evidence=graph_evidence, graph_search=graph_search)
    selected = attempts[-1]
    proved_reason = _proved_reason(selected)
    return RegionProof(selected.status, proved_reason if selected.status is ProofStatus.PROVED else RegionProofReason.TRANSITION,
                       selected.transitions, selected.counters, dependencies, domain,
                       relation=selected.relation, attempts=tuple(attempts), proposal_reason=proposal_reason,
                       graph_evidence=graph.evidence, memory_proposal_reason=memory_proposal_reason,
                       invariant=selected.invariant, invariant_proposal_reason=invariant_proposal_reason, graph_search=graph_search)
