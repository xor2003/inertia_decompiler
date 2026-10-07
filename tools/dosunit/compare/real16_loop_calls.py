"""Closed matched-loop induction with actual acyclic callee effects.

Layer: dosunit relational loop proofs.
Responsibility: discharge every full-state transition in a closed matched
region, composing direct calls through checked complete callee bodies rather
than assuming equal call targets imply equal post-call state. Proof is over
related function inputs; initialized-image admission is a separate obligation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.real16_call_boundary import compose_call_poststate
from tools.dosunit.compare.real16_call_contracts import (
    ComposeSession,
    FunctionCtx,
    Real16CallLimits,
    Real16CallRefusal,
    initial_state,
    materialize_function,
)
from tools.dosunit.compare.real16_call_evidence import (
    block_source,
    check_lowering_refusals,
    dependencies_for,
    group_lookup,
    reachable_call_ids,
)
from tools.dosunit.compare.real16_call_execution import compose_entry
from tools.dosunit.compare.real16_loop_invariants import (
    check_cutpoint_state,
    check_physical_successors,
    loop_entry_domain,
)
from tools.dosunit.contracts.proof_contracts import FactCounters, ProofStatus, proof_status_from_legacy


class LoopCallReason(StrEnum):
    """The exact induction obligation discharged or left incomplete."""

    TRANSITIONS_PROVED = "call_loop_transitions_proved"
    ENTRY_RELATION = "call_loop_entry_relation_unproved"
    MATCHED_CUTPOINTS = "call_loop_cutpoints_unmapped"
    CONTROL_CLOSURE = "call_loop_control_not_closed"
    TRANSITION = "call_loop_transition_unproved"
    CALLEE = "call_loop_callee_unproved"


class TransitionReason(StrEnum):
    """Machine obligation for one matched transition."""

    STATE_RELATION = "full_state_transition_relation"
    CONTROL_RELATION = "control_edge_relation_unproved"
    CALLEE_RELATION = "callee_transition_unproved"


@dataclass(frozen=True)
class LoopTransitionProof:
    """Typed verdict plus boundary diagnostics for one cutpoint step."""

    delta: int
    status: ProofStatus
    reason: TransitionReason
    diagnostics: dict[str, Any]


@dataclass(frozen=True)
class LoopCallProof:
    """A whole closed-region proof with complete per-transition accounting."""

    status: ProofStatus
    reason: LoopCallReason
    transitions: tuple[LoopTransitionProof, ...]
    dependencies: tuple[dict[str, Any], ...]
    counters: FactCounters
    detail: str = ""


def _check_graph(ctx: FunctionCtx) -> None:
    """Require direct closed successors or modeled normal return exits."""
    if 0 not in ctx.blocks:
        raise Real16CallRefusal("entry_block_unmapped", {"function": ctx.function_id})
    for delta, block in ctx.blocks.items():
        kind = block_source(block).get("jumpkind")
        successors = S._direct_successor_delta_set(block)
        if kind not in {"Ijk_Call", "Ijk_Boring", "Ijk_Ret"}:
            raise Real16CallRefusal("unsupported_exit", {"delta": delta})
        if kind != "Ijk_Ret" and not successors:
            raise Real16CallRefusal("successor_outside_region", {"delta": delta})
        if not successors <= set(ctx.blocks):
            raise Real16CallRefusal("successor_outside_region", {"delta": delta})
        if kind != "Ijk_Ret":
            check_physical_successors(ctx, block_source(block))


def _call_summary(
    session: ComposeSession, contexts: dict[str, FunctionCtx], ctx: FunctionCtx,
    delta: int, block: dict[str, Any],
) -> dict[str, Any]:
    """Publish one call transition after proving its actual return frame."""
    outputs = block.get("outputs")
    state = S._compose_block_outputs(block, outputs if isinstance(outputs, dict) else {},
                                     initial_state(), compose_stats=session.stats)
    post = compose_call_poststate(session, contexts, ctx, delta, block, state,
                                  frozenset({ctx.entry_linear}), 0, compose_entry)
    observed = dict(post.state)
    check_cutpoint_state(ctx, observed, continuing=True, timeout_ms=session.limits.ret_check_timeout_ms)
    return materialize_function(f"transition:{ctx.function_id}:{delta}", observed)


def _compare_call_transition(
    oracle: dict[str, Any], candidate: dict[str, Any], limits: Real16CallLimits, timeout_ms: int,
    ctx: FunctionCtx,
) -> dict[str, Any]:
    """Compare complete call post-state without caller-byte quick equality."""
    gate = S._ssa_solver_gate(
        oracle, candidate, max_solver_assignments=limits.max_solver_assignments,
        max_solver_inputs=limits.max_solver_inputs,
        max_solver_memory_stores=limits.max_solver_memory_stores,
    )
    compared: dict[str, Any] = gate if gate is not None else S._compare_functions(
        oracle, candidate, timeout_ms=timeout_ms, input_constraints=loop_entry_domain(ctx).constraints(),
    )
    return compared


def _step_summary(
    block: dict[str, Any], session: ComposeSession, label: str, ctx: FunctionCtx,
) -> dict[str, Any]:
    """Retain all state and explicit control without heuristic layout mapping."""
    outputs = block.get("outputs")
    state = S._compose_block_outputs(
        block, outputs if isinstance(outputs, dict) else {}, initial_state(),
        compose_stats=session.stats,
    )
    check_cutpoint_state(ctx, state, continuing=block_source(block).get("jumpkind") != "Ijk_Ret",
                         timeout_ms=session.limits.ret_check_timeout_ms)
    return materialize_function(label, state)


def _transition_verdict(delta: int, compared: dict[str, Any]) -> LoopTransitionProof:
    """Convert legacy solver diagnostics at the boundary; SAT stays incomplete."""
    status = proof_status_from_legacy(compared.get("status")) or ProofStatus.UNKNOWN
    if status is ProofStatus.COUNTEREXAMPLE:
        status = ProofStatus.UNKNOWN
    return LoopTransitionProof(delta, status, TransitionReason.STATE_RELATION, compared)


def _compare_transitions(
    oracle_contexts: dict[str, FunctionCtx], oracle_ctx: FunctionCtx,
    candidate_contexts: dict[str, FunctionCtx], candidate_ctx: FunctionCtx,
    limits: Real16CallLimits, timeout_ms: int,
) -> tuple[LoopTransitionProof, ...]:
    """Attempt every matched step over arbitrary related cutpoint states."""
    rows: list[LoopTransitionProof] = []
    original_session = ComposeSession.with_deadline(limits, timeout_ms)
    candidate_session = ComposeSession.with_deadline(limits, timeout_ms)
    deltas = set(oracle_ctx.blocks)
    for delta in sorted(deltas):
        original_session.bump()
        candidate_session.bump()
        left, right = oracle_ctx.blocks[delta], candidate_ctx.blocks[delta]
        kind = block_source(left).get("jumpkind")
        if (kind != block_source(right).get("jumpkind")
                or S._direct_successor_delta_set(left) != S._direct_successor_delta_set(right)):
            rows.append(LoopTransitionProof(delta, ProofStatus.UNKNOWN, TransitionReason.CONTROL_RELATION, {}))
            continue
        if kind == "Ijk_Call":
            try:
                left_summary = _call_summary(original_session, oracle_contexts, oracle_ctx, delta, left)
                right_summary = _call_summary(candidate_session, candidate_contexts, candidate_ctx, delta, right)
                row = _compare_call_transition(left_summary, right_summary, limits, timeout_ms, oracle_ctx)
                rows.append(_transition_verdict(delta, row))
            except (Real16CallRefusal, S.LowerFailure) as error:
                rows.append(LoopTransitionProof(delta, ProofStatus.UNKNOWN,
                                                TransitionReason.CALLEE_RELATION, {"detail": str(error)}))
        else:
            left_summary = _step_summary(left, original_session, f"oracle:{delta}", oracle_ctx)
            right_summary = _step_summary(right, candidate_session, f"candidate:{delta}", candidate_ctx)
            row = _compare_call_transition(left_summary, right_summary, limits, timeout_ms, oracle_ctx)
            rows.append(_transition_verdict(delta, row))
    S._compose_deadline_check(original_session.stats)
    S._compose_deadline_check(candidate_session.stats)
    return tuple(rows)


def compare_real16_loop_calls(
    oracle: dict[str, Any], candidate: dict[str, Any], function: str, *,
    candidate_function: str | None = None, limits: Real16CallLimits | None = None,
    timeout_ms: int = 30000,
) -> LoopCallProof:
    """Prove a closed matched call-containing loop without iteration unrolling.

    Identity relates the complete machine state at every paired cutpoint. The
    first transition proves initiation for all related function inputs; every
    outgoing edge and normal exit is checked. Synchronized steps establish
    equal termination/divergence. A SAT step may be unreachable from entry and
    therefore leaves a missing induction obligation, not a binary counterexample.
    Differing entry layouts currently require a separate relocation relation.
    """
    bound = limits or Real16CallLimits()
    try:
        left_contexts, left = group_lookup(oracle, function)
        right_contexts, right = group_lookup(candidate, candidate_function or function)
        check_lowering_refusals(oracle, reachable_call_ids(left_contexts, left) | {left.function_id})
        check_lowering_refusals(candidate, reachable_call_ids(right_contexts, right) | {right.function_id})
        _check_graph(left)
        _check_graph(right)
        loop_entry_domain(left)
        loop_entry_domain(right)
        if left.entry_linear != right.entry_linear:
            return LoopCallProof(ProofStatus.UNKNOWN, LoopCallReason.ENTRY_RELATION, (), (), FactCounters())
        if set(left.blocks) != set(right.blocks):
            return LoopCallProof(ProofStatus.UNKNOWN, LoopCallReason.MATCHED_CUTPOINTS, (), (), FactCounters())
        transitions = _compare_transitions(left_contexts, left, right_contexts, right, bound, timeout_ms)
        dependencies = ({"side": "oracle", **dependencies_for(oracle, function)},
                        {"side": "candidate", **dependencies_for(candidate, candidate_function or function)})
    except (Real16CallRefusal, S.LowerFailure) as error:
        return LoopCallProof(ProofStatus.UNKNOWN, LoopCallReason.CALLEE, (), (), FactCounters(1,1,1,1,1), str(error))
    failures = sum(row.status is not ProofStatus.PROVED for row in transitions)
    count = len(transitions)
    status = ProofStatus.PROVED if failures == 0 and count > 0 else ProofStatus.UNKNOWN
    reason = LoopCallReason.TRANSITIONS_PROVED if status is ProofStatus.PROVED else LoopCallReason.TRANSITION
    return LoopCallProof(status, reason, transitions, dependencies, FactCounters(count,count,count,count,failures))
