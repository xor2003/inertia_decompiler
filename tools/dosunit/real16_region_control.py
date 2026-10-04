"""Resolve region control only after full-width universal target proofs.

Layer: dosunit relational region proof.
Responsibility: reuse the acyclic composer's destination theorem for region
and macro transitions. Metadata proposes physical successors; every symbolic
arm must equal one proposal for every architectural entry selector. The
original deadline, term and composition limits remain binding. Only control
and its separately proved legacy projection may be reified; data, stored
addresses and return state remain unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from tools.dosunit.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.real16_call_contracts import (
    ComposeSession,
    FunctionCtx,
    Real16CallRefusal,
    const_term,
    prove_terms_equal,
    term_nodes,
)
from tools.dosunit.real16_control_resolution import prove_control_destination
from tools.dosunit.real16_loop_invariants import loop_entry_domain

type Term = dict[str, Any]


class RegionControlReason(StrEnum):
    """Unresolved control obligations that must stop region admission."""

    UNPROVED = "region_control_destination_unproved"
    SHAPE = "unsupported_control_transfer"
    PROJECTION = "legacy_control_projection_unproved"


@dataclass(frozen=True, slots=True)
class RegionControlProof:
    """Retain original/canonical control and closed leaf proof accounting."""

    original: Term
    resolved: Term
    counters: FactCounters


def _literal(value: int) -> Term:
    """Emit a proved physical control value at its full architectural width."""
    return {"op": "const", "width": 32, "value": hex(value)}


def _resolve_leaf(
    term: Term, candidates: frozenset[int], ctx: FunctionCtx, session: ComposeSession,
) -> Term:
    """Keep exact literals; prove symbolic proposals using the shared deadline."""
    literal = const_term(term)
    if literal is not None:
        if literal not in candidates:
            raise Real16CallRefusal("successor_outside_region", {"linear": literal})
        return _literal(literal)
    for candidate in sorted(candidates):
        session.bump()
        session.stats["region_control_solver_queries"] = session.stats.get("region_control_solver_queries", 0) + 1
        maximum = session.remaining_ms(session.limits.ret_check_timeout_ms)
        deadline = session.stats["deadline"]
        assert isinstance(deadline, float)  # remaining_ms validates the session.
        proof = prove_control_destination(
            term, candidate, ctx.entry_linear, deadline=deadline,
            max_solver_ms=maximum,
        )
        session.remaining_ms(maximum)
        if proof.status is ProofStatus.PROVED:
            return _literal(candidate)
    raise Real16CallRefusal(
        RegionControlReason.UNPROVED.value,
        {"function": ctx.function_id, "candidates": sorted(candidates)},
    )


def _resolve_control(
    term: Term, candidates: frozenset[int], ctx: FunctionCtx, session: ComposeSession,
    counts: list[int],
) -> Term:
    """Preserve ordered guards while independently proving every destination arm."""
    session.bump()
    if term.get("width") != 32:
        counts[0] += 1
        raise Real16CallRefusal(RegionControlReason.SHAPE.value)
    if term.get("op") == "ite":
        args = term.get("args")
        if not isinstance(args, list) or len(args) != 3:
            counts[0] += 1
            raise Real16CallRefusal(RegionControlReason.SHAPE.value)
        if not all(isinstance(arg, dict) for arg in args):
            counts[0] += 1
            raise Real16CallRefusal(RegionControlReason.SHAPE.value)
        return {
            "op": "ite", "width": 32,
            "args": [args[0], _resolve_control(args[1], candidates, ctx, session, counts),
                     _resolve_control(args[2], candidates, ctx, session, counts)],
        }
    counts[0] += 1
    resolved = _resolve_leaf(term, candidates, ctx, session)
    counts[1] += 1
    return resolved


def resolve_region_control(
    term: Term, candidates: frozenset[int], ctx: FunctionCtx, session: ComposeSession,
) -> RegionControlProof:
    """Resolve complete continuing control without assuming a nominal selector.

    All successful leaves retain five-stage accounting in the shared session;
    refusals record examined/unmaterialized leaves before propagating. Constant
    and ITE fast paths perform no new Z3 work. Symbolic proposals consume the
    existing composition budget rather than creating a fresh solver deadline.
    """
    if term_nodes(term, session.limits.max_term_nodes) > session.limits.max_term_nodes:
        raise Real16CallRefusal("compose_budget_exceeded", {"counter": "term_nodes"})
    counts = [0, 0]
    try:
        resolved = _resolve_control(term, candidates, ctx, session, counts)
    finally:
        raw, materialized = counts
        for name, count in (
            ("raw_fact_count", raw), ("normalized_fact_count", raw),
            ("classified_fact_count", raw), ("materialized_count", materialized),
            ("failure_count", raw - materialized),
        ):
            key = f"region_control_{name}"
            session.stats[key] = session.stats.get(key, 0) + count
    counters = FactCounters(counts[0], counts[0], counts[0], counts[1], 0)
    return RegionControlProof(term, resolved, counters)


def resolve_region_poststate(
    state: dict[str, Term], candidates: frozenset[int], ctx: FunctionCtx,
    session: ComposeSession,
) -> dict[str, Term]:
    """Reify only proved continuing control and its validated word projection.

    Return states never use this helper. Register/memory values containing
    control-like addresses remain the exact original terms. Even a proved
    physical destination cannot conceal an inconsistent legacy IP output.
    """
    control = state.get("control_ip")
    legacy = state.get("ip")
    if control is None or legacy is None:
        raise Real16CallRefusal(RegionControlReason.SHAPE.value)
    proof = resolve_region_control(control, candidates, ctx, session)
    projection: Term = {"op": "trunc", "width": 16, "args": [control]}
    status = ProofStatus.UNKNOWN
    try:
        status = _projection_status(legacy, control, projection, ctx, session)
    finally:
        for name, count in (
            ("raw_fact_count", 1), ("normalized_fact_count", 1),
            ("classified_fact_count", 1), ("materialized_count", int(status is ProofStatus.PROVED)),
            ("failure_count", int(status is not ProofStatus.PROVED)),
        ):
            key = f"region_control_projection_{name}"
            session.stats[key] = session.stats.get(key, 0) + count
    if status is not ProofStatus.PROVED:
        raise Real16CallRefusal(RegionControlReason.PROJECTION.value)
    return {**state, "control_ip": proof.resolved,
            "ip": {"op": "trunc", "width": 16, "args": [proof.resolved]}}


def _projection_status(
    legacy: Term, control: Term, projection: Term, ctx: FunctionCtx,
    session: ComposeSession,
) -> ProofStatus:
    """Check the word projection with cheap exact literals before bounded Z3."""
    if legacy.get("width") != 16:
        return ProofStatus.UNKNOWN
    if term_nodes([legacy, control], session.limits.max_term_nodes) > session.limits.max_term_nodes:
        raise Real16CallRefusal("compose_budget_exceeded", {"counter": "term_nodes"})
    if legacy == projection:
        return ProofStatus.PROVED
    legacy_literal, control_literal = const_term(legacy), const_term(control)
    if legacy_literal is not None and control_literal is not None:
        return ProofStatus.PROVED if legacy_literal == control_literal & 0xFFFF else ProofStatus.UNKNOWN
    maximum = session.remaining_ms(session.limits.ret_check_timeout_ms)
    status = prove_terms_equal(
        legacy, projection, maximum,
        input_constraints=loop_entry_domain(ctx).constraints(),
    )
    session.remaining_ms(maximum)
    return status
