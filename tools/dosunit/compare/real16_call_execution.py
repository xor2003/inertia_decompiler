"""Layer: tools/dosunit real-mode comparator execution.

Responsibility: bounded acyclic composition of real16 full-state SSA blocks
with actual direct-call inlining. Block ``control_ip`` terms live in the lifter's
linear control domain; a near call's ``memory``/``sp`` outputs already encode
the pushed architectural return frame. A callee's composed ``control_ip``
must prove equal to the recorded loader continuation, and its restored CS
must match the actual pre-CALL selector recovered from that frame.  Any missing or unprovable evidence refuses; no summary is
fabricated.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import tools.dosunit.compare.straightline_ssa as S
from tools.dosunit.compare.real16_call_boundary import compose_call_poststate
from tools.dosunit.compare.real16_call_contracts import (
    ComposeSession,
    FunctionCtx,
    Real16CallLimits,
    Real16CallRefusal,
    const_term,
    initial_state,
    prove_terms_equal,
    term_nodes,
)
from tools.dosunit.compare.real16_call_evidence import (
    IndirectTargetResolver,
    block_source,
    block_transfer,
    check_lowering_refusals,
    group_lookup,
    is_indirect_call_site,
    reachable_call_ids,
)
from tools.dosunit.compare.real16_call_indirect import compose_indirect_call_poststate
from tools.dosunit.compare.real16_control_resolution import prove_control_destination
from tools.dosunit.compare.real16_loop_invariants import declared_physical_successors
from tools.dosunit.contracts.proof_contracts import Architecture, ProofStatus
from tools.dosunit.contracts.real16_entry_domain import code_entry_domain

if TYPE_CHECKING:
    from tools.dosunit.contracts.ordered_io_environment import OrderedIoContract


def _delta_for_linear(ctx: FunctionCtx, linear: int) -> int:
    """Exact region-relative difference for a full loaded control target."""
    return linear - ctx.entry_linear


def _walk(
    session: ComposeSession,
    ctxs: dict[str, FunctionCtx],
    ctx: FunctionCtx,
    delta: int,
    state: dict[str, dict[str, Any]],
    visiting: frozenset[int],
    active: frozenset[int],
    depth: int,
    *, return_boundary: bool = False,
) -> dict[str, dict[str, Any]]:
    """Compose an acyclic path; proposed indirect exits require a caller boundary."""
    session.bump()
    block = ctx.blocks.get(delta)
    if block is None:
        raise Real16CallRefusal(
            "successor_outside_region", {"function": ctx.function_id, "delta": delta}
        )
    outputs = block.get("outputs")
    state = S._compose_block_outputs(
        block,
        outputs if isinstance(outputs, dict) else {},
        state,
        compose_stats=session.stats,
    )
    if term_nodes(state, session.limits.max_term_nodes) > session.limits.max_term_nodes:
        raise Real16CallRefusal(
            "compose_budget_exceeded",
            {"counter": "term_nodes", "limit": session.limits.max_term_nodes},
        )
    jumpkind = str(block_source(block).get("jumpkind") or "")
    transfer = block_transfer(block)
    kind = str(transfer.get("kind") or "")
    if jumpkind == "Ijk_Ret":
        return _compose_ret(state)
    if kind == "nonreturning_interrupt":
        raise Real16CallRefusal("unsupported_return_control", {"kind": kind})
    if jumpkind == "Ijk_Call" or kind == "direct_call":
        return _compose_call(session, ctxs, ctx, delta, block, state, visiting, active, depth,
                             return_boundary=return_boundary)
    if jumpkind and jumpkind != "Ijk_Boring":
        raise Real16CallRefusal("unsupported_exit", {"jumpkind": jumpkind})
    return _compose_ip_targets(
        session, ctxs, ctx, state, state.get("control_ip"), block, visiting, active, depth,
        return_boundary=return_boundary,
    )


def _compose_ret(state: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Return the composed callee state; conditional returns refuse."""
    ip = state.get("control_ip")
    if not isinstance(ip, dict):
        raise Real16CallRefusal("return_ip_unobserved")
    if ip.get("op") == "ite":
        raise Real16CallRefusal("unsupported_return_control", {"ip": "conditional"})
    return state


def _compose_ip_targets(
    session: ComposeSession,
    ctxs: dict[str, FunctionCtx],
    ctx: FunctionCtx,
    state: dict[str, dict[str, Any]],
    ip: Any,  # noqa: ANN401
    block: dict[str, Any],
    visiting: frozenset[int],
    active: frozenset[int],
    depth: int,
    *, return_boundary: bool = False,
) -> dict[str, dict[str, Any]]:
    """Follow physical successors or defer a callee's indirect exit to its caller.

    ``return_boundary`` permits publishing complete exit state only for a
    callee whose outer boundary will prove the actual target and CS. It never
    admits a root-level indirect exit or a callback target by equality alone.
    """
    if not isinstance(ip, dict) or ip.get("width") != 32:
        raise Real16CallRefusal("unsupported_control_transfer", {"ip": "full_control_missing"})
    const_value = const_term(ip)
    if const_value is None and isinstance(ip, dict) and ip.get("op") != "ite":
        const_value = _proved_symbolic_successor(session, ctx, ip, block)
    if const_value is not None:
        delta = _delta_for_linear(ctx, const_value)
        declared = {address - ctx.entry_linear for address in
                    declared_physical_successors(ctx, block_source(block))}
        if delta not in declared:
            raise Real16CallRefusal(
                "successor_delta_mismatch",
                {"function": ctx.function_id, "delta": delta, "declared": sorted(declared)},
            )
        if delta in visiting:
            raise Real16CallRefusal(
                "loop_requires_inductive_proof",
                {"function": ctx.function_id, "delta": delta},
            )
        return _walk(session, ctxs, ctx, delta, state, visiting | {delta}, active, depth,
                     return_boundary=return_boundary)
    if isinstance(ip, dict) and ip.get("op") == "ite":
        args = ip.get("args")
        if not isinstance(args, list) or len(args) != 3:
            raise Real16CallRefusal("unsupported_ir", {"ip_op": "ite_shape"})
        session.stats["branch_merges"] = session.stats.get("branch_merges", 0) + 1
        true_state = _compose_ip_targets(
            session, ctxs, ctx, state, args[1], block, visiting, active, depth,
            return_boundary=return_boundary,
        )
        false_state = _compose_ip_targets(
            session, ctxs, ctx, state, args[2], block, visiting, active, depth,
            return_boundary=return_boundary,
        )
        merged: dict[str, dict[str, Any]] = S._merge_abi_states(
            args[0], true_state, false_state, compose_stats=session.stats
        )
        return merged
    if return_boundary and block_transfer(block).get("kind") == "indirect_successor":
        # This is a proposed callee exit, not admitted return evidence. The
        # caller boundary must prove its full physical target and restored CS
        # before it can resume; arbitrary callback/tail destinations refuse.
        return _compose_ret(state)
    raise Real16CallRefusal("unsupported_control_transfer", {"ip": "indirect"})


def _proved_symbolic_successor(
    session: ComposeSession, ctx: FunctionCtx, term: dict[str, Any], block: dict[str, Any],
) -> int | None:
    """Prove one declared full destination across every admitted entry alias.

    Unsupported indirect returns remain caller-bound obligations. Direct
    metadata is checked before solver work, with no low-word normalization.
    Branch arms are checked independently without guessing guard constraints.
    """
    if block_transfer(block).get("kind") != "direct_successors":
        return None
    candidates: frozenset[int] = declared_physical_successors(ctx, block_source(block))
    for target in sorted(candidates):
        maximum = session.remaining_ms(session.limits.ret_check_timeout_ms)
        deadline = session.stats["deadline"]
        assert isinstance(deadline, float)
        proof = prove_control_destination(term, target, ctx.entry_linear,
                                          deadline=deadline, max_solver_ms=maximum)
        session.remaining_ms(maximum)
        if proof.status is ProofStatus.PROVED:
            return target
    return None


def _compose_call(
    session: ComposeSession,
    ctxs: dict[str, FunctionCtx],
    ctx: FunctionCtx,
    delta: int,
    block: dict[str, Any],
    state: dict[str, dict[str, Any]],
    visiting: frozenset[int],
    active: frozenset[int],
    depth: int,
    *, return_boundary: bool = False,
) -> dict[str, dict[str, Any]]:
    """Inline a decoded CALL and prove its actual return-frame relation.

    The composed callee control target must equal the declared continuation;
    restored CS must match the caller selector, including far CALL frames.
    Instruction/frame forms whose IR or return relation is incomplete refuse.
    A ``direct_call`` block without a literal target is a bounded indirect
    call: it is admitted only through ``compose_indirect_call_poststate``.
    """
    if session.admit_indirect_calls and is_indirect_call_site(block):
        post = compose_indirect_call_poststate(
            session, ctxs, ctx, delta, block, state, active, depth, compose_entry
        )
        fall_delta = post.fall_delta
        if fall_delta in visiting:
            raise Real16CallRefusal(
                "loop_requires_inductive_proof", {"function": ctx.function_id, "delta": fall_delta}
            )
        return _walk(session, ctxs, ctx, fall_delta, post.state, visiting | {fall_delta},
                     active, depth, return_boundary=return_boundary)
    result = compose_call_poststate(session, ctxs, ctx, delta, block, state, active, depth, compose_entry)
    fall_delta = result.site.fall_delta
    if fall_delta in visiting:
        raise Real16CallRefusal(
            "loop_requires_inductive_proof", {"function": ctx.function_id, "delta": fall_delta}
        )
    return _walk(session, ctxs, ctx, fall_delta, result.state, visiting | {fall_delta}, active, depth,
                 return_boundary=return_boundary)


def prove_status(
    term_a: dict[str, Any], term_b: dict[str, Any], session: ComposeSession
) -> ProofStatus:
    """Typed equality verdict for two terms under the session limits."""
    return prove_terms_equal(term_a, term_b, session.limits.ret_check_timeout_ms)


def compose_entry(
    session: ComposeSession,
    ctxs: dict[str, FunctionCtx],
    entry_linear: int,
    active: frozenset[int],
    depth: int,
) -> dict[str, dict[str, Any]]:
    """Compose a callee whose complete exit must satisfy its caller boundary."""
    callee = next((c for c in ctxs.values() if c.entry_linear == entry_linear), None)
    if callee is None and session.admit_indirect_calls and session.indirect_resolver is not None:
        # Lazily validated catalog owner: nested callees reached only through
        # solver-admitted targets are not part of the direct-call closure.
        callee = session.indirect_resolver.resolve(entry_linear, session)
        ctxs.setdefault(callee.function_id, callee)
        session.resolved_contexts[callee.function_id] = callee
    if callee is None:
        raise Real16CallRefusal("call_target_unmapped", {"target": entry_linear})
    return _walk(
        session, ctxs, callee, 0, initial_state(), frozenset({0}), active, depth,
        return_boundary=True,
    )


def summarize(
    doc: dict[str, Any],
    function_key: str,
    *,
    limits: Real16CallLimits,
    timeout_ms: int,
    io_model: OrderedIoContract | None = None,
) -> tuple[dict[str, dict[str, Any]], ComposeSession]:
    """Compose ``function_key`` into a final full-state summary.

    ``io_model`` declares the ordered-I/O environment contract under which
    covered scalar port events in the admitted call closure are composed;
    the session records it so nested callee resolution inherits the same
    model and report layers can bind the consumed premise.
    """
    if io_model is not None:
        io_model.validate_for(Architecture.REAL16)
    ctxs, ctx = group_lookup(doc, function_key, io_model=io_model)
    if code_entry_domain(ctx.entry_linear) is None:
        raise Real16CallRefusal("code_entry_domain_unmapped", {"entry": ctx.entry_linear})
    reachable = reachable_call_ids(ctxs, ctx) | {ctx.function_id}
    check_lowering_refusals(doc, reachable)
    session = ComposeSession.with_deadline(limits, timeout_ms)
    session.admit_indirect_calls = True
    session.indirect_resolver = IndirectTargetResolver(doc)
    session.io_model = io_model
    state = _walk(
        session, ctxs, ctx, 0, initial_state(), frozenset({0}),
        frozenset({ctx.entry_linear}), 0,
    )
    # Solver-admitted indirect callees are reachable but carry no declared
    # direct-call target; their lowering refusals are rechecked after the walk.
    check_lowering_refusals(doc, reachable | set(session.resolved_contexts))
    return state, session
