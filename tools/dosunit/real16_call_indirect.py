"""Bounded finite indirect-call composition through the existing call boundary.

Layer: dosunit callee composition.
Responsibility: close the target relation of one indirect CALL block over the
catalog-admitted callee set under every architectural entry alias, compose each
solver-admitted target through the real callee body, prove per-arm return
target and caller-CS restoration obligations, and merge arm post-states into
the caller continuation with the existing guarded-state machinery.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from tools.dosunit import straightline_ssa as S
from tools.dosunit.proof_contracts import ProofStatus
from tools.dosunit.real16_call_contracts import (
    ComposeSession,
    DirectCallSite,
    FunctionCtx,
    IndirectCallPostState,
    Real16CallRefusal,
    const_term,
    prove_terms_equal,
    substitute_state_term,
    term_nodes,
)
from tools.dosunit.real16_call_control import charge_call, restore_cs
from tools.dosunit.real16_call_evidence import block_transfer
from tools.dosunit.real16_call_frames import caller_cs_before_call, decoded_call_frame
from tools.dosunit.real16_entry_domain import Real16EntryDomain, code_entry_domain

type MachineState = dict[str, dict[str, Any]]
type ComposeCallee = Callable[[ComposeSession, dict[str, FunctionCtx], int, frozenset[int], int], MachineState]


def _const_term(value: int, width: int) -> dict[str, Any]:
    """Materialize a constant SSA term at an explicit width."""
    return {"op": "const", "value": S.normalize_hex(value), "width": width}


def _target_guard(control: dict[str, Any], entry: int) -> dict[str, Any]:
    """Arm predicate: the composed control destination equals this entry."""
    return {"op": "eq", "width": 1, "args": [control, _const_term(entry, 32)]}


def _entry_domain(linear: int) -> Real16EntryDomain:
    """Require a nonvacuous architectural code-entry relation."""
    domain = code_entry_domain(linear)
    if domain is None:
        raise Real16CallRefusal("code_entry_domain_unmapped", {"entry": linear})
    return domain


def _or_balanced(
    terms: list[dict[str, Any]], stats: dict[str, Any] | None
) -> dict[str, Any]:
    """Pairwise OR fold; balanced depth and deadline-checked at each level."""
    level = terms
    while len(level) > 1:
        S._compose_deadline_check(stats)
        paired = [
            {"op": "or", "width": 1, "args": [level[i], level[i + 1]]}
            for i in range(0, len(level) - 1, 2)
        ]
        if len(level) % 2:
            paired.append(level[-1])
        level = paired
    return level[0]


def _check_target_count(session: ComposeSession, count: int) -> None:
    """Apply the same live-arm limit to literal and solver-derived target sets."""
    if count > session.limits.max_indirect_call_targets:
        raise Real16CallRefusal(
            "compose_budget_exceeded",
            {"counter": "indirect_call_targets", "limit": session.limits.max_indirect_call_targets},
        )


def _closed_targets(
    session: ComposeSession, delta: int,
    control: dict[str, Any], domain: Real16EntryDomain,
) -> list[int]:
    """Prove a finite catalog-closed target image under all entry aliases.

    The coverage obligation is ``control in {candidate entries}`` quantified
    over the caller's entire ``cs`` alias interval and all other symbolic
    inputs.  Candidate discovery is bounded by ``max_indirect_call_candidates``
    before any term construction or solver call; an oversized catalog refuses
    instead of truncating.  Per-candidate nonvacuity then selects the arms
    that can actually execute; unknown candidates stay live (fail-closed) and
    are charged against ``max_indirect_call_targets``.
    """
    resolver = session.indirect_resolver
    if resolver is None:
        raise Real16CallRefusal("unsupported_call", {"delta": delta, "indirect": "resolver_missing"})
    literal = const_term(control)
    if literal is not None:
        _check_target_count(session, 1)
        return [literal]
    candidates = resolver.candidate_entries(session)
    if not candidates:
        raise Real16CallRefusal(
            "call_target_unresolved", {"delta": delta, "proof": "no_candidates"}
        )
    guards = [_target_guard(control, entry) for entry in candidates]
    membership = _or_balanced(guards, session.stats)
    if term_nodes(membership, session.limits.max_term_nodes) > session.limits.max_term_nodes:
        raise Real16CallRefusal(
            "compose_budget_exceeded",
            {"counter": "term_nodes", "limit": session.limits.max_term_nodes},
        )
    proof = prove_terms_equal(
        membership,
        _const_term(1, 1),
        session.remaining_ms(session.limits.ret_check_timeout_ms),
        input_constraints=domain.constraints(),
    )
    if proof is not ProofStatus.PROVED:
        raise Real16CallRefusal(
            "call_target_unresolved",
            {"delta": delta, "proof": proof.name.lower(), "candidates": len(candidates)},
        )
    live: list[int] = []
    for entry in candidates:
        dead = prove_terms_equal(
            _target_guard(control, entry),
            _const_term(0, 1),
            session.remaining_ms(session.limits.ret_check_timeout_ms),
            input_constraints=domain.constraints(),
        )
        if dead is ProofStatus.PROVED:
            continue
        live.append(entry)
        _check_target_count(session, len(live))
    if not live:
        raise Real16CallRefusal("call_target_unresolved", {"delta": delta, "proof": "vacuous"})
    return live


def _resolve_callee(
    session: ComposeSession, contexts: dict[str, FunctionCtx], target: int
) -> FunctionCtx:
    """Return the unique validated callee context for an admitted target."""
    existing = next((ctx for ctx in contexts.values() if ctx.entry_linear == target), None)
    if existing is not None:
        return existing
    resolver = session.indirect_resolver
    if resolver is None:
        raise Real16CallRefusal("call_target_unmapped", {"target": target})
    ctx = resolver.resolve(target, session)
    contexts.setdefault(ctx.function_id, ctx)
    session.resolved_contexts[ctx.function_id] = ctx
    return ctx


def _check_callee_arm_entry(
    session: ComposeSession, site: DirectCallSite, state: MachineState,
    caller_domain: Real16EntryDomain, guard: dict[str, Any] | None,
) -> None:
    """Prove the post-CALL selector meets this arm's callee entry precondition."""
    selector = state.get("cs")
    if not isinstance(selector, dict):
        raise Real16CallRefusal("callee_code_domain_unproved", {"target": site.target})
    predicate = _entry_domain(site.target).contains(selector)
    if guard is not None:
        predicate = {"op": "ite", "width": 1, "args": [guard, predicate, _const_term(1, 1)]}
    proved = prove_terms_equal(
        predicate,
        _const_term(1, 1),
        session.remaining_ms(session.limits.ret_check_timeout_ms),
        input_constraints=caller_domain.constraints(),
    )
    if proved is not ProofStatus.PROVED:
        raise Real16CallRefusal("callee_code_domain_unproved", {"target": site.target})


def _prove_arm_return(
    session: ComposeSession, delta: int, site: DirectCallSite,
    callee: MachineState, state: MachineState, expected: dict[str, Any],
    domain: Real16EntryDomain, guard: dict[str, Any] | None,
) -> None:
    """Prove this arm's callee returns to the caller fallthrough destination."""
    returned_ip = callee.get("control_ip")
    if not isinstance(returned_ip, dict):
        raise Real16CallRefusal("return_ip_unobserved", {"target": site.target})
    substituted = substitute_state_term(returned_ip, state)
    if guard is not None and S._term_width(substituted) == 32:
        substituted = {"op": "ite", "width": 32, "args": [guard, substituted, expected]}
    if substituted != expected and (
        prove_terms_equal(
            substituted,
            expected,
            session.remaining_ms(session.limits.ret_check_timeout_ms),
            input_constraints=domain.constraints(),
        )
        is not ProofStatus.PROVED
    ):
        raise Real16CallRefusal(
            "return_target_unproved",
            {"delta": delta, "target": site.target, "fallthrough": site.fallthrough},
        )
    session.return_targets_proved += 1


def _merge_arms(
    session: ComposeSession, arms: list[tuple[dict[str, Any], MachineState]]
) -> MachineState:
    """Fold arm post-states through the shared guarded merge machinery."""
    merged = arms[-1][1]
    for guard, post in reversed(arms[:-1]):
        merged = S._merge_abi_states(guard, post, merged, compose_stats=session.stats)
        session.stats["branch_merges"] = session.stats.get("branch_merges", 0) + 1
    if term_nodes(merged, session.limits.max_term_nodes) > session.limits.max_term_nodes:
        raise Real16CallRefusal(
            "compose_budget_exceeded",
            {"counter": "term_nodes", "limit": session.limits.max_term_nodes},
        )
    return merged


def compose_indirect_call_poststate(
    session: ComposeSession, contexts: dict[str, FunctionCtx], caller: FunctionCtx,
    delta: int, block: dict[str, Any], state: MachineState, active: frozenset[int],
    depth: int, compose_callee: ComposeCallee,
) -> IndirectCallPostState:
    """Close and compose a bounded finite indirect CALL through real callees.

    ``state["control_ip"]`` is the composed full-width physical control
    destination of the CALL.  The call is admitted only when the solver proves
    that destination lands inside a finite set of uniquely-owned catalog
    entries under every architectural ``cs`` alias.  Each live arm composes
    the actual callee body, proves return target and caller-CS restoration
    under its arm guard, and contributes to the merged post-state through the
    existing guarded merge.  Nothing about names, addresses, or rendered
    operands substitutes for these proofs.
    """
    if session.indirect_resolver is None:
        raise Real16CallRefusal("unsupported_call", {"delta": delta, "indirect": "resolver_missing"})
    transfer = block_transfer(block)
    value = transfer.get("fallthrough")
    fallthrough = value if isinstance(value, dict) else {}
    fallthrough_linear = S._optional_int(fallthrough.get("linear"))
    if fallthrough_linear is None:
        raise Real16CallRefusal("call_fallthrough_missing", {"delta": delta})
    fall_delta = fallthrough_linear - caller.entry_linear
    if fall_delta not in caller.blocks:
        raise Real16CallRefusal(
            "successor_outside_region",
            {"function": caller.function_id, "delta": fall_delta, "kind": "call_fallthrough"},
        )
    frame = decoded_call_frame(block)
    domain = _entry_domain(caller.entry_linear)
    control = state.get("control_ip")
    if not isinstance(control, dict) or control.get("width") != 32:
        raise Real16CallRefusal("unsupported_call", {"delta": delta, "ip": "full_control_missing"})
    targets = _closed_targets(session, delta, control, domain)
    guarded = len(targets) > 1
    arms: list[tuple[dict[str, Any], MachineState]] = []
    expected = _const_term(fallthrough_linear, 32)
    for target in targets:
        site = DirectCallSite(target, fallthrough_linear, fall_delta)
        charge_call(session, caller, site, active, depth)
        _resolve_callee(session, contexts, target)
        guard = _target_guard(control, target) if guarded else None
        _check_callee_arm_entry(session, site, state, domain, guard)
        callee = compose_callee(
            session, contexts, target, active | {caller.entry_linear}, depth + 1
        )
        _prove_arm_return(session, delta, site, callee, state, expected, domain, guard)
        restore_cs(
            session, state, callee, target,
            caller_cs=caller_cs_before_call(frame, state), guard=guard,
        )
        post = dict(state)
        for name, term in callee.items():
            if name not in {"ip", "eip", "control_ip"}:
                post[name] = substitute_state_term(term, state)
        post["control_ip"] = expected
        post["ip"] = {"op": "trunc", "width": 16, "args": [expected]}
        arms.append((_target_guard(control, target), post))
        session.indirect_targets_proved += 1
    session.indirect_call_sites += 1
    merged = arms[0][1] if len(arms) == 1 else _merge_arms(session, arms)
    return IndirectCallPostState(merged, fall_delta, tuple(targets))
