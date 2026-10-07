"""Binary control and return-frame checks for inlined calls.

Layer: dosunit call proof control.
Responsibility: validate direct-call target/continuation evidence, enforce
acyclic composition budgets and prove caller CS restoration at call
boundaries, including the per-arm guarded variant used by bounded indirect
call composition.
"""

from __future__ import annotations

from typing import Any

from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.real16_call_contracts import (
    ComposeSession,
    DirectCallSite,
    FunctionCtx,
    Real16CallRefusal,
    const_term,
    prove_terms_equal,
    substitute_state_term,
)
from tools.dosunit.compare.real16_call_evidence import block_source, block_transfer
from tools.dosunit.compare.real16_control_resolution import prove_control_destination
from tools.dosunit.contracts.proof_contracts import ProofStatus


def checked_call_site(
    ctx: FunctionCtx, delta: int, block: dict[str, Any], state: dict[str, dict[str, Any]],
    *, session: ComposeSession | None = None,
) -> DirectCallSite:
    """Require literal or universally proved full control and a closed continuation.

    Symbolic targets require the caller's existing composition deadline and
    every architectural entry alias; metadata alone never admits a target.
    """
    transfer = block_transfer(block)
    if str(transfer.get("kind") or "") != "direct_call":
        raise Real16CallRefusal(
            "unsupported_call",
            {"delta": delta, "jumpkind": block_source(block).get("jumpkind")},
        )
    value = transfer.get("target")
    target = value if isinstance(value, dict) else {}
    target_linear = S._optional_int(target.get("raw"))
    if target_linear is None:
        target_linear = S._optional_int(target.get("linear"))
    if target_linear is None:
        raise Real16CallRefusal("call_target_unresolved", {"delta": delta})
    _check_target(ctx, delta, state, target_linear, session)
    value = transfer.get("fallthrough")
    fallthrough = value if isinstance(value, dict) else {}
    fallthrough_linear = S._optional_int(fallthrough.get("linear"))
    if fallthrough_linear is None:
        raise Real16CallRefusal("call_fallthrough_missing", {"delta": delta})
    # A control destination is physical in this proof model. A word-sized
    # difference could alias another page to an existing continuation block.
    fall_delta = fallthrough_linear - ctx.entry_linear
    if fall_delta not in ctx.blocks:
        raise Real16CallRefusal(
            "successor_outside_region",
            {"function": ctx.function_id, "delta": fall_delta, "kind": "call_fallthrough"},
        )
    return DirectCallSite(target_linear, fallthrough_linear, fall_delta)


def _check_target(
    ctx: FunctionCtx, delta: int, state: dict[str, dict[str, Any]], target: int,
    session: ComposeSession | None,
) -> None:
    """Retain cheap literal checks and prove symbolic targets under all aliases."""
    if not 0 <= target <= 0xFFFFFFFF:
        raise Real16CallRefusal("call_target_mismatch", {"delta": delta, "target": target})
    term = state.get("control_ip")
    if term is None or term.get("width") != 32:
        raise Real16CallRefusal("unsupported_call", {"delta": delta, "ip": "full_control_missing"})
    block_ip = const_term(term)
    if block_ip is not None:
        if block_ip != target:
            raise Real16CallRefusal("call_target_mismatch", {"delta": delta, "ip": block_ip, "target": target})
        return
    if session is None:
        raise Real16CallRefusal("unsupported_call", {"delta": delta, "ip": "nonconstant"})
    maximum = session.remaining_ms(session.limits.ret_check_timeout_ms)
    deadline = session.stats["deadline"]
    assert isinstance(deadline, float)  # remaining_ms checked the owned boundary.
    proof = prove_control_destination(term, target, ctx.entry_linear,
                                      deadline=deadline, max_solver_ms=maximum)
    if proof.status is not ProofStatus.PROVED:
        reason = "call_target_mismatch" if proof.status is ProofStatus.COUNTEREXAMPLE else "unsupported_call"
        raise Real16CallRefusal(reason, {"delta": delta, "target": target, "proof": proof.reason.value})


def charge_call(
    session: ComposeSession, ctx: FunctionCtx, site: DirectCallSite, active: frozenset[int], depth: int,
) -> None:
    """Charge a direct call only after checking recursion, depth and total budget."""
    if site.target in active or site.target == ctx.entry_linear:
        raise Real16CallRefusal("recursive_call_cycle", {"target": site.target})
    if depth >= session.limits.max_inline_depth:
        raise Real16CallRefusal(
            "call_depth_budget_exceeded", {"limit": session.limits.max_inline_depth}
        )
    if session.inlined_calls >= session.limits.max_inlined_calls:
        raise Real16CallRefusal(
            "compose_budget_exceeded",
            {"counter": "inlined_calls", "limit": session.limits.max_inlined_calls},
        )
    session.inlined_calls += 1


def restore_cs(
    session: ComposeSession, state: dict[str, dict[str, Any]], callee_state: dict[str, dict[str, Any]], target: int,
    *, caller_cs: dict[str, Any] | None = None, guard: dict[str, Any] | None = None,
) -> None:
    """Require a proof that the actual callee effects preserve caller CS.

    ``guard`` is a 1-bit selector predicate for one indirect-call arm: the
    restoration obligation then holds only under that arm's condition.
    """
    caller_cs = state.get("cs") if caller_cs is None else caller_cs
    callee_cs = callee_state.get("cs")
    if not isinstance(caller_cs, dict) or not isinstance(callee_cs, dict):
        raise Real16CallRefusal("call_cs_not_restored", {"target": target})
    substituted_cs = substitute_state_term(callee_cs, state)
    if guard is not None and S._term_width(substituted_cs) == S._term_width(caller_cs):
        width = S._term_width(caller_cs)
        substituted_cs = {"op": "ite", "width": width, "args": [guard, substituted_cs, caller_cs]}
    if substituted_cs != caller_cs and (
        prove_terms_equal(
            substituted_cs, caller_cs, session.remaining_ms(session.limits.ret_check_timeout_ms)
        ) is not ProofStatus.PROVED
    ):
        raise Real16CallRefusal("call_cs_not_restored", {"target": target})
    session.cs_preserved_proved += 1
