"""Direct-call post-state composition for acyclic callees and loop cutpoints.

Layer: dosunit callee composition.
Responsibility: consume complete callee effects, prove the saved return target
and actual caller CS restoration, and publish full state at the continuation.
Both acyclic walking and matched-loop induction consume this boundary.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from tools.dosunit import straightline_ssa as S
from tools.dosunit.proof_contracts import ProofStatus
from tools.dosunit.real16_call_contracts import (
    ComposeSession,
    DirectCallSite,
    FunctionCtx,
    Real16CallRefusal,
    prove_terms_equal,
    substitute_state_term,
)
from tools.dosunit.real16_call_control import charge_call, checked_call_site, restore_cs
from tools.dosunit.real16_call_frames import caller_cs_before_call, decoded_call_frame
from tools.dosunit.real16_entry_domain import Real16EntryDomain, code_entry_domain

type MachineState = dict[str, dict[str, Any]]
type ComposeCallee = Callable[[ComposeSession, dict[str, FunctionCtx], int, frozenset[int], int], MachineState]


@dataclass(frozen=True, slots=True)
class CallPostState:
    """Complete callee post-state and its proved caller continuation."""

    state: MachineState
    site: DirectCallSite


def _entry_domain(linear: int) -> Real16EntryDomain:
    """Require a nonvacuous architectural code-entry relation."""
    domain = code_entry_domain(linear)
    if domain is None:
        raise Real16CallRefusal("code_entry_domain_unmapped", {"entry": linear})
    return domain


def _check_callee_entry(
    session: ComposeSession, contexts: dict[str, FunctionCtx], site: DirectCallSite,
    state: MachineState, caller_domain: Real16EntryDomain,
) -> None:
    """Prove the actual post-CALL selector meets the callee's entry precondition."""
    callee = next((ctx for ctx in contexts.values() if ctx.entry_linear == site.target), None)
    if callee is None:
        raise Real16CallRefusal("call_target_unmapped", {"target": site.target})
    selector = state.get("cs")
    if not isinstance(selector, dict):
        raise Real16CallRefusal("callee_code_domain_unproved", {"target": site.target})
    predicate = _entry_domain(callee.entry_linear).contains(selector)
    proved = prove_terms_equal(
        predicate, {"op": "const", "width": 1, "value": "0x1"},
        session.limits.ret_check_timeout_ms, input_constraints=caller_domain.constraints(),
    )
    if proved is not ProofStatus.PROVED:
        raise Real16CallRefusal("callee_code_domain_unproved", {"target": site.target})


def compose_call_poststate(
    session: ComposeSession, contexts: dict[str, FunctionCtx], caller: FunctionCtx,
    delta: int, block: dict[str, Any], state: MachineState, active: frozenset[int],
    depth: int, compose_callee: ComposeCallee,
) -> CallPostState:
    """Discharge the decoded CALL frame using the actual complete callee effects.

    The full loaded control destination is checked independently of the
    legacy word-IP projection. Saved CS comes from
    the actual frame for far CALL, and from the unchanged selector for near
    CALL. Matching call targets alone never establish post-state equality.
    """
    site = checked_call_site(caller, delta, block, state, session=session)
    frame = decoded_call_frame(block)
    domain = _entry_domain(caller.entry_linear)
    charge_call(session, caller, site, active, depth)
    _check_callee_entry(session, contexts, site, state, domain)
    callee = compose_callee(session, contexts, site.target, active | {caller.entry_linear}, depth + 1)
    returned_ip = callee.get("control_ip")
    if not isinstance(returned_ip, dict):
        raise Real16CallRefusal("return_ip_unobserved", {"target": site.target})
    substituted = substitute_state_term(returned_ip, state)
    # Control is a full physical destination. The architectural frame width
    # does not permit truncating this obligation or discarding upper EIP bits.
    expected = {"op": "const", "value": S.normalize_hex(site.fallthrough), "width": 32}
    if substituted != expected and (
        prove_terms_equal(substituted, expected, session.limits.ret_check_timeout_ms,
                          input_constraints=domain.constraints()) is not ProofStatus.PROVED
    ):
        raise Real16CallRefusal(
            "return_target_unproved", {"delta": delta, "target": site.target, "fallthrough": site.fallthrough}
        )
    session.return_targets_proved += 1
    restore_cs(session, state, callee, site.target, caller_cs=caller_cs_before_call(frame, state))
    post = dict(state)
    for name, term in callee.items():
        if name not in {"ip", "eip", "control_ip"}:
            post[name] = substitute_state_term(term, state)
    post["control_ip"] = expected
    post["ip"] = {"op": "trunc", "width": 16, "args": [expected]}
    return CallPostState(post, site)
