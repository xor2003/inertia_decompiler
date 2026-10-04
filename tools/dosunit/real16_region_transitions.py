"""Complete real16 SSA transitions for finite paired CFG regions.

Layer: dosunit relational region proof.
Responsibility: compose binary-derived blocks and checked acyclic callees,
retain complete data/segment/flag/memory state, and translate only proven
control destinations into paired cutpoint tokens. Stored addresses never
undergo control relocation or layout normalization.
"""

from __future__ import annotations

from typing import Any

from tools.dosunit import straightline_ssa as S
from tools.dosunit.paired_region_graph import CollapsedRegion, RegionExitKind, RegionNode
from tools.dosunit.proof_contracts import ProofStatus
from tools.dosunit.real16_call_boundary import compose_call_poststate
from tools.dosunit.real16_call_contracts import (
    ComposeSession,
    FunctionCtx,
    Real16CallRefusal,
    const_term,
    initial_state,
    prove_terms_equal,
    term_nodes,
)
from tools.dosunit.real16_call_evidence import block_source, block_transfer
from tools.dosunit.real16_call_execution import compose_entry
from tools.dosunit.real16_loop_invariants import (
    check_cutpoint_state,
    check_physical_successors,
    declared_physical_successors,
)
from tools.dosunit.real16_region_control import resolve_region_control, resolve_region_poststate

type MachineState = dict[str, dict[str, Any]]


def _constant(value: int, width: int) -> dict[str, Any]:
    """Publish a literal control pattern with its exact bitvector width."""
    return {"op": "const", "width": width, "value": hex(value)}


def _destinations(term: dict[str, Any]) -> tuple[int, ...]:
    """Read ordered true/false destinations from complete composed SSA control."""
    literal = const_term(term)
    if literal is not None:
        return (literal,)
    args = term.get("args")
    if term.get("op") != "ite" or not isinstance(args, list) or len(args) != 3:
        raise Real16CallRefusal("unsupported_control_transfer")
    if not isinstance(args[1], dict) or not isinstance(args[2], dict):
        raise Real16CallRefusal("unsupported_control_transfer")
    return tuple(dict.fromkeys((*_destinations(args[1]), *_destinations(args[2]))))


def region_nodes(ctx: FunctionCtx, session: ComposeSession) -> dict[int, RegionNode]:
    """Admit exact physical edges and complete integer block boundaries."""
    nodes: dict[int, RegionNode] = {}
    for delta, block in ctx.blocks.items():
        session.bump()
        source = block_source(block)
        try:
            kind = RegionExitKind(source.get("jumpkind"))
        except ValueError as error:
            raise Real16CallRefusal("unsupported_exit", {"delta": delta}) from error
        if kind is RegionExitKind.RETURN:
            successors: tuple[int, ...] = ()
        else:
            check_physical_successors(ctx, source)
            if kind is RegionExitKind.CALL:
                raw = block_transfer(block).get("fallthrough")
                linear = S._optional_int(raw.get("linear")) if isinstance(raw, dict) else None
                if linear is None:
                    raise Real16CallRefusal("call_fallthrough_missing", {"delta": delta})
                successors = (linear,)
            else:
                outputs = block.get("outputs")
                state = S._compose_block_outputs(block, outputs if isinstance(outputs, dict) else {},
                                                initial_state(), compose_stats=session.stats)
                control = state.get("control_ip")
                if not isinstance(control, dict) or control.get("width") != 32:
                    raise Real16CallRefusal("full_control_unobserved", {"delta": delta})
                control_proof = resolve_region_control(
                    control, declared_physical_successors(ctx, source), ctx, session,
                )
                successors = _destinations(control_proof.resolved)
                declared = {ctx.entry_linear + target for target in S._direct_successor_delta_set(block)}
                if set(successors) != declared:
                    raise Real16CallRefusal("successor_delta_mismatch", {"delta": delta})
        linear = ctx.entry_linear + delta
        nodes[linear] = RegionNode(linear, successors, kind)
    return nodes


def compose_region(
    session: ComposeSession, contexts: dict[str, FunctionCtx], ctx: FunctionCtx,
    region: CollapsedRegion,
    *, incoming: MachineState | None = None,
) -> MachineState:
    """Compose a finite nonempty region, checking internal progress and domains."""
    state = initial_state() if incoming is None else dict(incoming)
    state["control_ip"] = _constant(region.members[0], 32)
    state["ip"] = _constant(region.members[0] & 0xFFFF, 16)
    for index, linear in enumerate(region.members):
        session.bump()
        delta = linear - ctx.entry_linear
        block = ctx.blocks[delta]
        outputs = block.get("outputs")
        state = S._compose_block_outputs(block, outputs if isinstance(outputs, dict) else {}, state,
                                         compose_stats=session.stats)
        kind = region.kind if index + 1 == len(region.members) else RegionExitKind.BORING
        if kind is RegionExitKind.CALL:
            state = compose_call_poststate(session, contexts, ctx, delta, block, state,
                                            frozenset({ctx.entry_linear}), 0, compose_entry).state
        if term_nodes(state, session.limits.max_term_nodes) > session.limits.max_term_nodes:
            raise Real16CallRefusal("compose_budget_exceeded", {"counter": "term_nodes"})
        check_cutpoint_state(ctx, state, continuing=kind is not RegionExitKind.RETURN,
                             timeout_ms=session.remaining_ms(session.limits.ret_check_timeout_ms))
        if kind is not RegionExitKind.RETURN:
            state = resolve_region_poststate(
                state, declared_physical_successors(ctx, block_source(block)), ctx, session,
            )
        if index + 1 < len(region.members) and const_term(state.get("control_ip")) != region.members[index + 1]:
            raise Real16CallRefusal("internal_region_progress_unproved", {"delta": delta})
    return state


def _control_token(term: dict[str, Any], tokens: dict[int, int]) -> dict[str, Any]:
    """Translate only closed constant control arms, preserving branch guards."""
    literal = const_term(term)
    if literal is not None:
        if literal not in tokens:
            raise Real16CallRefusal("successor_outside_region", {"linear": literal})
        return _constant(tokens[literal], 32)
    args = term.get("args")
    if term.get("op") != "ite" or not isinstance(args, list) or len(args) != 3:
        raise Real16CallRefusal("unsupported_control_transfer")
    if not all(isinstance(arg, dict) for arg in args):
        raise Real16CallRefusal("unsupported_control_transfer")
    return {"op": "ite", "width": 32,
            "args": [args[0], _control_token(args[1], tokens), _control_token(args[2], tokens)]}


def related_outputs(
    state: MachineState, region: CollapsedRegion, tokens: dict[int, int], timeout_ms: int,
) -> MachineState:
    """Apply the explicit PC relation at continuing cutpoints; exits retain identity.

    All integer registers, segments, flags, memory and I/O remain observable.
    Only loaded PC and its derived legacy word projection follow the paired
    graph relation. Return destinations retain their full physical identity.
    """
    if region.kind is RegionExitKind.RETURN:
        return state
    projected = {"op": "trunc", "width": 16, "args": [state["control_ip"]]}
    if prove_terms_equal(state["ip"], projected, timeout_ms) is not ProofStatus.PROVED:
        raise Real16CallRefusal("legacy_control_projection_unproved")
    observed = {name: term for name, term in state.items() if name not in {"ip", "control_ip"}}
    observed["paired_control"] = _control_token(state["control_ip"], tokens)
    return observed
