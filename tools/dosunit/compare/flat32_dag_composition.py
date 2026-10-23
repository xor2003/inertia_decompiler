"""Layer: dosunit acyclic state composition.

Responsibility: compose closed DAGs once per block when path expansion
would duplicate effects at control-flow joins. Merge full guarded machine states at joins;
never change execution, memory observations, deadlines or composition limits.
"""
from __future__ import annotations

import heapq
from collections.abc import Callable
from typing import Any

from tools.dosunit.compare.flat32_call_contracts import (
    CallCompositionRefusal,
    _check_compose_deadline,
    _ComposeSession,
    _const_term_int,
    _LiftedBlock,
    _term_nodes,
)
from tools.dosunit.compare.flat32_call_lowering import _partition_block_entries
from tools.dosunit.ssa.composition import compose_block_outputs, merge_states
from tools.dosunit.ssa.guard_composition import GuardOperator, combine_guards

type State = dict[str, dict[str, Any]]
type GuardedState = tuple[dict[str, Any], State]
type CallStep = Callable[[_LiftedBlock, State, dict[str, Any]], State]


def _eligible(block: _LiftedBlock, allow_calls: bool) -> bool:
    """Delegate returning calls; keep unresolved/nonlocal control with its owner."""
    if any((block.tail_targets, block.part.get("summary"),
            block.part.get("obligations"), block.part.get("trap_exits"))):
        return False
    if block.jumpkind == "Ijk_Call":
        return (allow_calls and block.fallthrough is not None
                and (block.call_target is not None or block.external_slot is not None))
    return block.jumpkind in {"Ijk_Boring", "Ijk_Ret"} and block.external_slot is None


def _incoming_counts(blocks: dict[int, _LiftedBlock], allow_calls: bool) -> dict[int, int] | None:
    """Validate native closure and count predecessors before changing any state."""
    incoming = dict.fromkeys(blocks, 0)
    for block in blocks.values():
        if not _eligible(block, allow_calls):
            return None
        if block.jumpkind == "Ijk_Boring" and not block.successors:
            return None
        for target in set(block.successors):
            if target not in incoming:
                return None
            incoming[target] += 1
    return incoming


def _order(blocks: dict[int, _LiftedBlock], entry: int, budget: int, allow_calls: bool,
           *, selected: bool = False) -> list[int] | None:
    """Select closed acyclic regions with joins or excessive unfolded path work."""
    incoming = _incoming_counts(blocks, allow_calls)
    if incoming is None:
        return None
    reconverges = any(n > 1 for n in incoming.values())
    ready = [node for node, degree in incoming.items() if not degree]
    if ready != [entry]:
        return None
    order: list[int] = []
    paths = dict.fromkeys(blocks, 0)
    paths[entry] = 1
    while ready:
        node = heapq.heappop(ready)
        order.append(node)
        for target in sorted(set(blocks[node].successors)):
            paths[target] = min(budget + 1, paths[target] + paths[node])
            incoming[target] -= 1
            if not incoming[target]:
                heapq.heappush(ready, target)
    if len(order) != len(blocks) or (not selected and not reconverges and sum(paths.values()) <= budget):
        return None
    return order


def _guard(op: GuardOperator, left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    """Keep exact reachability while eliminating reconverged path histories."""
    return combine_guards(op, left, right)


def _merge(incoming: list[GuardedState], session: _ComposeSession) -> GuardedState:
    """Merge disjoint path states while preserving every register and memory byte."""
    reach, state = incoming[0]
    for guard, other in incoming[1:]:
        state = merge_states(guard, other, state, compose_stats=session.compose_stats)
        reach = _guard("or", reach, guard)
    return reach, state


def _edges(ip: dict[str, Any], guard: dict[str, Any]) -> list[tuple[int, dict[str, Any]]]:
    """Read only constant leaves of the actual composed control expression."""
    target = _const_term_int(ip)
    if target is not None:
        return [(target, guard)]
    args = ip.get("args", [])
    if ip.get("op") != "ite" or len(args) != 3:
        raise CallCompositionRefusal("indirect_or_unmodeled_branch")
    condition, yes, no = args
    negate = {"op": "not", "width": 1, "args": [condition]}
    return [*_edges(yes, _guard("and", guard, condition)),
            *_edges(no, _guard("and", guard, negate))]


def _apply_block(session: _ComposeSession, block: _LiftedBlock, state: State) -> State:
    """Charge each composition and enforce the same expression/control bounds."""
    session.compositions += 1
    if session.compositions > session.limits.max_compositions:
        raise CallCompositionRefusal("region_composition_limit")
    state = compose_block_outputs(block.part, block.part.get("outputs", {}), state,
                                     compose_stats=session.compose_stats)
    if _term_nodes(state, session.limits.max_term_nodes) > session.limits.max_term_nodes:
        raise CallCompositionRefusal("region_expression_limit")
    if not isinstance(state.get("ip"), dict):
        raise CallCompositionRefusal("full_width_ip_unobserved")
    return state


def _selected_graph(
    session: _ComposeSession, blocks: dict[int, _LiftedBlock], entry: int, allow_calls: bool,
) -> tuple[dict[int, _LiftedBlock], list[int]] | None:
    """Partition only an admitted acyclic execution view, retaining the source CFG."""
    budget = session.limits.max_compositions - session.compositions
    if _order(blocks, entry, budget, allow_calls) is None:
        return None
    copied = dict(blocks)
    _partition_block_entries(session, entry, entry + session.functions[entry], copied)
    order = _order(copied, entry, budget, allow_calls, selected=True)
    return (copied, order) if order is not None else None


def compose_dag_if_needed(
    session: _ComposeSession, blocks: dict[int, _LiftedBlock], entry: int, initial: State,
    *, call_step: CallStep | None = None, incoming_guard: dict[str, Any] | None = None,
) -> State | None:
    """Compose each reachable block once or decline before consuming any work.

    Returning calls delegate their complete effects and return proofs to the
    execution owner. Tail transfers, unresolved calls, cycles and native summary
    obligations keep the path-sensitive route. Every join retains exact guards.
    """
    _check_compose_deadline(session.compose_stats)
    selected = _selected_graph(session, blocks, entry, call_step is not None)
    if selected is None:
        return None
    blocks, order = selected
    initial_guard = incoming_guard if incoming_guard is not None else {"op": "const", "width": 1, "value": "0x1"}
    incoming: dict[int, list[GuardedState]] = {entry: [(initial_guard, initial)]}
    returns: list[GuardedState] = []
    for address in order:
        _check_compose_deadline(session.compose_stats)
        if address not in incoming:
            continue
        guard, state = _merge(incoming[address], session)
        block = blocks[address]
        state = _apply_block(session, block, state)
        if block.jumpkind == "Ijk_Call":
            assert call_step is not None
            state = call_step(block, state, guard)
        ip = state["ip"]
        if block.jumpkind == "Ijk_Ret":
            state["eip"] = ip
            returns.append((guard, state))
        else:
            for target, edge_guard in _edges(ip, guard):
                if target not in block.successors:
                    raise CallCompositionRefusal("successor_outside_complete_region")
                incoming.setdefault(target, []).append((edge_guard, state))
    if not returns:
        raise CallCompositionRefusal("complete_return_missing")
    _, final = _merge(returns, session)
    if _term_nodes(final, session.limits.max_term_nodes) > session.limits.max_term_nodes:
        raise CallCompositionRefusal("region_expression_limit")
    return final
