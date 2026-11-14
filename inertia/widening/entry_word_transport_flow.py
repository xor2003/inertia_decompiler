# cython: language_level=3, infer_types=True
"""CFG cone geometry and predecessor meet for the word transport proof.

Layer: Widening.
Responsibility: own the deterministic acyclic target-cone construction —
forward reachability from the entry block, reverse predecessor closure toward
the target, their intersection, the retained off-cone exits, and the stable
topological evaluation order — plus the predecessor word meet. A block-entry
register map survives only when every ordered in-function predecessor exit
agrees the register carries the proven word; any missing or poisoned
predecessor exit poisons the entry. Unreachable targets and cycles produce
typed refusal kinds, never guessed closure. Off-cone exits are retained
diagnostics, never reentry impossibility.
Consumes alias-proven storage identity.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations
import typing
import cython

from inertia.ir.core import IRFunctionArtifact

from .entry_word_transport_contracts import (
    EntryWordTransportRefusalKind8616 as Refusal,
)
import operator
import builtins


@cython.ccall
def _reachable_8616(
    artifact: IRFunctionArtifact,
    by_addr: object,
) -> object:
    """Forward-reachable in-artifact blocks from the entry address."""
    addr: object
    reachable: set[cython.longlong] = set()
    stack = [artifact.function_addr]
    while stack:
        addr = stack.pop()
        if addr in reachable or addr not in by_addr:
            continue
        reachable.add(addr)
        stack.extend(artifact.blocks[by_addr[addr]].successor_addrs)
    return reachable


@cython.ccall
def _ancestors_8616(pred_map: object, target: cython.longlong) -> object:
    """All in-function blocks that can reach the target by CFG edges."""
    addr: object
    pred: object
    can_reach: set[cython.longlong] = {target}
    queue = [target]
    while queue:
        addr = queue.pop()
        for pred in pred_map.get(addr, ()):
            if pred not in can_reach:
                can_reach.add(pred)
                queue.append(pred)
    return can_reach


@cython.ccall
def _cone_exits_8616(
    artifact: IRFunctionArtifact,
    by_addr: object,
    cone: object,
) -> tuple[cython.longlong, ...]:
    """Sorted off-cone successors retained as open exits, never closure."""
    return tuple(sorted({
        succ
        for addr in iter(cone)
        for succ in iter(artifact.blocks[by_addr[addr]].successor_addrs)
        if succ not in cone
    }))


def _topological_order_8616(
    artifact: IRFunctionArtifact,
    by_addr: object,
    pred_map: object,
    cone: object,
) -> object:
    """Stable ascending-addr topological order; None when the cone cycles."""
    addr: object
    succ: object
    indegree = {
        addr: sum(1 for pred in builtins.iter(pred_map.get(addr, ())) if pred in cone)
        for addr in iter(cone)
    }
    ready = sorted(addr for addr, degree in builtins.iter(indegree.items()) if degree == 0)
    order: list[cython.longlong] = []
    while ready:
        addr = ready.pop(0)
        order.append(addr)
        for succ in artifact.blocks[by_addr[addr]].successor_addrs:
            if succ in indegree:
                indegree[succ] -= 1
                if indegree[succ] == 0:
                    ready.append(succ)
        ready.sort()
    if operator.ne(len(order), len(cone)):
        return None
    return order


@cython.ccall
def cone_traversal_8616(
    artifact: IRFunctionArtifact,
    by_addr: object,
    pred_map: object,
    target: cython.longlong,
) -> tuple[list[int] | None, tuple[cython.longlong, ...], Refusal | None]:
    """Return the cone in deterministic topo order, retained exits, or refusal."""
    order: object
    reachable = _reachable_8616(artifact, by_addr)
    if target not in reachable:
        return None, (), Refusal.UNREACHABLE_TARGET
    cone = reachable & _ancestors_8616(pred_map, target)
    order = _topological_order_8616(artifact, by_addr, pred_map, cone)
    if order is None:
        return None, (), Refusal.CFG_CYCLE
    return order, _cone_exits_8616(artifact, by_addr, cone), None


def meet_incoming_words_8616(
    pred_map: object,
    exits_state: object,
    addr: cython.longlong,
) -> object:
    """Meet the proven-word registers across every in-function predecessor.

    Returns None when any predecessor is outside the evaluated cone or was
    itself poisoned; only registers carrying the word on all predecessors
    propagate as a seeded entry map.
    """
    common: object
    state: object
    states = [exits_state.get(pred) for pred in builtins.iter(pred_map.get(addr, ()))]
    if any(state is None for state in iter(states)):
        return None
    common = None
    for state in states:
        held = {name for name, word in builtins.iter((state or {}).items()) if word}
        common = held if common is None else common & held
    return dict.fromkeys(common or set(), True)
