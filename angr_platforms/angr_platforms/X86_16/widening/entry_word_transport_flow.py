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
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations

from ..ir.core import IRFunctionArtifact
from .entry_word_transport_contracts import (
    EntryWordTransportRefusalKind8616 as Refusal,
)


def _reachable_8616(
    artifact: IRFunctionArtifact,
    by_addr: dict[int, int],
) -> set[int]:
    """Forward-reachable in-artifact blocks from the entry address."""
    reachable: set[int] = set()
    stack = [artifact.function_addr]
    while stack:
        addr = stack.pop()
        if addr in reachable or addr not in by_addr:
            continue
        reachable.add(addr)
        stack.extend(artifact.blocks[by_addr[addr]].successor_addrs)
    return reachable


def _ancestors_8616(pred_map: dict[int, tuple[int, ...]], target: int) -> set[int]:
    """All in-function blocks that can reach the target by CFG edges."""
    can_reach: set[int] = {target}
    queue = [target]
    while queue:
        addr = queue.pop()
        for pred in pred_map.get(addr, ()):
            if pred not in can_reach:
                can_reach.add(pred)
                queue.append(pred)
    return can_reach


def _cone_exits_8616(
    artifact: IRFunctionArtifact,
    by_addr: dict[int, int],
    cone: set[int],
) -> tuple[int, ...]:
    """Sorted off-cone successors retained as open exits, never closure."""
    return tuple(sorted({
        succ
        for addr in cone
        for succ in artifact.blocks[by_addr[addr]].successor_addrs
        if succ not in cone
    }))


def _topological_order_8616(
    artifact: IRFunctionArtifact,
    by_addr: dict[int, int],
    pred_map: dict[int, tuple[int, ...]],
    cone: set[int],
) -> list[int] | None:
    """Stable ascending-addr topological order; None when the cone cycles."""
    indegree = {
        addr: sum(1 for pred in pred_map.get(addr, ()) if pred in cone)
        for addr in cone
    }
    ready = sorted(addr for addr, degree in indegree.items() if degree == 0)
    order: list[int] = []
    while ready:
        addr = ready.pop(0)
        order.append(addr)
        for succ in artifact.blocks[by_addr[addr]].successor_addrs:
            if succ in indegree:
                indegree[succ] -= 1
                if indegree[succ] == 0:
                    ready.append(succ)
        ready.sort()
    if len(order) != len(cone):
        return None
    return order


def cone_traversal_8616(
    artifact: IRFunctionArtifact,
    by_addr: dict[int, int],
    pred_map: dict[int, tuple[int, ...]],
    target: int,
) -> tuple[list[int] | None, tuple[int, ...], Refusal | None]:
    """Return the cone in deterministic topo order, retained exits, or refusal."""
    reachable = _reachable_8616(artifact, by_addr)
    if target not in reachable:
        return None, (), Refusal.UNREACHABLE_TARGET
    cone = reachable & _ancestors_8616(pred_map, target)
    order = _topological_order_8616(artifact, by_addr, pred_map, cone)
    if order is None:
        return None, (), Refusal.CFG_CYCLE
    return order, _cone_exits_8616(artifact, by_addr, cone), None


def meet_incoming_words_8616(
    pred_map: dict[int, tuple[int, ...]],
    exits_state: dict[int, dict[str, bool] | None],
    addr: int,
) -> dict[str, bool] | None:
    """Meet the proven-word registers across every in-function predecessor.

    Returns None when any predecessor is outside the evaluated cone or was
    itself poisoned; only registers carrying the word on all predecessors
    propagate as a seeded entry map.
    """
    states = [exits_state.get(pred) for pred in pred_map.get(addr, ())]
    if any(state is None for state in states):
        return None
    common: set[str] | None = None
    for state in states:
        held = {name for name, word in (state or {}).items() if word}
        common = held if common is None else common & held
    return dict.fromkeys(common or set(), True)
