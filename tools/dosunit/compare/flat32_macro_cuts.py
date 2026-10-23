"""Finite feedback-cut proposals for flat32 path induction.

Layer: dosunit relational control-flow proposal.
Responsibility: choose real DFS backedge targets as macro cuts. Ordered pairing
is a proposal only; all paths and every cut still require complete state proofs.
"""

from __future__ import annotations

from tools.dosunit.compare.macro_step_contracts import MacroStepReason, MacroStepRefusal
from tools.dosunit.compare.paired_region_graph import RegionNode


def _feedback_heads(nodes: dict[int, RegionNode], entry: int) -> tuple[int, ...]:
    """Retain entry and each DFS backedge target, cutting every reachable cycle."""
    visited = {entry}
    active = {entry}
    cuts = {entry}
    stack = [(entry, iter(nodes[entry].successors))]
    while stack:
        head, successors = stack[-1]
        target = next(successors, None)
        if target is None:
            active.remove(head)
            stack.pop()
        elif target in active:
            cuts.add(target)
        elif target not in visited:
            visited.add(target)
            active.add(target)
            stack.append((target, iter(nodes[target].successors)))
    return (entry, *sorted(cuts - {entry}))


def propose_feedback_cut_pairs(
    oracle: dict[int, RegionNode], candidate: dict[int, RegionNode],
    oracle_entry: int, candidate_entry: int,
) -> tuple[tuple[int, int], ...]:
    """Pair entry and ordered native feedback heads without claiming equality."""
    left = _feedback_heads(oracle, oracle_entry)
    right = _feedback_heads(candidate, candidate_entry)
    if len(left) != len(right):
        raise MacroStepRefusal(MacroStepReason.MACRO_ENDPOINT, {"detail": "feedback_cut_count"})
    return tuple(zip(left, right, strict=True))
