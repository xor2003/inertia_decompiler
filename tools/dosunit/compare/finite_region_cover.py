"""Overlapping finite CFG regions for loop-header rotation proposals.

Layer: dosunit relational control-flow proof.
Responsibility: retain closed cutpoints and complete binary-block coverage while
allowing one finite guard suffix to occur in multiple composed transitions.
Graph correspondence proposes synchronization only; state and progress require
the existing complete transition proofs before any equivalence is admitted.
"""

from __future__ import annotations

from dataclasses import dataclass

from tools.dosunit.compare.paired_region_graph import (
    CollapsedRegion,
    RegionExitKind,
    RegionGraphReason,
    RegionGraphRefusal,
    RegionNode,
    _check_nodes,
    pair_region_edges,
)


@dataclass(frozen=True, slots=True)
class FiniteRegionCover:
    """A complete cover with unique cutpoints and potentially shared suffixes."""

    regions: tuple[CollapsedRegion, ...]
    cutpoints: dict[int, int]
    entry: int
    covered: frozenset[int]


def _region(nodes: dict[int, RegionNode], head: int, cutpoints: set[int]) -> CollapsedRegion:
    """Follow a nonempty finite chain to a boundary without crossing a cutpoint."""
    members: list[int] = []
    seen: set[int] = set()
    current = head
    while True:
        if current in seen:
            raise RegionGraphRefusal(RegionGraphReason.CHAIN_CYCLE)
        seen.add(current)
        members.append(current)
        node = nodes[current]
        if node.kind is not RegionExitKind.BORING or len(node.successors) != 1:
            break
        target = node.successors[0]
        if target in cutpoints:
            if target == head:
                raise RegionGraphRefusal(RegionGraphReason.CHAIN_CYCLE)
            break
        current = target
    return CollapsedRegion(tuple(members), node.successors, node.kind)


def cover_regions(nodes: dict[int, RegionNode], entry: int) -> FiniteRegionCover:
    """Propose finite transitions allowing shared unconditional guard suffixes.

    Entry and successors of branches/calls are retained cutpoints. Unconditional
    prefixes may reach one shared guard from several cutpoints, so each path
    includes that guard's real effects independently. Every edge remains closed,
    every source block is covered, and no branch or cycle is silently skipped.
    """
    _check_nodes(nodes, entry)
    boundaries: set[int] = set()
    for node in nodes.values():
        if node.kind is RegionExitKind.CALL or len(node.successors) > 1:
            boundaries.update(node.successors)
    # Initial entry is a starting cutpoint, but unconditional reentry may include
    # its real guard effects in the predecessor transition. Conditional reentry
    # retains entry as a boundary through the successor rule above.
    heads = boundaries | {entry}
    regions = tuple(_region(nodes, head, boundaries) for head in sorted(heads))
    covered = frozenset(member for region in regions for member in region.members)
    if covered != frozenset(nodes):
        raise RegionGraphRefusal(RegionGraphReason.CLOSURE)
    cutpoints = {region.members[0]: index for index, region in enumerate(regions)}
    if any(target not in cutpoints for region in regions for target in region.exits):
        raise RegionGraphRefusal(RegionGraphReason.CLOSURE)
    return FiniteRegionCover(regions, cutpoints, entry, covered)


def pair_covers(oracle: FiniteRegionCover, candidate: FiniteRegionCover) -> tuple[tuple[int, int], ...]:
    """Match only retained cutpoints; shared members do not own a unique region."""
    return pair_region_edges(oracle.regions, candidate.regions, oracle.cutpoints, candidate.cutpoints,
                             oracle.entry, candidate.entry)
