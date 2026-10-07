"""Finite progress-preserving CFG collapse and paired cutpoint proposals.

Layer: dosunit relational control-flow proof.
Responsibility: derive finite superblocks and a closed graph correspondence
from binary CFG edges. Correspondence is a proposal only; consumers must prove
complete state transitions, branch agreement and exits before claiming equality.
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass
from enum import StrEnum


class RegionExitKind(StrEnum):
    """Admitted transition boundary in an integer-function proof."""

    BORING = "Ijk_Boring"
    CALL = "Ijk_Call"
    RETURN = "Ijk_Ret"


class RegionGraphReason(StrEnum):
    """Missing graph/progress obligation, never an execution counterexample."""

    EMPTY = "empty_region"
    ENTRY = "entry_block_unmapped"
    UNMAPPED = "successor_outside_region"
    EXIT = "invalid_region_exit"
    CHAIN_CYCLE = "unconditional_chain_cycle"
    SHAPE = "cfg_shape_mismatch"
    BIJECTION = "cfg_not_bijective"
    CLOSURE = "cfg_not_closed"
    MEMBERS = "region_materialization_incomplete"
    PROGRESS_MISSING = "internal_region_progress_missing"
    PROGRESS = "internal_region_progress_unproved"


class RegionGraphRefusal(Exception):
    """Structured failure of a candidate cutpoint/progress correspondence."""

    def __init__(self, reason: RegionGraphReason) -> None:
        """Retain the typed obligation at the graph/solver boundary."""
        self.reason = reason
        super().__init__(reason.value)


@dataclass(frozen=True, slots=True)
class RegionNode:
    """One binary-derived block and its ordered physical successor addresses."""

    address: int
    successors: tuple[int, ...]
    kind: RegionExitKind


@dataclass(frozen=True, slots=True)
class CollapsedRegion:
    """A nonempty finite chain with its final block's ordered boundary edges."""

    members: tuple[int, ...]
    exits: tuple[int, ...]
    kind: RegionExitKind


@dataclass(frozen=True, slots=True)
class RegionPartition:
    """Complete block ownership and finite nonzero step counts at cutpoints."""

    regions: tuple[CollapsedRegion, ...]
    owners: dict[int, int]
    entry: int


def _check_nodes(nodes: dict[int, RegionNode], entry: int) -> None:
    """Reject incomplete edges and inconsistent return/call boundaries."""
    if not nodes:
        raise RegionGraphRefusal(RegionGraphReason.EMPTY)
    if entry not in nodes:
        raise RegionGraphRefusal(RegionGraphReason.ENTRY)
    for address, node in nodes.items():
        if address != node.address or len(set(node.successors)) != len(node.successors):
            raise RegionGraphRefusal(RegionGraphReason.EXIT)
        if any(target not in nodes for target in node.successors):
            raise RegionGraphRefusal(RegionGraphReason.UNMAPPED)
        if node.kind is RegionExitKind.RETURN:
            if node.successors:
                raise RegionGraphRefusal(RegionGraphReason.EXIT)
        elif not node.successors or (node.kind is RegionExitKind.CALL and len(node.successors) != 1):
            raise RegionGraphRefusal(RegionGraphReason.EXIT)


def _chain(head: int, merged: dict[int, int]) -> tuple[int, ...]:
    """Follow a strictly finite internal chain; reject an internal cycle."""
    members = [head]
    seen = {head}
    while members[-1] in merged:
        target = merged[members[-1]]
        if target in seen:
            raise RegionGraphRefusal(RegionGraphReason.CHAIN_CYCLE)
        members.append(target)
        seen.add(target)
    return tuple(members)


def collapse_regions(nodes: dict[int, RegionNode], entry: int) -> RegionPartition:
    """Collapse only finite single-entry unconditional BORING chains.

    The function entry has an extra predecessor for its initial state. Calls
    stay boundaries so their checked continuation cannot disappear into a
    chain. Every paired transition contains at least one real block, and a
    cycle with no surviving cutpoint remains a missing progress obligation.
    """
    _check_nodes(nodes, entry)
    incoming = Counter(target for node in nodes.values() for target in node.successors)
    incoming[entry] += 1
    merged = {address: node.successors[0] for address, node in nodes.items()
              if node.kind is RegionExitKind.BORING and len(node.successors) == 1
              and incoming[node.successors[0]] == 1}
    targets = set(merged.values())
    owners: dict[int, int] = {}
    regions: list[CollapsedRegion] = []
    for head in sorted(nodes):
        if head in targets:
            continue
        members = _chain(head, merged)
        tail = nodes[members[-1]]
        if tail.kind is RegionExitKind.BORING and tail.successors == (head,):
            raise RegionGraphRefusal(RegionGraphReason.CHAIN_CYCLE)
        for address in members:
            owners[address] = len(regions)
        regions.append(CollapsedRegion(members, tail.successors, tail.kind))
    if len(owners) != len(nodes):
        raise RegionGraphRefusal(RegionGraphReason.CHAIN_CYCLE)
    return RegionPartition(tuple(regions), owners, entry)


def pair_regions(oracle: RegionPartition, candidate: RegionPartition) -> tuple[tuple[int, int], ...]:
    """Propose a bijection preserving entry and ordered boundary edges.

    Graph agreement never proves branch meaning or machine effects. The
    consumer must bind each proposed successor to a solver-checked control
    relation and prove every transition over complete cutpoint state.
    """
    return pair_region_edges(oracle.regions, candidate.regions, oracle.owners, candidate.owners,
                             oracle.entry, candidate.entry)


def _check_region_targets(regions: tuple[CollapsedRegion, ...], targets: dict[int, int]) -> None:
    """Require nonempty regions, closed boundary maps and valid region indices."""
    if not regions or any(not region.members for region in regions):
        raise RegionGraphRefusal(RegionGraphReason.EMPTY)
    if any(target not in targets for region in regions for target in region.exits):
        raise RegionGraphRefusal(RegionGraphReason.UNMAPPED)
    if any(not 0 <= index < len(regions) for index in targets.values()):
        raise RegionGraphRefusal(RegionGraphReason.BIJECTION)


def pair_region_edges(
    oracle_regions: tuple[CollapsedRegion, ...], candidate_regions: tuple[CollapsedRegion, ...],
    oracle_targets: dict[int, int], candidate_targets: dict[int, int],
    oracle_entry: int, candidate_entry: int,
) -> tuple[tuple[int, int], ...]:
    """Pair closed boundary edges without assuming unique internal block ownership.

    Both disjoint partitions and overlapping finite covers provide their actual
    boundary maps. Every region participates in the closed bijection; interior
    members are not relabeled as having one owner when several regions use them.
    """
    if oracle_entry not in oracle_targets or candidate_entry not in candidate_targets:
        raise RegionGraphRefusal(RegionGraphReason.ENTRY)
    _check_region_targets(oracle_regions, oracle_targets)
    _check_region_targets(candidate_regions, candidate_targets)
    pending = deque([(oracle_targets[oracle_entry], candidate_targets[candidate_entry])])
    forward: dict[int, int] = {}
    backward: dict[int, int] = {}
    pairs: list[tuple[int, int]] = []
    while pending:
        left, right = pending.popleft()
        if left in forward:
            if forward[left] != right:
                raise RegionGraphRefusal(RegionGraphReason.BIJECTION)
            continue
        if right in backward:
            raise RegionGraphRefusal(RegionGraphReason.BIJECTION)
        original, rebuilt = oracle_regions[left], candidate_regions[right]
        if original.kind is not rebuilt.kind or len(original.exits) != len(rebuilt.exits):
            raise RegionGraphRefusal(RegionGraphReason.SHAPE)
        forward[left], backward[right] = right, left
        pairs.append((left, right))
        pending.extend(zip((oracle_targets[address] for address in original.exits),
                           (candidate_targets[address] for address in rebuilt.exits), strict=True))
    if len(pairs) != len(oracle_regions) or len(pairs) != len(candidate_regions):
        raise RegionGraphRefusal(RegionGraphReason.CLOSURE)
    return tuple(pairs)
