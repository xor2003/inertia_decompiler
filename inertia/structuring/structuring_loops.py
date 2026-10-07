"""Adapt typed region graphs to authoritative natural-loop topology evidence.

Layer: Structuring.
Responsibility: project RegionGraph identities into the deterministic topology owner.
Forbidden: confidence scoring, independent topology acceptance, graph mutation,
region collapse, or rendered-text inference.

Package ownership contract (canonical inertia/structuring package):
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass

from inertia.structuring.natural_loop_topology import (
    LoopTopologyStats8616,
    LoopTopologyVerdict8616,
    NaturalLoopTopology8616,
    classify_natural_loop_topology_8616,
)
from inertia.structuring.structuring_region import DominatorInfo, Region, RegionGraph

__all__ = (
    "LoopTopologyStats8616",
    "LoopTopologyVerdict8616",
    "NaturalLoopTopology8616",
    "detect_natural_loop",
)


@dataclass(frozen=True, slots=True)
class _RegionIdGraph8616:
    """Immutable integer-ID snapshot of one RegionGraph."""

    successor_map: dict[int, tuple[int, ...]]
    predecessor_map: dict[int, tuple[int, ...]]

    def successors(self, node: int) -> tuple[int, ...]:
        """Return deterministic successor IDs for one region."""
        return self.successor_map[node]

    def predecessors(self, node: int) -> tuple[int, ...]:
        """Return deterministic predecessor IDs for one region."""
        return self.predecessor_map[node]


def _region_id_graph_8616(graph: RegionGraph) -> tuple[_RegionIdGraph8616, dict[int, Region]] | None:
    """Snapshot a RegionGraph only when every node has one unique integer ID."""
    regions = tuple(graph.nodes)
    if any(not isinstance(region.region_id, int) for region in regions):
        return None
    regions_by_id = {region.region_id: region for region in regions if isinstance(region.region_id, int)}
    if len(regions_by_id) != len(regions):
        return None

    successor_map: dict[int, tuple[int, ...]] = {}
    predecessor_map: dict[int, tuple[int, ...]] = {}
    for region_id, region in sorted(regions_by_id.items()):
        successors = graph.successors(region)
        predecessors = graph.predecessors(region)
        if any(
            not isinstance(neighbor.region_id, int) or neighbor.region_id not in regions_by_id
            for neighbor in (*successors, *predecessors)
        ):
            return None
        successor_map[region_id] = tuple(
            sorted({neighbor.region_id for neighbor in successors if neighbor.region_id is not None})
        )
        predecessor_map[region_id] = tuple(
            sorted({neighbor.region_id for neighbor in predecessors if neighbor.region_id is not None})
        )
    return _RegionIdGraph8616(successor_map, predecessor_map), regions_by_id


def detect_natural_loop(
    graph: RegionGraph,
    dominators: DominatorInfo,
    region: Region,
) -> NaturalLoopTopology8616 | None:
    """Classify deterministic loop-header candidates without mutating them.

    Every direct predecessor is submitted to the authoritative classifier so
    that abnormal entries cannot erase the latch by invalidating dominance.
    ``None`` means that no predecessor has a loop-body path from the header.
    """
    del dominators
    if region not in graph.nodes or not isinstance(region.region_id, int):
        return None
    snapshot = _region_id_graph_8616(graph)
    if snapshot is None:
        return None
    id_graph, _regions_by_id = snapshot
    candidates = tuple(
        classify_natural_loop_topology_8616(id_graph, region.region_id, latch_id)
        for latch_id in id_graph.predecessors(region.region_id)
    )
    proven = tuple(candidate for candidate in candidates if candidate.is_proven)
    if len(proven) == 1:
        return proven[0]
    substantive_refusals = tuple(
        candidate
        for candidate in candidates
        if candidate.refusal_reason not in {"incomplete-loop-body", "missing-latch-backedge"}
    )
    return substantive_refusals[0] if substantive_refusals else None
