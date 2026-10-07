"""Tests for RegionGraph projection into exact natural-loop topology."""

from inertia.structuring.structuring_loops import (
    LoopTopologyStats8616,
    LoopTopologyVerdict8616,
    detect_natural_loop,
)
from inertia.structuring.structuring_region import Region, RegionGraph, RegionType, compute_dominators


def _make_region_graph(edges: list[tuple[int, int]]) -> tuple[RegionGraph, dict[int, Region]]:
    """Build one RegionGraph with stable integer identities."""
    region_ids = sorted({node for edge in edges for node in edge})
    regions = {
        region_id: Region(block_addr=region_id, region_type=RegionType.Linear)
        for region_id in region_ids
    }
    graph = RegionGraph()
    graph.entry = regions[0]
    for region in regions.values():
        graph.add_node(region)
    for source, target in edges:
        graph.add_edge(regions[source], regions[target])
    return graph, regions


def _graph_snapshot(graph: RegionGraph) -> tuple[tuple[int | None, str, tuple[int | None, ...], tuple[int | None, ...]], ...]:
    """Capture node types and exact adjacency for mutation checks."""
    return tuple(
        (
            region.region_id,
            region.region_type.value,
            tuple(sorted(successor.region_id for successor in graph.successors(region) if successor.region_id is not None)),
            tuple(
                sorted(predecessor.region_id for predecessor in graph.predecessors(region) if predecessor.region_id is not None)
            ),
        )
        for region in sorted(graph.nodes, key=lambda item: item.region_id or 0)
    )


def test_detect_natural_loop_returns_exact_typed_topology():
    """The RegionGraph adapter preserves all exact first-slice edges."""
    graph, regions = _make_region_graph([(0, 1), (1, 2), (1, 4), (2, 3), (3, 1)])
    before = _graph_snapshot(graph)

    topology = detect_natural_loop(graph, compute_dominators(graph), regions[1])

    assert topology is not None
    assert topology.verdict is LoopTopologyVerdict8616.PROVEN
    assert topology.body == (1, 2, 3)
    assert topology.entry_edges == ((0, 1),)
    assert topology.backedges == ((3, 1),)
    assert topology.exit_edges == ((1, 4),)
    assert topology.stats == LoopTopologyStats8616(1, 1, 1, 1, 0)
    assert _graph_snapshot(graph) == before


def test_region_graph_external_non_header_entry_refuses():
    """The adapter cannot turn an abnormal body entry into a natural loop."""
    graph, regions = _make_region_graph([(0, 1), (1, 2), (1, 4), (2, 3), (3, 1), (0, 2)])

    topology = detect_natural_loop(graph, compute_dominators(graph), regions[1])

    assert topology is not None
    assert topology.verdict is LoopTopologyVerdict8616.UNKNOWN_REFUSE
    assert topology.refusal_reason == "external-non-header-entry"


def test_region_graph_reversed_insertion_order_is_equivalent():
    """RegionGraph set iteration and edge insertion cannot change topology."""
    edges = [(0, 1), (1, 2), (1, 4), (2, 3), (3, 1)]
    graph_a, regions_a = _make_region_graph(edges)
    graph_b, regions_b = _make_region_graph(list(reversed(edges)))

    topology_a = detect_natural_loop(graph_a, compute_dominators(graph_a), regions_a[1])
    topology_b = detect_natural_loop(graph_b, compute_dominators(graph_b), regions_b[1])

    assert topology_a is not None
    assert topology_b == topology_a


def test_region_without_backedge_has_no_loop_candidate():
    """Forward-only control flow does not invent a topology candidate."""
    graph, regions = _make_region_graph([(0, 1), (1, 2)])

    assert detect_natural_loop(graph, compute_dominators(graph), regions[1]) is None
