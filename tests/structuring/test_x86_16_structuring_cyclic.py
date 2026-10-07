"""Tests for mutation-free natural-loop topology publication."""

from inertia.structuring.structuring_analysis import StructureAnalysis
from inertia.structuring.structuring_loops import LoopTopologyVerdict8616
from inertia.structuring.structuring_region import Region, RegionGraph, RegionType


def _make_analysis(edges: list[tuple[int, int]]) -> tuple[StructureAnalysis, dict[int, Region]]:
    """Build a StructureAnalysis over stable integer-ID regions."""
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
    return StructureAnalysis(graph), regions


def _analysis_graph_snapshot(
    analysis: StructureAnalysis,
) -> tuple[tuple[int | None, str, tuple[int | None, ...], tuple[int | None, ...], tuple[str, ...]], ...]:
    """Capture graph topology, region kinds, and metadata keys."""
    return tuple(
        (
            region.region_id,
            region.region_type.value,
            tuple(
                sorted(
                    successor.region_id
                    for successor in analysis.graph.successors(region)
                    if successor.region_id is not None
                )
            ),
            tuple(
                sorted(
                    predecessor.region_id
                    for predecessor in analysis.graph.predecessors(region)
                    if predecessor.region_id is not None
                )
            ),
            tuple(sorted(region.metadata)),
        )
        for region in sorted(analysis.graph.nodes, key=lambda item: item.region_id or 0)
    )


def test_structure_analysis_publishes_proven_topology_without_collapse():
    """Topology proof is retained separately and does not authorize a loop region."""
    analysis, regions = _make_analysis([(0, 1), (1, 2), (1, 4), (2, 3), (3, 1)])
    before = _analysis_graph_snapshot(analysis)

    changed = analysis._try_natural_loop(regions[1])

    assert changed is False
    topology = analysis.natural_loop_topologies[1]
    assert topology.verdict is LoopTopologyVerdict8616.PROVEN
    assert topology.body == (1, 2, 3)
    assert _analysis_graph_snapshot(analysis) == before
    assert all(region.region_type is RegionType.Linear for region in analysis.graph.nodes)


def test_structure_analysis_publishes_external_entry_refusal():
    """A non-header entry is recorded as unknown without changing the graph."""
    analysis, regions = _make_analysis([(0, 1), (1, 2), (1, 4), (2, 3), (3, 1), (0, 2)])
    before = _analysis_graph_snapshot(analysis)

    assert analysis._try_natural_loop(regions[1]) is False

    topology = analysis.natural_loop_topologies[1]
    assert topology.verdict is LoopTopologyVerdict8616.UNKNOWN_REFUSE
    assert topology.refusal_reason == "external-non-header-entry"
    assert _analysis_graph_snapshot(analysis) == before


def test_structure_analysis_publishes_multiple_latch_refusal():
    """Two dominance-backed latches remain unstructured in the narrow slice."""
    analysis, regions = _make_analysis([(0, 1), (1, 2), (1, 3), (1, 4), (2, 1), (3, 1)])
    before = _analysis_graph_snapshot(analysis)

    assert analysis._try_natural_loop(regions[1]) is False

    topology = analysis.natural_loop_topologies[1]
    assert topology.verdict is LoopTopologyVerdict8616.UNKNOWN_REFUSE
    assert topology.refusal_reason == "non-unique-latch"
    assert _analysis_graph_snapshot(analysis) == before


def test_structure_analysis_publishes_multiple_exit_refusal():
    """Distinct loop exit targets cannot trigger region reduction."""
    analysis, regions = _make_analysis([(0, 1), (1, 2), (1, 4), (2, 3), (2, 5), (3, 1)])
    before = _analysis_graph_snapshot(analysis)

    assert analysis._try_natural_loop(regions[1]) is False

    topology = analysis.natural_loop_topologies[1]
    assert topology.verdict is LoopTopologyVerdict8616.UNKNOWN_REFUSE
    assert topology.refusal_reason == "non-unique-exit-target"
    assert _analysis_graph_snapshot(analysis) == before


def test_empty_graph_remains_empty():
    """The topology migration does not affect empty-graph convergence."""
    graph = RegionGraph()

    result = StructureAnalysis(graph).structure()

    assert not result.nodes


def test_single_region_graph_remains_unchanged():
    """Acyclic singleton analysis still converges without mutation."""
    region = Region(block_addr=0x7000, region_type=RegionType.Linear)
    graph = RegionGraph()
    graph.entry = region
    graph.add_node(region)
    analysis = StructureAnalysis(graph)

    result = analysis.structure()

    assert result.nodes == {region}
    assert analysis.stats.iterations <= 2


def test_linear_chain_reduction_remains_available():
    """Unrelated proven sequence reduction remains outside topology classification."""
    analysis, _regions = _make_analysis([(0, 1), (1, 2), (2, 3), (3, 4)])

    result = analysis.structure()

    assert len(result.nodes) <= 2
    assert analysis.stats.sequences_created > 0 or analysis.stats.regions_reduced > 0
