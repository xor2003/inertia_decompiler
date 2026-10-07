"""Tests for default-deny, mutation-free abnormal-loop eligibility."""

from inertia.structuring.structuring_abnormal_loops import (
    AbnormalLoopStructureAnalysis,
    apply_abnormal_loop_normalization,
    build_abnormal_loop_normalization_plan,
)
from inertia.structuring.structuring_loops import (
    LoopTopologyVerdict8616,
    NaturalLoopTopology8616,
    detect_natural_loop,
)
from inertia.structuring.structuring_region import Region, RegionGraph, RegionType, compute_dominators


def _make_exact_loop() -> tuple[RegionGraph, dict[int, Region], NaturalLoopTopology8616]:
    """Build and classify the exact positive natural-loop fixture."""
    regions = {
        region_id: Region(block_addr=region_id, region_type=RegionType.Linear)
        for region_id in range(5)
    }
    graph = RegionGraph()
    graph.entry = regions[0]
    for region in regions.values():
        graph.add_node(region)
    for source, target in ((0, 1), (1, 2), (1, 4), (2, 3), (3, 1)):
        graph.add_edge(regions[source], regions[target])
    topology = detect_natural_loop(graph, compute_dominators(graph), regions[1])
    assert topology is not None
    assert topology.verdict is LoopTopologyVerdict8616.PROVEN
    return graph, regions, topology


def _graph_snapshot(graph: RegionGraph) -> tuple[tuple[int | None, str, tuple[int | None, ...], tuple[str, ...]], ...]:
    """Capture graph shape and owned region state for mutation checks."""
    return tuple(
        (
            region.region_id,
            region.region_type.value,
            tuple(sorted(successor.region_id for successor in graph.successors(region) if successor.region_id is not None)),
            tuple(sorted(region.metadata)),
        )
        for region in sorted(graph.nodes, key=lambda item: item.region_id or 0)
    )


def test_missing_typed_condition_eligibility_is_unknown_refuse():
    """Absent eligibility is default deny, never implicit authorization."""
    graph, _regions, topology = _make_exact_loop()

    plan = build_abnormal_loop_normalization_plan(graph, compute_dominators(graph), topology)

    assert plan.verdict is LoopTopologyVerdict8616.UNKNOWN_REFUSE
    assert plan.refusal_reason == "missing-typed-condition-eligibility"
    assert plan.can_normalize is False


def test_false_typed_condition_eligibility_is_unknown_refuse():
    """An explicit false condition gate remains a typed refusal."""
    graph, regions, topology = _make_exact_loop()
    regions[1].metadata["typed_ir_allow_abnormal_loop_normalization"] = False

    plan = build_abnormal_loop_normalization_plan(graph, compute_dominators(graph), topology)

    assert plan.verdict is LoopTopologyVerdict8616.UNKNOWN_REFUSE
    assert plan.refusal_reason == "typed-condition-eligibility-not-proven"
    assert plan.can_normalize is False


def test_true_eligibility_does_not_authorize_abnormal_mutation():
    """Exact normal topology has no abnormal selectors to materialize."""
    graph, regions, topology = _make_exact_loop()
    regions[1].metadata["typed_ir_allow_abnormal_loop_normalization"] = True
    before = _graph_snapshot(graph)
    plan = build_abnormal_loop_normalization_plan(graph, compute_dominators(graph), topology)

    changed = apply_abnormal_loop_normalization(graph, regions[1], topology, plan)

    assert plan.verdict is LoopTopologyVerdict8616.PROVEN
    assert plan.can_normalize is False
    assert changed is False
    assert _graph_snapshot(graph) == before


def test_abnormal_analysis_inherits_non_mutating_topology_publication():
    """The abnormal-loop analysis cannot collapse or mark a proven natural loop."""
    graph, regions, _topology = _make_exact_loop()
    analysis = AbnormalLoopStructureAnalysis(graph)
    before = _graph_snapshot(graph)

    assert analysis._try_natural_loop(regions[1]) is False

    assert analysis.natural_loop_topologies[1].verdict is LoopTopologyVerdict8616.PROVEN
    assert _graph_snapshot(graph) == before
    assert all(region.region_type is RegionType.Linear for region in graph.nodes)
