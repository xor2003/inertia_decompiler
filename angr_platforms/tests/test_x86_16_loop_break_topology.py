"""New break guards require binary CFG exit evidence, never missing AST tags."""

from types import SimpleNamespace

import networkx as nx
import pytest
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CStatements, CWhileLoop
from angr_platforms.X86_16.register_source_block_inventory import (
    RegisterSourceBlockEvidence8616,
    RegisterSourceBlockInventory8616,
)
from angr_platforms.X86_16.structuring import loop_break_jcc, loop_break_topology
from angr_platforms.X86_16.structuring.loop_break_topology import LoopBreakTopology8616
from angr_platforms.X86_16.structuring.natural_loop_topology import classify_natural_loop_topology_8616
from test_x86_16_structuring_loop_break_jcc import _callbacks, _const, _DummyCodegen, _Insn, _reg


def topology(internal_target=False):
    graph = nx.DiGraph([(0x4000, 0x4010), (0x4010, 0x4000), (0x4000, 0x4007), (0x4007, 0x4020)])
    if internal_target:
        graph.add_edges_from([(0x4020, 0x4010), (0x4010, 0x4030)])
    loop = classify_natural_loop_topology_8616(graph, header=0x4000, latch=0x4010)
    return LoopBreakTopology8616((loop,), frozenset(graph.edges))


@pytest.mark.parametrize("evidence_kind", ["exit", "internal", "missing"])
def test_new_break_requires_cfg_exit(monkeypatch, evidence_kind):
    codegen = _DummyCodegen()
    assignment = CAssignment(_reg("ax", codegen), _const(1, codegen), codegen=codegen, tags={"ins_addr": 0x4010})
    loop = CWhileLoop(_const(1, codegen), CStatements([assignment], codegen=codegen), codegen=codegen)
    codegen.cfunc.statements = CStatements([loop], codegen=codegen)
    evidence = None if evidence_kind == "missing" else topology(evidence_kind == "internal")
    monkeypatch.setattr(loop_break_jcc, "collect_loop_break_topology_8616", lambda *_: evidence)
    changed = loop_break_jcc.materialize_unconsumed_loop_break_jcc_8616(
        SimpleNamespace(), codegen, _callbacks(_Insn(0x4005, "jg", 0x4010), evidence=[]),
    )
    assert changed is (evidence_kind == "exit")
    stats = codegen._inertia_unconsumed_loop_break_jcc_stats_8616
    assert stats.classified_fact_count == int(evidence_kind == "exit")
    assert stats.materialized_count == int(evidence_kind == "exit")
    if evidence_kind != "exit":
        assert loop.body.statements == [assignment]


@pytest.mark.parametrize("complete", [True, False])
def test_topology_collection_requires_complete_inventory(monkeypatch, complete):
    expected = topology()
    nodes = sorted({address for edge in expected.edges for address in edge})
    blocks = tuple(
        RegisterSourceBlockEvidence8616(address, tuple(sorted(src for src, dst in expected.edges if dst == address)), ())
        for address in nodes
    )
    count = len(blocks)
    inventory = RegisterSourceBlockInventory8616(0x4000, blocks, count, count, count, count, 0 if complete else 1)
    monkeypatch.setattr(loop_break_topology, "collect_register_source_block_inventory_8616", lambda _: inventory)
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_: object())))
    result = loop_break_topology.collect_loop_break_topology_8616(project, _DummyCodegen())
    if not complete:
        assert result is None
        return
    assert result == expected
    assert result.proves_exit(0x4000, 0x4010, 0x4007, 0x4020)
    assert not result.proves_exit(0x4000, 0x4010, 0x4010, 0x4020)


def test_missing_function_cfg_is_not_exit_evidence():
    assert loop_break_topology.collect_loop_break_topology_8616(SimpleNamespace(), _DummyCodegen()) is None


@pytest.mark.parametrize("extra_latch", [False, True])
def test_inner_loop_latch_excludes_outer_loop_reentry(extra_latch):
    graph = nx.DiGraph([(1, 2), (2, 3), (2, 6), (3, 4), (3, 5), (4, 3), (5, 2)])
    if extra_latch:
        graph.add_edges_from([(3, 7), (7, 3)])
    inner = classify_natural_loop_topology_8616(graph, header=3, latch=4, entry=1)
    assert inner.is_proven is not extra_latch
    if not extra_latch:
        assert inner.body == (3, 4)
        assert inner.entry_edges == ((2, 3),)
        assert inner.exit_edges == ((3, 5),)


@pytest.mark.parametrize("edges,entry,expected", [
    ([(1, 1), (1, 2)], 1, ((1, 1),)),
    ([(100, 20), (20, 100), (20, 300)], 100, ((100, 20),)),
    ([(0, 1), (0, 2), (1, 2), (2, 1)], 0, ()),
])
def test_backedges_require_dominance_not_address_order(edges, entry, expected):
    assert loop_break_topology._back_edges(nx.DiGraph(edges), entry) == expected


@pytest.mark.parametrize("case", ["empty", "effect", "refusal", "mismatch", "missing"])
def test_convergent_exits_require_ssa_transparency(monkeypatch, case):
    from angr_platforms.X86_16.ir.core import IRInstr
    from angr_platforms.X86_16.ir.ssa import SSABlock
    from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact

    latch, exit_connector = 4, 5
    graph = nx.DiGraph([(1, 2), (2, 3), (2, 5), (3, 4), (3, 6), (4, 2), (5, 7), (6, 7)])
    predecessors = {node: tuple(graph.predecessors(node)) for node in graph}
    blocks = tuple(RegisterSourceBlockEvidence8616(node, predecessors[node], ()) for node in graph)
    count = len(blocks)
    inventory = RegisterSourceBlockInventory8616(1, blocks, count, count, count, count, 0)
    artifact = SSAFunctionArtifact(
        1,
        tuple(
            SSABlock(
                node,
                () if node in (4, 5, 6) and not (case == "effect" and node == exit_connector)
                else (IRInstr(op="CALL", dst=None, args=(), size=0, addr=node),),
                (), refusals=("unknown",) if case == "refusal" and node == exit_connector else (),
            )
            for node in graph
        ),
        predecessor_map={**predecessors, 7: (6,)} if case == "mismatch" else predecessors,
    )
    monkeypatch.setattr(loop_break_topology, "collect_register_source_block_inventory_8616", lambda _: inventory)
    monkeypatch.setattr(
        loop_break_topology, "registered_function_ssa_artifact_8616",
        lambda *_: SimpleNamespace(artifact=None if case == "missing" else artifact), raising=False,
    )
    project = SimpleNamespace(kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_: object())))
    result = loop_break_topology.collect_loop_break_topology_8616(project, _DummyCodegen())
    if case != "empty":
        assert result is None
        return
    assert result is not None
    assert result.edges == frozenset(graph.edges)
    assert result.loops[0].latch == latch
    assert result.loops[0].exit_edges == ((2, 7), (3, 7))
    assert result.proves_exit(3, 4, 6, 7)
    assert not result.proves_exit(3, 4, 5, 7)
