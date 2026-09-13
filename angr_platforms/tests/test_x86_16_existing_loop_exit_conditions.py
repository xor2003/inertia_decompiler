"""Prove existing loop-break guards from exact CFG targets, not source tags."""

from dataclasses import replace

import networkx as nx
import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CBreak,
    CConstant,
    CDoWhileLoop,
    CIfElse,
    CStatements,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import IRValue, MemSpace
from angr_platforms.X86_16.pipeline.errors import PipelineHardError
from angr_platforms.X86_16.structuring.condition_materialization import (
    condition_key_from_tags_8616,
    invert_structured_condition_8616,
)
from angr_platforms.X86_16.structuring.existing_loop_exit_conditions import (
    _loop_owner_8616,
    materialize_existing_loop_exit_conditions_8616,
)
from angr_platforms.X86_16.structuring.loop_break_topology import LoopBreakTopology8616
from angr_platforms.X86_16.structuring.natural_loop_topology import classify_natural_loop_topology_8616
from test_x86_16_typed_condition_side_effect_preservation import _codegen


@pytest.mark.parametrize("case", ["connector", "direct", "wrong-header", "unbound"])
def test_posttest_owner_uses_body_header_and_proven_latch(case):
    codegen = _codegen()
    latch = 0x1030 if case == "direct" else 0x1038
    edges = [(0x1000, 0x1010), (0x1010, 0x1020), (0x1020, 0x1030),
             (0x1020, 0x1040), (0x1030, 0x1040), (latch, 0x1010)]
    if case != "direct":
        edges.append((0x1030, latch))
    graph = nx.DiGraph(edges)
    region = classify_natural_loop_topology_8616(graph, header=0x1010, latch=latch, entry=0x1000)
    condition = CBinaryOp("CmpNE", CConstant(1, SimTypeShort(False), codegen=codegen),
                          CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen,
                          tags={"ins_addr": 0x1035, "vex_block_addr": 0x1030,
                                "inertia_typed_loop_condition_bound_8616": case != "unbound",
                                "inertia_typed_loop_condition_key_8616": (0x1035, 0x1030),
                                "inertia_typed_loop_continuation_edge_8616": "taken"})
    entry = CConstant(0, SimTypeShort(False), codegen=codegen,
                      tags={"vex_block_addr": 0x1018 if case == "wrong-header" else 0x1010})
    loop = CDoWhileLoop(condition, CStatements([entry], codegen=codegen), codegen=codegen)
    result = _loop_owner_8616(loop, LoopBreakTopology8616((region,), frozenset(edges)))
    assert result is (None if case in {"wrong-header", "unbound"} else region)


def _fixture():
    codegen = _codegen()
    zero = CConstant(0, SimTypeShort(False), codegen=codegen)
    one = CConstant(1, SimTypeShort(False), codegen=codegen)
    header = CBinaryOp("CmpNE", one, zero, codegen=codegen, tags={
        "ins_addr": 0x1012, "vex_block_addr": 0x1010,
        "inertia_typed_loop_condition_key_8616": (0x1012, 0x1010),
        "inertia_typed_loop_condition_bound_8616": True,
        "inertia_typed_loop_continuation_edge_8616": "taken",
    })
    condition = CBinaryOp("CmpGT", one, zero, codegen=codegen,
                          tags={"ins_addr": 0x1025, "vex_block_addr": 0x1020})
    body = CStatements([CBreak(codegen=codegen)], codegen=codegen)
    guard = CIfElse([(condition, body)], codegen=codegen)
    loop = CWhileLoop(header, CStatements([guard], codegen=codegen), codegen=codegen)
    graph = nx.DiGraph([(0x1000, 0x1010), (0x1010, 0x1020), (0x1010, 0x1040),
                       (0x1020, 0x1030), (0x1020, 0x1040), (0x1030, 0x1010)])
    natural = classify_natural_loop_topology_8616(graph, header=0x1010, latch=0x1030)
    topology = LoopBreakTopology8616((natural,), frozenset(graph.edges))
    fact = ConditionIR("sgt", IRValue(MemSpace.REG, name="ax", offset=8, size=2),
                       IRValue(MemSpace.CONST, const=0, size=2), src_insn=0x1025,
                       block_addr=0x1020, taken_target=0x1040, fallthrough_target=0x1030)
    return codegen, loop, guard, condition, fact, topology


def _run(codegen, loop, facts, topology, *, lower=None):
    def default_lower(_fact):
        return CBinaryOp("CmpGT", CConstant(1, SimTypeShort(False), codegen=codegen),
                         CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen)

    return materialize_existing_loop_exit_conditions_8616(
        loop, facts, topology, condition_key=condition_key_from_tags_8616,
        lower=default_lower if lower is None else lower,
        invert=lambda expression: invert_structured_condition_8616(expression, codegen),
        record_precision=lambda _before, _after: True,
    )


@pytest.mark.parametrize("taken_exits", [False, True])
def test_existing_break_uses_proven_exit_polarity_and_preserves_body(taken_exits):
    codegen, loop, guard, _, fact, topology = _fixture()
    if not taken_exits:
        fact = replace(fact, taken_target=fact.fallthrough_target, fallthrough_target=fact.taken_target)
    body = guard.condition_and_nodes[0][1]
    stats = _run(codegen, loop, (fact,), topology)
    condition = guard.condition_and_nodes[0][0]
    assert condition.op == ("CmpGT" if taken_exits else "CmpLE")
    assert condition.tags["inertia_structuring_condition_cfg_materialized_8616"]
    assert condition_key_from_tags_8616(condition) == (fact.src_insn, fact.block_addr)
    assert guard.condition_and_nodes[0][1] is body
    assert stats.classified_fact_count == stats.materialized_count == stats.changed_count == 1
    assert stats.failure_count == 0
    assert _run(codegen, loop, (fact,), topology).changed_count == 0


@pytest.mark.parametrize("corruption", ["no_topology", "wrong_header", "ambiguous_loop", "wrong_edge",
                                         "extra_exit", "duplicate_fact", "missing_fact", "compound", "effect"])
def test_existing_break_refuses_incomplete_exit_proof(corruption):
    codegen, loop, guard, condition, fact, topology = _fixture()
    facts = (fact,)
    if corruption == "no_topology":
        topology = None
    elif corruption == "wrong_header":
        loop.condition.tags = {}
    elif corruption == "ambiguous_loop":
        topology = replace(topology, loops=topology.loops * 2)
    elif corruption == "wrong_edge":
        fact = replace(fact, taken_target=0x1050)
        facts = (fact,)
    elif corruption == "extra_exit":
        graph = nx.DiGraph(topology.edges)
        graph.remove_edge(0x1020, 0x1040)
        graph.add_edge(0x1020, 0x1050)
        natural = classify_natural_loop_topology_8616(graph, header=0x1010, latch=0x1030)
        topology = LoopBreakTopology8616((natural,), frozenset(graph.edges))
        facts = (replace(fact, taken_target=0x1050),)
    elif corruption == "duplicate_fact":
        facts = (fact, fact)
    elif corruption == "missing_fact":
        facts = ()
    elif corruption == "compound":
        condition.op = "LogicalOr"
        condition.rhs = condition.lhs
    else:
        guard.condition_and_nodes[0][1].statements.insert(0, CConstant(7, SimTypeShort(False), codegen=codegen))
    stats = _run(codegen, loop, facts, topology)
    assert stats.materialized_count == stats.changed_count == 0
    assert guard.condition_and_nodes[0][0] is condition


def test_classified_exit_reports_lowering_failure_early():
    codegen, loop, _, _, fact, topology = _fixture()
    with pytest.raises(PipelineHardError, match="loop-exit condition jcc=0x1025"):
        _run(codegen, loop, (fact,), topology, lower=lambda _fact: None)


@pytest.mark.parametrize("fault", [None, "missing-header", "wrong-entry", "nonconstant", "ambiguous"])
def test_unconditional_loop_requires_matching_cfg_header_and_body_entry(fault):
    codegen, loop, guard, old_condition, fact, topology = _fixture()
    header = topology.loops[0].header
    loop.condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    loop.tags = {"ins_addr": header}
    entry = CConstant(0, SimTypeShort(False), codegen=codegen, tags={"vex_block_addr": header})
    loop.body.statements.insert(0, entry)
    if fault == "missing-header":
        loop.tags = {}
    elif fault == "wrong-entry":
        entry.tags = {"vex_block_addr": fact.block_addr}
    elif fault == "nonconstant":
        loop.condition = old_condition
    elif fault == "ambiguous":
        topology = replace(topology, loops=topology.loops * 2)
    break_body = guard.condition_and_nodes[0][1]
    stats = _run(codegen, loop, (fact,), topology)
    assert stats.materialized_count == int(fault is None)
    assert guard.condition_and_nodes[0][1] is break_body
