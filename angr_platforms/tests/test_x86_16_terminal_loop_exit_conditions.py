"""Preserve composite branch ownership at terminal loop exits and on replay."""

from dataclasses import replace

import networkx as nx
import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CExpressionStatement,
    CIfElse,
    CMultiStatementExpression,
    CStatements,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.ir.ssa import SSABlock
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact
from angr_platforms.X86_16.pipeline.errors import PipelineHardError
from angr_platforms.X86_16.structuring.condition_chain_provenance import bind_condition_chain_provenance_8616
from angr_platforms.X86_16.structuring.condition_ownership import requires_composite_condition_ownership_8616
from angr_platforms.X86_16.structuring.loop_break_topology import LoopBreakTopology8616
from angr_platforms.X86_16.structuring.natural_loop_topology import classify_natural_loop_topology_8616
from angr_platforms.X86_16.structuring.terminal_loop_exit_conditions import (
    classify_terminal_loop_exit_8616,
    materialize_terminal_loop_exit_conditions_8616,
)
from test_x86_16_call_output_stack_objects import _wide_condition_fixture


@pytest.mark.parametrize("fact_count", [1, 3])
def test_compact_predicate_retains_its_composite_ownership(fact_count):
    codegen, _, facts, _, _ = _wide_condition_fixture()
    expression = CBinaryOp(
        "CmpGT", CConstant(1, SimTypeShort(False), codegen=codegen),
        CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen,
    )
    bind_condition_chain_provenance_8616(expression, facts[:fact_count])
    assert requires_composite_condition_ownership_8616(expression) is (fact_count > 1)


def _fixture(monkeypatch=None):
    codegen, expression, conditions, call, _ = _wide_condition_fixture(monkeypatch=monkeypatch)
    high, equal, low = conditions
    header, latch, exit_address = 0x1000, 0x1020, 0x1030
    facts = (
        replace(high, block_addr=high.src_insn, taken_target=equal.src_insn, fallthrough_target=exit_address),
        replace(equal, block_addr=equal.src_insn, taken_target=low.src_insn, fallthrough_target=latch),
        replace(low, block_addr=low.src_insn, taken_target=latch, fallthrough_target=exit_address),
    )
    for predicate, fact in zip((expression.lhs, expression.rhs.lhs, expression.rhs.rhs), facts, strict=True):
        predicate.tags = {"ins_addr": fact.src_insn, "vex_block_addr": fact.block_addr}
    before = CExpressionStatement(call, codegen=codegen, tags={"ins_addr": header, "vex_block_addr": header})
    guard = CIfElse([(expression, CBreak(codegen=codegen))], codegen=codegen, tags={"ins_addr": header})
    loop = CWhileLoop(CConstant(1, SimTypeShort(False), codegen=codegen),
                      CStatements([before, guard], codegen=codegen), codegen=codegen, tags={"ins_addr": header})
    successors = {f.block_addr: (f.taken_target, f.fallthrough_target) for f in facts}
    successors.update({header: (high.src_insn,), latch: (header,)})
    edges = frozenset((source, target) for source, targets in successors.items() for target in targets)
    natural = classify_natural_loop_topology_8616(nx.DiGraph(edges), header=header, latch=latch, entry=header)
    topology = LoopBreakTopology8616((natural,), edges)
    artifact = SSAFunctionArtifact(header, (SSABlock(latch, (), ()),), predecessor_map={header: (latch,)})
    return codegen, loop, facts, topology, successors, artifact


def test_terminal_exit_proves_wide_polarity_after_call_without_moving_it():
    _, loop, facts, topology, successors, artifact = _fixture()
    before = tuple(loop.body.statements)
    plan = classify_terminal_loop_exit_8616(loop, facts, topology, successors, artifact)
    assert plan is not None
    assert plan.guard is before[-1]
    assert plan.comparison.operator == "sgt"
    assert plan.comparison.conditions == facts
    assert tuple(loop.body.statements) == before


@pytest.mark.parametrize("fault", [
    "missing-fact", "duplicate-fact", "missing-tag", "wrong-header", "unknown-edge",
    "extra-exit", "nested-guard", "suffix-effect", "embedded-effect", "call-in-guard",
    "branch-body-effect", "missing-ssa", "conditional-header", "extra-loop-condition", "bypass-root",
])
def test_terminal_exit_refuses_incomplete_or_effectful_proof(fault):
    codegen, loop, facts, topology, successors, artifact = _fixture()
    _, guard = loop.body.statements
    current, _ = guard.condition_and_nodes[0]
    if fault == "missing-fact":
        facts = facts[1:]
    elif fault == "duplicate-fact":
        facts = (*facts, facts[0])
    elif fault == "missing-tag":
        current.lhs.tags = {}
    elif fault == "wrong-header":
        loop.tags = {"ins_addr": 0x7777}
    elif fault == "unknown-edge":
        successors[facts[0].block_addr] = ()
    elif fault in {"extra-exit", "bypass-root"}:
        target = 0x7777 if fault == "extra-exit" else facts[-1].block_addr
        edges = topology.edges | {(0x1000, target)}
        successors[0x1000] = (*successors[0x1000], target)
        region = classify_natural_loop_topology_8616(nx.DiGraph(edges), header=0x1000, latch=0x1020, entry=0x1000)
        topology = LoopBreakTopology8616((region,), edges)
    elif fault == "missing-ssa":
        artifact = None
    elif fault == "conditional-header":
        loop.condition = current
    elif fault == "extra-loop-condition":
        facts = (*facts, replace(facts[0], src_insn=0x1002, block_addr=0x1000))
    else:
        _damage_guard(codegen, loop, fault)
    assert classify_terminal_loop_exit_8616(loop, facts, topology, successors, artifact) is None


def _damage_guard(codegen, loop, fault):
    before, guard = loop.body.statements
    current, body = guard.condition_and_nodes[0]
    if fault == "nested-guard":
        loop.body.statements[-1] = CIfElse([(current, guard)], codegen=codegen)
    elif fault == "suffix-effect":
        loop.body.statements.append(before)
    elif fault == "embedded-effect":
        guard.condition_and_nodes = [(CMultiStatementExpression(
            CStatements([CAssignment(current.lhs, current.rhs, codegen=codegen)], codegen=codegen),
            current, codegen=codegen,
        ), body)]
    elif fault == "call-in-guard":
        current.lhs.lhs = before.expr
    elif fault == "branch-body-effect":
        guard.condition_and_nodes = [(current, CStatements([before, body], codegen=codegen))]
    else:
        pytest.fail(f"unknown corruption: {fault}")


def test_terminal_materialization_preserves_statement_positions_and_all_branch_owners():
    codegen, loop, facts, topology, successors, artifact = _fixture()
    before = tuple(loop.body.statements)
    old_body = before[-1].condition_and_nodes[0][1]
    expression = CBinaryOp("CmpGT", CConstant(1, SimTypeShort(False), codegen=codegen),
                          CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen)
    records = []
    stats = materialize_terminal_loop_exit_conditions_8616(
        loop, facts, topology, successors, artifact, lambda plan: expression,
        lambda old, new: records.append((old, new)) or True,
    )
    assert tuple(loop.body.statements) == before
    assert before[-1].condition_and_nodes[0] == (expression, old_body)
    assert requires_composite_condition_ownership_8616(expression)
    assert stats.classified_fact_count == stats.materialized_count == stats.changed_count == 1
    assert len(records) == 1
    # A compact predicate is no longer an unconsumed terminal decision.
    assert materialize_terminal_loop_exit_conditions_8616(
        loop, facts, topology, successors, artifact, lambda plan: pytest.fail("repeated lowering"),
        lambda old, new: True,
    ).changed_count == 0


def test_terminal_materialization_reports_classified_lowering_failure_early():
    _, loop, facts, topology, successors, artifact = _fixture()
    with pytest.raises(PipelineHardError, match="terminal-loop-exit jcc=0x1005"):
        materialize_terminal_loop_exit_conditions_8616(
            loop, facts, topology, successors, artifact, lambda plan: None, lambda old, new: True,
        )
