"""Composite pretest guards require complete identities and effect-free exits."""

from dataclasses import replace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CIfElse,
    CMultiStatementExpression,
    CStatements,
    CUnaryOp,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import IRInstr
from angr_platforms.X86_16.ir.ssa import SSABlock
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact
from angr_platforms.X86_16.structuring.composite_pretest_conditions import (
    classify_composite_pretest_condition_8616,
    materialize_composite_pretest_conditions_8616,
)
from test_x86_16_validation_branch_conditions import _Codegen

BODY_TARGET = 0x200
EXIT_TARGET = 0x300

def _fixture():
    codegen = _Codegen(None)
    zero = CConstant(0, SimTypeShort(False), codegen=codegen)
    one = CConstant(1, SimTypeShort(False), codegen=codegen)
    facts = (
        ConditionIR("sgt", "down", "up", src_insn=0x105, block_addr=0x100,
                    taken_target=0x120, fallthrough_target=0x110),
        ConditionIR("sle", "item", "pivot", src_insn=0x125, block_addr=0x120,
                    taken_target=0x200, fallthrough_target=0x130),
    )
    predicates = [
        CBinaryOp("CmpNE", one, zero, codegen=codegen,
                  tags={"ins_addr": fact.src_insn, "vex_block_addr": fact.block_addr})
        for fact in facts
    ]
    condition = CUnaryOp("Not", CBinaryOp("LogicalAnd", *predicates, codegen=codegen), codegen=codegen)
    guard = CIfElse([(condition, CBreak(codegen=codegen))], else_node=None,
                    codegen=codegen, tags={"ins_addr": 0x100})
    update = CAssignment(one, zero, codegen=codegen, tags={"vex_block_addr": 0x200})
    body = CStatements([guard, update], codegen=codegen)
    loop = CWhileLoop(one, body, codegen=codegen)
    edges = {0x100: (0x120, 0x110), 0x120: (0x200, 0x130), 0x110: (0x300,), 0x130: (0x300,)}
    effect = IRInstr(op="CALL", dst=None, args=(), size=0, addr=0x300)
    artifact = SSAFunctionArtifact(0x100, (
        SSABlock(0x110, (), ()), SSABlock(0x130, (), ()), SSABlock(0x300, (effect,), ()),
    ), predecessor_map={0x300: (0x110, 0x130)})
    return codegen, loop, facts, edges, artifact


def test_composite_pretest_proves_full_guard_and_stops_before_exit_effect():
    _codegen, loop, facts, edges, artifact = _fixture()
    plan = classify_composite_pretest_condition_8616(loop, facts, edges, artifact)
    assert plan is not None
    assert plan.root_condition is facts[0]
    assert plan.conditions == facts
    assert plan.body_target == BODY_TARGET
    assert plan.exit_target == EXIT_TARGET
    assert artifact.blocks[-1].instrs[0].op == "CALL"


@pytest.mark.parametrize("fault", [
    "missing-ssa", "exit-effect", "cfg-conflict", "duplicate-fact", "unknown-owner",
    "prefix-effect", "embedded-effect", "unknown-body", "nonconstant-header",
])
def test_composite_pretest_refuses_incomplete_or_effectful_evidence(fault):
    codegen, loop, facts, edges, artifact = _fixture()
    guard, update = loop.body.statements
    condition, body = guard.condition_and_nodes[0]
    if fault == "missing-ssa":
        artifact = None
    elif fault == "exit-effect":
        artifact = replace(artifact, blocks=(
            replace(artifact.blocks[0], instrs=artifact.blocks[-1].instrs), *artifact.blocks[1:],
        ))
    elif fault == "cfg-conflict":
        edges[0x100] = (0x200, 0x110)
    elif fault == "duplicate-fact":
        facts = (*facts, facts[0])
    elif fault == "unknown-owner":
        guard.tags = {}
    elif fault == "prefix-effect":
        loop.body.statements.insert(0, update)
    elif fault == "embedded-effect":
        guard.condition_and_nodes = [(CMultiStatementExpression(
            CStatements([update], codegen=codegen), condition, codegen=codegen,
        ), body)]
    elif fault == "unknown-body":
        update.tags = {}
    else:
        loop.condition = condition
    assert classify_composite_pretest_condition_8616(loop, facts, edges, artifact) is None


@pytest.mark.parametrize("lowered", [False, True])
def test_composite_materialization_keeps_body_and_records_refusal(lowered):
    codegen, loop, facts, edges, artifact = _fixture()
    statements = tuple(loop.body.statements)
    guard = statements[0]
    old_condition, old_break = guard.condition_and_nodes[0]
    replacement = CConstant(0, SimTypeShort(False), codegen=codegen)
    plans = []
    precision = []

    def lower(plan):
        plans.append(plan)
        return replacement if lowered else None

    def record(before, after):
        precision.append((before, after))
        return True

    stats = materialize_composite_pretest_conditions_8616(loop, facts, edges, artifact, lower, record)
    assert len(plans) == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == int(lowered)
    assert stats.failure_count == int(not lowered)
    assert tuple(loop.body.statements) == statements
    assert guard.condition_and_nodes[0][1] is old_break
    assert guard.condition_and_nodes[0][0] is (replacement if lowered else old_condition)
    assert precision == ([(old_condition, replacement)] if lowered else [])
