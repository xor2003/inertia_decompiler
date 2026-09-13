from __future__ import annotations

from dataclasses import replace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CMultiStatementExpression, CStatements
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.structuring import condition_ownership as ownership
from angr_platforms.X86_16.structuring.condition_ownership import (
    structured_node_owns_condition_fact_8616,
)
from test_x86_16_typed_condition_side_effect_preservation import _codegen


def _condition(block_addr: int = 0x1009) -> ConditionIR:
    return ConditionIR(
        op="sle",
        lhs="left",
        rhs="right",
        src_insn=0x1014,
        block_addr=block_addr,
        taken_target=0x1019,
        fallthrough_target=0x1016,
    )


def test_structuring_condition_owner_accepts_linear_preheader() -> None:
    assert structured_node_owns_condition_fact_8616(
        0x1000,
        _condition(),
        {0x1000: (0x1009,), 0x1009: (0x1016, 0x1019)},
        frozenset({0x1009}),
    )


def test_structuring_condition_owner_refuses_branching_preheader() -> None:
    assert not structured_node_owns_condition_fact_8616(
        0x1000,
        _condition(),
        {0x1000: (0x1009, 0x1010)},
        frozenset({0x1009}),
    )


def test_structuring_condition_owner_refuses_crossing_other_condition() -> None:
    assert not structured_node_owns_condition_fact_8616(
        0x1000,
        _condition(block_addr=0x1019),
        {0x1000: (0x1009,), 0x1009: (0x1019,)},
        frozenset({0x1009, 0x1019}),
    )


@pytest.mark.parametrize("mutation", [None, "branch-entry", "unrelated", "simple", "duplicate", "statements", "cycle", "foreign-origin"])
def test_composite_preheader_selects_first_predicate_not_descendant(mutation):
    root = _condition()
    tail = replace(root, block_addr=0x1019, src_insn=0x101C)
    facts = (root, tail)
    edges = {0x1000: (0x1009,), 0x1009: (0x1016, 0x1019)}
    codegen = _codegen()
    one = CConstant(1, SimTypeShort(False), codegen=codegen)
    comparison = CBinaryOp("CmpEQ", one, one, codegen=codegen)
    expression = CBinaryOp("LogicalOr", comparison, comparison, codegen=codegen)
    if mutation == "branch-entry":
        edges[0x1000] = (0x1009, 0x1020)
    elif mutation == "unrelated":
        edges[0x1009] = (0x1016, 0x1020)
    elif mutation == "simple":
        expression = comparison
    elif mutation == "duplicate":
        facts = (root, replace(root, op="eq"), tail)
    elif mutation == "statements":
        expression = CMultiStatementExpression(CStatements([], codegen=codegen), expression, codegen=codegen)
    elif mutation == "cycle":
        edges[0x1000] = (0x1000,)
    elif mutation == "foreign-origin":
        tail = replace(tail)
    selected = ownership.select_composite_preheader_root_8616(
        0x1000, expression, tail, facts, edges,
    )
    assert selected is (root if mutation is None else None)
