"""Verify CFG-proven restoration of split instruction statements."""

import pytest
from angr.analyses.decompiler.structured_codegen.c import CConstant
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.structuring.instruction_fragment_placement import (
    restore_instruction_fragment_placement_8616,
)
from test_x86_16_stack_update_scope_guard import _surface


def _fixture():
    root, loop, arm, iterator, fragment = _surface()
    iterator.tags = {"ins_addr": 500, "vex_block_addr": 500, "vex_stmt_idx": 11}
    fragment.tags = {"ins_addr": 500, "vex_block_addr": 500, "vex_stmt_idx": 10}
    branch = loop.body.statements[0]
    condition = branch.condition_and_nodes[0][0]
    condition.tags = {"ins_addr": 200, "vex_block_addr": 200, "vex_stmt_idx": 20}
    loop.condition = CConstant(
        1, SimTypeShort(False), codegen=condition.codegen,
        tags={"ins_addr": 100, "vex_block_addr": 100, "vex_stmt_idx": 20},
    )
    fact = ConditionIR("nonzero", "x", src_insn=200, block_addr=200, taken_target=300, fallthrough_target=400)
    successors = {100: (200,), 200: (300, 400), 300: (100,), 400: (500,), 500: (100,)}
    return root, loop, arm, iterator, fragment, fact, successors


def test_restores_exact_instruction_order_and_preserves_statement_objects():
    root, loop, arm, iterator, fragment, fact, successors = _fixture()
    stats = restore_instruction_fragment_placement_8616(root, (fact,), successors)
    assert stats.raw_fact_count == stats.normalized_fact_count == stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0
    assert loop.iterator is None
    assert arm.statements == [fragment, iterator]
    assert restore_instruction_fragment_placement_8616(root, (fact,), successors).materialized_count == 0


@pytest.mark.parametrize("missing_proof", [
    "both_edges", "missing_cfg", "wrong_cfg", "reversed_order", "missing_origin",
    "duplicate_condition", "wrong_condition", "intervening_statement",
])
def test_refuses_unproven_fragment_placement_without_mutation(missing_proof):
    root, loop, arm, iterator, fragment, fact, successors = _fixture()
    facts = (fact,)
    if missing_proof == "both_edges":
        successors[300] = (500,)
    elif missing_proof == "missing_cfg":
        del successors[300]
    elif missing_proof == "wrong_cfg":
        successors[200] = (400,)
    elif missing_proof == "reversed_order":
        fragment.tags["vex_stmt_idx"] = 12
    elif missing_proof == "missing_origin":
        del iterator.tags["vex_stmt_idx"]
    elif missing_proof == "duplicate_condition":
        facts = (fact, fact)
    elif missing_proof == "wrong_condition":
        facts = ()
    elif missing_proof == "intervening_statement":
        arm.statements.append(loop.condition)
    before = tuple(arm.statements)
    stats = restore_instruction_fragment_placement_8616(root, facts, successors)
    assert stats.materialized_count == 0
    assert loop.iterator is iterator
    assert tuple(arm.statements) == before
