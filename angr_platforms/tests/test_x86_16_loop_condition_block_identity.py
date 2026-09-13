"""Check exact block-origin condition binding at posttest loop headers."""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CBreak, CDoWhileLoop, CIfElse, CStatements
from angr_platforms.X86_16 import decompiler_postprocess_typed_conditions as typed_replay
from angr_platforms.X86_16.structuring.loop_condition_materialization import (
    materialize_typed_loop_continuation_conditions_8616,
)
from test_x86_16_loop_condition_materialization import _loop_fixture


@pytest.mark.parametrize("evidence", ["proven", "foreign_operand", "unmarked", "interior", "ambiguous", "wrong_cfg"])
def test_posttest_block_origin_requires_unique_cfg_branch(evidence, monkeypatch):
    codegen, old_loop, _root, typed = _loop_fixture()
    condition = old_loop.condition
    condition.tags = {
        "ins_addr": typed.block_addr,
        "vex_block_addr": typed.block_addr,
        "inertia_jcc_materialized_8616": evidence != "unmarked",
    }
    if evidence == "interior":
        condition.tags["ins_addr"] += 1
    body = CStatements([], codegen=codegen, tags={"vex_block_addr": 0x10093})
    if evidence == "foreign_operand":
        _other_codegen, other_loop, _other_root, _other_fact = _loop_fixture()
        foreign_condition = other_loop.condition
        foreign_condition.tags = {"ins_addr": typed.taken_target, "vex_block_addr": typed.taken_target}
        body.statements = [CIfElse([(foreign_condition, CBreak(codegen=codegen))], codegen=codegen)]
    loop = CDoWhileLoop(condition, body, codegen=codegen)
    root = CStatements([loop], codegen=codegen)
    successors = {
        typed.block_addr: (typed.taken_target, typed.fallthrough_target),
        typed.fallthrough_target: (0x10093,),
        0x10093: (typed.block_addr,),
        typed.taken_target: (0x10200,),
        0x10200: (0x10093, 0x10300),
        0x10300: (),
    }
    if evidence == "wrong_cfg":
        successors[typed.block_addr] = (0x10300,)
    facts = (typed, typed) if evidence == "ambiguous" else (typed,)
    stats = materialize_typed_loop_continuation_conditions_8616(
        root, codegen, facts, successors, lambda _fact: condition,
    )
    if evidence in {"proven", "foreign_operand"}:
        assert stats.materialized_count == 1
        assert loop.condition.op == "CmpLT"
        assert loop.condition.tags["inertia_typed_loop_condition_key_8616"] == (typed.src_insn, typed.block_addr)
        codegen.cfunc = SimpleNamespace(statements=root)
        codegen._inertia_typed_conditions = [typed]
        monkeypatch.setattr(typed_replay, "_build_c_condition_expr", lambda *_args: condition)
        typed_replay._apply_typed_conditions_to_codegen_8616(codegen.project, codegen)
        assert loop.condition.op == "CmpLT"
    else:
        assert stats.materialized_count == 0
        assert loop.condition is condition
