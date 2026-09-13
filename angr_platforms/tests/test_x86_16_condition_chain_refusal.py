"""Condition-chain proof failure must not authorize dropping boolean operands."""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CBreak, CConstant, CContinue, CStatements, CUnaryOp
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.structuring import condition_materialization as owner


class _Codegen:
    def __init__(self):
        self.index = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_node_idx(self):
        self.index += 1
        return self.index

    def next_ident(self, name):
        return name


@pytest.mark.parametrize("operator", ["LogicalAnd", "LogicalOr", "CmpEQ"])
@pytest.mark.parametrize("negated", [False, True])
@pytest.mark.parametrize("chain_proven", [False, True])
def test_failed_chain_proof_cannot_replace_compound_with_root(monkeypatch, operator, negated, chain_proven):
    codegen = _Codegen()
    lhs = CConstant(3, SimTypeShort(False), codegen=codegen)
    rhs = CConstant(5, SimTypeShort(False), codegen=codegen)
    original = CBinaryOp(operator, lhs, rhs, codegen=codegen)
    if negated:
        original = CUnaryOp("Not", original, codegen=codegen)
    root_expression = CBinaryOp("CmpNE", lhs, rhs, codegen=codegen)
    fact = ConditionIR(
        op="ne", lhs=3, rhs=5, block_addr=0x100, src_insn=0x102,
        taken_target=0x110, fallthrough_target=0x120,
    )
    monkeypatch.setattr(owner, "sole_return_statement_8616", lambda _body: None)
    monkeypatch.setattr(owner, "sole_return_expression_8616", lambda _body: None)
    monkeypatch.setattr(owner, "_single_branch_body_orientation_8616", lambda *_args: True)
    monkeypatch.setattr(owner, "_single_branch_orientation_8616", lambda *_args: True)
    monkeypatch.setattr(owner, "_first_tagged_ins_addr_8616", lambda _body: 0x130)
    monkeypatch.setattr(owner, "_first_tagged_block_addr_8616", lambda _body: 0x130)
    monkeypatch.setattr(
        owner, "_materialize_cfg_condition_chain_expr_8616",
        lambda *_args: original if chain_proven else None,
    )
    monkeypatch.setattr(owner, "materialize_condition_ir_expression_8616", lambda *_args: root_expression)
    monkeypatch.setattr(
        owner, "lower_call_output_stack_fields_in_condition_8616",
        lambda _codegen, expression, _facts: SimpleNamespace(expression=expression),
    )
    replayed = []
    monkeypatch.setattr(owner, "record_condition_replay_fact_8616", lambda *args: replayed.append(args))

    result = owner._materialize_cfg_single_branch_expr_8616(
        object(), codegen, fact, original, object(), {0x100: fact},
        {0x100: (0x110, 0x120), 0x110: (0x130,)},
    )

    if chain_proven:
        assert result is original
        assert len(replayed) == 1
    elif operator in {"LogicalAnd", "LogicalOr"}:
        assert result is None
        assert replayed == []
    else:
        assert result is root_expression
        assert len(replayed) == 1


@pytest.mark.parametrize("jump_type", [CBreak, CContinue])
@pytest.mark.parametrize("wrapped", [False, True])
@pytest.mark.parametrize("source_address", [0x110, 0x120])
def test_loop_jump_origin_is_not_a_branch_destination(jump_type, wrapped, source_address):
    codegen = _Codegen()
    fact = ConditionIR(
        op="ne", lhs=3, rhs=5, block_addr=0x100, src_insn=0x102,
        taken_target=0x110, fallthrough_target=0x120,
    )
    body = jump_type(codegen=codegen, tags={"ins_addr": source_address, "vex_block_addr": source_address})
    if wrapped:
        body = CStatements([CStatements([body], codegen=codegen)], codegen=codegen)
    assert owner._single_branch_body_orientation_8616(
        fact, body, {0x100: (0x110, 0x120), 0x110: (0x100,), 0x120: ()},
    ) is None
