"""Tests for Structuring-owned immediate stack-store branch placement."""

from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CIfElse,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import IRValue, MemSpace
from inertia.lowering.real_mode_linear import (
    DirectStackMoveFact8616,
    DirectStackMoveSourceKind8616,
)
from archinfo import ArchX86
from capstone.x86_const import X86_OP_IMM

from inertia.structuring.direct_stack_move_branches import (
    materialize_direct_stack_move_branch_ownership_8616,
    recover_direct_stack_move_branch_facts_8616,
)


def _condition() -> ConditionIR:
    return ConditionIR(
        op="ugt",
        lhs=IRValue(MemSpace.DS, offset=0x44, size=2),
        rhs=IRValue(MemSpace.DS, offset=0x46, size=2),
        src_insn=0x10BA5,
        producer_insn=0x10BA1,
        taken_target=0x10BAA,
        fallthrough_target=0x10BA7,
    )


def _immediate_fact() -> DirectStackMoveFact8616:
    return DirectStackMoveFact8616(
        dst_offset=-6,
        width=2,
        source_kind=DirectStackMoveSourceKind8616.IMMEDIATE,
        source_value=1,
        ins_addr=0x10BAD,
    )


def test_recovers_immediate_store_from_exact_innermost_branch_range() -> None:
    facts = recover_direct_stack_move_branch_facts_8616(
        (_condition(),),
        (_immediate_fact(),),
        {0x10BA7: 0x10BB9},
    )

    assert len(facts) == 1
    assert facts[0].move_ins_addr == 0x10BAD
    assert facts[0].arm_start == 0x10BAA
    assert facts[0].merge_addr == 0x10BB9


def test_moves_immediate_assignment_into_cfg_proven_branch() -> None:
    project = SimpleNamespace(arch=ArchX86())
    codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        cstyle_null_cmp=False,
        project=project,
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    destination = CVariable(
        SimStackVariable(-6, 2, base="bp", name="changed"),
        codegen=codegen,
    )
    marker = CAssignment(
        destination,
        destination,
        codegen=codegen,
        tags={"ins_addr": 0x10BAA},
    )
    body = CStatements([marker], codegen=codegen)
    condition = CBinaryOp(
        "CmpGT",
        destination,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x10BA1},
    )
    branch = CIfElse(
        [(condition, body)],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    assignment = CAssignment(
        destination,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x10BAD},
    )
    root = CStatements([branch, assignment], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_typed_conditions = (_condition(),)
    codegen._inertia_direct_stack_move_facts_8616 = (_immediate_fact(),)
    jump = SimpleNamespace(
        address=0x10BA7,
        operands=(SimpleNamespace(type=X86_OP_IMM, imm=0x10BB9),),
    )
    function = SimpleNamespace(
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(jump,))),),
    )

    assert materialize_direct_stack_move_branch_ownership_8616(
        project,
        codegen,
        function,
    )
    assert root.statements == [branch]
    assert body.statements == [marker, assignment]
    stats = codegen._inertia_direct_stack_move_branch_placement_8616
    assert stats.raw_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0
