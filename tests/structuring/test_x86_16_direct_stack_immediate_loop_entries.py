"""Tests for Structuring-owned immediate stack-store loop entries."""

from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CDoWhileLoop,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.lowering.real_mode_linear import (
    DirectStackMoveFact8616,
    DirectStackMoveSourceKind8616,
)
from archinfo import ArchX86
from capstone import CS_GRP_JUMP
from capstone.x86_const import X86_OP_IMM

from inertia.structuring.direct_stack_move_loop_entries import (
    materialize_direct_stack_move_loop_entry_ownership_8616,
)


def _surface(
    *,
    jump_target: int = 0x10C40,
    insert_gap: bool = False,
) -> tuple[object, object, object, CStatements, CStatements, CDoWhileLoop, CAssignment]:
    """Build one production-shaped misplaced immediate loop-entry store."""
    project = SimpleNamespace(arch=ArchX86())
    codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        cstyle_null_cmp=False,
        project=project,
        next_ident=lambda name: f"{name}_0",
        next_node_idx=lambda: 1,
    )
    changed_variable = SimStackVariable(-8, 2, base="bp", name="changed")
    changed = CVariable(
        changed_variable,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    reset = CAssignment(
        changed,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x10C40},
    )
    body_step = CAssignment(
        changed,
        changed,
        codegen=codegen,
        tags={"ins_addr": 0x10C45},
    )
    loop_body = CStatements([body_step], codegen=codegen)
    loop = CDoWhileLoop(
        CVariable(
            changed_variable,
            variable_type=SimTypeShort(False),
            codegen=codegen,
            tags={"ins_addr": 0x10CBA},
        ),
        loop_body,
        codegen=codegen,
    )
    root_statements: list[object] = [reset]
    if insert_gap:
        gap_variable = CVariable(
            SimStackVariable(-10, 2, base="bp", name="gap"),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        )
        root_statements.append(
            CAssignment(
                gap_variable,
                CConstant(1, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
                tags={"ins_addr": 0x10C43},
            )
        )
    root_statements.append(loop)
    root = CStatements(root_statements, codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_direct_stack_move_facts_8616 = (
        DirectStackMoveFact8616(
            dst_offset=-8,
            width=2,
            source_kind=DirectStackMoveSourceKind8616.IMMEDIATE,
            source_value=0,
            ins_addr=0x10C40,
        ),
    )
    function = SimpleNamespace(
        blocks=(
            SimpleNamespace(
                capstone=SimpleNamespace(
                    insns=(
                        SimpleNamespace(address=jump_target, groups=(), operands=()),
                        SimpleNamespace(address=0x10C40, groups=(), operands=()),
                        SimpleNamespace(address=0x10C45, groups=(), operands=()),
                        SimpleNamespace(
                            address=0x10CBC,
                            groups=(CS_GRP_JUMP,),
                            operands=(SimpleNamespace(type=X86_OP_IMM, imm=jump_target),),
                        ),
                    )
                )
            ),
        )
    )
    return project, codegen, function, root, loop_body, loop, reset


def test_moves_repeated_immediate_store_from_before_do_into_body() -> None:
    project, codegen, function, root, loop_body, loop, reset = _surface()

    assert materialize_direct_stack_move_loop_entry_ownership_8616(
        project,
        codegen,
        function,
    )
    assert root.statements == [loop]
    assert len(loop_body.statements) == 2
    assert loop_body.statements[0] is reset
    stats = codegen._inertia_direct_stack_move_loop_entry_placement_8616
    assert stats.raw_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_refuses_immediate_store_when_backedge_targets_earlier_prefix() -> None:
    project, codegen, function, root, loop_body, loop, reset = _surface(
        jump_target=0x10C3D,
    )

    assert not materialize_direct_stack_move_loop_entry_ownership_8616(
        project,
        codegen,
        function,
    )
    assert root.statements == [reset, loop]
    assert loop_body.statements[0] is not reset
    stats = codegen._inertia_direct_stack_move_loop_entry_placement_8616
    assert stats.refused_immediate_scope_count == 1
    assert stats.classified_fact_count == 0


def test_refuses_immediate_store_not_adjacent_to_owning_loop() -> None:
    project, codegen, function, root, loop_body, loop, reset = _surface(
        insert_gap=True,
    )

    assert not materialize_direct_stack_move_loop_entry_ownership_8616(
        project,
        codegen,
        function,
    )
    assert root.statements[0] is reset
    assert root.statements[-1] is loop
    assert loop_body.statements[0] is not reset
    stats = codegen._inertia_direct_stack_move_loop_entry_placement_8616
    assert stats.refused_immediate_scope_count == 1
    assert stats.classified_fact_count == 0
