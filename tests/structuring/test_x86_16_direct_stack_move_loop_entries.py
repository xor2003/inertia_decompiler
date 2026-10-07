"""Tests for Structuring-owned direct stack move loop-entry placement."""

from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDoWhileLoop,
    CStatements,
    CVariable,
    CWhileLoop,
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
    place_direct_stack_move_loop_entry_assignment_8616,
)


def _fact(address: int = 0x10D54) -> DirectStackMoveFact8616:
    return DirectStackMoveFact8616(
        dst_offset=-6,
        width=2,
        source_kind=DirectStackMoveSourceKind8616.STACK_SLOT,
        source_offset=4,
        ins_addr=address,
    )


def _instruction(address: int) -> SimpleNamespace:
    return SimpleNamespace(address=address, groups=(), operands=())


def _function(
    *,
    with_loopback: bool = True,
    jump_addr: int = 0x10DE2,
) -> SimpleNamespace:
    instructions = [
        _instruction(0x10D51),
        _instruction(0x10D54),
        _instruction(0x10D5A),
    ]
    if with_loopback:
        instructions.append(
            SimpleNamespace(
                address=jump_addr,
                groups=(CS_GRP_JUMP,),
                operands=(SimpleNamespace(type=X86_OP_IMM, imm=0x10D51),),
            )
        )
    return SimpleNamespace(
        blocks=(
            SimpleNamespace(
                capstone=SimpleNamespace(insns=tuple(instructions)),
            ),
        ),
    )


def _surface(
    *,
    assignment_inside_inner_loop: bool,
) -> tuple[
    object,
    object,
    object,
    CStatements,
    CStatements,
    CAssignment,
]:
    project = SimpleNamespace(arch=ArchX86())
    codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        cstyle_null_cmp=False,
        project=project,
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    destination = CVariable(
        SimStackVariable(-6, 2, base="bp", name="scan_up"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    source = CVariable(
        SimStackVariable(4, 2, base="bp", name="low"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    assignment = CAssignment(
        destination,
        source,
        codegen=codegen,
        tags={"ins_addr": 0x10D54},
    )
    inner_statements = [assignment] if assignment_inside_inner_loop else []
    inner_statements.append(
        CAssignment(
            destination,
            destination,
            codegen=codegen,
            tags={"ins_addr": 0x10D70},
        )
    )
    inner_body = CStatements(inner_statements, codegen=codegen)
    inner_loop = CWhileLoop(
        CConstant(
            1,
            SimTypeShort(False),
            codegen=codegen,
            tags={"ins_addr": 0x10D67},
        ),
        inner_body,
        codegen=codegen,
    )
    compare_counter = CAssignment(
        source,
        source,
        codegen=codegen,
        tags={"ins_addr": 0x10D5D},
    )
    outer_body_statements = [compare_counter, inner_loop]
    if not assignment_inside_inner_loop:
        outer_body_statements.insert(0, assignment)
    outer_body = CStatements(outer_body_statements, codegen=codegen)
    outer_condition = CBinaryOp(
        "CmpGT",
        destination,
        source,
        codegen=codegen,
        tags={"ins_addr": 0x10DE0},
    )
    outer_loop = CDoWhileLoop(
        outer_condition,
        outer_body,
        codegen=codegen,
    )
    root = CStatements([outer_loop], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_direct_stack_move_facts_8616 = (_fact(),)
    return project, _function(), codegen, outer_body, inner_body, assignment


def _insert_inner_entry_tag(
    codegen: object,
    inner_body: CStatements,
    assignment: CAssignment,
) -> None:
    """Add entry and post-loopback body origins to the pre-test fixture."""
    inner_body.statements.insert(
        0,
        CAssignment(
            assignment.lhs,
            assignment.lhs,
            codegen=codegen,
            tags={"ins_addr": 0x10D5A},
        ),
    )
    inner_body.statements.append(
        CAssignment(
            assignment.lhs,
            assignment.lhs,
            codegen=codegen,
            tags={"ins_addr": 0x10D80},
        )
    )


def test_moves_repeated_assignment_out_of_inner_scan_but_keeps_it_in_outer_do() -> None:
    project, function, codegen, outer_body, inner_body, assignment = _surface(
        assignment_inside_inner_loop=True,
    )

    assert materialize_direct_stack_move_loop_entry_ownership_8616(
        project,
        codegen,
        function,
    )
    assert outer_body.statements[0] is assignment
    assert assignment not in inner_body.statements
    stats = codegen._inertia_direct_stack_move_loop_entry_placement_8616
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_loop_entry_replay_is_idempotent_for_already_correct_outer_do() -> None:
    project, function, codegen, outer_body, inner_body, assignment = _surface(
        assignment_inside_inner_loop=False,
    )

    assert not materialize_direct_stack_move_loop_entry_ownership_8616(
        project,
        codegen,
        function,
    )
    assert outer_body.statements[0] is assignment
    assert assignment not in inner_body.statements
    stats = codegen._inertia_direct_stack_move_loop_entry_placement_8616
    assert stats.materialized_count == 1
    assert stats.already_materialized_count == 1
    assert stats.failure_count == 0


def test_places_lowering_built_assignment_at_proven_outer_do_entry() -> None:
    project, function, codegen, outer_body, inner_body, assignment = _surface(
        assignment_inside_inner_loop=True,
    )
    inner_body.statements.remove(assignment)

    assert place_direct_stack_move_loop_entry_assignment_8616(
        project,
        codegen,
        function,
        _fact(),
        assignment,
    )
    assert outer_body.statements[0] is assignment
    assert assignment not in inner_body.statements


def test_refuses_loop_entry_relocation_without_exact_loopback() -> None:
    project, _function_with_edge, codegen, outer_body, inner_body, assignment = _surface(
        assignment_inside_inner_loop=True,
    )

    assert not materialize_direct_stack_move_loop_entry_ownership_8616(
        project,
        codegen,
        _function(with_loopback=False),
    )
    assert assignment in inner_body.statements
    assert assignment not in outer_body.statements
    stats = codegen._inertia_direct_stack_move_loop_entry_placement_8616
    assert stats.refused_no_edge_count == 1
    assert stats.materialized_count == 0
    assert stats.failure_count == 0


def test_uses_binary_blocks_when_transformed_local_blocks_are_stale() -> None:
    project, function, codegen, outer_body, inner_body, assignment = _surface(
        assignment_inside_inner_loop=True,
    )
    function._local_blocks = {
        0x10D51: SimpleNamespace(capstone=SimpleNamespace(insns=())),
    }

    assert materialize_direct_stack_move_loop_entry_ownership_8616(
        project,
        codegen,
        function,
    )
    assert outer_body.statements[0] is assignment
    assert assignment not in inner_body.statements


def test_refuses_ambiguous_posttest_loop_owner() -> None:
    project, function, codegen, outer_body, inner_body, assignment = _surface(
        assignment_inside_inner_loop=True,
    )
    duplicate_condition = outer_body.statements[1].condition
    duplicate_body = CStatements(
        [
            CAssignment(
                duplicate_condition,
                duplicate_condition,
                codegen=codegen,
                tags={"ins_addr": 0x10D54},
            ),
            CAssignment(
                duplicate_condition,
                duplicate_condition,
                codegen=codegen,
                tags={"ins_addr": 0x10D70},
            ),
        ],
        codegen=codegen,
    )
    duplicate_loop = CDoWhileLoop(
        CBinaryOp(
            "CmpGT",
            assignment.lhs,
            assignment.rhs,
            codegen=codegen,
            tags={"ins_addr": 0x10DE0},
        ),
        duplicate_body,
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(duplicate_loop)

    assert not materialize_direct_stack_move_loop_entry_ownership_8616(
        project,
        codegen,
        function,
    )
    assert assignment in inner_body.statements
    stats = codegen._inertia_direct_stack_move_loop_entry_placement_8616
    assert stats.refused_no_site_count == 1
    assert stats.materialized_count == 0
    assert stats.failure_count == 1


def test_moves_repeated_assignment_into_constant_true_pretest_loop() -> None:
    project, _function_with_edge, codegen, outer_body, inner_body, assignment = _surface(
        assignment_inside_inner_loop=False,
    )
    _insert_inner_entry_tag(codegen, inner_body, assignment)

    assert materialize_direct_stack_move_loop_entry_ownership_8616(
        project,
        codegen,
        _function(jump_addr=0x10D78),
    )
    assert inner_body.statements[0] is assignment
    assert assignment not in outer_body.statements
    stats = codegen._inertia_direct_stack_move_loop_entry_placement_8616
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_refuses_pretest_loop_when_condition_is_not_constant_true() -> None:
    project, _function_with_edge, codegen, outer_body, inner_body, assignment = _surface(
        assignment_inside_inner_loop=False,
    )
    _insert_inner_entry_tag(codegen, inner_body, assignment)
    inner_loop = outer_body.statements[-1]
    inner_loop.condition.value = 0

    assert not materialize_direct_stack_move_loop_entry_ownership_8616(
        project,
        codegen,
        _function(jump_addr=0x10D78),
    )
    assert outer_body.statements[0] is assignment
    assert assignment not in inner_body.statements
