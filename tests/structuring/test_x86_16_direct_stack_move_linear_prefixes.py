"""Tests for CFG-proven direct stack move linear-prefix ownership."""

from __future__ import annotations

from types import SimpleNamespace

import networkx as nx
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CDoWhileLoop,
    CIfElse,
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

from inertia.structuring.direct_stack_move_linear_prefixes import (
    DirectStackMoveLinearPrefixVerdict8616,
    place_direct_stack_move_linear_prefix_assignment_8616,
)


class _Block:
    def __init__(self, address: int, instructions: tuple[SimpleNamespace, ...]) -> None:
        self.addr = address
        self.capstone = SimpleNamespace(insns=instructions)


def _instruction(
    address: int,
    *,
    jump_target: int | None = None,
) -> SimpleNamespace:
    groups = (CS_GRP_JUMP,) if jump_target is not None else ()
    operands = (
        (SimpleNamespace(type=X86_OP_IMM, imm=jump_target),)
        if jump_target is not None
        else ()
    )
    return SimpleNamespace(address=address, groups=groups, operands=operands)


def _block(address: int, instructions: tuple[SimpleNamespace, ...]) -> _Block:
    return _Block(address, instructions)


def _function(*, unresolved: bool = False, repeated: bool = False) -> SimpleNamespace:
    source = _block(
        0x10D44,
        tuple(_instruction(address) for address in (0x10D44, 0x10D47, 0x10D49, 0x10D4D, 0x10D4E)),
    )
    loop_entry = _block(
        0x10D51,
        tuple(_instruction(address) for address in (0x10D51, 0x10D54, 0x10D5A)),
    )
    blocks = [source, loop_entry]
    graph = nx.DiGraph()
    graph.add_edge(source, loop_entry)
    if repeated:
        loop_tail = _block(
            0x10DE0,
            (_instruction(0x10DE2, jump_target=0x10D44),),
        )
        blocks.append(loop_tail)
        graph.add_edge(loop_entry, loop_tail)
        graph.add_edge(loop_tail, source)
    return SimpleNamespace(
        has_unresolved_jumps=unresolved,
        block_addrs_set=frozenset(block.addr for block in blocks),
        blocks=tuple(blocks),
        transition_graph=graph,
    )


def _surface() -> tuple[object, object, CStatements, CStatements, CAssignment]:
    project = SimpleNamespace(arch=ArchX86())
    codegen = SimpleNamespace(
        project=project,
        next_idx=lambda _name: 1,
        next_ident=lambda name: f"{name}_0",
        next_node_idx=lambda: 1,
        cstyle_null_cmp=False,
    )
    destination = CVariable(
        SimStackVariable(-4, 2, base="bp", name="pivot"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    source = CConstant(
        7,
        SimTypeShort(False),
        codegen=codegen,
    )
    assignment = CAssignment(
        destination,
        source,
        codegen=codegen,
        tags={"ins_addr": 0x10D4E},
    )
    loop_body = CStatements(
        [
            CAssignment(
                destination,
                destination,
                codegen=codegen,
                tags={"ins_addr": 0x10D54},
            )
        ],
        codegen=codegen,
    )
    loop = CDoWhileLoop(
        CConstant(
            1,
            SimTypeShort(False),
            codegen=codegen,
            tags={"ins_addr": 0x10DE2},
        ),
        loop_body,
        codegen=codegen,
    )
    final_else = CStatements([loop], codegen=codegen)
    early_return = CStatements(
        [
            CAssignment(
                destination,
                source,
                codegen=codegen,
                tags={"ins_addr": 0x10E57},
            )
        ],
        codegen=codegen,
    )
    conditional = CIfElse(
        [
            (
                CConstant(1, SimTypeShort(False), codegen=codegen, tags={"ins_addr": 0x10CF1}),
                early_return,
            ),
            (
                CConstant(1, SimTypeShort(False), codegen=codegen, tags={"ins_addr": 0x10D02}),
                early_return,
            ),
        ],
        else_node=final_else,
        codegen=codegen,
    )
    root = CStatements([conditional], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)
    return project, codegen, final_else, loop_body, assignment


def _fact() -> DirectStackMoveFact8616:
    return DirectStackMoveFact8616(
        dst_offset=-4,
        width=2,
        source_kind=DirectStackMoveSourceKind8616.SEGMENTED_MEMORY,
        ins_addr=0x10D4E,
        source_segment_name="ds",
        source_displacement=0xB4C,
        source_index_offset=6,
        source_index_shift=1,
        source_access_width=1,
    )


def test_places_one_time_segmented_read_before_loop_container() -> None:
    project, codegen, final_else, loop_body, assignment = _surface()

    assert place_direct_stack_move_linear_prefix_assignment_8616(
        project,
        codegen,
        _function(),
        _fact(),
        assignment,
    )
    assert final_else.statements[0] is assignment
    assert assignment not in loop_body.statements
    stats = codegen._inertia_direct_stack_move_linear_prefix_8616
    assert stats.verdict is DirectStackMoveLinearPrefixVerdict8616.PROVEN_LINEAR_PREFIX
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_refuses_unresolved_cfg_instead_of_guessing_branch_scope() -> None:
    project, codegen, final_else, loop_body, assignment = _surface()

    assert not place_direct_stack_move_linear_prefix_assignment_8616(
        project,
        codegen,
        _function(unresolved=True),
        _fact(),
        assignment,
    )
    assert assignment not in final_else.statements
    assert assignment not in loop_body.statements
    stats = codegen._inertia_direct_stack_move_linear_prefix_8616
    assert stats.verdict is DirectStackMoveLinearPrefixVerdict8616.REFUSED_UNRESOLVED_CFG
    assert stats.materialized_count == 0
    assert stats.failure_count == 1


def test_refuses_repeated_move_so_loop_entry_owner_can_classify_it() -> None:
    project, codegen, final_else, loop_body, assignment = _surface()

    assert not place_direct_stack_move_linear_prefix_assignment_8616(
        project,
        codegen,
        _function(repeated=True),
        _fact(),
        assignment,
    )
    assert assignment not in final_else.statements
    assert assignment not in loop_body.statements
    stats = codegen._inertia_direct_stack_move_linear_prefix_8616
    assert stats.verdict is DirectStackMoveLinearPrefixVerdict8616.REFUSED_REPEATED_MOVE
    assert stats.materialized_count == 0
    assert stats.failure_count == 1
