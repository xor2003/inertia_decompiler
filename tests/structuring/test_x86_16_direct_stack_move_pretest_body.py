"""Tests for CFG-proven direct stack definitions inside pretest loops."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import networkx as nx
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CIfBreak,
    CStatements,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.real_mode_linear import (
    DirectStackMoveFact8616,
    DirectStackMoveSourceKind8616,
)
from inertia.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)

from inertia.structuring.direct_stack_move_loop_entries import (
    place_direct_stack_move_loop_entry_assignment_8616,
)
from inertia.structuring.direct_stack_move_pretest_body import (
    materialize_direct_stack_move_pretest_body_ownership_8616,
)
from inertia.structuring.direct_stack_move_pretest_body_evidence import (
    recover_direct_stack_move_pretest_body_evidence_8616,
)


class _Codegen:
    """Minimal structured-codegen boundary used by C AST fixtures."""

    cstyle_null_cmp = False

    def __init__(self, project: object) -> None:
        self.project = project
        self.cfunc: object | None = None
        self._next_index = 0

    def next_idx(self, _name: str = "") -> int:
        """Return one stable synthetic node index."""
        self._next_index += 1
        return self._next_index

    def next_node_idx(self) -> int:
        """Return one stable synthetic C node index."""
        return self.next_idx()

    def next_ident(self, name: str) -> str:
        """Return a deterministic synthetic identifier."""
        return f"{name}_{self.next_idx()}"


def _instruction(address: int) -> SimpleNamespace:
    """Build one decoded instruction boundary."""
    return SimpleNamespace(address=address, groups=(), operands=())


def _function(
    *,
    external_body_entry: bool = False,
    unresolved: bool = False,
) -> SimpleNamespace:
    """Build a pretest loop with an early body exit and one exact latch."""
    instructions = {
        0x109F1: (0x109F1,),
        0x109F9: (0x109F9, 0x109FD),
        0x109FF: (0x109FF,),
        0x10A02: (0x10A02, 0x10A05, 0x10A06, 0x10A08, 0x10A0A),
        0x10A25: (0x10A25,),
        0x10A28: (0x10A28,),
        0x10A58: (0x10A58,),
        0x10A5B: (0x10A5B,),
    }
    blocks = tuple(
        SimpleNamespace(
            addr=block_addr,
            capstone=SimpleNamespace(
                insns=tuple(_instruction(address) for address in addresses)
            ),
        )
        for block_addr, addresses in instructions.items()
    )
    graph = nx.DiGraph()
    graph.add_nodes_from(instructions)
    graph.add_edges_from(
        (
            (0x109F1, 0x109F9),
            (0x109F9, 0x109FF),
            (0x109F9, 0x10A02),
            (0x109FF, 0x10A5B),
            (0x10A02, 0x10A25),
            (0x10A02, 0x10A28),
            (0x10A25, 0x10A5B),
            (0x10A28, 0x10A58),
            (0x10A58, 0x109F9),
        )
    )
    if external_body_entry:
        graph.add_edge(0x109F1, 0x10A02)
    return SimpleNamespace(
        block_addrs_set=set(instructions),
        blocks=blocks,
        has_unresolved_jumps=unresolved,
        transition_graph=graph,
    )


def _fact() -> DirectStackMoveFact8616:
    """Build the loop-body stack definition represented by ``0x10a0a``."""
    return DirectStackMoveFact8616(
        dst_offset=-2,
        width=2,
        source_kind=DirectStackMoveSourceKind8616.STACK_SLOT_EXPR,
        source_offset=-4,
        ins_addr=0x10A0A,
    )


def _surface(
    *,
    assignment_in_root: bool = True,
    duplicate_loop: bool = False,
    header_in_leading_break: bool = False,
) -> tuple[object, _Codegen, CStatements, CStatements, CAssignment, CWhileLoop]:
    """Build the hoisted-definition AST shape seen in sidecar-free PercolateUp."""
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _Codegen(project)
    word = SimTypeShort(False)
    destination = CVariable(
        SimStackVariable(-4, 2, base="bp", name="parent"),
        variable_type=word,
        codegen=codegen,
    )
    source = CVariable(
        SimStackVariable(-6, 2, base="bp", name="index"),
        variable_type=word,
        codegen=codegen,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=destination.variable,
        cvar=destination,
        bp_offset=-2,
        entry_sp_offset=-4,
        size=2,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=source.variable,
        cvar=source,
        bp_offset=-4,
        entry_sp_offset=-6,
        size=2,
    )
    argument = CVariable(
        SimStackVariable(4, 2, base="bp", name="maximum"),
        variable_type=word,
        codegen=codegen,
    )
    scratch = CVariable(
        SimStackVariable(-8, 2, base="bp", name="scratch"),
        variable_type=word,
        codegen=codegen,
    )
    assignment = CAssignment(
        destination,
        CBinaryOp(
            "Div",
            source,
            CConstant(2, word, codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x10A0A},
    )
    initializer = CAssignment(
        source,
        argument,
        codegen=codegen,
        tags={"ins_addr": 0x109F6},
    )

    def build_loop() -> tuple[CStatements, CWhileLoop]:
        """Build one structured loop carrying exact header and body origins."""
        body_marker = CAssignment(
            scratch,
            scratch,
            codegen=codegen,
            tags={"ins_addr": 0x10A02},
        )
        destination_use = CAssignment(
            scratch,
            destination,
            codegen=codegen,
            tags={"ins_addr": 0x10A0D},
        )
        nested_use = CStatements([destination_use], codegen=codegen)
        body_items: list[object] = [body_marker, nested_use]
        if header_in_leading_break:
            body_items.insert(
                0,
                CIfBreak(
                    CBinaryOp(
                        "CmpEQ",
                        source,
                        CConstant(0, word, codegen=codegen),
                        codegen=codegen,
                        tags={"ins_addr": 0x109F9},
                    ),
                    codegen=codegen,
                ),
            )
        body = CStatements(body_items, codegen=codegen)
        loop = CWhileLoop(
            CConstant(
                1,
                word,
                codegen=codegen,
                tags={} if header_in_leading_break else {"ins_addr": 0x109F9},
            ),
            body,
            codegen=codegen,
        )
        return body, loop

    body, loop = build_loop()
    root_items: list[object] = [initializer, loop]
    if assignment_in_root:
        root_items.insert(0, assignment)
    if duplicate_loop:
        _duplicate_body, duplicate = build_loop()
        root_items.append(duplicate)
    root = CStatements(root_items, codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_direct_stack_move_facts_8616 = (_fact(),)
    return project, codegen, root, body, assignment, loop


def test_recovers_exact_pretest_body_entry_with_multiple_loop_exits() -> None:
    """Multiple exit blocks do not obscure the unique guarded body entry."""
    evidence = recover_direct_stack_move_pretest_body_evidence_8616(
        SimpleNamespace(),
        _function(),
        0x10A0A,
    )

    assert len(evidence) == 1
    assert evidence[0].header_addr == 0x109F9
    assert evidence[0].body_entry_addr == 0x10A02
    assert evidence[0].latch_addr == 0x10A58


def test_moves_hoisted_definition_after_initializer_and_into_loop_body() -> None:
    """The stack definition executes after the guard on every entered iteration."""
    project, codegen, root, body, assignment, loop = _surface()

    assert materialize_direct_stack_move_pretest_body_ownership_8616(
        project,
        codegen,
        _function(),
    )

    assert root.statements == [root.statements[0], loop]
    assert root.statements[0].tags["ins_addr"] == 0x109F6
    assert body.statements[1] is assignment
    stats = codegen._inertia_direct_stack_move_pretest_body_placement_8616
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_moves_segmented_memory_definition_into_pretest_body() -> None:
    """Typed segmented-memory loads use the same exact CFG placement proof."""
    project, codegen, root, body, assignment, loop = _surface()
    codegen._inertia_direct_stack_move_facts_8616 = (
        replace(
            _fact(),
            source_kind=DirectStackMoveSourceKind8616.SEGMENTED_MEMORY,
            source_offset=None,
            source_segment_name="ds",
            source_global_displacement=0xB4C,
            source_index_offset=-4,
            source_index_shift=1,
            source_access_width=2,
        ),
    )

    assert materialize_direct_stack_move_pretest_body_ownership_8616(
        project,
        codegen,
        _function(),
    )

    assert root.statements == [root.statements[0], loop]
    assert body.statements[1] is assignment
    stats = codegen._inertia_direct_stack_move_pretest_body_placement_8616
    assert stats.raw_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_pretest_body_replay_is_idempotent() -> None:
    """Lifecycle replay recognizes an assignment already at the exact site."""
    project, codegen, _root, body, assignment, _loop = _surface()
    function = _function()
    assert materialize_direct_stack_move_pretest_body_ownership_8616(
        project,
        codegen,
        function,
    )

    assert not materialize_direct_stack_move_pretest_body_ownership_8616(
        project,
        codegen,
        function,
    )
    assert body.statements[1] is assignment
    stats = codegen._inertia_direct_stack_move_pretest_body_placement_8616
    assert stats.already_materialized_count == 1


def test_moves_body_definition_when_header_is_in_leading_break() -> None:
    project, codegen, root, body, assignment, loop = _surface(
        header_in_leading_break=True,
    )

    assert materialize_direct_stack_move_pretest_body_ownership_8616(
        project,
        codegen,
        _function(),
    )
    assert root.statements == [root.statements[0], loop]
    assert assignment in body.statements


def test_loop_entry_service_falls_through_to_pretest_body_owner() -> None:
    """The existing Structuring service exposes the new narrower owner."""
    project, codegen, _root, body, assignment, _loop = _surface(
        assignment_in_root=False
    )

    assert place_direct_stack_move_loop_entry_assignment_8616(
        project,
        codegen,
        _function(),
        _fact(),
        assignment,
    )
    assert body.statements[1] is assignment


def test_refuses_external_nonheader_entry_and_unresolved_cfg() -> None:
    """Incomplete or abnormal CFG evidence cannot move an assignment."""
    for function in (
        _function(external_body_entry=True),
        _function(unresolved=True),
    ):
        project, codegen, root, body, assignment, _loop = _surface()

        assert not materialize_direct_stack_move_pretest_body_ownership_8616(
            project,
            codegen,
            function,
        )
        assert root.statements[0] is assignment
        assert assignment not in body.statements
        stats = codegen._inertia_direct_stack_move_pretest_body_placement_8616
        assert stats.refused_no_evidence_count == 1
        assert stats.materialized_count == 0


def test_refuses_ambiguous_structured_loop_site() -> None:
    """Two equally exact AST sites preserve the original hoisted assignment."""
    project, codegen, root, body, assignment, _loop = _surface(duplicate_loop=True)

    assert not materialize_direct_stack_move_pretest_body_ownership_8616(
        project,
        codegen,
        _function(),
    )
    assert root.statements[0] is assignment
    assert assignment not in body.statements
    stats = codegen._inertia_direct_stack_move_pretest_body_placement_8616
    assert stats.refused_no_site_count == 1
    assert stats.materialized_count == 0
