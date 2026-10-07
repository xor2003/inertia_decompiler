"""Tests for conservative instruction ordering inside owned stack-move arms."""

from __future__ import annotations

from types import SimpleNamespace

import archinfo
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.lowering.real_mode_linear import (
    DirectStackMoveFact8616,
    DirectStackMoveSourceKind8616,
)

from inertia.structuring.direct_stack_move_branches import (
    DirectStackMoveBranchArm8616,
    DirectStackMoveBranchFact8616,
    _assignment_matches_stack_move_fact_8616,
    _condition_branch_site_8616,
    _ordered_arm_insertion_index_8616,
    _site_suffix_owns_assignment_8616,
)


class _FakeCodegen:
    def __init__(self) -> None:
        self.project = SimpleNamespace(arch=archinfo.ArchX86())
        self._next_idx = 0

    def next_idx(self, _kind: str) -> int:
        self._next_idx += 1
        return self._next_idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _fact() -> DirectStackMoveBranchFact8616:
    return DirectStackMoveBranchFact8616(
        move_ins_addr=0x10940,
        condition_ins_addr=0x10912,
        condition_producer_insn=0x1090E,
        arm=DirectStackMoveBranchArm8616.TAKEN,
        arm_start=0x10917,
        merge_addr=0x10943,
    )


def test_ordering_ignores_only_recursively_empty_statement_wrappers() -> None:
    codegen = _FakeCodegen()
    before = structured_c.CExpressionStatement(
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x10937},
    )
    empty = structured_c.CStatements(
        [structured_c.CStatements([], codegen=codegen)],
        codegen=codegen,
    )

    assert _ordered_arm_insertion_index_8616((before, empty), SimpleNamespace(), _fact()) == 2


def test_ordering_refuses_untagged_nonempty_statement() -> None:
    codegen = _FakeCodegen()
    before = structured_c.CExpressionStatement(
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x10937},
    )
    untagged = structured_c.CExpressionStatement(
        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    assert _ordered_arm_insertion_index_8616((before, untagged), SimpleNamespace(), _fact()) is None


def test_ordering_inserts_before_tagged_post_merge_statement() -> None:
    codegen = _FakeCodegen()
    before = structured_c.CExpressionStatement(
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x10937},
    )
    after_merge = structured_c.CExpressionStatement(
        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x10949},
    )

    assert _ordered_arm_insertion_index_8616((before, after_merge), SimpleNamespace(), _fact()) == 1


def test_branch_site_accepts_cfg_tagged_pretest_loop_body() -> None:
    codegen = _FakeCodegen()
    condition = structured_c.CConstant(
        1,
        SimTypeShort(False),
        codegen=codegen,
        tags={"ins_addr": 0x10912},
    )
    body_statement = structured_c.CExpressionStatement(
        structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x10937},
    )
    body = structured_c.CStatements([body_statement], codegen=codegen)
    loop = structured_c.CForLoop(None, condition, None, body, codegen=codegen)

    site = _condition_branch_site_8616(loop, SimpleNamespace(), _fact(), ())

    assert site is not None
    assert site.statements is body.statements
    assert site.start_index == 0
    assert site.bounded_owner


def _stack_cvar(codegen: _FakeCodegen, offset: int) -> structured_c.CVariable:
    """Build one typed BP-relative test variable."""
    return structured_c.CVariable(
        SimStackVariable(offset, 2, base="bp", name=f"local_{-offset:x}"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _aggregate_branch_fact(move_addr: int) -> DirectStackMoveBranchFact8616:
    """Build one taken-arm fact for an indexed stack move."""
    return DirectStackMoveBranchFact8616(
        move_ins_addr=move_addr,
        condition_ins_addr=0x10602,
        condition_producer_insn=0x105FE,
        arm=DirectStackMoveBranchArm8616.TAKEN,
        arm_start=0x10607,
        merge_addr=0x10669,
    )


def test_branch_assignment_matches_indexed_stack_source() -> None:
    codegen = _FakeCodegen()
    assignment = structured_c.CAssignment(
        _stack_cvar(codegen, -114),
        structured_c.CIndexedVariable(
            _stack_cvar(codegen, -90),
            _stack_cvar(codegen, -118),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    move = DirectStackMoveFact8616(
        -114,
        2,
        DirectStackMoveSourceKind8616.STACK_AGGREGATE_ELEMENT,
        0x1061C,
        source_aggregate_base_offset=-90,
        source_index_offset=-118,
        source_access_width=2,
    )

    assert _assignment_matches_stack_move_fact_8616(
        codegen,
        assignment,
        _aggregate_branch_fact(0x1061C),
        move,
    )


def test_branch_assignment_matches_indexed_stack_destination() -> None:
    codegen = _FakeCodegen()
    assignment = structured_c.CAssignment(
        structured_c.CIndexedVariable(
            _stack_cvar(codegen, -90),
            _stack_cvar(codegen, -118),
            codegen=codegen,
        ),
        structured_c.CIndexedVariable(
            _stack_cvar(codegen, -90),
            _stack_cvar(codegen, -4),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    move = DirectStackMoveFact8616(
        -90,
        2,
        DirectStackMoveSourceKind8616.STACK_AGGREGATE_ELEMENT,
        0x1062C,
        source_aggregate_base_offset=-90,
        source_index_offset=-4,
        source_access_width=2,
        dst_index_stack_offset=-118,
    )

    assert _assignment_matches_stack_move_fact_8616(
        codegen,
        assignment,
        _aggregate_branch_fact(0x1062C),
        move,
    )


def test_branch_site_recognizes_nested_owned_assignment() -> None:
    codegen = _FakeCodegen()
    assignment = structured_c.CAssignment(
        _stack_cvar(codegen, -114),
        _stack_cvar(codegen, -90),
        codegen=codegen,
    )
    nested = structured_c.CStatements([assignment], codegen=codegen)
    statements = [structured_c.CStatements([], codegen=codegen), nested]
    site = SimpleNamespace(statements=statements, start_index=1)

    assert _site_suffix_owns_assignment_8616(site, assignment)
