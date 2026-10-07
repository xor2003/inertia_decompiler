"""Tests for Structuring-owned direct stack move branch placement."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CExpressionStatement,
    CForLoop,
    CIfElse,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimStackVariable
from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import IRValue, MemSpace
import inertia.lowering.real_mode_linear as real_mode_linear
from inertia.lowering.real_mode_linear import (
    DirectStackMoveFact8616,
    DirectStackMoveSourceKind8616,
)
from inertia.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)
from inertia.pipeline.errors import PipelineHardError
from archinfo import ArchX86
from capstone.x86_const import X86_OP_IMM

from inertia.structuring.condition_replay import (
    StructuringConditionReplayFact8616,
)
from inertia.structuring.direct_stack_move_branches import (
    finalize_direct_stack_move_branch_ownership_8616,
    materialize_direct_stack_move_branch_ownership_8616,
    place_direct_stack_move_assignment_8616,
    recover_direct_stack_move_branch_facts_8616,
)


def _move_fact() -> DirectStackMoveFact8616:
    return DirectStackMoveFact8616(
        dst_offset=-4,
        width=2,
        source_kind=DirectStackMoveSourceKind8616.STACK_SLOT,
        source_offset=-2,
        ins_addr=0x10BAD,
    )


def _indexed_condition() -> ConditionIR:
    return ConditionIR(
        op="slt",
        lhs=IRValue(
            MemSpace.DS,
            offset=0xB4C,
            size=1,
            index=IRValue(MemSpace.SS, name="bp", offset=-2, size=2),
            index_shift=1,
            memory_access_size=1,
        ),
        rhs=IRValue(
            MemSpace.DS,
            offset=0xB4C,
            size=1,
            index=IRValue(MemSpace.SS, name="bp", offset=-4, size=2),
            index_shift=1,
            memory_access_size=1,
        ),
        src_insn=0x10BA5,
        producer_insn=0x10BA1,
        taken_target=0x10BAA,
        fallthrough_target=0x10BA7,
    )


def test_recovers_branch_owner_when_condition_reads_source_and_destination() -> None:
    facts = recover_direct_stack_move_branch_facts_8616(
        (_indexed_condition(),),
        (_move_fact(),),
        {0x10BA7: 0x10BB9},
    )

    assert len(facts) == 1
    assert facts[0].move_ins_addr == 0x10BAD
    assert facts[0].condition_ins_addr == 0x10BA5
    assert facts[0].arm_start == 0x10BAA
    assert facts[0].merge_addr == 0x10BB9


def test_cfg_interval_proves_branch_owner_without_data_dependency() -> None:
    loop_condition = ConditionIR(
        op="sgt",
        lhs=IRValue(MemSpace.DS, offset=0xBA2, size=2),
        rhs=IRValue(MemSpace.SS, name="bp", offset=-6, size=2),
        src_insn=0x10B6D,
        producer_insn=0x10B69,
        taken_target=0x10B72,
        fallthrough_target=0x10B6F,
    )
    copy = DirectStackMoveFact8616(
        dst_offset=-4,
        width=2,
        source_kind=DirectStackMoveSourceKind8616.STACK_SLOT,
        source_offset=-6,
        ins_addr=0x10B75,
    )

    facts = recover_direct_stack_move_branch_facts_8616(
        (loop_condition,),
        (copy,),
        {0x10B6F: 0x10BEE},
    )

    assert len(facts) == 1
    assert facts[0].move_ins_addr == copy.ins_addr


def _surface(
    *,
    tagged_condition: bool = True,
    inverted: bool = False,
) -> tuple[object, object, object, CStatements, CStatements, CAssignment]:
    project = SimpleNamespace(arch=ArchX86())
    codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        cstyle_null_cmp=False,
        project=project,
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    source = CVariable(SimStackVariable(-2, 2, base="bp", name="next"), codegen=codegen)
    destination = CVariable(SimStackVariable(-4, 2, base="bp", name="minimum"), codegen=codegen)
    condition = CBinaryOp(
        "CmpLT",
        source,
        destination,
        codegen=codegen,
        tags={"ins_addr": 0x10BA1} if tagged_condition else {},
    )
    taken_marker = CAssignment(
        source,
        source,
        codegen=codegen,
        tags={"ins_addr": 0x10BAA},
    )
    taken_tail_marker = CAssignment(
        source,
        source,
        codegen=codegen,
        tags={"ins_addr": 0x10BB0},
    )
    taken_body = CStatements(
        [taken_marker, taken_tail_marker],
        codegen=codegen,
    )
    fallthrough_body = CStatements(
        [
            CAssignment(
                source,
                source,
                codegen=codegen,
                tags={"ins_addr": 0x10BA7},
            )
        ],
        codegen=codegen,
    )
    branch = CIfElse(
        [(condition, fallthrough_body if inverted else taken_body)],
        else_node=taken_body if inverted else None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    assignment = CAssignment(
        destination,
        source,
        codegen=codegen,
        tags={"ins_addr": 0x10BAD},
    )
    root = CStatements([branch, assignment], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)
    codegen._inertia_typed_conditions = (_indexed_condition(),)
    codegen._inertia_direct_stack_move_facts_8616 = (_move_fact(),)
    jump = SimpleNamespace(
        address=0x10BA7,
        operands=(SimpleNamespace(type=X86_OP_IMM, imm=0x10BB9),),
    )
    function = SimpleNamespace(
        blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(jump,))),),
    )
    return project, function, codegen, root, taken_body, assignment


def test_tagged_typed_immediate_assignment_uses_proven_branch_owner() -> None:
    project, function, codegen, root, body, assignment = _surface()
    assignment.rhs = CVariable(
        SimMemoryVariable(0x10, 2, name="inc_one"),
        codegen=codegen,
    )
    codegen._inertia_direct_stack_move_facts_8616 = (
        DirectStackMoveFact8616(
            dst_offset=-4,
            width=2,
            source_kind=DirectStackMoveSourceKind8616.IMMEDIATE,
            source_value=0x10,
            ins_addr=0x10BAD,
        ),
    )

    assert materialize_direct_stack_move_branch_ownership_8616(project, codegen, function)
    assert root.statements == [root.statements[0]]
    assert body.statements[1] is assignment
    assert len(body.statements) == 3
    assert not materialize_direct_stack_move_branch_ownership_8616(project, codegen, function)
    assert body.statements[1] is assignment
    assert len(body.statements) == 3


def test_recognizes_transparently_wrapped_assignment_as_materialized() -> None:
    project, function, codegen, _root, body, assignment = _surface()
    assert materialize_direct_stack_move_branch_ownership_8616(
        project,
        codegen,
        function,
    )
    wrapper = CExpressionStatement(assignment, codegen=codegen)
    body.statements[1] = wrapper

    assert not materialize_direct_stack_move_branch_ownership_8616(
        project,
        codegen,
        function,
    )
    assert body.statements[1] is wrapper
    stats = codegen._inertia_direct_stack_move_branch_placement_8616
    assert stats.materialized_count == 1
    assert stats.already_materialized_count == 1
    assert stats.failure_count == 0


def test_moves_assignment_into_machine_taken_arm_when_rendered_if_is_inverted() -> None:
    project, function, codegen, root, taken_body, assignment = _surface(
        inverted=True
    )

    assert materialize_direct_stack_move_branch_ownership_8616(
        project, codegen, function
    )
    assert root.statements == [root.statements[0]]
    assert taken_body.statements[1] is assignment
    rendered_if_body = root.statements[0].condition_and_nodes[0][1]
    assert assignment not in rendered_if_body.statements


def test_replays_unique_typed_stack_move_after_codegen_drops_assignment_tag() -> None:
    project, function, codegen, root, body, assignment = _surface()
    assignment.tags.clear()

    assert materialize_direct_stack_move_branch_ownership_8616(
        project, codegen, function
    )
    assert root.statements == [root.statements[0]]
    assert body.statements[1] is assignment


def test_replays_assignment_through_bp_to_entry_sp_projection() -> None:
    project, function, codegen, root, body, assignment = _surface()
    destination = assignment.lhs.variable
    source = assignment.rhs.variable
    destination.offset = -6
    source.offset = -4
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=destination,
        cvar=assignment.lhs,
        bp_offset=-4,
        entry_sp_offset=-6,
        size=2,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=source,
        cvar=assignment.rhs,
        bp_offset=-2,
        entry_sp_offset=-4,
        size=2,
    )

    assert materialize_direct_stack_move_branch_ownership_8616(project, codegen, function)
    assert root.statements == [root.statements[0]]
    assert body.statements[1] is assignment


def test_places_lowering_built_assignment_after_codegen_drops_the_store() -> None:
    project, function, codegen, root, body, assignment = _surface()
    root.statements.remove(assignment)

    assert place_direct_stack_move_assignment_8616(
        project,
        codegen,
        function,
        _move_fact(),
        assignment,
    )
    assert body.statements[1] is assignment


def test_replay_fact_places_only_taken_assignment_into_empty_body() -> None:
    """Typed arm targets place a move without circular body provenance."""
    project, function, codegen, root, body, assignment = _surface()
    body.statements.clear()
    codegen._inertia_structuring_condition_replay_facts_8616 = (
        StructuringConditionReplayFact8616(
            root_src_insn=0x10BA5,
            root_block_addr=0x10BA1,
            true_target=0x10BAD,
            false_target=0x10BB9,
        ),
    )

    assert materialize_direct_stack_move_branch_ownership_8616(
        project,
        codegen,
        function,
    )
    assert root.statements == [root.statements[0]]
    assert body.statements == [assignment]


def test_counts_exact_tagged_loop_iterator_as_materialized_branch_write() -> None:
    """Structuring may preserve a branch-tail write as a for-loop iterator."""
    project, function, codegen, root, _body, assignment = _surface()
    branch = root.statements[0]
    root.statements[:] = [
        CForLoop(
            None,
            CVariable(SimStackVariable(-4, 2, base="bp", name="minimum"), codegen=codegen),
            assignment,
            CStatements([branch], codegen=codegen),
            codegen=codegen,
        )
    ]

    assert not materialize_direct_stack_move_branch_ownership_8616(project, codegen, function)
    stats = codegen._inertia_direct_stack_move_branch_placement_8616
    assert stats.materialized_count == 1
    assert stats.already_materialized_count == 1
    assert stats.failure_count == 0


def test_lowering_uses_branch_service_when_generic_fallback_is_disabled(
    monkeypatch,
) -> None:
    project, function, codegen, root, body, assignment = _surface()
    root.statements.remove(assignment)
    assignment.tags.clear()
    body.statements.insert(1, assignment)
    assignment.lhs.variable.name = "local_4"
    assignment.rhs.variable.name = "local_2"
    word_type = SimTypeShort(False).with_arch(project.arch)
    assignment.lhs.variable_type = word_type
    assignment.rhs.variable_type = word_type
    codegen.cfunc.addr = 0x10B90
    codegen.cfunc.variables_in_use = {
        assignment.lhs.variable: assignment.lhs,
        assignment.rhs.variable: assignment.rhs,
    }
    codegen._inertia_direct_stack_move_branch_placement_service_8616 = (
        lambda fact, built_assignment: place_direct_stack_move_assignment_8616(
            project,
            codegen,
            function,
            fact,
            built_assignment,
        )
    )
    monkeypatch.setattr(
        real_mode_linear,
        "_direct_stack_move_instruction_facts_for_codegen_8616",
        lambda *_args: (_move_fact(),),
    )
    monkeypatch.setattr(
        real_mode_linear,
        "prune_frame_prologue_stack_assignments_8616",
        lambda *_args, **_kwargs: False,
    )
    monkeypatch.setattr(
        real_mode_linear,
        "materialize_stack_aggregate_objects_8616",
        lambda *_args, **_kwargs: False,
    )

    assert not real_mode_linear.materialize_direct_stack_mov_instructions_8616(
        codegen,
        project=project,
        function=function,
        allow_stack_slot_fallback=False,
        materialize_reloads=False,
    )
    assert len(codegen._inertia_direct_stack_move_evidence_8616) == 1
    replay_stats = codegen._inertia_direct_stack_replay_state_8616.stats
    assert replay_stats.changed_count == 0
    assert replay_stats.stable_count == 1
    body.statements.remove(assignment)

    assert real_mode_linear.materialize_direct_stack_mov_instructions_8616(
        codegen,
        project=project,
        function=function,
        allow_stack_slot_fallback=False,
        materialize_reloads=False,
    )
    inserted = body.statements[1]
    assert isinstance(inserted, CAssignment)
    assert inserted.lhs.variable is assignment.lhs.variable
    assert inserted.rhs.variable is assignment.rhs.variable


def test_moves_assignment_into_guarded_fallthrough_siblings() -> None:
    project, function, codegen, root, taken_body, assignment = _surface()
    original_branch = root.statements[0]
    condition = original_branch.condition_and_nodes[0][0]
    return_body = CStatements(
        [
            CAssignment(
                assignment.lhs,
                assignment.lhs,
                codegen=codegen,
                tags={"ins_addr": 0x10BA7},
            )
        ],
        codegen=codegen,
    )
    guard = CIfElse(
        [(condition, return_body)],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    root.statements[:] = [
        guard,
        taken_body.statements[0],
        taken_body.statements[1],
        assignment,
    ]

    assert materialize_direct_stack_move_branch_ownership_8616(
        project, codegen, function
    )
    assert root.statements[2] is assignment
    assert root.statements[1].tags["ins_addr"] == 0x10BAA
    assert root.statements[3].tags["ins_addr"] == 0x10BB0


def test_refuses_assignment_relocation_without_condition_provenance() -> None:
    project, function, codegen, root, body, assignment = _surface(
        tagged_condition=False
    )

    assert not materialize_direct_stack_move_branch_ownership_8616(project, codegen, function)
    assert not finalize_direct_stack_move_branch_ownership_8616(project, codegen, function)
    assert root.statements[-1] is assignment
    assert len(body.statements) == 2
    stats = codegen._inertia_direct_stack_move_branch_placement_8616
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 1


def test_finalizer_fails_when_proven_branch_assignment_is_absent() -> None:
    project, function, codegen, _root, _body, assignment = _surface()
    assignment.lhs = CVariable(
        SimStackVariable(-6, 2, base="bp", name="wrong_destination"),
        codegen=codegen,
    )

    with pytest.raises(PipelineHardError, match="classified direct stack move branch"):
        finalize_direct_stack_move_branch_ownership_8616(project, codegen, function)

    stats = codegen._inertia_direct_stack_move_branch_placement_8616
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 0
    assert stats.failure_count == 1
