from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CFunctionCall,
    CIfElse,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
import inertia.structuring.call_return_register_placement as placement_module
from archinfo import ArchX86

from inertia.structuring.call_return_register_index import (
    build_call_return_register_index_8616,
)
from inertia.structuring.call_return_register_placement import (
    CallReturnRegisterPlacementVerdict8616,
    classify_call_return_register_placement_8616,
    consume_exact_call_return_register_placement_8616,
)

CALLSITE = 0x101D4
CONDITION_PRODUCER = CALLSITE + 6
AX_SLICE = (8, 2)


def _codegen() -> SimpleNamespace:
    node_ids = iter(range(1, 100))
    identifiers = iter(range(1, 100))
    return SimpleNamespace(
        next_node_idx=lambda: next(node_ids),
        next_ident=lambda name: f"{name}_{next(identifiers)}",
        cstyle_null_cmp=False,
        project=SimpleNamespace(arch=ArchX86()),
    )


def _bound_call_assignment(codegen: SimpleNamespace, *, ins_addr: int) -> CAssignment:
    call = CFunctionCall(
        "sub_10010",
        SimpleNamespace(addr=0x10010, name="sub_10010"),
        [],
        codegen=codegen,
        tags={"ins_addr": CALLSITE},
    )
    return CAssignment(
        CVariable(SimRegisterVariable(*AX_SLICE), codegen=codegen),
        call,
        codegen=codegen,
        tags={"ins_addr": ins_addr},
    )


def _branch(codegen: SimpleNamespace) -> CIfElse:
    return CIfElse(
        [(CConstant(1, SimTypeShort(False), codegen=codegen), CStatements([], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )


def test_bound_call_identity_is_not_conflicted_by_later_assignment_instruction() -> None:
    """Treat an assignment source instruction as placement, not call identity."""
    codegen = _codegen()
    assignment = _bound_call_assignment(codegen, ins_addr=CONDITION_PRODUCER)
    branch = _branch(codegen)
    root = CStatements([assignment, branch], codegen=codegen)

    result = classify_call_return_register_placement_8616(
        root,
        branch,
        callsite_addr=CALLSITE,
        condition_producer_insn=CONDITION_PRODUCER,
        register_slice=AX_SLICE,
    )

    assert result.verdict is CallReturnRegisterPlacementVerdict8616.EXACT
    assert result.assignment is assignment


def test_direct_call_instruction_assignment_proves_return_producer() -> None:
    """Accept an adjacent direct AX call carrier tagged by its call instruction."""
    codegen = _codegen()
    assignment = _bound_call_assignment(codegen, ins_addr=CALLSITE)
    branch = _branch(codegen)
    root = CStatements([assignment, branch], codegen=codegen)

    result = classify_call_return_register_placement_8616(
        root,
        branch,
        callsite_addr=CALLSITE,
        condition_producer_insn=CONDITION_PRODUCER,
        register_slice=AX_SLICE,
    )

    assert result.verdict is CallReturnRegisterPlacementVerdict8616.EXACT
    assert result.assignment is assignment


def test_nonadjacent_bound_clone_conflicts_with_exact_producer() -> None:
    """Refuse to delete a same-callsite clone across an observable barrier."""
    codegen = _codegen()
    stale = _bound_call_assignment(codegen, ins_addr=CALLSITE + 9)
    separator = CAssignment(
        CVariable(SimRegisterVariable(12, 2), codegen=codegen),
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    adjacent = _bound_call_assignment(codegen, ins_addr=CONDITION_PRODUCER)
    branch = _branch(codegen)
    root = CStatements([stale, separator, adjacent, branch], codegen=codegen)

    result = classify_call_return_register_placement_8616(
        root,
        branch,
        callsite_addr=CALLSITE,
        condition_producer_insn=CONDITION_PRODUCER,
        register_slice=AX_SLICE,
    )

    assert result.verdict is CallReturnRegisterPlacementVerdict8616.CONFLICT
    assert result.assignment is None


def test_transparent_adjacent_statement_groups_prove_call_condition_order() -> None:
    """Accept unique adjacent sibling subtrees without flattening control flow."""
    codegen = _codegen()
    assignment = _bound_call_assignment(codegen, ins_addr=CONDITION_PRODUCER)
    branch = _branch(codegen)
    assignment_group = CStatements([assignment], codegen=codegen)
    branch_group = CStatements([branch], codegen=codegen)
    root = CStatements([assignment_group, branch_group], codegen=codegen)

    result = classify_call_return_register_placement_8616(
        root,
        branch,
        callsite_addr=CALLSITE,
        condition_producer_insn=CONDITION_PRODUCER,
        register_slice=AX_SLICE,
    )

    assert result.verdict is CallReturnRegisterPlacementVerdict8616.EXACT
    assert result.assignment_container is assignment_group
    assert result.assignment_index == 0


def test_consumes_adjacent_same_callsite_assignment_clone() -> None:
    """Consume producer and compare-tagged clones from one predecessor group."""
    codegen = _codegen()
    producer = _bound_call_assignment(codegen, ins_addr=CONDITION_PRODUCER)
    compare_clone = _bound_call_assignment(codegen, ins_addr=CONDITION_PRODUCER + 3)
    branch = _branch(codegen)
    assignment_group = CStatements([producer, compare_clone], codegen=codegen)
    root = CStatements([assignment_group, branch], codegen=codegen)
    assignment_index = build_call_return_register_index_8616(root)

    result = classify_call_return_register_placement_8616(
        root,
        branch,
        callsite_addr=CALLSITE,
        condition_producer_insn=CONDITION_PRODUCER,
        register_slice=AX_SLICE,
        assignment_index=assignment_index,
    )

    assert result.verdict is CallReturnRegisterPlacementVerdict8616.EXACT
    assert result.assignment is producer
    assert tuple(item.assignment for item in result.redundant_assignments) == (compare_clone,)
    assert assignment_index.bound_callsite_count(CALLSITE) == 2
    assert consume_exact_call_return_register_placement_8616(result)
    assert tuple(assignment_group.statements) == ()
    assert not assignment_index.valid
    after = classify_call_return_register_placement_8616(
        root,
        branch,
        callsite_addr=CALLSITE,
        condition_producer_insn=CONDITION_PRODUCER,
        register_slice=AX_SLICE,
        assignment_index=assignment_index,
    )
    assert after.verdict is CallReturnRegisterPlacementVerdict8616.MISSING


def test_duplicate_placement_reuses_one_statement_position_snapshot(monkeypatch) -> None:
    """Build adjacency positions once for one multi-candidate classification."""
    codegen = _codegen()
    producer = _bound_call_assignment(codegen, ins_addr=CONDITION_PRODUCER)
    compare_clone = _bound_call_assignment(codegen, ins_addr=CONDITION_PRODUCER + 3)
    branch = _branch(codegen)
    assignment_group = CStatements([producer, compare_clone], codegen=codegen)
    root = CStatements([assignment_group, branch], codegen=codegen)
    original = placement_module._statement_positions_8616
    calls = 0

    def counted_positions(candidate_root: object):
        nonlocal calls
        calls += 1
        return original(candidate_root)

    monkeypatch.setattr(placement_module, "_statement_positions_8616", counted_positions)

    result = classify_call_return_register_placement_8616(
        root,
        branch,
        callsite_addr=CALLSITE,
        condition_producer_insn=CONDITION_PRODUCER,
        register_slice=AX_SLICE,
    )

    assert result.verdict is CallReturnRegisterPlacementVerdict8616.EXACT
    assert calls == 1


def test_refuses_call_assignment_inside_condition_else_path() -> None:
    """Do not move a branch-local call into its enclosing condition."""
    codegen = _codegen()
    assignment = _bound_call_assignment(codegen, ins_addr=CONDITION_PRODUCER)
    branch = _branch(codegen)
    branch.else_node = CStatements([assignment], codegen=codegen)
    root = CStatements([branch], codegen=codegen)

    result = classify_call_return_register_placement_8616(
        root,
        branch,
        callsite_addr=CALLSITE,
        condition_producer_insn=CONDITION_PRODUCER,
        register_slice=AX_SLICE,
    )

    assert result.verdict is CallReturnRegisterPlacementVerdict8616.NONADJACENT
    assert result.assignment is assignment


def test_refuses_assignment_from_another_condition_instruction() -> None:
    """Require the assignment carrier to cite the exact typed condition."""
    codegen = _codegen()
    assignment = _bound_call_assignment(codegen, ins_addr=CALLSITE + 9)
    branch = _branch(codegen)
    root = CStatements([assignment, branch], codegen=codegen)

    result = classify_call_return_register_placement_8616(
        root,
        branch,
        callsite_addr=CALLSITE,
        condition_producer_insn=CONDITION_PRODUCER,
        register_slice=AX_SLICE,
    )

    assert result.verdict is CallReturnRegisterPlacementVerdict8616.MISSING


def test_refuses_nonadjacent_transparent_statement_groups() -> None:
    """Require producer and condition groups to be immediate siblings."""
    codegen = _codegen()
    assignment = _bound_call_assignment(codegen, ins_addr=CONDITION_PRODUCER)
    branch = _branch(codegen)
    assignment_group = CStatements([assignment], codegen=codegen)
    barrier_group = CStatements(
        [
            CAssignment(
                CVariable(SimRegisterVariable(12, 2), codegen=codegen),
                CConstant(0, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            )
        ],
        codegen=codegen,
    )
    branch_group = CStatements([branch], codegen=codegen)
    root = CStatements([assignment_group, barrier_group, branch_group], codegen=codegen)

    result = classify_call_return_register_placement_8616(
        root,
        branch,
        callsite_addr=CALLSITE,
        condition_producer_insn=CONDITION_PRODUCER,
        register_slice=AX_SLICE,
    )

    assert result.verdict is CallReturnRegisterPlacementVerdict8616.NONADJACENT
