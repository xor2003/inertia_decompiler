from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from angr import ailment
from angr.analyses.decompiler.structurer_nodes import (
    BreakNode,
    ConditionNode,
    LoopNode,
    SequenceNode,
)

from inertia.structuring.typed_switch_seqnode import (
    TypedSwitchSeqNodeRefusal8616,
    materialize_typed_switch_seqnode_8616,
)


@dataclass(frozen=True)
class _Block:
    addr: int


def _selector_prefix():
    selector = ailment.Expr.VirtualVariable(
        101, 74, 16, ailment.Expr.VirtualVariableCategory.REGISTER, oident=0,
    )
    return ailment.Block(0x1800, 4, statements=[
        ailment.Stmt.Assignment(102, selector, ailment.Expr.Const(103, 1, 16)),
    ])


def _selector_condition():
    use = ailment.Expr.VirtualVariable(
        111, 74, 16, ailment.Expr.VirtualVariableCategory.REGISTER, oident=0,
    )
    return ailment.Expr.BinaryOp(110, "CmpEQ", (use, ailment.Expr.Const(112, 1, 16)), False, bits=1)


def _switch_tree() -> tuple[SimpleNamespace, SequenceNode, SequenceNode, SequenceNode, SequenceNode, BreakNode]:
    case_a = SequenceNode(0x2100, [_Block(0x2100)])
    case_b = SequenceNode(0x2200, [_Block(0x2200)])
    default_break = BreakNode(0x2300, 0x3000)
    remainder = ConditionNode(0x2050, None, _selector_condition(), case_b, default_break)
    ladder = ConditionNode(0x2000, None, _selector_condition(), case_a, remainder)
    loop_sequence = SequenceNode(0x1000, [_selector_prefix(), ladder])
    loop_node = LoopNode("while", None, loop_sequence, addr=0x1000)
    root = SequenceNode(0x0800, [loop_node, SequenceNode(0x3000, [_Block(0x3000)])])
    project = SimpleNamespace(arch=SimpleNamespace(registers={"ax": (0, 2)}))
    return project, root, loop_sequence, case_a, case_b, default_break


def _nested_switch_tree() -> tuple[SimpleNamespace, SequenceNode, SequenceNode, SequenceNode, SequenceNode, BreakNode]:
    case_a = SequenceNode(0x2100, [_Block(0x2100)])
    case_b = SequenceNode(0x2200, [_Block(0x2200)])
    default_break = BreakNode(0x2300, 0x3000)
    condition = ConditionNode(0x2050, None, _selector_condition(), case_a, case_b)
    ladder = SequenceNode(0x2000, [condition, default_break])
    loop_sequence = SequenceNode(0x1000, [_selector_prefix(), ladder])
    loop_node = LoopNode("while", None, loop_sequence, addr=0x1000)
    root = SequenceNode(0x0800, [loop_node, SequenceNode(0x3000, [_Block(0x3000)])])
    project = SimpleNamespace(arch=SimpleNamespace(registers={"ax": (0, 2)}))
    return project, root, loop_sequence, case_a, case_b, default_break


def _materialize(
    project: SimpleNamespace,
    root: SequenceNode,
    *,
    case_values: list[object] | None = None,
    break_paths: list[list[int]] | None = None,
    prefix_count: int = 1,
):
    return materialize_typed_switch_seqnode_8616(
        project,
        root,
        first_mapping={
            "switch_condition_lhs": {
                "name": "ax",
                "offset": 0,
                "size": 2,
                "space": "reg",
            }
        },
        owner_paths={"ready": True, "ladder_owner_path": [0]},
        loop_mapping={
            "expanded_root_normalized_case_values": case_values if case_values is not None else [1, 2]
        },
        materialization_plan={
            "break_paths": break_paths if break_paths is not None else [[prefix_count, 1, 1]],
            "case_path_common_parent": [prefix_count],
            "case_paths": [[prefix_count, 0], [prefix_count, 1, 0]],
            "external_default_addr": 0x3000,
            "status": "candidate_loop_break_default_switch",
        },
    )


def test_typed_switch_seqnode_materializes_complete_structuring_evidence() -> None:
    project, root, loop_sequence, case_a, case_b, default_break = _switch_tree()

    result = _materialize(project, root)

    replacement = loop_sequence.nodes[1]
    assert result.changed is True
    assert result.refusal is None
    assert result.case_count == 2
    assert result.as_runtime_record()["selector_binding"] == {
        "raw_fact_count": 1, "normalized_fact_count": 1, "classified_fact_count": 1,
        "materialized_count": 1, "failure_count": 0,
    }
    assert result.default_target_addr == 0x3000
    assert type(replacement).__name__ == "SwitchCaseNode"
    assert isinstance(replacement.switch_expr, ailment.Expr.VirtualVariable)
    assert replacement.switch_expr.reg_offset == 0
    assert replacement.switch_expr.bits == 16
    assert replacement.switch_expr.idx == 111
    assert replacement.switch_expr.varid == loop_sequence.nodes[0].statements[0].dst.varid
    assert list(replacement.cases) == [1, 2]
    assert replacement.cases[1] is case_a
    assert replacement.cases[2] is case_b
    assert replacement.default_node is default_break


@pytest.mark.parametrize("offset,bits,accepted", [(0, 8, False), (1, 8, False), (0, 16, False),
                                                  (0, 32, False), (4, 16, True)])
def test_switch_selector_binding_respects_overlapping_register_writes(offset, bits, accepted):
    project, root, loop_sequence, *_ = _switch_tree()
    original_ladder = loop_sequence.nodes[1]
    dst = ailment.Expr.VirtualVariable(
        201, 75, bits, ailment.Expr.VirtualVariableCategory.REGISTER, oident=offset,
    )
    loop_sequence.nodes[0].statements.append(
        ailment.Stmt.Assignment(202, dst, ailment.Expr.Const(203, 0, bits)),
    )

    result = _materialize(project, root)

    assert result.changed is accepted
    if not accepted:
        assert result.refusal is TypedSwitchSeqNodeRefusal8616.MISSING_AIL_SWITCH_EXPRESSION
        assert loop_sequence.nodes[1] is original_ladder


@pytest.mark.parametrize("kind", ["missing", "call", "side-effect-call", "nested-call", "branch", "raw-register", "predicate-call"])
def test_switch_selector_binding_refuses_unproven_reaching_values(kind):
    project, root, loop_sequence, *_ = _switch_tree()
    original_ladder = loop_sequence.nodes[1]
    prefix = loop_sequence.nodes[0]
    call = ailment.Expr.Call(301, ailment.Expr.Const(302, 0x4000, 16), args=(), bits=16)
    if kind == "missing":
        prefix.statements.clear()
    elif kind == "call":
        prefix.statements.append(call)
    elif kind == "side-effect-call":
        prefix.statements.append(ailment.Stmt.SideEffectStatement(300, call))
    elif kind == "nested-call":
        prefix.statements.append(ailment.Stmt.Assignment(
            303, ailment.Expr.VirtualVariable(
                304, 76, 16, ailment.Expr.VirtualVariableCategory.REGISTER, oident=4,
            ), call,
        ))
    elif kind == "branch":
        loop_sequence.nodes[0] = ConditionNode(0x1800, None, None, prefix, None)
    elif kind == "predicate-call":
        loop_sequence.nodes[1].condition = ailment.Expr.Call(
            308, ailment.Expr.Const(309, 0x4000, 16), args=(prefix.statements[0].dst,), bits=16,
        )
    else:
        prefix.statements.append(ailment.Stmt.Assignment(
            305, ailment.Expr.Register(306, 0, 16), ailment.Expr.Const(307, 0, 16),
        ))

    result = _materialize(project, root)

    assert not result.changed
    assert result.as_runtime_record()["selector_binding"]["failure_count"] == 1
    assert result.refusal is TypedSwitchSeqNodeRefusal8616.MISSING_AIL_SWITCH_EXPRESSION
    assert loop_sequence.nodes[1] is original_ladder


def test_switch_selector_definition_after_side_effect_call_is_reaching():
    project, root, loop_sequence, *_ = _switch_tree()
    prefix = loop_sequence.nodes[0]
    call = ailment.Expr.Call(401, ailment.Expr.Const(402, 0x4000, 16), args=(), bits=16)
    prefix.statements.insert(0, ailment.Stmt.SideEffectStatement(400, call))
    expected = prefix.statements[1].dst

    result = _materialize(project, root)

    assert result.changed
    assert loop_sequence.nodes[1].switch_expr.idx == 111
    assert loop_sequence.nodes[1].switch_expr.varid == expected.varid


def test_switch_replay_preserves_folded_call_selector():
    project, root, loop_sequence, *_ = _switch_tree()
    assert _materialize(project, root).changed
    existing = loop_sequence.nodes[1]
    call = ailment.Expr.Call(501, ailment.Expr.Const(502, 0x4000, 16), args=(), bits=16)
    existing.switch_expr = call

    result = materialize_typed_switch_seqnode_8616(
        project, root,
        first_mapping={"switch_condition_lhs": {"name": "ax", "offset": 0, "size": 2, "space": "reg"}},
        owner_paths={"ready": True, "ladder_owner_path": [0]},
        loop_mapping={"expanded_root_normalized_case_values": [1, 2]},
        materialization_plan={
            "break_paths": [[1, 0]], "case_path_common_parent": [1],
            "case_paths": [[1, 1], [1, 2]], "external_default_addr": 0x3000,
            "status": "candidate_loop_break_default_switch",
        },
    )

    assert not result.changed
    assert loop_sequence.nodes[1] is existing
    assert existing.switch_expr is call


def test_typed_switch_preserves_reaching_ssa_selector_identity() -> None:
    project, root, loop_sequence, *_ = _switch_tree()
    selector = ailment.Expr.VirtualVariable(
        101, 74, 16, ailment.Expr.VirtualVariableCategory.REGISTER, oident=0,
    )
    prefix = ailment.Block(0x1800, 4, statements=[
        ailment.Stmt.Assignment(102, selector, ailment.Expr.Const(103, 1, 16)),
    ])
    loop_sequence.nodes[0] = prefix

    result = _materialize(project, root, prefix_count=1)

    assert result.changed
    assert loop_sequence.nodes[1].switch_expr.idx == 111
    assert loop_sequence.nodes[1].switch_expr.varid == selector.varid


def test_typed_switch_seqnode_refuses_duplicate_case_values_without_mutation() -> None:
    project, root, loop_sequence, *_ = _switch_tree()
    original_ladder = loop_sequence.nodes[1]

    result = _materialize(project, root, case_values=[1, 1])

    assert result.changed is False
    assert result.refusal is TypedSwitchSeqNodeRefusal8616.DUPLICATE_CASE_VALUE
    assert loop_sequence.nodes[1] is original_ladder


def test_typed_switch_seqnode_refuses_non_unique_default_without_mutation() -> None:
    project, root, loop_sequence, *_ = _switch_tree()
    original_ladder = loop_sequence.nodes[1]

    result = _materialize(project, root, break_paths=[[1, 2], [1, 2]])

    assert result.changed is False
    assert result.refusal is TypedSwitchSeqNodeRefusal8616.MISSING_UNIQUE_DEFAULT_BREAK_PATH
    assert loop_sequence.nodes[1] is original_ladder


def test_typed_switch_seqnode_resolves_condition_branch_paths() -> None:
    project, root, loop_sequence, case_a, case_b, default_break = _nested_switch_tree()

    result = materialize_typed_switch_seqnode_8616(
        project,
        root,
        first_mapping={
            "switch_condition_lhs": {
                "name": "ax",
                "offset": 0,
                "size": 2,
                "space": "reg",
            }
        },
        owner_paths={"ready": True, "ladder_owner_path": [0]},
        loop_mapping={"expanded_root_normalized_case_values": [1, 2]},
        materialization_plan={
            "break_paths": [[1, 1]],
            "case_path_common_parent": [1],
            "case_paths": [[1, 0, 0], [1, 0, 1]],
            "external_default_addr": 0x3000,
            "status": "candidate_loop_break_default_switch",
        },
    )

    replacement = loop_sequence.nodes[1]
    assert result.changed is True
    assert replacement.cases[1] is case_a
    assert replacement.cases[2] is case_b
    assert replacement.default_node is default_break
