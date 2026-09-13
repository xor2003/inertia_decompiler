"""Reject switch replacement that deletes definitions of retained SSA reads."""

import pytest
from angr import ailment
from angr.analyses.decompiler.structurer_nodes import ConditionNode, SequenceNode
from angr_platforms.X86_16.structuring.switch_definition_coverage import missing_switch_definition_ids_8616
from angr_platforms.X86_16.structuring.typed_switch_seqnode import _children_8616
from test_x86_16_typed_switch_seqnode import _switch_tree


def _variable(varid):
    return ailment.Expr.VirtualVariable(varid, varid, 16, ailment.Expr.VirtualVariableCategory.REGISTER, oident=0)


def _definition(varid, source):
    return ailment.Stmt.Assignment(varid, _variable(varid), source)


def test_switch_replacement_refuses_discarded_definition_used_by_case() -> None:
    project, root, sequence, _case_a, case_b, _default = _switch_tree()
    original = sequence.nodes[1]
    lost_id = 501
    prefix = ailment.Block(0x1900, 2, statements=[
        _definition(lost_id, ailment.Expr.Const(502, 7, 16)),
    ])
    original.false_node = SequenceNode(0x1900, [prefix, original.false_node])
    case_b.nodes = [ailment.Block(case_b.addr, 2, statements=[
        _definition(503, _variable(lost_id)),
    ])]
    # The existing plan's paths must identify the nested ladder exactly.
    from angr_platforms.X86_16.structuring.typed_switch_seqnode import materialize_typed_switch_seqnode_8616

    before = sequence.nodes[1]
    result = materialize_typed_switch_seqnode_8616(
        project, root,
        first_mapping={"switch_condition_lhs": {"name": "ax", "space": "reg", "offset": 0, "size": 2}},
        owner_paths={"ready": True, "ladder_owner_path": [0]},
        loop_mapping={"expanded_root_normalized_case_values": [1, 2]},
        materialization_plan={
            "status": "candidate_loop_break_default_switch",
            "case_paths": [[1, 0], [1, 1, 1, 0]],
            "break_paths": [[1, 1, 1, 1]],
            "case_path_common_parent": [1],
            "external_default_addr": 0x3000,
        },
    )
    assert result.changed is False
    assert result.refusal.value == "live_definition_loss"
    assert str(lost_id) in result.refusal_detail
    assert sequence.nodes[1] is before


@pytest.mark.parametrize("site", ["case", "tail", "condition", "discarded", "external", "retained"])
def test_definition_loss_check_covers_retained_surfaces(site) -> None:
    varid = 601
    definition = ailment.Block(0x1800, 2, statements=[
        _definition(varid, ailment.Expr.Const(602, 7, 16)),
    ])
    read = ailment.Block(0x2100, 2, statements=[_definition(603, _variable(varid))])
    replaced = SequenceNode(0x1800, [definition, read])
    root = SequenceNode(0x1000, [replaced])
    retained = (read,)
    expected = (varid,)
    if site == "tail":
        root.nodes.append(read)
        retained = ()
    elif site == "condition":
        retained = (ConditionNode(0x2100, None, _variable(varid), None, None),)
    elif site == "discarded":
        retained, expected = (), ()
    elif site == "external":
        replaced.nodes.remove(definition)
        expected = ()
    elif site == "retained":
        retained, expected = (definition, read), ()
    assert missing_switch_definition_ids_8616(
        root, replaced, retained, children=_children_8616,
    ) == expected
