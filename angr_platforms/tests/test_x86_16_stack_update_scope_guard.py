"""Prevent instruction-tag deduplication from broadening conditional effects."""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CForLoop,
    CIfElse,
    CStatements,
)
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.lowering.real_mode_linear import _replace_tagged_assignment_8616
from angr_platforms.X86_16.lowering.stack_update_scope_guard import require_stack_update_scope_8616
from angr_platforms.X86_16.pipeline.errors import PipelineHardError
from archinfo import ArchX86


def _surface(*, same_instruction=True, else_arm=False, guarded=True):
    codegen = SimpleNamespace(
        next_idx=lambda _name: 1, next_ident=lambda name: name,
        next_node_idx=lambda: 1, cstyle_null_cmp=False,
        project=SimpleNamespace(arch=ArchX86()),
    )
    value = CConstant(1, SimTypeShort(False), codegen=codegen)
    iterator = CAssignment(value, value, codegen=codegen, tags={"ins_addr": 0x1234})
    fragment = CAssignment(
        value, value, codegen=codegen,
        tags={"ins_addr": 0x1234 if same_instruction else 0x1240},
    )
    arm = CStatements([fragment], codegen=codegen)
    empty = CStatements([], codegen=codegen)
    branch = CIfElse(
        [(value, empty if else_arm else arm)],
        else_node=arm if else_arm else None, codegen=codegen,
    )
    body = CStatements([branch] if guarded else [fragment], codegen=codegen)
    loop = CForLoop(None, value, iterator, body, codegen=codegen)
    root = CStatements([loop], codegen=codegen)
    return root, loop, arm, iterator, fragment


@pytest.mark.parametrize("else_arm", [False, True])
def test_tagged_update_refuses_cross_scope_collapse_before_mutation(else_arm):
    root, loop, arm, iterator, fragment = _surface(else_arm=else_arm)
    with pytest.raises(PipelineHardError, match=r"0x1234.*CFG-proven placement") as error:
        _replace_tagged_assignment_8616(
            root, SimpleNamespace(), 0x1234,
            lambda _tags: pytest.fail("replacement factory ran before scope validation"),
            allow_tagged_iterator_expression=True,
            remove_duplicate_tagged_assignments=True,
        )
    assert error.value.layer == "Types/Lowering"
    assert loop.iterator is iterator
    assert arm.statements == [fragment]


@pytest.mark.parametrize(("same_instruction", "guarded"), [(False, True), (True, False)])
def test_scope_guard_does_not_claim_unrelated_or_unconditional_conflict(same_instruction, guarded):
    root, _loop, _arm, iterator, _fragment = _surface(
        same_instruction=same_instruction, guarded=guarded,
    )
    require_stack_update_scope_8616(
        root, 0x1234,
        lambda node: isinstance(node, CAssignment) and node.tags == iterator.tags,
    )
