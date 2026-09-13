"""Keep initialization observable when a stack address is passed to a callee."""

import pytest
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CFunctionCall, CUnaryOp
from angr_platforms.X86_16.tail_validation import (
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
)
from test_x86_16_tail_validation import _codegen, _const, _DummyCodegen, _project, _stack

_INITIAL_VALUE = 7


@pytest.mark.parametrize("offset", [-4, 0, 4])
@pytest.mark.parametrize("replacement", [None, 9, 7], ids=["removed", "changed-value", "equivalent-regenerated"])
def test_tail_validation_tracks_initialization_of_address_exposed_stack(offset: int, replacement: int | None) -> None:
    project = _project()
    summaries = []
    for initialize in (_INITIAL_VALUE, replacement):
        codegen = _DummyCodegen()
        slot = _stack(offset, codegen)
        statements = [CAssignment(slot, _const(initialize, codegen), codegen=codegen)] if initialize is not None else []
        statements.append(CFunctionCall("observe", None, [CUnaryOp("Reference", slot, codegen=codegen)], codegen=codegen))
        summaries.append(collect_x86_16_tail_validation_summary(project, _codegen(statements, codegen), mode="live_out"))
    diff = compare_x86_16_tail_validation_summaries(*summaries)
    assert diff["changed"] == (replacement != _INITIAL_VALUE), diff
    if replacement != _INITIAL_VALUE:
        assert diff["delta"]["exposed_stack_values"]["removed"]
    assert summaries[0].as_dict()["exposed_stack_values"]
