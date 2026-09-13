"""Real angr instruction tags must survive loop evidence queries."""

import pytest
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CStatements
from angr.rustylib.ailment import Tags
from angr_platforms.X86_16.structuring import loop_break_jcc
from test_x86_16_structuring_loop_break_jcc import _const, _DummyCodegen, _reg


@pytest.mark.parametrize("tag_type", [dict, Tags])
@pytest.mark.parametrize("cached", [False, True])
def test_loop_instruction_membership_accepts_angr_tags(tag_type, cached):
    """A present CFG target cannot become an apparent exit by losing its tags."""
    codegen = _DummyCodegen()
    assignment = CAssignment(
        _reg("ax", codegen), _const(1, codegen), codegen=codegen,
        tags=tag_type({"ins_addr": 0x4010, "vex_block_addr": 0x4000}),
    )
    body = CStatements([assignment], codegen=codegen)
    query = loop_break_jcc._LoopBreakAstQuerySession8616() if cached else None
    assert loop_break_jcc._root_contains_ins_addr_8616(body, 0x4010, query)
    assert not loop_break_jcc._root_contains_ins_addr_8616(body, 0x4020, query)
    assert loop_break_jcc._condition_tags_8616(assignment) == (0x4010, 0x4000)
