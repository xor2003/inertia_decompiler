"""Stack restoration must consume exact values, not shared expression labels."""

import pytest
from angr_platforms.X86_16.alias.segment_stack_fragments import (
    SegmentStackByteOrigin8616,
    register_value_fragments_8616,
)
from angr_platforms.X86_16.alias.segment_stack_restore import (
    SegmentStackRestoreVerdict8616,
    build_x86_16_stack_register_restore_artifact_8616,
)
from angr_platforms.X86_16.ir.core import IRValue, MemSpace
from test_x86_16_segment_stack_restore import _lift_function

_FAR_LOAD_ADDRESS = 0x1005


@pytest.mark.parametrize("opcode,segment", [(0xC4, "es"), (0xC5, "ds")])
def test_far_stack_load_keeps_offset_and_segment_word_sources_distinct(opcode, segment):
    # PUSH AX; PUSH DX; L[ED]S SI,[BP-4]: SI receives DX, the segment receives AX.
    code = bytes.fromhex("55 89 e5 50 52") + bytes([opcode, 0x76, 0xFC]) + bytes.fromhex("5a 58 5d c3")
    artifact = build_x86_16_stack_register_restore_artifact_8616(
        _lift_function(code), tracked_registers=frozenset({"ax", "dx", "si", segment}),
    )
    facts = {fact.restore_register: fact for fact in artifact.facts if fact.restore_instruction_addr == _FAR_LOAD_ADDRESS}
    assert facts["si"].verdict is SegmentStackRestoreVerdict8616.PROVEN
    assert facts["si"].saved_register == "dx"
    assert facts["si"].stack_offsets == (-6, -5)
    assert facts[segment].saved_register == "ax"
    assert facts[segment].stack_offsets == (-4, -3)


def test_unknown_exact_temporary_does_not_borrow_shared_expression_proof():
    value = IRValue(MemSpace.TMP, name="expr:Iop_Or16", size=2, source_tmp=17)
    unrelated = frozenset({SegmentStackByteOrigin8616("ax", 0x1000, 0, 0)})
    assert not register_value_fragments_8616(
        value, 0x1005, {value.name: unrelated}, tracked_registers=frozenset({"ax"}),
    )
