"""Pointer escape must cover every byte of the evidenced machine operand."""

import pytest
from angr_platforms.X86_16.semantics.call_stack_effects import materialize_call_stack_effects_8616
from test_x86_16_call_stack_effects import _summary
from x86_16_logical_memory_fixtures import FUNCTION_ADDR, lift_ir_artifact_with_blocks


@pytest.mark.parametrize("source,preserved", [
    (("bp_addr", -2), False),
    (("bp_addr", 0xFFFE), False),
    (("bp_addr", 0xFFFF), False),
    (("expr", ("bp_addr", -2), (("add", 0x8000), ("add", 0x8000))), False),
    (("bp_addr", 0x10000), True),
    (("imm", 7), True),
])
def test_call_preservation_covers_logical_word_execution_bytes(source, preserved):
    artifact = lift_ir_artifact_with_blocks(bytes.fromhex("558bece8fa0f8b46fe5dc3"),
                                          (FUNCTION_ADDR, FUNCTION_ADDR + 6),
                                          ((FUNCTION_ADDR, FUNCTION_ADDR + 6),))
    summary = _summary(arg_widths=(2,), push_arg_sources=(source,), cleanup=2)
    result = materialize_call_stack_effects_8616(artifact, {FUNCTION_ADDR + 3: summary})
    effect = result.facts[0].effect
    assert effect.complete
    high = next(instruction.args[0] for block in artifact.blocks for instruction in block.instrs
                if instruction.op == "LOAD" and instruction.args[0].base == ("bp",)
                and instruction.args[0].offset == -1)
    assert effect.preserves(high) is preserved
