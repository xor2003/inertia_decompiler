"""Frame access widths must follow machine operands, not execution bytes."""

from dataclasses import replace

import pytest
from angr_platforms.X86_16.analysis.stack_frame_ir import build_x86_16_ir_frame_access_artifact
from x86_16_logical_memory_fixtures import lift_ir_artifact


def test_frame_keeps_the_logical_word_width_of_a_bp_load():
    artifact = lift_ir_artifact(bytes.fromhex("558bec8b46fe5dc3"))
    frame = build_x86_16_ir_frame_access_artifact(artifact)
    bp_slots = {(slot.offset, slot.size) for slot in frame.slots if slot.base == "bp"}
    assert bp_slots == {(-2, 2)}


@pytest.mark.parametrize("code,expected", [
    ("558bec8a46fe8a66ff5dc3", {(-2, 1), (-1, 1)}),
    ("558bec8b46fe8a46ff5dc3", {(-2, 2), (-1, 1)}),
])
def test_independent_byte_operands_remain_independent(code, expected):
    frame = build_x86_16_ir_frame_access_artifact(lift_ir_artifact(bytes.fromhex(code)))
    assert {(slot.offset, slot.size) for slot in frame.slots if slot.base == "bp"} == expected


@pytest.mark.parametrize("mutation", ("missing", "foreign", "incomplete", "stale"))
def test_unproven_logical_bindings_retain_raw_byte_accesses(mutation):
    artifact = lift_ir_artifact(bytes.fromhex("558bec8b46fe5dc3"))
    logical = artifact.logical_memory
    assert logical is not None
    if mutation == "missing":
        artifact = replace(artifact, logical_memory=None)
    elif mutation == "foreign":
        artifact = replace(artifact, logical_memory=replace(logical, function_addr=0))
    elif mutation == "incomplete":
        artifact = replace(artifact, logical_memory=replace(logical, accesses=()))
    else:
        access = next(access for access in logical.accesses if access.address.base == ("bp",))
        part = access.execution_slices[0]
        block = artifact.blocks[0]
        instructions = list(block.instrs)
        instructions[part.instr_index] = replace(instructions[part.instr_index], addr=0)
        artifact = replace(artifact, blocks=(replace(block, instrs=tuple(instructions)),))
    frame = build_x86_16_ir_frame_access_artifact(artifact)
    assert {(slot.offset, slot.size) for slot in frame.slots if slot.base == "bp"} == {(-2, 1), (-1, 1)}
