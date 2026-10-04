from __future__ import annotations

from dataclasses import replace

import pytest
from angr_platforms.X86_16.ir.core import IRInstr, IRValue, MemSpace
from angr_platforms.X86_16.ir.logical_constant_word_receipt import (
    LogicalConstantWordFailure8616,
    prove_logical_constant_word_write_8616,
)
from angr_platforms.X86_16.ir.logical_memory_contracts import IRMemoryAccessKind8616
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa
from x86_16_logical_memory_fixtures import lift_ir_artifact


@pytest.mark.parametrize("code,expected", (
    ("b8 03 00 50 c3", 3),
    ("b8 00 00 50 c3", 0),
    ("b8 ff ff 50 c3", 0xFFFF),
    ("b8 03 00 90 50 c3", 3),
    ("b8 03 00 b0 07 50 c3", 7),
    ("b8 03 00 b4 01 50 c3", 0x103),
    ("66 b8 03 00 02 00 50 c3", 3),
))
def test_binary_word_receipt_retains_current_register_bits(code: str, expected: int) -> None:
    """Prefix replay must prove the actual STORE value, not an old AX root."""
    artifact = build_x86_16_function_ssa(lift_ir_artifact(bytes.fromhex(code)))
    memory = artifact.logical_memory
    assert memory is not None
    access = next(access for access in memory.accesses
                  if access.kind is IRMemoryAccessKind8616.WRITE and access.address.size == 2)
    receipt = prove_logical_constant_word_write_8616(artifact, access)
    assert receipt.complete and receipt.constant == expected
    assert receipt.lane_values == (expected & 0xFF, expected >> 8)
    assert receipt.matches_access(access)
    assert not receipt.matches_access(replace(access))
    assert not replace(receipt, constant=(expected + 1) & 0xFFFF).complete
    assert not replace(receipt, constant=bool(expected)).complete
    assert not replace(receipt, lane_values=None).complete
    assert not replace(receipt, block=None).complete
    assert not replace(receipt, stats=replace(receipt.stats, materialized_count=0)).complete
    assert (receipt.stats.raw_fact_count, receipt.stats.normalized_fact_count,
            receipt.stats.classified_fact_count, receipt.stats.materialized_count,
            receipt.stats.failure_count) == (1, 1, 1, 1, 0)
    foreign = prove_logical_constant_word_write_8616(artifact, replace(access))
    assert not foreign.complete and foreign.failure is LogicalConstantWordFailure8616.FOREIGN_ACCESS


@pytest.mark.parametrize("after_capture", (False, True))
def test_call_invalidates_live_register_but_not_earned_capture(after_capture: bool) -> None:
    """A corrupted CALL distinguishes live AX from a prior immutable GET."""
    artifact = build_x86_16_function_ssa(lift_ir_artifact(bytes.fromhex("b8 03 00 50 c3")))
    block = artifact.blocks[0]
    capture = next(index for index, instruction in enumerate(block.instrs)
                   if instruction.dst is not None and instruction.dst.space is MemSpace.TMP
                   and instruction.op == "MOV" and len(instruction.args) == 1
                   and isinstance(instruction.args[0], IRValue)
                   and instruction.args[0].space is MemSpace.REG and instruction.args[0].name == "ax")
    insertion = capture + int(after_capture)
    call = IRInstr("CALL", IRValue(MemSpace.CONST, const=0x2000, size=2),
                   (IRValue(MemSpace.CONST, const=0x2000, size=2),), addr=0x1002)
    instructions = (*block.instrs[:insertion], call, *block.instrs[insertion:])
    memory = artifact.logical_memory
    assert memory is not None
    access = next(access for access in memory.accesses
                  if access.kind is IRMemoryAccessKind8616.WRITE and access.address.size == 2)
    shifted = replace(access, execution_slices=tuple(
        replace(lane, instr_index=lane.instr_index + int(lane.instr_index >= insertion))
        for lane in access.execution_slices
    ))
    source = replace(artifact, blocks=(replace(block, instrs=instructions),),
                     logical_memory=replace(memory, accesses=tuple(
                         shifted if candidate is access else candidate for candidate in memory.accesses)))
    receipt = prove_logical_constant_word_write_8616(source, shifted)
    if after_capture:
        assert receipt.complete and receipt.constant == 3
    else:
        assert not receipt.complete and receipt.failure is LogicalConstantWordFailure8616.VALUE_UNKNOWN
        assert receipt.constant is None and receipt.stats.failure_count == 1


def test_word_receipt_rejects_changed_source_prefix() -> None:
    """A retained receipt cannot survive a changed defining instruction."""
    artifact = build_x86_16_function_ssa(lift_ir_artifact(bytes.fromhex("b8 03 00 50 c3")))
    memory = artifact.logical_memory
    assert memory is not None
    access = next(access for access in memory.accesses
                  if access.kind is IRMemoryAccessKind8616.WRITE and access.address.size == 2)
    receipt = prove_logical_constant_word_write_8616(artifact, access)
    assert receipt.complete and receipt.constant == 3
    block = artifact.blocks[0]
    definition = next(index for index, instruction in enumerate(block.instrs)
                      if instruction.dst is not None and instruction.dst.space is MemSpace.REG
                      and instruction.dst.name == "ax" and instruction.op == "MOV"
                      and len(instruction.args) == 1
                      and isinstance(instruction.args[0], IRValue)
                      and instruction.args[0].space is MemSpace.CONST)
    changed = replace(block.instrs[definition],
                      args=(IRValue(MemSpace.CONST, const=4, size=2),))
    changed_block = replace(block, instrs=(*block.instrs[:definition], changed,
                                          *block.instrs[definition + 1:]))
    changed_artifact = replace(artifact, blocks=(changed_block,))
    assert not replace(receipt, artifact=changed_artifact).complete
    refreshed = prove_logical_constant_word_write_8616(changed_artifact, access)
    assert refreshed.complete and refreshed.constant == 4
