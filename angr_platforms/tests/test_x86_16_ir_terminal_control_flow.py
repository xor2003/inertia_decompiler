"""Preserve proven return control flow independently of return-value recovery."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.alias.segment_stack_restore import (
    SegmentStackRestoreVerdict8616,
    build_x86_16_stack_register_restore_artifact_8616,
)
from angr_platforms.X86_16.ir.core import MemSpace
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa
from angr_platforms.X86_16.ir.vex_control_flow import terminal_control_flow_instr_8616
from x86_16_logical_memory_fixtures import FUNCTION_ADDR, lift_ir_artifact, lift_ir_artifact_with_blocks


def test_return_marker_does_not_require_a_constant_destination():
    terminal = terminal_control_flow_instr_8616(SimpleNamespace(jumpkind="Ijk_Ret", next=object()), FUNCTION_ADDR)
    assert terminal is not None
    assert terminal.op == "RET"
    assert terminal.addr == FUNCTION_ADDR
    assert terminal.dst is None
    assert terminal.args == ()


@pytest.mark.parametrize("jumpkind", ("Ijk_Boring", "Ijk_NoDecode", "Ijk_Sys_int128"))
def test_nonreturn_terminal_is_not_invented_from_an_unknown_destination(jumpkind):
    assert terminal_control_flow_instr_8616(SimpleNamespace(jumpkind=jumpkind, next=object()), FUNCTION_ADDR) is None


def test_constant_call_target_remains_explicit():
    target = FUNCTION_ADDR + 0x20
    vex = SimpleNamespace(jumpkind="Ijk_Call", next=SimpleNamespace(con=SimpleNamespace(value=target)))
    terminal = terminal_control_flow_instr_8616(vex, FUNCTION_ADDR)
    assert terminal is not None
    assert terminal.op == "CALL"
    assert terminal.args[0].const == target


def test_unknown_call_target_does_not_erase_the_call_boundary():
    vex = SimpleNamespace(jumpkind="Ijk_Call", next=object())
    terminal = terminal_control_flow_instr_8616(vex, FUNCTION_ADDR)
    assert terminal is not None
    assert terminal.op == "CALL"
    assert terminal.addr == FUNCTION_ADDR
    assert terminal.args[0].space is MemSpace.UNKNOWN
    assert terminal.call_stack_effect is None


@pytest.mark.parametrize("encoding", ["ffd0", "ff5604", "66ffd0"])
def test_indirect_binary_call_keeps_target_provenance_in_ir_and_ssa(encoding):
    artifact = lift_ir_artifact(bytes.fromhex(encoding))
    ssa = build_x86_16_function_ssa(artifact)
    for block in (artifact.blocks[0], ssa.blocks[0]):
        terminal = block.instrs[-1]
        assert terminal.op == "CALL"
        assert terminal.addr == FUNCTION_ADDR
        assert terminal.args[0].space is not MemSpace.CONST
        assert terminal.args[0].source_tmp is not None


def test_unknown_indirect_call_refuses_false_stack_restore_proof():
    # PUSH SI; PUSH AX; CALL BX; ADD SP,2; POP SI; RET.
    continuation = FUNCTION_ADDR + 4
    artifact = lift_ir_artifact_with_blocks(
        bytes.fromhex("5650ffd383c4025ec3"),
        (FUNCTION_ADDR, continuation), ((FUNCTION_ADDR, continuation),),
    )
    corrupted = replace(artifact, blocks=tuple(
        replace(block, instrs=tuple(instruction for instruction in block.instrs if instruction.op != "CALL"))
        for block in artifact.blocks
    ))
    for candidate, missing_call in ((artifact, False), (corrupted, True)):
        result = build_x86_16_stack_register_restore_artifact_8616(
            candidate, tracked_registers=frozenset({"si", "ax"}),
        )
        false_restore = any(
            fact.restore_register == "si" and fact.saved_register == "ax"
            and fact.verdict is SegmentStackRestoreVerdict8616.PROVEN
            for fact in result.facts
        )
        assert false_restore is missing_call


def test_binary_return_marker_survives_ir_and_ssa_projection():
    code = bytes.fromhex("558bec83ec048be55dc3")
    artifact = lift_ir_artifact(code)
    ssa = build_x86_16_function_ssa(artifact)
    for block in (artifact.blocks[0], ssa.blocks[0]):
        assert block.instrs[-1].op == "RET"
        assert block.instrs[-1].addr == FUNCTION_ADDR + len(code) - 1
