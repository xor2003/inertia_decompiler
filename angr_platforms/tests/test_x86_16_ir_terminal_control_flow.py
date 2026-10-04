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
from angr_platforms.X86_16.ir.vex_terminal_jump import (
    TerminalJumpRefusalReason8616,
    terminal_direct_jump_evidence_8616,
)
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


@pytest.mark.parametrize("encoding", ("eb00", "e90000"))
def test_effectless_direct_jump_retains_its_instruction_and_target(encoding):
    """A VEX terminal jump remains an exact IR instruction, not just a CFG edge."""
    code = bytes.fromhex(encoding + "c3")
    continuation = FUNCTION_ADDR + len(bytes.fromhex(encoding))
    artifact = lift_ir_artifact_with_blocks(code, (FUNCTION_ADDR, continuation), ((FUNCTION_ADDR, continuation),))
    assert artifact.blocks[0].instrs, "the exact terminal jump instruction disappeared"
    jump = artifact.blocks[0].instrs[-1]
    assert jump.op == "JMP"
    assert jump.addr == FUNCTION_ADDR
    assert jump.args[0].space is MemSpace.CONST
    assert jump.args[0].const == continuation
    assert artifact.blocks[0].successor_addrs == (continuation,)


def test_terminal_jump_after_earlier_effects_keeps_its_own_address() -> None:
    """Retention comes from decoded bytes, so an earlier NOP does not hide it."""
    target = FUNCTION_ADDR + 4
    artifact = lift_ir_artifact_with_blocks(
        bytes.fromhex("90eb0190c3"), (FUNCTION_ADDR, target), ((FUNCTION_ADDR, target),),
    )
    block = artifact.blocks[0]
    jump = block.instrs[-1]
    assert jump.op == "JMP"
    assert jump.addr == FUNCTION_ADDR + 1
    assert jump.args[0].space is MemSpace.CONST
    assert jump.args[0].const == target
    assert block.successor_addrs == (target,)


def test_backward_direct_jump_keeps_symbolic_target_and_typed_refusal() -> None:
    """A target outside every fetch window stays symbolic, never guessed."""
    artifact = lift_ir_artifact(bytes.fromhex("eb80"))
    block = artifact.blocks[0]
    jump = block.instrs[-1]
    assert jump.op == "JMP"
    assert jump.addr == FUNCTION_ADDR
    assert jump.args[0].space is not MemSpace.CONST
    assert block.successor_addrs == ()
    assert any(
        refusal.kind
        == TerminalJumpRefusalReason8616.SELECTOR_WINDOW_UNPROVED.value
        for refusal in block.refusals
    )


def test_terminal_noop_fallthrough_does_not_invent_a_jump() -> None:
    """An ordinary fallthrough tail must not gain a synthetic transfer."""
    artifact = lift_ir_artifact(bytes.fromhex("90"))
    block = artifact.blocks[0]
    assert all(instr.op != "JMP" for instr in block.instrs)
    assert block.refusals == ()


def test_conditional_relative_terminal_is_never_flattened_to_a_jump() -> None:
    """A conditional near edge keeps its live Exit, not an unconditional JMP."""
    artifact = lift_ir_artifact_with_blocks(
        bytes.fromhex("e300c3"),
        (FUNCTION_ADDR, FUNCTION_ADDR + 2, FUNCTION_ADDR + 3),
        ((FUNCTION_ADDR, FUNCTION_ADDR + 2), (FUNCTION_ADDR, FUNCTION_ADDR + 3)),
    )
    block = artifact.blocks[0]
    assert block.instrs
    assert all(instr.op != "JMP" for instr in block.instrs)


def test_terminal_jump_evidence_refuses_a_conflicting_constant_next() -> None:
    """A literal ``next`` disagreeing with decoded bytes is a typed refusal."""
    block = SimpleNamespace(addr=FUNCTION_ADDR, size=2, bytes=b"\xeb\x00")
    vex = SimpleNamespace(
        jumpkind="Ijk_Boring",
        next=SimpleNamespace(con=SimpleNamespace(value=0x9999)),
    )
    evidence = terminal_direct_jump_evidence_8616(
        block, vex,
        instruction_addr=FUNCTION_ADDR, instruction_size=2, tmp_exprs={},
    )
    assert evidence.retain
    assert evidence.proven_target is None
    assert evidence.failure is TerminalJumpRefusalReason8616.CONSTANT_CONFLICT
    assert evidence.stats.closed


def test_terminal_jump_evidence_rejects_non_terminal_and_non_jump_bytes() -> None:
    """Non-tail extents and non-jump terminals never produce a retained jump."""
    vex = SimpleNamespace(
        jumpkind="Ijk_Boring",
        next=SimpleNamespace(con=SimpleNamespace(value=FUNCTION_ADDR + 3)),
    )
    not_tail = terminal_direct_jump_evidence_8616(
        SimpleNamespace(addr=FUNCTION_ADDR, size=3, bytes=b"\xeb\x00\x90"),
        vex,
        instruction_addr=FUNCTION_ADDR, instruction_size=2, tmp_exprs={},
    )
    not_jump = terminal_direct_jump_evidence_8616(
        SimpleNamespace(addr=FUNCTION_ADDR, size=1, bytes=b"\x90"),
        vex,
        instruction_addr=FUNCTION_ADDR, instruction_size=1, tmp_exprs={},
    )
    conditional = terminal_direct_jump_evidence_8616(
        SimpleNamespace(addr=FUNCTION_ADDR, size=2, bytes=b"\xe3\x00"),
        vex,
        instruction_addr=FUNCTION_ADDR, instruction_size=2, tmp_exprs={},
    )
    far = terminal_direct_jump_evidence_8616(
        SimpleNamespace(addr=FUNCTION_ADDR, size=5, bytes=b"\xea\x00\x00\x00\x00"),
        vex,
        instruction_addr=FUNCTION_ADDR, instruction_size=5, tmp_exprs={},
    )
    for evidence in (not_tail, not_jump, conditional, far):
        assert not evidence.retain
        assert evidence.proven_target is None
        assert evidence.failure is None


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
