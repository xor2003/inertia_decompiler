"""Saved stack bytes must survive proven loop back-edges, not unknown writes."""

import pytest
from angr_platforms.X86_16.alias.segment_stack_restore import (
    SegmentStackRestoreVerdict8616,
    build_x86_16_segment_stack_restore_artifact,
    build_x86_16_stack_register_restore_artifact_8616,
)
from angr_platforms.X86_16.ir.core import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRCallStackEffect8616,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from test_x86_16_segment_stack_restore import _lift_function, _pop_ds_ir, _push_ds_ir


@pytest.mark.parametrize("backedge_first", [False, True])
@pytest.mark.parametrize("clobber", ["none", "byte", "sp"])
def test_loop_backedge_preserves_only_unchanged_saved_stack_bytes(backedge_first, clobber):
    header, body = (0x4020, 0x4010) if backedge_first else (0x4010, 0x4020)
    instructions = ()
    if clobber == "byte":
        instructions = (IRInstr(
            "STORE", None,
            (IRAddress(MemSpace.SS, ("sp",), 1, 1, AddressStatus.STABLE, SegmentOrigin.PROVEN),
             IRValue(MemSpace.CONST, const=0, size=1)),
            addr=body,
        ),)
    elif clobber == "sp":
        instructions = (IRInstr(
            "MOV", IRValue(MemSpace.REG, name="sp", size=2),
            (IRValue(MemSpace.REG, name="sp", offset=-2, size=2),), addr=body,
        ),)
    artifact = IRFunctionArtifact(0x4000, blocks=(
        IRBlock(0x4000, instrs=_push_ds_ir(0x4000), successor_addrs=(header,)),
        IRBlock(header, successor_addrs=(body, 0x4030)),
        IRBlock(body, instrs=instructions, successor_addrs=(header,)),
        IRBlock(0x4030, instrs=_pop_ds_ir(0x4030)),
    ))

    result = build_x86_16_segment_stack_restore_artifact(artifact)

    assert len(result.facts) == 1
    fact = result.facts[0]
    if clobber == "none":
        assert fact.verdict is SegmentStackRestoreVerdict8616.PROVEN
        assert fact.saved_instruction_addr == artifact.function_addr
        assert fact.stack_offsets == (-2, -1)
    else:
        assert fact.verdict is SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE
        assert fact.saved_instruction_addr is None


def test_real_vex_loop_keeps_saved_si_identity():
    # PUSH SI; MOV CX,2; DEC CX; JNZ DEC; POP SI; RET.
    artifact = _lift_function(bytes.fromhex("56 b9 02 00 49 75 fd 5e c3"))
    result = build_x86_16_stack_register_restore_artifact_8616(
        artifact, tracked_registers=frozenset({"si"}),
    )
    facts = [fact for fact in result.facts if fact.restore_register == "si"]
    assert len(facts) == 1
    assert facts[0].verdict is SegmentStackRestoreVerdict8616.PROVEN
    assert facts[0].saved_instruction_addr == artifact.function_addr


@pytest.mark.parametrize("loop", ["", "b902004975fd"])
def test_real_vex_nested_saves_restore_their_own_registers(loop):
    # PUSH DI; PUSH SI; PUSH ES; optional loop; POP ES; POP SI; POP DI; RET.
    artifact = _lift_function(bytes.fromhex("575606" + loop + "075e5fc3"))
    result = build_x86_16_stack_register_restore_artifact_8616(
        artifact, tracked_registers=frozenset({"di", "si", "es"}),
    )
    restored = {fact.restore_register: fact for fact in result.facts}
    assert restored.keys() == {"di", "si", "es"}
    for register, save_address in (("di", 0x1000), ("si", 0x1001), ("es", 0x1002)):
        fact = restored[register]
        assert fact.verdict is SegmentStackRestoreVerdict8616.PROVEN
        assert fact.saved_register == register
        assert fact.saved_instruction_addr == save_address


@pytest.mark.parametrize("delta", [-18, 0, 4])
@pytest.mark.parametrize("complete", [False, True])
def test_proven_call_delta_preserves_saved_bytes_at_entry_coordinates(delta, complete):
    call_address = 0x4010
    effect = IRCallStackEffect8616(net_stack_delta=delta, complete=complete)
    call_push = IRInstr(
        "MOV", IRValue(MemSpace.REG, name="sp", size=2),
        (IRValue(MemSpace.REG, name="sp", offset=-2, size=2),), addr=call_address,
    )
    undo_allocation = IRInstr(
        "MOV", IRValue(MemSpace.REG, name="sp", size=2),
        (IRValue(MemSpace.REG, name="sp", offset=-delta, size=2),), addr=0x4020,
    )
    artifact = IRFunctionArtifact(0x4000, blocks=(
        IRBlock(0x4000, instrs=_push_ds_ir(0x4000), successor_addrs=(call_address,)),
        IRBlock(call_address, instrs=(
            call_push, IRInstr("CALL", None, (), addr=call_address, call_stack_effect=effect),
        ), successor_addrs=(0x4020,)),
        IRBlock(0x4020, instrs=(undo_allocation, *_pop_ds_ir(0x4021))),
    ))

    fact = build_x86_16_segment_stack_restore_artifact(artifact).facts[0]

    expected = SegmentStackRestoreVerdict8616.PROVEN if complete else SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE
    assert fact.verdict is expected
    if complete:
        assert fact.stack_offsets == (-2, -1)


def test_saves_after_allocation_use_the_adjusted_entry_coordinate():
    delta = -18
    artifact = IRFunctionArtifact(0x4000, blocks=(IRBlock(0x4000, instrs=(
        IRInstr("CALL", None, (), addr=0x4000,
                call_stack_effect=IRCallStackEffect8616(net_stack_delta=delta, complete=True)),
        *_push_ds_ir(0x4003), *_pop_ds_ir(0x4004),
    )),))

    fact = build_x86_16_segment_stack_restore_artifact(artifact).facts[0]

    assert fact.verdict is SegmentStackRestoreVerdict8616.PROVEN
    assert fact.stack_offsets == (delta - 2, delta - 1)


def test_known_call_delta_does_not_invent_an_unknown_entry_sp():
    artifact = IRFunctionArtifact(0x4000, blocks=(IRBlock(0x4000, instrs=(
        IRInstr("MOV", IRValue(MemSpace.REG, name="sp", size=2),
                (IRValue(MemSpace.REG, name="dx", size=2),), addr=0x4000),
        IRInstr("CALL", None, (), addr=0x4003,
                call_stack_effect=IRCallStackEffect8616(net_stack_delta=-18, complete=True)),
        *_push_ds_ir(0x4006), *_pop_ds_ir(0x4007),
    )),))

    fact = build_x86_16_segment_stack_restore_artifact(artifact).facts[0]

    assert fact.verdict is SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE
