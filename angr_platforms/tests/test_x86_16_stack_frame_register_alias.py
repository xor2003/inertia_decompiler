"""Prove frame-relative stores against saved-register byte identities."""

from dataclasses import replace

import pytest
from angr_platforms.X86_16.alias.segment_stack_restore import (
    SegmentStackRestoreVerdict8616,
    build_x86_16_stack_register_restore_artifact_8616,
)
from angr_platforms.X86_16.alias.stack_pointer_snapshots import StackPointerSnapshots8616
from angr_platforms.X86_16.alias.stack_restore_state import (
    StackRestoreState8616,
    join_stack_restore_states_8616,
)
from angr_platforms.X86_16.ir import IRAddress, IRCallStackEffect8616, IRInstr, IRValue, MemSpace
from test_x86_16_segment_stack_restore import _lift_function

_DI_SAVE_DISPLACEMENT = 0xEC


@pytest.mark.parametrize("store_offset", [0xFE, 0xEC])
def test_native_bp_store_preserves_only_disjoint_saved_registers(store_offset):
    # PUSH BP; MOV BP,SP; SUB SP,18; PUSH DI; PUSH SI; STORE; POP SI/DI;
    # MOV SP,BP; POP BP; RET. BP-20 aliases DI; BP-2 is a disjoint local.
    code = bytes.fromhex("55 8b ec 83 ec 12 57 56 c6 46")
    code += bytes((store_offset, 0)) + bytes.fromhex("5e 5f 8b e5 5d c3")
    artifact = _lift_function(code)
    result = build_x86_16_stack_register_restore_artifact_8616(
        artifact, tracked_registers=frozenset({"di", "si"}),
    )
    restored = {fact.restore_register: fact for fact in result.facts}

    assert restored["si"].verdict is SegmentStackRestoreVerdict8616.PROVEN
    assert restored["si"].stack_offsets == (-24, -23)
    expected_di = (SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE
                   if store_offset == _DI_SAVE_DISPLACEMENT else SegmentStackRestoreVerdict8616.PROVEN)
    assert restored["di"].verdict is expected_di


@pytest.mark.parametrize("bp_preserved", [False, True])
def test_call_requires_a_bp_proof_before_later_frame_stores(bp_preserved):
    code = bytes.fromhex("55 8b ec 83 ec 12 57 56 e8 0a 00 c6 46 fe 00 5e 5f 8b e5 5d c3 c3")
    artifact = _lift_function(code)
    effect = IRCallStackEffect8616(net_stack_delta=0, complete=True, bp_preserved=bp_preserved)
    artifact = replace(artifact, blocks=tuple(
        replace(block, instrs=tuple(
            replace(instruction, call_stack_effect=effect) if instruction.op == "CALL" else instruction
            for instruction in block.instrs
        )) for block in artifact.blocks
    ))

    result = build_x86_16_stack_register_restore_artifact_8616(
        artifact, tracked_registers=frozenset({"si", "di"}),
    )

    assert result.facts
    expected = SegmentStackRestoreVerdict8616.PROVEN if bp_preserved else SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE
    assert all(fact.verdict is expected for fact in result.facts)


@pytest.mark.parametrize("clobber", ["66 bd 34 12 00 00", "66 bc 34 12 00 00"])
def test_full_parent_register_clobber_invalidates_frame_coordinates(clobber):
    code = bytes.fromhex("55 8b ec 83 ec 12 57 56 " + clobber + " c6 46 fe 00 5e 5f 8b e5 5d c3")
    result = build_x86_16_stack_register_restore_artifact_8616(
        _lift_function(code), tracked_registers=frozenset({"si", "di"}),
    )

    assert result.facts
    assert all(fact.verdict is SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE for fact in result.facts)


@pytest.mark.parametrize("other_bp", [-2, 0, None])
def test_bp_join_requires_identical_incoming_coordinates(other_bp):
    first = StackRestoreState8616(-24, bp_delta=-2)
    second = StackRestoreState8616(-24, bp_delta=other_bp)

    joined = join_stack_restore_states_8616((first, second))

    assert joined.sp_delta == first.sp_delta
    assert joined.bp_delta == (first.bp_delta if other_bp == first.bp_delta else None)


def test_bp_capture_is_not_reinterpreted_after_register_changes():
    snapshots = StackPointerSnapshots8616()
    read = IRInstr("MOV", IRValue(MemSpace.TMP, name="t0", size=2, source_tmp=0),
                   (IRValue(MemSpace.REG, name="bp", size=2),))
    original_bp = -2
    snapshots.observe(read, -24, original_bp)
    address = IRAddress(MemSpace.SS, ("bp",), base_values=(
        IRValue(MemSpace.REG, name="bp", size=2, source_tmp=0),
    ))

    base = snapshots.address_base(address, 0, 0)

    assert base is not None
    assert base.register == "bp"
    assert base.entry_sp_offset == original_bp
    missing = replace(address, base_values=(replace(address.base_values[0], source_tmp=9),))
    assert snapshots.address_base(missing, 0, 0) is None


def test_computed_capture_does_not_use_current_sp_or_add_its_offset_twice():
    snapshots = StackPointerSnapshots8616()
    snapshots.observe(IRInstr(
        "MOV", IRValue(MemSpace.TMP, name="t0", size=2, source_tmp=0),
        (IRValue(MemSpace.REG, name="sp", size=2),),
    ), -24)
    snapshots.observe(IRInstr(
        "Iop_Sub16", IRValue(MemSpace.TMP, name="t1", size=2, source_tmp=1),
        (IRValue(MemSpace.REG, name="sp", size=2, source_tmp=0),
         IRValue(MemSpace.CONST, const=2, size=2)),
    ), -4)
    write = IRInstr("MOV", IRValue(MemSpace.REG, name="sp", size=2), (
        IRValue(MemSpace.REG, name="sp", size=2, source_tmp=1, offset=-2, expr=("Iop_Sub16",)),
    ))

    expected = -26
    assert snapshots.updated_register("sp", write, -4, None) == expected


def test_unproven_frame_expression_is_not_a_register_identity():
    write = IRInstr("MOV", IRValue(MemSpace.REG, name="sp", size=2), (
        IRValue(MemSpace.REG, name="sp", size=2, expr=("Iop_And16",)),
    ))

    assert StackPointerSnapshots8616().updated_register("sp", write, -4, None) is None


@pytest.mark.parametrize("register", ["sp", "bp"])
@pytest.mark.parametrize("size,expression,source_tmp", [
    (2, ("Iop_And16",), None), (1, (), None), (1, (), 0),
])
def test_address_base_requires_a_complete_proven_frame_value(register, size, expression, source_tmp):
    snapshots = StackPointerSnapshots8616(offsets={0: -2})
    address = IRAddress(MemSpace.SS, (register,), base_values=(
        IRValue(MemSpace.REG, name=register, size=size, expr=expression, source_tmp=source_tmp),
    ))

    assert snapshots.address_base(address, -24, -2) is None
