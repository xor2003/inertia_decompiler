"""General word-register copies preserve only must-proven stack coordinates."""

from dataclasses import replace

import pytest

from inertia.alias.segment_stack_restore import _transfer_block
from inertia.alias.stack_pointer_snapshots import StackPointerSnapshots8616
from inertia.alias.stack_restore_state import StackRestoreState8616, join_stack_restore_states_8616
from inertia.ir.core import IRInstr, IRValue, MemSpace


def _reg(name, size=2):
    return IRValue(space=MemSpace.REG, name=name, size=size)


def _mov(dst, source, addr=0x1000):
    return IRInstr(op="MOV", dst=dst, args=(source,), addr=addr)


@pytest.mark.parametrize("register", ["ax", "bx", "cx", "dx", "si", "di"])
def test_word_register_retains_captured_sp(register):
    snapshots = StackPointerSnapshots8616()
    snapshots.observe(_mov(_reg(register), _reg("sp")), -6, None)
    assert snapshots.value_offset(_reg(register), 4, None) == -6
    assert snapshots.updated_register("sp", _mov(_reg("sp"), _reg(register)), 4, None) == -6


@pytest.mark.parametrize("name,size", [("bl", 1), ("bh", 1), ("bx", 1), ("ebx", 4), ("bx", 8)])
def test_overlapping_write_invalidates_word_coordinate(name, size):
    snapshots = StackPointerSnapshots8616()
    snapshots.observe(_mov(_reg("bx"), _reg("sp")), -6, None)
    snapshots.observe(_mov(_reg(name, size), IRValue(space=MemSpace.CONST, const=0, size=size)), -6, None)
    assert snapshots.value_offset(_reg("bx"), -6, None) is None


def test_unsupported_register_write_refuses():
    snapshots = StackPointerSnapshots8616()
    snapshots.observe(_mov(_reg("bx"), _reg("sp")), -6, None)
    snapshots.observe(IRInstr(op="OPAQUE", dst=_reg("bx"), args=(), addr=0x1001), -6, None)
    assert snapshots.value_offset(_reg("bx"), -6, None) is None


@pytest.mark.parametrize("other", [(), (("bx", 4),)])
def test_join_discards_missing_or_disagreeing_coordinate(other):
    first = StackRestoreState8616(0, register_offsets=(("bx", -6),))
    joined = join_stack_restore_states_8616((first, replace(first, register_offsets=other)))
    assert joined.register_offset_map() == {}


def test_join_keeps_common_coordinate_and_copies_state():
    first = StackRestoreState8616(0, register_offsets=(("bx", -6),))
    joined = join_stack_restore_states_8616((first, first))
    mutable = joined.register_offset_map()
    assert mutable == {"bx": -6}
    mutable.clear()
    assert joined.register_offset_map() == {"bx": -6}


def test_unknown_call_cannot_preserve_a_general_register_coordinate():
    instructions = (
        _mov(_reg("bx"), _reg("sp")),
        IRInstr(op="CALL", dst=None, args=(IRValue(space=MemSpace.CONST, const=0x2000, size=2),), addr=0x1002),
        _mov(_reg("sp"), _reg("bx"), 0x1005),
    )
    _facts, state = _transfer_block(0x1000, instructions, StackRestoreState8616(0))
    assert state.sp_delta is None
    assert state.register_offset_map() == {}


@pytest.mark.parametrize("decoration", [{"offset": 1}, {"size": 4}, {"version": 3}, {"expr": ("OPAQUE",)}, {"index_shift": 1}])
def test_decorated_register_read_cannot_borrow_a_live_coordinate(decoration):
    snapshots = StackPointerSnapshots8616()
    snapshots.observe(_mov(_reg("bx"), _reg("sp")), -6, None)
    assert snapshots.value_offset(replace(_reg("bx"), **decoration), -6, None) is None


@pytest.mark.parametrize("decoration", [{"offset": 1}, {"size": 4}, {"version": 3}, {"expr": ("OPAQUE",)}, {"index_shift": 1}])
def test_decorated_register_write_invalidates_the_live_coordinate(decoration):
    snapshots = StackPointerSnapshots8616()
    snapshots.observe(_mov(_reg("bx"), _reg("sp")), -6, None)
    snapshots.observe(_mov(replace(_reg("bx"), **decoration), _reg("sp")), -6, None)
    assert snapshots.value_offset(_reg("bx"), -6, None) is None


@pytest.mark.parametrize("op", ["CALL", "INT", "INTERRUPT", "SYSCALL"])
def test_snapshot_api_invalidates_general_registers_at_external_effects(op):
    snapshots = StackPointerSnapshots8616()
    snapshots.observe(_mov(_reg("bx"), _reg("sp")), -6, None)
    snapshots.observe(IRInstr(op=op, dst=None, args=(), addr=0x1002), -6, None)
    assert snapshots.value_offset(_reg("bx"), -6, None) is None
