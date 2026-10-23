"""Guarded helper identity must invalidate, not project, native SP state."""
from types import SimpleNamespace

import pytest

import inertia.frontend.x86_16.stack_tracker_allocation as consumer
from inertia.ir import IRBlock, IRInstr, IRValue, MemSpace


@pytest.mark.parametrize("allocation_size", [None, 0, 18, 32])
def test_native_consumer_keeps_guarded_call_and_refuses_sp(monkeypatch, allocation_size):
    """Even a returning failure tail cannot make prefix identity authoritative."""
    helper = bytes.fromhex("59 8b dc 2b d8 72 0a 3b 1e ec 00 72 04 8b e3 ff e1 bd ef be ff e1")
    puts = []
    call = IRInstr("CALL", None, (IRValue(MemSpace.CONST, const=0x206a, size=2),), addr=0x1003)
    writes = (() if allocation_size is None else (IRInstr(
        "MOV", IRValue(MemSpace.REG, name="ax", size=2),
        (IRValue(MemSpace.CONST, const=allocation_size, size=2),), size=2, addr=0x1000,
    ),))
    block = IRBlock(0x1000, (*writes, call))
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16", sp_offset=16),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda _addr, size: helper[:size])),
    )
    tracker = SimpleNamespace(project=project, reg_offsets={16})
    state = SimpleNamespace(put=lambda offset, value, *, force: puts.append((offset, value, force)))
    vex = SimpleNamespace(addr=0x1000, jumpkind="Ijk_Call")
    monkeypatch.setattr(consumer, "_bound_terminal_direct_call_8616", lambda *_: (block, call, 0x206a))
    consumer._apply_allocation(tracker, vex, state, 0x1003)
    assert puts == [(16, None, True)]
    assert block.instrs[-1] is call


def test_native_consumer_leaves_ordinary_call_sp_intact(monkeypatch):
    """An ordinary return opcode does not become a guarded allocation."""
    puts = []
    call = IRInstr("CALL", None, (IRValue(MemSpace.CONST, const=0x206a, size=2),), addr=0x1003)
    block = IRBlock(0x1000, (call,))
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16", sp_offset=16),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda _addr, _size: b"\xc3")),
    )
    tracker = SimpleNamespace(project=project, reg_offsets={16})
    state = SimpleNamespace(put=lambda offset, value, *, force: puts.append((offset, value, force)))
    monkeypatch.setattr(consumer, "_bound_terminal_direct_call_8616", lambda *_: (block, call, 0x206a))
    consumer._apply_allocation(tracker, SimpleNamespace(addr=0x1000, jumpkind="Ijk_Call"), state, 0x1003)
    assert puts == []
