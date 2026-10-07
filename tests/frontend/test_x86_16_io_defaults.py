from __future__ import annotations

import contextlib

import angr
from angr import options as o
from inertia.frontend.x86_16.arch_86_16 import Arch86_16


def _run_one_instruction_local(arch, code: bytes, ax: int = 0x125A, di: int = 0x200):
    project = angr.load_shellcode(
        code,
        arch=arch,
        start_offset=0x100,
        load_address=0x100,
        selfmodifying_code=False,
        rebase_granularity=0x1000,
    )
    state = project.factory.blank_state(
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )
    state.regs.ax = ax
    state.regs.es = 0
    with contextlib.suppress(AttributeError):
        state.regs.di = di
    with contextlib.suppress(AttributeError):
        state.regs.edi = di

    simgr = project.factory.simgr(state)
    simgr.step(num_inst=1, insn_bytes=code)
    assert len(simgr.active) == 1
    return simgr.active[0]


def test_insb_default_writes_ff_and_advances_di():
    state = _run_one_instruction_local(Arch86_16(), b"\x6c", ax=0, di=0x200)
    assert state.solver.eval(state.regs.di) == 0x201
    assert state.solver.eval(state.memory.load(0x200, 1)) == 0xFF


def test_insw_default_writes_ffff_and_advances_di():
    state = _run_one_instruction_local(Arch86_16(), b"\x6d", ax=0, di=0x200)
    assert state.solver.eval(state.regs.di) == 0x202
    assert state.solver.eval(state.memory.load(0x200, 2)) == 0xFFFF


def test_in_al_imm8_defaults_to_ff():
    # IN AL, imm8 -> opcode E4 imm8
    state = _run_one_instruction_local(Arch86_16(), b"\xe4\x40", ax=0)
    # AL may be part of AX; check low byte
    try:
        val = state.solver.eval(state.regs.al)
    except Exception:
        val = state.solver.eval(state.regs.ax & 0xFF)
    assert val == 0xFF
