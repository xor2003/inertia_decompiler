"""Verify architectural FLAGS ownership of x86-16 string direction."""

from __future__ import annotations

import angr
import pytest
from angr import options as o
from angr_platforms.X86_16.arch_86_16 import Arch86_16


@pytest.mark.parametrize("direction_flag", (0, 0x0400))
@pytest.mark.parametrize(
    ("code", "address_bits", "repeated"),
    (
        (bytes.fromhex("a4"), 16, False),
        (bytes.fromhex("f3a4"), 16, True),
        (bytes.fromhex("67a4"), 32, False),
        (bytes.fromhex("f367a4"), 32, True),
    ),
)
def test_movsb_uses_flags_for_single_and_repeated_address_widths(
    code: bytes,
    address_bits: int,
    repeated: bool,
    direction_flag: int,
) -> None:
    """Follow DF for the selected indices even when derived ``d`` state is stale."""
    project = angr.load_shellcode(
        code,
        arch=Arch86_16(),
        start_offset=0x100,
        load_address=0x100,
        selfmodifying_code=False,
        rebase_granularity=0x1000,
    )
    state = project.factory.blank_state(
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )
    state.regs.flags = direction_flag
    state.regs.d = 1 if direction_flag else 0xFFFFFFFF
    state.regs.ds = 0x10
    state.regs.es = 0x20
    state.memory.store(0x100, b"Q")

    if address_bits == 32:
        state.regs.esi = 0
        state.regs.edi = 0
        if repeated:
            state.regs.ecx = 2
    else:
        state.regs.si = 0
        state.regs.di = 0
        if repeated:
            state.regs.cx = 2

    simgr = project.factory.simgr(state)
    simgr.step(num_inst=1, insn_bytes=code)

    assert len(simgr.active) == 1
    result = simgr.active[0]
    assert result.solver.eval(result.memory.load(0x200, 1)) == ord("Q")
    if address_bits == 32:
        expected = 0xFFFFFFFF if direction_flag else 1
        assert result.solver.eval(result.regs.esi) == expected
        assert result.solver.eval(result.regs.edi) == expected
        if repeated:
            assert result.solver.eval(result.regs.ecx) == 1
    else:
        expected = 0xFFFF if direction_flag else 1
        assert result.solver.eval(result.regs.si) == expected
        assert result.solver.eval(result.regs.di) == expected
        if repeated:
            assert result.solver.eval(result.regs.cx) == 1
    assert result.addr == (0x100 if repeated else 0x100 + len(code))


@pytest.mark.parametrize("direction_flag", [0, 0x400])
@pytest.mark.parametrize("encoded", ["83 c0 04", "83 e8 04", "40", "31 c0", "f8", "f9", "fd", "fc"])
def test_flags_write_synchronizes_stale_direction_without_changing_df(encoded, direction_flag):
    """Status updates preserve DF; STD/CLD still change it and resync stale d."""
    code = bytes.fromhex(encoded)
    project = angr.load_shellcode(code, arch=Arch86_16(), load_address=0x100, start_offset=0x100)
    state = project.factory.blank_state(
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
    )
    state.regs.flags = direction_flag
    state.regs.d = 1 if direction_flag else 0xffffffff
    state.regs.ax = 0x7fff
    manager = project.factory.simgr(state)
    manager.step(num_inst=1, insn_bytes=code)
    assert len(manager.active) == 1
    result = manager.active[0]
    expected_df = 0x400 if encoded == "fd" else 0 if encoded == "fc" else direction_flag
    assert result.solver.eval(result.regs.flags) & 0x400 == expected_df
    assert result.solver.eval(result.regs.d) == (0xffffffff if expected_df else 1)
