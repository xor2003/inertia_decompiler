"""Preserve implicit stack width and distinguish guest offsets from loader PC."""

from __future__ import annotations

import io

import angr
import pytest
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.control_coordinates import ControlAddressDomain
from unicorn import UC_ARCH_X86, UC_MODE_16, Uc
from unicorn.x86_const import UC_X86_REG_CS, UC_X86_REG_EIP, UC_X86_REG_ESP, UC_X86_REG_SS


@pytest.mark.parametrize("encoded,size,push", [("50", 2, True), ("66 50", 4, True), ("58", 2, False), ("66 58", 4, False)])
@pytest.mark.parametrize("initial_esp", [0x12348000, 0xFFFF0010])
def test_implicit_stack_update_preserves_upper_esp(encoded, size, push, initial_esp):
    project = angr.Project(
        io.BytesIO(bytes.fromhex(encoded)), auto_load_libs=False,
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000},
    )
    state = project.factory.blank_state(addr=0x1000)
    state.regs.esp, state.regs.eax, state.regs.ss = initial_esp, 0xDEADBEEF, 0x2000
    stack_address = 0x20000 + (initial_esp & 0xFFFF)
    state.memory.store(stack_address, 0x11223344, size=4, endness="Iend_LE")
    (result,) = project.factory.successors(state, num_inst=1).flat_successors
    expected_sp = ((initial_esp & 0xFFFF) + (-size if push else size)) & 0xFFFF
    assert result.solver.eval(result.regs.esp) == (initial_esp & 0xFFFF0000) | expected_sp
    if push:
        value = result.memory.load(0x20000 + expected_sp, size, endness="Iend_LE")
        assert result.solver.eval(value) == 0xDEADBEEF & ((1 << (size * 8)) - 1)
    else:
        expected_eax = 0x11223344 if size == 4 else 0xDEAD3344
        assert result.solver.eval(result.regs.eax) == expected_eax


@pytest.mark.parametrize("initial_esp", [0x12348000, 0xFFFF0010])
def test_operand32_leave_uses_bp_for_stack_and_pops_full_ebp(initial_esp):
    project = angr.Project(
        io.BytesIO(bytes.fromhex("66 c9")), auto_load_libs=False,
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000},
    )
    state = project.factory.blank_state(addr=0x1000)
    state.regs.esp, state.regs.ebp, state.regs.ss = initial_esp, 0xABCD9000, 0x2000
    state.memory.store(0x29000, 0xFEED1234, size=4, endness="Iend_LE")
    (result,) = project.factory.successors(state, num_inst=1).flat_successors
    assert result.solver.eval(result.regs.esp) == (initial_esp & 0xFFFF0000) | 0x9004
    assert result.solver.eval(result.regs.ebp) == 0xFEED1234


@pytest.mark.parametrize("far_return", [False, True], ids=["near", "far"])
@pytest.mark.parametrize("cleanup", [0, 6], ids=["plain", "argument-cleanup"])
@pytest.mark.parametrize("initial_esp", [0x12348000, 0xFFFF0010])
@pytest.mark.parametrize("domain", list(ControlAddressDomain))
def test_operand32_return_cleanup_preserves_upper_esp(
    far_return: bool, cleanup: int, initial_esp: int, domain: ControlAddressDomain,
) -> None:
    """Original RET bytes establish saved offset, selector and stack cleanup.

    The loader's PC is a loaded address; the native adapter's PC is the guest
    offset. Compare both to an independent unhooked guest, never to a shared
    production coordinate helper or an assumed literal PC.
    """
    opcode = 0xCA if far_return else 0xC2
    code = bytes((0x66, opcode, cleanup, 0))
    project = angr.Project(
        io.BytesIO(code), auto_load_libs=False,
        main_opts={
            "backend": "blob", "arch": Arch86_16(control_address_domain=domain),
            "base_addr": 0x1000, "entry_point": 0x1000,
        },
    )
    state = project.factory.blank_state(addr=0x1000)
    state.regs.esp, state.regs.ss, state.regs.cs = initial_esp, 0x2000, 0
    stack_address = 0x20000 + (initial_esp & 0xFFFF)
    state.memory.store(stack_address, 0x3000, size=4, endness="Iend_LE")
    state.memory.store(stack_address + 4, 0x400, size=4, endness="Iend_LE")

    guest = Uc(UC_ARCH_X86, UC_MODE_16)
    guest.mem_map(0, 0x100000)
    guest.mem_write(0x1000, code)
    guest.reg_write(UC_X86_REG_CS, 0)
    guest.reg_write(UC_X86_REG_SS, 0x2000)
    guest.reg_write(UC_X86_REG_ESP, initial_esp)
    guest.mem_write(stack_address, (0x3000).to_bytes(4, "little") + (0x400).to_bytes(4, "little"))
    guest.emu_start(0x1000, 0x100000, count=1)

    (result,) = project.factory.successors(state, num_inst=1).flat_successors
    frame_size = 8 if far_return else 4
    expected_sp = ((initial_esp & 0xFFFF) + frame_size + cleanup) & 0xFFFF
    assert result.solver.eval(result.regs.esp) == (initial_esp & 0xFFFF0000) | expected_sp
    assert result.solver.eval(result.regs.cs) == (0x400 if far_return else 0)
    assert result.solver.eval(result.regs.esp) == guest.reg_read(UC_X86_REG_ESP)
    assert result.solver.eval(result.regs.cs) == guest.reg_read(UC_X86_REG_CS)
    guest_offset = guest.reg_read(UC_X86_REG_EIP)
    assert guest_offset == 0x3000
    expected_pc = guest_offset
    if domain is ControlAddressDomain.LOADER_LINEAR:
        expected_pc += guest.reg_read(UC_X86_REG_CS) << 4
    assert result.solver.eval(result.regs.eip) == expected_pc
