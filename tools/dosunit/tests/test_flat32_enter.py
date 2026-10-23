"""Byte-backed ENTER lifting agrees with native execution and symbolic controls."""

from pathlib import Path

import angr
import pytest
import unicorn
from unicorn import x86_const

from tools.dosunit.architectures.flat32_loader import load_flat32_project
from tools.dosunit.tests.test_flat32_comparator_lane import BASE, _compare_calls, _driver_lane
from tools.dosunit.tests.test_flat32_loaded_byte_boundaries import pe32_bytes

pytestmark = pytest.mark.ssa_z3


def _project(tmp_path: Path, code: bytes):
    path = tmp_path / "enter.exe"
    path.write_bytes(pe32_bytes(code))
    project = load_flat32_project(path)
    entry = next(section.min_addr for section in project.loader.main_object.sections if section.is_executable)
    return project, entry


def test_pe_loader_decodes_enter(tmp_path: Path) -> None:
    project, entry = _project(tmp_path, bytes.fromhex("c8000000c9c3"))
    irsb = project.factory.block(entry, num_inst=1, opt_level=0).vex
    assert irsb.size == 4
    assert irsb.jumpkind == "Ijk_Boring"


@pytest.mark.parametrize("allocation,nesting", [(0, 0), (0x1234, 0), (32, 1), (16, 2), (16, 31), (16, 0xE2)])
@pytest.mark.parametrize("alias_frame", [False, True])
def test_enter_matches_native_stack_and_flags(tmp_path: Path, allocation: int, nesting: int, alias_frame: bool) -> None:
    """Aliased display reads observe prior pushes, with unchanged flags and GPRs."""
    code = b"\xc8" + allocation.to_bytes(2, "little") + bytes([nesting])
    project, entry = _project(tmp_path, code + b"\xc3")
    assert project.factory.block(entry, num_inst=1, opt_level=0).vex.size == 4
    stack_base, stack_size, esp = 0x200000, 0x4000, 0x202000
    initial_memory = bytes((index * 37 + 11) & 255 for index in range(stack_size))
    registers = {"eax": 0x12345678, "ebx": 0x13579BDF, "ecx": 0x2468ACE0,
                 "edx": 0x76543210, "esi": 0x11112222, "edi": 0x33334444,
                 "esp": esp, "ebp": esp - 4 if alias_frame else esp + 0x100}
    register_ids = {"eax": x86_const.UC_X86_REG_EAX, "ebx": x86_const.UC_X86_REG_EBX,
                    "ecx": x86_const.UC_X86_REG_ECX, "edx": x86_const.UC_X86_REG_EDX,
                    "esi": x86_const.UC_X86_REG_ESI, "edi": x86_const.UC_X86_REG_EDI,
                    "esp": x86_const.UC_X86_REG_ESP, "ebp": x86_const.UC_X86_REG_EBP}
    native = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
    native.mem_map(entry & ~0xFFF, 0x1000)
    native.mem_write(entry, code)
    native.mem_map(stack_base, stack_size)
    native.mem_write(stack_base, initial_memory)
    state = project.factory.blank_state(addr=entry, add_options={
        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS, angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
    })
    state.memory.store(stack_base, initial_memory)
    for name, value in registers.items():
        native.reg_write(register_ids[name], value)
        state.registers.store(name, value)
    native.reg_write(x86_const.UC_X86_REG_EFLAGS, 0xCD7)
    state.regs.eflags = 0xCD7
    # angr's eflags alias contains condition codes only; DF lives in d.
    state.regs.d = 0xFFFFFFFF
    native.emu_start(entry, entry + len(code), count=1)
    successors = project.factory.successors(state, num_inst=1, opt_level=0)
    assert len(successors.flat_successors) == 1
    lifted = successors.flat_successors[0]
    for name, identifier in register_ids.items():
        assert lifted.solver.eval(lifted.registers.load(name)) == native.reg_read(identifier), name
    assert lifted.solver.eval(lifted.regs.eflags) & 0x8D5 == native.reg_read(x86_const.UC_X86_REG_EFLAGS) & 0x8D5
    assert lifted.solver.eval(lifted.regs.d) == 0xFFFFFFFF
    assert native.reg_read(x86_const.UC_X86_REG_EFLAGS) & 0x400
    assert lifted.addr == native.reg_read(x86_const.UC_X86_REG_EIP) == entry + 4
    assert lifted.solver.eval(lifted.memory.load(stack_base, stack_size), cast_to=bytes) == bytes(
        native.mem_read(stack_base, stack_size))


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
@pytest.mark.parametrize("changed", [False, True])
def test_enter_frame_proves_and_changed_argument_fails(tmp_path: Path, driver: str, changed: bool) -> None:
    """The real frontend composes ENTER with ordinary instructions and near RET."""
    _project(tmp_path, bytes.fromhex("c8200000c9c3"))
    original = "c8200000 8b4508 c9 c3"
    candidate = "55 89e5 8d6424e0 " + ("8b450c" if changed else "8b4508") + " c9 c3"
    with _driver_lane(driver) as lane:
        result = _compare_calls(lane, original, candidate,
            oracle_functions={BASE: len(bytes.fromhex(original))},
            candidate_functions={BASE: len(bytes.fromhex(candidate))},
            outputs=lane.adapter.OUTPUT_REGS)
    assert result["status"] == ("failed" if changed else "passed"), result


@pytest.mark.parametrize("code", ["0f0b", "c8", "c80000", "66c8000000", "67c8000000"])
def test_unrelated_undecodable_instruction_stays_undecodable(tmp_path: Path, code: str) -> None:
    """Registering ENTER must not reinterpret UD2 or truncated byte sequences."""
    machine_code = bytes.fromhex(code)
    project, entry = _project(tmp_path, machine_code)
    assert project.factory.block(entry, size=len(machine_code), opt_level=0).vex.jumpkind == "Ijk_NoDecode"
