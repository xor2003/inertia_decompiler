from __future__ import annotations

import pytest
import pyvex
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from pyvex.lifting.util.syntax_wrapper import VexValue
from pyvex.lifting.util.vex_helper import IRSBCustomizer, Type

from inertia.frontend.x86_16.cr import CR
from inertia.frontend.x86_16.emulator import Emulator


def test_control_registers_start_as_real_mode_zero_state() -> None:
    registers = CR()

    assert registers.get_crn(0) == 0
    assert registers.get_crn(1) == 0
    assert registers.get_crn(2) == 0
    assert registers.get_crn(3) == 0
    assert registers.get_crn(4) == 0
    assert registers.is_protected() is False
    assert registers.is_ena_paging() is False


def test_control_register_helpers_report_owned_register_fields() -> None:
    registers = CR()
    registers.cr0 = 1 << 31
    registers.cr3 = 0x12345000

    assert registers.is_ena_paging() is True
    assert registers.get_pdir_base() == 0x12000


def test_control_register_lookup_rejects_unknown_register_index() -> None:
    with pytest.raises(ValueError, match="Invalid CR index: 5"):
        CR().get_crn(5)


@pytest.mark.parametrize("index", (0, 2, 3))
@pytest.mark.parametrize("representation", ("integer", "raw", "wrapped"))
def test_lifted_control_register_values_keep_32_bit_puts(index, representation):
    """Keep concrete, raw VEX, and wrapped VEX inputs on the same register lane."""
    arch = Arch86_16()
    emulator = Emulator(arch)
    emulator.set_crn(index, 0x12345678)
    assert emulator.get_crn(index) == 0x12345678
    irsb = pyvex.IRSB.empty_block(arch, 0x1000)
    customizer = IRSBCustomizer(irsb)
    emulator.lifter_instruction = customizer
    raw = customizer.mkconst(0x12345678, Type.int_32)
    value = (0x12345678 if representation == "integer" else
             VexValue(customizer, raw) if representation == "wrapped" else raw)
    emulator.set_crn(index, value)
    put = irsb.statements[-1]
    assert isinstance(put, pyvex.stmt.Put)
    assert put.offset == arch.get_register_offset(f"cr{index}")
    assert put.data.result_size(irsb.tyenv) == 32
    assert isinstance(emulator.get_crn(index), VexValue)


def test_lifted_control_register_write_rejects_non_expression():
    """Invalid boundary values must not become malformed VEX Put statements."""
    arch = Arch86_16()
    emulator = Emulator(arch)
    irsb = pyvex.IRSB.empty_block(arch, 0x1000)
    emulator.lifter_instruction = IRSBCustomizer(irsb)
    with pytest.raises(TypeError, match="VEX expression"):
        emulator.set_crn(0, object())
    assert irsb.statements == []
