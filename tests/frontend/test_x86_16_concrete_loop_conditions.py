"""Regress atomic refusal outside the LOOP and JCXZ lifting contract."""

from types import SimpleNamespace

import pytest
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.regs import reg32_t

from inertia.frontend.x86_16.emulator import Emulator
from inertia.frontend.x86_16.instr32 import Instr32


@pytest.mark.parametrize("address_bits", [16, 32])
@pytest.mark.parametrize("entry_counter", [0, 1, 2, 0x10000])
def test_concrete_loop_condition_refuses_before_counter_mutation(address_bits, entry_counter):
    emulator = Emulator(Arch86_16())
    emulator.set_gpreg(reg32_t.ECX, entry_counter)
    instruction = object.__new__(Instr32)
    instruction.emu = emulator
    instruction.instr = SimpleNamespace(address_bits=address_bits)

    with pytest.raises(TypeError, match="requires a VexValue"):
        instruction._loop_counter_nonzero()
    assert emulator.get_gpreg(reg32_t.ECX) == entry_counter


@pytest.mark.parametrize("address_bits", [16, 32])
@pytest.mark.parametrize("entry_counter", [0, 1, 0x10000])
def test_concrete_jcxz_keeps_existing_missing_lifter_refusal(monkeypatch, address_bits, entry_counter):
    emulator = Emulator(Arch86_16())
    emulator.set_gpreg(reg32_t.ECX, entry_counter)
    instruction = object.__new__(Instr32)
    instruction.emu = emulator
    instruction.instr = SimpleNamespace(address_bits=address_bits, imm8=4, size=3)
    seen = []
    monkeypatch.setattr(
        "inertia.frontend.x86_16.instr32.branch_rel8",
        lambda _emulator, condition, displacement, size: seen.append((condition, displacement, size)),
    )

    with pytest.raises(RuntimeError, match="require an active lifter"):
        instruction.jcxz_rel8()
    assert not seen
    assert emulator.get_gpreg(reg32_t.ECX) == entry_counter
