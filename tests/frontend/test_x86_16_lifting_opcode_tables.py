import inspect
from types import SimpleNamespace

import pytest
import inertia.frontend.x86_16.instr16 as instr16
import inertia.frontend.x86_16.instr32 as instr32
from inertia.frontend.x86_16.lift_86_16 import Instruction_ANY

from inertia.frontend.x86_16.instr_base import InstrBase
from inertia.frontend.x86_16.instruction import CHK_IMM8, CHK_MODRM, MAX_OPCODE


@pytest.mark.parametrize("module,cls,width", [(instr16, instr16.Instr16, 16), (instr32, instr32.Instr32, 32)])
@pytest.mark.parametrize("selector", range(8))
def test_bit_immediate_group_dispatches_or_reports_exact_invalid_selector(
    monkeypatch, module, cls, width, selector
):
    """Keep valid bit handlers and invalid-extension diagnostics coherent."""
    host = cls.__new__(cls)
    host.instr = SimpleNamespace(modrm=SimpleNamespace(reg=selector))
    calls = []
    errors = []
    for operation in ("bt", "bts", "btr", "btc"):
        monkeypatch.setattr(
            host, f"{operation}_rm{width}_imm8", lambda op=operation: calls.append(op)
        )
    monkeypatch.setattr(module, "ERROR", lambda fmt, reg: errors.append((fmt, reg)))

    host.code_0fba()

    assert calls == ([] if selector < 4 else [("bt", "bts", "btr", "btc")[selector - 4]])
    assert errors == ([("invalid 0x0fba /%d\n", selector)] if selector < 4 else [])


def _dummy_handler() -> None:
    return None


def test_instruction_any_implements_gymrat_decoder_contract():
    assert Instruction_ANY.bin_format == "xxxxxxxx"
    assert Instruction_ANY.name == "nop"
    assert not inspect.isabstract(Instruction_ANY)


def _table_host():
    return SimpleNamespace(instrfuncs=[None] * MAX_OPCODE, chk=[0] * MAX_OPCODE)


def test_set_funcflag_maps_0f_prefixed_opcode_into_two_byte_table_slot():
    host = _table_host()

    InstrBase.set_funcflag(host, 0x0F90, _dummy_handler, CHK_MODRM)

    assert host.instrfuncs[0x190] is _dummy_handler
    assert host.chk[0x190] == CHK_MODRM


def test_set_funcflag_maps_single_byte_opcode_into_direct_slot():
    host = _table_host()

    InstrBase.set_funcflag(host, 0x8A, _dummy_handler, CHK_IMM8)

    assert host.instrfuncs[0x8A] is _dummy_handler
    assert host.chk[0x8A] == CHK_IMM8


def test_register_opcode_range_fills_all_slots_with_same_handler_and_flags():
    host = _table_host()

    InstrBase._register_opcode_range(host, 0x40, 0x47, _dummy_handler, CHK_MODRM)

    for opcode in range(0x40, 0x48):
        assert host.instrfuncs[opcode] is _dummy_handler
        assert host.chk[opcode] == CHK_MODRM
