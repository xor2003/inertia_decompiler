"""Loader-linear address range must preserve real16 instruction defaults."""
from __future__ import annotations

import pytest
import pyvex

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from tools.dosunit.recursive_proofs.real16_loader_arch import real16_loader_arch
from tools.dosunit.recursive_proofs.real16_operand_access import _fresh_lift


@pytest.mark.parametrize("address", [0x1000, 0x84560, 0xFFFF0])
def test_real16_relift_keeps_word_instruction_width_at_linear_addresses(address: int) -> None:
    """MOV AX,imm16 followed by RET maps high without decoding an imm32."""
    block = _fresh_lift(bytes.fromhex("b83412c3"), address)
    marks = [(s.addr, s.len) for s in block.statements if isinstance(s, pyvex.stmt.IMark)]
    assert marks == [(address, 3), (address + 3, 1)]
    assert block.jumpkind == "Ijk_Ret"


def test_loader_arch_is_isolated_from_default_instruction_arch() -> None:
    """Loader widening never mutates the default register/decoder contract."""
    loader = real16_loader_arch()
    default = Arch86_16()
    assert loader.bits == 32
    assert default.bits == 16
    assert loader.registers == default.registers
    assert loader.control_address_domain == default.control_address_domain
