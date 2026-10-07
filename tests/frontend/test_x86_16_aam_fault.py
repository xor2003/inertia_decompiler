"""Layer: tests.
Responsibility: retain AAM divide-error outcomes and valid nondecimal bases.
"""
from __future__ import annotations

import hashlib

import angr
import pytest
import pyvex
from angr import options
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from unicorn import UC_ARCH_X86, UC_ERR_EXCEPTION, UC_MODE_16, Uc, UcError
from unicorn.x86_const import UC_X86_REG_AX

from tools.dosunit.contracts.model import canonical_json_bytes
from tools.dosunit.compare.real16_call_contracts import initial_state
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import bind_real16_mz
from tools.dosunit.recursive_proofs.real16_native_effect_binding import (
    NativeBindingReason,
    NativeBlockRequest,
    bind_real16_native_effects,
)


def _execute_aam(code: bytes, ax: int) -> list[angr.SimState]:
    """Execute one lifted instruction and retain feasible normal successors."""
    project = angr.load_shellcode(code, arch=Arch86_16(), load_address=0x100)
    state = project.factory.blank_state(
        addr=0x100,
        add_options={options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                     options.ZERO_FILL_UNCONSTRAINED_REGISTERS},
    )
    state.regs.ax = ax
    successors = project.factory.successors(state, num_inst=1)
    return successors.flat_successors


def test_aam_zero_retains_native_divide_fault() -> None:
    """Zero base faults before AX changes; lifting must retain that outcome."""
    code = bytes.fromhex("d400")
    guest = Uc(UC_ARCH_X86, UC_MODE_16)
    guest.mem_map(0, 0x1000)
    guest.mem_write(0x100, code)
    guest.reg_write(UC_X86_REG_AX, 7)
    with pytest.raises(UcError) as captured:
        guest.emu_start(0x100, 0x102, count=1)
    assert captured.value.errno == UC_ERR_EXCEPTION
    assert guest.reg_read(UC_X86_REG_AX) == 7

    block = pyvex.IRSB(code, 0x100, Arch86_16(), opt_level=0)
    faults = [statement for statement in block.statements
              if isinstance(statement, pyvex.stmt.Exit)
              and statement.jumpkind == "Ijk_SigFPE_IntDiv"]
    assert len(faults) == 1
    assert not _execute_aam(code, 7)


def test_aam_zero_cannot_receive_normal_native_effect_binding() -> None:
    """The recursive proof boundary must retain the independently lifted fault."""
    from tests.fixtures.mz import _mz_exe

    load = bind_real16_mz(
        _mz_exe(bytes(0x200) + bytes.fromhex("d400")), load_segment=0x1000
    )
    proposal = canonical_json_bytes(initial_state())
    request = NativeBlockRequest(
        0x10200, 2, hashlib.sha256(proposal).hexdigest(), proposal
    )
    binding = bind_real16_native_effects(load, (request,), timeout_ms=10000)
    assert binding.reason is NativeBindingReason.FAULT, binding


@pytest.mark.parametrize("base", [1, 2, 10, 255])
def test_aam_nonzero_base_preserves_quotient_and_remainder(base: int) -> None:
    """Nonzero immediate bases execute normally without an invented trap."""
    code = bytes((0xD4, base))
    successors = _execute_aam(code, 0xABEF)
    assert len(successors) == 1
    result = successors[0]
    assert result.history.jumpkind == "Ijk_Boring"
    assert result.solver.eval(result.regs.ax) == ((0xEF // base) << 8) | (0xEF % base)
