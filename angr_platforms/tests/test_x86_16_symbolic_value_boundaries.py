"""Execute native VEX payloads across the frontend's typed value boundaries."""

from __future__ import annotations

from types import SimpleNamespace

import angr
import claripy
import pytest
import pyvex
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.instr_base import _require_vex_value
from angr_platforms.X86_16.memory import Memory
from angr_platforms.X86_16.processor import Processor
from angr_platforms.X86_16.vex_value_contract import require_vex_value_8616
from pyvex.lifting.util.syntax_wrapper import VexValue
from pyvex.lifting.util.vex_helper import IRSBCustomizer, Type

DWORD_BITS = 32
BYTE_BITS = 8
STORED_BYTE = 0x34


class _Lifter(IRSBCustomizer):
    """Use real VEX expressions with the instruction's constant interface."""

    def __init__(self):
        super().__init__(pyvex.IRSB.empty_block(Arch86_16(), 0x1000))
        self._irsb_c = self
        self.irsb_c = self
        self.imark(0x1000, 1)

    def constant(self, value, ty):
        return VexValue(self, self.mkconst(value, ty))


def _execute(lifter):
    lifter.irsb.next = lifter.mkconst(0x1001, Type.int_32)
    lifter.irsb.jumpkind = "Ijk_Boring"
    project = angr.load_shellcode(b"\x90", arch=lifter.arch, load_address=0x1000)
    state = project.factory.blank_state(addr=0x1000)
    successors = project.factory.successors(state, irsb=lifter.irsb).flat_successors
    assert len(successors) == 1
    return successors[0]


@pytest.mark.parametrize("wrapped_address", (False, True))
@pytest.mark.parametrize("wrapped_value", (False, True))
def test_byte_store_preserves_native_address_and_low_byte(wrapped_address, wrapped_value):
    lifter = _Lifter()
    memory = Memory()
    memory.lifter_instruction = lifter
    address = lifter.constant(0x2000, Type.int_32) if wrapped_address else 0x2000
    value = lifter.constant(0xAB34, Type.int_16) if wrapped_value else 0x34
    memory.write_mem8(address, value)
    stores = [stmt for stmt in lifter.irsb.statements if isinstance(stmt, pyvex.stmt.Store)]
    assert len(stores) == 1
    assert stores[0].addr.result_size(lifter.irsb.tyenv) == DWORD_BITS
    assert stores[0].data.result_size(lifter.irsb.tyenv) == BYTE_BITS
    result = _execute(lifter)
    assert result.solver.eval(result.memory.load(0x2000, 1)) == STORED_BYTE


@pytest.mark.parametrize("flags,expected", ((0, 1), (0x0400, 0xFFFFFFFF), (0xFBFF, 1), (0xFFFF, 0xFFFFFFFF)))
@pytest.mark.parametrize("wrapped", (False, True))
def test_direction_step_preserves_native_32_bit_signed_value(flags, expected, wrapped):
    lifter = _Lifter()
    processor = Processor()
    processor.set_lifter_instruction(lifter)
    source = lifter.constant(flags, Type.int_16) if wrapped else flags
    step = processor._lifted_direction_step_from_flags(source)
    assert isinstance(step, VexValue) and step.width == DWORD_BITS
    assert not any(
        isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(stmt.data, pyvex.expr.ITE)
        for stmt in lifter.irsb.statements
    ), "Derived direction must not introduce conditional control-flow candidates"
    lifter.store(lifter.mkconst(0x2000, Type.int_32), step.rdt)
    result = _execute(lifter)
    assert result.solver.eval(result.memory.load(0x2000, 4, endness="Iend_LE")) == expected


def test_direction_step_matches_df_for_every_symbolic_flags_value():
    """Prove exact 32-bit +1/-1 behavior without constraining other FLAGS bits."""
    lifter = _Lifter()
    processor = Processor()
    processor.set_lifter_instruction(lifter)
    source = VexValue(lifter, lifter.rdreg(lifter.arch.registers["flags"][0], Type.int_16))
    step = processor._lifted_direction_step_from_flags(source)
    lifter.store(lifter.mkconst(0x2000, Type.int_32), step.rdt)
    result = _execute(lifter)
    expected = claripy.If(
        (result.regs.flags & 0x0400) != 0,
        claripy.BVV(0xFFFFFFFF, DWORD_BITS),
        claripy.BVV(1, DWORD_BITS),
    )
    actual = result.memory.load(0x2000, 4, endness="Iend_LE")
    assert not result.solver.satisfiable(extra_constraints=(actual != expected,))


@pytest.mark.parametrize("invalid", (None, 7, SimpleNamespace(rdt=object()), object()))
def test_symbolic_guard_refuses_non_wrappers(invalid):
    assert _require_vex_value is require_vex_value_8616
    with pytest.raises(TypeError, match="requires a VexValue"):
        require_vex_value_8616(invalid)


def test_symbolic_guard_preserves_wrapper_and_refuses_raw_expression():
    value = _Lifter().constant(7, Type.int_16)
    assert require_vex_value_8616(value) is value
    with pytest.raises(TypeError, match="requires a VexValue"):
        require_vex_value_8616(value.rdt)


def test_invalid_direction_source_refuses_before_emitting_vex():
    lifter = _Lifter()
    processor = Processor()
    processor.set_lifter_instruction(lifter)
    before = tuple(lifter.irsb.statements)
    with pytest.raises(TypeError, match="requires a VexValue"):
        processor._lifted_direction_step_from_flags(SimpleNamespace(cast_to=lambda _ty: None))
    assert tuple(lifter.irsb.statements) == before


@pytest.mark.parametrize("flags,expected", ((0, 1), (0x0400, -1)))
def test_concrete_direction_step_remains_an_integer(flags, expected):
    processor = Processor()
    processor.flags = flags
    assert processor.get_direction_step() == expected
