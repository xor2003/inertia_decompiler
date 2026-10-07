from __future__ import annotations

import angr
import pytest
import pyvex
from angr import options as o
from inertia.semantics.alu_semantics import masked_shift_count
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from archinfo import ArchX86
from pyvex.expr import ITE


class _ConstantValue:
    value = 0x21

    def cast_to(self, _value_type: object) -> object:
        raise AssertionError("known shift counts must be folded before casting")


class _ConstantHost:
    def constant(self, value: int, value_type: object) -> tuple[int, object]:
        return value, value_type


def _run_shift(arch: object, value: int, flags: int) -> angr.SimState:
    project = angr.load_shellcode(
        bytes.fromhex("d0e0"),
        arch=arch,
        start_offset=0x100,
        load_address=0x100,
        selfmodifying_code=False,
        rebase_granularity=0x1000,
    )
    state = project.factory.blank_state(
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    )
    state.regs.ax = value
    state.regs.flags = flags
    successor = project.factory.successors(state, num_inst=1).flat_successors
    assert len(successor) == 1
    return successor[0]


def test_masked_shift_count_folds_symbolic_constant() -> None:
    folded = masked_shift_count(_ConstantHost(), _ConstantValue(), 8)

    assert folded[0] == 1


def test_al_shift_one_has_bounded_vex_without_ite_fanout() -> None:
    irsb = pyvex.lift(bytes.fromhex("d0e0"), 0x100, Arch86_16())

    assert len(irsb.statements) < 100
    assert sum(isinstance(expression, ITE) for expression in irsb.expressions) <= 1


def test_byte_stack_load_shift_xor_block_has_compact_vex() -> None:
    code = bytes.fromhex("8a4604d0e0324606e90000")
    irsb = pyvex.lift(code, 0x10035, Arch86_16())

    assert len(irsb.statements) < 145
    assert sum(isinstance(expression, ITE) for expression in irsb.expressions) <= 6


@pytest.mark.parametrize("value", [0x00, 0x01, 0x40, 0x80, 0xFF])
@pytest.mark.parametrize("flags", [0x0000, 0x08D5])
def test_al_shift_one_matches_x86_result_and_defined_flags(value: int, flags: int) -> None:
    expected = _run_shift(ArchX86(), value, flags)
    actual = _run_shift(Arch86_16(), value, flags)

    assert actual.solver.eval(actual.regs.ax) == expected.solver.eval(expected.regs.ax)
    for bit in (0, 2, 6, 7, 11):
        assert actual.solver.eval(actual.regs.flags[bit]) == expected.solver.eval(expected.regs.flags[bit])
