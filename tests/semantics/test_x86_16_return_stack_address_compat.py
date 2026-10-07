"""Tests for BP provenance on current angr AIL stack-address nodes."""

from types import SimpleNamespace

import pytest
from angr import ailment
from angr.ailment.expression import StackBaseOffset
from angr.sim_variable import SimStackVariable

from inertia.frontend.x86_16.decompiler_return_compat import (
    _ail_const_value_8616,
    _bp_offset_from_linear_stack_addr_8616,
    _register_assignment_source_8616,
    _terminal_ax_stack_load_from_instructions_8616,
    _tmp_assignment_source_8616,
)


def test_stack_base_offset_retains_typed_bp_provenance() -> None:
    """A current AIL stack node is BP-relative only when its variable proves it."""
    variable = SimStackVariable(6, 2, base="bp", region=0x1000)
    expression = StackBaseOffset(1, 16, 6, variable=variable)

    assert _bp_offset_from_linear_stack_addr_8616(SimpleNamespace(), expression) == 6


def test_stack_base_offset_without_bp_variable_is_not_reclassified() -> None:
    """A generic stack-base node must not be guessed to be BP-relative."""
    expression = StackBaseOffset(1, 16, 6)

    assert _bp_offset_from_linear_stack_addr_8616(SimpleNamespace(), expression) is None


def _instruction(mnemonic: str, operands: tuple[object, ...] = ()) -> SimpleNamespace:
    names = {1: "ax", 2: "bp"}
    return SimpleNamespace(mnemonic=mnemonic, operands=operands, reg_name=lambda reg: names.get(reg, ""))


def test_terminal_ax_stack_load_uses_typed_instruction_effect() -> None:
    destination = SimpleNamespace(type=1, reg=1)
    source = SimpleNamespace(type=3, size=2, mem=SimpleNamespace(base=2, index=0, disp=-2))
    block = SimpleNamespace(
        capstone=SimpleNamespace(insns=(_instruction("mov", (destination, source)), _instruction("ret")))
    )

    assert _terminal_ax_stack_load_from_instructions_8616(SimpleNamespace(blocks=(block,))) == (-2, 2)


def test_terminal_ax_stack_load_refuses_later_ax_overwrite() -> None:
    destination = SimpleNamespace(type=1, reg=1)
    stack_source = SimpleNamespace(type=3, size=2, mem=SimpleNamespace(base=2, index=0, disp=-2))
    immediate = SimpleNamespace(type=2, imm=7)
    block = SimpleNamespace(
        capstone=SimpleNamespace(
            insns=(
                _instruction("mov", (destination, stack_source)),
                _instruction("mov", (destination, immediate)),
                _instruction("ret"),
            )
        )
    )

    assert _terminal_ax_stack_load_from_instructions_8616(SimpleNamespace(blocks=(block,))) is None


@pytest.mark.parametrize("offset,bits,accepted", [(8, 16, True), (9, 16, False), (8, 32, False)])
def test_native_register_assignment_requires_exact_destination(offset, bits, accepted) -> None:
    source = ailment.Expr.Const(1, 7, 16)
    stmt = ailment.Stmt.Assignment(0, ailment.Expr.Register(2, offset, bits), source)
    result = _register_assignment_source_8616(stmt, reg_offset=8, reg_size=2)
    assert (result == source) if accepted else result is None


@pytest.mark.parametrize("index,accepted", [(3, True), (4, False)])
def test_native_tmp_assignment_requires_exact_destination(index, accepted) -> None:
    source = ailment.Expr.Const(1, 7, 16)
    stmt = ailment.Stmt.Assignment(0, ailment.Expr.Tmp(2, index, 16), source)
    result = _tmp_assignment_source_8616(stmt, tmp_idx=3)
    assert (result == source) if accepted else result is None


@pytest.mark.parametrize("native", [True, False])
def test_assignment_readers_refuse_wrong_native_kind_and_lookalikes(native) -> None:
    source = ailment.Expr.Const(1, 7, 16)
    stmt = ailment.Stmt.Assignment(0, source, source) if native else SimpleNamespace(
        dst=SimpleNamespace(reg_offset=8, bits=16, tmp_idx=3), src=source
    )
    assert _register_assignment_source_8616(stmt, reg_offset=8, reg_size=2) is None
    assert _tmp_assignment_source_8616(stmt, tmp_idx=3) is None


def test_native_const_reader_refuses_non_const_variants_and_lookalikes() -> None:
    assert _ail_const_value_8616(ailment.Expr.Const(1, 0xFFFF, 16)) == 0xFFFF
    assert _ail_const_value_8616(ailment.Expr.Register(1, 8, 16)) is None
    assert _ail_const_value_8616(SimpleNamespace(value=7)) is None


def test_terminal_ax_stack_load_accepts_generator_blocks() -> None:
    destination = SimpleNamespace(type=1, reg=1)
    source = SimpleNamespace(type=3, size=2, mem=SimpleNamespace(base=2, index=0, disp=-2))
    block = SimpleNamespace(
        capstone=SimpleNamespace(insns=(_instruction("mov", (destination, source)), _instruction("ret")))
    )
    assert _terminal_ax_stack_load_from_instructions_8616(SimpleNamespace(blocks=iter((block,)))) == (-2, 2)
