"""Closed-refusal controls for malformed writes, conversions, and CALL dst.

Durable public controls for ``IRConstantFlow8616``: malformed register writes
at any size poison the
storage family, conversion decorations must be earned by the retained
definition, and a CALL destination is a target — never an output definition.
"""

from __future__ import annotations

import pytest
from angr_platforms.X86_16.ir.constant_flow import IRConstantFlow8616
from angr_platforms.X86_16.ir.core import IRInstr, IRValue, MemSpace


def _reg(name: str, size: int) -> IRValue:
    """Return a register view read of the given byte width."""
    return IRValue(MemSpace.REG, name=name, size=size)


def _const(value: int, size: int) -> IRValue:
    """Return an exact integer constant operand."""
    return IRValue(MemSpace.CONST, const=value, size=size)


def _tmp(name: str, size: int, tmp: int, expr: tuple[str, ...] = ()) -> IRValue:
    """Return a temporary definition or read carrying ``source_tmp``."""
    return IRValue(MemSpace.TMP, name=name, size=size, expr=expr, source_tmp=tmp)


def _move(destination: IRValue, value: int) -> IRInstr:
    """Build a constant MOV matching the parent's control construction."""
    return IRInstr(
        "MOV", destination,
        (IRValue(MemSpace.CONST, const=value, size=destination.size),),
    )


def _state(instrs: tuple[IRInstr, ...]) -> IRConstantFlow8616:
    """Observe ``instrs`` in order and return the resulting flow state."""
    state = IRConstantFlow8616()
    for instruction in instrs:
        state.observe(instruction)
    return state


@pytest.mark.parametrize("bad_size", (0, 3, 8))
def test_unsupported_write_size_poisons_storage_family(bad_size: int) -> None:
    """An AL write at a size outside the view set invalidates every lane."""
    state = _state((
        _move(_reg("ah", 1), 0x4C),
        _move(_reg("al", bad_size), 0x1234),
    ))
    assert state.constant(_reg("ah", 1)) is None
    assert state.constant(_reg("al", 1)) is None
    assert state.constant(_reg("ax", 2)) is None
    assert state.constant(_reg("eax", 4)) is None


def test_unearned_conversion_target_refuses() -> None:
    """A retained 32-bit constant does not embody a 16Uto32 decoration."""
    state = _state((_move(_tmp("wide", 4, 7), 0x01020304),))
    read = IRValue(MemSpace.TMP, source_tmp=7, size=4, expr=("Iop_16Uto32",))
    assert state.constant(read) is None


def test_actual_conversion_reread_is_stable() -> None:
    """A temporary re-decorated with its own producing conversion proves."""
    state = _state((
        _move(_tmp("raw", 1, 1), 0x80),
        IRInstr("MOV", _tmp("wide", 2, 2),
                (_tmp("raw", 2, 1, ("Iop_8Uto16",)),)),
    ))
    assert state.constant(_tmp("wide", 2, 2, ("Iop_8Uto16",))) == 0x80


def test_different_conversion_operation_refuses() -> None:
    """A produced-8Uto16 temporary cannot be re-read as a 32to16 result."""
    state = _state((
        _move(_tmp("raw", 1, 1), 0x80),
        IRInstr("MOV", _tmp("wide", 2, 2),
                (_tmp("raw", 2, 1, ("Iop_8Uto16",)),)),
    ))
    wrong = IRValue(MemSpace.TMP, source_tmp=2, size=2, expr=("Iop_32to16",))
    assert state.constant(wrong) is None
    assert state.constant(_tmp("wide", 2, 2)) == 0x80


def test_fabricated_operation_label_refuses() -> None:
    """A descriptive binop label not earned by the definition refuses."""
    state = _state((_move(_tmp("word", 2, 3), 0x1234),))
    fabricated = IRValue(MemSpace.TMP, source_tmp=3, size=2,
                         expr=("Iop_Or16",))
    assert state.constant(fabricated) is None
    assert state.constant(_tmp("word", 2, 3)) == 0x1234


def test_call_target_is_not_an_output_definition() -> None:
    """CALL clears registers but never overwrites the target temporary."""
    state = _state((
        _move(_reg("ah", 1), 0x4C),
        _move(_tmp("target", 2, 1), 0x1234),
        IRInstr("CALL", _tmp("target", 2, 1), (_tmp("target", 2, 1),)),
    ))
    assert state.constant(_tmp("target", 2, 1)) == 0x1234
    assert state.constant(_reg("ah", 1)) is None


def test_malformed_temporary_width_invalidates_the_definition() -> None:
    """A write at a width outside the supported set drops the old value."""
    state = _state((
        _move(_tmp("kept", 2, 1), 0x1234),
        _move(_tmp("kept", 3, 1), 0x1234),
    ))
    assert state.constant(_tmp("kept", 2, 1)) is None


def test_unknown_layout_register_write_refuses() -> None:
    """A name outside the register view layout earns no storage object."""
    state = _state((_move(_reg("not_a_reg", 1), 0x4C),))
    assert state.constant(_reg("not_a_reg", 1)) is None
    assert state.constant(_reg("ax", 2)) is None
