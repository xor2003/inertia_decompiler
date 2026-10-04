"""Public scalar metadata decisions and retained producer-view controls.

Existing constant-flow known-lane, CALL, and malformed-write controls exercise
the consuming engine; these tests cover the newly shared metadata contract.
"""

from __future__ import annotations

import pytest
from angr_platforms.X86_16.ir.constant_flow import IRConstantFlow8616
from angr_platforms.X86_16.ir.core import IRInstr, IRValue, MemSpace
from angr_platforms.X86_16.ir.scalar_value_projection import (
    ScalarBinaryKind8616,
    ScalarProjectionKind8616,
    scalar_binary_operation_8616,
    scalar_produced_decoration_8616,
    scalar_read_projection_8616,
)


@pytest.mark.parametrize("expression,source,target,produced,kind,signed", [
    ((), 16, 16, (), ScalarProjectionKind8616.IDENTITY, False),
    (("Iop_Shl16",), 16, 16, ("Iop_Shl16",),
     ScalarProjectionKind8616.EARNED_REDECORATION, False),
    (("Iop_Add16", "ax", "bx"), 16, 16, ("Iop_Add16", "ax", "bx"),
     ScalarProjectionKind8616.EARNED_REDECORATION, False),
    (("Iop_8Uto16",), 8, 16, (), ScalarProjectionKind8616.CONVERSION, False),
    (("Iop_8Sto16",), 8, 16, (), ScalarProjectionKind8616.CONVERSION, True),
    (("Iop_32to8",), 32, 8, (), ScalarProjectionKind8616.CONVERSION, False),
])
def test_shared_projection_decision(
    expression: tuple[str, ...], source: int, target: int,
    produced: tuple[str, ...], kind: ScalarProjectionKind8616, signed: bool,
) -> None:
    """Only exact width/conversion metadata yields the declared projection."""
    result = scalar_read_projection_8616(
        read_expr=expression, read_bits=target,
        produced=produced, produced_bits=source,
    )
    assert result is not None
    assert (result.kind, result.source_bits, result.target_bits, result.signed) == (
        kind, source, target, signed,
    )


@pytest.mark.parametrize("expression,source,target,produced", [
    ((), 8, 16, ()),
    ((), 24, 24, ()),
    ((), 0, 0, ()),
    (("Iop_8Uto16",), 16, 16, ()),
    (("Iop_8Uto16",), 8, 32, ()),
    (("Iop_16Uto32",), 8, 32, ()),
    (("Iop_8Uto16", "extra"), 8, 16, ()),
    (("Iop_NotARegisteredOperation",), 8, 16, ()),
    (("Iop_Or16",), 16, 16, ()),
    (("Iop_Add16",), 16, 16, ("Iop_Add16", "ax", "bx")),
    (("Iop_Add16", "ax", "cx"), 16, 16, ("Iop_Add16", "ax", "bx")),
])
def test_unearned_or_malformed_projection_refuses(
    expression: tuple[str, ...], source: int, target: int,
    produced: tuple[str, ...],
) -> None:
    """Unearned labels, unsupported widths and implicit conversion refuse."""
    assert scalar_read_projection_8616(
        read_expr=expression, read_bits=target,
        produced=produced, produced_bits=source,
    ) is None


@pytest.mark.parametrize("kind", tuple(ScalarBinaryKind8616))
@pytest.mark.parametrize("bits", (8, 16, 32, 64))
def test_binary_operation_decoding(kind: ScalarBinaryKind8616, bits: int) -> None:
    """Backend spelling is decoded once into typed operation/width metadata."""
    result = scalar_binary_operation_8616(f"Iop_{kind.value}{bits}")
    assert result is not None
    assert result.kind is kind and result.bits == bits


@pytest.mark.parametrize("operation", ("Iop_CmpNE16", "Iop_Add24", "Iop_Mul16", "MOV"))
def test_unsupported_binary_operation_refuses(operation: str) -> None:
    """Unowned operations never acquire a supported pure-operation kind."""
    assert scalar_binary_operation_8616(operation) is None


def _register(name: str, size: int = 2) -> IRValue:
    """Construct one typed architectural register view."""
    return IRValue(MemSpace.REG, name=name, size=size)


def _temporary(identifier: int, expression: tuple[str, ...] = ()) -> IRValue:
    """Construct a word temporary read with an exact retained decoration."""
    return IRValue(MemSpace.TMP, source_tmp=identifier, size=2, expr=expression)


@pytest.mark.parametrize("operation,left,right,expected", [
    ("Iop_Add16", _register("ax"), _register("bx"), ("Iop_Add16", "ax", "bx")),
    ("Iop_Add32", _register("eax", 4), _register("ebx", 4), ("Iop_Add32", "eax", "ebx")),
    ("Iop_Or16", _register("ax"), _register("bx"), ("Iop_Or16",)),
    ("Iop_Add16", _register("ax"), IRValue(MemSpace.CONST, const=1, size=2), ("Iop_Add16",)),
])
def test_producer_decoration_preserves_operand_roles(
    operation: str, left: IRValue, right: IRValue, expected: tuple[str, ...],
) -> None:
    """Register addition retains names; other operations keep their own label."""
    instruction = IRInstr(operation, _temporary(9), (left, right))
    assert scalar_produced_decoration_8616(instruction) == expected


def test_load_and_mov_decoration_transport() -> None:
    """LOAD labels and MOV's source decoration survive without inventing proof."""
    source = _temporary(9, ("Iop_Add16", "ax", "bx"))
    assert scalar_produced_decoration_8616(IRInstr("MOV", _temporary(10), (source,))) == source.expr
    assert scalar_produced_decoration_8616(IRInstr("LOAD", _temporary(9), ())) == ("load",)
    assert scalar_produced_decoration_8616(IRInstr("UNKNOWN", _temporary(9), ())) == ()


def test_flow_keeps_exact_register_add_view_after_refused_read() -> None:
    """Bad decorations cannot replace or poison the earned immutable value."""
    state = IRConstantFlow8616()
    ax, bx = _register("ax"), _register("bx")
    for instruction in (
        IRInstr("MOV", ax, (IRValue(MemSpace.CONST, const=1, size=2),)),
        IRInstr("MOV", bx, (IRValue(MemSpace.CONST, const=2, size=2),)),
        IRInstr("Iop_Add16", _temporary(9), (ax, bx)),
    ):
        state.observe(instruction)
    assert state.constant(_temporary(9, ("Iop_Add16",))) is None
    assert state.constant(_temporary(9, ("Iop_Add16", "ax", "cx"))) is None
    assert state.constant(_temporary(9, ("Iop_Add16", "ax", "bx"))) == 3
    assert state.constant(_temporary(9)) == 3


def test_refused_conversion_does_not_change_immutable_identity_relations() -> None:
    """Discarded conversion work cannot bind a register's newer definition."""
    state = IRConstantFlow8616()
    bx = _register("bx")
    state.observe(IRInstr("MOV", _temporary(9), (bx,)))
    assert state.constant(IRValue(
        MemSpace.TMP, source_tmp=9, size=4, expr=("Iop_16Uto64",),
    )) is None
    state.observe(IRInstr("MOV", bx, (IRValue(MemSpace.CONST, const=7, size=2),)))
    assert state.constant(_temporary(9)) is None
    assert state.constant(bx) == 7
    state.observe(IRInstr("Iop_Xor16", _temporary(10), (_temporary(9), _temporary(9))))
    assert state.constant(_temporary(10, ("Iop_Xor16",))) == 0
