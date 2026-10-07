"""Producer-derived constants and register captures must retain address meaning."""
from functools import partial

import pytest
import pyvex
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
import inertia.ir.vex_import as imp
from inertia.ir.core import MemSpace
from inertia.ir.vex_addressing import expr_to_address
from inertia.ir.vex_condition_demand import VexConditionDemand8616, VexConditionDemandStats8616


def context(producer):
    arch = Arch86_16()
    env = pyvex.IRTypeEnv(arch, types=["Ity_I16"] * 8)
    views, conditions, expressions = {}, {}, {}
    imp._stmt_to_instr(pyvex.stmt.WrTmp(7, producer), views, conditions,
        instruction_addr=0x1000, segment_hints={}, tmp_exprs=expressions,
        type_environment=env, condition_demand=VexConditionDemand8616(frozenset(), VexConditionDemandStats8616()))
    return partial(imp._expr_to_value, type_environment=env), views, conditions, expressions


@pytest.mark.parametrize("mapped", [False, True])
@pytest.mark.parametrize("op,extended,reverse", [
    ("Iop_Add16", False, False), ("Iop_Sub16", False, False),
    ("Iop_Add16", False, True), ("Iop_Add32", True, False),
])
def test_pinned_complement_literal_requires_producer(mapped, op, extended, reverse):
    convert, views, conditions, expressions = context(pyvex.expr.Unop("Iop_Not16", [
        pyvex.expr.Const(pyvex.const.U16(0))]))
    register = pyvex.expr.Get(Arch86_16().registers["ebx" if extended else "bx"][0],
                            "Ity_I32" if extended else "Ity_I16")
    operand = pyvex.expr.RdTmp(7)
    if extended:
        operand = pyvex.expr.Unop("Iop_16Uto32", [operand])
    args = [operand, register] if reverse else [register, operand]
    address = expr_to_address(pyvex.expr.Binop(op, args), views, conditions,
        expr_to_value=convert, size=2, tmp_exprs=expressions if mapped else None)
    if not mapped:
        assert address.space is MemSpace.UNKNOWN and not address.base
    else:
        assert address.base == (("ebx",) if extended else ("bx",))
        if extended:
            assert 9 + address.offset == 65544
        else:
            assert (9 + address.offset) & 0xFFFF == (10 if op == "Iop_Sub16" else 8)


@pytest.mark.parametrize("mapped", [False, True])
def test_ordinary_zero_extension_keeps_register_capture(mapped):
    arch = Arch86_16()
    convert, views, conditions, expressions = context(pyvex.expr.Get(arch.registers["bx"][0], "Ity_I16"))
    expression = pyvex.expr.Binop("Iop_Add32", [
        pyvex.expr.Unop("Iop_16Uto32", [pyvex.expr.RdTmp(7)]),
        pyvex.expr.Const(pyvex.const.U32(4))])
    address = expr_to_address(expression, views, conditions, expr_to_value=convert,
        size=2, tmp_exprs=expressions if mapped else None)
    assert address.base == ("bx",) and address.offset == 4
    assert address.base_values[0].source_tmp == 7


def test_unpinned_literal_arithmetic_remains_exact():
    arch = Arch86_16()
    convert, views, conditions, expressions = context(pyvex.expr.Get(arch.registers["bx"][0], "Ity_I16"))
    address = expr_to_address(pyvex.expr.Binop("Iop_Add16", [
        pyvex.expr.Get(arch.registers["bx"][0], "Ity_I16"),
        pyvex.expr.Const(pyvex.const.U16(4))]), views, conditions,
        expr_to_value=convert, size=2, tmp_exprs=expressions)
    assert address.base == ("bx",) and address.offset == 4
