"""Keep native unary operations and immutable operand captures exact."""

from __future__ import annotations

import pytest
import pyvex
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir import vex_import
from angr_platforms.X86_16.ir.constant_flow import IRConstantFlow8616
from angr_platforms.X86_16.ir.vex_condition_demand import (
    VexConditionDemand8616,
    VexConditionDemandStats8616,
)


def _observe_native(flow: IRConstantFlow8616, raw: bytes) -> None:
    """Import genuine native instruction bytes before consuming their effects."""
    block = pyvex.IRSB(raw, 0x1000, Arch86_16(), opt_level=0)
    views, conditions, expressions = {}, {}, {}
    demand = VexConditionDemand8616(frozenset(), VexConditionDemandStats8616())
    for statement in block.statements:
        row = vex_import._stmt_to_instr(
            statement, views, conditions, instruction_addr=0x1000,
            segment_hints={}, tmp_exprs=expressions, type_environment=block.tyenv,
            condition_demand=demand,
        )
        if row is not None:
            flow.observe(row)


@pytest.mark.parametrize("op,expected", [("Iop_16Sto32", 0xFFFF8000), ("Iop_16Uto32", 0x8000)])
def test_unary_constant_uses_capture_after_register_changes(op: str, expected: int) -> None:
    flow = IRConstantFlow8616()
    _observe_native(flow, bytes.fromhex("b80080"))
    arch = Arch86_16()
    environment = pyvex.IRTypeEnv(arch, types=["Ity_I16"] * 128)
    views, conditions, expressions = {}, {}, {}
    row = vex_import._stmt_to_instr(
        pyvex.stmt.WrTmp(127, pyvex.expr.Get(arch.registers["ax"][0], "Ity_I16")),
        views, conditions, instruction_addr=0x1003, segment_hints={},
        tmp_exprs=expressions, type_environment=environment,
        condition_demand=VexConditionDemand8616(frozenset(), VexConditionDemandStats8616()),
    )
    assert row is not None
    flow.observe(row)
    _observe_native(flow, bytes.fromhex("b80100"))
    value = vex_import._expr_to_value(
        pyvex.expr.Unop(op, [pyvex.expr.RdTmp(127)]), views, conditions,
        type_environment=environment,
    )
    assert flow.constant(value) == expected


@pytest.mark.parametrize("inner,expected", [("Iop_8Sto16", 0xFFFFFF80), ("Iop_8Uto16", 0x80)])
def test_nested_constant_conversion_keeps_inner_signedness(inner: str, expected: int) -> None:
    expression = pyvex.expr.Unop("Iop_16Sto32", [
        pyvex.expr.Unop(inner, [pyvex.expr.Const(pyvex.const.U8(0x80))]),
    ])
    value = vex_import._expr_to_value(
        expression, {}, {}, type_environment=pyvex.IRTypeEnv(Arch86_16()),
    )
    assert IRConstantFlow8616().constant(value) == expected


def test_native_not_constant_remains_exact() -> None:
    flow = IRConstantFlow8616()
    _observe_native(flow, bytes.fromhex("b80100f7d0"))
    value = vex_import._expr_to_value(
        pyvex.expr.Get(Arch86_16().registers["ax"][0], "Ity_I16"), {}, {},
    )
    assert flow.constant(value) == 0xFFFE


def test_unsupported_unary_constant_is_not_its_operand() -> None:
    value = vex_import._expr_to_value(
        pyvex.expr.Unop("Iop_Clz32", [pyvex.expr.Const(pyvex.const.U32(16))]), {}, {},
        type_environment=pyvex.IRTypeEnv(Arch86_16()),
    )
    assert IRConstantFlow8616().constant(value) is None
