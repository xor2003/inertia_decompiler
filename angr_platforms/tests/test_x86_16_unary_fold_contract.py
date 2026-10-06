"""Keep active unary operands intact when projecting genuine VEX arithmetic."""

from __future__ import annotations

import pytest
import pyvex
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir import real16_edge_feasibility8616 as edge
from angr_platforms.X86_16.ir import real16_invocation_domain as domain
from angr_platforms.X86_16.ir import vex_import
from angr_platforms.X86_16.ir.core import IRValue
from angr_platforms.X86_16.ir.vex_condition_demand import (
    VexConditionDemand8616,
    VexConditionDemandStats8616,
)


@pytest.mark.parametrize(
    ("operation", "active_left", "expected"),
    [("Add", True, 0), ("Add", False, 8),
     ("Sub", True, 0xFFFE), ("Sub", False, 10)],
)
def test_unary_operand_survives_binary_projection(
    operation: str, active_left: bool, expected: int,
) -> None:
    """Compatibility views never invent a value; complete WrTmp rows stay exact."""
    arch = Arch86_16()
    environment = pyvex.IRTypeEnv(arch, types=["Ity_I16"] * 9)
    demand = VexConditionDemand8616(frozenset(), VexConditionDemandStats8616())
    views: dict[int, IRValue] = {}
    capture = vex_import._stmt_to_instr(
        pyvex.stmt.WrTmp(7, pyvex.expr.Get(arch.registers["bx"][0], "Ity_I16")),
        views, {}, instruction_addr=0x1000, segment_hints={}, tmp_exprs={},
        type_environment=environment, condition_demand=demand,
    )
    assert capture is not None
    operands = (
        [pyvex.expr.Unop("Iop_Not16", [pyvex.expr.RdTmp(7)]),
         pyvex.expr.Const(pyvex.const.U16(1))]
        if active_left else
        [pyvex.expr.Get(arch.registers["bx"][0], "Ity_I16"),
         pyvex.expr.Unop("Iop_Not16", [pyvex.expr.Const(pyvex.const.U16(0))])]
    )
    expression = pyvex.expr.Binop(f"Iop_{operation}16", operands)
    assert expression.result_type(environment) == "Ity_I16"
    value = vex_import._expr_to_value(expression, views, {}, type_environment=environment)
    scalar = domain._eval_value_8616(value, {"bx": 9}, {7: 0})
    bits = edge._kb_eval_value_8616(value, {"bx": (0xFFFF, 9)}, {7: (0xFFFF, 0)})
    assert scalar is None or scalar == expected
    assert bits is None or expected & bits[0] == bits[1]
    row = vex_import._stmt_to_instr(
        pyvex.stmt.WrTmp(8, expression), views, {}, instruction_addr=0x1000,
        segment_hints={}, tmp_exprs={}, type_environment=environment,
        condition_demand=demand,
    )
    assert row is not None and row.dst is not None
    captured = {7: 0}
    domain._simulate_tmp_write_8616(row, row.dst, {"bx": 9}, captured)
    assert captured[8] == expected
