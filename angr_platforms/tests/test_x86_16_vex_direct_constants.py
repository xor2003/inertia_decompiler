"""Preserve real pyvex constants at the typed IR boundary."""

from types import SimpleNamespace

import pytest
import pyvex
from angr_platforms.X86_16.ir.core import IRValue, MemSpace
from angr_platforms.X86_16.ir.vex_import import (
    _expr_to_value,
    build_x86_16_ir_function_artifact,
)
from angr_platforms.X86_16.ir.vex_types import vex_expr_size_bytes
from test_x86_16_vex_import import _block, _project


@pytest.mark.parametrize(
    ("constant", "size"),
    [
        (pyvex.const.U1(1), 1),
        (pyvex.const.U8(0xFF), 1),
        (pyvex.const.U16(0xFFFF), 2),
        (pyvex.const.U32(0xFFFFFFFF), 4),
        (pyvex.const.U64(0xFFFFFFFFFFFFFFFF), 8),
    ],
)
def test_direct_integer_constant_matches_wrapped_expression(constant, size) -> None:
    direct = _expr_to_value(constant, {}, {})
    wrapped = _expr_to_value(pyvex.expr.Const(constant), {}, {})
    assert direct == wrapped == IRValue(MemSpace.CONST, const=constant.value, size=size)
    assert vex_expr_size_bytes(constant) == size


def test_real_exit_destination_survives_ir_import() -> None:
    entry, target, fallthrough = 0x1000, 0x1040, 0x1002
    function = SimpleNamespace(addr=entry, block_addrs_set={entry}, info={})
    exit_statement = pyvex.stmt.Exit(
        pyvex.expr.Const(pyvex.const.U1(1)), pyvex.const.U16(target), "Ijk_Boring", 0,
    )
    block = _block(entry, exit_statement, next_expr=pyvex.expr.Const(pyvex.const.U16(fallthrough)))
    artifact = build_x86_16_ir_function_artifact(_project({entry: block}, function), function)
    branch = next(instruction for instruction in artifact.blocks[0].instrs if instruction.op == "CJMP")
    assert branch.args[1] == IRValue(MemSpace.CONST, const=target, size=2)
    assert set(artifact.blocks[0].successor_addrs) == {target, fallthrough}


def test_bare_float_is_not_classified_as_integer() -> None:
    assert _expr_to_value(pyvex.const.F64(1.5), {}, {}).space is MemSpace.UNKNOWN
