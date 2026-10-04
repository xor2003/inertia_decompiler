"""Typed result widths without inventing unsupported value semantics.

Layer: IR regression tests.
Responsibility: retain VEX result-width evidence across generic temporary
writes while unsupported ITE values stay UNKNOWN. Real VEX ITE, constants,
register reads and widening operations cover instruction/destination/retained
result agreement. This is not ITE value recovery or emitted-C acceptance.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import partial

import angr_platforms.X86_16.ir.vex_import as vi
import archinfo
import pytest
import pyvex
from angr_platforms.X86_16.ir.core import IRCondition, IRValue, MemSpace
from angr_platforms.X86_16.ir.vex_condition_demand import (
    VexConditionDemand8616,
    VexConditionDemandStats8616,
)

_ARCH = archinfo.ArchX86()
_DEMAND = VexConditionDemand8616(frozenset(), VexConditionDemandStats8616())


def _ctx(tyenv: pyvex.IRTypeEnv) -> vi._StmtImportContext8616:
    """Build the production statement-import context over a real type env."""
    return vi._StmtImportContext8616(
        convert=partial(vi._expr_to_value, type_environment=tyenv),
        instruction_addr=None,
        segment_hints={},
        tmp_exprs={},
        type_environment=tyenv,
        condition_demand=_DEMAND,
    )


@pytest.mark.parametrize(
    ("const_factory", "result_bytes"),
    [
        (pyvex.const.U8, 1),
        (pyvex.const.U16, 2),
        (pyvex.const.U32, 4),
    ],
)
def test_ite_result_width_coherent_with_unknown_operand(
    const_factory: Callable[[int], pyvex.const.IRConst], result_bytes: int,
) -> None:
    """ITE imports keep UNKNOWN operand honest at declared result width."""
    tyenv = pyvex.IRTypeEnv(_ARCH)
    tyenv.add("Ity_I1")
    tmps: dict[int, IRValue] = {}
    conditions: dict[int, IRCondition] = {}
    ctx = _ctx(tyenv)
    data = pyvex.expr.ITE(
        pyvex.expr.RdTmp(0),
        pyvex.expr.Const(const_factory(1)),
        pyvex.expr.Const(const_factory(2)),
    )
    instr = vi._wrtmp_instr_8616(pyvex.stmt.WrTmp(9, data), tmps, conditions, ctx)
    assert instr is not None and instr.dst is not None and instr.op == "MOV"
    assert instr.dst is not None and instr.dst.size == result_bytes
    assert instr.size == result_bytes
    assert tmps[9].size == result_bytes
    assert tmps[9].space is MemSpace.UNKNOWN
    assert tmps[9].name == "Iex_ITE"
    assert tmps[9].source_tmp == 9
    source = instr.args[0]
    assert isinstance(source, IRValue)
    assert source.space is MemSpace.UNKNOWN and source.name == "Iex_ITE"
    assert source.size == 0
    assert 9 not in conditions


def test_const_mov_result_width_unchanged() -> None:
    """An ordinary constant MOV keeps its result width on all three owners."""
    tyenv = pyvex.IRTypeEnv(_ARCH)
    tmps: dict[int, IRValue] = {}
    conditions: dict[int, IRCondition] = {}
    ctx = _ctx(tyenv)
    stmt = pyvex.stmt.WrTmp(5, pyvex.expr.Const(pyvex.const.U16(0xBEEF)))
    instr = vi._wrtmp_instr_8616(stmt, tmps, conditions, ctx)
    assert instr is not None and instr.dst is not None and instr.op == "MOV"
    assert instr.size == 2 and instr.dst.size == 2 and tmps[5].size == 2
    source = instr.args[0]
    assert isinstance(source, IRValue)
    assert source.space is MemSpace.CONST and source.const == 0xBEEF


def test_get_mov_result_width_unchanged() -> None:
    """A register read MOV keeps result and operand widths at 2 bytes."""
    tyenv = pyvex.IRTypeEnv(_ARCH)
    tyenv.add("Ity_I16")
    tmps: dict[int, IRValue] = {}
    conditions: dict[int, IRCondition] = {}
    ctx = _ctx(tyenv)
    stmt = pyvex.stmt.WrTmp(6, pyvex.expr.Get(0, "Ity_I16"))
    instr = vi._wrtmp_instr_8616(stmt, tmps, conditions, ctx)
    assert instr is not None and instr.dst is not None and instr.op == "MOV"
    assert instr.size == 2 and instr.dst.size == 2 and tmps[6].size == 2
    source = instr.args[0]
    assert isinstance(source, IRValue)
    assert source.space is MemSpace.REG and source.size == 2


def test_unop_result_width_unchanged() -> None:
    """A 1-to-16 widening unop keeps result width 2 on all three owners."""
    tyenv = pyvex.IRTypeEnv(_ARCH)
    tyenv.add("Ity_I1")
    tmps: dict[int, IRValue] = {}
    conditions: dict[int, IRCondition] = {}
    ctx = _ctx(tyenv)
    stmt = pyvex.stmt.WrTmp(
        7, pyvex.expr.Unop("Iop_1Uto16", [pyvex.expr.RdTmp(0)]),
    )
    instr = vi._wrtmp_instr_8616(stmt, tmps, conditions, ctx)
    assert instr is not None and instr.dst is not None and instr.op == "MOV"
    assert instr.size == 2 and instr.dst.size == 2 and tmps[7].size == 2
    assert tmps[7].expr == ("Iop_1Uto16",)

