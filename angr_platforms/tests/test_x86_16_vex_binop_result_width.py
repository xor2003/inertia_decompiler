"""Result-width coherence at the typed VEX-to-IR boundary.

Layer: IR regression tests.
Responsibility: keep instruction, destination and retained-result widths tied
to the actual VEX result type while scalar operands retain their own widths.
Real VEX expressions/type environments cover comparisons, arithmetic and
independent shift counts. These checks grant no callee or emitted-C acceptance.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import partial

import angr_platforms.X86_16.ir.vex_import as vi
import archinfo
import pytest
import pyvex
from angr_platforms.X86_16.ir.core import IRCondition, IRInstr, IRValue
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


def _wrtmp(
    stmt: pyvex.stmt.WrTmp,
    tmps: dict[int, IRValue],
    conditions: dict[int, IRCondition],
    ctx: vi._StmtImportContext8616,
) -> IRInstr | None:
    """Import one real ``Ist_WrTmp`` through the production call path."""
    return vi._wrtmp_instr_8616(stmt, tmps, conditions, ctx)


def _seed_const(
    tmps: dict[int, IRValue],
    conditions: dict[int, IRCondition],
    ctx: vi._StmtImportContext8616,
    tmp_id: int,
    const: pyvex.const.IRConst,
) -> None:
    """Define one temporary from a real constant write."""
    _wrtmp(pyvex.stmt.WrTmp(tmp_id, pyvex.expr.Const(const)), tmps, conditions, ctx)


@pytest.mark.parametrize(
    ("op", "type_token", "const_factory", "operand_bytes"),
    [
        ("Iop_CmpEQ16", "Ity_I16", pyvex.const.U16, 2),
        ("Iop_CmpLT16U", "Ity_I16", pyvex.const.U16, 2),
        ("Iop_CmpNE32", "Ity_I32", pyvex.const.U32, 4),
        ("Iop_CmpEQ64", "Ity_I64", pyvex.const.U64, 8),
    ],
)
def test_comparison_result_width_is_one_byte(
    op: str, type_token: str, const_factory: Callable[[int], pyvex.const.IRConst], operand_bytes: int,
) -> None:
    """Comparison instr/dst/retained-tmp widths are the 1-byte predicate."""
    tyenv = pyvex.IRTypeEnv(_ARCH)
    tyenv.add(type_token)
    tyenv.add(type_token)
    tyenv.add("Ity_I1")
    tmps: dict[int, IRValue] = {}
    conditions: dict[int, IRCondition] = {}
    ctx = _ctx(tyenv)
    _seed_const(tmps, conditions, ctx, 0, const_factory(0x11))
    _seed_const(tmps, conditions, ctx, 1, const_factory(0x22))
    stmt = pyvex.stmt.WrTmp(
        9, pyvex.expr.Binop(op, [pyvex.expr.RdTmp(0), pyvex.expr.RdTmp(1)]),
    )
    instr = _wrtmp(stmt, tmps, conditions, ctx)
    assert instr is not None and instr.op == op
    assert instr.dst is not None and instr.dst.size == 1
    assert tmps[9].size == 1
    assert instr.size == 1
    assert [arg.size for arg in instr.args] == [operand_bytes, operand_bytes]
    assert 9 in conditions


def test_arithmetic_result_width_matches_operands() -> None:
    """A 16-bit add keeps result width 2 across instr/dst/retained tmp."""
    tyenv = pyvex.IRTypeEnv(_ARCH)
    tyenv.add("Ity_I16")
    tyenv.add("Ity_I16")
    tyenv.add("Ity_I16")
    tmps: dict[int, IRValue] = {}
    conditions: dict[int, IRCondition] = {}
    ctx = _ctx(tyenv)
    _seed_const(tmps, conditions, ctx, 0, pyvex.const.U16(1))
    _seed_const(tmps, conditions, ctx, 1, pyvex.const.U16(2))
    stmt = pyvex.stmt.WrTmp(
        9, pyvex.expr.Binop("Iop_Add16", [pyvex.expr.RdTmp(0), pyvex.expr.RdTmp(1)]),
    )
    instr = _wrtmp(stmt, tmps, conditions, ctx)
    assert instr is not None and instr.dst is not None and instr.op == "Iop_Add16"
    assert instr.size == 2 and instr.dst.size == 2 and tmps[9].size == 2
    assert [arg.size for arg in instr.args] == [2, 2]


def test_shift_keeps_independent_count_width() -> None:
    """A 16-bit shift has result width 2 while its count operand stays 1."""
    tyenv = pyvex.IRTypeEnv(_ARCH)
    tyenv.add("Ity_I16")
    tyenv.add("Ity_I16")
    tmps: dict[int, IRValue] = {}
    conditions: dict[int, IRCondition] = {}
    ctx = _ctx(tyenv)
    _seed_const(tmps, conditions, ctx, 0, pyvex.const.U16(1))
    stmt = pyvex.stmt.WrTmp(
        9,
        pyvex.expr.Binop(
            "Iop_Shl16", [pyvex.expr.RdTmp(0), pyvex.expr.Const(pyvex.const.U8(8))],
        ),
    )
    instr = _wrtmp(stmt, tmps, conditions, ctx)
    assert instr is not None and instr.dst is not None and instr.op == "Iop_Shl16"
    assert instr.size == 2 and instr.dst.size == 2 and tmps[9].size == 2
    assert [arg.size for arg in instr.args] == [2, 1]


def test_retained_tmp_preserves_value_view() -> None:
    """The retained tmp keeps its provenance decoration at result width."""
    tyenv = pyvex.IRTypeEnv(_ARCH)
    tyenv.add("Ity_I16")
    tyenv.add("Ity_I16")
    tyenv.add("Ity_I1")
    tmps: dict[int, IRValue] = {}
    conditions: dict[int, IRCondition] = {}
    ctx = _ctx(tyenv)
    _seed_const(tmps, conditions, ctx, 0, pyvex.const.U16(7))
    _seed_const(tmps, conditions, ctx, 1, pyvex.const.U16(7))
    stmt = pyvex.stmt.WrTmp(
        9, pyvex.expr.Binop("Iop_CmpEQ16", [pyvex.expr.RdTmp(0), pyvex.expr.RdTmp(1)]),
    )
    _wrtmp(stmt, tmps, conditions, ctx)
    retained = tmps[9]
    assert retained.source_tmp == 9
    assert retained.size == 1
    assert retained.expr == ("Iop_CmpEQ16",)

