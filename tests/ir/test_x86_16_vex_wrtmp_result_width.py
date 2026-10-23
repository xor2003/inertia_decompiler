"""Typed result widths without inventing unsupported value semantics.

Layer: IR regression tests.
Responsibility: retain VEX result-width evidence across generic temporary
writes while unbound ITE values stay UNKNOWN. Bound atomic selections retain
all three input dependencies. Real VEX ITE, constants,
register reads and widening operations cover instruction/destination/retained
result agreement. This is not emitted-C acceptance.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import partial

import archinfo
import pytest
import pyvex

import inertia.ir.vex_import as vi
from inertia.ir.core import IRCondition, IRValue, MemSpace
from inertia.ir.vex_condition_demand import (
    VexConditionDemand8616,
    VexConditionDemandStats8616,
)
from inertia.ir.vex_condition_lifting import _try_ite_condition_8616

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


@pytest.mark.parametrize("bits", [8, 16, 32])
@pytest.mark.parametrize(("true", "false"), [(1, 0), (0, 1), (2, 0), (1, 1)])
def test_boolean_ite_retains_truncated_captured_guard(bits: int, true: int, false: int) -> None:
    """Boolean arms retain the actual guard conversion and immutable capture."""
    captured = IRValue(
        MemSpace.REG, name={8: "al", 16: "ax", 32: "eax"}[bits],
        size=bits // 8, source_tmp=7,
    )
    tyenv = pyvex.IRTypeEnv(_ARCH, types=[f"Ity_I{bits}"] * 8)
    guard = pyvex.expr.Unop(f"Iop_{bits}to1", [pyvex.expr.RdTmp(7)])
    expression = pyvex.expr.ITE(
        guard, pyvex.expr.Const(pyvex.const.U16(false)),
        pyvex.expr.Const(pyvex.const.U16(true)),
    )
    condition = _try_ite_condition_8616(
        expression, {7: captured}, {},
        expr_to_value=partial(vi._expr_to_value, type_environment=tyenv), tmp_exprs=None,
    )
    if (true, false) not in ((1, 0), (0, 1)):
        assert condition is None
        return
    assert condition is not None
    assert condition.op == ("nonzero" if true else "zero")
    assert condition.width_bits == 8
    atom = condition.args[0]
    assert isinstance(atom, IRValue)
    assert atom.source_tmp is None and atom.name == captured.name
    assert atom.active_unary is not None
    assert atom.active_unary.op == f"Iop_{bits}to1"
    assert atom.active_unary.result_bits == 1
    assert atom.active_unary.operand == captured
    assert atom.active_unary.operand.source_tmp == 7
    assert atom.expr == (f"Iop_{bits}to1",) and atom.size == 1


def test_boolean_ite_preserves_recovered_tmp_comparison() -> None:
    """A generic fallback must not replace an existing richer guard."""
    tyenv = pyvex.IRTypeEnv(_ARCH, types=["Ity_I16"] * 8 + ["Ity_I1"])
    captured = IRValue(MemSpace.REG, name="ax", size=2, source_tmp=7)
    comparison = pyvex.expr.Binop(
        "Iop_CmpEQ16", [pyvex.expr.RdTmp(7), pyvex.expr.Const(pyvex.const.U16(5))],
    )
    expression = pyvex.expr.ITE(
        pyvex.expr.RdTmp(8), pyvex.expr.Const(pyvex.const.U16(0)),
        pyvex.expr.Const(pyvex.const.U16(1)),
    )
    condition = _try_ite_condition_8616(
        expression, {7: captured}, {},
        expr_to_value=partial(vi._expr_to_value, type_environment=tyenv),
        tmp_exprs={8: comparison},
    )
    assert condition is not None and condition.op == "eq"
    assert condition.width_bits == 16
    assert condition.args[0] == captured


@pytest.mark.parametrize("bits", [1, 8, 16, 32, 64])
def test_bound_ite_retains_guard_arms_and_result(bits: int) -> None:
    """A bound select retains true/false ordering and its exact result width."""
    from inertia.ir.scalar_instruction_effects import (
        ScalarInstructionEffectKind8616,
        scalar_instruction_effect_8616,
    )

    tyenv = pyvex.IRTypeEnv(_ARCH)
    tyenv.add("Ity_I1")
    guard = IRValue(MemSpace.TMP, name="t0", size=1, source_tmp=0)
    tmps = {0: guard}
    factory = {1: pyvex.const.U1, 8: pyvex.const.U8, 16: pyvex.const.U16,
               32: pyvex.const.U32, 64: pyvex.const.U64}[bits]
    # VEX's constructor takes false before true; owned IR uses semantic order.
    data = pyvex.expr.ITE(
        pyvex.expr.RdTmp(0), pyvex.expr.Const(factory(0)),
        pyvex.expr.Const(factory(1)),
    )
    instr = vi._wrtmp_instr_8616(pyvex.stmt.WrTmp(9, data), tmps, {}, _ctx(tyenv))
    assert instr is not None and instr.dst is not None
    assert instr.op == f"SELECT{bits}"
    assert instr.args[0] is guard
    assert isinstance(instr.args[1], IRValue) and instr.args[1].const == 1
    assert isinstance(instr.args[2], IRValue) and instr.args[2].const == 0
    assert instr.size == instr.dst.size == tmps[9].size == (bits + 7) // 8
    assert tmps[9].space is MemSpace.TMP and tmps[9].source_tmp == 9
    assert scalar_instruction_effect_8616(instr).kind is (
        ScalarInstructionEffectKind8616.CLOSED_DESTINATION
    )


def test_select_keeps_all_inputs_live_but_dead_select_can_be_removed() -> None:
    """A live select needs all input definitions; dead pure selections do not."""
    from inertia.ir.core import IRBlock, IRInstr
    from inertia.ir.dead_temporary_normalization import normalize_dead_temporaries_8616
    from inertia.ir.ssa import build_x86_16_block_local_ssa

    guard = IRValue(MemSpace.TMP, name="t0", size=1, source_tmp=0)
    true_value = IRValue(MemSpace.TMP, name="t1", size=2, source_tmp=1)
    false_value = IRValue(MemSpace.TMP, name="t2", size=2, source_tmp=2)
    dst = IRValue(MemSpace.TMP, name="t3", size=2, source_tmp=3)
    inputs = (guard, true_value, false_value)
    definitions = tuple(
        IRInstr(op="MOV", dst=value, args=(IRValue(MemSpace.CONST, const=i, size=value.size),), size=value.size)
        for i, value in enumerate(inputs)
    )
    select = IRInstr(op="SELECT16", dst=dst, args=inputs, size=2)
    store_result = IRInstr(op="MOV", dst=IRValue(MemSpace.REG, name="ax", size=2), args=(dst,), size=2)
    live = IRBlock(addr=0x100, instrs=(*definitions, select, store_result))
    normalized = normalize_dead_temporaries_8616(live)
    assert normalized.block.instrs == live.instrs
    ssa = build_x86_16_block_local_ssa(live)
    assert len(ssa.instrs[3].args) == 3
    dead = IRBlock(addr=0x100, instrs=(*definitions, select))
    assert normalize_dead_temporaries_8616(dead).block.instrs == ()


@pytest.mark.parametrize("guard_bits", [8, 16])
def test_select_rejects_non_boolean_guard(guard_bits: int) -> None:
    """A byte value equal to one is not proof of a one-bit predicate."""
    tyenv = pyvex.IRTypeEnv(_ARCH, types=[f"Ity_I{guard_bits}"])
    tmps = {0: IRValue(MemSpace.TMP, name="t0", size=guard_bits // 8, source_tmp=0)}
    data = pyvex.expr.ITE(pyvex.expr.RdTmp(0), pyvex.expr.Const(pyvex.const.U16(0)),
                         pyvex.expr.Const(pyvex.const.U16(1)))
    instr = vi._wrtmp_instr_8616(pyvex.stmt.WrTmp(9, data), tmps, {}, _ctx(tyenv))
    assert instr is not None and instr.op == "MOV"
    assert tmps[9].space is MemSpace.UNKNOWN


@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("true_arm", [False, True])
def test_select_refuses_unbound_or_nested_arm(nested: bool, true_arm: bool) -> None:
    """No missing definition or nested computation may disappear into a select."""
    tyenv = pyvex.IRTypeEnv(_ARCH, types=["Ity_I1", "Ity_I16"])
    tmps = {0: IRValue(MemSpace.TMP, name="t0", size=1, source_tmp=0)}
    unknown = (pyvex.expr.Unop("Iop_Not16", [pyvex.expr.Const(pyvex.const.U16(0))])
               if nested else pyvex.expr.RdTmp(1))
    known = pyvex.expr.Const(pyvex.const.U16(3))
    arms = (known, unknown) if true_arm else (unknown, known)
    data = pyvex.expr.ITE(pyvex.expr.RdTmp(0), *arms)
    instr = vi._wrtmp_instr_8616(pyvex.stmt.WrTmp(9, data), tmps, {}, _ctx(tyenv))
    assert instr is not None and instr.op == "MOV"
    assert tmps[9].space is MemSpace.UNKNOWN


def test_select_arm_keeps_captured_register_before_overwrite() -> None:
    """An arm captured from AX must retain its TMP snapshot after AX changes."""
    from inertia.ir.core import IRBlock, IRInstr
    from inertia.ir.ssa import build_x86_16_block_local_ssa

    tyenv = pyvex.IRTypeEnv(_ARCH, types=["Ity_I1", "Ity_I16"])
    captured = IRValue(MemSpace.REG, name="ax", size=2, source_tmp=1)
    tmps = {0: IRValue(MemSpace.TMP, name="t0", size=1, source_tmp=0), 1: captured}
    data = pyvex.expr.ITE(pyvex.expr.RdTmp(0), pyvex.expr.Const(pyvex.const.U16(4)), pyvex.expr.RdTmp(1))
    select = vi._wrtmp_instr_8616(pyvex.stmt.WrTmp(9, data), tmps, {}, _ctx(tyenv))
    assert select is not None and select.args[1] is captured
    read = IRInstr(op="MOV", dst=IRValue(MemSpace.TMP, name="t1", source_tmp=1, size=2),
                   args=(IRValue(MemSpace.REG, name="ax", size=2),), size=2)
    overwrite = IRInstr(op="MOV", dst=IRValue(MemSpace.REG, name="ax", size=2),
                        args=(IRValue(MemSpace.CONST, const=99, size=2),), size=2)
    ssa = build_x86_16_block_local_ssa(IRBlock(addr=0x100, instrs=(read, overwrite, select)))
    arm = ssa.instrs[2].args[1]
    assert isinstance(arm, IRValue) and arm.source_tmp == 1
    assert arm.version != ssa.instrs[1].dst.version
