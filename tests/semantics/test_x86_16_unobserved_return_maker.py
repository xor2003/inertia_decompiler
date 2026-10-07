"""AIL return-maker regressions for closed unobserved result evidence."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr import ailment
from angr.analyses.decompiler.return_maker import ReturnMaker
from angr.calling_conventions import SimRegArg
from angr.sim_type import SimTypeShort
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.frontend.x86_16.decompiler_return_compat import (
    apply_x86_16_decompiler_return_compatibility,
)


class _SingleBlockGraph:
    """Minimal third-party graph surface consumed by ReturnMaker."""

    def __init__(self, block: object) -> None:
        self._block = block

    def nodes(self) -> list[object]:
        """Return the only AIL block in this fixture graph."""
        return [self._block]

    def predecessors(self, _node: object) -> list[object]:
        """Return no predecessors for the single-block fixture."""
        return []


@pytest.mark.parametrize("intervening_call", [None, "side_effect", "direct", "assignment"])
def test_proven_unobserved_return_keeps_binary_ax_value(monkeypatch, intervening_call) -> None:
    """Preserve the proven terminal AX value even when current callers ignore it."""
    monkeypatch.setattr(ReturnMaker, "_handle_Return", lambda *_args: "fallback")
    apply_x86_16_decompiler_return_compatibility()

    arch = Arch86_16()
    ax = ailment.Expr.Register(
        1,
        arch.registers["ax"][0],
        16,
        reg_name="ax",
        ins_addr=0x10517,
    )
    assignment = ailment.Stmt.Assignment(
        2,
        ax,
        ailment.Expr.Const(3, 75, 16, ins_addr=0x10517),
        ins_addr=0x10517,
    )
    ret_stmt = ailment.Stmt.Return(4, [], ins_addr=0x1051F)
    block = SimpleNamespace(statements=[assignment, ret_stmt])
    if intervening_call:
        call = ailment.Expr.Call(10, ailment.Expr.Const(11, 0x2000, 16), bits=16)
        if intervening_call == "side_effect":
            barrier = ailment.Stmt.SideEffectStatement(12, call, ins_addr=0x1051A)
        elif intervening_call == "assignment":
            dx = ailment.Expr.Register(13, arch.registers["dx"][0], 16, reg_name="dx")
            barrier = ailment.Stmt.Assignment(12, dx, call, ins_addr=0x1051A)
        else:
            barrier = call
        block.statements.insert(1, barrier)
    function = SimpleNamespace(
        addr=0x1000,
        prototype=SimpleNamespace(returnty=SimTypeShort(False)),
        calling_convention=SimpleNamespace(return_val=lambda _returnty: SimRegArg("ax", 2)),
        is_prototype_guessed=True,
        _inertia_return_compat_caller_uses_return_8616=False,
    )
    maker = SimpleNamespace(
        function=function,
        graph=_SingleBlockGraph(block),
        arch=arch,
        _next_atom=lambda: 99,
        _new_block=None,
    )

    result = ReturnMaker._handle_Return(maker, len(block.statements) - 1, ret_stmt, block)

    assert isinstance(result, ailment.Stmt.Return)
    if intervening_call:
        assert result.ret_exprs == []
        return
    assert len(result.ret_exprs) == 1
    assert isinstance(result.ret_exprs[0], ailment.Expr.Register)
    assert result.ret_exprs[0].reg_offset == ax.reg_offset
    assert assignment.src.value == 75
    assert isinstance(function.prototype.returnty, SimTypeShort)


@pytest.mark.parametrize("observed", [True, False, None])
@pytest.mark.parametrize("change", ["bp_restore", "partial_write", "memory_write"])
def test_return_captures_ax_after_producer_dependencies_change(monkeypatch, observed, change):
    """Producer expressions cannot be moved past register or memory mutations."""
    monkeypatch.setattr(ReturnMaker, "_handle_Return", lambda *_args: "fallback")
    apply_x86_16_decompiler_return_compatibility()
    arch = Arch86_16()
    ax = ailment.Expr.Register(1, arch.registers["ax"][0], 16, reg_name="ax", ins_addr=0x1006)
    bp = ailment.Expr.Register(2, arch.registers["bp"][0], 16, reg_name="bp", ins_addr=0x1006)
    value = ailment.Expr.BinaryOp(
        3, "Sub", [bp, ailment.Expr.Const(4, 2, 16)], False, bits=16, ins_addr=0x1006,
    )
    assignment = ailment.Stmt.Assignment(5, ax, value, ins_addr=0x1006)
    restore = ailment.Stmt.Assignment(6, bp, ailment.Expr.Const(7, 0x4000, 16), ins_addr=0x100e)
    if change == "partial_write":
        assignment = ailment.Stmt.Assignment(5, ax, ailment.Expr.Const(4, 75, 16), ins_addr=0x1006)
        al = ailment.Expr.Register(2, arch.registers["al"][0], 8, reg_name="al", ins_addr=0x100e)
        restore = ailment.Stmt.Assignment(6, al, ailment.Expr.Const(7, 7, 8), ins_addr=0x100e)
    elif change == "memory_write":
        address = ailment.Expr.Const(4, 0x200, 16)
        assignment = ailment.Stmt.Assignment(
            5, ax, ailment.Expr.Load(3, address, 2, "Iend_LE"), ins_addr=0x1006,
        )
        restore = ailment.Stmt.Store(6, address, ailment.Expr.Const(7, 7, 16), 2, "Iend_LE", ins_addr=0x100e)
    ret = ailment.Stmt.Return(8, [], ins_addr=0x100f)
    block = SimpleNamespace(statements=[assignment, restore, ret])
    function = SimpleNamespace(
        addr=0x1000, prototype=SimpleNamespace(returnty=SimTypeShort(False)),
        calling_convention=SimpleNamespace(return_val=lambda _: SimRegArg("ax", 2)),
        is_prototype_guessed=True, _inertia_return_compat_caller_uses_return_8616=observed,
    )
    maker = SimpleNamespace(
        function=function, graph=_SingleBlockGraph(block), arch=arch, _next_atom=lambda: 99, _new_block=None,
    )

    result = ReturnMaker._handle_Return(maker, 2, ret, block)

    assert isinstance(result, ailment.Stmt.Return)
    captured = result.ret_exprs[0]
    assert isinstance(captured, ailment.Expr.Register)
    assert captured.reg_offset == arch.registers["ax"][0]
    assert captured.bits == 16
    assert captured.tags["ins_addr"] == 0x100f
    assert ret.ret_exprs == []
    assert block.statements == [assignment, restore, ret]
