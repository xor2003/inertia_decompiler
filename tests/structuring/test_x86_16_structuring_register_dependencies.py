"""Tests for evidence-backed same-block return register dependencies."""

from __future__ import annotations

from angr import ailment
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.structuring.register_dependencies import (
    resolve_same_block_data_register_dependencies_8616,
)


def _copy_expression(expr: object) -> object:
    return expr.copy() if isinstance(expr, ailment.Expr.Expression) else expr


def _resolve_temporaries(expr: object, _statements: object, _before_index: int) -> object:
    return expr


def _register_name(arch: Arch86_16, expr: object) -> str | None:
    if not isinstance(expr, ailment.Expr.Register):
        return None
    return arch.translate_register_name(expr.reg_offset, expr.bits // 8)


def test_resolves_secondary_data_register_in_return_expression() -> None:
    arch = Arch86_16()
    ax = ailment.Expr.Register(1, arch.registers["ax"][0], 16, reg_name="ax")
    dx = ailment.Expr.Register(2, arch.registers["dx"][0], 16, reg_name="dx")
    value = ailment.Expr.Const(3, 0x1234, 16)
    assignment = ailment.Stmt.Assignment(4, dx, value)
    expression = ailment.Expr.BinaryOp(5, "Add", [ax, dx], False, bits=16)

    resolved = resolve_same_block_data_register_dependencies_8616(
        expression,
        [assignment],
        before_index=1,
        register_name=lambda candidate: _register_name(arch, candidate),
        resolve_temporaries=_resolve_temporaries,
        copy_expression=_copy_expression,
    )

    assert isinstance(resolved, ailment.Expr.BinaryOp)
    assert resolved.operands[0] == ax
    assert isinstance(resolved.operands[1], ailment.Expr.Const)
    assert resolved.operands[1].value == 0x1234


def test_refuses_secondary_register_after_overlapping_partial_write() -> None:
    arch = Arch86_16()
    dx = ailment.Expr.Register(1, arch.registers["dx"][0], 16, reg_name="dx")
    dl = ailment.Expr.Register(2, arch.registers["dl"][0], 8, reg_name="dl")
    dx_assignment = ailment.Stmt.Assignment(3, dx, ailment.Expr.Const(4, 0x1234, 16))
    dl_assignment = ailment.Stmt.Assignment(5, dl, ailment.Expr.Const(6, 0x56, 8))

    resolved = resolve_same_block_data_register_dependencies_8616(
        dx,
        [dx_assignment, dl_assignment],
        before_index=2,
        register_name=lambda candidate: _register_name(arch, candidate),
        resolve_temporaries=_resolve_temporaries,
        copy_expression=_copy_expression,
    )

    assert resolved == dx
