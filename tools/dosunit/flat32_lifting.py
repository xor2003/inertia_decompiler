"""Layer: validation lowering adapter.

Responsibility: provide scoped i386 register and pure flag-helper lowering
through the shared SSA engine, restoring its real16 configuration on exit.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pyvex

from tools.dosunit import straightline_ssa as S

_FLAT32_GPRS: tuple[str, ...] = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
_FLAT32_REG_NAMES: tuple[str, ...] = (
    *_FLAT32_GPRS, "cc_op", "cc_dep1", "cc_dep2", "cc_ndep", "d",
    "eip", "cs", "ds", "es", "fs", "gs", "ss",
)


def _flat32_register_map() -> dict[int, tuple[str, int]]:
    """Build the flat i386 guest-offset map from the actual architecture."""
    import archinfo

    arch = archinfo.ArchX86()
    return {
        int(arch.registers[name][0]): (name, int(arch.registers[name][1]) * 8)
        for name in _FLAT32_REG_NAMES
    }


_FLAT32_REGS = _flat32_register_map()


def _flat32_register_access(offset: int, width: int | None) -> tuple[str, int, int] | None:
    """Resolve full, low-word, low-byte and legacy high-byte i386 registers."""
    for base, (name, bits) in _FLAT32_REGS.items():
        if offset == base and (width is None or width == bits):
            return name, bits, 0
        if name in _FLAT32_GPRS and offset == base and width in (8, 16):
            return name, bits, 0
        if name in _FLAT32_GPRS[:4] and offset == base + 1 and width in (None, 8):
            return name, bits, 8
    return None


def _flat32_read_register(
    reg_versions: dict[str, S.SsaExpr], offset: int, width: int, *, source: str
) -> S.SsaExpr | S.LowerFailure:
    """Read a partial register without dropping the enclosing register width."""
    access = _flat32_register_access(offset, width)
    if access is None:
        return S.LowerFailure("unsupported_ir", f"{source}: unsupported register {offset}:{width}")
    name, bits, shift = access
    value = reg_versions.get(name, S.SsaExpr("input", bits, name=name))
    if shift:
        value = S.SsaExpr("lshr", bits, (value, S.SsaExpr("const", bits, value=shift)))
    return S._coerce_width(value, width)


def _flat32_write_target(offset: int, width: int | None) -> tuple[str, int] | None:
    """Make partial writes depend on their full enclosing register."""
    access = _flat32_register_access(offset, width)
    return None if access is None else access[:2]


def _flat32_write_register(
    reg_versions: dict[str, S.SsaExpr], offset: int, expr: S.SsaExpr
) -> S.LowerFailure | None:
    """Preserve upper bits for i386 byte/word writes, including AH/CH/DH/BH."""
    access = _flat32_register_access(offset, expr.width)
    if access is None:
        return S.LowerFailure("unsupported_ir", f"unsupported register write {offset}:{expr.width}")
    name, bits, shift = access
    if expr.width == bits:
        reg_versions[name] = expr
        return None
    previous = reg_versions.get(name, S.SsaExpr("input", bits, name=name))
    mask = ((1 << bits) - 1) ^ (((1 << expr.width) - 1) << shift)
    kept = S.SsaExpr("and", bits, (previous, S.SsaExpr("const", bits, value=mask)))
    inserted = S._coerce_width(expr, bits)
    if shift:
        inserted = S.SsaExpr("shl", bits, (inserted, S.SsaExpr("const", bits, value=shift)))
    reg_versions[name] = S.SsaExpr("or", bits, (kept, inserted))
    return None


_ORIGINAL_LOWER_EXPR = S._lower_expr
_FLAT32_CCALL_ARITIES = {
    "x86g_calculate_condition": 5,
    "x86g_calculate_eflags_c": 4,
    "x86g_calculate_eflags_all": 4,
}


def _flat32_lower_expr(
    expr: pyvex.expr.IRExpr,
    **kwargs: Any,  # noqa: ANN401 - opaque third-party expression kwargs
) -> S.SsaExpr | S.LowerFailure:
    """Abstract the known pure lazy-flag helpers; refuse all other CCalls."""
    if isinstance(expr, pyvex.expr.Const) and not isinstance(expr.con.value, int):
        return S.LowerFailure(
            "unsupported_ir", "non-integer constants are outside the integer model"
        )
    if not isinstance(expr, pyvex.expr.CCall):
        return _ORIGINAL_LOWER_EXPR(expr, **kwargs)
    if len(expr.args) != _FLAT32_CCALL_ARITIES.get(expr.cee.name):
        return S.LowerFailure("unsupported_ir", f"unsupported CCall: {expr.cee.name}")
    args: list[S.SsaExpr] = []
    for argument in expr.args:
        lowered = _flat32_lower_expr(argument, **kwargs)
        if isinstance(lowered, S.LowerFailure):
            return lowered
        args.append(lowered)
    return S.SsaExpr(f"summary_{expr.cee.name}", expr.result_size(kwargs["tyenv"]), tuple(args))


@contextmanager
def _flat32_seam() -> Iterator[None]:
    """Install the staged flat32 register/expression seam on the SSA owner.

    This is the same isolated patch contract the flat32 drivers' adapter
    installs; it is scoped to this module's lowering calls and restored on
    every exit path.
    """
    previous = (
        S.REG_BY_OFFSET, S.SSA_REGISTER_WIDTHS, S.INTERNAL_STATE_REGS,
        S.HIGH_HALF_REGS, S._read_register, S._write_register,
        S._register_write_target, S._lower_expr,
    )
    try:
        S.REG_BY_OFFSET = _FLAT32_REGS
        S.SSA_REGISTER_WIDTHS = dict(_FLAT32_REGS.values())
        S.INTERNAL_STATE_REGS = _FLAT32_REG_NAMES
        S.HIGH_HALF_REGS = ()
        S._read_register = _flat32_read_register
        S._write_register = _flat32_write_register
        S._register_write_target = _flat32_write_target
        S._lower_expr = _flat32_lower_expr
        yield
    finally:
        (
            S.REG_BY_OFFSET, S.SSA_REGISTER_WIDTHS, S.INTERNAL_STATE_REGS,
            S.HIGH_HALF_REGS, S._read_register, S._write_register,
            S._register_write_target, S._lower_expr,
        ) = previous


