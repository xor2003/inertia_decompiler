"""Native port-immediate controls against the independent upstream X86 lifter."""
from __future__ import annotations

import archinfo
import pytest
import pyvex
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.io import retained_port_events

_PORT_HELPERS = frozenset({"x86g_dirtyhelper_IN", "x86g_dirtyhelper_OUT"})

#: Zero-extension ops leave a port value unchanged.  Narrowing or arithmetic
#: ops are deliberately absent so any other expression shape refuses loudly.
_WIDENING_OPS = frozenset({"Iop_8Uto16", "Iop_8Uto32", "Iop_16Uto32"})


def _const_value(
    expr: pyvex.expr.IRExpr,
    tmps: dict[int, int | None],
    puts: dict[int, pyvex.expr.IRExpr],
) -> int | None:
    """Resolve one port expression to a constant from same-block evidence.

    Accepts a direct constant, an earlier temp binding, a zero-extension of a
    resolvable operand, or a guest-register GET whose offset was PUT to a
    same-width constant earlier in the block.  Returns ``None`` when none of
    those prove the value; callers then refuse instead of guessing.
    """
    if isinstance(expr, pyvex.expr.Const):
        return int(expr.con.value)
    if isinstance(expr, pyvex.expr.RdTmp):
        return tmps.get(expr.tmp)
    if isinstance(expr, pyvex.expr.Get):
        bound = puts.get(expr.offset)
        if (
            isinstance(bound, pyvex.expr.Const)
            and pyvex.get_type_size(expr.ty) == bound.con.size
        ):
            return int(bound.con.value)
        return None
    if isinstance(expr, pyvex.expr.Unop) and expr.op in _WIDENING_OPS:
        return _const_value(expr.args[0], tmps, puts)
    return None


def _port_argument(code: bytes, arch: archinfo.Arch) -> int:
    """Extract the actual helper's constant port after native VEX optimization.

    The port argument may reach the dirty helper as a constant, a temp chain,
    or a guest-register read of a value put earlier in the same block; each
    shape resolves only through in-block evidence and refuses otherwise.
    """
    block = pyvex.IRSB(code, 0x100, arch, opt_level=1)
    return _port_from_block(block)


def _port_from_block(block: pyvex.IRSB) -> int:
    """Resolve the port in statement order without replaying register reads."""
    tmps: dict[int, int | None] = {}
    puts: dict[int, pyvex.expr.IRExpr] = {}
    resolved: int | None = None
    dirty_count = 0
    for statement in block.statements:
        if isinstance(statement, pyvex.stmt.WrTmp):
            # A temporary captures the register value at this statement.
            tmps[statement.tmp] = _const_value(statement.data, tmps, puts)
        elif isinstance(statement, pyvex.stmt.Put):
            # Fail closed on overlapping guest-register writes, including
            # different-width writes starting at a different byte offset.
            start = statement.offset
            end = start + statement.data.result_size(block.tyenv) // 8
            for offset, value in tuple(puts.items()):
                previous_end = offset + value.result_size(block.tyenv) // 8
                if start < previous_end and offset < end:
                    del puts[offset]
            puts[statement.offset] = statement.data
        elif isinstance(statement, pyvex.stmt.PutI):
            # An indexed put may clobber any tracked register.
            puts.clear()
        elif isinstance(statement, pyvex.stmt.Dirty):
            assert statement.cee.name in _PORT_HELPERS, statement.cee.name
            assert dirty_count == 0
            dirty_count += 1
            resolved = _const_value(statement.args[0], tmps, puts)
            # A dirty helper may write guest state for later statements.
            puts.clear()
    assert dirty_count == 1
    assert resolved is not None
    return resolved


def test_port_resolver_captures_register_read_before_overwrite() -> None:
    """A later guest-register write cannot retroactively change an SSA temp."""
    with retained_port_events():
        block = pyvex.IRSB(bytes.fromhex("ba80ffec"), 0x100, Arch86_16(), opt_level=1)
    read = next(
        statement.data for statement in block.statements
        if isinstance(statement, pyvex.stmt.WrTmp)
        and isinstance(statement.data, pyvex.expr.Get)
    )
    dirty_index = next(
        index for index, statement in enumerate(block.statements)
        if isinstance(statement, pyvex.stmt.Dirty)
    )
    block.statements.insert(
        dirty_index,
        pyvex.stmt.Put(pyvex.expr.Const(pyvex.const.U16(0x1234)), read.offset),
    )
    assert _port_from_block(block) == 0xFF80


def test_port_resolver_refuses_overlapping_partial_write() -> None:
    """An intervening byte write invalidates a previously recorded word."""
    with retained_port_events():
        block = pyvex.IRSB(bytes.fromhex("ba80ffec"), 0x100, Arch86_16(), opt_level=1)
    read_index, read = next(
        (index, statement.data) for index, statement in enumerate(block.statements)
        if isinstance(statement, pyvex.stmt.WrTmp)
        and isinstance(statement.data, pyvex.expr.Get)
    )
    block.statements.insert(
        read_index,
        pyvex.stmt.Put(pyvex.expr.Const(pyvex.const.U8(0x12)), read.offset + 1),
    )
    with pytest.raises(AssertionError):
        _port_from_block(block)


@pytest.mark.parametrize("local,upstream", [
    ("e4", "e4"), ("e6", "e6"),
    ("e5", "66e5"), ("e7", "66e7"),
    ("66e5", "e5"), ("66e7", "e7"),
])
@pytest.mark.parametrize("port", [0x7F, 0x80, 0xFF])
def test_immediate_port_matches_upstream_x86(local: str, upstream: str, port: int) -> None:
    """All six forms zero-extend their unsigned imm8 ports in both VEX lifters."""
    with retained_port_events():
        actual = _port_argument(bytes.fromhex(local) + bytes([port]), Arch86_16())
    expected = _port_argument(bytes.fromhex(upstream) + bytes([port]), archinfo.ArchX86())
    assert actual == expected == port


def test_native_dx_port_is_not_truncated() -> None:
    """MOV DX,0xff80 followed by IN AL,DX retains the full port address."""
    with retained_port_events():
        actual = _port_argument(bytes.fromhex("ba80ffec"), Arch86_16())
    expected = _port_argument(bytes.fromhex("66ba80ffec"), archinfo.ArchX86())
    assert actual == expected == 0xFF80
