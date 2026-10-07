"""Native-byte and genuine-VEX controls for the typed ``active_unary``
value contract.

Layer: Tests.
Responsibility: preserve exact unary computation and captured-value identity.

Every positive case drives real pyvex lifts (native instruction bytes) or
real pyvex expressions through the production-shaped importer, then
consumes the typed ``IRValue`` through the invocation simulator
(``_simulate_*_8616`` / ``_eval_value_8616``) and the private edge
feasibility evaluator (``_kb_eval_value_8616``). Corruption controls
forge or mutate the typed evidence itself.
"""

from __future__ import annotations

import pytest
import pyvex
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
import inertia.ir.real16_edge_feasibility8616 as edge
import inertia.ir.real16_invocation_domain as domain
import inertia.ir.vex_import as vex_import
from inertia.ir.core import (
    IRActiveUnary8616,
    IRValue,
    MemSpace,
)
from inertia.ir.vex_condition_demand import (
    VexConditionDemand8616,
    VexConditionDemandStats8616,
)

pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

_ARCH = Arch86_16()
_DEMAND = VexConditionDemand8616(frozenset(), VexConditionDemandStats8616())


def _import_bytes(raw: bytes) -> tuple[list, dict, dict]:
    """Lift one native instruction and import every statement to rows."""
    vex = pyvex.IRSB(raw, 0x1000, _ARCH, num_inst=1, opt_level=0)
    views: dict = {}
    conditions: dict = {}
    tmp_exprs: dict = {}
    imported = []
    addr = 0x1000
    for stmt in vex.statements:
        if stmt.tag == "Ist_IMark":
            addr = stmt.addr
        row = vex_import._stmt_to_instr(
            stmt,
            views,
            conditions,
            instruction_addr=addr,
            segment_hints={},
            tmp_exprs=tmp_exprs,
            type_environment=vex.tyenv,
            condition_demand=_DEMAND,
        )
        if row is not None:
            imported.append(row)
    return imported, views, tmp_exprs


def _simulate(rows: list, registers: dict[str, int]) -> dict[str, int]:
    """Run imported rows through the invocation value consumers."""
    tmps: dict[int, int] = {}
    dirty: set[str] = set()
    for instruction in rows:
        dst = instruction.dst
        if dst is not None and dst.space is MemSpace.TMP:
            domain._simulate_tmp_write_8616(instruction, dst, registers, tmps)
        elif dst is not None and dst.space is MemSpace.REG:
            domain._simulate_reg_write_8616(
                instruction, dst, registers, tmps, dirty
            )
        else:
            raise AssertionError(f"unexpected row {instruction.to_dict()}")
    return registers


def test_native_xchg_ax_bx_reads_captured_temps() -> None:
    """``xchg ax,bx`` (0x93) captures both operands before writing either.

    The second write must read the *captured* ax (0x1234 into bx via
    tmp0's captured bx and tmp1's captured ax), not the just-written
    register. Exact expected values, not merely non-``None``.
    """
    rows, _views, _exprs = _import_bytes(bytes.fromhex("93"))
    registers = _simulate(rows, {"ax": 0x1234, "bx": 0x5678})
    assert domain._register_read_8616("ax", registers) == 0x5678
    assert domain._register_read_8616("bx", registers) == 0x1234


def test_native_movsx_eax_ax_sign_extends() -> None:
    """``movsx eax,ax`` (66 0f bf c0) sign-extends 0x8000 to 0xffff8000.

    The lifter emits a genuine ``Iop_16Sto32`` Unop; the typed active
    evidence must produce the sign-extended constant, not the raw
    register read (the former 0x8000 mis-evaluation).
    """
    rows, _views, _exprs = _import_bytes(bytes.fromhex("660fbfc0"))
    assert any(
        arg is not None and arg.active_unary is not None
        for row in rows
        for arg in row.args
    ), "native MOVSX lift must carry active unary evidence"
    registers = _simulate(rows, {"ax": 0x8000})
    assert domain._register_read_8616("eax", registers) == 0xFFFF8000


def _convert(expr: object, tmps: dict, type_environment: object) -> IRValue:
    """Convert one genuine VEX expression through the real importer."""
    return vex_import._expr_to_value(
        expr, tmps, {}, type_environment=type_environment
    )


def _env(*types: str) -> object:
    """A real pyvex type environment for the given tmp types."""
    return pyvex.IRTypeEnv(_ARCH, types=list(types))


def test_nested_signed_unsigned_conversions_distinguish() -> None:
    """``16Uto32(8Sto16(t7))`` and ``16Uto32(8Uto16(t7))`` differ.

    These previously serialized to identical views — proof-corrigible
    information loss. Typed nested evidence must keep the inner sign op,
    and consumers must produce 0xff80 vs 0x80 at tmp7=0x80.
    """
    env = _env(*["Ity_I8"] * 8)
    tmps = {7: IRValue(MemSpace.TMP, size=1, source_tmp=7)}
    signed = _convert(
        pyvex.expr.Unop(
            "Iop_16Uto32",
            [
                pyvex.expr.Unop(
                    "Iop_8Sto16", [pyvex.expr.RdTmp(7)]
                )
            ],
        ),
        tmps,
        env,
    )
    unsigned = _convert(
        pyvex.expr.Unop(
            "Iop_16Uto32",
            [
                pyvex.expr.Unop(
                    "Iop_8Uto16", [pyvex.expr.RdTmp(7)]
                )
            ],
        ),
        tmps,
        env,
    )
    assert signed.to_dict() != unsigned.to_dict()
    assert signed.active_unary is not None
    assert signed.active_unary.operand.active_unary is not None
    assert signed.active_unary.operand.active_unary.op == "Iop_8Sto16"
    captured = {7: 0x80}
    assert domain._eval_value_8616(signed, {}, captured) == 0xFF80
    assert domain._eval_value_8616(unsigned, {}, captured) == 0x80
    kb_captured = {7: (0xFF, 0x80)}
    assert edge._kb_eval_value_8616(signed, {}, kb_captured) == (
        0xFFFFFFFF,
        0xFF80,
    )
    assert edge._kb_eval_value_8616(unsigned, {}, kb_captured) == (
        0xFFFFFFFF,
        0x80,
    )


def test_high_half_extraction_is_exact() -> None:
    """``32HIto16(t7)`` returns the operand's high half, not its low."""
    env = _env(*["Ity_I32"] * 8)
    value = _convert(
        pyvex.expr.Unop("Iop_32HIto16", [pyvex.expr.RdTmp(7)]),
        {7: IRValue(MemSpace.TMP, size=4, source_tmp=7)},
        env,
    )
    assert domain._eval_value_8616(value, {}, {7: 0x12345678}) == 0x1234
    assert edge._kb_eval_value_8616(
        value, {}, {7: (0xFFFFFFFF, 0x12345678)}
    ) == (0xFFFF, 0x1234)


def test_active_not_and_captured_readback() -> None:
    """A genuine ``WrTmp`` NOT producer computes once; its captured
    reference reads the stored result without re-inverting."""
    env = _env(*["Ity_I16"] * 16)
    tmps: dict = {7: IRValue(MemSpace.TMP, size=2, source_tmp=7)}
    tmp_exprs: dict = {}
    ctx = vex_import._StmtImportContext8616(
        lambda expr, t, c: _convert(expr, t, env),
        0x1000,
        {},
        tmp_exprs,
        env,
        _DEMAND,
    )
    row = vex_import._wrtmp_instr_8616(
        pyvex.stmt.WrTmp(
            8,
            pyvex.expr.Unop(
                "Iop_Not16", [pyvex.expr.RdTmp(7)]
            ),
        ),
        tmps,
        {},
        ctx,
    )
    assert row is not None
    producer_arg = row.args[0]
    assert producer_arg.active_unary is not None
    assert producer_arg.active_unary.op == "Iop_Not16"
    # The stored view of tmp8 is the computed result — no active evidence.
    stored = tmps[8]
    assert stored.active_unary is None
    assert stored.source_tmp == 8
    evaluated_tmps: dict[int, int] = {7: 0x00F0}
    domain._simulate_tmp_write_8616(row, row.dst, {}, evaluated_tmps)
    assert evaluated_tmps[8] == 0xFF0F
    # Read-back of the captured tmp8 returns 0xff0f verbatim.
    read = _convert(pyvex.expr.RdTmp(8), tmps, env)
    assert domain._eval_value_8616(read, {}, evaluated_tmps) == 0xFF0F
    assert edge._kb_eval_value_8616(
        read, {}, {8: (0xFFFF, 0xFF0F)}
    ) == (0xFFFF, 0xFF0F)


def test_truncation_is_exact() -> None:
    """``16to8(t7)`` keeps only the operand's proven low byte."""
    env = _env(*["Ity_I16"] * 8)
    value = _convert(
        pyvex.expr.Unop("Iop_16to8", [pyvex.expr.RdTmp(7)]),
        {7: IRValue(MemSpace.TMP, size=2, source_tmp=7)},
        env,
    )
    assert domain._eval_value_8616(value, {}, {7: 0x12FF}) == 0xFF
    assert edge._kb_eval_value_8616(value, {}, {7: (0xFFFF, 0x12FF)}) == (
        0xFF,
        0xFF,
    )
    # Unknown high bits propagate exactly: low byte stays proven.
    assert edge._kb_eval_value_8616(value, {}, {7: (0x0FFF, 0x02FF)}) == (
        0xFF,
        0xFF,
    )


def test_unsupported_active_op_is_unknown_not_raw() -> None:
    """An unsupported active op (``Iop_Clz32``) refuses, never returning
    the raw operand as if the operation were inert."""
    env = _env(*["Ity_I32"] * 8)
    value = _convert(
        pyvex.expr.Unop("Iop_Clz32", [pyvex.expr.RdTmp(7)]),
        {7: IRValue(MemSpace.TMP, size=4, source_tmp=7)},
        env,
    )
    assert value.active_unary is not None
    assert domain._eval_value_8616(value, {}, {7: 0x10}) is None
    assert edge._kb_eval_value_8616(
        value, {}, {7: (0xFFFFFFFF, 0x10)}
    ) is None


def test_corrupted_evidence_refuses() -> None:
    """Forged or contradictory unary evidence must not evaluate."""
    env = _env(*["Ity_I16"] * 8)
    good = _convert(
        pyvex.expr.Unop("Iop_16to8", [pyvex.expr.RdTmp(7)]),
        {7: IRValue(MemSpace.TMP, size=2, source_tmp=7)},
        env,
    )
    # Forged result width that contradicts the op's declared width.
    forged_bits = IRValue(
        MemSpace.TMP,
        size=good.size,
        expr=good.expr,
        active_unary=IRActiveUnary8616(
            op="Iop_16to8",
            operand=IRValue(MemSpace.TMP, size=2, source_tmp=7),
            result_bits=16,
        ),
    )
    assert domain._eval_value_8616(forged_bits, {}, {7: 0x1234}) is None
    assert edge._kb_eval_value_8616(
        forged_bits, {}, {7: (0xFFFF, 0x1234)}
    ) is None
    # A capture pin combined with active evidence is contradictory.
    pinned_active = IRValue(
        MemSpace.REG,
        name="ax",
        size=2,
        source_tmp=7,
        active_unary=IRActiveUnary8616(
            op="Iop_16to8",
            operand=IRValue(MemSpace.REG, name="ax", size=2),
            result_bits=8,
        ),
    )
    assert domain._eval_value_8616(pinned_active, {"ax": 1}, {7: 2}) is None
    assert edge._kb_eval_value_8616(
        pinned_active, {"ax": (0xFFFF, 1)}, {7: (0xFFFF, 2)}
    ) is None
    # A legacy unary ``expr`` projection without typed evidence refuses.
    legacy = IRValue(MemSpace.REG, name="ax", size=2, expr=("Iop_16Sto32",))
    assert domain._eval_value_8616(legacy, {"ax": 0x8000}, {}) is None
    assert edge._kb_eval_value_8616(legacy, {"ax": (0xFFFF, 0x8000)}, {}) is None
    # An unsupported non-Iop-prefixed op name is not assumed inert either.
    bogus = IRValue(
        MemSpace.REG,
        name="ax",
        size=2,
        active_unary=IRActiveUnary8616(
            op="Iop_MullS16x2",
            operand=IRValue(MemSpace.REG, name="ax", size=2),
            result_bits=16,
        ),
    )
    assert domain._eval_value_8616(bogus, {"ax": 5}, {}) is None


def test_active_evidence_mutations_break_equality_and_binding() -> None:
    """Inner signedness, operand and result-width mutations change the
    typed view: equality, serialization and native binding all notice."""
    env = _env(*["Ity_I8"] * 8)
    tmps = {7: IRValue(MemSpace.TMP, size=1, source_tmp=7)}
    signed_inner = _convert(
        pyvex.expr.Unop("Iop_8Sto16", [pyvex.expr.RdTmp(7)]), tmps, env
    )
    unsigned_inner = _convert(
        pyvex.expr.Unop("Iop_8Uto16", [pyvex.expr.RdTmp(7)]), tmps, env
    )
    assert signed_inner != unsigned_inner
    assert signed_inner.to_dict() != unsigned_inner.to_dict()
    assert not domain._native_value_equal_8616(signed_inner, unsigned_inner, 0)
    # Operand mutation must break binding too.
    forged = IRValue(
        MemSpace.TMP,
        size=signed_inner.size,
        expr=signed_inner.expr,
        active_unary=IRActiveUnary8616(
            op="Iop_8Sto16",
            operand=IRValue(MemSpace.TMP, size=1, source_tmp=8),
            result_bits=16,
        ),
    )
    assert not domain._native_value_equal_8616(signed_inner, forged, 0)
    forged_bits = IRValue(
        MemSpace.TMP,
        size=signed_inner.size,
        expr=signed_inner.expr,
        active_unary=IRActiveUnary8616(
            op="Iop_8Sto16",
            operand=IRValue(MemSpace.TMP, size=1, source_tmp=7),
            result_bits=32,
        ),
    )
    assert not domain._native_value_equal_8616(signed_inner, forged_bits, 0)
