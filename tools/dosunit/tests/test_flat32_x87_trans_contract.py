"""Regression tests for the transcendental value/flag contract.

Independent parent evidence ``parent-trans-contract.json`` (24 native
cases, 12 wrong concrete NaN outputs, 4 missing RC dependencies) showed:

* FSIN/FCOS/F2XM1 on a QNaN preserve the payload on host hardware; the
  previous ``badop`` path forced every NaN to the indefinite encoding.
* FSIN/FCOS of 1.0 differ between CW.RC settings; the previous
  ``x87_trans_*`` UFs lacked the control word and erased that dependency.

The fixed contract: every approximation UF carries ``(cw, operands...)``;
NaN operands quiet/propagate per the x86 rules; inf and unsupported
encodings deliver the masked indefinite (FPATAN accepts infinities per
the SDM atan2 table); exact SDM zero edges are modeled directly.  UF
equality still only proves congruence under identical inputs -- these
tests never claim two different numeric algorithms equal.
"""

from __future__ import annotations

from typing import ClassVar

import pytest
import z3

from tools.dosunit.ssa.z3_x87_fp import apply_x87_op
from tools.dosunit.tests.test_flat32_x87_arith import _run, _tags

CW_NE = 0x037F            # all exceptions masked, RNE
TOP = 0x3800              # status-word TOP field mask
CW_RTP = 0x077F           # RC = +inf
CW_RTN = 0x0B7F           # RC = -inf
CW_RTZ = 0x0F7F           # RC = toward zero

ONE = 0x3FFF8000000000000000
TWO = 0x40008000000000000000
HALF = 0x3FFE8000000000000000
NINF = 0xFFFF8000000000000000
INDEF = 0xFFFFC000000000000000
QNAN = 0x7FFFC000000000000123
SNAN = 0x7FFFB000000000000123
PINF = 0x7FFF8000000000000000
NZERO = 0x80000000000000000000
UNNORMAL = 0x00014000000000000000    # exp!=0, J=0 -> unsupported class

_UNARY = ("sin", "cos", "f2xm1")
_OPCODES = {"sin": "d9fe", "cos": "d9ff", "f2xm1": "d9f0",
            "ptan": "d9f2", "fpatan": "d9f3", "fyl2x": "d9f1",
            "fyl2xp1": "d9f9", "sincos": "d9fb",
            "yl2x": "d9f1", "yl2xp1": "d9f9"}


def _op(name: str, args: list[int]) -> z3.ExprRef:
    """Apply an x87fp trans op: arg0 is the 16-bit CW, rest are ext80."""
    widths = [16] + [80] * (len(args) - 1)
    return apply_x87_op(f"x87fp_{name}", 80,
                        [z3.BitVecVal(v, w) for v, w
                         in zip(args, widths, strict=True)], z3)


class TestNaNOperandClasses:
    """Host-verified: quiet NaN payload preserved; sNaN quiets with IE."""

    @pytest.mark.parametrize("op", _UNARY)
    def test_qnan_payload_preserved(self, op: str) -> None:
        result = _op(op, [CW_NE, QNAN])
        assert z3.simplify(result).as_long() == QNAN

    @pytest.mark.parametrize("op", _UNARY)
    def test_snan_quieted_with_ie(self, op: str) -> None:
        result = _op(op, [CW_NE, SNAN])
        flags = apply_x87_op(f"x87fp_flags_{op}", 16,
                             [z3.BitVecVal(SNAN, 80)], z3)
        assert z3.simplify(result).as_long() == SNAN | (1 << 62)
        assert z3.simplify(flags).as_long() & 1 == 1          # IE

    @pytest.mark.parametrize("op", _UNARY)
    def test_qnan_no_invalid_flag(self, op: str) -> None:
        flags = apply_x87_op(f"x87fp_flags_{op}", 16,
                             [z3.BitVecVal(QNAN, 80)], z3)
        assert z3.simplify(flags).as_long() & 1 == 0

    @pytest.mark.parametrize("op", _UNARY)
    def test_unsupported_is_indefinite(self, op: str) -> None:
        result = _op(op, [CW_NE, UNNORMAL])
        flags = apply_x87_op(f"x87fp_flags_{op}", 16,
                             [z3.BitVecVal(UNNORMAL, 80)], z3)
        assert z3.simplify(result).as_long() == INDEF
        assert z3.simplify(flags).as_long() & 1 == 1

    @pytest.mark.parametrize("op", ["sin", "cos"])
    def test_infinity_is_indefinite(self, op: str) -> None:
        result = _op(op, [CW_NE, PINF])
        assert z3.simplify(result).as_long() == INDEF

    @pytest.mark.parametrize(("src", "expected"), [
        (PINF, PINF),                          # 2^(+inf)-1 = +inf
        (0xFFFF8000000000000000, 0xBFFF8000000000000000),  # 2^(-inf)-1=-1
    ])
    def test_f2xm1_infinity_defined(self, src: int, expected: int) -> None:
        # Host + pinned bochs-ref/f2xm1.cc: infinities are defined
        # operands, not masked-invalid; no exception flags.
        result = _op("f2xm1", [CW_NE, src])
        flags = apply_x87_op("x87fp_flags_f2xm1", 16,
                             [z3.BitVecVal(src, 80)], z3)
        assert z3.simplify(result).as_long() == expected
        assert z3.simplify(flags).as_long() == 0

    @pytest.mark.parametrize(("src", "expected"), [
        (0xBFFF8000000000000000, 0xBFFE8000000000000000),  # -1.0 -> -0.5
        (0x40008000000000000000, 0x40008000000000000000),  # +2.0 -> kept
    ])
    def test_f2xm1_out_of_domain_operand_with_pe(
            self, src: int, expected: int) -> None:
        # Pinned Bochs/host: |x|>=1 is the documented
        # operand-unchanged-with-PE response (|x|=+-1 still computes the
        # exact value).
        result = _op("f2xm1", [CW_NE, src])
        flags = apply_x87_op("x87fp_flags_f2xm1", 16,
                             [z3.BitVecVal(src, 80)], z3)
        assert z3.simplify(result).as_long() == expected
        assert z3.simplify(flags).as_long() == 0x20          # PE

    @pytest.mark.parametrize("operand", [QNAN, SNAN | (1 << 63)])
    def test_atan2_propagates_nan(self, operand: int) -> None:
        result = _op("atan2", [CW_NE, operand, TWO])
        assert z3.simplify(result).as_long() == operand | (1 << 62)

    def test_atan2_unsupported_precedes_nan(self) -> None:
        result = _op("atan2", [CW_NE, UNNORMAL, QNAN])
        assert z3.simplify(result).as_long() == INDEF

    def test_atan2_infinity_reaches_uf(self) -> None:
        # FPATAN accepts +-inf (SDM atan2 table): the result stays an
        # uninterpreted application, not the indefinite.
        result = _op("atan2", [CW_NE, PINF, TWO])
        assert "x87_trans_atan2" in str(z3.simplify(result))


class TestExactZeroEdges:
    """SDM-exact results that must not depend on the UF."""

    @pytest.mark.parametrize(("op", "src", "expected"), [
        ("sin", 0, 0), ("sin", NZERO, NZERO),
        ("tan", 0, 0), ("f2xm1", 0, 0), ("f2xm1", NZERO, NZERO),
        ("cos", 0, ONE), ("cos", NZERO, ONE),
        ("lg2", 0, 0xFFFF8000000000000000),
        ("lg2p1", NZERO, NZERO),
    ])
    def test_zero_edge(self, op: str, src: int, expected: int) -> None:
        assert z3.simplify(_op(op, [CW_NE, src])).as_long() == expected


class TestRoundingControlDependency:
    """CW is a true UF input; identical names alone prove nothing."""

    # Operand 0.5 keeps every op on the approximation path (f2xm1
    # short-circuits to the operand for |x|>=1).
    @pytest.mark.parametrize("op", ["sin", "cos", "tan", "f2xm1",
                                    "lg2", "lg2p1"])
    def test_uf_application_carries_cw(self, op: str) -> None:
        result = z3.simplify(_op(op, [CW_NE, HALF]))
        assert result.decl().name() == f"x87_trans_{op}"
        assert result.num_args() == 2
        assert result.arg(0).size() == 16
        assert result.arg(1).size() == 80

    def test_atan2_uf_application_carries_cw(self) -> None:
        result = z3.simplify(_op("atan2", [CW_NE, TWO, ONE]))
        assert result.decl().name() == "x87_trans_atan2"
        assert result.num_args() == 3
        assert result.arg(0).size() == 16

    @pytest.mark.parametrize("op", ["sin", "cos", "f2xm1"])
    @pytest.mark.parametrize("cw2", [CW_RTP, CW_RTN, CW_RTZ])
    def test_distinct_rc_terms_not_provable_equal(self, op: str,
                                                  cw2: int) -> None:
        # Regression control: before the fix both sides were the same UF
        # application (provably equal).  Now differing CW yields terms a
        # solver cannot equate under UF congruence.
        nearest = _op(op, [CW_NE, HALF])
        other = _op(op, [cw2, HALF])
        solver = z3.Solver()
        solver.add(nearest != other)
        assert solver.check() == z3.sat

    @pytest.mark.parametrize("op", ["sin", "cos", "f2xm1"])
    def test_identical_inputs_congruent(self, op: str) -> None:
        first = _op(op, [CW_NE, HALF])
        second = _op(op, [CW_NE, HALF])
        solver = z3.Solver()
        solver.add(first != second)
        assert solver.check() == z3.unsat


class TestLogProductEdges:
    """parent-log-edges22.json host matrix + pinned fyl2x.cc boundaries.

    The whole-instruction op takes (cw, y=ST1 multiplier, x=ST0 operand);
    only the genuinely inexact finite path is uninterpreted, so concrete
    rows assert exact values while UF-path rows assert flags only.
    """

    @pytest.mark.parametrize(("op", "x", "y", "expected", "flags"), [
        # x=+inf: log=+inf, defined operand, product sign(y) inf.
        ("yl2x", PINF, ONE, PINF, 0),
        ("yl2xp1", PINF, ONE, PINF, 0),
        ("yl2x", PINF, TWO, PINF, 0),
        # x=-inf: domain invalid.
        ("yl2x", 0xFFFF8000000000000000, ONE, INDEF, 1),
        ("yl2xp1", 0xFFFF8000000000000000, ONE, INDEF, 1),
        # yl2x x=1.0: log=+0, exact sign(y) zero, no PE.
        ("yl2x", ONE, ONE, 0, 0),
        ("yl2x", ONE, NZERO, NZERO, 0),
        # yl2xp1 x=+-0: log2(1)=+0 identity, sign(x)^sign(y) zero.
        ("yl2xp1", 0, ONE, 0, 0),
        ("yl2xp1", NZERO, ONE, NZERO, 0),
        # yl2x x=+-0 with finite nonzero y: -inf boundary, ZE.
        ("yl2x", 0, ONE, 0xFFFF8000000000000000, 4),
        ("yl2x", 0, 0xC0008000000000000000, PINF, 4),   # y=-1.5 -> +inf
        # x=1,y=+inf -> 0*inf invalid (yl2x); log2(2)=1 -> +inf (yl2xp1).
        ("yl2x", ONE, PINF, INDEF, 1),
        ("yl2xp1", ONE, PINF, PINF, 0),
        # y=+-inf & x<1 (yl2x): log2(x)<0 -> zSign=bSign^1 inf; x>1 ->
        # sign(y) inf.  x=+-0,y=+-inf also lands here (log=-inf is a
        # defined product), not at the ZE boundary.
        ("yl2x", HALF, PINF, NINF, 0),
        ("yl2x", 0, PINF, NINF, 0),
        ("yl2xp1", 0, PINF, INDEF, 1),   # log2(1+0)=+0: 0*inf invalid
        ("yl2x", TWO, 0xFFFF8000000000000000,
         0xFFFF8000000000000000, 0),
        # x=+-0 & y=0 -> 0*inf invalid (yl2x); x=+-0 -> +-0 (yl2xp1).
        ("yl2x", 0, 0, INDEF, 1),
        ("yl2xp1", 0, 0, 0, 0),
        # yl2x x<0 finite -> invalid; yl2xp1 x<=-1 finite -> operand +PE.
        ("yl2x", 0xBFFF8000000000000000, ONE, INDEF, 1),
        ("yl2xp1", 0xBFFF8000000000000000, ONE,
         0xBFFF8000000000000000, 0x20),
        ("yl2xp1", 0xC0008000000000000000, ONE,
         0xC0008000000000000000, 0x20),
        # y=+-0: exact signed zero returned before the inexact raise.
        ("yl2x", TWO, 0, 0, 0),
        ("yl2x", HALF, 0, NZERO, 0),
        ("yl2xp1", TWO, 0, 0, 0),
    ])
    def test_host_boundary(self, op: str, x: int, y: int, expected: int,
                           flags: int) -> None:
        result = _op(op, [CW_NE, y, x])
        raised = apply_x87_op(f"x87fp_flags_{op}", 16,
                              [z3.BitVecVal(x, 80), z3.BitVecVal(y, 80)],
                              z3)
        assert z3.simplify(result).as_long() == expected
        assert z3.simplify(raised).as_long() == flags

    @pytest.mark.parametrize(("op", "x", "y"), [
        ("yl2x", TWO, ONE),          # log2(2)*1: UF path, PE
        ("yl2xp1", ONE, ONE),        # log2(2)*1: UF path, PE
        ("yl2xp1", TWO, ONE),        # log2(3)*1: UF path, PE
    ])
    def test_uf_path_inexact_flag_only(self, op: str, x: int,
                                       y: int) -> None:
        result = _op(op, [CW_NE, y, x])
        raised = apply_x87_op(f"x87fp_flags_{op}", 16,
                              [z3.BitVecVal(x, 80), z3.BitVecVal(y, 80)],
                              z3)
        assert f"x87_trans_{op}" in str(z3.simplify(result))
        assert z3.simplify(raised).as_long() == 0x20          # PE

    @pytest.mark.parametrize(("op", "x", "y", "expected", "flags"), [
        ("yl2x", PINF, ONE, PINF, 0),
        ("yl2xp1", PINF, ONE, PINF, 0),
        ("yl2x", ONE, ONE, 0, 0),
        ("yl2x", ONE, PINF, INDEF, 1),
        ("yl2xp1", ONE, PINF, PINF, 0),
    ])
    def test_native_decode(self, op: str, x: int, y: int, expected: int,
                           flags: int) -> None:
        out = _run(bytes.fromhex(_OPCODES[op]),
                   {"x87_status_word": 0, "x87_control_word": CW_NE,
                    "x87_tag_word": _tags(0, 0),
                    "x87_st0": x, "x87_st1": y})
        assert out["x87_st1"] == expected
        assert out["x87_status_word"] & 0x3F == flags


class TestNativePath:
    """Decode-path regressions matching parent-trans-contract.json."""

    _BASE: ClassVar[dict[str, object]] = {
        "x87_status_word": 0, "x87_control_word": CW_NE,
        "x87_tag_word": _tags(0, 0)}

    @pytest.mark.parametrize("op", _UNARY)
    def test_qnan_preserved_through_decode(self, op: str) -> None:
        out = _run(bytes.fromhex(_OPCODES[op]),
                   dict(self._BASE, x87_st0=QNAN))
        assert out["x87_st0"] == QNAN
        assert out["x87_status_word"] & 0x3F == 0

    @pytest.mark.parametrize("op", _UNARY)
    def test_snan_quiets_through_decode(self, op: str) -> None:
        out = _run(bytes.fromhex(_OPCODES[op]),
                   dict(self._BASE, x87_st0=SNAN))
        assert out["x87_st0"] == SNAN | (1 << 62)
        assert out["x87_status_word"] & 1 == 1

    def test_sincos_qnan_quiets_and_pushes_quieted(self) -> None:
        out = _run(bytes.fromhex(_OPCODES["sincos"]),
                   dict(self._BASE, x87_st0=QNAN))
        assert out["x87_st0"] == QNAN
        assert out["x87_st7"] == QNAN                  # pushed cos copy
        assert out["x87_status_word"] & TOP == 7 << 11

    def test_fpatan_qnan_propagates(self) -> None:
        out = _run(bytes.fromhex(_OPCODES["fpatan"]),
                   dict(self._BASE, x87_st0=QNAN, x87_st1=TWO))
        assert out["x87_st1"] == QNAN
        assert out["x87_status_word"] & TOP == 1 << 11  # popped

    def test_fyl2x_qnan_propagates(self) -> None:
        out = _run(bytes.fromhex(_OPCODES["fyl2x"]),
                   dict(self._BASE, x87_st0=QNAN, x87_st1=TWO))
        assert out["x87_st1"] == QNAN

    def test_fyl2x_unsupported_operand_indefinite(self) -> None:
        out = _run(bytes.fromhex(_OPCODES["fyl2x"]),
                   dict(self._BASE, x87_st0=UNNORMAL, x87_st1=TWO))
        assert out["x87_st1"] == INDEF
        assert out["x87_status_word"] & 1 == 1
