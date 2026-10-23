"""Focused tests for the exact x87 extF80 numeric operator layer.

The ``x87fp_*`` operators in ``tools/dosunit/ssa/z3_x87_fp`` implement
single-rounding ext80 semantics over the architectural explicit-integer-bit
encoding: SoftFloat-style exact alignment in a widened bit-vector magnitude,
one symbolic round to the CW-selected precision, architectural masked
responses and the six status exception bits.

Expected values are host-derived hardware vectors supplied by the parent
(double-rounding audit, unnormal narrow store, masked stack-fault vectors)
plus SoftFloat-attributable boundary cases.  They deliberately avoid host
doubles: every vector is a literal ext80/IEEE encoding.
"""

from __future__ import annotations

import z3

from tools.dosunit.ssa.z3_ops import apply_operator

CW_NE = 0x037F            # all exceptions masked, RNE, PC64
CW_PC24 = 0x007F          # RNE, PC=00 (single precision)
CW_PC53 = 0x027F          # RNE, PC=10 (double precision)
CW_RTZ = 0x037F | 0x0C00
CW_RTN = 0x037F | 0x0400
CW_RTP = 0x037F | 0x0800

ONE = 0x3FFF8000000000000000
TWO = 0x40008000000000000000
FOUR = 0x40018000000000000000
ZERO = 0x00000000000000000000
INDEF = 0xFFFFC000000000000000
QNAN = 0x7FFFC000000000000000
SNAN = 0x7FFFB000000000000000
PINF = 0x7FFF8000000000000000
NINF = 0xFFFF8000000000000000
UNNORMAL = 0x00010000000000000000
PSEUDO_DEN = 0x00008000000000000001


_NO_CW = {"widen", "i2f", "rem", "rem1", "remcc", "remcc1",
          "com_lt", "com_eq", "com_uno", "flags_rem", "flags_rem1",
          "flags_com", "flags_ucom", "flags_load"}


def _apply(op: str, width: int, args: list[int | z3.ExprRef]) -> z3.ExprRef:
    """Apply an x87fp operator to literal operands with per-op arg widths."""
    tail = op[len("x87fp_"):]
    bvs = []
    for i, arg in enumerate(args):
        if hasattr(arg, "size"):
            bvs.append(arg)
        elif i == 0 and tail not in _NO_CW:
            bvs.append(z3.BitVecVal(arg, 16))
        elif tail == "widen":
            bvs.append(z3.BitVecVal(arg, 32 if arg <= 0xFFFFFFFF else 64))
        elif tail in {"i2f", "flags_i2f"}:
            bvs.append(z3.BitVecVal(arg, 32))
        else:
            bvs.append(z3.BitVecVal(arg, 80))
    return apply_operator(op, width, bvs, z3)


def _num(op: str, width: int, args: list[int]) -> int:
    """Evaluate a fully concrete x87fp application to a numeral."""
    expr = _apply(op, width, args)
    simplified = z3.simplify(expr)
    assert z3.is_bv_value(simplified), f"{op} not concrete: {simplified}"
    return int(simplified.as_long())


def _model(op: str, width: int, args: list[z3.ExprRef]) -> int:
    """Evaluate a partially symbolic x87fp application through the solver."""
    expr = _apply(op, width, args)
    solver = z3.Solver()
    probe = z3.BitVec("probe", width)
    solver.add(probe == expr)
    assert solver.check() == z3.sat
    return int(solver.model()[probe].as_long())


class TestExactAddition:
    """Host-derived double-rounding vectors (parent audit, real hardware)."""

    def test_pc24_guard_sticky_round_up(self) -> None:
        """1+2^-24 + 2^-65 at PC24: guard+sticky -> round up to 1+2^-23."""
        a = 0x3FFF8000008000000000
        b = 0x3FBE8000000000000000
        assert _num("x87fp_add", 80, [CW_PC24, a, b]) == 0x3FFF8000010000000000
        assert _num("x87fp_flags_add", 16, [CW_PC24, a, b]) == 0x20

    def test_pc53_guard_sticky_round_up(self) -> None:
        """1+2^-53 + 2^-65 at PC53: rounds up to 1+2^-52."""
        a = 0x3FFF8000000000000400
        b = 0x3FBE8000000000000000
        assert _num("x87fp_add", 80, [CW_PC53, a, b]) == 0x3FFF8000000000000800
        assert _num("x87fp_flags_add", 16, [CW_PC53, a, b]) == 0x20

    def test_pc24_exact_tie_rounds_even(self) -> None:
        """1 + 2^-24 at PC24: dropped==half exactly -> ties-to-even -> 1.0."""
        quarter_lsb = 0x3FE78000000000000000  # 2^-24 = half the PC24 lsb
        assert _num("x87fp_add", 80, [CW_PC24, ONE, quarter_lsb]) == ONE
        assert _num("x87fp_flags_add", 16, [CW_PC24, ONE, quarter_lsb]) == 0x20

    def test_basic(self) -> None:
        assert _num("x87fp_add", 80, [CW_NE, ONE, ONE]) == TWO
        assert _num("x87fp_flags_add", 16, [CW_NE, ONE, ONE]) == 0

    def test_huge_exponent_gap_inexact(self) -> None:
        """1 + 2^-300: far alignment; result 1.0 but PE must be set."""
        tiny = 0x3E738000000000000000
        assert _num("x87fp_add", 80, [CW_NE, ONE, tiny]) == ONE
        assert _num("x87fp_flags_add", 16, [CW_NE, ONE, tiny]) == 0x20

    def test_cancellation_exact(self) -> None:
        """a - a = +0 exactly (RNE), no exception flags."""
        assert _num("x87fp_sub", 80, [CW_NE, ONE, ONE]) == ZERO
        assert _num("x87fp_flags_sub", 16, [CW_NE, ONE, ONE]) == 0
        # Under RTN an exact zero difference is -0.
        neg_zero = _num("x87fp_sub", 80, [CW_RTN, ONE, ONE])
        assert neg_zero == (1 << 79)


class TestMulDivSqrt:
    """Exact multiply/divide/sqrt cores."""

    def test_mul_basic(self) -> None:
        assert _num("x87fp_mul", 80, [CW_NE, TWO, TWO]) == FOUR
        assert _num("x87fp_mul", 80, [CW_NE, ONE, TWO]) == TWO

    def test_mul_inexact_flag(self) -> None:
        # 1+2^-62 squared drops bits -> PE.
        a = 0x3FFF8000000000000004
        flags = _num("x87fp_flags_mul", 16, [CW_NE, a, a])
        assert flags & 0x20

    def test_div_basic(self) -> None:
        assert _num("x87fp_div", 80, [CW_NE, TWO, TWO]) == ONE

    def test_div_by_zero(self) -> None:
        assert _num("x87fp_div", 80, [CW_NE, ONE, ZERO]) == PINF
        flags = _num("x87fp_flags_div", 16, [CW_NE, ONE, ZERO])
        assert flags & 0x4
        assert not flags & 0x20  # ZE path is not inexact

    def test_div_third_inexact(self) -> None:
        # 1/3 rounds inexactly: PE set.
        three = 0x4000C000000000000000
        flags = _num("x87fp_flags_div", 16, [CW_NE, ONE, three])
        assert flags == 0x20

    def test_sqrt_exact(self) -> None:
        assert _num("x87fp_sqrt", 80, [CW_NE, FOUR]) == TWO
        assert _num("x87fp_flags_sqrt", 16, [CW_NE, FOUR]) == 0

    def test_sqrt_two(self) -> None:
        # sqrt(2) = 0x3FFFB504F333F9DE6484 exactly as hardware encodes.
        assert _num("x87fp_sqrt", 80, [CW_NE, TWO]) == 0x3FFFB504F333F9DE6484
        assert _num("x87fp_flags_sqrt", 16, [CW_NE, TWO]) == 0x20

    def test_sqrt_negative_invalid(self) -> None:
        neg4 = (1 << 79) | FOUR
        assert _num("x87fp_sqrt", 80, [CW_NE, neg4]) == INDEF
        assert _num("x87fp_flags_sqrt", 16, [CW_NE, neg4]) == 0x1


class TestConversions:
    """Widen/narrow/integer conversions and masked responses."""

    def test_widen32(self) -> None:
        assert _num("x87fp_widen", 80, [0x3FC00000]) == 0x3FFFC000000000000000

    def test_widen64(self) -> None:
        assert _num("x87fp_widen", 80, [0x3FF8000000000000]) == 0x3FFFC000000000000000

    def test_narrow32(self) -> None:
        assert _num("x87fp_narrow", 32, [CW_NE, TWO]) == 0x40000000
        assert _num("x87fp_narrow", 64, [CW_NE, TWO]) == 0x4000000000000000

    def test_narrow_inexact_flag(self) -> None:
        # ext80 value below f32 resolution -> PE.
        tiny_extra = 0x3FFF8000000000000001
        flags = _num("x87fp_flags_narrow32", 16, [CW_NE, tiny_extra])
        assert flags & 0x20

    def test_narrow_unnormal_masked_response(self) -> None:
        """Host vector: FSTP m32 of unnormal -> 0xFFC00000 + IE."""
        assert _num("x87fp_narrow", 32, [CW_NE, UNNORMAL]) == 0xFFC00000
        assert _num("x87fp_flags_narrow32", 16, [CW_NE, UNNORMAL]) & 0x1
        assert _num("x87fp_narrow", 64, [CW_NE, UNNORMAL]) == 0xFFF8000000000000

    def test_narrow_overflow(self) -> None:
        # Beyond f32 max: RN -> +inf with OE+PE.
        huge = 0x407F8000000000000000  # 2^128
        assert _num("x87fp_narrow", 32, [CW_NE, huge]) == 0x7F800000
        flags = _num("x87fp_flags_narrow32", 16, [CW_NE, huge])
        assert flags & 0x28

    def test_i2f_exact(self) -> None:
        assert _num("x87fp_i2f", 80, [42]) == 0x4004A800000000000000
        neg = _num("x87fp_i2f", 80, [z3.BitVecVal(-42 & 0xFFFFFFFF, 32)])
        assert neg == (1 << 79) | 0x4004A800000000000000

    def test_f2i_rounding_modes(self) -> None:
        v35 = 0x4000E000000000000000  # 3.5
        assert _num("x87fp_f2i", 32, [CW_NE, v35]) == 4
        assert _num("x87fp_f2i", 32, [CW_RTZ, v35]) == 3
        assert _num("x87fp_f2i", 32, [CW_RTN, v35]) == 3
        assert _num("x87fp_f2i", 32, [CW_RTP, v35]) == 4

    def test_f2i_indefinite(self) -> None:
        assert _num("x87fp_f2i", 32, [CW_NE, PINF]) == 0x80000000
        assert _num("x87fp_f2i", 32, [CW_NE, QNAN]) == 0x80000000
        assert _num("x87fp_f2i", 16, [CW_NE, QNAN]) == 0x8000
        big = 0x403E8000000000000000  # 2^63
        assert _num("x87fp_f2i", 64, [CW_NE, big]) == 0x8000000000000000

    def test_f2i_inexact_flag(self) -> None:
        v35 = 0x4000E000000000000000
        assert _num("x87fp_flags_f2i32", 16, [CW_NE, v35]) & 0x20
        v4 = 0x40018000000000000000
        assert _num("x87fp_flags_f2i32", 16, [CW_NE, v4]) == 0


class TestMaskedResponses:
    """Invalid-operation and NaN-propagation responses."""

    def test_inf_minus_inf(self) -> None:
        assert _num("x87fp_sub", 80, [CW_NE, PINF, PINF]) == INDEF
        assert _num("x87fp_flags_sub", 16, [CW_NE, PINF, PINF]) & 0x1

    def test_zero_times_inf(self) -> None:
        assert _num("x87fp_mul", 80, [CW_NE, ZERO, PINF]) == INDEF

    def test_nan_quiets_and_propagates(self) -> None:
        # SNaN payload propagates: quiet bit set, payload retained.
        snan_payload = 0x7FFFA000000000000001
        result = _num("x87fp_add", 80, [CW_NE, snan_payload, ONE])
        assert result == 0x7FFFE000000000000001
        assert _num("x87fp_flags_add", 16, [CW_NE, snan_payload, ONE]) & 0x1

    def test_qnan_passthrough_no_ie(self) -> None:
        assert _num("x87fp_add", 80, [CW_NE, QNAN, ONE]) == QNAN
        assert _num("x87fp_flags_add", 16, [CW_NE, QNAN, ONE]) == 0

    def test_unsupported_operand(self) -> None:
        assert _num("x87fp_add", 80, [CW_NE, UNNORMAL, ONE]) == INDEF
        assert _num("x87fp_flags_add", 16, [CW_NE, UNNORMAL, ONE]) & 0x1

    def test_pseudo_denormal_operand(self) -> None:
        """SoftFloat3e: exp=0,J=1 normalizes to the exp=1 normal value + DE."""
        # PSEUDO_DEN = 1.000...001 x 2^-16382 -> add 0 keeps the normal form.
        assert _num("x87fp_add", 80, [CW_NE, PSEUDO_DEN, ZERO]) == \
            0x00018000000000000001
        flags = _num("x87fp_flags_add", 16, [CW_NE, PSEUDO_DEN, ZERO])
        assert flags & 0x2          # denormal operand -> DE
        assert not flags & 0x1      # not unsupported -> no IE

    def test_denormal_de_flag(self) -> None:
        den = 0x00000000000000000001  # smallest ext80 denormal
        flags = _num("x87fp_flags_add", 16, [CW_NE, den, ONE])
        assert flags & 0x2

    def test_com_primitives(self) -> None:
        assert _num("x87fp_com_lt", 1, [ONE, TWO]) == 1
        assert _num("x87fp_com_lt", 1, [TWO, ONE]) == 0
        assert _num("x87fp_com_eq", 1, [ONE, ONE]) == 1
        assert _num("x87fp_com_uno", 1, [QNAN, ONE]) == 1
        assert _num("x87fp_com_uno", 1, [ONE, TWO]) == 0

    def test_fprem_truncated_quotient(self) -> None:
        """FPREM truncates the quotient: rem(10,3)=1, rem(7,2)=+1."""
        ten = 0x4002A000000000000000   # 10.0 = 1.25 * 2^3
        three = 0x4000C000000000000000
        assert _num("x87fp_rem", 80, [ten, three]) == ONE
        seven = 0x4001E000000000000000  # 7.0 = 1.75 * 2^2
        assert _num("x87fp_rem", 80, [seven, TWO]) == ONE  # q=3 trunc -> +1

    def test_fprem1_nearest_quotient(self) -> None:
        """FPREM1 rounds the quotient to nearest even: rem(7,2) = -1."""
        ten = 0x4002A000000000000000
        three = 0x4000C000000000000000
        assert _num("x87fp_rem1", 80, [ten, three]) == ONE
        seven = 0x4001E000000000000000
        # q = 3.5 -> nearest even 4 -> 7 - 8 = -1 (sign flipped)
        assert _num("x87fp_rem1", 80, [seven, TWO]) == (1 << 79) | ONE

    def test_fprem_small_dividend(self) -> None:
        """|a| < |b|/2 returns a verbatim for both forms."""
        assert _num("x87fp_rem", 80, [ONE, FOUR]) == ONE
        assert _num("x87fp_rem1", 80, [ONE, FOUR]) == ONE
        # Quotient is 0 -> all condition codes clear (not a partial result).
        assert _num("x87fp_remcc", 16, [ONE, FOUR]) == 0
        assert _num("x87fp_remcc1", 16, [ONE, FOUR]) == 0

    def test_fprem_cc_quotient_bits(self) -> None:
        """86Box mapping: C1=q0, C3=q1, C0=q2; C2=0 on complete."""
        seven = 0x4001E000000000000000
        # FPREM: q=3 -> C1=1, C3=1, C0=0 -> 0b1010 = 0xA
        assert _num("x87fp_remcc", 16, [seven, TWO]) == 0xA
        # FPREM1: q=4 -> 0b100 -> C1=0, C3=0, C0=1 -> 0x1
        assert _num("x87fp_remcc1", 16, [seven, TWO]) == 0x1

    def test_fprem_partial_c2(self) -> None:
        """Exponent gap >= 64: partial remainder, C2 set, C0-C3 = 0."""
        huge = 0x40638000000000000000  # 2^100
        three = 0x4000C000000000000000
        assert _num("x87fp_remcc", 16, [huge, three]) == 0x4
        result = _num("x87fp_rem", 80, [huge, three])
        assert result != 0
        # Partial result's exponent gap to b is < 64: continue until C2=0.
        second = _num("x87fp_rem", 80, [result, three])
        second_cc = _num("x87fp_remcc", 16, [result, three])
        # iterating converges to 2^100 mod 3 = 1
        assert second_cc & 0x4 == 0
        assert second == ONE

    def test_fprem_invalid(self) -> None:
        assert _num("x87fp_rem", 80, [PINF, TWO]) == INDEF
        assert _num("x87fp_flags_rem", 16, [PINF, TWO]) & 0x1
        assert _num("x87fp_flags_rem", 16, [ONE, ZERO]) & 0x1
        assert _num("x87fp_rem", 80, [ONE, PINF]) == ONE  # b inf -> a


class TestSymbolicCWDriven:
    """The same instruction must respect a symbolic control word."""

    def test_symbolic_rc_selects_f2i(self) -> None:
        cw = z3.BitVec("cw", 16)
        v35 = z3.BitVecVal(0x4000E000000000000000, 80)
        expr = apply_operator("x87fp_f2i", 32, [cw, v35], z3)
        for rc, want in [(0x000, 4), (0x400, 3), (0x800, 4), (0xC00, 3)]:
            solver = z3.Solver()
            solver.add(cw == 0x037F | rc)
            probe = z3.BitVec("p", 32)
            solver.add(probe == expr)
            assert solver.check() == z3.sat
            assert solver.model()[probe].as_long() == want

    def test_symbolic_pc_selects_add(self) -> None:
        cw = z3.BitVec("cw", 16)
        a = z3.BitVecVal(0x3FFF8000008000000000, 80)
        b = z3.BitVecVal(0x3FBE8000000000000000, 80)
        expr = apply_operator("x87fp_add", 80, [cw, a, b], z3)
        expected = {0x007F: 0x3FFF8000010000000000,  # PC24 -> 1+2^-23
                    0x027F: 0x3FFF8000008000000000,  # PC53 -> 1+2^-24
                    0x037F: 0x3FFF8000008000000000}  # PC64 -> 1+2^-24 exact? (2^-65 inexact still)
        for cwval in (0x007F, 0x027F, 0x037F):
            solver = z3.Solver()
            solver.add(cw == cwval)
            probe = z3.BitVec("p", 80)
            solver.add(probe == expr)
            assert solver.check() == z3.sat
            assert solver.model()[probe].as_long() == expected[cwval]


class TestTestFloatVectors:
    """Regression rows from the pinned TestFloat extF80 generators
    (``.cache/ssa-capability-audit/emulators/build-sources/berkeley-testfloat-3``
    ``testfloat_gen``).  Rows cite ``<file>`` line N; flag byte is SoftFloat
    order {inexact:1, underflow:2, overflow:4, infinite:8, invalid:16} mapped
    to x87 {PE:32, UE:16, OE:8, ZE:4, IE:1}; DE is excluded because
    TestFloat does not report operand-denormal classification.
    """

    @staticmethod
    def _tf_flags(flags: int) -> int:
        return (((flags & 1) << 5) | ((flags & 2) << 3) | ((flags & 4) << 1)
                | ((flags & 8) >> 1) | ((flags & 16) >> 4))

    def test_far_sub_borrows_low_word(self) -> None:
        """sub-80-ne L23670 analog via extF80-add-vectors L7: opposite-sign
        addition with a huge exponent gap must round through the borrowed
        low word, not a bare decrement (parent batch9 finding)."""
        a = int("4400E140D8876452D3DD", 16)
        b = int("BC03EFFF8000800000000", 16)
        expected = int("4400E140D8876452D3DD", 16)
        assert _num("x87fp_add", 80, [CW_NE, a, b]) == expected
        # And the sub-form: -0 - b = -b verbatim (sub-80-ne L23378).
        b2 = 0x4001FFFFBFDFFFFFFFFF
        assert _num("x87fp_sub", 80, [CW_NE, 0x80000000000000000000, b2]) == (
            0xC001FFFFBFDFFFFFFFFF)

    def test_zero_operand_rounds_to_pc(self) -> None:
        """add-32-ne L23378: -0 + b still applies PC24 rounding + PE."""
        b = 0x4001FFFFBFDFFFFFFFFF
        got = _num("x87fp_add", 80, [CW_PC24, 0x80000000000000000000, b])
        assert got == 0x4001FFFFC00000000000
        assert _num("x87fp_flags_add", 16,
                    [CW_PC24, 0x80000000000000000000, b]) & 0x20

    def test_tiny_inexact_result_raises_ue(self) -> None:
        """mul-80-ne L2630: denormal-or-zero inexact result -> UE|PE."""
        a = 0x00018000000000000000
        b = 0xBB978080000010000000
        assert _num("x87fp_mul", 80, [CW_NE, a, b]) == 0x80000000000000000000
        flags = _num("x87fp_flags_mul", 16, [CW_NE, a, b])
        assert flags & 0x30 == 0x30

    def test_directed_overflow_gives_max_finite_at_pc(self) -> None:
        """div-64-min L18703: RC=down overflow -> exp 0x7FFE, PC53-max
        significand; not an all-ones pseudo-NaN under 0x7FFF."""
        a = 0x7FFDFFE0001FFFFFFFFF
        b = 0x3FE3800000000001FFFA
        cw = 0x027F | 0x0400
        assert _num("x87fp_div", 80, [cw, a, b]) == 0x7FFEFFFFFFFFFFFFF800
        assert _num("x87fp_flags_div", 16, [cw, a, b]) & 0x28 == 0x28

    def test_overflow_to_inf_is_inexact(self) -> None:
        """div-80-ne L38574: masked overflow to -inf raises OE|PE."""
        a = 0xC0018000000000000001
        b = 0x00018000000000000000
        assert _num("x87fp_div", 80, [CW_NE, a, b]) == 0xFFFF8000000000000000
        assert _num("x87fp_flags_div", 16, [CW_NE, a, b]) & 0x28 == 0x28

    def test_sqrt_invalid_no_pe(self) -> None:
        """sqrt-80-ne L1754: sqrt(negative) -> indefinite with IE only."""
        a = 0xBFFFEFFFFFF7FFFFFFFF
        assert _num("x87fp_sqrt", 80, [CW_NE, a]) == INDEF
        assert _num("x87fp_flags_sqrt", 16, [CW_NE, a]) & 0x3F == 0x01

    def test_denormal_promotes_to_min_normal(self) -> None:
        """numeric10-denormal-boundary (host + testfloat_ver): the largest
        denormal-rounded product promotes to exponent 1 minimum normal and
        still raises UE|PE (tininess detected before rounding)."""
        a = 0x00018000000000000000
        b = 0x3FFEFFFFFFFFFFFFFFFF
        assert _num("x87fp_mul", 80, [CW_NE, a, b]) == 0x00018000000000000000
        assert _num("x87fp_flags_mul", 16, [CW_NE, a, b]) & 0x3F == 0x30

    def test_denormal_promotion_directed_modes(self) -> None:
        """Same product: round-down/zero keep the max denormal, round-up
        promotes — tininess flag raised either way."""
        a = 0x00018000000000000000
        b = 0x3FFEFFFFFFFFFFFFFFFF
        assert _num("x87fp_mul", 80, [CW_RTN, a, b]) == 0x00007FFFFFFFFFFFFFFF
        assert _num("x87fp_mul", 80, [CW_RTZ, a, b]) == 0x00007FFFFFFFFFFFFFFF
        assert _num("x87fp_mul", 80, [CW_RTP, a, b]) == 0x00018000000000000000
        for cw in (CW_RTN, CW_RTZ, CW_RTP):
            assert _num("x87fp_flags_mul", 16, [cw, a, b]) & 0x3F == 0x30

    def test_fscale_truncates_scale_operand(self) -> None:
        """FSCALE truncates ST(1) toward zero (SDM), then scales exactly."""
        one, three = 0x3FFF8000000000000000, 0x4000C000000000000000
        two5 = 0x4000A000000000000000   # 2.5 -> trunc 2
        neg17 = 0xBFFFD000000000000000  # -1.7 -> trunc -1
        p19 = 0x3FFFF333333333333333    # 1.9 -> trunc 1
        assert _num("x87fp_scale", 80, [CW_NE, three, two5]) == 0x4002C000000000000000
        assert _num("x87fp_scale", 80, [CW_NE, 0x3FFFC000000000000000, neg17]) \
            == 0x3FFEC000000000000000  # 1.5 * 2^-1 = 0.75
        assert _num("x87fp_scale", 80, [CW_NE, one, p19]) == TWO  # 1 * 2^1

    def test_fscale_saturation_flags(self) -> None:
        """Huge |ST(1)| saturates through the pack: +inf OE|PE, +0 UE|PE."""
        one = 0x3FFF8000000000000000
        big_pos = 0x400E8000000000000000   # 2^15
        big_neg = 0xC00E8000000000000000   # -2^15
        assert _num("x87fp_scale", 80, [CW_NE, one, big_pos]) == 0x7FFF8000000000000000
        assert _num("x87fp_flags_scale", 16, [CW_NE, one, big_pos]) & 0x3F == 0x28
        assert _num("x87fp_scale", 80, [CW_NE, one, big_neg]) == 0
        assert _num("x87fp_flags_scale", 16, [CW_NE, one, big_neg]) & 0x3F == 0x30
