"""Layer: dosunit SSA solver translation.

Responsibility: exact x87 extF80 numeric operators for the Z3 backend.

Arithmetic uses a SoftFloat-style exact bit-vector core: operands are kept
in the architectural 80-bit encoding (explicit integer bit), aligned exactly
in a widened magnitude with a bounded analytic sticky tail, normalized by
symbolic most-significant-bit search, and rounded exactly once to the
control-word precision.  This avoids double rounding for every exponent
gap; Z3's FP sort is only used for single-rounding conversions (widen is
exact, narrow/integer conversions are themselves the rounding), never as
an intermediate-precision approximation — its ``fpRem`` is also wrong on
``FPSort(15, 64)`` (probe: rem(10, 3) = +0.0), so remainders are exact-BV.

Masked responses match i387 semantics: invalid operations and unsupported
encodings (unnormal: nonzero exponent with a clear integer bit) yield the
negative QNaN real indefinite 0xFFFFC000000000000000; floating stores of
those operands yield the target-format negative indefinite
(0xFFC00000 / 0xFFF8000000000000); out-of-range integer conversions yield
the signed integer indefinite (most negative value).  Pseudo-denormals
(exponent zero, integer bit set) are valid operands per the pinned
SoftFloat3e ``extF80_class``/``extF80_isUnsupported``: they classify as
denormal (DE) and are normalized to exponent 1 before arithmetic.  NaN
results propagate/quiet the operand encoding at bit level (x87 semantics),
not Z3's default NaN.  Flag ops return the six status-word exception bits
(bit0 IE .. bit5 PE) for OR-ing into ``x87_status_word``.

``x87fp_rem``/``x87fp_rem1`` implement FPREM/FPREM1 on the same exact-BV
core (SoftFloat3e ``fprem.cc``): truncating versus nearest-even quotient
selection, the ``expDiff >= 64`` partial-reduction step that consumes
``(expDiff & 31) | 32`` bits and raises C2, and the quotient low bits
{C1=q0, C3=q1, C0=q2} exposed via ``x87fp_remcc``/``x87fp_remcc1``.

Declared contract (premise): reserved precision-control encoding PC=01 is
resolved as single precision (24-bit significand); the effect layer emits
the typed premise record ``x87_pc01_reserved_contract`` whenever a
precision-controlled op is modeled so the verdict stays conditional.
"""

from __future__ import annotations

from typing import Any

from tools.dosunit.contracts.model import DosUnitError

_X87_INDEF = 0xFFFFC000000000000000
_X87_EXP_MAX = 0x7FFF
_X87_SIG_INF = 0x8000000000000000
_X87_NARROW_INDEF = {32: 0xFFC00000, 64: 0xFFF8000000000000}
_EXT_WIDTH = 202


# ---------------------------------------------------------------------------
# Typed operator admission.
#
# ``x87fp_*`` terms are an internal contract between the architecture owners
# (arith/stack effects) and this evaluator.  ``apply_x87_op`` validates every
# admitted operator BEFORE Z3 evaluation: the exact operator name or flags
# suffix, the arity, the bit-vector width of every argument, and the declared
# output width.  Shapes that violate the contract raise ``DosUnitError`` so a
# malformed term can never reach the evaluator and be silently misread (the
# batch-20 defect class: extra operands dropped, missing operands crashing on
# index, width mismatches propagating as unconstrained terms).  Names or
# suffixes absent from the tables return ``None`` and stay unadmitted —
# admission is by exact name, never prefix matching.
# ---------------------------------------------------------------------------

_CW = frozenset((16,))
_E80 = frozenset((80,))
_MEM_FP = frozenset((32, 64))
_MEM_INT = frozenset((16, 32, 64))
_FLAG_W = frozenset((16,))
_PRED_W = frozenset((1,))

_X87_ARITH_KINDS = frozenset(
    ("add", "sub", "mul", "div", "scale", "sqrt", "rnd", "rem", "rem1"))

# Value operator name -> (per-argument allowed widths, allowed output widths).
# cw is the 16-bit x87 control word; ext80 operands are architectural
# explicit-integer-bit 80-bit vectors; remcc outputs the 16-bit {C0..C3}
# nibble word; com_*/badop/range63 output single-bit predicates.
_X87_VALUE_SHAPES: dict[str, tuple[tuple[frozenset[int], ...], frozenset[int]]] = {
    "add":     ((_CW, _E80, _E80), _E80),
    "sub":     ((_CW, _E80, _E80), _E80),
    "mul":     ((_CW, _E80, _E80), _E80),
    "div":     ((_CW, _E80, _E80), _E80),
    "scale":   ((_CW, _E80, _E80), _E80),
    "sqrt":    ((_CW, _E80), _E80),
    "rnd":     ((_CW, _E80), _E80),
    "rem":     ((_E80, _E80), _E80),
    "rem1":    ((_E80, _E80), _E80),
    "remcc":   ((_E80, _E80), _FLAG_W),
    "remcc1":  ((_E80, _E80), _FLAG_W),
    "widen":   ((_MEM_FP,), _E80),
    "i2f":     ((_MEM_INT,), _E80),
    "narrow":  ((_CW, _E80), _MEM_FP),
    "f2i":     ((_CW, _E80), _MEM_INT),
    "fbld":    ((_E80,), _E80),
    "fbst":    ((_CW, _E80), _E80),
    "xtract_e": ((_E80,), _E80),
    "xtract_s": ((_E80,), _E80),
    "com_lt":  ((_E80, _E80), _PRED_W),
    "com_eq":  ((_E80, _E80), _PRED_W),
    "com_uno": ((_E80, _E80), _PRED_W),
    "badop":   ((_E80,), _PRED_W),
    "range63": ((_E80,), _PRED_W),
    "atan2":   ((_CW, _E80, _E80), _E80),
    "yl2x":    ((_CW, _E80, _E80), _E80),
    "yl2xp1":  ((_CW, _E80, _E80), _E80),
    "sin":     ((_CW, _E80), _E80),
    "cos":     ((_CW, _E80), _E80),
    "tan":     ((_CW, _E80), _E80),
    "f2xm1":   ((_CW, _E80), _E80),
    "atan":    ((_CW, _E80), _E80),
    "lg2":     ((_CW, _E80), _E80),
    "lg2p1":   ((_CW, _E80), _E80),
}

# ``x87fp_flags_<tail>`` suffix -> (per-argument allowed widths, output 16).
# Mirrors the producer ``_flags(op, args)`` call sites; every flags term
# carries the six SW exception bits in a 16-bit word.
_X87_FLAG_SHAPES: dict[str, tuple[tuple[frozenset[int], ...], frozenset[int]]] = {
    "load":    ((_MEM_FP,), _FLAG_W),
    "narrow32": ((_CW, _E80), _FLAG_W),
    "narrow64": ((_CW, _E80), _FLAG_W),
    "f2i16":   ((_CW, _E80), _FLAG_W),
    "f2i32":   ((_CW, _E80), _FLAG_W),
    "f2i64":   ((_CW, _E80), _FLAG_W),
    "xtract":  ((_E80,), _FLAG_W),
    "fbst":    ((_CW, _E80), _FLAG_W),
    "add":     ((_CW, _E80, _E80), _FLAG_W),
    "sub":     ((_CW, _E80, _E80), _FLAG_W),
    "mul":     ((_CW, _E80, _E80), _FLAG_W),
    "div":     ((_CW, _E80, _E80), _FLAG_W),
    "scale":   ((_CW, _E80, _E80), _FLAG_W),
    "sqrt":    ((_CW, _E80), _FLAG_W),
    "rnd":     ((_CW, _E80), _FLAG_W),
    "rem":     ((_E80, _E80), _FLAG_W),
    "rem1":    ((_E80, _E80), _FLAG_W),
    "com":     ((_E80, _E80), _FLAG_W),
    "ucom":    ((_E80, _E80), _FLAG_W),
    "sin":     ((_E80,), _FLAG_W),
    "cos":     ((_E80,), _FLAG_W),
    "sincos":  ((_E80,), _FLAG_W),
    "ptan":    ((_E80,), _FLAG_W),
    "f2xm1":   ((_E80,), _FLAG_W),
    "atan":    ((_E80, _E80), _FLAG_W),
    "yl2x":    ((_E80, _E80), _FLAG_W),
    "yl2xp1":  ((_E80, _E80), _FLAG_W),
}


def apply_x87_op(op: str, width: int, args: list[Any], z3: Any) -> Any | None:  # noqa: ANN401
    """Interpret one ``x87fp_*`` operator or return ``None`` when unknown.

    Admission is by exact operator name against ``_X87_VALUE_SHAPES`` /
    ``_X87_FLAG_SHAPES``; admitted shapes are validated before evaluation so
    malformed producer terms fail as ``DosUnitError`` instead of silently
    dropping operands or unpacking the wrong arity.
    """
    if not op.startswith("x87fp_"):
        return None
    name = op[6:]
    if name.startswith("flags_"):
        spec = _X87_FLAG_SHAPES.get(name[6:])
        if spec is None:
            return None
        _check_shape(name, spec, width, args, z3)
        return _flags(name[6:], width, args, z3)
    spec = _X87_VALUE_SHAPES.get(name)
    if spec is None:
        return None
    _check_shape(name, spec, width, args, z3)
    return _value_op(name, width, args, z3)


def _check_shape(name: str,
                 spec: tuple[tuple[frozenset[int], ...], frozenset[int]],
                 width: int, args: list[Any], z3: Any) -> None:  # noqa: ANN401
    """Enforce one admission entry: output width, arity, argument widths."""
    arg_widths, out_widths = spec
    if width not in out_widths:
        raise DosUnitError(
            f"x87fp_{name} output width {width} not in {sorted(out_widths)}")
    if len(args) != len(arg_widths):
        raise DosUnitError(
            f"x87fp_{name} expects {len(arg_widths)} args, got {len(args)}")
    for index, (arg, allowed) in enumerate(zip(args, arg_widths, strict=True)):
        if not z3.is_bv(arg) or int(arg.size()) not in allowed:
            got: Any = int(arg.size()) if z3.is_bv(arg) else "non-BV"
            raise DosUnitError(
                f"x87fp_{name} arg{index} width {got} "
                f"not in {sorted(allowed)}")


def _value_op(name: str, width: int, args: list[Any], z3: Any) -> Any:  # noqa: ANN401
    """Evaluate an admitted value operator; shapes already enforced."""
    if name in _X87_ARITH_KINDS:
        return _arith_result(name, args, z3)["value"]
    if name in {"remcc", "remcc1"}:
        return _rem_cc(args[0], args[1], name == "remcc1", z3)
    if name.startswith("com_"):
        return _com_value(name[4:], args, z3)
    return _convert_or_trans(name, width, args, z3)


def _convert_or_trans(name: str, width: int, args: list[Any],
                      z3: Any) -> Any:  # noqa: ANN401
    """Load/store conversion, FXTRACT, BCD and transcendental dispatch."""
    if name == "widen":
        return _widen_value(args[0], z3)
    if name == "narrow":
        return _narrow_value(args[0], args[1], width, z3)
    if name == "i2f":
        fp = z3.fpToFP(z3.RoundNearestTiesToEven(), args[0],
                       _sort(15, 64, z3))
        return _ieee80(fp, z3)
    if name == "f2i":
        return _f2i_value(args[0], args[1], width, z3)
    if name == "xtract_e":
        return _xtract("e", args[0], z3)
    if name == "xtract_s":
        return _xtract("s", args[0], z3)
    if name == "fbld":
        return _fbld_value(args[0], z3)
    if name == "fbst":
        return _fbst_value(args[0], args[1], z3)
    return _trans_value(name, args, z3)


def _widen_value(bits: Any, z3: Any) -> Any:  # noqa: ANN401
    """Widen IEEE memory, retaining NaN sign/payload and quieting sNaN.

    Z3 FP NaN has no payload identity; route NaN encodings around FP
    conversion. The separate flags_load operator supplies invalid for sNaN.
    """
    width = int(bits.size())
    fraction_width = 23 if width == 32 else 52
    exponent_width = width - fraction_width - 1
    fraction = z3.Extract(fraction_width - 1, 0, bits)
    exponent = z3.Extract(width - 2, fraction_width, bits)
    is_nan = z3.And(exponent == (1 << exponent_width) - 1, fraction != 0)
    payload = z3.Concat(fraction, z3.BitVecVal(0, 63 - fraction_width))
    quiet_payload = payload | z3.BitVecVal(1 << 62, 63)
    nan = z3.Concat(z3.Extract(width - 1, width - 1, bits),
                    z3.BitVecVal(0x7FFF, 15), z3.BitVecVal(1, 1), quiet_payload)
    finite = _ieee80(z3.fpToFP(z3.RoundNearestTiesToEven(),
                             _to_fp(bits, z3), _sort(15, 64, z3)), z3)
    return z3.If(is_nan, nan, finite)


def _log_product(name: str, cw: Any, y: Any, x: Any, z3: Any) -> Any:  # noqa: ANN401
    """Whole-instruction ST1*log(ST0) summary for FYL2X/FYL2XP1.

    Modeling the result as a rounded log UF feeding ``x87fp_mul`` would
    invent an intermediate rounding and CW.PC behaviour hardware does not
    exhibit.  This contract encodes the operand classes and the exact
    boundary products verified against pinned bochs-ref/fyl2x.cc and the
    parent-log-edges22 host matrix; only the genuinely inexact finite
    path defers to the ``x87_trans_<op>(cw, y, x)`` uninterpreted
    function, so no equality is manufactured and the approximation
    premise stays explicit.  Arguments: ``y`` = ST(1) multiplier,
    ``x`` = ST(0) log operand.
    """
    cx, cy = _cls(x, z3), _cls(y, z3)
    fn = z3.Function(f"x87_trans_{name}", z3.BitVecSort(16),
                     z3.BitVecSort(80), z3.BitVecSort(80),
                     z3.BitVecSort(80))
    fx = _to_fp(_normv(x, z3), z3)
    indef = _indef(z3)
    pos_inf = _pack(0, _X87_EXP_MAX, _X87_SIG_INF, z3)
    neg_inf = _pack(1, _X87_EXP_MAX, _X87_SIG_INF, z3)
    pos_zero = _pack(0, 0, 0, z3)
    neg_zero = _pack(1, 0, 0, z3)
    f_one = _to_fp(_pack(0, 0x3FFF, _X87_SIG_INF, z3), z3)
    is_one = z3.fpEQ(fx, f_one)
    xp1 = name == "yl2xp1"
    # zSign: FYL2X uses sign(y)^1 (log2(x) sign at the +-0 boundary);
    # FYL2XP1 uses sign(x)^sign(y) (sign of 1+x's log).
    zneg = z3.Xor(cx["neg"], cy["neg"]) if xp1 else z3.Not(cy["neg"])
    signed_inf = z3.If(zneg, neg_inf, pos_inf)
    signed_zero = z3.If(zneg, neg_zero, pos_zero)
    y_signed_inf = z3.If(cy["neg"], neg_inf, pos_inf)
    y_signed_zero = z3.If(cy["neg"], neg_zero, pos_zero)
    x_neg_finite = z3.And(cx["neg"], z3.Not(cx["zero"]))
    # x = +infinity: log is +inf; 0 * inf is invalid, else sign(y) * inf.
    x_inf_r = z3.If(cx["neg"], indef,
                    z3.If(cy["zero"], indef, y_signed_inf))
    if xp1:
        # y = +-infinity: x=+-0 gives 0*inf -> invalid; else zSign inf.
        y_inf_r = z3.If(cx["zero"], indef, signed_inf)
        x_zero_r = signed_zero                    # log2(1+0) = +0 * y
        y_zero_r = signed_zero
        tail = z3.If(
            z3.And(cx["neg"],
                   z3.UGE(_exp(x, z3), z3.BitVecVal(0x3FFF, 15))),
            x,                                    # |x|>=1 negative: keep
            fn(cw, y, x))
        mid = z3.If(cx["zero"], x_zero_r,
                    z3.If(cy["zero"], y_zero_r, tail))
        upper = z3.If(cy["inf"], y_inf_r, mid)
    else:
        # y = +-infinity: x<0 invalid first; x<1 -> zSign inf; x=1 ->
        # 0*inf invalid; x>1 -> sign(y) inf.
        y_inf_r = z3.If(
            x_neg_finite, indef,
            z3.If(z3.fpLT(fx, f_one), signed_inf,
                  z3.If(is_one, indef, y_signed_inf)))
        # x = +-0: y=0 -> 0*inf invalid; else ZE infinity with zSign.
        x_zero_r = z3.If(cy["zero"], indef, signed_inf)
        x_neg_r = indef                           # log2 of negative
        # y = +-0: x<1 -> zSign zero; x>=1 -> sign(y) zero.  x=1.0 (the
        # log=+0 identity) -> sign(y) zero, both exact.
        mid = z3.If(
            cy["zero"],
            z3.If(z3.fpLT(fx, f_one), signed_zero, y_signed_zero),
            z3.If(is_one, y_signed_zero, fn(cw, y, x)))
        upper = z3.If(cy["inf"], y_inf_r,
                      z3.If(cx["zero"], x_zero_r,
                            z3.If(x_neg_finite, x_neg_r, mid)))
    return z3.If(z3.Or(cx["unsupported"], cy["unsupported"]), indef,
                 z3.If(z3.Or(cx["nan"], cy["nan"]),
                       _propagate_nan(x, y, cx, cy, z3),
                       z3.If(cx["inf"], x_inf_r, upper)))


def _trans_value(name: str, args: list[Any], z3: Any) -> Any:  # noqa: ANN401
    """Transcendental values and operand predicates.

    Approximation results are typed uninterpreted functions so architectural
    effects compose while bit equivalence stays a conditional premise, never
    an asserted equality.  The control word is a true input of every
    approximation (RC changes FSIN/FCOS results on hardware), so the UF
    carries ``(cw, operands...)`` — identical UFs can only prove congruence
    under identical inputs, never equality of differing approximations.

    Operand classes are architectural: a NaN operand quiets/propagates its
    payload (host-verified), while inf and unsupported encodings deliver the
    masked indefinite before any approximation.
    """
    if name in {"sin", "cos", "tan", "f2xm1", "atan", "lg2", "lg2p1"}:
        cw, a = args
        c = _cls(a, z3)
        fn = z3.Function(f"x87_trans_{name}", z3.BitVecSort(16),
                         z3.BitVecSort(80), z3.BitVecSort(80))
        # Exact SDM zero edges: sin/tan/f2xm1/lg2p1(+-0)=+-0, cos(+-0)=+1.0,
        # lg2(+-0)=-inf (the divide-by-zero boundary is flagged by the
        # producing yl2x/yl2xp1 effects).
        zero_map = {"cos": z3.BitVecVal(0x3FFF8000000000000000, 80),
                    "lg2": z3.BitVecVal(0xFFFF8000000000000000, 80)}
        core = z3.If(c["zero"], zero_map.get(name, a), fn(cw, a))
        inf_r = _indef(z3)
        if name == "f2xm1":
            # Host + pinned Bochs: 2^(+inf)-1 = +inf, 2^(-inf)-1 = -1.0,
            # no exceptions.
            inf_r = z3.If(c["neg"],
                          z3.BitVecVal(0xBFFF8000000000000000, 80),
                          z3.BitVecVal(0x7FFF8000000000000000, 80))
            # Outside the documented [-1,+1] domain, hardware returns the
            # operand unchanged with PE (pinned bochs-ref/f2xm1.cc); -1.0
            # computes to -0.5 and +1.0 returns itself.
            ge1 = z3.UGE(_exp(a, z3), z3.BitVecVal(0x3FFF, 15))
            is_neg_one = a == z3.BitVecVal(0xBFFF8000000000000000, 80)
            edge = z3.If(is_neg_one,
                         z3.BitVecVal(0xBFFE8000000000000000, 80), a)
            core = z3.If(ge1, edge, core)
        return z3.If(c["unsupported"], _indef(z3),
                     z3.If(c["nan"], _quiet(a, z3),
                           z3.If(c["inf"], inf_r, core)))
    if name == "atan2":
        # FPATAN accepts infinities (SDM atan2 table), so only unsupported
        # encodings preempt the UF; NaNs propagate per the x86 rules.
        cw, a, b = args
        ca, cb = _cls(a, z3), _cls(b, z3)
        fn = z3.Function("x87_trans_atan2", z3.BitVecSort(16),
                         z3.BitVecSort(80), z3.BitVecSort(80),
                         z3.BitVecSort(80))
        return z3.If(z3.Or(ca["unsupported"], cb["unsupported"]),
                     _indef(z3),
                     z3.If(z3.Or(ca["nan"], cb["nan"]),
                           _propagate_nan(a, b, ca, cb, z3),
                           fn(cw, a, b)))
    if name in {"yl2x", "yl2xp1"}:
        return _log_product(name, args[0], args[1], args[2], z3)
    if name == "badop":
        # Masked-invalid operand class: NaN/inf/unsupported encodings drive
        # the indefinite-NaN masked response.
        c = _cls(args[0], z3)
        return z3.If(z3.Or(c["nan"], c["inf"], c["unsupported"]),
                     z3.BitVecVal(1, 1), z3.BitVecVal(0, 1))
    # range63: |a| < 2**63 in-range predicate for argument reduction
    # (C2=1 when 0).
    c = _cls(args[0], z3)
    fa = _to_fp(_normv(args[0], z3), z3)
    bound = _f80_const(0, 0x3FFF + 63, 1 << 63, z3)
    return z3.If(z3.And(z3.Not(c["inf"]), z3.Not(c["nan"]),
                        z3.Not(c["unsupported"]),
                        z3.fpLT(z3.fpAbs(fa), bound)),
                 z3.BitVecVal(1, 1), z3.BitVecVal(0, 1))


def _sort(exp_bits: int, sig_bits: int, z3: Any) -> Any:  # noqa: ANN401
    return z3.FPSort(exp_bits, sig_bits)


def _fp_sort_for_width(width: int, z3: Any) -> Any:  # noqa: ANN401
    if width == 32:
        return _sort(8, 24, z3)
    if width == 64:
        return _sort(11, 53, z3)
    return _sort(15, 64, z3)



def _to_fp(bits: Any, z3: Any) -> Any:  # noqa: ANN401
    """Convert an IEEE/ext80 BV into the FP sort matching its width.

    Architectural ext80 carries an explicit integer bit (bit 63); Z3's IEEE
    bit-vector for ``FPSort(15,64)`` is 79 bits with an implicit leading bit.
    For every supported ext80 encoding the integer bit equals that implicit
    bit, so conversion only drops or re-derives bit 63.  Unsupported encodings
    are classified at BV level before FP evaluation.
    """
    if int(bits.size()) == 80:
        packed = z3.Concat(z3.Extract(79, 79, bits), z3.Extract(78, 64, bits),
                           z3.Extract(62, 0, bits))
        return z3.fpToFP(packed, _sort(15, 64, z3))
    return z3.fpToFP(bits, _fp_sort_for_width(int(bits.size()), z3))


def _ieee(fp: Any, z3: Any) -> Any:  # noqa: ANN401
    return z3.fpToIEEEBV(fp)


def _ieee80(fp: Any, z3: Any) -> Any:  # noqa: ANN401
    """Pack a (15,64) FP result into the architectural ext80 encoding."""
    packed = _ieee(fp, z3)
    exp = z3.Extract(77, 63, packed)
    intbit = z3.If(exp == 0, z3.BitVecVal(0, 1), z3.BitVecVal(1, 1))
    return z3.Concat(z3.Extract(78, 78, packed), exp, intbit,
                     z3.Extract(62, 0, packed))


def _indef(z3: Any) -> Any:  # noqa: ANN401
    return z3.BitVecVal(_X87_INDEF, 80)


def _rm(cw: Any, z3: Any) -> Any:  # noqa: ANN401
    """Dynamic rounding-mode value from CW bits 10-11 (x87 RC encoding)."""
    rc = z3.Extract(11, 10, cw)
    return z3.If(rc == 0, z3.RoundNearestTiesToEven(), z3.If(
        rc == 1, z3.RoundTowardNegative(), z3.If(
            rc == 2, z3.RoundTowardPositive(), z3.RoundTowardZero())))


def _rc(cw: Any, z3: Any) -> Any:  # noqa: ANN401
    return z3.Extract(11, 10, cw)


def _pc_bits(cw: Any, z3: Any) -> Any:  # noqa: ANN401
    """Precision-control target significand width: 0→24, 2→53, 3→64, 1→24."""
    pc = z3.Extract(9, 8, cw)
    return z3.If(z3.Or(pc == 0, pc == 1), z3.BitVecVal(24, 8),
                 z3.If(pc == 2, z3.BitVecVal(53, 8), z3.BitVecVal(64, 8)))


def _exp(a: Any, z3: Any) -> Any:  # noqa: ANN401
    return z3.Extract(78, 64, a)


def _sig(a: Any, z3: Any) -> Any:  # noqa: ANN401
    return z3.Extract(63, 0, a)


def _frac(a: Any, z3: Any) -> Any:  # noqa: ANN401
    return z3.Extract(62, 0, a)


def _cls(a: Any, z3: Any) -> dict[str, Any]:  # noqa: ANN401
    """Architectural ext80 operand classes over the explicit-integer-bit BV."""
    exp, sig = _exp(a, z3), _sig(a, z3)
    max_exp = exp == _X87_EXP_MAX
    nan = z3.And(max_exp, _frac(a, z3) != 0)
    return {
        # Only unnormals (exp!=0, J=0) are unsupported per
        # softfloat3e extF80_isUnsupported; pseudo-denormals (exp=0, J=1)
        # are denormal-class operands that normalize to the exp=1 value.
        "unsupported": z3.And(z3.Extract(63, 63, a) == 0, exp != 0),
        "nan": nan,
        "snan": z3.And(nan, z3.Extract(62, 62, a) == 0),
        "inf": z3.And(max_exp, sig == _X87_SIG_INF),
        "zero": z3.And(exp == 0, sig == 0),
        "denormal": z3.And(exp == 0, sig != 0),
        "neg": z3.Extract(79, 79, a) == 1,
    }


def _quiet(a: Any, z3: Any) -> Any:  # noqa: ANN401
    """Quiet an ext80 NaN in place: set the quiet bit, keep sign/payload."""
    return a | z3.BitVecVal(1 << 62, 80)


def _pack(sign: Any, exp_field: Any, sig: Any, z3: Any) -> Any:  # noqa: ANN401
    """Assemble sign/exp/significand BVs into the ext80 encoding."""
    return z3.Concat(_resize1(sign, z3), _resize_exp(exp_field, z3),
                     _resize_sig(sig, z3))


def _asbv(v: Any, z3: Any) -> Any:  # noqa: ANN401
    if z3.is_bool(v):
        return z3.If(v, z3.BitVecVal(1, 1), z3.BitVecVal(0, 1))
    if hasattr(v, "size"):
        return v
    return z3.BitVecVal(v, max(32, int(v).bit_length()))


def _resize1(v: Any, z3: Any) -> Any:  # noqa: ANN401
    v = _asbv(v, z3)
    size = int(v.size())
    return v if size == 1 else z3.Extract(0, 0, v)


def _resize_exp(v: Any, z3: Any) -> Any:  # noqa: ANN401
    v = _asbv(v, z3)
    size = int(v.size())
    if size == 15:
        return v
    if size > 15:
        return z3.Extract(14, 0, v)
    return z3.ZeroExt(15 - size, v)


def _resize_sig(v: Any, z3: Any) -> Any:  # noqa: ANN401
    v = _asbv(v, z3)
    size = int(v.size())
    if size == 64:
        return v
    if size > 64:
        return z3.Extract(63, 0, v)
    return z3.ZeroExt(64 - size, v)



def _msb_pos(x: Any, z3: Any) -> Any:  # noqa: ANN401
    """Index of the most significant set bit of a BV (0 when input is 0)."""
    pos = z3.BitVecVal(0, 8)
    for step in (128, 64, 32, 16, 8, 4, 2, 1):
        cand = pos + z3.BitVecVal(step, 8)
        pos = z3.If(z3.LShR(x, z3.ZeroExt(_EXT_WIDTH - 8, cand)) != 0, cand, pos)
    return pos


def _sext20(v: Any, z3: Any) -> Any:  # noqa: ANN401
    size = int(v.size())
    if size == 20:
        return v
    if size > 20:
        return z3.Extract(19, 0, v)
    return z3.SignExt(20 - size, v)


def _shamt(v: Any, z3: Any) -> Any:  # noqa: ANN401
    """Unsigned 202-bit shift operand from a signed 20-bit magnitude."""
    return z3.ZeroExt(_EXT_WIDTH - 16, z3.Extract(15, 0, v))


def _exact_pack(sign: Any, scale: Any, mag: Any, sticky_low: Any,  # noqa: ANN401
                cw: Any, target_bits: Any | None, z3: Any) -> dict[str, Any]:  # noqa: ANN401
    """Normalize ``mag * 2^scale`` and round exactly once to ``target_bits``.

    ``mag`` is a ``_EXT_WIDTH``-wide unsigned exact magnitude whose bit 0 has
    unbiased exponent ``scale``; ``sticky_low`` records analytic low bits
    discarded outside the alignment window.  Returns the packed ext80 value
    plus ``inexact``/``denormal``/``overflow`` conditions for the flag layer.
    Denormal outputs fold the exponent clamp into the rounding shift; the
    masked overflow response follows RC (inf or largest finite).
    """
    p = z3.ZeroExt(12, _msb_pos(mag, z3))
    exp_field = _sext20(scale, z3) + p + z3.BitVecVal(0x3FFF, 20)
    target = _sext20(target_bits if target_bits is not None else _pc_bits(cw, z3), z3)
    den = exp_field < 1
    den_shift = z3.If(den, 1 - exp_field, z3.BitVecVal(0, 20))
    shift = p - (target - 1) + den_shift
    neg = shift < 0
    norm = z3.If(neg, mag << _shamt(-shift, z3), z3.LShR(mag, _shamt(shift, z3)))
    drop_mask = z3.If(z3.Or(neg, shift == 0), z3.BitVecVal(0, _EXT_WIDTH),
                      (z3.BitVecVal(1, _EXT_WIDTH) << _shamt(shift, z3)) - 1)
    dropped_bits = mag & drop_mask
    half = z3.If(shift < 1, z3.BitVecVal(0, _EXT_WIDTH),
                 z3.BitVecVal(1, _EXT_WIDTH) << _shamt(shift - 1, z3))
    guard = (dropped_bits & half) != 0
    rest = z3.If(shift < 2, False,
                 (mag & ((z3.BitVecVal(1, _EXT_WIDTH) << _shamt(shift - 1, z3)) - 1)) != 0)
    inexact = z3.Or(dropped_bits != 0, sticky_low)
    rest_any = z3.Or(rest, sticky_low)
    lsb = z3.Extract(0, 0, norm) == 1
    rc = _rc(cw, z3)
    rne_up = z3.And(guard, z3.Or(rest_any, lsb))
    directed_up = z3.Or(z3.And(rc == 1, sign == 1, inexact),
                        z3.And(rc == 2, sign == 0, inexact))
    round_up = z3.If(rc == 0, rne_up, directed_up)
    keep = norm + z3.If(round_up, z3.BitVecVal(1, _EXT_WIDTH),
                        z3.BitVecVal(0, _EXT_WIDTH))
    carry = z3.LShR(keep, z3.ZeroExt(_EXT_WIDTH - 20, target)) != 0
    keep = z3.If(carry, z3.LShR(keep, 1), keep)
    # Denormal->normal promotion: with den_shift == 1 the kept significand's
    # leading bit sits at `target - 1`, which is the integer (J) bit of the
    # ext80 encoding.  Rounding a max-magnitude denormal up must therefore
    # produce exponent 1 (minimum normal), never exp 0 with J set
    # (pseudo-denormal).  Host + testfloat_ver evidence: PC64/RNE
    # 0001_8000000000000000 * 3FFE_FFFFFFFFFFFFFFFF -> 0001_8000000000000000
    # with UE|PE (numeric10-denormal-boundary.json).
    promote = z3.And(den, z3.LShR(keep, z3.ZeroExt(_EXT_WIDTH - 20, target - 1)) != 0)
    exp_out = z3.If(den, z3.If(promote, z3.BitVecVal(1, 20), z3.BitVecVal(0, 20)),
                    exp_field + z3.If(carry, z3.BitVecVal(1, 20), z3.BitVecVal(0, 20)))
    overflow = z3.And(z3.Not(den), exp_out > 0x7FFE)
    away = z3.Or(rc == 0, z3.Or(z3.And(rc == 1, sign == 1),
                                z3.And(rc == 2, sign == 0)))
    # Masked overflow response: RNE (and toward-the-sign directions) gives
    # infinity; the opposing directed modes give the largest finite value at
    # the *target* precision — exponent 0x7FFE, significand of `target` ones
    # (SoftFloat3e roundPackToExtF80's LT-inf/max case), not an all-ones
    # encoding under exponent 0x7FFF which is a pseudo-NaN.
    max_sig = ((z3.BitVecVal(1, _EXT_WIDTH) << z3.ZeroExt(_EXT_WIDTH - 20, target))
               - 1) << _shamt(64 - target, z3)
    sig_out = z3.If(overflow,
                    z3.If(away, z3.BitVecVal(_X87_SIG_INF, _EXT_WIDTH), max_sig),
                    keep << _shamt(64 - target, z3))
    exp_res = z3.If(overflow,
                    z3.If(away, z3.BitVecVal(_X87_EXP_MAX, 20),
                          z3.BitVecVal(0x7FFE, 20)),
                    exp_out)
    value = z3.If(mag == 0, _pack(sign, 0, 0, z3),
                  _pack(sign, exp_res, _resize_sig(sig_out, z3), z3))
    return {
        "value": value,
        # Masked overflow implies inexact: rounding to inf/max-finite is a
        # rounded result (SoftFloat3e raises overflow+inexact together).
        "inexact": z3.Or(inexact, overflow),
        # Tininess for x87 is detected BEFORE rounding: the pre-rounding
        # exponent field below 1 marks the result tiny whether it stays
        # denormal, promotes to minimum normal, or flushes to signed zero.
        # Host evidence (numeric10-denormal-boundary.json): the promoted
        # min-normal result still raises UE|PE = 0x30.
        "denormal": den,
        "overflow": overflow,
        "round_up": round_up,
    }


def _exact_addsub(sub: bool, cw: Any, a: Any, b: Any, z3: Any) -> dict[str, Any]:  # noqa: ANN401
    """Exact finite add/sub: align to the smaller exponent once, then round."""
    sa = z3.Extract(79, 79, a)
    sb = z3.Extract(79, 79, b)
    ea, ma = _norm_ms(a, z3)
    eb, mb = _norm_ms(b, z3)
    sb_eff = sb if not sub else sb ^ z3.BitVecVal(1, 1)
    same = sa == sb_eff
    swap = ea < eb
    e_hi = z3.If(swap, eb, ea)
    e_lo = z3.If(swap, ea, eb)
    m_hi = z3.If(swap, mb, ma)
    m_lo = z3.If(swap, ma, mb)
    s_hi = z3.If(swap, sb_eff, sa)
    s_lo = z3.If(swap, sa, sb_eff)
    gap = e_hi - e_lo
    near = z3.ULE(gap, 136)
    m_hi_w = z3.ZeroExt(_EXT_WIDTH - 64, m_hi)
    m_lo_w = z3.ZeroExt(_EXT_WIDTH - 64, m_lo)
    hi_shift = m_hi_w << z3.ZeroExt(_EXT_WIDTH - 20, gap)
    mag_sum = hi_shift + m_lo_w
    hi_ge = z3.UGE(hi_shift, m_lo_w)
    mag_dif = z3.If(hi_ge, hi_shift - m_lo_w, m_lo_w - hi_shift)
    dif_sign = z3.If(hi_ge, s_hi, s_lo)
    mag_far_add = m_hi_w << z3.BitVecVal(136, _EXT_WIDTH)
    # Far subtraction is m_hi*2^136 - m_lo = (m_hi-1)*2^136 + (2^136 - m_lo).
    # The borrowed low word fills the guard window: with m_lo != 0 it always
    # exceeds half of the dropped range, so nearest/directed rounding must
    # see those real bits, not just a sticky flag (SoftFloat3e keeps the
    # full shifted significand). m_lo == 0 folds back to m_hi*2^136 exactly.
    mag_far_sub = ((m_hi_w - z3.BitVecVal(1, _EXT_WIDTH)) << z3.BitVecVal(136, _EXT_WIDTH)
                   ) + (z3.BitVecVal(1 << 136, _EXT_WIDTH) - m_lo_w)
    mag = z3.If(near, z3.If(same, mag_sum, mag_dif),
                z3.If(same, mag_far_add, mag_far_sub))
    sticky_low = z3.And(z3.Not(near), m_lo != 0)
    scale_lo = e_lo - z3.BitVecVal(0x3FFF + 63, 20)
    scale_hi = scale_lo + _sext20(gap, z3) - z3.BitVecVal(136, 20)
    scale = z3.If(near, scale_lo, scale_hi)
    sign = z3.If(same, sa, z3.If(near, dif_sign, s_hi))
    packed = _exact_pack(sign, scale, mag, sticky_low, cw, None, z3)
    cancel = z3.And(z3.Not(same), near, mag_dif == 0)
    packed["value"] = z3.If(
        cancel, _pack(_rc(cw, z3) == 1, 0, 0, z3), packed["value"])
    packed["inexact"] = z3.And(packed["inexact"], z3.Not(cancel))
    return packed


def _exact_mul(cw: Any, a: Any, b: Any, z3: Any) -> dict[str, Any]:  # noqa: ANN401
    """Exact finite multiply: the 64x64 product needs no alignment window."""
    sa = z3.Extract(79, 79, a)
    sb = z3.Extract(79, 79, b)
    ea, ma = _norm_ms(a, z3)
    eb, mb = _norm_ms(b, z3)
    prod = z3.ZeroExt(_EXT_WIDTH - 128, z3.ZeroExt(64, ma) * z3.ZeroExt(64, mb))
    scale = ea + eb - z3.BitVecVal(2 * 0x3FFF + 126, 20)
    return _exact_pack(sa ^ sb, scale, prod, False, cw, None, z3)


def _exact_div(cw: Any, a: Any, b: Any, z3: Any) -> dict[str, Any]:  # noqa: ANN401
    """Exact finite divide: 66 shifted quotient bits plus remainder sticky."""
    sa = z3.Extract(79, 79, a)
    sb = z3.Extract(79, 79, b)
    ea, ma = _norm_ms(a, z3)
    eb, mb = _norm_ms(b, z3)
    num = z3.ZeroExt(_EXT_WIDTH - 64, ma) << z3.BitVecVal(66, _EXT_WIDTH)
    den = z3.ZeroExt(_EXT_WIDTH - 64, mb)
    quot = z3.UDiv(num, den)
    scale = ea - eb - z3.BitVecVal(66, 20)
    return _exact_pack(sa ^ sb, scale, quot, z3.URem(num, den) != 0, cw, None, z3)


def _exact_sqrt(cw: Any, a: Any, z3: Any) -> dict[str, Any]:  # noqa: ANN401
    """Exact finite sqrt via integer square root on the shifted significand."""
    ea, ma = _norm_ms(a, z3)
    u = ea - z3.BitVecVal(0x3FFF + 63, 20)
    odd = (u & 1) != 0
    rad_w = z3.ZeroExt(_EXT_WIDTH - 64, ma) << z3.If(
        odd, z3.BitVecVal(127, _EXT_WIDTH), z3.BitVecVal(126, _EXT_WIDTH))
    root, has_rem = _isqrt(rad_w, z3)
    half = _sext20(u - z3.If(odd, z3.BitVecVal(1, 20), z3.BitVecVal(0, 20)), z3)
    scale = z3.BitVecVal(0, 20) + (half >> 1) - z3.BitVecVal(63, 20)
    return _exact_pack(z3.BitVecVal(0, 1), scale, root, has_rem, cw, None, z3)


def _isqrt(x: Any, z3: Any) -> tuple[Any, Any]:  # noqa: ANN401
    """Integer square root of a wide BV via the unrolled bit-trial method."""
    root = z3.BitVecVal(0, _EXT_WIDTH)
    rem = z3.BitVecVal(0, _EXT_WIDTH + 2)
    for i in range((_EXT_WIDTH + 1) // 2):
        pair = z3.Extract(_EXT_WIDTH - 1 - 2 * i, _EXT_WIDTH - 2 - 2 * i, x)
        rem = z3.Concat(z3.Extract(_EXT_WIDTH - 1, 0, rem), pair)
        trial = z3.Concat(z3.Extract(_EXT_WIDTH - 1, 0, root), z3.BitVecVal(1, 2))
        take = z3.UGE(rem, trial)
        rem = z3.If(take, rem - trial, rem)
        root = z3.Concat(z3.Extract(_EXT_WIDTH - 2, 0, root),
                         z3.If(take, z3.BitVecVal(1, 1), z3.BitVecVal(0, 1)))
    return root, rem != 0



def _normv(a: Any, z3: Any) -> Any:  # noqa: ANN401
    """Corrected ext80 operand for value math.

    Pseudo-denormals (exp=0, J=1) are legal operands; SoftFloat3e normalizes
    them through ``normSubnormalExtF80Sig`` (shift distance 0) to the normal
    encoding with exponent 1.  Real denormals and all other encodings pass
    through unchanged.
    """
    pseudo = z3.And(_exp(a, z3) == 0, z3.Extract(63, 63, a) == 1)
    return z3.If(pseudo, _pack(z3.Extract(79, 79, a), 1, _sig(a, z3), z3), a)


def _norm_ms(a: Any, z3: Any) -> tuple[Any, Any]:  # noqa: ANN401
    """Normalize a finite ext80 operand: (signed20 exponent, sig64).

    Mirrors ``softfloat_normSubnormalExtF80Sig`` + ``aExp = normExp + 1``:
    denormal inputs (exp=0, J=0) shift their significand left until the
    integer bit is set and take the correspondingly negative exponent.
    Normal operands are returned unchanged.
    """
    e, m = _exp(a, z3), _sig(a, z3)
    den = e == 0
    msb = z3.ZeroExt(12, _msb_pos(z3.ZeroExt(_EXT_WIDTH - 64, m), z3))
    e_n = z3.If(den, msb - z3.BitVecVal(62, 20), z3.ZeroExt(5, e))
    lz = z3.BitVecVal(63, 20) - msb
    m_n = z3.If(den, m << z3.ZeroExt(58, z3.Extract(5, 0, lz)), m)
    return e_n, m_n


def _exact_rem(a: Any, b: Any, ieee: bool, z3: Any) -> dict[str, Any]:  # noqa: ANN401
    """FPREM/FPREM1 remainder core after the SoftFloat3e ``do_fprem`` model.

    Both operands must be finite and nonzero (caller's special paths handle
    unsupported/NaN/inf/zero).  The dividend is aligned into a 128-bit frame
    at the divisor's scale; the kernel is ``N mod mb`` exactly.  ``ieee``
    selects FPREM1 (nearest-even quotient adjustment against b/2, possible
    sign flip) versus FPREM (truncated quotient, dividend sign).

    Partial reduction for ``expDiff >= 64`` follows the emulator:
    ``n = (expDiff & 31) | 32`` bits are consumed, C2 is raised and the
    condition-code quotient bits read 0.  Returns the result value plus
    ``c2`` and the low quotient for C1/C3/C0 (C1=q0, C3=q1, C0=q2).
    """
    sa = z3.Extract(79, 79, a)
    ea, ma = _norm_ms(a, z3)
    eb, mb = _norm_ms(b, z3)
    g = ea - eb
    ma_w = z3.ZeroExt(_EXT_WIDTH - 64, ma)
    b128 = z3.ZeroExt(_EXT_WIDTH - 64, mb) << z3.BitVecVal(64, _EXT_WIDTH)
    partial = g >= 64
    n_part = (g & z3.BitVecVal(0x1F, 20)) | z3.BitVecVal(0x20, 20)
    g_c = z3.If(g == -1, z3.BitVecVal(-1, 20), z3.If(g < -1, z3.BitVecVal(0, 20), g))
    shift = z3.If(partial, z3.BitVecVal(64, 20) + n_part, z3.BitVecVal(64, 20) + g_c)
    a128 = ma_w << z3.ZeroExt(_EXT_WIDTH - 8,
                              z3.Concat(z3.BitVecVal(0, 1), z3.Extract(6, 0, shift)))
    q = z3.If(z3.Or(partial, g < -1), z3.BitVecVal(0, _EXT_WIDTH),
              z3.UDiv(a128, b128))
    rem = z3.If(g < -1, z3.BitVecVal(0, _EXT_WIDTH), z3.URem(a128, b128))
    scale = eb - z3.BitVecVal(0x3FFF + 127, 20) + z3.If(partial, g - n_part,
                                                       z3.BitVecVal(0, 20))
    if ieee:
        half = b128 >> 1
        over = z3.UGT(rem, half)
        tie_odd = z3.And(rem == half, z3.Extract(0, 0, q) == 1)
        flip = z3.Or(over, tie_odd)
        rem = z3.If(over, b128 - rem, rem)
        sign = sa ^ z3.If(flip, z3.BitVecVal(1, 1), z3.BitVecVal(0, 1))
        q = q + z3.If(flip, z3.BitVecVal(1, _EXT_WIDTH),
                        z3.BitVecVal(0, _EXT_WIDTH))
    else:
        sign = sa
    packed = _exact_pack(sign, scale, rem, False, z3.BitVecVal(0x037F, 16),
                         z3.BitVecVal(64, 20), z3)
    value = z3.If(g < -1, _normv(a, z3), packed["value"])
    q3 = z3.If(partial, z3.BitVecVal(0, 3), z3.Extract(2, 0, q))
    return {"value": value, "c2": partial, "q_low3": q3}


def _xtract(part: str, a: Any, z3: Any) -> Any:  # noqa: ANN401
    """FXTRACT split components of an operand, specials included.

    ``xtract_e``: the unbiased exponent as a real number (exact, fits int32).
    ``xtract_s``: the significand re-encoded with exponent field 0x3FFF and
    the operand's sign; denormal inputs are normalized first (SDM: the split
    applies to the normalized source).  Special operands follow the SDM
    table: +-0 -> exponent part -inf, significand part +-0 (ZE raised by the
    flags layer); +-inf -> +inf exponent, sign-preserving inf significand;
    NaN -> quieted propagation; unsupported -> indefinite.
    """
    c = _cls(a, z3)
    sa = z3.Extract(79, 79, a)
    e_n, m = _norm_ms(a, z3)
    pos_inf = _pack(0, _X87_EXP_MAX, _X87_SIG_INF, z3)
    if part == "e":
        ue = e_n - z3.BitVecVal(0x3FFF, 20)
        fp = z3.fpToFP(z3.RoundNearestTiesToEven(), z3.SignExt(12, ue),
                       _sort(15, 64, z3))
        finite = _ieee80(fp, z3)
        special = z3.If(c["zero"], _pack(1, _X87_EXP_MAX, _X87_SIG_INF, z3),
                        pos_inf)
    else:
        finite = _pack(sa, z3.BitVecVal(0x3FFF, 15), m, z3)
        special = z3.If(c["zero"], _pack(sa, 0, 0, z3),
                        _pack(sa, _X87_EXP_MAX, _X87_SIG_INF, z3))
    return z3.If(c["nan"], _quiet(a, z3),
                 z3.If(c["unsupported"], _indef(z3),
                       z3.If(z3.Or(c["zero"], c["inf"]), special, finite)))


def _flags_xtract(a: Any, z3: Any) -> Any:  # noqa: ANN401
    """FXTRACT exception bits: IE on unsupported/SNaN, DE, ZE on +-0."""
    c = _cls(a, z3)
    return _flags_pack({
        "IE": z3.Or(c["unsupported"], c["snan"]),
        "DE": c["denormal"],
        "ZE": c["zero"]}, z3)


def _exact_scale(cw: Any, a: Any, b: Any, z3: Any) -> dict[str, Any]:  # noqa: ANN401
    """FSCALE exact core: ``a * 2^trunc(b)``.

    The scale operand's integer part is taken by truncation toward zero
    (SDM: a non-integral ST(1) is truncated toward 0 before scaling) and
    clamped far beyond the representable exponent range, so saturated
    results flow through the pack's overflow/underflow response instead of
    wrapping the 15-bit exponent.  The significand is kept at full 64-bit
    precision: PC does not apply to FSCALE, and CW.RC still rounds any
    denormal boundary result.  Both operands must be finite and nonzero
    (caller handles NaN/inf/zero); denormal inputs are normalized.
    """
    e_a, m_a = _norm_ms(a, z3)
    e_b, m_b = _norm_ms(b, z3)
    e1 = e_b - z3.BitVecVal(0x3FFF, 20)  # unbiased exponent of |b|
    # |b| < 1 truncates to 0; e1 >= 63 means |trunc| >= 2^62, far beyond
    # the exponent range, so clamp instead of shifting the significand.
    shift = z3.BitVecVal(63, 20) - e1
    trunc = z3.LShR(z3.ZeroExt(_EXT_WIDTH - 64, m_b), _shamt(shift, z3))
    clamp = z3.BitVecVal(0x40000, _EXT_WIDTH)
    k_mag = z3.If(e1 < 0, z3.BitVecVal(0, _EXT_WIDTH),
                  z3.If(e1 >= 63, clamp,
                        z3.If(z3.UGT(trunc, clamp), clamp, trunc)))
    k = z3.If(z3.Extract(79, 79, b) == 1,
              -k_mag, k_mag)
    scale = e_a - z3.BitVecVal(0x3FFF + 63, 20) + z3.Extract(19, 0, k)
    return _exact_pack(z3.Extract(79, 79, a), scale,
                       z3.ZeroExt(_EXT_WIDTH - 64, m_a), False, cw,
                       z3.BitVecVal(64, 20), z3)


def _propagate_nan(a: Any, b: Any, ca: dict[str, Any], cb: dict[str, Any],  # noqa: ANN401
                   z3: Any) -> Any:  # noqa: ANN401
    """x86 NaN selection, matching SoftFloat 8086 extF80 specialization.

    Prefer quiet over signaling NaN. For equal classes choose larger payload,
    then positive sign on equal payload. A lone NaN is quieted in place.
    Invalid exception signaling is handled by the flags operator.
    """
    qa, qb = _quiet(a, z3), _quiet(b, z3)
    a_quiet = z3.And(ca["nan"], z3.Not(ca["snan"]))
    b_quiet = z3.And(cb["nan"], z3.Not(cb["snan"]))
    a_sig, b_sig = _sig(a, z3), _sig(b, z3)
    a_larger = z3.Or(z3.UGT(a_sig, b_sig),
                     z3.And(a_sig == b_sig, z3.Not(ca["neg"])))
    same_class = z3.If(a_larger, qa, qb)
    both = z3.If(z3.And(a_quiet, cb["snan"]), qa,
                 z3.If(z3.And(b_quiet, ca["snan"]), qb, same_class))
    return z3.If(z3.And(ca["nan"], cb["nan"]), both,
                 z3.If(ca["nan"], qa, qb))


def _invalid_combo(kind: str, ca: dict[str, Any], cb: dict[str, Any], z3: Any) -> Any:  # noqa: ANN401
    """Invalid-operation condition when neither input is a NaN."""
    if kind == "add":
        return z3.And(ca["inf"], cb["inf"], ca["neg"] != cb["neg"])
    if kind == "sub":
        return z3.And(ca["inf"], cb["inf"], ca["neg"] == cb["neg"])
    if kind == "mul":
        return z3.Or(z3.And(ca["inf"], cb["zero"]), z3.And(ca["zero"], cb["inf"]))
    if kind == "div":
        return z3.Or(z3.And(ca["zero"], cb["zero"]), z3.And(ca["inf"], cb["inf"]))
    if kind == "sqrt":
        return z3.And(ca["neg"], z3.Not(ca["zero"]))
    if kind == "rem":
        return z3.Or(ca["inf"], cb["zero"])
    # scale has no IEEE-invalid operand combination beyond NaN/unsupported.
    return False


def _special_value(kind: str, ca: dict[str, Any], cb: dict[str, Any],
                   a: Any, b: Any, exact: Any, z3: Any) -> Any:  # noqa: ANN401
    """Direct results when at least one operand is non-finite or zero."""
    if kind == "add":
        # Zero operands flow through the exact engine: x87 still applies the
        # PC rounding to the surviving operand (TestFloat precision32 rows
        # expect PE and a narrowed significand on x + 0), and the engine's
        # cancel path implements the sign-of-exact-zero rules.
        return z3.If(ca["inf"], a, z3.If(cb["inf"], b, exact))
    if kind == "sub":
        return z3.If(ca["inf"], a,
                     z3.If(cb["inf"], _pack(z3.Not(cb["neg"]), _X87_EXP_MAX,
                                            _X87_SIG_INF, z3),
                           exact))
    if kind == "mul":
        sign = ca["neg"] != cb["neg"]
        inf_out = _pack(sign, _X87_EXP_MAX, _X87_SIG_INF, z3)
        zero_out = _pack(sign, 0, 0, z3)
        return z3.If(z3.Or(ca["inf"], cb["inf"]), inf_out,
                     z3.If(z3.Or(ca["zero"], cb["zero"]), zero_out, exact))
    if kind == "div":
        sign = ca["neg"] != cb["neg"]
        inf_out = _pack(sign, _X87_EXP_MAX, _X87_SIG_INF, z3)
        zero_out = _pack(sign, 0, 0, z3)
        return z3.If(ca["inf"],
                     z3.If(cb["inf"], _indef(z3), inf_out),
                     z3.If(cb["inf"], zero_out,
                          z3.If(cb["zero"], inf_out,
                                z3.If(ca["zero"], zero_out, exact))))
    if kind == "scale":
        # FSCALE special paths: a=inf -> a; b=+inf -> inf with a's sign,
        # b=-inf -> signed zero of a's sign; a=0 or b=0 -> normalized a.
        # (Exponent saturation through the pack agrees with +inf.)
        av = _normv(a, z3)
        sa = ca["neg"]
        return z3.If(ca["inf"], a,
                     z3.If(cb["inf"],
                           z3.If(cb["neg"], _pack(sa, 0, 0, z3),
                                 _pack(sa, _X87_EXP_MAX, _X87_SIG_INF, z3)),
                           z3.If(z3.Or(ca["zero"], cb["zero"]), av, exact)))
    return exact


def _arith_result(kind: str, args: list[Any], z3: Any) -> dict[str, Any]:  # noqa: ANN401
    """Apply unsupported-encoding precedence before ordinary NaN selection.

    Native x87 returns the masked indefinite for any unnormal/pseudo-NaN
    operand, even when another operand is an ordinary NaN. Preserve the
    core metadata consumed by exception calculation.
    """
    result = _arith_core(kind, args, z3)
    operands = args if kind in {"rem", "rem1"} else args[1:]
    unsupported = z3.Or(*[_cls(arg, z3)["unsupported"] for arg in operands])
    result["value"] = z3.If(unsupported, _indef(z3), result["value"])
    return result


def _arith_core(kind: str, args: list[Any], z3: Any) -> dict[str, Any]:  # noqa: ANN401
    """Masked x87 result and exception bits over architectural operands."""
    if kind in {"rem", "rem1"}:
        a, b = args
        ca, cb = _cls(a, z3), _cls(b, z3)
        bad = z3.Or(
            ca["unsupported"], cb["unsupported"],
            z3.And(z3.Not(ca["nan"]), z3.Not(cb["nan"]),
                   _invalid_combo("rem", ca, cb, z3)))
        core = _exact_rem(a, b, kind == "rem1", z3)
        av = _normv(a, z3)
        value = z3.If(z3.Or(ca["nan"], cb["nan"]), _propagate_nan(a, b, ca, cb, z3),
                      z3.If(bad, _indef(z3),
                            z3.If(z3.Or(ca["zero"], cb["inf"]), av, core["value"])))
        return {"value": value, "a": a, "b": b, "rem": core}
    cw, a = args[0], args[1]
    if kind == "rnd":
        ca = _cls(a, z3)
        raw = _ieee80(z3.fpRoundToIntegral(_rm(cw, z3), _to_fp(_normv(a, z3), z3)), z3)
        value = z3.If(ca["nan"], _quiet(a, z3),
                      z3.If(z3.Or(ca["unsupported"], ca["snan"]), _indef(z3), raw))
        return {"value": value, "a": a}
    if kind == "sqrt":
        ca = _cls(a, z3)
        bad = z3.Or(ca["unsupported"], ca["snan"],
                    z3.And(z3.Not(ca["nan"]), _invalid_combo("sqrt", ca, ca, z3)))
        exact = _exact_sqrt(cw, a, z3)
        value = z3.If(ca["nan"], _quiet(a, z3),
                      z3.If(bad, _indef(z3),
                            z3.If(z3.Or(ca["inf"], ca["zero"]), a, exact["value"])))
        return {"value": value, "a": a, "exact": exact}
    b = args[2]
    ca, cb = _cls(a, z3), _cls(b, z3)
    engines = {"add": lambda: _exact_addsub(False, cw, a, b, z3),
               "sub": lambda: _exact_addsub(True, cw, a, b, z3),
               "mul": lambda: _exact_mul(cw, a, b, z3),
               "div": lambda: _exact_div(cw, a, b, z3),
               "scale": lambda: _exact_scale(cw, a, b, z3)}
    exact = engines[kind]()
    special = _special_value(kind, ca, cb, a, b, exact["value"], z3)
    bad = z3.Or(
        ca["unsupported"], cb["unsupported"],
        z3.And(z3.Not(ca["nan"]), z3.Not(cb["nan"]),
               _invalid_combo(kind, ca, cb, z3)))
    value = z3.If(z3.Or(ca["nan"], cb["nan"]),
                  _propagate_nan(a, b, ca, cb, z3),
                  z3.If(bad, _indef(z3), special))
    return {"value": value, "a": a, "b": b, "exact": exact}


def _narrow_value(cw: Any, a: Any, width: int, z3: Any) -> Any:  # noqa: ANN401
    """FST(P) m32/m64 masked response: RC rounding, no precision control."""
    c = _cls(a, z3)
    fa = _to_fp(_normv(a, z3), z3)
    raw = z3.fpToFP(_rm(cw, z3), fa, _fp_sort_for_width(width, z3))
    nan32 = z3.Concat(z3.Extract(79, 79, a), z3.BitVecVal(0xFF, 8),
                      z3.BitVecVal(1, 1), z3.Extract(61, 40, a))
    nan64 = z3.Concat(z3.Extract(79, 79, a), z3.BitVecVal(0x7FF, 11),
                      z3.BitVecVal(1, 1), z3.Extract(61, 11, a))
    nan_out = nan32 if width == 32 else nan64
    return z3.If(
        c["unsupported"],
        z3.BitVecVal(_X87_NARROW_INDEF[width], width),
        z3.If(c["nan"], nan_out,
              z3.If(c["inf"],
                    z3.Concat(z3.Extract(79, 79, a),
                              z3.BitVecVal(0xFF, 8) if width == 32 else z3.BitVecVal(0x7FF, 11),
                              z3.BitVecVal(0, 23) if width == 32 else z3.BitVecVal(0, 52)),
                    _ieee(raw, z3))))


def _f80_const(sign: int, exp: int, sig: int, z3: Any) -> Any:  # noqa: ANN401
    """Materialize a literal ext80 encoding for bound comparisons."""
    return _to_fp(z3.BitVecVal((sign << 79) | (exp << 64) | sig, 80), z3)


def _f2i_bounds(width: int, z3: Any) -> tuple[Any, Any]:  # noqa: ANN401
    """(high, low): value must satisfy low <= rounded < high = 2^(width-1)."""
    exp = (width - 1) + 0x3FFF
    return (_f80_const(0, exp, _X87_SIG_INF, z3),
            _f80_const(1, exp, _X87_SIG_INF, z3))


def _f2i_value(cw: Any, a: Any, width: int, z3: Any) -> Any:  # noqa: ANN401
    """FIST(P) masked response: integer indefinite on invalid/out-of-range."""
    c = _cls(a, z3)
    fa = _to_fp(_normv(a, z3), z3)
    hi, lo = _f2i_bounds(width, z3)
    rounded = z3.fpRoundToIntegral(_rm(cw, z3), fa)
    out = z3.Or(z3.fpGEQ(rounded, hi), z3.fpLT(rounded, lo))
    invalid = z3.Or(c["unsupported"], c["nan"], c["inf"], out)
    return z3.If(invalid, z3.BitVecVal(1 << (width - 1), width),
                 z3.fpToSBV(_rm(cw, z3), fa, z3.BitVecSort(width)))


def _flags_pack(entries: dict[str, Any], z3: Any) -> Any:  # noqa: ANN401
    """Pack {IE,DE,ZE,OE,UE,PE} booleans into SW exception-bit positions."""
    bits = {"IE": 0, "DE": 1, "ZE": 2, "OE": 3, "UE": 4, "PE": 5}
    result = z3.BitVecVal(0, 16)
    for name, bit in bits.items():
        cond = entries.get(name)
        if cond is not None:
            result = z3.If(cond, result | z3.BitVecVal(1 << bit, 16), result)
    return result


def _flags(tail: str, width: int, args: list[Any], z3: Any) -> Any | None:  # noqa: ANN401
    """Compute the six SW exception bits for a modeled x87 operation."""
    if tail == "load" and len(args) == 1:
        src = args[0]
        if int(src.size()) in {32, 64}:
            fp = _to_fp(src, z3)
            # SNaN has the fraction msb (quiet bit) clear: bit 22 for f32,
            # bit 51 for f64.
            quiet = 22 if int(src.size()) == 32 else 51
            snan = z3.And(z3.fpIsNaN(fp), z3.Extract(quiet, quiet, src) == 0)
            return _flags_pack({"IE": snan, "DE": z3.fpIsSubnormal(fp)}, z3)
        c = _cls(src, z3)
        return _flags_pack({"IE": c["snan"], "DE": c["denormal"]}, z3)
    if tail.startswith("narrow") and len(args) == 2:
        return _flags_narrow(args[0], args[1], int(tail[6:]), z3)
    if tail.startswith("f2i") and len(args) == 2:
        return _flags_f2i(args[0], args[1], int(tail[3:]), z3)
    if tail == "xtract" and len(args) == 1:
        return _flags_xtract(args[0], z3)
    if tail == "fbst" and len(args) == 2:
        return _flags_fbst(args[0], args[1], z3)
    if tail in {"sin", "cos", "sincos", "ptan", "f2xm1", "atan",
                "yl2x", "yl2xp1"}:
        return _flags_trans(tail, args, z3)
    if tail in {"add", "sub", "mul", "div", "sqrt", "rnd", "rem", "rem1",
                "com", "ucom", "scale"}:
        return _flags_op(tail, args, z3)
    return None


def _fbld_value(a: Any, z3: Any) -> Any:  # noqa: ANN401
    """FBLD m80dec: sum the 18 packed BCD nibbles into an exact integer.

    Each byte contributes ``hi*10 + lo`` at weight ``100^i``; malformed
    nibbles (>9) are summed literally with no fault, matching pinned
    emulator behavior.  The top sign byte's bit 7 carries the sign.
    """
    acc = z3.BitVecVal(0, 96)
    for index in range(9):
        hi = z3.ZeroExt(92, z3.Extract(8 * index + 7, 8 * index + 4, a))
        lo = z3.ZeroExt(92, z3.Extract(8 * index + 3, 8 * index, a))
        digit = hi * z3.BitVecVal(10, 96) + lo
        acc = acc + digit * z3.BitVecVal(100 ** index, 96)
    sign = z3.Extract(79, 79, a)
    msb = _msb_pos(z3.ZeroExt(_EXT_WIDTH - 96, acc), z3)
    shifted = acc << z3.ZeroExt(88, z3.BitVecVal(63, 8) - msb)
    sig = z3.Extract(63, 0, shifted)
    exp = z3.BitVecVal(0x3FFF, 15) + z3.ZeroExt(7, msb)
    return z3.If(acc == 0, z3.Concat(sign, z3.BitVecVal(0, 79)),
                 z3.Concat(sign, exp, sig))


# Pinned Bochs FBSTP masked response: save_reg_hi=0xFFFF, lo=0xC000000000000000.
_BCD_INDEF = 0xFFFFC000000000000000


def _fbst_value(cw: Any, a: Any, z3: Any) -> Any:  # noqa: ANN401
    """FBSTP m80dec: RC-rounded integer rendered as packed BCD bytes.

    Magnitudes >= 10**18, NaN, infinity and unsupported encodings produce
    the all-ones packed-BCD indefinite image (IE is reported separately).
    """
    c = _cls(a, z3)
    fa = _to_fp(_normv(a, z3), z3)
    rm = _rm(cw, z3)
    rounded = z3.fpRoundToIntegral(rm, fa)
    bound = _f80_const(0, 0x3FFF + 59, 0xDE0B6B3A76400000, z3)
    invalid = z3.Or(c["unsupported"], c["nan"], c["inf"],
                    z3.fpGEQ(z3.fpAbs(rounded), bound))
    mag = z3.fpToUBV(z3.RoundTowardZero(), z3.fpAbs(rounded), z3.BitVecSort(64))
    bytes_ = []
    for index in range(9):
        pair = z3.URem(z3.UDiv(mag, z3.BitVecVal(100 ** index, 64)),
                       z3.BitVecVal(100, 64))
        tens = z3.Extract(7, 0, z3.UDiv(pair, z3.BitVecVal(10, 64)))
        ones = z3.Extract(7, 0, z3.URem(pair, z3.BitVecVal(10, 64)))
        bytes_.append((tens << 4) | ones)
    sign = z3.Concat(z3.Extract(79, 79, a), z3.BitVecVal(0, 7))
    return z3.If(invalid, z3.BitVecVal(_BCD_INDEF, 80),
                 z3.Concat(sign, *reversed(bytes_)))


def _flags_trans(kind: str, args: list[Any], z3: Any) -> Any:  # noqa: ANN401
    """Exception bits for the transcendental family (SDM tables).

    sin/cos/sincos/ptan and f2xm1 take one operand; atan/yl2x/yl2xp1 take
    two (ST1 op ST0).  IE covers SNaN, unsupported encodings, infinity
    (trig), and domain violations (yl2x a<=0, atan n/a).  DE reports
    denormal operands; PE marks an inexact finite result.
    """
    a = args[0]
    ca = _cls(a, z3)
    fa = _to_fp(_normv(a, z3), z3)
    entries: dict[str, Any] = {"DE": ca["denormal"]}
    trig = kind in {"sin", "cos", "sincos", "ptan"}
    ie = z3.Or(ca["snan"], ca["unsupported"])
    if trig:
        # Trig rejects infinities (masked-invalid); f2xm1 and the
        # atan2/log kinds treat +-inf as defined operands (pinned
        # bochs-ref f2xm1.cc/fyl2x.cc special-case tables).
        ie = z3.Or(ie, ca["inf"])
    if kind in {"yl2x", "yl2xp1"}:
        # Whole-instruction flags matching pinned bochs-ref/fyl2x.cc
        # (fyl2x/fyl2xp1) and the parent-log-edges22 host matrix.
        # args: a = ST0 log operand, args[1] = ST1 multiplier.  Flags
        # follow the source's exact check order: unsupported -> NaN
        # propagate -> x inf -> y inf -> x zero/denormal -> x negative ->
        # y zero/denormal -> x==1 identity -> inexact + domain tail.
        cb = _cls(args[1], z3)
        f_one = _to_fp(_pack(0, 0x3FFF, _X87_SIG_INF, z3), z3)
        x_pinf = z3.And(ca["inf"], z3.Not(ca["neg"]))
        x_neg = z3.And(ca["neg"], z3.Not(ca["zero"]))
        is_one = z3.fpEQ(fa, f_one)
        base = z3.Or(ca["snan"], ca["unsupported"],
                     cb["snan"], cb["unsupported"])
        preempted = z3.Or(ca["nan"], ca["unsupported"],
                          cb["nan"], cb["unsupported"])
        free = z3.Not(preempted)
        if kind == "yl2x":
            # Invalid: negative x (incl -inf), +inf x with y=0, +-0 x
            # with y=0, x=1 with y=+-inf (each is an inf*0 / log-of-
            # negative invalid product).
            invalid = z3.Or(base,
                            z3.And(free, x_neg),
                            z3.And(free, x_pinf, cb["zero"]),
                            z3.And(free, ca["zero"], cb["zero"]),
                            z3.And(free, is_one, cb["inf"]))
            # x=+-0 with a finite nonzero y: log = -inf, exact signed
            # infinity result flagged ZE.  y=+-inf/NaN short-circuits
            # into the y-inf branch or NaN propagation first.
            ze = z3.And(free, ca["zero"], z3.Not(cb["zero"]),
                        z3.Not(cb["inf"]))
            # DE fires only where the source normalizes: x positive
            # denormal (any y path); y denormal when reached (x=+inf
            # branch, or finite positive nonzero x at !bExp).  x=+-0
            # returns via ZE/invalid without normalizing y; negative x
            # is invalid first.
            x_pos_fin_nz = z3.And(free, z3.Not(ca["neg"]),
                                  z3.Not(ca["zero"]), z3.Not(ca["inf"]))
            de = z3.Or(
                z3.And(free, ca["denormal"], z3.Not(ca["neg"])),
                z3.And(free, cb["denormal"],
                       z3.Or(x_pinf, x_pos_fin_nz)))
            approx = z3.And(free, z3.Not(ca["inf"]), z3.Not(cb["inf"]),
                            z3.Not(ca["zero"]), z3.Not(x_neg),
                            z3.Not(cb["zero"]), z3.Not(is_one))
        else:
            # FYL2XP1: invalid only for -inf x, +inf x with y=0, and
            # +-0 x with y=+-inf.  Negative finite x (incl |x|>=1) is
            # the documented operand-returned-with-PE undefined-domain
            # response, not invalid.
            invalid = z3.Or(base,
                            z3.And(free, ca["inf"], ca["neg"]),
                            z3.And(free, x_pinf, cb["zero"]),
                            z3.And(free, ca["zero"], cb["inf"]))
            ze = z3.BoolVal(False)
            # DE fires at every normalization point the flow reaches:
            # x denormal of either sign (xp1's !aExp block has no
            # aSign invalid gate); y denormal for x=+inf or any
            # non-inf x (x=+-0 checks bSig for DE before returning
            # its signed zero).  Only x=-inf preempts y's check.
            de = z3.Or(
                z3.And(free, ca["denormal"]),
                z3.And(free, cb["denormal"],
                       z3.Or(x_pinf, z3.Not(ca["inf"]))))
            approx = z3.And(free, z3.Not(ca["inf"]), z3.Not(cb["inf"]),
                            z3.Not(ca["zero"]), z3.Not(cb["zero"]))
        entries["DE"] = de
        entries["IE"] = invalid
        entries["ZE"] = ze
        entries["PE"] = approx
        return _flags_pack(entries, z3)
    entries["IE"] = ie
    finite_ok = z3.And(z3.Not(ca["nan"]), z3.Not(ca["inf"]),
                       z3.Not(ca["unsupported"]), z3.Not(ie))
    inexact = z3.Not(z3.fpEQ(fa, z3.fpSub(z3.RoundNearestTiesToEven(),
                                          fa, fa)))
    if trig:
        # Out-of-range trig operands leave the register untouched: C2=1 and
        # no precision bit (the approximation never ran).
        bound = _f80_const(0, 0x3FFF + 63, 1 << 63, z3)
        inexact = z3.And(inexact, z3.fpLT(z3.fpAbs(fa), bound))
    entries["PE"] = z3.And(finite_ok, inexact)
    if len(args) == 2:
        cb = _cls(args[1], z3)
        entries["DE"] = z3.Or(entries["DE"], cb["denormal"])
        entries["IE"] = z3.Or(entries["IE"], cb["snan"], cb["unsupported"])
        entries["PE"] = z3.And(entries["PE"],
                               z3.And(z3.Not(cb["nan"]), z3.Not(cb["inf"]),
                                      z3.Not(cb["unsupported"])))
    return _flags_pack(entries, z3)


def _flags_fbst(cw: Any, a: Any, z3: Any) -> Any:  # noqa: ANN401
    """Exception bits for FBSTP: IE on invalid source, PE on rounding."""
    c = _cls(a, z3)
    fa = _to_fp(_normv(a, z3), z3)
    rm = _rm(cw, z3)
    rounded = z3.fpRoundToIntegral(rm, fa)
    bound = _f80_const(0, 0x3FFF + 59, 0xDE0B6B3A76400000, z3)
    invalid = z3.Or(c["unsupported"], c["nan"], c["inf"],
                    z3.fpGEQ(z3.fpAbs(rounded), bound))
    return _flags_pack({
        "IE": invalid,
        "DE": c["denormal"],
        "PE": z3.And(z3.Not(invalid), z3.Not(z3.fpEQ(rounded, fa)))}, z3)


def _flags_narrow(cw: Any, a: Any, fmt: int, z3: Any) -> Any:  # noqa: ANN401
    """Exception bits for FST(P) m32/m64 stores."""
    c = _cls(a, z3)
    fa = _to_fp(_normv(a, z3), z3)
    target = _sort(8, 24, z3) if fmt == 32 else _sort(11, 53, z3)
    narrow = z3.fpToFP(_rm(cw, z3), fa, target)
    sig_width = 24 if fmt == 32 else 53
    emax = 127 if fmt == 32 else 1023
    maxv = _f80_const(0, 0x3FFF + emax, ((1 << (sig_width + 1)) - 1) << (64 - sig_width - 1), z3)
    boundary = _f80_const(0, 0x3FFF + emax,
                          ((1 << (sig_width + 2)) - 1) << (64 - sig_width - 2), z3)
    finite = z3.And(z3.Not(c["nan"]), z3.Not(c["inf"]), z3.Not(c["unsupported"]))
    overflow = z3.If(z3.Extract(11, 10, cw) == 0,
                     z3.fpGEQ(z3.fpAbs(fa), boundary),
                     z3.fpGT(z3.fpAbs(fa), maxv))
    inexact = z3.Not(z3.fpEQ(z3.fpToFP(z3.RoundNearestTiesToEven(), narrow, _sort(15, 64, z3)), fa))
    return _flags_pack({
        "IE": z3.Or(c["unsupported"], c["snan"]),
        "DE": c["denormal"],
        "OE": z3.And(finite, overflow),
        "UE": z3.And(finite, z3.fpIsSubnormal(narrow), inexact),
        "PE": z3.And(finite, inexact)}, z3)


def _flags_f2i(cw: Any, a: Any, fmt: int, z3: Any) -> Any:  # noqa: ANN401
    """Exception bits for FIST(P) integer stores."""
    c = _cls(a, z3)
    fa = _to_fp(_normv(a, z3), z3)
    hi, lo = _f2i_bounds(fmt, z3)
    rm = _rm(cw, z3)
    rounded = z3.fpRoundToIntegral(rm, fa)
    out = z3.Or(z3.fpGEQ(rounded, hi), z3.fpLT(rounded, lo))
    invalid = z3.Or(c["unsupported"], c["nan"], c["inf"], out)
    back = z3.fpToFP(rm, z3.fpToSBV(rm, fa, z3.BitVecSort(64)), _sort(15, 64, z3))
    inexact = z3.Not(z3.fpEQ(back, fa))
    return _flags_pack({
        "IE": invalid,
        "DE": c["denormal"],
        "PE": z3.And(z3.Not(invalid), inexact)}, z3)


def _flags_op(kind: str, args: list[Any], z3: Any) -> Any | None:  # noqa: ANN401
    """Exception bits for arithmetic, sqrt/rnd/rem and compare operations."""
    if kind in {"com", "ucom"}:
        a, b = args
        ca, cb = _cls(a, z3), _cls(b, z3)
        quiet_ie = z3.Or(ca["snan"], cb["snan"], ca["unsupported"], cb["unsupported"])
        ie = quiet_ie if kind == "ucom" else z3.Or(quiet_ie, ca["nan"], cb["nan"])
        return _flags_pack({"IE": ie, "DE": z3.Or(ca["denormal"], cb["denormal"])}, z3)
    if kind in {"rem", "rem1"}:
        a, b = args
        ca, cb = _cls(a, z3), _cls(b, z3)
        ie = z3.Or(
            ca["unsupported"], cb["unsupported"], ca["snan"], cb["snan"],
            z3.And(z3.Not(ca["nan"]), z3.Not(cb["nan"]),
                   _invalid_combo("rem", ca, cb, z3)))
        return _flags_pack({"IE": ie, "DE": z3.Or(ca["denormal"], cb["denormal"])}, z3)
    res = _arith_result(kind, args, z3)
    a, b = res["a"], res.get("b", res["a"])
    ca, cb = _cls(a, z3), _cls(b, z3)
    cr = _cls(res["value"], z3)
    finite = z3.And(z3.Not(ca["nan"]), z3.Not(ca["inf"]), z3.Not(ca["unsupported"]),
                    z3.Not(cb["nan"]), z3.Not(cb["inf"]), z3.Not(cb["unsupported"]))
    invalid = z3.Or(
        ca["unsupported"], cb["unsupported"], ca["snan"], cb["snan"],
        z3.And(z3.Not(ca["nan"]), z3.Not(cb["nan"]),
               _invalid_combo(kind, ca, cb, z3)))
    exact = res.get("exact")
    if exact is not None:
        computable = z3.And(finite, z3.Not(invalid))
        if kind == "div":
            computable = z3.And(computable, z3.Not(cb["zero"]))
        inexact = z3.And(computable, exact["inexact"])
        underflow = z3.And(computable, exact["denormal"], inexact)
        overflow = z3.And(computable, exact["overflow"])
    else:
        fa = _to_fp(_normv(a, z3), z3)
        inexact = z3.And(finite, z3.Not(invalid),
                         z3.Not(z3.fpEQ(_to_fp(res["value"], z3), fa)))
        underflow = z3.And(finite, z3.Not(invalid), cr["denormal"], inexact)
        overflow = z3.And(finite, z3.Not(invalid), cr["inf"])
    entries: dict[str, Any] = {
        "IE": invalid,
        "DE": z3.Or(ca["denormal"], cb["denormal"]),
        "OE": overflow,
        "UE": underflow,
        "PE": inexact,
    }
    if kind == "div":
        entries["ZE"] = z3.And(finite, z3.Not(ca["zero"]), cb["zero"])
    return _flags_pack(entries, z3)


def _rem_cc(a: Any, b: Any, ieee: bool, z3: Any) -> Any:  # noqa: ANN401
    """FPREM/FPREM1 condition codes: {C0,C1,C2,C3} in bits {0,1,2,3}.

    Mapping after 86Box ``sf_FPREM``/``sf_FPREM1``: C2 on partial reduction
    (other bits 0); otherwise C1=q0, C3=q1, C0=q2 of the low quotient.
    """
    core = _exact_rem(a, b, ieee, z3)
    q3 = core["q_low3"]
    return z3.If(core["c2"], z3.BitVecVal(0x4, 16),
                 z3.Concat(z3.BitVecVal(0, 12),
                           z3.Extract(1, 1, q3),   # C3 = q1
                           z3.BitVecVal(0, 1),     # C2 = 0
                           z3.Extract(0, 0, q3),   # C1 = q0
                           z3.Extract(2, 2, q3)))  # C0 = q2


def _com_value(tail: str, args: list[Any], z3: Any) -> Any | None:  # noqa: ANN401
    """FCOM/FUCOM primitive comparisons over architectural ext80 operands."""
    a, b = args
    fa, fb = _to_fp(_normv(a, z3), z3), _to_fp(_normv(b, z3), z3)
    one, zero = z3.BitVecVal(1, 1), z3.BitVecVal(0, 1)
    if tail == "lt":
        return z3.If(z3.fpLT(fa, fb), one, zero)
    if tail == "eq":
        return z3.If(z3.fpEQ(fa, fb), one, zero)
    if tail == "uno":
        return z3.If(z3.Or(z3.fpIsNaN(fa), z3.fpIsNaN(fb)), one, zero)
    return None
