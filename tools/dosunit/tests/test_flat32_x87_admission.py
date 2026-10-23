"""Layer: dosunit tests.

Responsibility: typed admission contract for ``x87fp_*`` SSA operators.

Batch-20 contract: ``apply_x87_op`` validates every emitted operator name,
arity, argument bit-vector width and declared output width BEFORE Z3
evaluation.  Contract violations raise ``DosUnitError`` — malformed terms
can no longer drop extra operands (``x87fp_rnd`` ignored a third argument),
crash on unpacking (``x87fp_rem`` with three args), index missing operands
(``x87fp_add`` with two args) or propagate width mismatches into evaluation.
Unknown names and suffixes stay unadmitted; admission is by exact name,
never prefix matching (``x87fp_rem2``, ``x87fp_xtract_q``, ``x87fp_flags_x``
all refuse).

The positive corpus below enumerates every ``x87fp_*`` name actually
emitted by the arith/stack architecture owners with its exact producer
shape; each must evaluate to a bit-vector of the declared output width.
"""

from __future__ import annotations

import pytest
import z3

from tools.dosunit.contracts.model import DosUnitError
from tools.dosunit.ssa.z3_x87_fp import (
    _X87_FLAG_SHAPES,
    _X87_VALUE_SHAPES,
    apply_x87_op,
)


def _args(*widths: int) -> list[z3.BitVecVal]:
    return [z3.BitVecVal(0, w) for w in widths]


# --- Positive corpus ------------------------------------------------------
# (operator name, declared output width, argument widths) for every
# x87fp_* term shape emitted by flat32_x87_arith.py / flat32_x87_stack.py.

_VALUE_CORPUS: list[tuple[str, int, tuple[int, ...]]] = [
    ("x87fp_add", 80, (16, 80, 80)),
    ("x87fp_sub", 80, (16, 80, 80)),
    ("x87fp_mul", 80, (16, 80, 80)),
    ("x87fp_div", 80, (16, 80, 80)),
    ("x87fp_scale", 80, (16, 80, 80)),
    ("x87fp_sqrt", 80, (16, 80)),
    ("x87fp_rnd", 80, (16, 80)),
    ("x87fp_rem", 80, (80, 80)),
    ("x87fp_rem1", 80, (80, 80)),
    ("x87fp_remcc", 16, (80, 80)),
    ("x87fp_remcc1", 16, (80, 80)),
    ("x87fp_widen", 80, (32,)),
    ("x87fp_widen", 80, (64,)),
    ("x87fp_i2f", 80, (16,)),
    ("x87fp_i2f", 80, (32,)),
    ("x87fp_i2f", 80, (64,)),
    ("x87fp_narrow", 32, (16, 80)),
    ("x87fp_narrow", 64, (16, 80)),
    ("x87fp_f2i", 16, (16, 80)),
    ("x87fp_f2i", 32, (16, 80)),
    ("x87fp_f2i", 64, (16, 80)),
    ("x87fp_fbld", 80, (80,)),
    ("x87fp_fbst", 80, (16, 80)),
    ("x87fp_xtract_e", 80, (80,)),
    ("x87fp_xtract_s", 80, (80,)),
    ("x87fp_com_lt", 1, (80, 80)),
    ("x87fp_com_eq", 1, (80, 80)),
    ("x87fp_com_uno", 1, (80, 80)),
    ("x87fp_badop", 1, (80,)),
    ("x87fp_range63", 1, (80,)),
    ("x87fp_atan2", 80, (16, 80, 80)),
    ("x87fp_sin", 80, (16, 80)),
    ("x87fp_cos", 80, (16, 80)),
    ("x87fp_tan", 80, (16, 80)),
    ("x87fp_f2xm1", 80, (16, 80)),
    ("x87fp_lg2", 80, (16, 80)),
    ("x87fp_lg2p1", 80, (16, 80)),
]

_FLAG_CORPUS: list[tuple[str, tuple[int, ...]]] = [
    ("x87fp_flags_load", (32,)),
    ("x87fp_flags_load", (64,)),
    ("x87fp_flags_narrow32", (16, 80)),
    ("x87fp_flags_narrow64", (16, 80)),
    ("x87fp_flags_f2i16", (16, 80)),
    ("x87fp_flags_f2i32", (16, 80)),
    ("x87fp_flags_f2i64", (16, 80)),
    ("x87fp_flags_xtract", (80,)),
    ("x87fp_flags_fbst", (16, 80)),
    ("x87fp_flags_add", (16, 80, 80)),
    ("x87fp_flags_sub", (16, 80, 80)),
    ("x87fp_flags_mul", (16, 80, 80)),
    ("x87fp_flags_div", (16, 80, 80)),
    ("x87fp_flags_scale", (16, 80, 80)),
    ("x87fp_flags_sqrt", (16, 80)),
    ("x87fp_flags_rnd", (16, 80)),
    ("x87fp_flags_rem", (80, 80)),
    ("x87fp_flags_rem1", (80, 80)),
    ("x87fp_flags_com", (80, 80)),
    ("x87fp_flags_ucom", (80, 80)),
    ("x87fp_flags_sin", (80,)),
    ("x87fp_flags_cos", (80,)),
    ("x87fp_flags_sincos", (80,)),
    ("x87fp_flags_ptan", (80,)),
    ("x87fp_flags_f2xm1", (80,)),
    ("x87fp_flags_atan", (80, 80)),
    ("x87fp_flags_yl2x", (80, 80)),
    ("x87fp_flags_yl2xp1", (80, 80)),
]


class TestEmittedCorpusAccepted:
    """Every producer-emitted shape evaluates to the declared width."""

    @pytest.mark.parametrize(
        ("op", "width", "arg_widths"), _VALUE_CORPUS,
        ids=[f"{op}:{w}<-{','.join(map(str, a))}"
             for op, w, a in _VALUE_CORPUS])
    def test_value_ops(self, op: str, width: int,
                       arg_widths: tuple[int, ...]) -> None:
        result = apply_x87_op(op, width, _args(*arg_widths), z3)
        assert result is not None
        assert z3.is_bv(result)
        assert int(result.size()) == width

    @pytest.mark.parametrize(
        ("op", "arg_widths"), _FLAG_CORPUS,
        ids=[f"{op}<-{','.join(map(str, a))}" for op, a in _FLAG_CORPUS])
    def test_flags_ops(self, op: str, arg_widths: tuple[int, ...]) -> None:
        result = apply_x87_op(op, 16, _args(*arg_widths), z3)
        assert result is not None
        assert z3.is_bv(result)
        assert int(result.size()) == 16

    def test_corpus_matches_admission_tables(self) -> None:
        """The recorded producer corpus stays a subset of the contract."""
        emitted_values = {op[len("x87fp_"):] for op, _, _ in _VALUE_CORPUS}
        emitted_flags = {op[len("x87fp_flags_"):] for op, _ in _FLAG_CORPUS}
        assert emitted_values <= set(_X87_VALUE_SHAPES)
        assert emitted_flags <= set(_X87_FLAG_SHAPES)


class TestMalformedRefuses:
    """Known-bad shapes raise DosUnitError before evaluation."""

    @pytest.mark.parametrize(
        ("op", "width", "args"),
        [
            # Extra operands (batch-20 defect: x87fp_rnd dropped args[2]).
            ("x87fp_rnd", 80, _args(16, 80, 80)),
            ("x87fp_rem", 80, _args(80, 80, 80)),
            ("x87fp_rem1", 80, _args(80, 80, 80)),
            ("x87fp_add", 80, _args(16, 80, 80, 80)),
            ("x87fp_widen", 80, _args(32, 32)),
            ("x87fp_sin", 80, _args(80, 80)),
            ("x87fp_com_lt", 1, _args(80, 80, 80)),
            ("x87fp_fbld", 80, _args(80, 80)),
            ("x87fp_badop", 1, _args(80, 80)),
            # Missing operands (x87fp_add with 2 args indexed args[2]).
            ("x87fp_add", 80, _args(16, 80)),
            ("x87fp_rnd", 80, _args(16,)),
            ("x87fp_rem", 80, _args(80,)),
            ("x87fp_atan2", 80, _args(80,)),
            ("x87fp_narrow", 32, _args(16,)),
            ("x87fp_fbst", 80, _args(16,)),
            ("x87fp_flags_add", 16, _args(16, 80)),
            ("x87fp_flags_rem", 16, _args(80,)),
            ("x87fp_flags_yl2x", 16, _args(80,)),
            # Wrong control-word width.
            ("x87fp_add", 80, _args(32, 80, 80)),
            ("x87fp_add", 80, _args(80, 80, 80)),
            ("x87fp_sqrt", 80, _args(8, 80)),
            ("x87fp_narrow", 32, _args(64, 80)),
            ("x87fp_f2i", 32, _args(32, 80)),
            ("x87fp_fbst", 80, _args(80, 80)),
            ("x87fp_flags_add", 16, _args(80, 80, 80)),
            ("x87fp_flags_narrow32", 16, _args(32, 80)),
            # Wrong ext80 operand widths.
            ("x87fp_add", 80, _args(16, 64, 80)),
            ("x87fp_add", 80, _args(16, 80, 64)),
            ("x87fp_rem", 80, _args(16, 80)),
            ("x87fp_com_lt", 1, _args(80, 64)),
            ("x87fp_sin", 80, _args(64,)),
            ("x87fp_range63", 1, _args(32,)),
            ("x87fp_xtract_e", 80, _args(16,)),
            ("x87fp_flags_com", 16, _args(64, 80)),
            # Wrong memory-source widths.
            ("x87fp_widen", 80, _args(16,)),
            ("x87fp_widen", 80, _args(80,)),
            ("x87fp_i2f", 80, _args(80,)),
            ("x87fp_i2f", 80, _args(8,)),
            ("x87fp_flags_load", 16, _args(80,)),
            ("x87fp_flags_load", 16, _args(16,)),
            # Unsupported output widths.
            ("x87fp_add", 64, _args(16, 80, 80)),
            ("x87fp_add", 16, _args(16, 80, 80)),
            ("x87fp_narrow", 80, _args(16, 80)),
            ("x87fp_narrow", 16, _args(16, 80)),
            ("x87fp_f2i", 80, _args(16, 80)),
            ("x87fp_f2i", 8, _args(16, 80)),
            ("x87fp_remcc", 80, _args(80, 80)),
            ("x87fp_remcc", 1, _args(80, 80)),
            ("x87fp_com_lt", 80, _args(80, 80)),
            ("x87fp_badop", 16, _args(80,)),
            ("x87fp_sin", 64, _args(80,)),
            ("x87fp_flags_add", 80, _args(16, 80, 80)),
            ("x87fp_flags_add", 32, _args(16, 80, 80)),
            ("x87fp_flags_load", 8, _args(32,)),
        ],
        ids=lambda case: case if isinstance(case, str) else None)
    def test_malformed_raises(self, op: str, width: int,
                              args: list[z3.BitVecVal]) -> None:
        with pytest.raises(DosUnitError):
            apply_x87_op(op, width, args, z3)

    def test_non_bv_argument_raises(self) -> None:
        with pytest.raises(DosUnitError):
            apply_x87_op("x87fp_add", 80,
                         [z3.BitVecVal(0, 16), z3.BoolVal(True),
                          z3.BitVecVal(0, 80)], z3)


class TestUnknownStaysUnadmitted:
    """Unknown names/suffixes refuse — never alias a known prefix."""

    @pytest.mark.parametrize(
        "op",
        [
            "x87fp_foo",
            "x87fp_rem2",          # extra suffix on a known family
            "x87fp_rem1x",
            "x87fp_addx",
            "x87fp_ad",            # known-name prefix
            "x87fp_xtract_q",      # invalid xtract selector
            "x87fp_xtract",        # bare family name
            "x87fp_com",           # bare compare prefix
            "x87fp_com_gt",
            "x87fp_comx",
            "x87fp_flags_",        # empty flags suffix
            "x87fp_flags_addx",
            "x87fp_flags_narrow16",
            "x87fp_flags_f2i8",
            "x87fp_flags_foo",
            "x87fp_flags_rem2",
            "x87fp_",
            "x87fp",
        ])
    def test_unknown_name_returns_none(self, op: str) -> None:
        assert apply_x87_op(op, 80, _args(16, 80, 80), z3) is None

    def test_non_x87_prefix_unadmitted(self) -> None:
        assert apply_x87_op("f87fp_add", 80, _args(16, 80, 80), z3) is None
        assert apply_x87_op("x87_add", 80, _args(16, 80, 80), z3) is None


class TestAdmissionIsExactName:
    """Admission table keys are complete names, not prefixes."""

    def test_every_table_name_is_admitted(self) -> None:
        # Table-driven self-consistency: every declared name evaluates.
        for name, (arg_widths, outs) in _X87_VALUE_SHAPES.items():
            width = sorted(outs)[0]
            args = _args(*(sorted(w)[0] for w in arg_widths))
            result = apply_x87_op(f"x87fp_{name}", width, args, z3)
            assert result is not None, name
        for tail, (arg_widths, _outs) in _X87_FLAG_SHAPES.items():
            args = _args(*(sorted(w)[0] for w in arg_widths))
            result = apply_x87_op(f"x87fp_flags_{tail}", 16, args, z3)
            assert result is not None, tail

    def test_no_alias_by_prefix(self) -> None:
        # "rem" must not admit "rem1" shapes and vice versa.
        assert _X87_VALUE_SHAPES["rem"][0] == _X87_VALUE_SHAPES["rem1"][0]
        assert "rem2" not in _X87_VALUE_SHAPES
        assert "xtract" not in _X87_VALUE_SHAPES
        assert "com" not in _X87_VALUE_SHAPES
