"""Preserve real pyvex constants at the typed IR boundary."""

from types import SimpleNamespace

import pytest
import pyvex
import pyvex.enums

from inertia.ir.core import IRValue, MemSpace
from inertia.ir.vex_import import (
    _expr_to_value,
    build_x86_16_ir_function_artifact,
)
from inertia.ir.vex_types import vex_expr_size_bytes
from tests.ir.test_x86_16_vex_import import _block, _project


@pytest.mark.parametrize(
    ("constant", "size"),
    [
        (pyvex.const.U1(1), 1),
        (pyvex.const.U8(0xFF), 1),
        (pyvex.const.U16(0xFFFF), 2),
        (pyvex.const.U32(0xFFFFFFFF), 4),
        (pyvex.const.U64(0xFFFFFFFFFFFFFFFF), 8),
    ],
)
def test_direct_integer_constant_matches_wrapped_expression(constant, size) -> None:
    direct = _expr_to_value(constant, {}, {})
    wrapped = _expr_to_value(pyvex.expr.Const(constant), {}, {})
    assert direct == wrapped == IRValue(MemSpace.CONST, const=constant.value, size=size)
    assert vex_expr_size_bytes(constant) == size


def test_real_exit_destination_survives_ir_import() -> None:
    entry, target, fallthrough = 0x1000, 0x1040, 0x1002
    function = SimpleNamespace(addr=entry, block_addrs_set={entry}, info={})
    exit_statement = pyvex.stmt.Exit(
        pyvex.expr.Const(pyvex.const.U1(1)), pyvex.const.U16(target), "Ijk_Boring", 0,
    )
    block = _block(entry, exit_statement, next_expr=pyvex.expr.Const(pyvex.const.U16(fallthrough)))
    artifact = build_x86_16_ir_function_artifact(_project({entry: block}, function), function)
    branch = next(instruction for instruction in artifact.blocks[0].instrs if instruction.op == "CJMP")
    assert branch.args[1] == IRValue(MemSpace.CONST, const=target, size=2)
    assert set(artifact.blocks[0].successor_addrs) == {target, fallthrough}


def test_bare_float_is_not_classified_as_integer() -> None:
    assert _expr_to_value(pyvex.const.F64(1.5), {}, {}).space is MemSpace.UNKNOWN


class _TypeEnv:
    """Minimal duck-typed type environment like the stock tyenv surface."""

    def __init__(self, token: object = "Ity_I16") -> None:
        self.token = token
        self.lookups: list[object] = []

    def lookup(self, tmp: object) -> object:
        self.lookups.append(tmp)
        return self.token


def _size(expr: object, env: object) -> int:
    """Bytes under the width resolver for one expression."""
    return vex_expr_size_bytes(expr, type_environment=env)


@pytest.mark.parametrize(
    ("expr", "env", "size"),
    [
        (pyvex.expr.Const(pyvex.const.U1(1)), _TypeEnv(), 1),
        (pyvex.expr.Const(pyvex.const.U8(7)), _TypeEnv(), 1),
        (pyvex.expr.Const(pyvex.const.U16(7)), _TypeEnv(), 2),
        (pyvex.expr.Const(pyvex.const.U32(7)), _TypeEnv(), 4),
        (pyvex.expr.Const(pyvex.const.U64(7)), _TypeEnv(), 8),
        (pyvex.expr.Get(4, "Ity_I8"), _TypeEnv(), 1),
        (pyvex.expr.Get(4, "Ity_I16"), _TypeEnv(), 2),
        (pyvex.expr.Get(4, "Ity_I32"), _TypeEnv(), 4),
        (
            pyvex.expr.Load("Iend_LE", "Ity_I16", pyvex.expr.Const(pyvex.const.U16(4))),
            _TypeEnv(),
            2,
        ),
        (
            pyvex.expr.Load("Iend_LE", "Ity_I64", pyvex.expr.Const(pyvex.const.U16(4))),
            _TypeEnv(),
            8,
        ),
        (pyvex.expr.RdTmp(5), _TypeEnv("Ity_I8"), 1),
        (pyvex.expr.RdTmp(5), _TypeEnv("Ity_I32"), 4),
        (pyvex.expr.RdTmp(5), _TypeEnv("Ity_I7"), 1),
        (pyvex.expr.RdTmp(5), _TypeEnv("Ity_F32"), 4),
        (
            pyvex.expr.Binop(
                "Iop_Add16",
                [pyvex.expr.Const(pyvex.const.U16(1)), pyvex.expr.Const(pyvex.const.U16(2))],
            ),
            _TypeEnv(),
            2,
        ),
    ],
)
def test_canonical_width_matches_stock_result_size(expr, env, size) -> None:
    """Each canonical leaf yields the same bytes as stock result_size."""
    assert _size(expr, env) == size
    assert _size(expr, env) == max(1, (int(expr.result_size(env)) + 7) // 8)


def test_rdtmp_consults_environment_every_call() -> None:
    """A mutated type environment must change the answer; widths uncached."""
    env = _TypeEnv("Ity_I8")
    tmp = pyvex.expr.RdTmp(9)
    assert _size(tmp, env) == 1
    env.token = "Ity_I64"
    assert _size(tmp, env) == 8
    assert env.lookups == [9, 9]


def test_rdtmp_rejects_environment_without_lookup() -> None:
    """A type environment lacking ``lookup`` propagates the same stock error."""
    with pytest.raises(AttributeError):
        _size(pyvex.expr.RdTmp(5), object())


def test_overridden_result_size_takes_callable_precedence() -> None:
    """A subclass overriding result_size must not take the canonical route."""

    class Narrow(pyvex.expr.Get):
        def result_size(self, tyenv):
            return 24

    expr = Narrow(4, "Ity_I16")
    assert _size(expr, _TypeEnv()) == 3


def test_overridden_result_type_takes_callable_precedence() -> None:
    """A subclass overriding result_type keeps its authoritative token."""

    class Wide(pyvex.expr.Get):
        def result_type(self, tyenv):
            return "Ity_I64"

    expr = Wide(4, "Ity_I16")
    assert _size(expr, _TypeEnv()) == 8


def test_patched_get_type_size_is_authoritative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Replacing pyvex.expr.get_type_size must change canonical results."""
    import pyvex.expr as pyvex_expr

    monkeypatch.setattr(pyvex_expr, "get_type_size", lambda ty: 40)
    assert _size(pyvex.expr.Get(4, "Ity_I16"), _TypeEnv()) == 5


def test_patched_stock_result_type_is_authoritative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Replacing ``Get.result_type`` on the class forces the callable route."""
    monkeypatch.setattr(pyvex.expr.Get, "result_type", lambda self, tyenv: "Ity_I64")
    assert _size(pyvex.expr.Get(4, "Ity_I16"), _TypeEnv()) == 8


def test_conflicting_metadata_prefers_callable_result_size() -> None:
    """Synthetic surfaces keep callable result_size precedence over ty text."""
    boundary = SimpleNamespace(ty="Ity_I64", result_size=lambda tyenv: 8)
    assert _size(boundary, _TypeEnv()) == 1


def test_unsupported_type_token_falls_back_to_default() -> None:
    """An unsized token keeps stock ValueError → None → token-map → default."""
    expr = pyvex.expr.Get(4, "Ity_I16")
    expr.ty_int = pyvex.enums.get_int_from_enum("Ity_INVALID")
    assert _size(expr, _TypeEnv()) == 2


def test_noninteger_type_token_uses_stock_get_type_size() -> None:
    """A float token outside the integer map still resolves through stock."""
    expr = pyvex.expr.Get(4, "Ity_F32")
    assert _size(expr, _TypeEnv()) == 4


def test_no_type_environment_stays_on_token_route() -> None:
    """Without an environment, canonical exprs keep the token-map fallback."""
    assert vex_expr_size_bytes(pyvex.expr.Get(4, "Ity_I32")) == 4
    assert vex_expr_size_bytes(pyvex.expr.Const(pyvex.const.U16(7))) == 2
