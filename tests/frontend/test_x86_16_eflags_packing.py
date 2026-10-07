from __future__ import annotations

from dataclasses import dataclass

from pyvex.lifting.util.vex_helper import Type

from inertia.frontend.x86_16.eflags import Eflags, StatusFlagValueFactories
from inertia.semantics.status_flag_contracts import STATUS_FLAGS_8616, StatusFlag8616


def _width(ty: object) -> int:
    return {
        Type.int_1: 1,
        Type.int_8: 8,
        Type.int_16: 16,
        Type.int_32: 32,
        Type.int_64: 64,
    }[ty]


@dataclass(frozen=True)
class _ConcreteExpr:
    value: int
    width: int

    def cast_to(self, ty: object) -> _ConcreteExpr:
        width = _width(ty)
        return _ConcreteExpr(self.value & ((1 << width) - 1), width)

    def __and__(self, other: object) -> _ConcreteExpr:
        rhs = other.value if isinstance(other, _ConcreteExpr) else int(other)
        return _ConcreteExpr(self.value & rhs, self.width)

    def __or__(self, other: object) -> _ConcreteExpr:
        rhs = other.value if isinstance(other, _ConcreteExpr) else int(other)
        return _ConcreteExpr(self.value | rhs, self.width)

    def __lshift__(self, count: int) -> _ConcreteExpr:
        return _ConcreteExpr((self.value << count) & ((1 << self.width) - 1), self.width)


class _ConcreteEflags(Eflags):
    def constant(self, value: object, ty: object = Type.int_16) -> _ConcreteExpr:
        raw = value.value if isinstance(value, _ConcreteExpr) else int(value)
        return _ConcreteExpr(raw, _width(ty))


def test_packed_live_status_flags_match_sequential_projection() -> None:
    host = _ConcreteEflags()
    flags = _ConcreteExpr(0xA55A, 16)
    concrete_values = (
        (StatusFlag8616.CARRY, 1),
        (StatusFlag8616.PARITY, 0),
        (StatusFlag8616.AUXILIARY, 1),
        (StatusFlag8616.ZERO, 1),
        (StatusFlag8616.SIGN, 0),
        (StatusFlag8616.OVERFLOW, 1),
    )
    factories: StatusFlagValueFactories = tuple(
        (flag, lambda value=value: value) for flag, value in concrete_values
    )
    expected = flags
    for flag, value in concrete_values:
        expected = host.set_flag(expected, int(flag).bit_length() - 1, value)

    actual = host._set_live_status_flags_8616(flags, STATUS_FLAGS_8616, factories)

    assert actual == expected


def test_packed_live_status_flags_preserve_other_bits_and_factory_order() -> None:
    host = _ConcreteEflags()
    flags = _ConcreteExpr(0xFFFF, 16)
    evaluated: list[str] = []

    def value(label: str, result: int) -> int:
        evaluated.append(label)
        return result

    factories: StatusFlagValueFactories = (
        (StatusFlag8616.CARRY, lambda: value("carry", 0)),
        (StatusFlag8616.ZERO, lambda: value("zero", 0)),
        (StatusFlag8616.SIGN, lambda: value("sign", 0)),
    )

    actual = host._set_live_status_flags_8616(
        flags,
        StatusFlag8616.CARRY | StatusFlag8616.ZERO,
        factories,
    )

    assert actual.value == 0xFFBE
    assert evaluated == ["carry", "zero"]


def test_packed_live_status_flags_refuse_all_dead_factories() -> None:
    host = _ConcreteEflags()
    flags = _ConcreteExpr(0x1234, 16)

    def forbidden() -> int:
        raise AssertionError("dead flag value factory was evaluated")

    actual = host._set_live_status_flags_8616(
        flags,
        StatusFlag8616.NONE,
        ((StatusFlag8616.CARRY, forbidden),),
    )

    assert actual is flags


def test_full_writer_zeros_dead_defined_status_bits() -> None:
    """A full writer does not retain incoming flags solely for dead equations."""
    host = _ConcreteEflags()
    flags = _ConcreteExpr(0xFFFF, 16)

    actual = host._set_live_status_flags_8616(
        flags,
        StatusFlag8616.SIGN,
        ((StatusFlag8616.SIGN, lambda: 0),),
        written=STATUS_FLAGS_8616,
    )

    assert actual.value == 0xFFFF & ~int(STATUS_FLAGS_8616)
