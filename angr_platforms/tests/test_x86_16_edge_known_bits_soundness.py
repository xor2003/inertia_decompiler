"""Check abstract arithmetic against every concrete member of small bit domains."""

from __future__ import annotations

import itertools
import operator
from collections.abc import Callable

import pytest
from angr_platforms.X86_16.ir import real16_edge_feasibility8616 as edge


def _states(positions: tuple[int, ...]) -> list[tuple[tuple[int, int], tuple[int, ...]]]:
    """Enumerate all unknown/zero/one assignments with other bits known zero."""
    states = []
    varying = sum(1 << position for position in positions)
    for digits in itertools.product((-1, 0, 1), repeat=len(positions)):
        mask, value = 0xFF ^ varying, 0
        for bit, digit in zip(positions, digits, strict=True):
            if digit >= 0:
                mask |= 1 << bit
                value |= digit << bit
        members = tuple(item for item in range(256) if item & mask == value)
        states.append(((mask, value), members))
    return states


_BINARY: dict[str, Callable[[int, int], int]] = {
    "Add8": operator.add, "Sub8": operator.sub, "Mul8": operator.mul,
    "And8": operator.and_, "Or8": operator.or_, "Xor8": operator.xor,
    "CmpEQ8": lambda a, b: int(a == b),
    "CmpNE8": lambda a, b: int(a != b),
}


@pytest.mark.parametrize("positions", [(0, 1, 2, 3), (0, 1, 6, 7)])
def test_known_bits_binary_results_cover_all_concrete_members(positions: tuple[int, ...]) -> None:
    """Carry, borrow, wrap and bitwise facts cannot eliminate a concrete result."""
    states = _states(positions)
    for name, concrete in _BINARY.items():
        for (left, left_members), (right, right_members) in itertools.product(states, repeat=2):
            result = edge._kb_binary_op_8616(f"Iop_{name}", left, right)
            assert result is not None
            mask, value = result
            assert value & ~mask == 0
            if left[0] == right[0] == 0xFF:
                assert mask == (1 if name in ("CmpEQ8", "CmpNE8") else 0xFF)
            for a, b in itertools.product(left_members, right_members):
                assert (concrete(a, b) & 0xFF) & mask == value, (name, left, right, a, b, result)


@pytest.mark.parametrize("positions", [(0, 1, 2, 3), (0, 1, 6, 7)])
def test_known_bits_shifts_and_extensions_cover_concrete_members(positions: tuple[int, ...]) -> None:
    """Shift fill and signed extension retain only bits every member agrees on."""
    for value, members in _states(positions):
        for count in (0, 1, 3, 7, 8, 15):
            for name, shift in (("Shl8", operator.lshift), ("Shr8", operator.rshift)):
                result = edge._kb_binary_op_8616(f"Iop_{name}", value, (0xFF, count), count_bits=8)
                assert result is not None
                mask, known = result
                assert known & ~mask == 0
                if value[0] == 0xFF:
                    assert mask == 0xFF
                assert all((shift(member, count) & 0xFF) & mask == known for member in members)
        for signed in (False, True):
            result = edge._kb_unary_evidence_8616(f"Iop_8{'S' if signed else 'U'}to16", value, 16)
            assert result is not None
            mask, known = result
            assert known & ~mask == 0
            if value[0] == 0xFF:
                assert mask == 0xFFFF
            for member in members:
                extended = member - 256 if signed and member & 0x80 else member
                assert (extended & 0xFFFF) & mask == known
