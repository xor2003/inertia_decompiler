"""Numeric selection transfer contracts.

Layer: IR tests.
Responsibility: verify exact and known-bit selection, capture identity and refusals.
"""
from dataclasses import replace

import pytest

from inertia.ir import real16_edge_feasibility8616 as kb
from inertia.ir import real16_invocation_domain as exact
from inertia.ir.core import IRActiveUnary8616, IRInstr, IRValue, MemSpace


def _row(bits: int = 16, guard: IRValue | None = None,
         true: IRValue | None = None, false: IRValue | None = None) -> IRInstr:
    """Create a typed selection with independently pinned operands."""
    size = (bits + 7) // 8
    dst = IRValue(MemSpace.TMP, source_tmp=9, size=size)
    args = (
        guard if guard is not None else IRValue(MemSpace.TMP, source_tmp=0, size=1),
        true if true is not None else IRValue(MemSpace.TMP, source_tmp=1, size=size),
        false if false is not None else IRValue(MemSpace.TMP, source_tmp=2, size=size),
    )
    return IRInstr(op=f"SELECT{bits}", dst=dst, args=args, size=size)


@pytest.mark.parametrize("bits", [1, 8, 16, 32, 64])
@pytest.mark.parametrize("guard", [0, 1, 2, 3])
def test_exact_and_known_guard(bits: int, guard: int) -> None:
    """Only the low guard bit selects the width-masked result."""
    row = _row(bits)
    mask = (1 << bits) - 1
    state = {0: guard, 1: 0xD5, 2: 0xAA}
    expected = state[1 if guard & 1 else 2] & mask
    exact._simulate_tmp_write_8616(row, row.dst, {}, state)
    assert state[9] == expected
    known = {0: (1, guard & 1), 1: (mask, 0xD5 & mask), 2: (mask, 0xAA & mask)}
    kb._kb_tmp_write_8616(row, row.dst, {}, known)
    assert known[9] == (mask, expected)


def test_unknown_guard_keeps_only_equal_known_bits() -> None:
    """An unknown predicate joins arms without inventing differing bits."""
    row = _row()
    state = {1: 42, 2: 42, 9: 99}
    exact._simulate_tmp_write_8616(row, row.dst, {}, state)
    assert 9 not in state
    known = {0: (0xFE, 0x80), 1: (0xFF, 0xAC), 2: (0xF7, 0xA5)}
    kb._kb_tmp_write_8616(row, row.dst, {}, known)
    mask = 0xFF & 0xF7 & ~(0xAC ^ 0xA5)
    assert known[9] == (mask, 0xAC & mask)


@pytest.mark.parametrize("known_guard", [True, False])
def test_missing_arm_stays_conservative(known_guard: bool) -> None:
    """Unselected unknown arms do not poison a proven selection."""
    row = _row()
    known = {1: (0xFFFF, 7)}
    if known_guard:
        known[0] = (1, 1)
    kb._kb_tmp_write_8616(row, row.dst, {}, known)
    assert known[9] == ((0xFFFF, 7) if known_guard else (0, 0))


def test_captured_register_arm_does_not_read_new_register() -> None:
    """Captured temporary identity wins over the current register value."""
    row = _row(true=IRValue(MemSpace.REG, name="ax", size=2, source_tmp=1))
    state = {0: 1, 1: 7, 2: 8}
    exact._simulate_tmp_write_8616(row, row.dst, {"ax": 99}, state)
    assert state[9] == 7
    known = {0: (1, 1), 1: (0xFFFF, 7), 2: (0xFFFF, 8)}
    kb._kb_tmp_write_8616(row, row.dst, {"ax": (0xFFFF, 99)}, known)
    assert known[9] == (0xFFFF, 7)


def test_one_bit_select_can_be_widened_without_inventing_upper_bits() -> None:
    """A retained I1 result is consumed once by an explicit unsigned widening."""
    row = _row(1)
    state = {0: 1, 1: 3, 2: 0}
    known = {0: (1, 1), 1: (1, 1), 2: (1, 0)}
    exact._simulate_tmp_write_8616(row, row.dst, {}, state)
    kb._kb_tmp_write_8616(row, row.dst, {}, known)
    value = IRValue(MemSpace.TMP, size=2, expr=("Iop_1Uto16",),
                    active_unary=IRActiveUnary8616("Iop_1Uto16", row.dst, 16))
    assert exact._eval_atom_8616(value, {}, state) == 1
    assert kb._kb_eval_value_8616(value, {}, known) == (0xFFFF, 1)


@pytest.mark.parametrize("fault", ["count", "width", "opcode", "destination"])
def test_malformed_select_is_not_evaluated(fault: str) -> None:
    """Shape contradictions clear stale numeric knowledge."""
    row = _row()
    if fault == "count":
        row = replace(row, args=row.args[:2])
    elif fault == "width":
        row = replace(row, size=1)
    elif fault == "opcode":
        row = replace(row, op="SELECT7")
    else:
        row = replace(row, dst=IRValue(MemSpace.REG, name="ax", size=2, source_tmp=9))
    state = {0: 1, 1: 7, 2: 8, 9: 99}
    exact._simulate_tmp_write_8616(row, row.dst, {}, state)
    assert 9 not in state
    known = {0: (1, 1), 1: (0xFFFF, 7), 2: (0xFFFF, 8), 9: (0xFFFF, 99)}
    kb._kb_tmp_write_8616(row, row.dst, {}, known)
    assert known[9] == (0, 0)
