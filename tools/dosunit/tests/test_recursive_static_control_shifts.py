"""Bounded scalar shift controls for exact native control-coordinate intake."""
from __future__ import annotations

import pytest

from tools.dosunit.recursive_proofs.recursive_static_control import (
    StaticControlReason,
    resolve_static_control,
)


@pytest.mark.parametrize("count,expected", [(0, 0xFFFF), (4, 0xFFFF0), (32, 0), (255, 0)])
def test_segment_shift_is_exact_and_bounded(count: int, expected: int) -> None:
    """A byte count shifts a DWORD with explicit bitvector saturation."""
    term = {"op": "shl", "width": 32, "args": [
        {"op": "const", "width": 32, "value": "0xffff"},
        {"op": "const", "width": 8, "value": count},
    ]}
    result = resolve_static_control(term)
    assert result.complete
    assert result.targets == frozenset({expected})


def test_shift_with_wrong_value_width_refuses() -> None:
    """A count-width exception never relaxes the shifted value's type."""
    term = {"op": "shl", "width": 32, "args": [
        {"op": "const", "width": 16, "value": "0xffff"},
        {"op": "const", "width": 8, "value": 4},
    ]}
    assert resolve_static_control(term).reason is StaticControlReason.MALFORMED
