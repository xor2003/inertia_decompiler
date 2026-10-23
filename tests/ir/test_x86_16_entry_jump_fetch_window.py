"""Layer: Tests.

Responsibility: check near-IP wrapping against the selector-domain theorem.
"""

import pytest

from inertia.frontend.x86_16.relative_control_edge import (
    DecodedRelativeEdge,
    decode_relative_edge,
)
from inertia.ir.entry_jump_domain import _window_invariant_target_8616


@pytest.mark.parametrize(
    ("root", "head", "encoding", "invariant"),
    ((0x102C2, 0x102D2, b"\xeb\x16", False),
     (0x1000, 0x1008, b"\xeb\x06", True)),
)
def test_near_jump_admission_matches_all_fetchable_selectors(
    root: int, head: int, encoding: bytes, invariant: bool,
) -> None:
    """A call-free leaf still needs a premise when its IP may wrap."""
    decoded = decode_relative_edge(head, encoding, source="block_terminal")
    assert isinstance(decoded, DecodedRelativeEdge)
    destinations = {
        (selector << 4)
        + ((head - (selector << 4) + len(encoding) + decoded.displacement) & 0xFFFF)
        for selector in range(0x10000)
        if 0 <= root - (selector << 4) <= 0xFFFF
        and 0 <= head - (selector << 4) <= 0xFFFF
    }
    expected = decoded.next_head + decoded.displacement
    assert (destinations == {expected}) is invariant
    assert _window_invariant_target_8616(decoded, root) == (
        expected if invariant else None
    )
    if not invariant:
        assert destinations == {0x2EA, 0x102EA}
