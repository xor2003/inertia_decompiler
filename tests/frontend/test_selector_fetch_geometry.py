"""Fetch-extent boundary controls for the canonical selector geometry.

Every native instruction — including ordinary non-control rows — must
fit its authenticated CS window under conservative A20 limits before any
source binding is attempted.
"""

from __future__ import annotations

import pytest

from inertia.frontend.x86_16.instruction_fetch_geometry import (
    FetchVerdict8616,
    check_instruction_fetch_8616,
)

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize(("addr", "encoded", "cs", "expected"), [
    (0x1000, b"\x90", 0x100, FetchVerdict8616.CLOSED),
    (0x10FFF, b"\x90", 0x100, FetchVerdict8616.CLOSED),
    (0x1000, b"\x90", None, FetchVerdict8616.REFUSED),
    (0x1000, b"\x90", -1, FetchVerdict8616.REFUSED),
    (0x1000, None, 0x100, FetchVerdict8616.REFUSED),
    (0x1000, b"", 0x100, FetchVerdict8616.REFUSED),
    (0x10FFF, b"\x90\x90", 0x100, FetchVerdict8616.REFUSED),
    (0xFFFFF, b"\x90\x90", 0xFFFF, FetchVerdict8616.REFUSED),
])
def test_all_fetch_extent_boundaries(
    addr: int, encoded: bytes | None, cs: int | None, expected: FetchVerdict8616,
) -> None:
    """Every instruction, including ordinary rows, needs complete selector geometry."""
    assert check_instruction_fetch_8616(addr, encoded, cs).verdict is expected


def test_fetch_refusals_carry_typed_detail() -> None:
    """A refused fetch names its exact boundary violation, never a guess."""
    assert check_instruction_fetch_8616(
        0x10FFF, b"\x90\x90", 0x100).detail == "fetch_outside_cs_window"
    assert check_instruction_fetch_8616(
        0xFFFFF, b"\x90\x90", 0xFFFF).detail == "fetch_a20_ambiguous"
    assert check_instruction_fetch_8616(
        0x1000, b"\x90", None).detail == "cs_unbound"
    closed = check_instruction_fetch_8616(0x1000, b"\x90", 0x100)
    assert closed.detail == "instruction_fetch_bound"
    assert closed.cs == 0x100 and closed.size == 1
