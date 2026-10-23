"""Shared vector effects retain live state and reject malformed selectors."""

import pytest

from inertia.frontend.real16_vector_response8616 import (
    VectorResponseEffect8616,
    VectorResponseRefusal8616,
    vector_response_8616,
)


def test_query_update_query_uses_current_slot() -> None:
    """The effect consumes the current slot, never a cached initial vector."""
    first = vector_response_8616(function=0x35, number=5, slot_before=b"\x44\x44\x11\x11")
    assert isinstance(first, VectorResponseEffect8616)
    assert (first.es, first.bx, first.slot_after) == (0x1111, 0x4444, None)
    update = vector_response_8616(
        function=0x25, number=5, slot_before=b"\x44\x44\x11\x11", ds=0x2222, dx=0x3333,
    )
    assert isinstance(update, VectorResponseEffect8616)
    assert update.slot_after == b"\x33\x33\x22\x22"
    assert update.es is update.bx is None
    final = vector_response_8616(function=0x35, number=5, slot_before=update.slot_after)
    assert isinstance(final, VectorResponseEffect8616)
    assert (final.es, final.bx) == (0x2222, 0x3333)


@pytest.mark.parametrize("field,value", [
    ("function", True), ("function", 0x30), ("number", True), ("number", -1),
    ("number", 256), ("slot_before", b"123"), ("slot_before", bytearray(4)),
    ("ds", None), ("ds", True), ("ds", 65536), ("dx", -1), ("dx", True), ("dx", 65536),
])
def test_malformed_response_inputs_refuse(field: str, value: object) -> None:
    """No bool, truncated slot or overflowing word becomes a valid effect."""
    fields = {"function": 0x25, "number": 5, "slot_before": bytes(4), "ds": 0x1234, "dx": 0x5678}
    fields[field] = value
    assert vector_response_8616(**fields) is VectorResponseRefusal8616.FUNCTION_UNSUPPORTED


def test_dos_dispatch_update_requires_unchanged_pointer() -> None:
    """A no-op update is allowed; replacing DOS dispatch requires a handler model."""
    slot = bytes.fromhex("78563412")
    same = vector_response_8616(function=0x25, number=0x21, slot_before=slot, ds=0x1234, dx=0x5678)
    assert isinstance(same, VectorResponseEffect8616)
    assert same.slot_after == slot
    changed = vector_response_8616(function=0x25, number=0x21, slot_before=slot, ds=0x1234, dx=0x5679)
    assert changed is VectorResponseRefusal8616.DOS_UPDATE
