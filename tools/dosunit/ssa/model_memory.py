"""Layer: dosunit SSA counterexample evidence.

Responsibility: serialize complete finite byte-array models for independent
replay without inventing bytes for unsupported or truncated model forms.
"""
from __future__ import annotations

from enum import StrEnum
from typing import Any


class MemoryModelStatus(StrEnum):
    """Whether a serialized memory model defines every input byte."""

    COMPLETE = "complete"
    UNSUPPORTED = "unsupported"
    LIMIT = "limit"


def serialize_byte_memory(value: Any, *, max_stores: int = 4096) -> dict[str, Any]:  # noqa: ANN401
    """Flatten a third-party Z3 array value, respecting latest-write precedence.

    Only a constant byte array with finite concrete Store overrides is complete.
    The default byte describes all other addresses, not just sampled loads.
    Unsupported forms and exhausted bounds publish no partial replay image.
    """
    import z3

    if type(max_stores) is not int or max_stores < 0:
        raise ValueError("memory-model store limit must be a nonnegative integer")
    unsupported = {"status": MemoryModelStatus.UNSUPPORTED}
    if not z3.is_array(value):
        return unsupported
    sort = value.sort()
    if sort.domain() != z3.BitVecSort(32) or sort.range() != z3.BitVecSort(8):
        return unsupported
    stores: dict[int, int] = {}
    current = value
    count = 0
    while z3.is_store(current):
        if count >= max_stores:
            return {"status": MemoryModelStatus.LIMIT}
        address, byte = current.arg(1), current.arg(2)
        if not z3.is_bv_value(address) or not z3.is_bv_value(byte):
            return unsupported
        # Visit outer stores first: an older write must not overwrite them.
        stores.setdefault(address.as_long(), byte.as_long())
        current = current.arg(0)
        count += 1
    if not z3.is_const_array(current) or not z3.is_bv_value(current.arg(0)):
        return unsupported
    return {
        "status": MemoryModelStatus.COMPLETE, "address_bits": 32, "byte_bits": 8,
        "default_byte": current.arg(0).as_long(),
        "stores": [{"address": hex(address), "value": byte} for address, byte in sorted(stores.items())],
    }
