"""Layer: IR.

Responsibility: describe and evaluate bounded native repeated-store effects.
The caller authenticates the complete IR block against freshly lifted source
bytes. This owner decodes those bytes through the frontend's Capstone boundary;
no rendered instruction text or register-name heuristic authorizes a transfer.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

from inertia.frontend.x86_16.frontend_repeated_store8616 import RepeatedStore8616, decoded_repeated_store_8616

from .core import IRBlock


class RepeatedStoreStatus8616(Enum):
    """Whether an authenticated whole-instruction transfer was consumed."""

    NOT_APPLICABLE = "not_applicable"
    APPLIED = "applied"
    REFUSED = "refused"


@dataclass(frozen=True, slots=True)
class RepeatedStoreEffect8616:
    """Complete non-wrapping footprint and final index/count for one repeat."""

    base: int
    size: int
    data: bytes | None
    final_di: int | None


_MAX_REPEAT_BYTES_8616: int = 0x10000


def native_repeated_store_8616(project: object, block: IRBlock, encoded: bytes) -> RepeatedStore8616 | None:
    """Decode a single-instruction repeat block with its exact continuation.

    The full native-row comparison belongs to the caller and is mandatory
    before consuming this descriptor. Other prefix/width/control shapes keep
    the ordinary conservative nonterminal-exit refusal.
    """
    if block.refusals or not block.instrs:
        return None
    if any(row.addr != block.addr for row in block.instrs):
        return None
    if block.successor_addrs != (block.addr + len(encoded),):
        return None
    return decoded_repeated_store_8616(project, block.addr, encoded)


def repeated_store_effect_8616(
    instruction: RepeatedStore8616, registers: Mapping[str, int],
    direction: bool | None,
) -> RepeatedStoreEffect8616 | None:
    """Evaluate the whole footprint without executing/unrolling iterations.

    Unknown source data marks the entire proven span unknown. Unknown count,
    selector/index/direction, 16-bit index wrap or physical wrap refuses. A
    zero count performs no read/write and preserves even an unknown DI.
    """
    if instruction.width not in (1, 2):
        return None
    count = registers.get("cx")
    if type(count) is not int or not 0 <= count <= 0xFFFF:
        return None
    index = registers.get("di")
    if count == 0:
        return RepeatedStoreEffect8616(0, 0, b"", index)
    segment = registers.get("es")
    if direction is None or type(index) is not int or type(segment) is not int:
        return None
    if not 0 <= index <= 0xFFFF or not 0 <= segment <= 0xFFFF:
        return None
    size = count * instruction.width
    final = index + (-size if direction else size)
    start = index - size + instruction.width if direction else index
    if size > _MAX_REPEAT_BYTES_8616 or min(start, final) < 0 or max(start + size, final) > 0xFFFF:
        return None
    base = (segment << 4) + start
    if base + size > 0x100000:
        return None
    value = registers.get("al" if instruction.width == 1 else "ax")
    data = None if value is None else (value & ((1 << (8 * instruction.width)) - 1)).to_bytes(instruction.width, "little") * count
    return RepeatedStoreEffect8616(base, size, data, final)
