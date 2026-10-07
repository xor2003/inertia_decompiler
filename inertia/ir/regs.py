"""Register offset and segment-space helpers for IR construction.

Layer: IR.
Responsibility: owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

__all__ = [
    "REG8_OFFSET_MAP",
    "REG16_OFFSET_MAP",
    "REG32_OFFSET_MAP",
    "register_name_from_offset",
    "segment_space_for_base",
]


REG8_OFFSET_MAP: dict[int, str] = {
    0: "al",
    1: "ah",
    4: "cl",
    5: "ch",
    8: "dl",
    9: "dh",
    12: "bl",
    13: "bh",
}


REG16_OFFSET_MAP: dict[int, str] = {
    0: "ax",
    4: "cx",
    8: "dx",
    12: "bx",
    16: "sp",
    20: "bp",
    24: "si",
    28: "di",
    32: "ip",
    36: "flags",
    40: "cs",
    42: "ds",
    44: "es",
    46: "fs",
    48: "gs",
    50: "ss",
}

REG32_OFFSET_MAP: dict[int, str] = {
    0: "eax",
    4: "ecx",
    8: "edx",
    12: "ebx",
    16: "esp",
    20: "ebp",
    24: "esi",
    28: "edi",
    32: "eip",
    36: "eflags",
    164: "cr0",
    168: "cr2",
    172: "cr3",
}


def register_name_from_offset(offset: int, size: int = 2) -> str:
    """Return the width-correct register view for a VEX offset and byte size."""
    offset_value = int(offset)
    if size == 1 and offset_value in REG8_OFFSET_MAP:
        return REG8_OFFSET_MAP[offset_value]
    if size == 4 and offset_value in REG32_OFFSET_MAP:
        return REG32_OFFSET_MAP[offset_value]
    return REG16_OFFSET_MAP.get(offset_value, f"r{offset}")


def segment_space_for_base(name: str | None) -> str:
    """Return the default segment space implied by a base register name."""
    if name in {"bp", "sp"}:
        return "ss"
    if name == "di":
        return "es"
    if name in {"si", "bx"}:
        return "ds"
    return "unknown"
