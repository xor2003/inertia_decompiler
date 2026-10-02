"""Layer: dosunit binary instruction admission.

Responsibility: classify repeat-string control from immutable decoded bytes and
admit only the exact operand/address/segment forms covered by the active summary.
Unsupported forms retain native IR; instruction display text is never evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class StringFamily(StrEnum):
    """Architectural operation executed once per admitted repeat iteration."""

    MOVE = "movs"
    STORE = "stos"
    SCAN = "scas"
    COMPARE = "cmps"


class RepeatMode(StrEnum):
    """Counter-only repetition or the post-iteration equality condition."""

    COUNT = "rep"
    EQUAL = "repe"
    NOT_EQUAL = "repne"


class RepeatArchitecture(StrEnum):
    """Declared defaults for the active instruction and register-state adapter."""

    REAL16 = "real16"
    FLAT32 = "flat32"


@dataclass(frozen=True, slots=True)
class RepeatStringSpec:
    """A byte-derived repeat operation under explicit architectural defaults."""

    repeat: RepeatMode
    family: StringFamily
    width: int
    architecture: RepeatArchitecture

    def to_document(self) -> dict[str, Any]:
        """Serialize the owned instruction contract for existing SSA consumers."""
        return {"repeat": self.repeat.value, "family": self.family.value,
                "width": self.width,
                "architecture": self.architecture.value,
                "mnemonic": self.family.value + {1: "b", 2: "w", 4: "d"}[self.width]}


_PREFIXES: frozenset[int] = frozenset({0xF0, 0xF2, 0xF3, 0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67})
_STRING_OPCODES: frozenset[int] = frozenset({0x6C, 0x6D, 0x6E, 0x6F, 0xA4, 0xA5, 0xA6, 0xA7,
                                         0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF})
_FAMILIES: dict[int, StringFamily] = {0xA4: StringFamily.MOVE, 0xA5: StringFamily.MOVE,
                                    0xA6: StringFamily.COMPARE, 0xA7: StringFamily.COMPARE,
                                    0xAA: StringFamily.STORE, 0xAB: StringFamily.STORE,
                                    0xAE: StringFamily.SCAN, 0xAF: StringFamily.SCAN}


def _instruction_bytes(instruction: dict[str, Any]) -> bytes:
    """Read the decoded byte record; malformed or absent bytes are no evidence."""
    raw = instruction.get("bytes")
    if not isinstance(raw, str):
        return b""
    try:
        code = bytes.fromhex(raw)
    except ValueError:
        return b""
    return code if instruction.get("size") == len(code) else b""


def is_repeat_string_instruction(instruction: dict[str, Any]) -> bool:
    """Recognize repeat control even when overrides require native-IR fallback."""
    code = _instruction_bytes(instruction)
    at = 0
    repeated = False
    while at < len(code) and code[at] in _PREFIXES:
        repeated |= code[at] in {0xF2, 0xF3}
        at += 1
    return repeated and at + 1 == len(code) and code[at] in _STRING_OPCODES


def decode_repeat_summary(
    instructions: list[dict[str, Any]], *,
    architecture: RepeatArchitecture = RepeatArchitecture.REAL16,
) -> RepeatStringSpec | None:
    """Admit one isolated default-form REP; preserve all other blocks as IR.

    Prefix instructions before REP, address/operand overrides and source-segment
    overrides must not be silently replaced by a default-form summary. This
    admission rule makes no assertion that their native semantics are unsupported.
    """
    if len(instructions) != 1:
        return None
    if architecture is RepeatArchitecture.REAL16:
        default_width = 2
    elif architecture is RepeatArchitecture.FLAT32:
        default_width = 4
    else:
        return None
    code = _instruction_bytes(instructions[0])
    if len(code) != 2 or code[0] not in {0xF2, 0xF3}:
        return None
    family = _FAMILIES.get(code[1])
    if family is None:
        return None
    mode = RepeatMode.COUNT
    if family in {StringFamily.SCAN, StringFamily.COMPARE}:
        mode = RepeatMode.NOT_EQUAL if code[0] == 0xF2 else RepeatMode.EQUAL
    return RepeatStringSpec(mode, family, 1 if code[1] % 2 == 0 else default_width, architecture)
