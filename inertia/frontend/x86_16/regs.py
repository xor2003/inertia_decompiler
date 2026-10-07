"""Layer: IR compatibility.

Responsibility: stable register enums for legacy and migrated 16-bit x86 code.
Forbidden: semantic recovery, alias ownership, lowering, structuring, or rewrite work.
"""

from __future__ import annotations

from enum import Enum, IntEnum


class reg32_t(IntEnum):
    """32-bit general register identifiers used by legacy 86:16 helpers."""

    EAX = 0
    ECX = 1
    EDX = 2
    EBX = 3
    ESP = 4
    EBP = 5
    ESI = 6
    EDI = 7
    GPREGS_COUNT = 8
    EIP = 9
    EFLAGS = 10


class reg16_t(IntEnum):
    """16-bit general register identifiers used by legacy 86:16 helpers."""

    AX = 0
    CX = 1
    DX = 2
    BX = 3
    SP = 4
    BP = 5
    SI = 6
    DI = 7
    IP = 8
    FLAGS = 9


class reg8_t(IntEnum):
    """8-bit general register identifiers used by legacy 86:16 helpers."""

    AL = 0
    CL = 1
    DL = 2
    BL = 3
    AH = 4
    CH = 5
    DH = 6
    BH = 7


class sgreg_t(IntEnum):
    """Segment register identifiers for the 86:16 segmented memory model."""

    ES = 0
    CS = 1
    SS = 2
    DS = 3
    FS = 4
    GS = 5
    SGREGS_COUNT = 6


class dtreg_t(IntEnum):
    """Descriptor-table register identifiers accepted by legacy helpers."""

    GDTR = 0
    IDTR = 1
    LDTR = 2
    TR = 3
    DTREGS_COUNT = 4


def _coerce_enum[E: IntEnum](enum_cls: type[E], value: object) -> E:
    """Coerce a numeric register identifier while retaining its enum type."""
    if isinstance(value, enum_cls):
        return value
    raw_value = value.value if isinstance(value, IntEnum) else value
    if isinstance(raw_value, enum_cls):
        return raw_value
    if isinstance(raw_value, int):
        try:
            return enum_cls(raw_value)
        except Exception:
            pass
    raise ValueError(f"Register {value!r} does not exist")


def coerce_reg32_t(value: object) -> reg32_t:
    """Return a 32-bit register enum from an enum member or numeric index."""
    return _coerce_enum(reg32_t, value)


def coerce_reg16_t(value: object) -> reg16_t:
    """Return a 16-bit register enum from an enum member or numeric index."""
    return _coerce_enum(reg16_t, value)


def coerce_reg8_t(value: object) -> reg8_t:
    """Return an 8-bit register enum from an enum member or numeric index."""
    return _coerce_enum(reg8_t, value)


def coerce_sgreg_t(value: object) -> sgreg_t:
    """Return a segment register enum from an enum member or numeric index."""
    return _coerce_enum(sgreg_t, value)


def register_name_8616(value: object) -> str:
    """Return the lowercase canonical name for a known 86:16 register."""
    if isinstance(value, Enum):
        return value.name.lower()
    try:
        return _coerce_enum(reg32_t, value).name.lower()
    except Exception:
        pass
    try:
        return _coerce_enum(reg16_t, value).name.lower()
    except Exception:
        pass
    try:
        return _coerce_enum(reg8_t, value).name.lower()
    except Exception:
        pass
    raise ValueError(f"Register {value!r} does not exist")
