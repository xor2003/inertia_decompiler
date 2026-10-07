"""Alias-domain keys and register view helpers.

Layer: Alias.
Responsibility: owns storage identity for register domains and bit views.
Owns canonical register-domain and slice identities.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, slots=True)
class DomainKey:
    """Canonical key for an alias storage domain."""

    kind: Literal["reg"]
    name: str


@dataclass(frozen=True, slots=True)
class View:
    """Bit range within a canonical alias domain."""

    bit_offset: int
    bit_width: int

    @property
    def bit_end(self) -> int:
        """Return the exclusive bit offset for this view."""
        return self.bit_offset + self.bit_width

    def can_join(self, other: View) -> bool:
        """Return whether two views are adjacent and can form a wider view."""
        return self.bit_end == other.bit_offset or other.bit_end == self.bit_offset

    def join(self, other: View) -> View | None:
        """Return a combined view when two views are adjacent."""
        if not self.can_join(other):
            return None
        first, second = (self, other) if self.bit_offset <= other.bit_offset else (other, self)
        return View(first.bit_offset, first.bit_width + second.bit_width)


FULL16: View = View(0, 16)
LOW8: View = View(0, 8)
HIGH8: View = View(8, 8)

AX: DomainKey = DomainKey("reg", "AX")
BX: DomainKey = DomainKey("reg", "BX")
CX: DomainKey = DomainKey("reg", "CX")
DX: DomainKey = DomainKey("reg", "DX")
SP: DomainKey = DomainKey("reg", "SP")
BP: DomainKey = DomainKey("reg", "BP")
SI: DomainKey = DomainKey("reg", "SI")
DI: DomainKey = DomainKey("reg", "DI")

REGISTER_VIEWS: dict[str, tuple[DomainKey, View]] = {
    "ax": (AX, FULL16),
    "al": (AX, LOW8),
    "ah": (AX, HIGH8),
    "bx": (BX, FULL16),
    "bl": (BX, LOW8),
    "bh": (BX, HIGH8),
    "cx": (CX, FULL16),
    "cl": (CX, LOW8),
    "ch": (CX, HIGH8),
    "dx": (DX, FULL16),
    "dl": (DX, LOW8),
    "dh": (DX, HIGH8),
    "sp": (SP, FULL16),
    "bp": (BP, FULL16),
    "si": (SI, FULL16),
    "di": (DI, FULL16),
}

REGISTER_OFFSETS: dict[str, int] = {
    "ax": 0,
    "cx": 2,
    "dx": 4,
    "bx": 6,
    "sp": 8,
    "bp": 10,
    "si": 12,
    "di": 14,
}

REGISTER_PAIR_NAMES: dict[str, str] = {
    "al": "ax",
    "ah": "ax",
    "bl": "bx",
    "bh": "bx",
    "cl": "cx",
    "ch": "cx",
    "dl": "dx",
    "dh": "dx",
}


def register_domain_for_name(name: str | None) -> DomainKey | None:
    """Return the canonical register alias domain for a register name."""
    if not isinstance(name, str):
        return None
    view_entry = REGISTER_VIEWS.get(name.lower())
    if view_entry is None:
        return None
    return view_entry[0]


def register_view_for_name(name: str | None) -> View | None:
    """Return the bit view represented by a register name."""
    if not isinstance(name, str):
        return None
    view_entry = REGISTER_VIEWS.get(name.lower())
    if view_entry is None:
        return None
    return view_entry[1]


def register_pair_name(name: str | None) -> str | None:
    """Return the full 16-bit register name for a byte or word register."""
    if not isinstance(name, str):
        return None
    name = name.lower()
    if name in REGISTER_PAIR_NAMES:
        return REGISTER_PAIR_NAMES[name]
    if name in REGISTER_OFFSETS:
        return name
    return None


def register_offset_for_name(name: str | None) -> int | None:
    """Return the 16-bit angr register offset for a register name."""
    if not isinstance(name, str):
        return None
    return REGISTER_OFFSETS.get(name.lower())


def register_views_can_join(left: View, right: View) -> bool:
    """Return whether two register views are adjacent."""
    return left.can_join(right)


def join_register_views(left: View, right: View) -> View | None:
    """Return the joined register view when two views are adjacent."""
    return left.join(right)


__all__ = [
    "AX",
    "BP",
    "BX",
    "CX",
    "DI",
    "DX",
    "FULL16",
    "HIGH8",
    "LOW8",
    "REGISTER_OFFSETS",
    "REGISTER_PAIR_NAMES",
    "REGISTER_VIEWS",
    "SI",
    "SP",
    "DomainKey",
    "View",
    "join_register_views",
    "register_domain_for_name",
    "register_offset_for_name",
    "register_pair_name",
    "register_view_for_name",
    "register_views_can_join",
]
