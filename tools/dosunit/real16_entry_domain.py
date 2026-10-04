"""Architectural code-entry constraints for loaded real16 proof states.

Layer: dosunit proof input domain.
Responsibility: relate a loaded physical entry to every possible 16-bit CS:IP
alias. The domain follows from the binary entry address and real-mode code
offset width; it never assumes a nominal compiler selector or a calling ABI.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class Real16EntryDomain:
    """Nonempty selector interval whose code window contains the physical entry."""

    linear_entry: int
    minimum_cs: int
    maximum_cs: int

    def __post_init__(self) -> None:
        """Reject a vacuous or out-of-machine selector interval."""
        if not 0 <= self.minimum_cs <= self.maximum_cs <= 0xFFFF:
            raise ValueError("invalid real16 code-entry selector domain")

    def constraints(self) -> list[dict[str, Any]]:
        """Serialize the owned entry interval at the SSA solver boundary."""
        return [{"name": "cs", "kind": "unsigned_range", "min": self.minimum_cs, "max": self.maximum_cs}]

    def contains(self, cs: dict[str, Any]) -> dict[str, Any]:
        """Produce a Boolean SSA predicate for a substituted callee selector."""
        lower = {"op": "const", "width": 16, "value": hex(self.minimum_cs)}
        upper = {"op": "const", "width": 16, "value": hex(self.maximum_cs)}
        return {"op": "and", "width": 1, "args": [
            {"op": "uge", "width": 1, "args": [cs, lower]},
            {"op": "ule", "width": 1, "args": [cs, upper]},
        ]}


def code_entry_domain(linear_entry: int) -> Real16EntryDomain | None:
    """Admit all CS values with ``0 <= entry - 16*CS <= 0xffff``.

    A missing interval means the physical address has no real16 logical
    representation. Such an entry cannot become a vacuous successful proof.
    """
    minimum = max(0, (linear_entry - 0xFFFF + 15) // 16)
    maximum = min(0xFFFF, linear_entry // 16)
    if linear_entry < 0 or minimum > maximum:
        return None
    return Real16EntryDomain(linear_entry, minimum, maximum)
