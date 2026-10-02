"""Exact address indexing for closed SSA function composition.

Layer: dosunit semantic comparison.
Responsibility: preserve full loaded control addresses and reject ambiguous
legacy aliases instead of letting unrelated blocks replace each other.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any


class ControlIndexReason(StrEnum):
    """Missing or contradictory address evidence at the SSA CFG boundary."""

    MISSING = "control_entry_missing"
    AMBIGUOUS = "control_entry_ambiguous"


class ControlIndexRefusal(Exception):
    """Retain a typed refusal when a closed block index cannot be constructed."""

    def __init__(self, reason: ControlIndexReason) -> None:
        """Publish the exact address obligation that lacks evidence."""
        self.reason = reason
        super().__init__(reason.value)


def _address(value: object) -> int | None:
    """Parse declared nonnegative addresses without truncating their width."""
    if type(value) is int:
        return value if value >= 0 else None
    if isinstance(value, str):
        try:
            parsed = int(value, 0)
        except ValueError:
            return None
        return parsed if parsed >= 0 else None
    return None


def closed_block_index(parts: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    """Index physical control by exact linear address; retain proved legacy keys.

    Fresh VEX SSA publishes ``control_ip`` and therefore must have a physical
    entry for every block. Legacy documents without that contract can use their
    declared IP keys, but contradictory aliases refuse. No implicit low-word
    projection can establish a physical successor relationship.
    """
    physical = any("control_ip" in part.get("outputs", {}) for part in parts)
    index: dict[int, dict[str, Any]] = {}
    for part in parts:
        entry = part.get("entry", {})
        keys = (_address(entry.get("linear")),) if physical else (
            _address(entry.get("linear")), _address(entry.get("ip")),
        )
        admitted = tuple(key for key in keys if key is not None)
        if not admitted:
            raise ControlIndexRefusal(ControlIndexReason.MISSING)
        for key in admitted:
            if key in index and index[key] is not part:
                raise ControlIndexRefusal(ControlIndexReason.AMBIGUOUS)
            index[key] = part
    return index
