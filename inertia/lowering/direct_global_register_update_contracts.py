"""Define direct-global register update facts and closed materialization stats.

Layer: Types/Lowering.
Responsibility: own typed contracts shared by binary evidence collection and
structured-C materialization without collecting or rewriting either surface.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class DirectGlobalRegisterUpdateOp8616(StrEnum):
    """Supported logical operation proven by one machine instruction."""

    AND = "And"
    OR = "Or"
    XOR = "Xor"


@dataclass(frozen=True, slots=True)
class DirectGlobalRegisterUpdate8616:
    """One adjacent global-load and global-update instruction pair."""

    source_offset: int
    destination_offset: int
    width: int
    register_id: int
    operation: DirectGlobalRegisterUpdateOp8616
    load_insn_addr: int
    update_insn_addr: int


@dataclass(frozen=True, slots=True)
class DirectGlobalRegisterUpdateStats8616:
    """Closed materialization counters for register-carried updates."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def complete(self) -> bool:
        """Return whether every binary fact was materialized or refused."""
        return (
            self.raw_fact_count == self.materialized_count + self.failure_count
            and self.normalized_fact_count
            == self.classified_fact_count
            == self.raw_fact_count
        )


__all__ = [
    "DirectGlobalRegisterUpdate8616",
    "DirectGlobalRegisterUpdateOp8616",
    "DirectGlobalRegisterUpdateStats8616",
]
