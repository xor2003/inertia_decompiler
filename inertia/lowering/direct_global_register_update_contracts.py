# cython: language_level=3, infer_types=True
"""Define direct-global register update facts and closed materialization stats.

Layer: Types/Lowering.
Responsibility: own typed contracts shared by binary evidence collection and
structured-C materialization without collecting or rewriting either surface.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum
import dataclasses
import operator


class DirectGlobalRegisterUpdateOp8616(StrEnum):
    """Supported logical operation proven by one machine instruction."""

    AND = "And"
    OR = "Or"
    XOR = "Xor"


@dataclasses.dataclass(frozen=True, )
class DirectGlobalRegisterUpdate8616:
    """One adjacent global-load and global-update instruction pair."""

    source_offset: cython.longlong
    destination_offset: cython.longlong
    width: cython.longlong
    register_id: cython.longlong
    operation: DirectGlobalRegisterUpdateOp8616
    load_insn_addr: cython.longlong
    update_insn_addr: cython.longlong


@dataclasses.dataclass(frozen=True, )
class DirectGlobalRegisterUpdateStats8616:
    """Closed materialization counters for register-carried updates."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong

    @property
    def complete(self) -> cython.bint:
        """Return whether every binary fact was materialized or refused."""
        return (
            operator.eq(self.raw_fact_count, self.materialized_count + self.failure_count)
            and self.normalized_fact_count
            == self.classified_fact_count
            == self.raw_fact_count
        )


__all__ = [
    "DirectGlobalRegisterUpdate8616",
    "DirectGlobalRegisterUpdateOp8616",
    "DirectGlobalRegisterUpdateStats8616",
]
