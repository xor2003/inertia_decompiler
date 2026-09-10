"""Immutable evidence for binary terminal stack effects.

Layer: Semantics.
Responsibility: retain cleanup, return kind and operand width as independent
facts. Missing width never proves a word-sized return. Consumers must require
complete evidence before transferring machine frame ownership.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

_DECODED_PREFIX_SLOTS: int = 4
_OPERAND_SIZE_OVERRIDE: int = 0x66


class TerminalReturnFrameKind8616(StrEnum):
    """Machine return-frame shapes proven on terminal callee paths."""

    NEAR = "near"
    FAR = "far"
    INTERRUPT = "interrupt"


@dataclass(frozen=True, slots=True)
class TerminalStackCleanupEvidence8616:
    """Closed accounting for cleanup amounts and decoded return properties."""

    cleanup_amounts: frozenset[int]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    return_frame_kinds: frozenset[TerminalReturnFrameKind8616] = frozenset()
    return_operand_bits: frozenset[int | None] = frozenset()

    @property
    def complete(self) -> bool:
        """Return whether every terminal path has a valid cleanup amount."""
        return (
            self.raw_fact_count > 0
            and self.normalized_fact_count == self.raw_fact_count
            and self.classified_fact_count == self.raw_fact_count
            and self.materialized_count == self.classified_fact_count
            and self.failure_count == 0
        )

    @property
    def consistent_cleanup(self) -> int | None:
        """Return the one cleanup amount proven on every terminal path."""
        if not self.complete or len(self.cleanup_amounts) != 1:
            return None
        return next(iter(self.cleanup_amounts))

    @property
    def consistent_return_frame_kind(self) -> TerminalReturnFrameKind8616 | None:
        """Return the one machine return-frame shape on every terminal path."""
        if not self.complete or len(self.return_frame_kinds) != 1:
            return None
        return next(iter(self.return_frame_kinds))

    @property
    def consistent_return_operand_bits(self) -> int | None:
        """Return an agreed decoded width; absent or mixed evidence refuses."""
        if not self.complete or len(self.return_operand_bits) != 1:
            return None
        return next(iter(self.return_operand_bits))


class _DecodedReturnBoundary8616(Protocol):
    """Capstone prefix field at the instruction decoder boundary."""

    prefix: list[int]


def decoded_return_operand_bits_8616(instruction: object) -> int | None:
    """Read operand size from decoded prefixes in the 16-bit default mode."""
    try:
        prefixes = cast(_DecodedReturnBoundary8616, instruction).prefix
    except AttributeError:
        return None
    if not isinstance(prefixes, (list, tuple)) or len(prefixes) != _DECODED_PREFIX_SLOTS:
        return None
    return 32 if _OPERAND_SIZE_OVERRIDE in prefixes else 16
