# cython: language_level=3, infer_types=True
"""Immutable evidence for binary terminal stack effects.

Layer: Semantics.
Responsibility: retain cleanup, return kind and operand width as independent
facts. Missing width never proves a word-sized return. Consumers must require
complete evidence before transferring machine frame ownership.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast
import dataclasses
import operator

_DECODED_PREFIX_SLOTS: cython.longlong = 4
_OPERAND_SIZE_OVERRIDE: cython.longlong = 0x66


class TerminalReturnFrameKind8616(StrEnum):
    """Machine return-frame shapes proven on terminal callee paths."""

    NEAR = "near"
    FAR = "far"
    INTERRUPT = "interrupt"


@dataclasses.dataclass(frozen=True, )
class TerminalStackCleanupEvidence8616:
    """Closed accounting for distinct reachable returns and incomplete edges."""

    cleanup_amounts: object
    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong
    return_frame_kinds: frozenset[TerminalReturnFrameKind8616] = frozenset()
    return_operand_bits: frozenset[int | None] = frozenset()

    @property
    def complete(self) -> cython.bint:
        """Return whether every reachable terminal fact has a valid cleanup amount."""
        return (
            self.raw_fact_count > 0
            and operator.eq(self.normalized_fact_count, self.raw_fact_count)
            and operator.eq(self.classified_fact_count, self.raw_fact_count)
            and operator.eq(self.materialized_count, self.classified_fact_count)
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

    prefix: object


@cython.ccall
def decoded_return_operand_bits_8616(instruction: object) -> int | None:
    """Read operand size from decoded prefixes in the 16-bit default mode."""
    try:
        prefixes = cast(_DecodedReturnBoundary8616, instruction).prefix
    except AttributeError:
        return None
    if not isinstance(prefixes, (list, tuple)) or operator.ne(len(prefixes), _DECODED_PREFIX_SLOTS):
        return None
    return 32 if _OPERAND_SIZE_OVERRIDE in prefixes else 16
