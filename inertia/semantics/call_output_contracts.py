"""Typed contracts for register outputs produced by exact machine calls.

Layer: Semantics.
Responsibility: own immutable call-output identities, shapes, verdicts,
failures, and closed accounting before SSA and Alias consume those outputs.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.core import IRCallOutputShape8616 as CallOutputShape8616
from inertia.ir.core import IRValue


class CallOutputVerdict8616(StrEnum):
    """Typed result for one exact CALL output classification."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


class CallOutputFailure8616(StrEnum):
    """Stable reasons a used call result cannot become SSA definitions."""

    CALL_ADDRESS_MISSING = "call_address_missing"
    CALL_NOT_TERMINAL = "call_not_terminal"
    DUPLICATE_CALL_ADDRESS = "duplicate_call_address"
    FRAME_KIND_UNKNOWN = "frame_kind_unknown"
    RETURN_BLOCK_HAS_OTHER_PREDECESSOR = "return_block_has_other_predecessor"
    RETURN_BLOCK_MISSING = "return_block_missing"
    RETURN_EDGE_MISMATCH = "return_edge_mismatch"
    RETURN_SHAPE_UNKNOWN = "return_shape_unknown"
    RETURN_USE_UNKNOWN = "return_use_unknown"
    SUMMARY_MISSING = "summary_missing"
    TARGET_UNRESOLVED = "target_unresolved"


@dataclass(frozen=True, slots=True)
class CallOutputFact8616:
    """One CALL and the exact register definitions on its return edge."""

    call_block_addr: int
    call_instr_index: int
    callsite_addr: int | None
    target_addr: int | None
    return_block_addr: int | None
    shape: CallOutputShape8616 | None
    outputs: tuple[IRValue, ...]
    verdict: CallOutputVerdict8616
    failure: CallOutputFailure8616 | None


@dataclass(frozen=True, slots=True)
class CallOutputStats8616:
    """Closed accounting for every CALL output decision in one function."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def closed(self) -> bool:
        """Return whether every CALL has one retained typed outcome."""
        return (
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
        )

    @property
    def complete(self) -> bool:
        """Return whether every output decision is positively proven."""
        return self.closed and self.failure_count == 0

    def to_dict(self) -> dict[str, int]:
        """Return deterministic closed-loop counters."""
        return {
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
        }


__all__ = [
    "CallOutputFact8616",
    "CallOutputFailure8616",
    "CallOutputShape8616",
    "CallOutputStats8616",
    "CallOutputVerdict8616",
]
