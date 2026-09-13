"""Typed evidence contracts for caller-frame effects across machine calls.

Layer: Semantics.
Responsibility: own immutable verdicts, failures, per-call effects, and closed
evidence accounting for exact caller stack ranges crossing CALL boundaries.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from ..ir import IRCallStackEffect8616


class CallStackEffectVerdict8616(StrEnum):
    """Evidence result for one exact machine CALL instruction."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


class CallStackEffectFailure8616(StrEnum):
    """Stable reasons caller-frame preservation cannot be proven."""

    ARGUMENT_CLASSES_INCOMPLETE = "argument_classes_incomplete"
    ARGUMENT_ADDRESS_PROVENANCE_CONFLICT = "argument_address_provenance_conflict"
    ARGUMENT_COUNT_UNKNOWN = "argument_count_unknown"
    ARGUMENT_SOURCES_INCOMPLETE = "argument_sources_incomplete"
    ARGUMENT_WIDTHS_INCOMPLETE = "argument_widths_incomplete"
    CALL_ADDRESS_MISSING = "call_address_missing"
    DUPLICATE_CALL_ADDRESS = "duplicate_call_address"
    EXISTING_EFFECT_CONFLICT = "existing_effect_conflict"
    FRAME_KIND_UNKNOWN = "frame_kind_unknown"
    POINTER_ARGUMENT_MAY_ESCAPE = "pointer_argument_may_escape"
    RETURN_ADDRESS_UNKNOWN = "return_address_unknown"
    STACK_ALLOCATION_UNPROVEN = "stack_allocation_unproven"
    STACK_CLEANUP_MISMATCH = "stack_cleanup_mismatch"
    STACK_CLEANUP_UNKNOWN = "stack_cleanup_unknown"
    SUMMARY_MISSING = "summary_missing"
    TARGET_UNRESOLVED = "target_unresolved"


@dataclass(frozen=True, slots=True)
class CallStackEffectFact8616:
    """One exact CALL and its proven effect or conservative refusal."""

    block_addr: int
    instr_index: int
    callsite_addr: int | None
    target_addr: int | None
    verdict: CallStackEffectVerdict8616
    effect: IRCallStackEffect8616
    failure: CallStackEffectFailure8616 | None


@dataclass(frozen=True, slots=True)
class CallStackEffectStats8616:
    """Closed accounting for every CALL seen in one IR function."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def closed(self) -> bool:
        """Return whether every raw CALL has one durable typed outcome."""
        return (
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
        )

    @property
    def complete(self) -> bool:
        """Return whether all retained outcomes are positive proofs."""
        return self.closed and self.failure_count == 0

    def to_dict(self) -> dict[str, int]:
        """Return deterministic diagnostics for the closed evidence loop."""
        return {
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
        }


__all__ = [
    "CallStackEffectFact8616",
    "CallStackEffectFailure8616",
    "CallStackEffectStats8616",
    "CallStackEffectVerdict8616",
]
