"""Typed outcomes for carry/borrow bit-value Lowering.

Layer: Types/Lowering.
Responsibility: own closed accounting and exact instruction ownership.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.semantics.carry_borrow_contracts import CarryBorrowKind8616
from inertia.widening.carry_borrow_values import WideCarryBorrowValue8616


class CarryBorrowBitLoweringVerdict8616(StrEnum):
    """Closed outcome for one proven wide carry/borrow value."""

    MATERIALIZED = "materialized"
    UNKNOWN_REFUSE = "unknown_refuse"


class CarryBorrowBitLoweringFailure8616(StrEnum):
    """Typed reasons why Lowering kept the original numeric FLAGS carrier."""

    PROVENANCE_MISSING = "provenance_missing"
    UNSUPPORTED_OPERATION = "unsupported_operation"
    CARRY_USE_MISSING = "carry_use_missing"
    CARRY_USE_AMBIGUOUS = "carry_use_ambiguous"
    CARRY_VARIABLE_IDENTITY_MISSING = "carry_variable_identity_missing"
    CARRIER_ASSIGNMENT_MISSING = "carrier_assignment_missing"
    CARRIER_ASSIGNMENT_AMBIGUOUS = "carrier_assignment_ambiguous"
    EXECUTION_OWNER_MISSING = "execution_owner_missing"
    EXECUTION_OWNER_AMBIGUOUS = "execution_owner_ambiguous"
    EXECUTION_ORDER_CONFLICT = "execution_order_conflict"
    CARRY_PREDICATE_MISSING = "carry_predicate_missing"
    CARRY_PREDICATE_AMBIGUOUS = "carry_predicate_ambiguous"
    CARRY_PREDICATE_MISMATCH = "carry_predicate_mismatch"
    REPLACEMENT_FAILED = "replacement_failed"


@dataclass(frozen=True)
class CarryBorrowBitLoweringFact8616:
    """Exact low/high block and instruction identity consumed by Lowering."""

    function_addr: int
    kind: CarryBorrowKind8616
    low_block_addr: int
    low_ins_addr: int
    high_block_addr: int
    high_ins_addr: int


@dataclass(frozen=True)
class CarryBorrowBitLoweringResolution8616:
    """Materialized predicate or typed refusal for one Widening value."""

    source: WideCarryBorrowValue8616
    verdict: CarryBorrowBitLoweringVerdict8616
    fact: CarryBorrowBitLoweringFact8616 | None = None
    failure: CarryBorrowBitLoweringFailure8616 | None = None
    placement_classified: bool = False
    changed: bool = False
    already_materialized: bool = False

    @property
    def failure_diagnostic(self) -> str:
        """Render one refusal from typed fields for deterministic diagnostics."""
        failure = self.failure.value if self.failure is not None else "none"
        if self.fact is None:
            return f"{failure}:fact=unavailable"
        return (
            f"{failure}:function={self.fact.function_addr:#x}:kind={self.fact.kind.value}:"
            f"low={self.fact.low_block_addr:#x}:{self.fact.low_ins_addr:#x}:"
            f"high={self.fact.high_block_addr:#x}:{self.fact.high_ins_addr:#x}"
        )


@dataclass(frozen=True)
class CarryBorrowBitLoweringStats8616:
    """Closed evidence counters for carry/borrow bit-value Lowering."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    changed_count: int
    already_materialized_count: int

    @property
    def complete(self) -> bool:
        """Return whether every raw Widening value has one closed outcome."""
        return (
            self.raw_fact_count == self.materialized_count + self.failure_count
            and 0 <= self.normalized_fact_count <= self.raw_fact_count
            and 0 <= self.classified_fact_count <= self.normalized_fact_count
            and 0 <= self.changed_count <= self.materialized_count
            and 0 <= self.already_materialized_count <= self.materialized_count
        )


@dataclass(frozen=True)
class CarryBorrowBitLoweringArtifact8616:
    """Function-level materialization results attached to the codegen boundary."""

    function_addr: int
    resolutions: tuple[CarryBorrowBitLoweringResolution8616, ...]
    stats: CarryBorrowBitLoweringStats8616

    @property
    def complete(self) -> bool:
        """Return whether resolutions and closed counters agree."""
        return self.stats.complete and len(self.resolutions) == self.stats.raw_fact_count


def refused_carry_borrow_bit_lowering_8616(
    source: WideCarryBorrowValue8616,
    failure: CarryBorrowBitLoweringFailure8616,
    *,
    fact: CarryBorrowBitLoweringFact8616 | None = None,
    placement_classified: bool = False,
) -> CarryBorrowBitLoweringResolution8616:
    """Create one explicit UNKNOWN_REFUSE outcome without mutating C."""
    return CarryBorrowBitLoweringResolution8616(
        source=source,
        verdict=CarryBorrowBitLoweringVerdict8616.UNKNOWN_REFUSE,
        fact=fact,
        failure=failure,
        placement_classified=placement_classified,
    )


__all__ = [
    "CarryBorrowBitLoweringArtifact8616",
    "CarryBorrowBitLoweringFact8616",
    "CarryBorrowBitLoweringFailure8616",
    "CarryBorrowBitLoweringResolution8616",
    "CarryBorrowBitLoweringStats8616",
    "CarryBorrowBitLoweringVerdict8616",
    "refused_carry_borrow_bit_lowering_8616",
]
