"""Typed Alias contracts for carry-linked split arithmetic.

Layer: Alias.
Responsibility: own immutable register, segmented-memory, and constant carrier
identities plus closed projection accounting. This module does not discover
Semantics links, widen values, lower types, or inspect rendered text.
Owns storage identity and exact Alias projection outcomes.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.core import IRCallOutputProvenance8616, IRValue
from inertia.semantics.carry_borrow_contracts import (
    CarryBorrowLink8616,
    CarryBorrowOperandUse8616,
    CarryBorrowResolution8616,
)

from .domains import DomainKey
from .storage_fact_join import SegmentedAliasRange8616


class CarryBorrowAliasVerdict8616(StrEnum):
    """Stable Alias outcome for one Semantics carry/borrow resolution."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


class CarryBorrowAliasFailure8616(StrEnum):
    """Stable reason a semantic link lacks exact Alias carrier proof."""

    CARRIER_ALIAS_MISMATCH = "carrier_alias_mismatch"
    CALL_OUTPUT_CONFLICT = "call_output_conflict"
    CALL_OUTPUT_DEFINITION_AMBIGUOUS = "call_output_definition_ambiguous"
    CALL_OUTPUT_DEFINITION_MISSING = "call_output_definition_missing"
    CALL_OUTPUT_ORDER_MISMATCH = "call_output_order_mismatch"
    CALL_OUTPUT_PARTIAL = "call_output_partial"
    CALL_OUTPUT_SHAPE_MISMATCH = "call_output_shape_mismatch"
    CALL_OUTPUT_SSA_MISSING = "call_output_ssa_missing"
    FUNCTION_SSA_MISMATCH = "function_ssa_mismatch"
    RESULT_CARRIER_MISMATCH = "result_carrier_mismatch"
    SEGMENT_MISMATCH = "segment_mismatch"
    SEMANTICS_INCOMPLETE = "semantics_incomplete"
    SEMANTICS_REFUSED = "semantics_refused"
    SOURCE_ALIAS_UNPROVEN = "source_alias_unproven"
    SOURCE_CARRIER_MISMATCH = "source_carrier_mismatch"
    SOURCE_DEFINITION_MISMATCH = "source_definition_mismatch"
    SOURCE_RANGE_MISMATCH = "source_range_mismatch"
    SOURCE_RANGE_WRAP_UNSUPPORTED = "source_range_wrap_unsupported"
    WIDTH_MISMATCH = "width_mismatch"


class CarryBorrowOperandRole8616(StrEnum):
    """Stable role of one operand in a split carry/borrow operation."""

    LOW_LHS = "low_lhs"
    LOW_RHS = "low_rhs"
    HIGH_LHS = "high_lhs"
    HIGH_RHS = "high_rhs"


@dataclass(frozen=True, slots=True)
class CarryBorrowOperandAlias8616:
    """Exact Alias or immutable constant identity for one semantic operand."""

    use: CarryBorrowOperandUse8616
    source: IRValue
    register_domain: DomainKey | None = None
    memory: SegmentedAliasRange8616 | None = None
    constant: IRValue | None = None

    @property
    def complete(self) -> bool:
        """Return whether exactly one supported carrier identity is present."""
        return sum(
            item is not None
            for item in (self.register_domain, self.memory, self.constant)
        ) == 1


@dataclass(frozen=True, slots=True)
class CarryBorrowCallOutputAlias8616:
    """Exact low/high register definitions produced by one machine call."""

    provenance: IRCallOutputProvenance8616
    low_output: IRValue
    high_output: IRValue


@dataclass(frozen=True, slots=True)
class CarryBorrowAliasFact8616:
    """Alias-proven result and operand identities for one carry-linked value."""

    link: CarryBorrowLink8616
    low_result_domain: DomainKey
    high_result_domain: DomainKey
    low_lhs: CarryBorrowOperandAlias8616
    low_rhs: CarryBorrowOperandAlias8616
    high_lhs: CarryBorrowOperandAlias8616
    high_rhs: CarryBorrowOperandAlias8616
    lhs_call_output: CarryBorrowCallOutputAlias8616 | None = None
    source_memory: SegmentedAliasRange8616 | None = None
    source_constant: int | None = None


@dataclass(frozen=True, slots=True)
class CarryBorrowAliasResolution8616:
    """Alias fact or typed refusal corresponding to one Semantics outcome."""

    semantics: CarryBorrowResolution8616 | None
    verdict: CarryBorrowAliasVerdict8616
    fact: CarryBorrowAliasFact8616 | None = None
    failure: CarryBorrowAliasFailure8616 | None = None
    failure_operand: CarryBorrowOperandRole8616 | None = None


@dataclass(frozen=True, slots=True)
class CarryBorrowAliasStats8616:
    """Closed accounting for carry/borrow Alias projection."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every Semantics outcome has one Alias result."""
        return (
            self.raw_fact_count == self.normalized_fact_count
            and self.raw_fact_count == self.materialized_count + self.failure_count
            and self.classified_fact_count == self.materialized_count
        )


@dataclass(frozen=True, slots=True)
class CarryBorrowAliasEvidence8616:
    """Function-level Alias facts and refusals for carry-linked values."""

    function_addr: int
    resolutions: tuple[CarryBorrowAliasResolution8616, ...]
    stats: CarryBorrowAliasStats8616

    @property
    def facts(self) -> tuple[CarryBorrowAliasFact8616, ...]:
        """Return every proven Alias fact in deterministic order."""
        return tuple(item.fact for item in self.resolutions if item.fact is not None)

    @property
    def complete(self) -> bool:
        """Return whether projection count and evidence accounting are closed."""
        return self.stats.complete and len(self.resolutions) == self.stats.raw_fact_count


__all__ = [
    "CarryBorrowAliasEvidence8616",
    "CarryBorrowAliasFact8616",
    "CarryBorrowAliasFailure8616",
    "CarryBorrowAliasResolution8616",
    "CarryBorrowAliasStats8616",
    "CarryBorrowAliasVerdict8616",
    "CarryBorrowCallOutputAlias8616",
    "CarryBorrowOperandAlias8616",
    "CarryBorrowOperandRole8616",
]
