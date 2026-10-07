"""Typed contracts for wide call-output assignment Lowering.

Layer: Types/Lowering.
Responsibility: own immutable facts, verdicts, refusals, and closed counters for
materializing call-result arithmetic after Alias and Widening prove it.
Consumes alias, widening, and typed facts; does not inspect or mutate C-AST nodes.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.core import IRCallOutputProvenance8616
from inertia.semantics.carry_borrow_contracts import CarryBorrowKind8616
from inertia.widening.carry_borrow_storage import WideCarryBorrowStorage8616


class WideCallOutputAssignmentVerdict8616(StrEnum):
    """Typed Types/Lowering result for one proven wide call-result store."""

    MATERIALIZED = "materialized"
    UNKNOWN_REFUSE = "unknown_refuse"


class WideCallOutputAssignmentFailure8616(StrEnum):
    """Stable reason a proven wide call result could not become one C assignment."""

    CALLSITE_AMBIGUOUS = "callsite_ambiguous"
    CALLSITE_MISSING = "callsite_missing"
    CARRIER_COVERAGE_MISSING = "carrier_coverage_missing"
    CARRIER_ORDER_MISMATCH = "carrier_order_mismatch"
    CARRIER_PLACEMENT_AMBIGUOUS = "carrier_placement_ambiguous"
    DESTINATION_CVARIABLE_MISSING = "destination_cvariable_missing"
    DESTINATION_LOWERING_MISSING = "destination_lowering_missing"
    INSTRUCTION_PROVENANCE_MISSING = "instruction_provenance_missing"
    MIXED_STATEMENT_OWNERSHIP = "mixed_statement_ownership"
    SOURCE_CVARIABLE_MISSING = "source_cvariable_missing"
    SOURCE_RANGE_MISMATCH = "source_range_mismatch"
    UNSUPPORTED_OPERATION = "unsupported_operation"


@dataclass(frozen=True, slots=True)
class WideCallOutputAssignmentFact8616:
    """Exact typed evidence needed to replace one split wide operation."""

    call_output: IRCallOutputProvenance8616
    kind: CarryBorrowKind8616
    source_offset: int
    destination_offset: int
    carrier_ins_addrs: tuple[int, ...]
    store_ins_addrs: tuple[int, int]


@dataclass(frozen=True, slots=True)
class WideCallOutputAssignmentResolution8616:
    """One materialized assignment or one conservative Types/Lowering refusal."""

    source: WideCarryBorrowStorage8616
    verdict: WideCallOutputAssignmentVerdict8616
    fact: WideCallOutputAssignmentFact8616 | None = None
    failure: WideCallOutputAssignmentFailure8616 | None = None
    placement_classified: bool = False
    changed: bool = False
    already_materialized: bool = False


@dataclass(frozen=True, slots=True)
class WideCallOutputAssignmentStats8616:
    """Closed evidence counters for wide call-output assignment Lowering."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    changed_count: int = 0
    already_materialized_count: int = 0

    @property
    def complete(self) -> bool:
        """Return whether every input closes without a lost classified placement."""
        return (
            self.raw_fact_count == self.materialized_count + self.failure_count
            and 0
            <= self.materialized_count
            <= self.classified_fact_count
            <= self.normalized_fact_count
            <= self.raw_fact_count
            and self.classified_fact_count == self.materialized_count
        )


@dataclass(frozen=True, slots=True)
class WideCallOutputAssignmentArtifact8616:
    """Function-level results for typed wide call-output assignment Lowering."""

    function_addr: int
    resolutions: tuple[WideCallOutputAssignmentResolution8616, ...]
    stats: WideCallOutputAssignmentStats8616

    @property
    def complete(self) -> bool:
        """Return whether outcome count and closed counters agree."""
        return self.stats.complete and len(self.resolutions) == self.stats.raw_fact_count


def refused_wide_call_output_assignment_8616(
    source: WideCarryBorrowStorage8616,
    failure: WideCallOutputAssignmentFailure8616,
    *,
    fact: WideCallOutputAssignmentFact8616 | None = None,
    placement_classified: bool = False,
) -> WideCallOutputAssignmentResolution8616:
    """Return one conservative Types/Lowering refusal."""
    return WideCallOutputAssignmentResolution8616(
        source=source,
        verdict=WideCallOutputAssignmentVerdict8616.UNKNOWN_REFUSE,
        fact=fact,
        failure=failure,
        placement_classified=placement_classified,
    )


__all__ = [
    "WideCallOutputAssignmentArtifact8616",
    "WideCallOutputAssignmentFact8616",
    "WideCallOutputAssignmentFailure8616",
    "WideCallOutputAssignmentResolution8616",
    "WideCallOutputAssignmentStats8616",
    "WideCallOutputAssignmentVerdict8616",
    "refused_wide_call_output_assignment_8616",
]
