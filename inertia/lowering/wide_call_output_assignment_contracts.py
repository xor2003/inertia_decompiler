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

from inertia.ir.core import IRCallOutputProvenance8616, MemSpace
from inertia.semantics.carry_borrow_contracts import CarryBorrowKind8616
from inertia.widening.carry_borrow_storage import WideCarryBorrowStorage8616
from inertia.widening.pair_type_contracts import (
    WidePairEvidence8616,
    wide_pair_value_consistent_8616,
)


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
    PAIR_LEGALITY_UNPROVEN = "pair_legality_unproven"
    SOURCE_CVARIABLE_MISSING = "source_cvariable_missing"
    SOURCE_RANGE_MISMATCH = "source_range_mismatch"
    UNSUPPORTED_OPERATION = "unsupported_operation"


@dataclass(frozen=True, slots=True)
class WideCallOutputAssignmentFact8616:
    """Exact typed evidence needed to replace one split wide operation.

    ``pair`` is the retained named-pair legality evidence that authorized
    this fact; materialization and replay consume it for validity and
    layout. ``None`` appears only on identity-key constructions, never on a
    fact the normalizer published for materialization.
    """

    call_output: IRCallOutputProvenance8616
    kind: CarryBorrowKind8616
    source_offset: int
    destination_offset: int
    carrier_ins_addrs: tuple[int, ...]
    store_ins_addrs: tuple[int, int]
    pair: WidePairEvidence8616 | None = None


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


def wide_call_output_pair_authenticated_8616(
    source: object,
    fact: WideCallOutputAssignmentFact8616,
) -> bool:
    """Return whether retained source, value, and pair prove this fact.

    The fact's retained pair must be combine-authorized, identical to the
    storage's value pair, consistent with the still-live wide value, and
    cover the exact source and destination layout in retained half order.
    The fact's declared operation must be the proven value kind (which the
    retained pair already binds to itself). Source versions, the SS:BP source
    range, and the SS:BP destination scope are re-bound here so a source or
    fact mutated after normalization cannot inherit the earlier proof.
    Callsite identity is deliberately excluded here; each consumer binds it
    to its own provenance tolerance.
    """
    if not isinstance(source, WideCarryBorrowStorage8616):
        return False
    pair = fact.pair
    if not isinstance(pair, WidePairEvidence8616):
        return False
    if not pair.combine_authorized or pair != source.pair:
        return False
    if fact.kind is not source.value.kind:
        return False
    if wide_pair_value_consistent_8616(source.value) is not None:
        return False
    low_store = source.destination.low_store
    high_store = source.destination.high_store
    source_memory = source.value.source_memory
    low_address = low_store.address
    high_address = high_store.address
    return (
        source.value.lhs_call_output is not None
        and source_memory is not None
        and source_memory.space is MemSpace.SS
        and all(address.base == ("bp",) for address in source_memory.addresses)
        and source_memory.size == pair.type.total_size
        and fact.source_offset == source_memory.offset
        and source.source_versions == low_store.versions + high_store.versions
        and fact.destination_offset == source.address.offset
        and source.address.space is MemSpace.SS
        and source.address.base == ("bp",)
        and source.address.size == pair.type.total_size
        and source.address.offset == low_address.offset
        and low_address.space is MemSpace.SS
        and high_address.space is MemSpace.SS
        and low_address.base == ("bp",)
        and high_address.base == ("bp",)
        and low_address.size == pair.low.size
        and high_address.size == pair.high.size
        and high_address.offset == low_address.offset + low_address.size
    )


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
    "wide_call_output_pair_authenticated_8616",
]
