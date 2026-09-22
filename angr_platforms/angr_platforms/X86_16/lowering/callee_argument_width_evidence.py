"""Aggregate exact incoming call widths for one callee interface.

Layer: Types/Lowering.
Responsibility: project complete binary caller PUSH summaries onto positive-BP
callee argument offsets and publish one closed width verdict.
Consumes alias, widening, and typed facts from complete callsite summaries.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from ..callsite_summary import CallsiteSummary8616, logical_argument_widths_from_callsite_8616
from ..ir import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from .argument_frame_base import proven_first_argument_machine_bp_offset_at_8616
from .callee_argument_count_evidence import (
    CalleeArgumentCountEvidence8616,
    collect_callee_argument_count_evidence_8616,
)

__all__ = [
    "CalleeArgumentWidthEvidence8616",
    "CalleeArgumentWidthVerdict8616",
    "collect_callee_argument_width_evidence_8616",
]


class CalleeArgumentWidthVerdict8616(StrEnum):
    """Typed outcome of joining incoming logical argument widths."""

    UNKNOWN = "unknown"
    CONSISTENT = "consistent"
    CONFLICT = "conflict"


@dataclass(frozen=True, slots=True)
class CalleeArgumentWidthEvidence8616:
    """Closed incoming-width evidence mapped to architectural BP offsets."""

    target_addr: int
    verdict: CalleeArgumentWidthVerdict8616
    widths_by_offset: tuple[tuple[int, int], ...] = ()
    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    argument_count: int | None = None
    argument_storage: tuple[IRAddress, ...] = ()
    count_evidence: CalleeArgumentCountEvidence8616 | None = field(
        default=None,
        compare=False,
    )

    @property
    def closes_census(self) -> bool:
        """Return whether all callers prove one exact callee stack layout."""
        count_evidence = self.count_evidence
        if (
            self.verdict is not CalleeArgumentWidthVerdict8616.CONSISTENT
            or count_evidence is None
            or not count_evidence.closes_census
            or self.argument_count != count_evidence.argument_count
            or self.raw_fact_count <= 0
            or not self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            or self.failure_count != 0
        ):
            return False
        return len(self.argument_storage) == self.argument_count

    @property
    def argument_widths(self) -> tuple[int, ...]:
        """Return source-order widths from the accepted stack identities."""
        if not self.closes_census:
            return ()
        return tuple(address.size for address in self.argument_storage)

    @property
    def required_count_evidence(self) -> CalleeArgumentCountEvidence8616:
        """Return the retained arity census or fail an invalid owned contract."""
        if self.count_evidence is None:
            raise TypeError("callee argument storage evidence must retain count evidence")
        return self.count_evidence


def _widths_by_offset_8616(
    widths: tuple[int, ...],
    first_argument_bp_offset: int = 4,
) -> tuple[tuple[int, int], ...]:
    """Map source-order argument widths onto the callee's BP argument storage."""
    offset = first_argument_bp_offset
    mapped: list[tuple[int, int]] = []
    for width in widths:
        mapped.append((offset, width))
        offset += width
    return tuple(mapped)


def _argument_storage_8616(
    widths_by_offset: tuple[tuple[int, int], ...],
) -> tuple[IRAddress, ...]:
    """Build exact callee `SS:BP+offset` identities for source arguments."""
    return tuple(
        IRAddress(
            space=MemSpace.SS,
            base=("bp",),
            offset=offset,
            size=width,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.DEFAULTED,
        )
        for offset, width in widths_by_offset
    )


def _logical_widths_for_proven_count_8616(
    summary: CallsiteSummary8616,
    argument_count: int,
) -> tuple[int, ...] | None:
    """Project widths after arity proof without requiring value provenance."""
    explicit_widths: tuple[int, ...] = summary.logical_arg_widths
    physical_widths: tuple[int, ...] = summary.arg_widths
    if explicit_widths:
        if (
            len(explicit_widths) != argument_count
            or any(width <= 0 for width in explicit_widths)
            or any(width <= 0 for width in physical_widths)
            or sum(explicit_widths) != sum(physical_widths)
            or summary.stack_cleanup != sum(explicit_widths)
        ):
            return None
        return explicit_widths
    widths: tuple[int, ...] | None = logical_argument_widths_from_callsite_8616(
        summary,
        expected_arg_count=argument_count,
    )
    if widths is not None:
        return widths
    if (
        len(physical_widths) != argument_count
        or summary.stack_cleanup != sum(physical_widths)
        or any(not isinstance(width, int) or width <= 0 for width in physical_widths)
    ):
        return None
    return tuple(reversed(physical_widths))


def collect_callee_argument_width_evidence_8616(
    project: object,
    target_addr: int,
) -> CalleeArgumentWidthEvidence8616:
    """Join exact logical widths from every completely classified caller."""
    count_evidence = collect_callee_argument_count_evidence_8616(project, target_addr)
    summaries = count_evidence.callsite_summaries
    raw_count = count_evidence.raw_fact_count
    if count_evidence.closes_census and count_evidence.argument_count == 0:
        return CalleeArgumentWidthEvidence8616(
            target_addr=target_addr,
            verdict=CalleeArgumentWidthVerdict8616.CONSISTENT,
            raw_fact_count=raw_count,
            normalized_fact_count=raw_count,
            classified_fact_count=raw_count,
            materialized_count=raw_count,
            argument_count=0,
            count_evidence=count_evidence,
        )
    if (
        not count_evidence.closes_census
        or not isinstance(count_evidence.argument_count, int)
        or count_evidence.argument_count <= 0
    ):
        return CalleeArgumentWidthEvidence8616(
            target_addr=target_addr,
            verdict=CalleeArgumentWidthVerdict8616.UNKNOWN,
            raw_fact_count=raw_count,
            failure_count=raw_count,
            count_evidence=count_evidence,
        )
    classified_widths = tuple(
        widths
        for summary in summaries
        if (
            widths := _logical_widths_for_proven_count_8616(
                summary,
                count_evidence.argument_count,
            )
        )
        is not None
    )
    distinct_widths = set(classified_widths)
    failure_count = raw_count - len(classified_widths)
    if len(distinct_widths) == 1 and failure_count == 0:
        widths = next(iter(distinct_widths))
        verdict = CalleeArgumentWidthVerdict8616.CONSISTENT
        mapped_widths = _widths_by_offset_8616(
            widths,
            proven_first_argument_machine_bp_offset_at_8616(project, target_addr),
        )
        argument_storage = _argument_storage_8616(mapped_widths)
        materialized_count = len(classified_widths)
    elif len(distinct_widths) > 1:
        verdict = CalleeArgumentWidthVerdict8616.CONFLICT
        mapped_widths = ()
        argument_storage = ()
        materialized_count = 0
        failure_count += 1
    else:
        verdict = CalleeArgumentWidthVerdict8616.UNKNOWN
        mapped_widths = ()
        argument_storage = ()
        materialized_count = 0
    return CalleeArgumentWidthEvidence8616(
        target_addr=target_addr,
        verdict=verdict,
        widths_by_offset=mapped_widths,
        raw_fact_count=raw_count,
        normalized_fact_count=len(classified_widths),
        classified_fact_count=len(classified_widths),
        materialized_count=materialized_count,
        failure_count=failure_count,
        argument_count=count_evidence.argument_count,
        argument_storage=argument_storage,
        count_evidence=count_evidence,
    )
