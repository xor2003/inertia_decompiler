"""Plan positive-BP arguments without mutating the generated C interface.

Layer: Types/Lowering.
Responsibility: join a body-proven positive-BP argument prefix with one closed
caller-width census before codegen variables or prototypes are changed.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass, field, replace
from enum import StrEnum
from itertools import accumulate

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_type import SimType

from ..callsite_summary import CallsiteSummary8616
from .callee_argument_width_evidence import CalleeArgumentWidthEvidence8616

_FIRST_ARGUMENT_OFFSET = 4
_WORD_BYTES = 2
_WIDE_BYTES = 4


class PositiveBpArgumentPlanDecision8616(StrEnum):
    """Typed outcome of joining body storage with incoming argument storage."""

    BODY_ONLY = "body_only"
    BODY_CALLER_PHYSICAL = "body_caller_physical"
    CALLER_COMPLETE = "caller_complete"
    REFUSE = "refuse"


@dataclass(frozen=True, slots=True)
class PositiveBpArgumentPlanEntry8616:
    """One proposed argument slot and its optional existing C variable."""

    bp_offset: int
    width: int
    name: str
    argument_type: SimType
    cvar: CVariable | None = field(default=None, compare=False)


@dataclass(frozen=True, slots=True)
class PositiveBpArgumentPlan8616:
    """Mutation-free positive-BP interface decision with retained evidence."""

    decision: PositiveBpArgumentPlanDecision8616
    entries: tuple[PositiveBpArgumentPlanEntry8616, ...]
    evidence: CalleeArgumentWidthEvidence8616 = field(compare=False)


def complete_positive_bp_body_word_access_plan_8616(
    body_entries: tuple[PositiveBpArgumentPlanEntry8616, ...],
    word_access_offsets: Collection[int],
    *,
    default_argument_type: SimType,
    wide_access_offsets: Collection[int] = (),
) -> tuple[PositiveBpArgumentPlanEntry8616, ...]:
    """Complete one contiguous body plan from decoded word and wide accesses.

    Existing typed entries remain authoritative. A missing slot is synthesized
    only when the binary contains an exact word access at the current ABI
    cursor; widening-proven adjacent words become one four-byte owner. The first
    gap ends recovery.
    """
    entries_by_offset = {entry.bp_offset: entry for entry in body_entries}
    accesses = frozenset(offset for offset in word_access_offsets if offset >= _FIRST_ARGUMENT_OFFSET)
    wide_accesses = frozenset(
        offset for offset in wide_access_offsets if offset >= _FIRST_ARGUMENT_OFFSET
    )
    completed: list[PositiveBpArgumentPlanEntry8616] = []
    cursor = _FIRST_ARGUMENT_OFFSET
    while (
        cursor in entries_by_offset
        or cursor in accesses
        or cursor in wide_accesses
    ):
        entry = entries_by_offset.get(cursor)
        if entry is None:
            entry = PositiveBpArgumentPlanEntry8616(
                bp_offset=cursor,
                width=_WIDE_BYTES if cursor in wide_accesses else _WORD_BYTES,
                name=f"arg_{cursor:x}",
                argument_type=default_argument_type,
            )
        elif cursor in wide_accesses:
            if entry.width not in {_WORD_BYTES, _WIDE_BYTES}:
                break
            entry = replace(entry, width=_WIDE_BYTES)
        if entry.width < _WORD_BYTES or entry.width % _WORD_BYTES:
            break
        completed.append(entry)
        cursor += entry.width
    return tuple(completed)


def _physical_call_covers_body_8616(widths: tuple[int, ...], summary: CallsiteSummary8616) -> bool:
    """Check physical coverage without inventing or splitting logical operands."""
    physical = tuple(reversed(summary.arg_widths))
    if not physical or summary.arg_count != len(physical):
        return False
    if any(width <= 0 for width in (*widths, *physical)):
        return False
    if summary.logical_arg_widths and summary.logical_arg_widths != widths:
        return False
    # PUSH order is opposite to BP argument order. A body-proven wide operand
    # may consume several complete pushes, never part of a caller-owned slot.
    return sum(widths) == sum(physical) and set(accumulate(widths)) <= set(accumulate(physical))


def _body_layout_matches_all_physical_calls_8616(
    body_entries: tuple[PositiveBpArgumentPlanEntry8616, ...],
    evidence: CalleeArgumentWidthEvidence8616,
) -> bool:
    """Accept an unknown logical grouping only when every footprint matches."""
    count_evidence = evidence.count_evidence
    if count_evidence is None or count_evidence.raw_fact_count <= 0:
        return False
    summaries = count_evidence.callsite_summaries
    if len(summaries) != count_evidence.raw_fact_count:
        return False
    widths = tuple(entry.width for entry in body_entries)
    return all(_physical_call_covers_body_8616(widths, summary) for summary in summaries)


def complete_positive_bp_argument_plan_8616(
    body_entries: tuple[PositiveBpArgumentPlanEntry8616, ...],
    evidence: CalleeArgumentWidthEvidence8616,
    *,
    default_argument_type: SimType,
) -> PositiveBpArgumentPlan8616:
    """Complete an exact body prefix from a closed caller-width census.

    No caller facts leaves body-owned recovery unchanged. Once caller facts
    exist, an incomplete or width-inconsistent census refuses the whole plan.
    Unused trailing arguments are materialized only from the exact remaining
    slots in a closed logical-width layout.
    """
    if not body_entries or evidence.raw_fact_count == 0:
        return PositiveBpArgumentPlan8616(
            PositiveBpArgumentPlanDecision8616.BODY_ONLY,
            body_entries,
            evidence,
        )
    if not evidence.closes_census:
        decision = (
            PositiveBpArgumentPlanDecision8616.BODY_CALLER_PHYSICAL
            if _body_layout_matches_all_physical_calls_8616(body_entries, evidence)
            else PositiveBpArgumentPlanDecision8616.REFUSE
        )
        return PositiveBpArgumentPlan8616(
            decision,
            body_entries,
            evidence,
        )

    evidence_layout = evidence.widths_by_offset
    body_layout = tuple((entry.bp_offset, entry.width) for entry in body_entries)
    if len(body_layout) > len(evidence_layout) or body_layout != evidence_layout[: len(body_layout)]:
        return PositiveBpArgumentPlan8616(
            PositiveBpArgumentPlanDecision8616.REFUSE,
            body_entries,
            evidence,
        )

    completed = list(body_entries)
    completed.extend(
        PositiveBpArgumentPlanEntry8616(
            bp_offset=offset,
            width=width,
            name=f"arg_{offset:x}",
            argument_type=default_argument_type,
        )
        for offset, width in evidence_layout[len(body_layout) :]
    )
    return PositiveBpArgumentPlan8616(
        PositiveBpArgumentPlanDecision8616.CALLER_COMPLETE,
        tuple(completed),
        evidence,
    )


__all__ = [
    "PositiveBpArgumentPlan8616",
    "PositiveBpArgumentPlanDecision8616",
    "PositiveBpArgumentPlanEntry8616",
    "complete_positive_bp_argument_plan_8616",
    "complete_positive_bp_body_word_access_plan_8616",
]
