"""Layer: Types/Lowering.

Responsibility: reconcile proven logical C argument widths with physical PUSH facts.
Forbidden: infer call interfaces from rendered C, helper names, or unproven AST shape.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import cast

from ..callsite_summary import (
    CallsiteArgumentClass8616,
    CallsitePushSourceKind8616,
    CallsiteSummary8616,
)
from .call_argument_arity_ownership import (
    CallsiteZeroArgumentDecision8616,
    CallsiteZeroArgumentOwnership8616,
    classify_callsite_zero_argument_ownership_8616,
)
from .call_argument_state import ProtectedCallArgument8616, ProtectedCallArgumentStore8616

__all__ = [
    "CallerStackObject8616",
    "CallsiteArgumentShapeDecision8616",
    "CallsiteArgumentShapeReconciliation8616",
    "CallsiteZeroArgumentDecision8616",
    "CallsiteZeroArgumentOwnership8616",
    "LogicalArgumentShapeEvidence8616",
    "LogicalArgumentShapeEvidenceSource8616",
    "ProtectedCallArgument8616",
    "ProtectedCallArgumentStore8616",
    "accounted_target_prototype_shape_evidence_8616",
    "accounted_variadic_target_shape_evidence_8616",
    "carry_forward_logical_call_argument_shape_8616",
    "classify_callsite_zero_argument_ownership_8616",
    "exact_call_return_pair_shape_evidence_8616",
    "exact_caller_stack_object_for_word_pair_8616",
    "exact_caller_stack_object_shape_evidence_8616",
    "reconcile_materialized_call_argument_shape_8616",
]


class LogicalArgumentShapeEvidenceSource8616(StrEnum):
    """Typed provenance for a logical argument-width grouping."""

    EXACT_CALLEE_ABI = "exact-callee-abi"
    ACCOUNTED_TARGET_PROTOTYPE = "accounted-target-prototype"
    ACCOUNTED_VARIADIC_TARGET_PROTOTYPE = "accounted-variadic-target-prototype"
    EXACT_CALLER_STACK_OBJECT = "exact-caller-stack-object"
    EXACT_CALL_RETURN_PAIR = "exact-call-return-pair"


@dataclass(frozen=True, slots=True)
class CallerStackObject8616:
    """Exact BP-relative caller object available to one outgoing call."""

    offset: int
    width: int


@dataclass(frozen=True, slots=True)
class LogicalArgumentShapeEvidence8616:
    """A logical argument grouping proven before C-AST reconciliation."""

    widths: tuple[int, ...]
    source: LogicalArgumentShapeEvidenceSource8616
    return_argument_indices: tuple[int, ...] = ()


class CallsiteArgumentShapeDecision8616(StrEnum):
    """Typed outcome for physical and logical call-width reconciliation."""

    PRESERVED_COMPLETE_BINARY = "preserved-complete-binary"
    PRESERVED_UNPROVEN_LIVE_SHAPE = "preserved-unproven-live-shape"
    MATERIALIZED_LOGICAL_FAR_POINTER = "materialized-logical-far-pointer"
    MATERIALIZED_PROVEN_LOGICAL_SHAPE = "materialized-proven-logical-shape"
    MATERIALIZED_LIVE_SHAPE = "materialized-live-shape"
    INVALID_LIVE_SHAPE = "invalid-live-shape"
    INVALID_LOGICAL_EVIDENCE = "invalid-logical-evidence"


@dataclass(frozen=True, slots=True)
class CallsiteArgumentShapeReconciliation8616:
    """Closed evidence result for one materialized call argument shape."""

    summary: CallsiteSummary8616
    decision: CallsiteArgumentShapeDecision8616
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


def _valid_widths_8616(widths: tuple[int, ...]) -> bool:
    """Return whether every supplied width is a positive integer."""
    return all(isinstance(width, int) and not isinstance(width, bool) and width > 0 for width in widths)


def _identical_physical_summary_8616(
    fresh_summary: CallsiteSummary8616,
    previous_summary: CallsiteSummary8616,
) -> bool:
    """Return whether the rebuild reproduced the exact physical summary."""
    if (
        fresh_summary.callsite_addr != previous_summary.callsite_addr
        or fresh_summary.target_addr != previous_summary.target_addr
        or fresh_summary.return_addr != previous_summary.return_addr
        or fresh_summary.kind != previous_summary.kind
        or fresh_summary.arg_count != previous_summary.arg_count
    ):
        return False
    return (
        fresh_summary.arg_widths == previous_summary.arg_widths
        and fresh_summary.stack_cleanup == previous_summary.stack_cleanup
        and fresh_summary.push_arg_sources == previous_summary.push_arg_sources
        and fresh_summary.push_arg_instruction_addrs
        == previous_summary.push_arg_instruction_addrs
        and fresh_summary.stack_cleanup_instruction_addr
        == previous_summary.stack_cleanup_instruction_addr
    )


def carry_forward_logical_call_argument_shape_8616(
    fresh_summary: CallsiteSummary8616,
    previous_summary: CallsiteSummary8616,
) -> CallsiteSummary8616:
    """Carry a proven logical projection across an identical physical summary rebuild."""
    logical_widths = previous_summary.logical_arg_widths
    if fresh_summary.logical_arg_widths or not _valid_widths_8616(logical_widths):
        return fresh_summary
    if not _identical_physical_summary_8616(fresh_summary, previous_summary):
        return fresh_summary

    physical_widths = fresh_summary.arg_widths
    if not _valid_widths_8616(physical_widths):
        return fresh_summary
    physical_total = sum(physical_widths)
    cleanup = fresh_summary.stack_cleanup
    complete_physical_shape = (
        isinstance(cleanup, int) and cleanup > 0 and cleanup == physical_total
    ) or (
        len(fresh_summary.push_arg_sources) == len(physical_widths)
        and bool(fresh_summary.push_arg_sources)
        and all(source is not None for source in fresh_summary.push_arg_sources)
    )
    if not complete_physical_shape or sum(logical_widths) != physical_total:
        return fresh_summary

    logical_classes = previous_summary.logical_arg_classes
    if len(logical_classes) != len(logical_widths):
        logical_classes = ()
    return replace(
        fresh_summary,
        logical_arg_widths=logical_widths,
        logical_arg_classes=logical_classes,
    )


def accounted_target_prototype_shape_evidence_8616(
    summary: CallsiteSummary8616,
    live_widths: tuple[int, ...],
    prototype_widths: tuple[int, ...] | None,
) -> LogicalArgumentShapeEvidence8616 | None:
    """Prove a grouped live shape from complete PUSH facts and its target prototype."""
    if prototype_widths is None or not _valid_widths_8616(live_widths):
        return None
    if not _valid_widths_8616(prototype_widths) or prototype_widths != live_widths:
        return None

    physical_widths = summary.arg_widths
    if not _valid_widths_8616(physical_widths) or len(prototype_widths) >= len(physical_widths):
        return None
    physical_total = sum(physical_widths)
    if sum(prototype_widths) != physical_total:
        return None

    cleanup = summary.stack_cleanup
    cleanup_accounts_for_shape = isinstance(cleanup, int) and cleanup > 0 and cleanup == physical_total
    push_sources = summary.push_arg_sources
    sources_account_for_shape = (
        len(push_sources) == len(physical_widths)
        and bool(push_sources)
        and all(source is not None for source in push_sources)
    )
    if not cleanup_accounts_for_shape and not sources_account_for_shape:
        return None
    return LogicalArgumentShapeEvidence8616(
        widths=prototype_widths,
        source=LogicalArgumentShapeEvidenceSource8616.ACCOUNTED_TARGET_PROTOTYPE,
    )


def accounted_variadic_target_shape_evidence_8616(
    summary: CallsiteSummary8616,
    live_widths: tuple[int, ...],
    fixed_prototype_widths: tuple[int, ...],
) -> LogicalArgumentShapeEvidence8616 | None:
    """Prove a variadic live shape from its fixed prefix and complete PUSH extent."""
    if not _valid_widths_8616(live_widths) or not _valid_widths_8616(fixed_prototype_widths):
        return None
    if len(live_widths) < len(fixed_prototype_widths):
        return None
    if live_widths[: len(fixed_prototype_widths)] != fixed_prototype_widths:
        return None
    physical_widths = summary.arg_widths
    if not _valid_widths_8616(physical_widths) or len(live_widths) >= len(physical_widths):
        return None
    physical_total = sum(physical_widths)
    if sum(live_widths) != physical_total:
        return None
    cleanup = summary.stack_cleanup
    cleanup_accounts_for_shape = isinstance(cleanup, int) and cleanup > 0 and cleanup == physical_total
    push_sources = summary.push_arg_sources
    sources_account_for_shape = (
        len(push_sources) == len(physical_widths)
        and bool(push_sources)
        and all(source is not None for source in push_sources)
    )
    if not cleanup_accounts_for_shape and not sources_account_for_shape:
        return None
    return LogicalArgumentShapeEvidence8616(
        widths=live_widths,
        source=LogicalArgumentShapeEvidenceSource8616.ACCOUNTED_VARIADIC_TARGET_PROTOTYPE,
    )


def exact_call_return_pair_shape_evidence_8616(
    summary: CallsiteSummary8616,
) -> LogicalArgumentShapeEvidence8616 | None:
    """Project exact same-callsite DX:AX PUSH pairs into logical arguments."""
    physical_widths = summary.arg_widths
    sources = summary.push_arg_sources
    if (
        not _valid_widths_8616(physical_widths)
        or len(sources) != len(physical_widths)
    ):
        return None
    physical_total = sum(physical_widths)
    cleanup = summary.stack_cleanup
    if (
        isinstance(cleanup, int)
        and cleanup > 0
        and cleanup != physical_total
    ) or any(source is None for source in sources):
        return None

    push_order_widths: list[int] = []
    push_order_sources: list[tuple[tuple[object, ...], ...]] = []
    grouped = False
    index = 0
    while index < len(physical_widths):
        low_source = sources[index]
        high_source = sources[index + 1] if index + 1 < len(sources) else None
        is_return_pair = (
            physical_widths[index : index + 2] == (2, 2)
            and isinstance(low_source, tuple)
            and len(low_source) >= 3
            and isinstance(high_source, tuple)
            and len(high_source) >= 3
            and low_source[0] == CallsitePushSourceKind8616.RETURN_REGISTER.value
            and high_source[0] == CallsitePushSourceKind8616.RETURN_REGISTER.value
            and isinstance(low_source[1], int)
            and low_source[1] == high_source[1]
            and low_source[2:3] == ("dx",)
            and high_source[2:3] == ("ax",)
        )
        if is_return_pair:
            push_order_widths.append(4)
            push_order_sources.append(
                (
                    cast(tuple[object, ...], low_source),
                    cast(tuple[object, ...], high_source),
                )
            )
            grouped = True
            index += 2
            continue
        if not isinstance(low_source, tuple):
            return None
        push_order_widths.append(physical_widths[index])
        push_order_sources.append((low_source,))
        index += 1

    logical_widths = tuple(reversed(push_order_widths))
    logical_sources = tuple(reversed(push_order_sources))
    return_argument_indices = tuple(
        index
        for index, source_group in enumerate(logical_sources)
        if len(source_group) == 2
        and all(
            source[0] == CallsitePushSourceKind8616.RETURN_REGISTER.value
            for source in source_group
        )
    )
    if not grouped or not return_argument_indices or sum(logical_widths) != physical_total:
        return None
    return LogicalArgumentShapeEvidence8616(
        widths=logical_widths,
        source=LogicalArgumentShapeEvidenceSource8616.EXACT_CALL_RETURN_PAIR,
        return_argument_indices=return_argument_indices,
    )


def _ordered_non_overlapping_objects_8616(
    stack_objects: tuple[CallerStackObject8616, ...],
) -> tuple[CallerStackObject8616, ...] | None:
    """Return offset-sorted stack objects when none overlap and all are valid."""
    ordered_objects = tuple(sorted(stack_objects, key=lambda item: item.offset))
    if any(
        item.offset < 4
        or item.width <= 0
        or (
            index > 0
            and ordered_objects[index - 1].offset + ordered_objects[index - 1].width > item.offset
        )
        for index, item in enumerate(ordered_objects)
    ):
        return None
    return ordered_objects


def _object_owned_slices_8616(
    sources: tuple[object, ...],
    physical_widths: tuple[int, ...],
    ordered_objects: tuple[CallerStackObject8616, ...],
) -> list[CallerStackObject8616 | None]:
    """Resolve the unique containing stack object for each BP-sourced slice."""
    owned_slices: list[CallerStackObject8616 | None] = []
    for source, width in zip(sources, physical_widths, strict=False):
        owner: CallerStackObject8616 | None = None
        if isinstance(source, tuple) and len(source) >= 2 and source[0] == "bp" and isinstance(source[1], int):
            candidates = tuple(
                item
                for item in ordered_objects
                if item.offset <= source[1] and source[1] + width <= item.offset + item.width
            )
            if len(candidates) == 1:
                owner = candidates[0]
        owned_slices.append(owner)
    return owned_slices


def _grouped_push_widths_8616(
    physical_widths: tuple[int, ...],
    sources: tuple[object, ...],
    owned_slices: list[CallerStackObject8616 | None],
) -> tuple[list[int], bool] | None:
    """Merge contiguous slices that exactly cover one stack object."""
    push_order_widths: list[int] = []
    grouped = False
    index = 0
    while index < len(physical_widths):
        owner = owned_slices[index]
        if owner is None:
            push_order_widths.append(physical_widths[index])
            index += 1
            continue
        end = index + 1
        while end < len(physical_widths) and owned_slices[end] == owner:
            end += 1
        slice_rows: list[tuple[int, int]] = []
        for position in range(index, end):
            source = sources[position]
            if not isinstance(source, tuple) or len(source) < 2 or not isinstance(source[1], int):
                return None
            slice_rows.append((source[1], physical_widths[position]))
        slices = sorted(slice_rows)
        cursor = owner.offset
        for slice_offset, slice_width in slices:
            if slice_offset != cursor:
                break
            cursor += slice_width
        if cursor == owner.offset + owner.width and end - index > 1:
            push_order_widths.append(owner.width)
            grouped = True
        else:
            push_order_widths.extend(physical_widths[index:end])
        index = end
    return push_order_widths, grouped


def exact_caller_stack_object_shape_evidence_8616(
    summary: CallsiteSummary8616,
    stack_objects: tuple[CallerStackObject8616, ...],
) -> LogicalArgumentShapeEvidence8616 | None:
    """Group physical PUSH slices that exactly cover one caller stack object."""
    physical_widths = summary.arg_widths
    sources = summary.push_arg_sources
    if (
        not _valid_widths_8616(physical_widths)
        or len(sources) != len(physical_widths)
        or not sources
    ):
        return None
    ordered_objects = _ordered_non_overlapping_objects_8616(stack_objects)
    if ordered_objects is None:
        return None
    owned_slices = _object_owned_slices_8616(sources, physical_widths, ordered_objects)
    grouped_result = _grouped_push_widths_8616(physical_widths, sources, owned_slices)
    if grouped_result is None:
        return None
    push_order_widths, grouped = grouped_result
    if not grouped or sum(push_order_widths) != sum(physical_widths):
        return None
    return LogicalArgumentShapeEvidence8616(
        widths=tuple(reversed(push_order_widths)),
        source=LogicalArgumentShapeEvidenceSource8616.EXACT_CALLER_STACK_OBJECT,
    )


def exact_caller_stack_object_for_word_pair_8616(
    low_source: object,
    high_source: object,
    stack_objects: tuple[CallerStackObject8616, ...],
) -> CallerStackObject8616 | None:
    """Return the unique four-byte caller object exactly covered by two BP words."""
    if not (
        isinstance(low_source, tuple)
        and len(low_source) >= 2
        and low_source[0] == CallsitePushSourceKind8616.BP_VALUE.value
        and isinstance(low_source[1], int)
        and isinstance(high_source, tuple)
        and len(high_source) >= 2
        and high_source[0] == CallsitePushSourceKind8616.BP_VALUE.value
        and isinstance(high_source[1], int)
        and high_source[1] == low_source[1] + 2
    ):
        return None
    candidates = tuple(
        stack_object
        for stack_object in stack_objects
        if stack_object.offset == low_source[1] and stack_object.width == 4
    )
    return candidates[0] if len(candidates) == 1 else None


def _materialized_far_pointer_logical_widths_8616(
    summary: CallsiteSummary8616,
    live_widths: tuple[int, ...],
) -> tuple[int, ...]:
    """Classify one far pointer from exact segment-and-offset PUSH facts."""
    if len(live_widths) != 1 or summary.arg_widths != (2, 2):
        return ()
    if summary.stack_cleanup is not None and summary.stack_cleanup != 4:
        return ()
    sources = summary.push_arg_sources
    if len(sources) != 2:
        return ()

    segment_count = 0
    address_count = 0
    for source in sources:
        if not isinstance(source, tuple) or len(source) < 2:
            return ()
        kind, value = source[:2]
        if kind == CallsitePushSourceKind8616.SEGMENT.value:
            if not isinstance(value, str) or value.lower() not in {"cs", "ds", "es", "ss"}:
                return ()
            segment_count += 1
        elif kind == CallsitePushSourceKind8616.BP_ADDRESS.value:
            if not isinstance(value, int) or isinstance(value, bool):
                return ()
            address_count += 1
        else:
            return ()
    return (4,) if segment_count == 1 and address_count == 1 else ()


def reconcile_materialized_call_argument_shape_8616(
    summary: CallsiteSummary8616,
    argument_widths: tuple[int, ...],
    *,
    logical_evidence: LogicalArgumentShapeEvidence8616 | None = None,
) -> CallsiteArgumentShapeReconciliation8616:
    """Publish proven logical widths while retaining physical machine PUSH facts."""
    if not _valid_widths_8616(argument_widths):
        return CallsiteArgumentShapeReconciliation8616(
            summary=summary,
            decision=CallsiteArgumentShapeDecision8616.INVALID_LIVE_SHAPE,
            raw_fact_count=len(argument_widths),
            normalized_fact_count=0,
            classified_fact_count=0,
            materialized_count=0,
            failure_count=1,
        )

    live_widths = tuple(int(width) for width in argument_widths)
    evidence_widths = logical_evidence.widths if logical_evidence is not None else ()
    if logical_evidence is not None and not _valid_widths_8616(evidence_widths):
        return CallsiteArgumentShapeReconciliation8616(
            summary=summary,
            decision=CallsiteArgumentShapeDecision8616.INVALID_LOGICAL_EVIDENCE,
            raw_fact_count=len(argument_widths) + len(evidence_widths),
            normalized_fact_count=len(live_widths),
            classified_fact_count=1,
            materialized_count=0,
            failure_count=1,
        )

    physical_widths = tuple(
        width
        for width in summary.arg_widths
        if isinstance(width, int) and not isinstance(width, bool) and width > 0
    )
    cleanup = summary.stack_cleanup if isinstance(summary.stack_cleanup, int) and summary.stack_cleanup > 0 else None
    push_sources = tuple(summary.push_arg_sources)
    complete_physical_shape = bool(physical_widths) and (
        (cleanup is not None and sum(physical_widths) == cleanup)
        or (
            len(push_sources) == len(physical_widths)
            and bool(push_sources)
            and all(source is not None for source in push_sources)
        )
    )
    if complete_physical_shape:
        far_pointer_widths = _materialized_far_pointer_logical_widths_8616(summary, live_widths)
        if far_pointer_widths and summary.logical_arg_widths != far_pointer_widths:
            return CallsiteArgumentShapeReconciliation8616(
                summary=replace(
                    summary,
                    logical_arg_widths=far_pointer_widths,
                    logical_arg_classes=(CallsiteArgumentClass8616.POINTER,),
                ),
                decision=CallsiteArgumentShapeDecision8616.MATERIALIZED_LOGICAL_FAR_POINTER,
                raw_fact_count=len(argument_widths),
                normalized_fact_count=len(live_widths),
                classified_fact_count=1,
                materialized_count=1,
                failure_count=0,
            )
        if logical_evidence is None:
            candidate = exact_call_return_pair_shape_evidence_8616(summary)
            if candidate is not None and len(candidate.widths) == len(live_widths):
                logical_evidence = candidate
        if logical_evidence is not None:
            evidence_widths = logical_evidence.widths
            logical_widths = tuple(int(width) for width in evidence_widths)
            exact_return_pair_matches = (
                logical_evidence.source
                is LogicalArgumentShapeEvidenceSource8616.EXACT_CALL_RETURN_PAIR
                and exact_call_return_pair_shape_evidence_8616(summary) == logical_evidence
                and len(logical_widths) == len(live_widths)
            )
            logical_shape_is_consistent = (
                (logical_widths == live_widths or exact_return_pair_matches)
                and sum(logical_widths) == sum(physical_widths)
                and (cleanup is None or sum(logical_widths) == cleanup)
            )
            if not logical_shape_is_consistent:
                return CallsiteArgumentShapeReconciliation8616(
                    summary=summary,
                    decision=CallsiteArgumentShapeDecision8616.INVALID_LOGICAL_EVIDENCE,
                    raw_fact_count=len(argument_widths) + len(logical_widths),
                    normalized_fact_count=len(live_widths) + len(logical_widths),
                    classified_fact_count=2,
                    materialized_count=0,
                    failure_count=1,
                )
            logical_classes = (
                summary.logical_arg_classes
                if len(summary.logical_arg_classes) == len(logical_widths)
                else ()
            )
            updated = (
                summary
                if (
                    summary.logical_arg_widths == logical_widths
                    and summary.logical_arg_classes == logical_classes
                )
                else replace(
                    summary,
                    logical_arg_widths=logical_widths,
                    logical_arg_classes=logical_classes,
                )
            )
            return CallsiteArgumentShapeReconciliation8616(
                summary=updated,
                decision=CallsiteArgumentShapeDecision8616.MATERIALIZED_PROVEN_LOGICAL_SHAPE,
                raw_fact_count=len(argument_widths) + len(logical_widths),
                normalized_fact_count=len(live_widths) + len(logical_widths),
                classified_fact_count=2,
                materialized_count=1,
                failure_count=0,
            )
        return CallsiteArgumentShapeReconciliation8616(
            summary=summary,
            decision=CallsiteArgumentShapeDecision8616.PRESERVED_COMPLETE_BINARY,
            raw_fact_count=len(argument_widths),
            normalized_fact_count=len(live_widths),
            classified_fact_count=1,
            materialized_count=1,
            failure_count=0,
        )

    live_shape_accounts_for_stack = cleanup is not None and sum(live_widths) == cleanup
    no_physical_shape = not physical_widths and cleanup is None
    if live_shape_accounts_for_stack or no_physical_shape:
        live_arg_count = len(live_widths)
        updated = (
            summary
            if summary.arg_count == live_arg_count and summary.arg_widths == live_widths
            else replace(summary, arg_count=live_arg_count, arg_widths=live_widths)
        )
        return CallsiteArgumentShapeReconciliation8616(
            summary=updated,
            decision=CallsiteArgumentShapeDecision8616.MATERIALIZED_LIVE_SHAPE,
            raw_fact_count=len(argument_widths),
            normalized_fact_count=len(live_widths),
            classified_fact_count=1,
            materialized_count=1,
            failure_count=0,
        )

    return CallsiteArgumentShapeReconciliation8616(
        summary=summary,
        decision=CallsiteArgumentShapeDecision8616.PRESERVED_UNPROVEN_LIVE_SHAPE,
        raw_fact_count=len(argument_widths),
        normalized_fact_count=len(live_widths),
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
    )
