# cython: language_level=3, infer_types=True
"""Layer: Types/Lowering.

Responsibility: reconcile proven logical C argument widths with physical PUSH facts.
Forbidden: infer call interfaces from rendered C, helper names, or unproven AST shape.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import cast

from inertia.lowering.analysis_helpers import CallTargetKind8616
from inertia.semantics.callsite_summary import (
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
from .function_pointer_parameter_evidence import (
    FunctionPointerParameterFact8616,
    collect_function_pointer_parameter_evidence_8616,
)
import dataclasses
import operator
import builtins

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
    "exact_far_callback_call_shape_evidence_8616",
    "reconcile_materialized_call_argument_shape_8616",
]


class LogicalArgumentShapeEvidenceSource8616(StrEnum):
    """Typed provenance for a logical argument-width grouping."""

    EXACT_CALLEE_ABI = "exact-callee-abi"
    ACCOUNTED_TARGET_PROTOTYPE = "accounted-target-prototype"
    ACCOUNTED_VARIADIC_TARGET_PROTOTYPE = "accounted-variadic-target-prototype"
    EXACT_CALLER_STACK_OBJECT = "exact-caller-stack-object"
    EXACT_CALL_RETURN_PAIR = "exact-call-return-pair"


@dataclasses.dataclass(frozen=True, )
class CallerStackObject8616:
    """Exact BP-relative caller object available to one outgoing call."""

    offset: cython.longlong
    width: cython.longlong


@dataclasses.dataclass(frozen=True, )
class LogicalArgumentShapeEvidence8616:
    """A logical argument grouping proven before C-AST reconciliation."""

    widths: object
    source: LogicalArgumentShapeEvidenceSource8616
    return_argument_indices: tuple[cython.longlong, ...] = ()


class CallsiteArgumentShapeDecision8616(StrEnum):
    """Typed outcome for physical and logical call-width reconciliation."""

    PRESERVED_COMPLETE_BINARY = "preserved-complete-binary"
    PRESERVED_UNPROVEN_LIVE_SHAPE = "preserved-unproven-live-shape"
    MATERIALIZED_LOGICAL_FAR_POINTER = "materialized-logical-far-pointer"
    MATERIALIZED_PROVEN_LOGICAL_SHAPE = "materialized-proven-logical-shape"
    MATERIALIZED_LIVE_SHAPE = "materialized-live-shape"
    INVALID_LIVE_SHAPE = "invalid-live-shape"
    INVALID_LOGICAL_EVIDENCE = "invalid-logical-evidence"


@dataclasses.dataclass(frozen=True, )
class CallsiteArgumentShapeReconciliation8616:
    """Closed evidence result for one materialized call argument shape."""

    summary: CallsiteSummary8616
    decision: CallsiteArgumentShapeDecision8616
    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong


def _valid_widths_8616(widths: object) -> cython.bint:
    """Return whether every supplied width is a positive integer."""
    return all(isinstance(width, int) and not isinstance(width, bool) and width > 0 for width in iter(widths))


@cython.ccall
def _identical_physical_summary_8616(
    fresh_summary: CallsiteSummary8616,
    previous_summary: CallsiteSummary8616,
) -> cython.bint:
    """Return whether the rebuild reproduced the exact physical summary."""
    if (
        operator.ne(fresh_summary.callsite_addr, previous_summary.callsite_addr)
        or operator.ne(fresh_summary.target_addr, previous_summary.target_addr)
        or operator.ne(fresh_summary.return_addr, previous_summary.return_addr)
        or operator.ne(fresh_summary.kind, previous_summary.kind)
        or operator.ne(fresh_summary.arg_count, previous_summary.arg_count)
    ):
        return False
    return bool(
        operator.eq(fresh_summary.arg_widths, previous_summary.arg_widths)
        and operator.eq(fresh_summary.stack_cleanup, previous_summary.stack_cleanup)
        and operator.eq(fresh_summary.push_arg_sources, previous_summary.push_arg_sources)
        and operator.eq(fresh_summary.push_arg_instruction_addrs, previous_summary.push_arg_instruction_addrs)
        and operator.eq(fresh_summary.stack_cleanup_instruction_addr, previous_summary.stack_cleanup_instruction_addr)
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
        operator.eq(len(fresh_summary.push_arg_sources), len(physical_widths))
        and bool(fresh_summary.push_arg_sources)
        and all(source is not None for source in iter(fresh_summary.push_arg_sources))
    )
    if not complete_physical_shape or operator.ne(sum(logical_widths), physical_total):
        return fresh_summary

    logical_classes = previous_summary.logical_arg_classes
    if operator.ne(len(logical_classes), len(logical_widths)):
        logical_classes = ()
    return replace(
        fresh_summary,
        logical_arg_widths=logical_widths,
        logical_arg_classes=logical_classes,
    )


def accounted_target_prototype_shape_evidence_8616(
    summary: CallsiteSummary8616,
    live_widths: object,
    prototype_widths: object,
) -> LogicalArgumentShapeEvidence8616 | None:
    """Prove a grouped live shape from complete PUSH facts and its target prototype."""
    if prototype_widths is None or not _valid_widths_8616(live_widths):
        return None
    if not _valid_widths_8616(prototype_widths) or operator.ne(prototype_widths, live_widths):
        return None

    physical_widths = summary.arg_widths
    if not _valid_widths_8616(physical_widths) or len(prototype_widths) >= len(physical_widths):
        return None
    physical_total = sum(physical_widths)
    if operator.ne(sum(prototype_widths), physical_total):
        return None

    cleanup = summary.stack_cleanup
    cleanup_accounts_for_shape = isinstance(cleanup, int) and cleanup > 0 and cleanup == physical_total
    push_sources = summary.push_arg_sources
    sources_account_for_shape = (
        operator.eq(len(push_sources), len(physical_widths))
        and bool(push_sources)
        and all(source is not None for source in iter(push_sources))
    )
    if not cleanup_accounts_for_shape and not sources_account_for_shape:
        return None
    return LogicalArgumentShapeEvidence8616(
        widths=prototype_widths,
        source=LogicalArgumentShapeEvidenceSource8616.ACCOUNTED_TARGET_PROTOTYPE,
    )


def accounted_variadic_target_shape_evidence_8616(
    summary: CallsiteSummary8616,
    live_widths: object,
    fixed_prototype_widths: object,
) -> LogicalArgumentShapeEvidence8616 | None:
    """Prove a variadic live shape from its fixed prefix and complete PUSH extent."""
    if not _valid_widths_8616(live_widths) or not _valid_widths_8616(fixed_prototype_widths):
        return None
    if len(live_widths) < len(fixed_prototype_widths):
        return None
    if operator.ne(live_widths[: len(fixed_prototype_widths)], fixed_prototype_widths):
        return None
    physical_widths = summary.arg_widths
    if not _valid_widths_8616(physical_widths) or len(live_widths) >= len(physical_widths):
        return None
    physical_total = sum(physical_widths)
    if operator.ne(sum(live_widths), physical_total):
        return None
    cleanup = summary.stack_cleanup
    cleanup_accounts_for_shape = isinstance(cleanup, int) and cleanup > 0 and cleanup == physical_total
    push_sources = summary.push_arg_sources
    sources_account_for_shape = (
        operator.eq(len(push_sources), len(physical_widths))
        and bool(push_sources)
        and all(source is not None for source in iter(push_sources))
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
        or operator.ne(len(sources), len(physical_widths))
    ):
        return None
    physical_total = sum(physical_widths)
    cleanup = summary.stack_cleanup
    if (
        isinstance(cleanup, int)
        and cleanup > 0
        and cleanup != physical_total
    ) or any(source is None for source in iter(sources)):
        return None

    push_order_widths: list[cython.longlong] = []
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
            and operator.eq(low_source[0], CallsitePushSourceKind8616.RETURN_REGISTER.value)
            and operator.eq(high_source[0], CallsitePushSourceKind8616.RETURN_REGISTER.value)
            and isinstance(low_source[1], int)
            and operator.eq(low_source[1], high_source[1])
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
        for index, source_group in builtins.iter(enumerate(logical_sources))
        if len(source_group) == 2
        and all(
            operator.eq(source[0], CallsitePushSourceKind8616.RETURN_REGISTER.value)
            for source in iter(source_group)
        )
    )
    if not grouped or not return_argument_indices or operator.ne(sum(logical_widths), physical_total):
        return None
    return LogicalArgumentShapeEvidence8616(
        widths=logical_widths,
        source=LogicalArgumentShapeEvidenceSource8616.EXACT_CALL_RETURN_PAIR,
        return_argument_indices=return_argument_indices,
    )


def _ordered_non_overlapping_objects_8616(
    stack_objects: object,
) -> object:
    """Return offset-sorted stack objects when none overlap and all are valid."""
    ordered_objects = tuple(sorted(stack_objects, key=lambda item: item.offset))
    if any(
        item.offset < 4
        or item.width <= 0
        or (
            index > 0
            and ordered_objects[index - 1].offset + ordered_objects[index - 1].width > item.offset
        )
        for index, item in builtins.iter(enumerate(ordered_objects))
    ):
        return None
    return ordered_objects


def _object_owned_slices_8616(
    sources: object,
    physical_widths: object,
    ordered_objects: object,
) -> object:
    """Resolve the unique containing stack object for each BP-sourced slice."""
    source: object
    width: object
    owned_slices: list[CallerStackObject8616 | None] = []
    for source, width in zip(sources, physical_widths, strict=False):
        owner: CallerStackObject8616 | None = None
        if isinstance(source, tuple) and len(source) >= 2 and source[0] == "bp" and isinstance(source[1], int):
            candidates = tuple(
                item
                for item in iter(ordered_objects)
                if item.offset <= source[1] and source[1] + width <= item.offset + item.width
            )
            if len(candidates) == 1:
                owner = candidates[0]
        owned_slices.append(owner)
    return owned_slices


@cython.ccall
def _grouped_push_widths_8616(
    physical_widths: object,
    sources: object,
    owned_slices: object,
) -> object:
    """Merge contiguous slices that exactly cover one stack object."""
    owner: object
    slice_offset: object
    slice_width: object
    push_order_widths: list[cython.longlong] = []
    grouped = False
    index = 0
    while index < len(physical_widths):
        owner = owned_slices[index]
        if owner is None:
            push_order_widths.append(physical_widths[index])
            index += 1
            continue
        end = index + 1
        while end < len(physical_widths) and operator.eq(owned_slices[end], owner):
            end += 1
        slice_rows: list[tuple[cython.longlong, cython.longlong]] = []
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
        if operator.eq(cursor, owner.offset + owner.width) and end - index > 1:
            push_order_widths.append(owner.width)
            grouped = True
        else:
            push_order_widths.extend(physical_widths[index:end])
        index = end
    return push_order_widths, grouped


@cython.ccall
def exact_caller_stack_object_shape_evidence_8616(
    summary: CallsiteSummary8616,
    stack_objects: object,
) -> LogicalArgumentShapeEvidence8616 | None:
    """Group physical PUSH slices that exactly cover one caller stack object."""
    grouped_result: object
    ordered_objects: object
    physical_widths = summary.arg_widths
    sources = summary.push_arg_sources
    if (
        not _valid_widths_8616(physical_widths)
        or operator.ne(len(sources), len(physical_widths))
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
    if not grouped or operator.ne(sum(push_order_widths), sum(physical_widths)):
        return None
    return LogicalArgumentShapeEvidence8616(
        widths=tuple(reversed(push_order_widths)),
        source=LogicalArgumentShapeEvidenceSource8616.EXACT_CALLER_STACK_OBJECT,
    )


def exact_caller_stack_object_for_word_pair_8616(
    low_source: object,
    high_source: object,
    stack_objects: object,
) -> CallerStackObject8616 | None:
    """Return the unique four-byte caller object exactly covered by two BP words."""
    if not (
        isinstance(low_source, tuple)
        and len(low_source) >= 2
        and operator.eq(low_source[0], CallsitePushSourceKind8616.BP_VALUE.value)
        and isinstance(low_source[1], int)
        and isinstance(high_source, tuple)
        and len(high_source) >= 2
        and operator.eq(high_source[0], CallsitePushSourceKind8616.BP_VALUE.value)
        and isinstance(high_source[1], int)
        and operator.eq(high_source[1], low_source[1] + 2)
    ):
        return None
    candidates = tuple(
        stack_object
        for stack_object in iter(stack_objects)
        if operator.eq(stack_object.offset, low_source[1]) and stack_object.width == 4
    )
    return candidates[0] if len(candidates) == 1 else None


@cython.ccall
def _exact_bp_word_offset_8616(source: object) -> int | None:
    """Read a machine-proven BP word source without claiming object identity."""
    if not isinstance(source, tuple) or len(source) != 3:
        return None
    kind, offset, width = source
    if (
        operator.ne(kind, CallsitePushSourceKind8616.BP_VALUE.value)
        or not isinstance(offset, int)
        or isinstance(offset, bool)
        or width != 2
    ):
        return None
    return offset


def exact_far_callback_call_shape_evidence_8616(
    caller: CallsiteSummary8616,
    *,
    callee_addr: cython.longlong,
    callee_fact: FunctionPointerParameterFact8616,
    callee_indirect_calls: object,
) -> LogicalArgumentShapeEvidence8616 | None:
    """Prove a far callback plus scalar from exact caller and callee ABI facts.

    This classifies logical stack widths only. It does not claim that the two
    caller BP words are one C object or authorize replacing either store.
    """
    high_offset: object
    low_offset: object
    sources = caller.push_arg_sources
    invalid_caller_contract = (
        operator.ne(caller.target_addr, callee_addr)
        or caller.kind is not CallTargetKind8616.DIRECT_FAR_CALL
        or caller.arg_widths != (2, 2, 2)
        or caller.stack_cleanup != 6
    )
    if invalid_caller_contract or len(sources) != 3 or sources[0] is None:
        return None
    high_offset = _exact_bp_word_offset_8616(sources[1])
    low_offset = _exact_bp_word_offset_8616(sources[2])
    if high_offset is None or low_offset is None or operator.ne(high_offset, low_offset + 2):
        return None
    if not callee_indirect_calls or operator.ne(tuple(sorted(call.callsite_addr for call in iter(callee_indirect_calls))), callee_fact.callsite_addresses):
        return None
    evidence = collect_function_pointer_parameter_evidence_8616(callee_indirect_calls)
    if evidence.failure_count or operator.ne(evidence.facts, (callee_fact,)):
        return None
    if callee_fact.stack_offset != 6 or callee_fact.pointer_width != 4:
        return None
    if any(
        call.arg_widths != (2,)
        or call.stack_cleanup != 2
        or _exact_bp_word_offset_8616(call.push_arg_sources[0] if call.push_arg_sources else None) != 10
        for call in iter(callee_indirect_calls)
    ):
        return None
    return LogicalArgumentShapeEvidence8616(
        widths=(4, 2),
        source=LogicalArgumentShapeEvidenceSource8616.EXACT_CALLEE_ABI,
    )


@cython.ccall
def _materialized_far_pointer_logical_widths_8616(
    summary: CallsiteSummary8616,
    live_widths: object,
) -> object:
    """Classify one far pointer from exact segment-and-offset PUSH facts."""
    source: object
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
        kind, value = tuple(source[:2])
        if operator.eq(kind, CallsitePushSourceKind8616.SEGMENT.value):
            if not isinstance(value, str) or value.lower() not in {"cs", "ds", "es", "ss"}:
                return ()
            segment_count += 1
        elif operator.eq(kind, CallsitePushSourceKind8616.BP_ADDRESS.value):
            if not isinstance(value, int) or isinstance(value, bool):
                return ()
            address_count += 1
        else:
            return ()
    return tuple((4,)) if segment_count == 1 and address_count == 1 else tuple(())


def reconcile_materialized_call_argument_shape_8616(
    summary: CallsiteSummary8616,
    argument_widths: object,
    *,
    logical_evidence: LogicalArgumentShapeEvidence8616 | None = None,
) -> CallsiteArgumentShapeReconciliation8616:
    """Publish proven logical widths while retaining physical machine PUSH facts."""
    candidate: object
    cleanup: object
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

    live_widths = tuple(int(width) for width in iter(argument_widths))
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
        for width in iter(summary.arg_widths)
        if isinstance(width, int) and not isinstance(width, bool) and width > 0
    )
    cleanup = summary.stack_cleanup if isinstance(summary.stack_cleanup, int) and summary.stack_cleanup > 0 else None
    push_sources = tuple(summary.push_arg_sources)
    complete_physical_shape = bool(physical_widths) and (
        (cleanup is not None and operator.eq(sum(physical_widths), cleanup))
        or (
            operator.eq(len(push_sources), len(physical_widths))
            and bool(push_sources)
            and all(source is not None for source in iter(push_sources))
        )
    )
    if complete_physical_shape:
        far_pointer_widths = _materialized_far_pointer_logical_widths_8616(summary, live_widths)
        if far_pointer_widths and operator.ne(summary.logical_arg_widths, far_pointer_widths):
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
            if candidate is not None and operator.eq(len(candidate.widths), len(live_widths)):
                logical_evidence = candidate
        if logical_evidence is not None:
            evidence_widths = logical_evidence.widths
            logical_widths = tuple(int(width) for width in iter(evidence_widths))
            exact_return_pair_matches = (
                logical_evidence.source
                is LogicalArgumentShapeEvidenceSource8616.EXACT_CALL_RETURN_PAIR
                and operator.eq(exact_call_return_pair_shape_evidence_8616(summary), logical_evidence)
                and operator.eq(len(logical_widths), len(live_widths))
            )
            logical_shape_is_consistent = (
                (logical_widths == live_widths or exact_return_pair_matches)
                and operator.eq(sum(logical_widths), sum(physical_widths))
                and (cleanup is None or operator.eq(sum(logical_widths), cleanup))
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
                if operator.eq(len(summary.logical_arg_classes), len(logical_widths))
                else ()
            )
            updated = (
                summary
                if (
                    operator.eq(summary.logical_arg_widths, logical_widths)
                    and operator.eq(summary.logical_arg_classes, logical_classes)
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

    live_shape_accounts_for_stack = cleanup is not None and operator.eq(sum(live_widths), cleanup)
    no_physical_shape = not physical_widths and cleanup is None
    if live_shape_accounts_for_stack or no_physical_shape:
        live_arg_count = len(live_widths)
        updated = (
            summary
            if operator.eq(summary.arg_count, live_arg_count) and operator.eq(summary.arg_widths, live_widths)
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
