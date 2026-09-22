"""Classify stack parameters used as indirect call targets.

Layer: Types/Lowering.
Responsibility: join typed binary callsite summaries into conservative
function-pointer parameter facts without mutating structured C. A 4-byte
indirect-call operand proves a far (segment:offset) function pointer; a
2-byte operand proves a near one.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum

from ..callsite_summary import CallsiteSummary8616


class FunctionPointerParameterFailure8616(Enum):
    """Typed refusal reasons for indirect-call parameter evidence."""

    INVALID_CALL_SIGNATURE = "invalid_call_signature"
    CONFLICTING_CALL_SIGNATURES = "conflicting_call_signatures"
    PARAMETER_SLOT_MISSING = "parameter_slot_missing"
    VARIABLE_MANAGER_REJECTED = "variable_manager_rejected"


@dataclass(frozen=True, order=True, slots=True)
class FunctionPointerParameterFact8616:
    """One consistent indirect-call contract for an exact BP parameter.

    ``pointer_width`` is the binary-proven call-operand width: 2 for a near
    function pointer and 4 for a far (segment:offset) function pointer.
    """

    stack_offset: int
    argument_widths: tuple[int, ...]
    return_width: int
    callsite_addresses: tuple[int, ...]
    pointer_width: int = 2


@dataclass(frozen=True, slots=True)
class FunctionPointerParameterEvidence8616:
    """Closed evidence census for function-pointer parameter recovery."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    facts: tuple[FunctionPointerParameterFact8616, ...] = ()
    failures: tuple[FunctionPointerParameterFailure8616, ...] = ()


def _supported_widths_8616(summary: CallsiteSummary8616) -> tuple[int, ...] | None:
    """Return one exact supported argument-width vector, or refuse it."""
    widths = summary.logical_arg_widths or summary.arg_widths
    if summary.arg_count is not None and summary.arg_count != len(widths):
        return None
    if any(width not in {1, 2, 4} for width in widths):
        return None
    return widths


def _used_return_width_8616(summary: CallsiteSummary8616) -> int | None:
    """Return the binary-proven used return width for one indirect call."""
    if summary.return_used is not True:
        return None
    if summary.return_shape == "dx_ax":
        return 4
    if summary.return_register == "ax" and summary.return_shape in {None, "ax"}:
        return 2
    return None


def collect_function_pointer_parameter_evidence_8616(
    summaries: Sequence[CallsiteSummary8616],
) -> FunctionPointerParameterEvidence8616:
    """Join consistent BP-indirect call summaries into parameter type facts."""
    grouped: dict[int, list[tuple[CallsiteSummary8616, tuple[int, ...], int, int]]] = defaultdict(list)
    raw_count = 0
    normalized_count = 0
    failures: list[FunctionPointerParameterFailure8616] = []
    for summary in summaries:
        target_source = summary.target_source
        if (
            summary.target_addr is not None
            or not isinstance(target_source, tuple)
            or not target_source
            or target_source[0] != "bp"
        ):
            continue
        raw_count += 1
        widths = _supported_widths_8616(summary)
        return_width = _used_return_width_8616(summary)
        pointer_width = target_source[2] if len(target_source) >= 3 else 2
        if (
            len(target_source) < 2
            or not isinstance(target_source[1], int)
            or target_source[1] < 4
            or not isinstance(pointer_width, int)
            or pointer_width not in {2, 4}
            or widths is None
            or return_width is None
        ):
            failures.append(FunctionPointerParameterFailure8616.INVALID_CALL_SIGNATURE)
            continue
        normalized_count += 1
        grouped[target_source[1]].append((summary, widths, return_width, pointer_width))

    facts: list[FunctionPointerParameterFact8616] = []
    for stack_offset, candidates in sorted(grouped.items()):
        signatures = {
            (widths, return_width, pointer_width)
            for _summary, widths, return_width, pointer_width in candidates
        }
        if len(signatures) != 1:
            failures.extend(
                FunctionPointerParameterFailure8616.CONFLICTING_CALL_SIGNATURES for _candidate in candidates
            )
            continue
        argument_widths, return_width, pointer_width = next(iter(signatures))
        facts.append(
            FunctionPointerParameterFact8616(
                stack_offset=stack_offset,
                argument_widths=argument_widths,
                return_width=return_width,
                callsite_addresses=tuple(sorted(summary.callsite_addr for summary, _widths, _ret, _ptr in candidates)),
                pointer_width=pointer_width,
            )
        )
    return FunctionPointerParameterEvidence8616(
        raw_fact_count=raw_count,
        normalized_fact_count=normalized_count,
        classified_fact_count=len(facts),
        failure_count=len(failures),
        facts=tuple(facts),
        failures=tuple(failures),
    )


__all__ = [
    "FunctionPointerParameterEvidence8616",
    "FunctionPointerParameterFact8616",
    "FunctionPointerParameterFailure8616",
    "collect_function_pointer_parameter_evidence_8616",
]
