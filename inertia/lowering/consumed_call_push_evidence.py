# cython: language_level=3, infer_types=True
"""Project consumed call-PUSH provenance across predecessor paths.

Layer: Types/Lowering.
Responsibility: Expand one typed callsite summary into every exact PUSH
instruction whose stack effect is consumed by materialized call arguments.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Alias owns the predecessor traces; this module validates and projects them for
Lowering. It does not inspect AST text, decode instructions, or prune code.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import Enum

from inertia.semantics.callsite_summary import CallsiteSummary8616
import dataclasses
import operator
import builtins

__all__ = [
    "ConsumedCallPushEvidenceResult8616",
    "ConsumedCallPushEvidenceStatus8616",
    "normalize_consumed_call_push_evidence_8616",
]


class ConsumedCallPushEvidenceStatus8616(Enum):
    """Typed normalization outcome for one callsite's PUSH provenance."""

    NOT_APPLICABLE = "not_applicable"
    NORMALIZED = "normalized"
    REFUSED = "refused"


@dataclasses.dataclass(frozen=True, )
class ConsumedCallPushEvidenceResult8616:
    """Return complete PUSH addresses with closed evidence accounting."""

    status: ConsumedCallPushEvidenceStatus8616
    instruction_addrs: tuple[cython.longlong, ...] = ()
    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    failure_count: cython.longlong = 0


@cython.ccall
def _valid_instruction_addr_8616(value: object) -> cython.bint:
    """Return whether a value is a concrete non-boolean instruction address."""
    return isinstance(value, int) and not isinstance(value, bool)


def normalize_consumed_call_push_evidence_8616(
    summary: CallsiteSummary8616,
) -> ConsumedCallPushEvidenceResult8616:
    """Return every validated representative and alternative PUSH address."""
    merge: object
    representatives = summary.push_arg_instruction_addrs
    if not representatives:
        return ConsumedCallPushEvidenceResult8616(
            ConsumedCallPushEvidenceStatus8616.NOT_APPLICABLE
        )
    merge = summary.predecessor_stack_merge
    alternative_count = (
        sum(len(lane) for lane in iter(merge.alternative_instruction_addrs))
        if merge is not None
        else 0
    )
    raw_count = len(representatives) + alternative_count
    if not all(_valid_instruction_addr_8616(address) for address in iter(representatives)):
        return ConsumedCallPushEvidenceResult8616(
            ConsumedCallPushEvidenceStatus8616.REFUSED,
            raw_fact_count=raw_count,
            failure_count=1,
        )
    if merge is None:
        normalized = tuple(dict.fromkeys(representatives))
        return ConsumedCallPushEvidenceResult8616(
            ConsumedCallPushEvidenceStatus8616.NORMALIZED,
            normalized,
            raw_count,
            len(normalized),
            0,
        )
    lane_count = len(merge.widths)
    alternatives = merge.alternative_instruction_addrs
    if (
        lane_count > len(representatives)
        or operator.ne(len(merge.representative_instruction_addrs), lane_count)
        or operator.ne(len(alternatives), lane_count)
        or operator.ne(representatives[:lane_count], merge.representative_instruction_addrs)
        or any(
            not lane
            or not all(_valid_instruction_addr_8616(address) for address in iter(lane))
            or representative not in lane
            for representative, lane in builtins.iter(zip(
                merge.representative_instruction_addrs,
                alternatives,
                strict=True,
            ))
        )
    ):
        return ConsumedCallPushEvidenceResult8616(
            ConsumedCallPushEvidenceStatus8616.REFUSED,
            raw_fact_count=raw_count,
            failure_count=1,
        )
    if merge.traces:
        if any(operator.ne(len(trace.instruction_addrs), lane_count) for trace in iter(merge.traces)):
            return ConsumedCallPushEvidenceResult8616(
                ConsumedCallPushEvidenceStatus8616.REFUSED,
                raw_fact_count=raw_count,
                failure_count=1,
            )
        traced_lanes = tuple(
            tuple(sorted(tuple(set(lane))))
            for lane in builtins.iter(zip(
                *(trace.instruction_addrs for trace in iter(merge.traces)),
                strict=True,
            ))
        )
        if traced_lanes != alternatives:
            return ConsumedCallPushEvidenceResult8616(
                ConsumedCallPushEvidenceStatus8616.REFUSED,
                raw_fact_count=raw_count,
                failure_count=1,
            )
    expanded = tuple(
        dict.fromkeys(
            address
            for lane in iter(alternatives)
            for address in iter(lane)
        )
    ) + tuple(dict.fromkeys(representatives[lane_count:]))
    normalized = tuple(dict.fromkeys(expanded))
    return ConsumedCallPushEvidenceResult8616(
        ConsumedCallPushEvidenceStatus8616.NORMALIZED,
        normalized,
        raw_count,
        len(normalized),
        0,
    )
