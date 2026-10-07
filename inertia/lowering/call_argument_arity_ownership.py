"""Own exact zero-argument callsite arity before C-AST materialization.

Layer: Types/Lowering.
Responsibility: preserve a complete binary-proven zero-argument call shape and
refuse later candidate arguments that conflict with that shape. This module
does not infer arity from callee names, prototypes, assembly text, or rendered
C.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.semantics.callsite_summary import CallsiteSummary8616

__all__ = [
    "CallsiteZeroArgumentDecision8616",
    "CallsiteZeroArgumentOwnership8616",
    "classify_callsite_zero_argument_ownership_8616",
]


class CallsiteZeroArgumentDecision8616(StrEnum):
    """Typed ownership outcome for one candidate materialized call shape."""

    NOT_ZERO_ARGUMENT = "not-zero-argument"
    INVALID_ZERO_ARGUMENT_FACT = "invalid-zero-argument-fact"
    PRESERVE_ZERO_ARGUMENT = "preserve-zero-argument"
    REFUSE_NONZERO_CANDIDATE = "refuse-nonzero-candidate"


@dataclass(frozen=True, slots=True)
class CallsiteZeroArgumentOwnership8616:
    """Closed evidence result for one binary callsite and candidate arity."""

    decision: CallsiteZeroArgumentDecision8616
    candidate_arg_count: int
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def enforces_zero_arguments(self) -> bool:
        """Return whether the binary fact owns the call's empty argument list."""
        return self.decision in {
            CallsiteZeroArgumentDecision8616.PRESERVE_ZERO_ARGUMENT,
            CallsiteZeroArgumentDecision8616.REFUSE_NONZERO_CANDIDATE,
        }

    @property
    def blocks_candidate(self) -> bool:
        """Return whether the proposed argument materialization must be refused."""
        return self.decision in {
            CallsiteZeroArgumentDecision8616.INVALID_ZERO_ARGUMENT_FACT,
            CallsiteZeroArgumentDecision8616.REFUSE_NONZERO_CANDIDATE,
        }


def classify_callsite_zero_argument_ownership_8616(
    summary: CallsiteSummary8616,
    candidate_arg_count: int,
) -> CallsiteZeroArgumentOwnership8616:
    """Classify whether an exact summary requires an empty C argument list."""
    if summary.arg_count != 0:
        return CallsiteZeroArgumentOwnership8616(
            CallsiteZeroArgumentDecision8616.NOT_ZERO_ARGUMENT,
            candidate_arg_count,
            1,
            1,
            0,
            0,
            0,
        )

    zero_shape_is_complete = (
        isinstance(candidate_arg_count, int)
        and not isinstance(candidate_arg_count, bool)
        and candidate_arg_count >= 0
        and summary.stack_cleanup == 0
        and not summary.arg_widths
        and not summary.logical_arg_widths
        and not summary.logical_arg_classes
        and not summary.push_arg_sources
        and not summary.push_arg_instruction_addrs
        and summary.stack_cleanup_instruction_addr is None
    )
    if not zero_shape_is_complete:
        return CallsiteZeroArgumentOwnership8616(
            CallsiteZeroArgumentDecision8616.INVALID_ZERO_ARGUMENT_FACT,
            candidate_arg_count,
            1,
            0,
            0,
            0,
            1,
        )

    decision = (
        CallsiteZeroArgumentDecision8616.PRESERVE_ZERO_ARGUMENT
        if candidate_arg_count == 0
        else CallsiteZeroArgumentDecision8616.REFUSE_NONZERO_CANDIDATE
    )
    return CallsiteZeroArgumentOwnership8616(
        decision,
        candidate_arg_count,
        1,
        1,
        1,
        1,
        0,
    )
