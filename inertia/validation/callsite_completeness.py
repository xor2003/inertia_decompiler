"""Layer: Validation.

Responsibility: classify CFG-to-AST callsite completeness improvements at validation boundaries.
Forbidden: recover calls, infer call arguments, or mutate structured C.
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

_MISSING_CALLSITE_PREFIX_8616 = "missing-callsite:"


class TailValidationCallsiteSummary8616(Protocol):
    """Summary surface required for typed callsite-completeness classification."""

    @property
    def helper_calls(self) -> tuple[str, ...]:
        """Read collected call fingerprints without permitting summary mutation."""
        ...


class CallsiteCompletenessDeltaVerdict8616(Enum):
    """Classification of one callsite-completeness validation delta."""

    NO_CANDIDATE = "no_candidate"
    COMPLETE_IMPROVEMENT = "complete_improvement"
    UNKNOWN_REFUSE = "unknown_refuse"


class CallsiteCompletenessDeltaReason8616(Enum):
    """Reason one callsite-completeness delta was accepted or refused."""

    NO_PRIOR_DEFICIT = "no_prior_deficit"
    VALIDATION_SHAPE_UNKNOWN = "validation_shape_unknown"
    SEMANTIC_FAILURE = "semantic_failure"
    OTHER_OBSERVABLE_DELTA = "other_observable_delta"
    HELPER_DELTA_SHAPE_UNKNOWN = "helper_delta_shape_unknown"
    ADDED_HELPER_CALL = "added_helper_call"
    REMAINING_DEFICIT = "remaining_deficit"
    REMOVED_DEFICIT_MISMATCH = "removed_deficit_mismatch"
    COMPLETE = "complete"


@dataclass(frozen=True, slots=True)
class CallsiteCompletenessDeltaResult8616:
    """Typed evidence loop for a CFG-proven callsite-completeness improvement."""

    verdict: CallsiteCompletenessDeltaVerdict8616
    reason: CallsiteCompletenessDeltaReason8616
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def accepted(self) -> bool:
        """Return whether the delta only removes all prior callsite deficits."""
        return self.verdict is CallsiteCompletenessDeltaVerdict8616.COMPLETE_IMPROVEMENT

    def as_dict(self) -> dict[str, int | str | bool]:
        """Return a serializable projection for diagnostics and snapshots."""
        return {
            "verdict": self.verdict.value,
            "reason": self.reason.value,
            "accepted": self.accepted,
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
        }


def _missing_callsites_8616(summary: TailValidationCallsiteSummary8616) -> tuple[str, ...]:
    return tuple(item for item in summary.helper_calls if item.startswith(_MISSING_CALLSITE_PREFIX_8616))


def _string_tuple_8616(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, (list, tuple)) or not all(isinstance(item, str) for item in value):
        return None
    return tuple(value)


def _delta_field_changed_8616(value: object) -> bool:
    if not isinstance(value, Mapping):
        return bool(value)
    return bool(value.get("added") or value.get("removed"))


def _delta_refusal_8616(
    validation: Mapping[str, object],
    before_missing: tuple[str, ...],
    after_missing: tuple[str, ...],
) -> CallsiteCompletenessDeltaReason8616 | None:
    """Return the refusal reason when the validation delta does not close."""
    delta = validation.get("delta")
    if not isinstance(delta, Mapping):
        return CallsiteCompletenessDeltaReason8616.VALIDATION_SHAPE_UNKNOWN
    if validation.get("semantic_failures"):
        return CallsiteCompletenessDeltaReason8616.SEMANTIC_FAILURE
    touched_fields = {name for name, value in delta.items() if _delta_field_changed_8616(value)}
    if touched_fields != {"helper_calls"}:
        return CallsiteCompletenessDeltaReason8616.OTHER_OBSERVABLE_DELTA
    helper_delta = delta.get("helper_calls")
    if not isinstance(helper_delta, Mapping):
        return CallsiteCompletenessDeltaReason8616.HELPER_DELTA_SHAPE_UNKNOWN
    added = _string_tuple_8616(helper_delta.get("added"))
    removed = _string_tuple_8616(helper_delta.get("removed"))
    if added is None or removed is None:
        return CallsiteCompletenessDeltaReason8616.HELPER_DELTA_SHAPE_UNKNOWN
    if added:
        return CallsiteCompletenessDeltaReason8616.ADDED_HELPER_CALL
    if after_missing:
        return CallsiteCompletenessDeltaReason8616.REMAINING_DEFICIT
    if Counter(removed) != Counter(before_missing):
        return CallsiteCompletenessDeltaReason8616.REMOVED_DEFICIT_MISMATCH
    return None


def classify_callsite_completeness_delta_8616(
    before: TailValidationCallsiteSummary8616,
    after: TailValidationCallsiteSummary8616,
    validation: Mapping[str, object],
) -> CallsiteCompletenessDeltaResult8616:
    """Classify removal of all CFG-proven missing-callsite deficits.

    The result is accepted only when the final AST satisfies every contextual
    callsite, helper-call completeness is the sole delta, and no semantic
    failure accompanies the change.
    """
    before_missing = _missing_callsites_8616(before)
    if not before_missing:
        return CallsiteCompletenessDeltaResult8616(
            CallsiteCompletenessDeltaVerdict8616.NO_CANDIDATE,
            CallsiteCompletenessDeltaReason8616.NO_PRIOR_DEFICIT,
            0,
            0,
            0,
            0,
            0,
        )

    raw_count = len(before_missing)

    def _refuse(reason: CallsiteCompletenessDeltaReason8616) -> CallsiteCompletenessDeltaResult8616:
        return CallsiteCompletenessDeltaResult8616(
            CallsiteCompletenessDeltaVerdict8616.UNKNOWN_REFUSE,
            reason,
            raw_count,
            raw_count,
            0,
            0,
            raw_count,
        )

    after_missing = _missing_callsites_8616(after)
    reason = _delta_refusal_8616(validation, before_missing, after_missing)
    if reason is not None:
        return _refuse(reason)
    return CallsiteCompletenessDeltaResult8616(
        CallsiteCompletenessDeltaVerdict8616.COMPLETE_IMPROVEMENT,
        CallsiteCompletenessDeltaReason8616.COMPLETE,
        raw_count,
        raw_count,
        raw_count,
        raw_count,
        0,
    )
