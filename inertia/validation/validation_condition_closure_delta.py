"""Validate condition-only Structuring deltas from closed typed evidence.

Layer: Tail Validation.
Responsibility: accept a Structuring condition-fingerprint rewrite only when
every binary ConditionIR owner is materialized, absolute semantic validation
is clean, and the delta contains no effects beyond matching conditions and
control guards. Raw flag equations are not treated as semantic evidence.

Package ownership contract (canonical inertia/validation package):
Layer: Validation.
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from inertia.structuring.condition_evidence_closure import ConditionEvidenceClosure8616

__all__ = [
    "ConditionClosureDeltaResult8616",
    "ConditionClosureDeltaStats8616",
    "ConditionClosureDeltaStatus8616",
    "validate_condition_closure_delta_8616",
]


class ConditionClosureDeltaStatus8616(StrEnum):
    """Typed outcome for one closed-condition validation attempt."""

    ACCEPTED = "accepted"
    REFUSED_INCOMPLETE_CLOSURE = "refused_incomplete_closure"
    REFUSED_SEMANTIC_FAILURE = "refused_semantic_failure"
    REFUSED_EFFECT_SURFACE = "refused_effect_surface"
    REFUSED_GUARD_MISMATCH = "refused_guard_mismatch"


@dataclass(frozen=True, slots=True)
class ConditionClosureDeltaStats8616:
    """Closed accounting for one condition-only validation attempt."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class ConditionClosureDeltaResult8616:
    """Typed result of validating one Structuring condition-only delta."""

    status: ConditionClosureDeltaStatus8616
    stats: ConditionClosureDeltaStats8616

    @property
    def accepted(self) -> bool:
        """Return whether the exact closed-evidence contract passed."""
        return self.status is ConditionClosureDeltaStatus8616.ACCEPTED


def _changed_delta_fields_8616(
    delta: Mapping[str, object],
) -> frozenset[str] | None:
    """Return fields with typed added/removed tuple surfaces, or refuse."""
    changed: set[str] = set()
    for field_name, field_delta in delta.items():
        if not isinstance(field_delta, Mapping):
            return None
        added = field_delta.get("added")
        removed = field_delta.get("removed")
        if not isinstance(added, tuple) or not isinstance(removed, tuple):
            return None
        if added or removed:
            changed.add(field_name)
    return frozenset(changed)


def _string_delta_8616(
    delta: Mapping[str, object],
    field_name: str,
) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    """Read one exact string-valued validation delta field."""
    field_delta = delta.get(field_name)
    if not isinstance(field_delta, Mapping):
        return None
    added = field_delta.get("added")
    removed = field_delta.get("removed")
    if not isinstance(added, tuple) or not isinstance(removed, tuple):
        return None
    if not all(isinstance(item, str) for item in (*added, *removed)):
        return None
    return added, removed


def _guard_condition_8616(effect: str) -> str | None:
    """Extract one plain if guard without accepting body-effect tokens."""
    prefix = "if:"
    if not effect.startswith(prefix):
        return None
    condition = effect[len(prefix) :]
    return condition if condition and not condition.startswith("else") else None


def _result_8616(
    status: ConditionClosureDeltaStatus8616,
    *,
    raw_count: int,
    normalized_count: int = 0,
    classified_count: int = 0,
    materialized_count: int = 0,
) -> ConditionClosureDeltaResult8616:
    """Build one result while keeping failure accounting closed."""
    return ConditionClosureDeltaResult8616(
        status=status,
        stats=ConditionClosureDeltaStats8616(
            raw_fact_count=raw_count,
            normalized_fact_count=normalized_count,
            classified_fact_count=classified_count,
            materialized_count=materialized_count,
            failure_count=0 if status is ConditionClosureDeltaStatus8616.ACCEPTED else 1,
        ),
    )


def validate_condition_closure_delta_8616(
    closure: ConditionEvidenceClosure8616 | None,
    validation: Mapping[str, object],
) -> ConditionClosureDeltaResult8616:
    """Validate a condition-only delta against complete final ConditionIR owners.

    This contract deliberately ignores the shape of raw flag equations. It is
    valid only after the absolute branch validator reports no semantic failure,
    every required binary condition has exactly one typed final owner, and the
    compared stage changed no calls, writes, returns, or body effects.
    """
    raw_count = len(closure.required_keys) if closure is not None else 0
    if (
        closure is None
        or not closure.complete
        or not closure.required_keys
        or closure.materialized_keys != closure.required_keys
    ):
        return _result_8616(
            ConditionClosureDeltaStatus8616.REFUSED_INCOMPLETE_CLOSURE,
            raw_count=raw_count,
        )
    semantic_failures = validation.get("semantic_failures")
    if semantic_failures:
        return _result_8616(
            ConditionClosureDeltaStatus8616.REFUSED_SEMANTIC_FAILURE,
            raw_count=raw_count,
        )
    delta = validation.get("delta")
    if not isinstance(delta, Mapping):
        return _result_8616(
            ConditionClosureDeltaStatus8616.REFUSED_EFFECT_SURFACE,
            raw_count=raw_count,
        )
    changed_fields = _changed_delta_fields_8616(delta)
    if changed_fields != frozenset({"conditions", "control_flow_effects"}):
        return _result_8616(
            ConditionClosureDeltaStatus8616.REFUSED_EFFECT_SURFACE,
            raw_count=raw_count,
        )
    conditions = _string_delta_8616(delta, "conditions")
    controls = _string_delta_8616(delta, "control_flow_effects")
    if conditions is None or controls is None:
        return _result_8616(
            ConditionClosureDeltaStatus8616.REFUSED_EFFECT_SURFACE,
            raw_count=raw_count,
        )
    condition_added, condition_removed = conditions
    control_added, control_removed = controls
    normalized_count = len(condition_added) + len(condition_removed)
    if (
        not condition_added
        or len(condition_added) != len(condition_removed)
        or len(control_added) != len(control_removed)
    ):
        return _result_8616(
            ConditionClosureDeltaStatus8616.REFUSED_GUARD_MISMATCH,
            raw_count=raw_count,
            normalized_count=normalized_count,
        )
    added_guards = tuple(_guard_condition_8616(effect) for effect in control_added)
    removed_guards = tuple(_guard_condition_8616(effect) for effect in control_removed)
    if (
        None in (*added_guards, *removed_guards)
        or Counter(condition_added) != Counter(added_guards)
        or Counter(condition_removed) != Counter(removed_guards)
    ):
        return _result_8616(
            ConditionClosureDeltaStatus8616.REFUSED_GUARD_MISMATCH,
            raw_count=raw_count,
            normalized_count=normalized_count,
        )
    return _result_8616(
        ConditionClosureDeltaStatus8616.ACCEPTED,
        raw_count=raw_count,
        normalized_count=normalized_count,
        classified_count=normalized_count,
        materialized_count=normalized_count,
    )
