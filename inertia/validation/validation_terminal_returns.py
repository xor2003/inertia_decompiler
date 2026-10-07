"""Validate exact terminal return replacements from Structuring evidence.

Layer: Validation.
Responsibility: match one closed terminal-register materialization result to
the corresponding whole-tail return delta.

This module does not recover return semantics or mutate C ASTs. Unknown,
partial, or mixed-effect deltas are refused.

Package ownership contract (canonical inertia/validation package):
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations

import contextlib
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from inertia.structuring.terminal_register_values import (
    TerminalReturnValueMaterializationResult8616,
    TerminalReturnValueMaterializationStatus8616,
)

from .tail_validation import (
    canonicalize_tail_validation_summary_field_values_8616,
    validation_delta_touched_fields_8616,
)
from .tail_validation_fingerprint import _expr_fingerprint

__all__ = [
    "TerminalReturnValidationRefusal8616",
    "TerminalReturnValidationResult8616",
    "TerminalReturnValidationStats8616",
    "TerminalReturnValidationStatus8616",
    "terminal_return_value_validation_delta_8616",
]


class TerminalReturnValidationStatus8616(Enum):
    """Outcome of matching a terminal-return validation delta."""

    ACCEPTED = "accepted"
    REFUSED = "refused"


class _TailValidationProjectSurface8616(Protocol):
    """Dynamic project field used by canonical tail-validation fingerprints."""

    _inertia_tail_validation_active_codegen: object | None


class TerminalReturnValidationRefusal8616(Enum):
    """Typed reason why a terminal-return delta was not accepted."""

    NONE = "none"
    MATERIALIZATION_NOT_CLOSED = "materialization_not_closed"
    MISSING_EXPRESSION_EVIDENCE = "missing_expression_evidence"
    MISSING_DELTA = "missing_delta"
    UNRELATED_DELTA = "unrelated_delta"
    MALFORMED_RETURN_DELTA = "malformed_return_delta"
    FINGERPRINT_MISMATCH = "fingerprint_mismatch"


@dataclass(frozen=True, slots=True)
class TerminalReturnValidationStats8616:
    """Closed evidence accounting for one terminal-return validation."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class TerminalReturnValidationResult8616:
    """Typed result of matching a validation delta to Structuring evidence."""

    status: TerminalReturnValidationStatus8616
    refusal: TerminalReturnValidationRefusal8616
    stats: TerminalReturnValidationStats8616

    @property
    def accepted(self) -> bool:
        """Return whether the complete delta matches the materialization."""
        return self.status is TerminalReturnValidationStatus8616.ACCEPTED


def _refused_result_8616(
    refusal: TerminalReturnValidationRefusal8616,
    *,
    raw_fact_count: int = 0,
    normalized_fact_count: int = 0,
) -> TerminalReturnValidationResult8616:
    """Build one typed refusal without claiming accepted evidence."""
    return TerminalReturnValidationResult8616(
        TerminalReturnValidationStatus8616.REFUSED,
        refusal,
        TerminalReturnValidationStats8616(
            raw_fact_count=raw_fact_count,
            normalized_fact_count=normalized_fact_count,
            failure_count=1,
        ),
    )


def _delta_tokens_8616(field: object) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    """Read one validation field as immutable added and removed token tuples."""
    if not isinstance(field, Mapping):
        return None
    added = field.get("added", ())
    removed = field.get("removed", ())
    if not isinstance(added, (list, tuple)) or not isinstance(removed, (list, tuple)):
        return None
    if not all(isinstance(item, str) for item in (*added, *removed)):
        return None
    return tuple(added), tuple(removed)


def terminal_return_value_validation_delta_8616(
    project: object,
    codegen: object,
    materialization: TerminalReturnValueMaterializationResult8616 | None,
    validation: dict[str, object],
) -> TerminalReturnValidationResult8616:
    """Accept only the exact return replacement carried by closed evidence."""
    if materialization is None or materialization.status is not TerminalReturnValueMaterializationStatus8616.MATERIALIZED:
        return _refused_result_8616(
            TerminalReturnValidationRefusal8616.MATERIALIZATION_NOT_CLOSED,
        )
    raw_count = materialization.raw_fact_count
    if not (
        raw_count > 0
        and materialization.normalized_fact_count == raw_count
        and materialization.classified_fact_count == raw_count
        and materialization.materialized_count == raw_count
        and materialization.failure_count == 0
    ):
        return _refused_result_8616(
            TerminalReturnValidationRefusal8616.MATERIALIZATION_NOT_CLOSED,
            raw_fact_count=raw_count,
        )
    before = materialization.replaced_return_value
    after = materialization.materialized_return_value
    if before is None or after is None:
        return _refused_result_8616(
            TerminalReturnValidationRefusal8616.MISSING_EXPRESSION_EVIDENCE,
            raw_fact_count=raw_count,
        )
    delta = validation.get("delta")
    if not isinstance(delta, Mapping):
        return _refused_result_8616(
            TerminalReturnValidationRefusal8616.MISSING_DELTA,
            raw_fact_count=raw_count,
        )
    if validation_delta_touched_fields_8616(delta) != {"returns"}:
        return _refused_result_8616(
            TerminalReturnValidationRefusal8616.UNRELATED_DELTA,
            raw_fact_count=raw_count,
        )
    return_tokens = _delta_tokens_8616(delta.get("returns"))
    if return_tokens is None:
        return _refused_result_8616(
            TerminalReturnValidationRefusal8616.MALFORMED_RETURN_DELTA,
            raw_fact_count=raw_count,
        )
    added, removed = return_tokens
    project_surface = cast(_TailValidationProjectSurface8616, project)
    had_active_codegen = True
    try:
        previous_active_codegen = project_surface._inertia_tail_validation_active_codegen
    except AttributeError:
        had_active_codegen = False
        previous_active_codegen = None
    project_surface._inertia_tail_validation_active_codegen = codegen
    try:
        expected_added = canonicalize_tail_validation_summary_field_values_8616(
            "returns",
            {_expr_fingerprint(after, project)},
        )
        expected_removed = canonicalize_tail_validation_summary_field_values_8616(
            "returns",
            {_expr_fingerprint(before, project)},
        )
    finally:
        if had_active_codegen:
            project_surface._inertia_tail_validation_active_codegen = previous_active_codegen
        else:
            with contextlib.suppress(AttributeError):
                del project_surface._inertia_tail_validation_active_codegen
    if (
        len(added) != 1
        or len(removed) != 1
        or {added[0]} != expected_added
        or {removed[0]} != expected_removed
    ):
        return _refused_result_8616(
            TerminalReturnValidationRefusal8616.FINGERPRINT_MISMATCH,
            raw_fact_count=raw_count,
            normalized_fact_count=1,
        )
    return TerminalReturnValidationResult8616(
        TerminalReturnValidationStatus8616.ACCEPTED,
        TerminalReturnValidationRefusal8616.NONE,
        TerminalReturnValidationStats8616(
            raw_fact_count=raw_count,
            normalized_fact_count=raw_count,
            classified_fact_count=raw_count,
            materialized_count=raw_count,
        ),
    )
