"""Validate exact condition precision changes from Structuring evidence.

Layer: Validation.
Responsibility: record immutable before/after C-AST fingerprints for proven
Structuring condition replacements and match them against whole-tail deltas.

This module validates an already proven transformation. It does not infer
conditions, alter C-AST semantics, or inspect rendered C, assembly, or sidecar
text. Unknown or partially matched deltas are refused.
"""

from __future__ import annotations

import logging
import os
from collections import Counter
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CExpression

from .ir.condition_ir import (
    canonicalize_condition_storage_fingerprint_8616,
    normalize_condition_fingerprint_string_8616,
)
from .tail_validation_fingerprint import _expr_fingerprint
from .validation_observable_compaction import (
    compact_normalized_validation_observable_8616,
)

__all__ = [
    "ConditionPrecisionEvidence8616",
    "ConditionPrecisionValidationResult8616",
    "ConditionPrecisionValidationStats8616",
    "condition_precision_evidence_8616",
    "condition_precision_token_8616",
    "condition_precision_validation_delta_8616",
    "record_condition_precision_evidence_8616",
]


class _ConditionPrecisionCodegen8616(Protocol):
    """Owned validation metadata attached at the dynamic codegen boundary."""

    _inertia_condition_precision_evidence_8616: tuple[ConditionPrecisionEvidence8616, ...]
    _inertia_condition_precision_validation_result_8616: ConditionPrecisionValidationResult8616


@dataclass(frozen=True, slots=True)
class ConditionPrecisionEvidence8616:
    """One immutable condition fingerprint replacement proven by Structuring."""

    before: str
    after: str
    jcc_addr: int | None = None
    after_integer_view: str | None = None


@dataclass(frozen=True, slots=True)
class ConditionPrecisionValidationStats8616:
    """Closed evidence accounting for one condition precision validation."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class ConditionPrecisionValidationResult8616:
    """Result of matching a validation delta to exact Structuring evidence."""

    accepted: bool
    stats: ConditionPrecisionValidationStats8616


def record_condition_precision_evidence_8616(
    project: object,
    codegen: object,
    before: CExpression,
    after: CExpression,
) -> bool:
    """Record one exact, nontrivial C-AST condition replacement."""
    # The identity bridge also materializes ConditionIR; defer its import until
    # Structuring has initialized.
    from .validation_condition_identity import condition_precision_view_fingerprint_8616

    before_fingerprint = condition_precision_token_8616(_expr_fingerprint(before, project))
    after_fingerprint = condition_precision_token_8616(_expr_fingerprint(after, project))
    if not before_fingerprint or not after_fingerprint or before_fingerprint == after_fingerprint:
        return False
    jcc_addr = after.tags.get("ins_addr")
    evidence = ConditionPrecisionEvidence8616(
        before_fingerprint,
        after_fingerprint,
        jcc_addr if isinstance(jcc_addr, int) else None,
        condition_precision_token_8616(condition_precision_view_fingerprint_8616(
            after, lambda expression: _expr_fingerprint(expression, project),
        )),
    )
    surface = cast(_ConditionPrecisionCodegen8616, codegen)
    try:
        existing = surface._inertia_condition_precision_evidence_8616
    except AttributeError:
        existing = ()
    if evidence in existing:
        return False
    surface._inertia_condition_precision_evidence_8616 = (*existing, evidence)
    return True


def condition_precision_evidence_8616(
    codegen: object,
) -> tuple[ConditionPrecisionEvidence8616, ...]:
    """Return immutable Structuring precision evidence at the codegen boundary."""
    surface = cast(_ConditionPrecisionCodegen8616, codegen)
    try:
        evidence = surface._inertia_condition_precision_evidence_8616
    except AttributeError:
        return ()
    return tuple(
        item
        for item in evidence
        if isinstance(item, ConditionPrecisionEvidence8616)
    )


def _delta_tokens_8616(field: object) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    """Read one validation field as immutable added and removed token tuples."""
    if not isinstance(field, dict):
        return (), ()
    added_value = field.get("added", ())
    removed_value = field.get("removed", ())
    if not isinstance(added_value, (list, tuple)) or not isinstance(removed_value, (list, tuple)):
        return None
    if not all(isinstance(item, str) for item in (*added_value, *removed_value)):
        return None
    return tuple(added_value), tuple(removed_value)


def condition_precision_token_8616(token: str) -> str:
    """Normalize and compact a raw condition fingerprint for precision matching.

    Stored evidence already contains these tokens. Consumers must tokenize the
    current raw fingerprint once, not compare raw text with a recorded digest
    or repeatedly compact the stored token.
    """
    normalized = str(
        normalize_condition_fingerprint_string_8616(
            canonicalize_condition_storage_fingerprint_8616(token)
        )
    )
    return compact_normalized_validation_observable_8616(
        "conditions",
        normalized,
    )


def _control_condition_token_8616(token: str) -> str | None:
    """Extract a condition from one supported control-flow fingerprint."""
    normalized = condition_precision_token_8616(token)
    for prefix in ("if:", "ifbreak:", "while:", "dowhile:", "for:"):
        if normalized.startswith(prefix):
            return normalized[len(prefix) :]
    return None


def _evidence_covers_delta_8616(
    evidence: tuple[ConditionPrecisionEvidence8616, ...],
    removed: tuple[str, ...],
    added: tuple[str, ...],
) -> bool:
    """Return whether evidence provides a complete one-to-one delta matching."""
    if not removed or len(removed) != len(added):
        return False
    pair_counts = Counter(
        (condition_precision_token_8616(item.before), condition_precision_token_8616(item.after))
        for item in evidence
    )

    def _match(index: int, remaining_added: Counter[str]) -> bool:
        if index == len(removed):
            return not remaining_added
        before = removed[index]
        for after in tuple(remaining_added):
            pair = (before, after)
            if remaining_added[after] <= 0 or pair_counts[pair] <= 0:
                continue
            pair_counts[pair] -= 1
            remaining_added[after] -= 1
            if remaining_added[after] == 0:
                del remaining_added[after]
            if _match(index + 1, remaining_added):
                return True
            remaining_added[after] += 1
            pair_counts[pair] += 1
        return False

    return _match(0, Counter(added))


def condition_precision_validation_delta_8616(
    codegen: object,
    validation: dict[str, object],
) -> ConditionPrecisionValidationResult8616:
    """Accept only exact condition and control deltas covered by typed evidence."""
    surface = cast(_ConditionPrecisionCodegen8616, codegen)
    evidence = condition_precision_evidence_8616(codegen)
    raw_count = len(evidence)
    delta = validation.get("delta")
    if not evidence or not isinstance(delta, dict):
        result = ConditionPrecisionValidationResult8616(
            False,
            ConditionPrecisionValidationStats8616(raw_fact_count=raw_count, failure_count=1),
        )
        surface._inertia_condition_precision_validation_result_8616 = result
        return result
    parsed = {
        field_name: _delta_tokens_8616(field_delta)
        for field_name, field_delta in delta.items()
    }
    if any(value is None for value in parsed.values()):
        result = ConditionPrecisionValidationResult8616(
            False,
            ConditionPrecisionValidationStats8616(raw_fact_count=raw_count, failure_count=1),
        )
        surface._inertia_condition_precision_validation_result_8616 = result
        return result
    touched = {
        field_name
        for field_name, value in parsed.items()
        if value is not None and (value[0] or value[1])
    }
    if touched != {"conditions", "control_flow_effects"}:
        result = ConditionPrecisionValidationResult8616(
            False,
            ConditionPrecisionValidationStats8616(raw_fact_count=raw_count, failure_count=1),
        )
        surface._inertia_condition_precision_validation_result_8616 = result
        return result
    condition_tokens = parsed["conditions"]
    control_tokens = parsed["control_flow_effects"]
    if condition_tokens is None or control_tokens is None:
        raise AssertionError("validated condition fields must be present")
    condition_added = tuple(condition_precision_token_8616(item) for item in condition_tokens[0])
    condition_removed = tuple(condition_precision_token_8616(item) for item in condition_tokens[1])
    control_added = tuple(_control_condition_token_8616(item) for item in control_tokens[0])
    control_removed = tuple(_control_condition_token_8616(item) for item in control_tokens[1])
    normalized_count = len(condition_added) + len(condition_removed)
    normalized = None not in (*control_added, *control_removed)
    control_added_exact = tuple(item for item in control_added if item is not None)
    control_removed_exact = tuple(item for item in control_removed if item is not None)
    covered = (
        normalized
        and Counter(condition_added) == Counter(control_added_exact)
        and Counter(condition_removed) == Counter(control_removed_exact)
        and _evidence_covers_delta_8616(evidence, condition_removed, condition_added)
    )
    if os.environ.get("INERTIA_DEBUG_CONDITION_PRECISION") == "1":
        logging.getLogger(__name__).warning(
            "[condition-precision-validation] covered=%s evidence=%r "
            "condition_added=%r condition_removed=%r control_added=%r "
            "control_removed=%r",
            covered,
            evidence,
            condition_added,
            condition_removed,
            control_added,
            control_removed,
        )
    classified_count = len(condition_added) if covered else 0
    result = ConditionPrecisionValidationResult8616(
        covered,
        ConditionPrecisionValidationStats8616(
            raw_fact_count=raw_count,
            normalized_fact_count=normalized_count,
            classified_fact_count=classified_count,
            materialized_count=classified_count,
            failure_count=0 if covered else 1,
        ),
    )
    surface._inertia_condition_precision_validation_result_8616 = result
    return result
