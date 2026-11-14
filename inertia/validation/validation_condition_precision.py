# cython: language_level=3, infer_types=True
"""Validate exact condition precision changes from Structuring evidence.

Layer: Validation.
Responsibility: record immutable before/after C-AST fingerprints for proven
Structuring condition replacements and match them against whole-tail deltas.

This module validates an already proven transformation. It does not infer
conditions, alter C-AST semantics, or inspect rendered C, assembly, or sidecar
text. Unknown or partially matched deltas are refused.

Package ownership contract (canonical inertia/validation package):
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations
import typing
import cython

import logging
import os
from collections import Counter
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CExpression

from inertia.ir.condition_ir import (
    canonicalize_condition_storage_fingerprint_8616,
    normalize_condition_fingerprint_algebraic_8616,
    normalize_condition_fingerprint_string_8616,
)

from .tail_validation_fingerprint import _expr_fingerprint
from .validation_control_condition_delta import control_condition_delta_matches_8616
from .validation_observable_compaction import (
    compact_normalized_validation_observable_8616,
)
import dataclasses
import operator
import builtins

__all__ = [
    "ConditionPrecisionEvidence8616",
    "ConditionPrecisionValidationResult8616",
    "ConditionPrecisionValidationStats8616",
    "condition_precision_evidence_8616",
    "condition_precision_token_8616",
    "condition_precision_validation_delta_8616",
    "matches_recorded_condition_precision_8616",
    "record_condition_precision_evidence_8616",
]


class _ConditionPrecisionCodegen8616(Protocol):
    """Owned validation metadata attached at the dynamic codegen boundary."""

    _inertia_condition_precision_evidence_8616: object
    _inertia_condition_precision_validation_result_8616: ConditionPrecisionValidationResult8616


@dataclasses.dataclass(frozen=True, )
class ConditionPrecisionEvidence8616:
    """One immutable condition fingerprint replacement proven by Structuring."""

    before: object
    after: object
    jcc_addr: int | None = None
    after_integer_view: object = None


@dataclasses.dataclass(frozen=True, )
class ConditionPrecisionValidationStats8616:
    """Closed evidence accounting for one condition precision validation."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0


@dataclasses.dataclass(frozen=True, )
class ConditionPrecisionValidationResult8616:
    """Result of matching a validation delta to exact Structuring evidence."""

    accepted: cython.bint
    stats: ConditionPrecisionValidationStats8616


def record_condition_precision_evidence_8616(
    project: object,
    codegen: object,
    before: CExpression,
    after: CExpression,
) -> cython.bint:
    """Record one exact, nontrivial C-AST condition replacement."""
    jcc_addr: object
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
        for item in iter(evidence)
        if isinstance(item, ConditionPrecisionEvidence8616)
    )


@cython.ccall
def matches_recorded_condition_precision_8616(
    codegen: object, jcc_addr: cython.longlong, fingerprint: object,
) -> cython.bint:
    """Require the current predicate to match one unambiguous proven branch view.

    This is the same exact after-token check used by final branch validation.
    It must not substitute a historical predicate for changed current code.
    """
    candidates = {
        evidence.after
        for evidence in builtins.iter(condition_precision_evidence_8616(codegen))
        if operator.eq(evidence.jcc_addr, jcc_addr)
    }
    return candidates == {condition_precision_token_8616(fingerprint)}


def _delta_tokens_8616(field: object) -> object:
    """Read one validation field as immutable added and removed token tuples."""
    added_value: object
    removed_value: object
    if not isinstance(field, dict):
        return (), ()
    added_value = field.get("added", ())
    removed_value = field.get("removed", ())
    if not isinstance(added_value, (list, tuple)) or not isinstance(removed_value, (list, tuple)):
        return None
    if not all(isinstance(item, str) for item in iter(tuple(added_value) + tuple(removed_value))):
        return None
    return tuple(added_value), tuple(removed_value)


@cython.ccall
def condition_precision_token_8616(token: object) -> object:
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
    normalized = str(normalize_condition_fingerprint_algebraic_8616(normalized))
    return compact_normalized_validation_observable_8616(
        "conditions",
        normalized,
    )


def _evidence_covers_delta_8616(
    evidence: object,
    removed: object,
    added: object,
    control_removed: object,
    control_added: object,
) -> cython.bint:
    """Return whether evidence provides a complete one-to-one delta matching."""
    if not removed or operator.ne(len(removed), len(added)):
        return False
    pair_counts = Counter(
        (condition_precision_token_8616(item.before), condition_precision_token_8616(item.after))
        for item in iter(evidence)
    )

    chosen_pairs: list[tuple[str, str]] = []

    def _match(index: cython.longlong, remaining_added: Counter[str]) -> cython.bint:
        after: object
        if operator.eq(index, len(removed)):
            return not remaining_added and control_condition_delta_matches_8616(
                control_removed, control_added, tuple(chosen_pairs),
            )
        before = removed[index]
        for after in tuple(remaining_added):
            pair = (before, after)
            if remaining_added[after] <= 0 or pair_counts[pair] <= 0:
                continue
            pair_counts[pair] -= 1
            remaining_added[after] -= 1
            if remaining_added[after] == 0:
                del remaining_added[after]
            chosen_pairs.append(pair)
            if _match(index + 1, remaining_added):
                return True
            chosen_pairs.pop()
            remaining_added[after] += 1
            pair_counts[pair] += 1
        return False

    return _match(0, Counter(added))


def condition_precision_validation_delta_8616(
    codegen: object,
    validation: object,
) -> ConditionPrecisionValidationResult8616:
    """Accept only exact condition and control deltas covered by typed evidence."""
    condition_tokens: object
    control_tokens: object
    delta: object
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
        for field_name, field_delta in builtins.iter(delta.items())
    }
    if any(value is None for value in builtins.iter(parsed.values())):
        result = ConditionPrecisionValidationResult8616(
            False,
            ConditionPrecisionValidationStats8616(raw_fact_count=raw_count, failure_count=1),
        )
        surface._inertia_condition_precision_validation_result_8616 = result
        return result
    touched = {
        field_name
        for field_name, value in builtins.iter(parsed.items())
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
    condition_added = tuple(condition_precision_token_8616(item) for item in iter(condition_tokens[0]))
    condition_removed = tuple(condition_precision_token_8616(item) for item in iter(condition_tokens[1]))
    control_added = control_tokens[0]
    control_removed = control_tokens[1]
    normalized_count = len(condition_added) + len(condition_removed)
    covered = _evidence_covers_delta_8616(
        evidence, condition_removed, condition_added, control_removed, control_added,
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
