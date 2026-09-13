"""Check current condition ownership against published Structuring obligations.

Layer: Tail Validation.
Responsibility: detect required predicates without current typed AST owners.
Do not recover conditions, mutate the AST, or trust cached completion as proof
that a predicate survived later passes.
"""

from __future__ import annotations

from typing import Protocol, cast

from .ir.condition_ir import ConditionIR
from .structuring.condition_evidence_closure import (
    ConditionEvidenceClosure8616,
    ConditionEvidenceKey8616,
    classify_condition_evidence_closure_8616,
)


class _ConditionClosureBoundary8616(Protocol):
    """Optional Structuring metadata on the third-party codegen object."""

    _inertia_structuring_condition_evidence_closure_8616: ConditionEvidenceClosure8616


def missing_required_condition_keys_8616(
    codegen: object,
    root: object,
    typed_conditions: tuple[ConditionIR, ...],
) -> tuple[ConditionEvidenceKey8616, ...]:
    """Recheck published obligations against current single/composite owners.

    Pre-Structuring snapshots have no published ownership obligations. Once
    published, neither a previously complete snapshot nor a reduced fact list
    may hide a missing predicate. Composite provenance is consumed by the
    authoritative Structuring classifier, not inferred from expression text.
    """
    try:
        closure = cast(_ConditionClosureBoundary8616, codegen)._inertia_structuring_condition_evidence_closure_8616
    except AttributeError:
        return ()
    current = classify_condition_evidence_closure_8616(root, typed_conditions, {})
    required = closure.required_keys | current.required_keys
    return tuple(sorted(required - current.materialized_keys))
