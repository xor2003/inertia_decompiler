"""Normalize exact Boolean ITE encodings used as structured conditions.

Layer: Structuring.
Responsibility: replace control-condition ``CITE`` nodes and bounded logical
negations only when their outcomes prove an exact Boolean encoding, preserving
the outer control origin and the original predicate's evaluation count.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.

This pass does not infer branch semantics. It consumes the structured C form
``condition ? 0 : 1`` or ``condition ? 1 : 0`` as an algebraic identity.
Every other ITE is retained unchanged as insufficient evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CConstant,
    CDoWhileLoop,
    CExpression,
    CForLoop,
    CIfElse,
    CUnaryOp,
    CWhileLoop,
)

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.lowering.structured_tags import copy_structured_tags_8616
from inertia.pipeline.errors import PipelineHardError

from .condition_materialization import invert_structured_condition_8616


class BooleanConditionIteDisposition8616(Enum):
    """Typed outcome for one structured control-condition candidate."""

    NOT_ITE = "not_ite"
    REFUSED_NON_CONSTANT = "refused_non_constant"
    REFUSED_NON_BOOLEAN = "refused_non_boolean"
    MATERIALIZED_IDENTITY = "materialized_identity"
    MATERIALIZED_INVERTED = "materialized_inverted"


@dataclass(frozen=True, slots=True)
class BooleanConditionIteStats8616:
    """Closed evidence-loop counters for Boolean control-condition ITEs."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def changed(self) -> bool:
        """Return whether at least one proven condition was materialized."""
        return self.materialized_count > 0


class _CodegenSurface8616(Protocol):
    """Typed writable view of the third-party structured-codegen boundary."""

    cfunc: object
    _inertia_boolean_condition_ite_stats_8616: BooleanConditionIteStats8616


def _constant_integer_8616(expression: CExpression) -> int | None:
    """Return an exact Python integer from one structured constant."""
    if not isinstance(expression, CConstant) or not isinstance(expression.value, int):
        return None
    return int(expression.value)


_LOGICAL_NOT_WRAPPER_LIMIT_8616 = 4


def _unwrap_logical_not_chain_8616(
    condition: CExpression,
) -> tuple[CExpression, int]:
    """Unwrap a bounded chain of logical Not operators around one expression.

    Only the ``CUnaryOp`` ``"Not"`` operator is a logical negation; bitwise
    complement and every other node stop the chain. The bound keeps the pass
    honest instead of descending arbitrary wrapper depth.
    """
    operand = condition
    not_count = 0
    while (
        not_count < _LOGICAL_NOT_WRAPPER_LIMIT_8616
        and isinstance(operand, CUnaryOp)
        and operand.op == "Not"
    ):
        operand = operand.operand
        not_count += 1
    return operand, not_count


def _merge_condition_origin_tags_8616(replacement: CExpression, condition: CExpression) -> None:
    """Preserve inner comparison and outer wrapper instruction-origin tags."""
    encoded, _not_count = _unwrap_logical_not_chain_8616(condition)
    if not isinstance(encoded, CITE):
        return
    tags = copy_structured_tags_8616(encoded.cond.tags) or {}
    tags.update(copy_structured_tags_8616(replacement.tags) or {})
    tags.update(copy_structured_tags_8616(encoded.tags) or {})
    wrappers: list[CUnaryOp] = []
    wrapper = condition
    while wrapper is not encoded:
        wrappers.append(cast(CUnaryOp, wrapper))
        wrapper = cast(CUnaryOp, wrapper).operand
    # This is a control-expression replacement: its outermost source origin
    # must win over locations belonging only to inner Boolean encodings.
    for wrapper in reversed(wrappers):
        tags.update(copy_structured_tags_8616(wrapper.tags) or {})
    replacement.tags = tags


def _normalize_boolean_ite_8616(
    condition: CExpression,
    codegen: object,
) -> tuple[CExpression, BooleanConditionIteDisposition8616]:
    """Normalize one control condition when its ITE outcomes prove Booleanity.

    A bounded logical Not chain may wrap the literal ``(0, 1)``/``(1, 0)`` ITE;
    each wrapper only flips truth parity, so the folded expression still
    evaluates ``cond`` exactly once and preserves the original guard truth.
    """
    encoded, not_count = _unwrap_logical_not_chain_8616(condition)
    if not isinstance(encoded, CITE):
        return condition, BooleanConditionIteDisposition8616.NOT_ITE
    true_value = _constant_integer_8616(encoded.iftrue)
    false_value = _constant_integer_8616(encoded.iffalse)
    if true_value is None or false_value is None:
        return condition, BooleanConditionIteDisposition8616.REFUSED_NON_CONSTANT
    if (true_value, false_value) not in {(0, 1), (1, 0)}:
        return condition, BooleanConditionIteDisposition8616.REFUSED_NON_BOOLEAN

    negations = not_count + (0 if (true_value, false_value) == (1, 0) else 1)
    replacement = (
        encoded.cond
        if negations % 2 == 0
        else invert_structured_condition_8616(encoded.cond, codegen)
    )
    _merge_condition_origin_tags_8616(replacement, condition)
    disposition = (
        BooleanConditionIteDisposition8616.MATERIALIZED_IDENTITY
        if negations % 2 == 0
        else BooleanConditionIteDisposition8616.MATERIALIZED_INVERTED
    )
    return replacement, disposition


def normalize_boolean_condition_ites_8616(codegen: object) -> BooleanConditionIteStats8616:
    """Normalize all exact Boolean ITEs that directly control branches or loops."""
    surface = cast(_CodegenSurface8616, codegen)
    try:
        root = surface.cfunc
    except AttributeError:
        return BooleanConditionIteStats8616()

    dispositions: list[BooleanConditionIteDisposition8616] = []
    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, CIfElse):
            pairs: list[tuple[CExpression, object]] = []
            for condition, body in tuple(node.condition_and_nodes):
                replacement, disposition = _normalize_boolean_ite_8616(condition, codegen)
                dispositions.append(disposition)
                pairs.append((replacement, body))
            node.condition_and_nodes = pairs
            continue
        if isinstance(node, (CForLoop, CWhileLoop, CDoWhileLoop)):
            replacement, disposition = _normalize_boolean_ite_8616(node.condition, codegen)
            dispositions.append(disposition)
            node.condition = replacement

    raw_count = sum(disposition is not BooleanConditionIteDisposition8616.NOT_ITE for disposition in dispositions)
    normalized_count = sum(
        disposition
        not in {
            BooleanConditionIteDisposition8616.NOT_ITE,
            BooleanConditionIteDisposition8616.REFUSED_NON_CONSTANT,
        }
        for disposition in dispositions
    )
    materialized_count = sum(
        disposition
        in {
            BooleanConditionIteDisposition8616.MATERIALIZED_IDENTITY,
            BooleanConditionIteDisposition8616.MATERIALIZED_INVERTED,
        }
        for disposition in dispositions
    )
    stats = BooleanConditionIteStats8616(
        raw_fact_count=raw_count,
        normalized_fact_count=normalized_count,
        classified_fact_count=materialized_count,
        materialized_count=materialized_count,
        failure_count=raw_count - materialized_count,
    )
    if stats.classified_fact_count > stats.materialized_count:
        raise PipelineHardError("boolean_condition_ite: classified facts were not materialized")
    surface._inertia_boolean_condition_ite_stats_8616 = stats
    return stats


__all__ = [
    "BooleanConditionIteDisposition8616",
    "BooleanConditionIteStats8616",
    "normalize_boolean_condition_ites_8616",
]
