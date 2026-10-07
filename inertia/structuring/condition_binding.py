"""Bind regenerated structured expressions back to typed condition facts.

Layer: Structuring.
Responsibility: recover condition provenance after codegen regeneration by
requiring one unique structural AST match to an already-proven ``ConditionIR``.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.

This module does not decode instructions, compare rendered text, or infer new
semantics. Ambiguous or unavailable materializations are refused.
"""

from __future__ import annotations

from collections.abc import Callable

from angr.analyses.decompiler.structured_codegen.c import CExpression

from inertia.ir.condition_ir import ConditionIR

type ConditionMaterializer8616 = Callable[[ConditionIR], CExpression | None]
type ConditionExpressionComparer8616 = Callable[[CExpression, CExpression], bool]


def select_unique_condition_by_expression_8616(
    expression: CExpression,
    conditions: tuple[ConditionIR, ...],
    materialize: ConditionMaterializer8616,
    same_expression: ConditionExpressionComparer8616,
) -> ConditionIR | None:
    """Return the sole typed fact whose materialized AST matches exactly."""
    matches: list[ConditionIR] = []
    for condition in conditions:
        candidate = materialize(condition)
        if candidate is not None and same_expression(expression, candidate):
            matches.append(condition)
    return matches[0] if len(matches) == 1 else None
