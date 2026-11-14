# cython: language_level=3, infer_types=True
"""Classify target-directed wide comparison outcomes before C lowering.

Layer: Structuring.
Responsibility: identify one comparison from all high/low ordering outcomes.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence. Operand storage, call identity, widening and signedness
must already be proven by the caller. This module introduces none of them.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Callable

from inertia.ir.condition_ir import ConditionOp
import operator
import builtins

WideOrderingEvaluator8616 = typing.TypeAliasType("WideOrderingEvaluator8616", Callable[[int, int], bool | None])

ORDERING_RELATIONS8616: tuple[cython.longlong, ...] = (-1, 0, 1)


@cython.ccall
def wide_operator_result_8616(op: ConditionOp, relation: cython.longlong) -> bool | None:
    """Evaluate a comparison over an already-proven signed or unsigned order."""
    if op == "eq":
        return relation == 0
    if op == "ne":
        return relation != 0
    if op in {"slt", "ult"}:
        return relation < 0
    if op in {"sle", "ule"}:
        return relation <= 0
    if op in {"sgt", "ugt"}:
        return relation > 0
    if op in {"sge", "uge"}:
        return relation >= 0
    return None


@cython.ccall
def candidate_wide_ops_8616(signed: bool | None) -> tuple[ConditionOp, ...]:
    """Restrict candidates to the proven ordering family."""
    if signed is True:
        return ("eq", "ne", "slt", "sle", "sgt", "sge")
    if signed is False:
        return ("eq", "ne", "ult", "ule", "ugt", "uge")
    return ("eq", "ne")


def prove_wide_ordering_operator_8616(
    signed: bool | None,
    evaluate: WideOrderingEvaluator8616,
) -> ConditionOp | None:
    """Require a unique operator matching every target-directed CFG outcome.

    Unknown paths refuse. High-word ordering dominates unless the high words
    are equal; only then does the unsigned low-word order determine the result.
    The evaluator must not materialize C or mutate the graph while proving it.
    """
    outcome: object
    high: object
    low: object
    outcomes: dict[tuple[cython.longlong, cython.longlong], cython.bint] = {}
    for high in ORDERING_RELATIONS8616:
        for low in ORDERING_RELATIONS8616:
            outcome = evaluate(high, low)
            if outcome is None:
                return None
            outcomes[(high, low)] = outcome
    matches = tuple(
        op
        for op in builtins.iter(candidate_wide_ops_8616(signed))
        if all(
            operator.eq(wide_operator_result_8616(op, high if high != 0 else low), outcome)
            for (high, low), outcome in builtins.iter(outcomes.items())
        )
    )
    return matches[0] if len(matches) == 1 else None
