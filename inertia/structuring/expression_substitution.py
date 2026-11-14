# cython: language_level=3, infer_types=True
"""Substitute exact leaves in structured C expressions.

Layer: Structuring.
Responsibility: Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.

This module does not recover calls, arguments, aliases, or types. Callers must
provide both the exact source node and its evidence-backed replacement.
"""

from __future__ import annotations
import cython

from collections.abc import Callable, Iterable

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CExpression, CIfElse, CUnaryOp
import builtins


def unique_tagged_conditions_8616(
    root: object,
    iter_nodes: Callable[[object], Iterable[object]],
    condition_key: Callable[[object], object],
) -> dict[tuple[cython.longlong, cython.longlong], CExpression]:
    """Index only uniquely owned structured conditions by exact JCC and block tags."""
    _body: object
    condition: object
    node: object
    candidates: dict[tuple[cython.longlong, cython.longlong], list[CExpression]] = {}
    for node in iter_nodes(root):
        if not isinstance(node, CIfElse):
            continue
        for condition, _body in node.condition_and_nodes:
            key = condition_key(condition)
            if (
                isinstance(condition, CExpression)
                and isinstance(key, tuple)
                and len(key) == 2
                and all(isinstance(value, int) for value in iter(key))
            ):
                candidates.setdefault((int(key[0]), int(key[1])), []).append(condition)
    return {key: values[0] for key, values in builtins.iter(candidates.items()) if len(values) == 1}


@cython.ccall
def replace_exact_expression_8616(
    expression: CExpression,
    source: CExpression,
    replacement: CExpression,
) -> CExpression:
    """Replace one identity-matched expression leaf while preserving its owners."""
    if expression is source:
        return replacement
    if isinstance(expression, CBinaryOp):
        expression.lhs = replace_exact_expression_8616(expression.lhs, source, replacement)
        expression.rhs = replace_exact_expression_8616(expression.rhs, source, replacement)
    elif isinstance(expression, CUnaryOp):
        expression.operand = replace_exact_expression_8616(expression.operand, source, replacement)
    return expression
