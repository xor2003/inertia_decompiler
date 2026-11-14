# cython: language_level=3, infer_types=True
"""Expose exact structured condition carriers for pretest loops.

Layer: Structuring.
Responsibility: project a pretest loop's explicit header and unique leading
break guard as typed C expressions for Structuring consumers.
This module identifies only C-AST shape. It does not infer condition meaning,
invert predicates, recover values or types, or perform rewrite cleanup.

Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence. Do not perform alias-state ownership, widening,
type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen.c import (
    CBreak,
    CExpression,
    CForLoop,
    CIfBreak,
    CIfElse,
    CStatements,
    CWhileLoop,
)
import dataclasses


@dataclasses.dataclass(frozen=True, )
class PretestConditionSurface8616:
    """Typed condition carriers owned by one structured pretest loop."""

    conditions: object
    leading_break_guard: CIfBreak | CIfElse | None


@cython.ccall
def _first_executable_statement_8616(node: object) -> object | None:
    """Return the first node reached through statement-list wrappers only."""
    candidate: object
    statement: object
    if not isinstance(node, CStatements):
        return node
    for statement in node.statements:
        candidate = _first_executable_statement_8616(statement)
        if candidate is not None:
            return candidate
    return None


@cython.ccall
def _break_only_8616(node: object) -> cython.bint:
    """Return whether ``node`` contains exactly one unconditional break."""
    if isinstance(node, CBreak):
        return True
    return (
        isinstance(node, CStatements)
        and len(node.statements) == 1
        and _break_only_8616(node.statements[0])
    )


@cython.ccall
def _leading_break_condition_8616(
    node: object,
) -> object:
    """Return one exact leading break condition and its structured owner."""
    if isinstance(node, CIfBreak):
        return (node.condition, node) if isinstance(node.condition, CExpression) else None
    if not isinstance(node, CIfElse) or node.else_node is not None:
        return None
    arms = tuple(node.condition_and_nodes)
    if len(arms) != 1:
        return None
    condition, body = arms[0]
    if not isinstance(condition, CExpression) or not _break_only_8616(body):
        return None
    return condition, node


def pretest_condition_surface_8616(
    loop: CForLoop | CWhileLoop,
) -> PretestConditionSurface8616:
    """Project exact header and leading-break expressions without semantics."""
    leading: object
    conditions: list[CExpression] = []
    if isinstance(loop.condition, CExpression):
        conditions.append(loop.condition)

    leading = _leading_break_condition_8616(
        _first_executable_statement_8616(loop.body)
    )
    guard = leading[1] if leading is not None else None
    if leading is not None and all(leading[0] is not item for item in iter(conditions)):
        conditions.append(leading[0])
    return PretestConditionSurface8616(tuple(conditions), guard)
