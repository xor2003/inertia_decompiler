# cython: language_level=3, infer_types=True
"""Prove read-before-store order for a pure scalar C assignment.

Layer: Types/Lowering.
Responsibility: classify assignment evaluation order without changing the AST or
granting register provenance. Calls, nested stores, unsupported operators and
cyclic expression graphs remain unknown.
Consumes alias, widening, and typed facts
Do not recover semantics from COD, source, assembly, or rendered C text
"""
from __future__ import annotations
import typing
import cython

from collections.abc import Callable
from enum import StrEnum
from typing import TypeGuard

from angr.analyses.decompiler.structured_codegen import c

from .c_ast_utils import iter_c_direct_children_8616
import builtins

_PURE_BINARY_OPERATORS: frozenset[str] = frozenset({
    "Add", "Sub", "Mul", "Div", "Mod", "And", "Or", "Xor", "Shl", "Shr",
    "CmpEQ", "CmpNE", "CmpLT", "CmpLE", "CmpGT", "CmpGE",
    "LogicalAnd", "LogicalOr", "Comma",
})
_PURE_UNARY_OPERATORS: frozenset[str] = frozenset({"Neg", "BitwiseNeg", "LogicalNot"})


class RegisterUpdateOrder8616(StrEnum):
    """Whether a register update has a proven read-before-publication phase."""

    READS_BEFORE_WRITE = "reads_before_write"
    UNKNOWN_REFUSE = "unknown_refuse"


@cython.ccall
def _read_only_node_8616(
    node: object, is_register_leaf: Callable[[object], cython.bint],
) -> TypeGuard[c.CConstruct]:
    """Narrow to a recognized C construct with no storage side effect."""
    if isinstance(node, (c.CConstant, c.CVariable, c.CTypeCast)):
        return True
    if isinstance(node, c.CBinaryOp):
        return node.op in _PURE_BINARY_OPERATORS
    if isinstance(node, c.CUnaryOp):
        return node.op in _PURE_UNARY_OPERATORS
    if isinstance(node, c.CDirtyExpression):
        return is_register_leaf(node)
    return False


def _read_only_expression_8616(root: object, is_register_leaf: Callable[[object], cython.bint]) -> cython.bint:
    """Check every edge while refusing cycles and propagating child-read defects."""
    leaving: object
    node: object
    work: list[tuple[object, cython.bint]] = [(root, False)]
    active: set[cython.longlong] = set()
    complete: set[cython.longlong] = set()
    while work:
        node, leaving = work.pop()
        identity = id(node)
        if leaving:
            active.remove(identity)
            complete.add(identity)
            continue
        if identity in active:
            return False
        if identity in complete:
            continue
        if not _read_only_node_8616(node, is_register_leaf):
            return False
        active.add(identity)
        work.append((node, True))
        work.extend((child, False) for child in builtins.iter(iter_c_direct_children_8616(node)))
    return True


@cython.ccall
def register_update_read_order_8616(
    statement: object, is_register_leaf: Callable[[object], cython.bint],
) -> RegisterUpdateOrder8616:
    """Prove operand reads precede one scalar assignment's destination store.

    The caller separately authenticates register storage and entry versions.
    This proof covers only a top-level assignment with read-only operands;
    control constructs and effectful expression trees receive no ordering.
    """
    if not isinstance(statement, c.CAssignment):
        return RegisterUpdateOrder8616.UNKNOWN_REFUSE
    if not _read_only_expression_8616(statement.lhs, is_register_leaf):
        return RegisterUpdateOrder8616.UNKNOWN_REFUSE
    if not _read_only_expression_8616(statement.rhs, is_register_leaf):
        return RegisterUpdateOrder8616.UNKNOWN_REFUSE
    return RegisterUpdateOrder8616.READS_BEFORE_WRITE
