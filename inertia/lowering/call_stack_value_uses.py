"""Classify structured C value uses before architectural call-context binding.

Layer: Types/Lowering.
Responsibility: retain required call results while recognizing statement-only
and explicitly discarded expressions. No instruction or rendered-text recovery.
"""
from __future__ import annotations

from enum import StrEnum

from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeBottom

from .c_ast_utils import iter_c_direct_children_8616


class CallStackValueUse8616(StrEnum):
    """Whether a C expression must supply a value to its actual consumers."""

    VALUE = 'value'
    DISCARDED = 'discarded'
    UNKNOWN = 'unknown'


_VALUE: CallStackValueUse8616 = CallStackValueUse8616.VALUE
_DISCARDED: CallStackValueUse8616 = CallStackValueUse8616.DISCARDED
_UNKNOWN: CallStackValueUse8616 = CallStackValueUse8616.UNKNOWN


def _merge_use(previous: CallStackValueUse8616, current: CallStackValueUse8616) -> CallStackValueUse8616:
    """Any value consumer retains the result; uncertainty forbids discarding."""
    if _VALUE in (previous, current):
        return _VALUE
    if _UNKNOWN in (previous, current):
        return _UNKNOWN
    return _DISCARDED


def _control_uses(node: c.CConstruct) -> tuple[tuple[object, CallStackValueUse8616], ...] | None:
    """Identify statement versus condition positions in native control nodes."""
    if isinstance(node, c.CStatements):
        return tuple((statement, _DISCARDED) for statement in node.statements)
    if isinstance(node, c.CExpressionStatement):
        return ((node.expr, _DISCARDED),)
    if isinstance(node, c.CIfElse):
        children: list[tuple[object, CallStackValueUse8616]] = []
        for condition, branch in node.condition_and_nodes:
            children.extend(((condition, _VALUE), (branch, _DISCARDED)))
        children.append((node.else_node, _DISCARDED))
        return tuple(children)
    if isinstance(node, c.CForLoop):
        return ((node.initializer, _DISCARDED), (node.condition, _VALUE),
                (node.iterator, _DISCARDED), (node.body, _DISCARDED))
    if isinstance(node, (c.CWhileLoop, c.CDoWhileLoop)):
        return ((node.condition, _VALUE), (node.body, _DISCARDED))
    if isinstance(node, c.CSwitchCase):
        return ((node.switch, _VALUE), *((body, _DISCARDED) for _labels, body in node.cases),
                (node.default, _DISCARDED))
    return None


def _child_uses(node: c.CConstruct, use: CallStackValueUse8616) -> tuple[tuple[object, CallStackValueUse8616], ...]:
    """Follow actual C grammar roles, retaining unknown syntax conservatively."""
    controls = _control_uses(node)
    if controls is not None:
        return controls
    if isinstance(node, c.CMultiStatementExpression):
        return ((node.stmts, _DISCARDED), (node.expr, use))
    if isinstance(node, c.CTypeCast) and isinstance(node.dst_type, SimTypeBottom):
        return ((node.expr, _DISCARDED),)
    if isinstance(node, c.CBinaryOp) and node.op == 'Comma':
        return ((node.lhs, _DISCARDED), (node.rhs, use))
    if isinstance(node, (c.CConstant, c.CVariable)):
        return ()
    if isinstance(node, (c.CExpression, c.CReturn, c.CAssignment)):
        return tuple((child, _VALUE) for child in iter_c_direct_children_8616(node))
    return tuple((child, _UNKNOWN) for child in iter_c_direct_children_8616(node))


def call_stack_value_uses_8616(root: object) -> dict[int, CallStackValueUse8616]:
    """Classify every occurrence; a shared node retains any required value use.

    Function bodies and control bodies discard bare expression values. Return,
    assignment and ordinary expression operands require values. Traversing each
    node/use pair preserves DAG sharing without conflating statement and value
    occurrences or following metadata back-references.
    """
    pending = [(root, _DISCARDED)]
    seen: set[tuple[int, CallStackValueUse8616]] = set()
    result: dict[int, CallStackValueUse8616] = {}
    while pending:
        node, use = pending.pop()
        if not isinstance(node, c.CConstruct) or (id(node), use) in seen:
            continue
        seen.add((id(node), use))
        result[id(node)] = _merge_use(result.get(id(node), use), use)
        pending.extend(_child_uses(node, use))
    return result
