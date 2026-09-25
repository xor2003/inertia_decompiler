"""Structured-AST ancestry evidence for shared-tail call ownership.

Layer: Structuring.
Responsibility: collect exact call occurrences and prove their relative
ownership in structured statement lists without interpreting call semantics.

Owns structured ancestry and statement ordering from the generated AST.
Do not infer call arguments, return types, alias identity, or rendered-C facts.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c

from ..c_ast_utils import _iter_c_nodes_deep_8616

__all__ = (
    "SharedTailCallOccurrence8616",
    "SharedTailCallOccurrenceKind8616",
    "collect_shared_tail_call_occurrences_8616",
    "standalone_follows_nested_clone_8616",
)


@dataclass(frozen=True, slots=True)
class _ControlPathStep8616:
    """One structured control arm and its position in the enclosing sequence."""

    owner_id: int
    parent_statements_id: int
    owner_index: int
    arm_kind: str
    arm_index: int
    parent: structured_c.CStatements = field(compare=False, repr=False)


class SharedTailCallOccurrenceKind8616(Enum):
    """Supported exact AST occurrences of one machine callsite."""

    CONDITION = "condition"
    RETURNED = "returned"
    RETURN_CARRIER = "return_carrier"
    STANDALONE = "standalone"


@dataclass(frozen=True, slots=True)
class SharedTailCallOccurrence8616:
    """One writable exact call occurrence at the third-party AST boundary."""

    kind: SharedTailCallOccurrenceKind8616
    call: structured_c.CFunctionCall
    statement: object
    parent: structured_c.CStatements
    statement_index: int
    control_path: tuple[_ControlPathStep8616, ...]
    destination_variable: object | None = None


def _ifelse_arms_8616(
    statement: structured_c.CIfElse,
) -> tuple[tuple[str, int, structured_c.CStatements], ...]:
    """Return writable statement-list arms from one third-party if/else node."""
    result: list[tuple[str, int, structured_c.CStatements]] = []
    pairs = statement.condition_and_nodes
    if isinstance(pairs, (list, tuple)):
        for index, pair in enumerate(pairs):
            if isinstance(pair, tuple) and len(pair) == 2 and isinstance(pair[1], structured_c.CStatements):
                result.append(("if", index, pair[1]))
    if isinstance(statement.else_node, structured_c.CStatements):
        result.append(("else", 0, statement.else_node))
    return tuple(result)


def _child_statement_arms_8616(
    statement: structured_c.CStatement,
) -> tuple[tuple[str, int, structured_c.CStatements], ...]:
    """Return supported structured child arms without interpreting conditions."""
    if isinstance(statement, structured_c.CIfElse):
        return _ifelse_arms_8616(statement)
    result: list[tuple[str, int, structured_c.CStatements]] = []
    if isinstance(statement, (structured_c.CDoWhileLoop, structured_c.CForLoop, structured_c.CWhileLoop)):  # noqa: SIM102
        if isinstance(statement.body, structured_c.CStatements):
            result.append(("body", 0, statement.body))
    if isinstance(statement, structured_c.CSwitchCase):
        cases = cast(Any, statement).cases
        if isinstance(cases, (list, tuple)):
            for index, case in enumerate(cases):
                if isinstance(case, tuple) and len(case) == 2 and isinstance(case[1], structured_c.CStatements):
                    result.append(("case", index, case[1]))
        default = cast(Any, statement).default
        if isinstance(default, structured_c.CStatements):
            result.append(("default", 0, default))
    return tuple(result)


def _condition_calls_8616(
    statement: structured_c.CStatement,
) -> tuple[structured_c.CFunctionCall, ...]:
    """Collect calls embedded in one third-party structured condition."""
    expressions: list[structured_c.CExpression] = []
    if isinstance(statement, structured_c.CIfElse):
        pairs = statement.condition_and_nodes
        if isinstance(pairs, (list, tuple)):
            expressions.extend(
                pair[0]
                for pair in pairs
                if isinstance(pair, tuple)
                and len(pair) == 2
                and isinstance(pair[0], structured_c.CExpression)
            )
    elif isinstance(
        statement,
        (
            structured_c.CDoWhileLoop,
            structured_c.CForLoop,
            structured_c.CIfBreak,
            structured_c.CWhileLoop,
        ),
    ) and isinstance(statement.condition, structured_c.CExpression):
        expressions.append(statement.condition)
    return tuple(
        node
        for expression in expressions
        for node in _iter_c_nodes_deep_8616(expression)
        if isinstance(node, structured_c.CFunctionCall)
    )


def collect_shared_tail_call_occurrences_8616(
    root: structured_c.CStatements,
) -> tuple[SharedTailCallOccurrence8616, ...]:
    """Collect supported call occurrences with exact structured ancestry."""
    occurrences: list[SharedTailCallOccurrence8616] = []
    pending: list[tuple[structured_c.CStatements, tuple[_ControlPathStep8616, ...]]] = [(root, ())]
    seen: set[int] = set()
    while pending:
        parent, control_path = pending.pop()
        if id(parent) in seen:
            continue
        seen.add(id(parent))
        statements = parent.statements
        if not isinstance(statements, list):
            continue
        for index, statement in enumerate(statements):
            _collect_statement_8616(
                statement,
                parent,
                index,
                control_path,
                occurrences,
                pending,
            )
    return tuple(occurrences)


def _collect_statement_8616(
    statement: object,
    parent: structured_c.CStatements,
    index: int,
    control_path: tuple[_ControlPathStep8616, ...],
    occurrences: list[SharedTailCallOccurrence8616],
    pending: list[tuple[structured_c.CStatements, tuple[_ControlPathStep8616, ...]]],
) -> None:
    """Collect call occurrences for one statement and queue its children."""
    if isinstance(statement, structured_c.CFunctionCall):
        occurrences.append(
            SharedTailCallOccurrence8616(
                SharedTailCallOccurrenceKind8616.STANDALONE,
                statement,
                statement,
                parent,
                index,
                control_path,
            )
        )
        return
    if isinstance(statement, structured_c.CStatements):
        step = _ControlPathStep8616(id(statement), id(parent), index, "statements", 0, parent)
        pending.append((statement, (*control_path, step)))
        return
    if not isinstance(statement, structured_c.CStatement):
        return
    occurrences.extend(
        SharedTailCallOccurrence8616(
            SharedTailCallOccurrenceKind8616.CONDITION,
            call,
            statement,
            parent,
            index,
            control_path,
        )
        for call in _condition_calls_8616(statement)
    )
    kinded = _kinded_occurrence_8616(statement, parent, index, control_path)
    if kinded is not None:
        occurrences.append(kinded)
    for arm_kind, arm_index, child in _child_statement_arms_8616(statement):
        step = _ControlPathStep8616(
            id(statement),
            id(parent),
            index,
            arm_kind,
            arm_index,
            parent,
        )
        pending.append((child, (*control_path, step)))


def _kinded_occurrence_8616(
    statement: structured_c.CStatement,
    parent: structured_c.CStatements,
    index: int,
    control_path: tuple[_ControlPathStep8616, ...],
) -> SharedTailCallOccurrence8616 | None:
    """Return the call occurrence carried by one statement's kind, if any."""
    if isinstance(statement, structured_c.CReturn) and isinstance(
        statement.retval,
        structured_c.CFunctionCall,
    ):
        return SharedTailCallOccurrence8616(
            SharedTailCallOccurrenceKind8616.RETURNED,
            statement.retval,
            statement,
            parent,
            index,
            control_path,
        )
    if (
        isinstance(statement, structured_c.CAssignment)
        and isinstance(statement.rhs, structured_c.CFunctionCall)
        and isinstance(statement.lhs, structured_c.CVariable)
        and isinstance(statement.lhs.name, str)
    ):
        return SharedTailCallOccurrence8616(
            SharedTailCallOccurrenceKind8616.RETURN_CARRIER,
            statement.rhs,
            statement,
            parent,
            index,
            control_path,
            statement.lhs.variable,
        )
    if isinstance(statement, structured_c.CExpressionStatement) and isinstance(
        statement.expr,
        structured_c.CFunctionCall,
    ):
        return SharedTailCallOccurrence8616(
            SharedTailCallOccurrenceKind8616.STANDALONE,
            statement.expr,
            statement,
            parent,
            index,
            control_path,
        )
    return None


def standalone_follows_nested_clone_8616(
    nested: SharedTailCallOccurrence8616,
    standalone: SharedTailCallOccurrence8616,
) -> bool:
    """Prove that one trailing call statement follows a nested occurrence."""
    if standalone.kind not in (
        SharedTailCallOccurrenceKind8616.RETURN_CARRIER,
        SharedTailCallOccurrenceKind8616.STANDALONE,
    ):
        return False
    nested_controls = tuple(step for step in nested.control_path if step.arm_kind != "statements")
    standalone_controls = tuple(step for step in standalone.control_path if step.arm_kind != "statements")
    if len(nested_controls) <= len(standalone_controls):
        return False
    if nested_controls[: len(standalone_controls)] != standalone_controls:
        return False
    common_length = 0
    for nested_step, standalone_step in zip(nested.control_path, standalone.control_path, strict=False):
        if nested_step != standalone_step:
            break
        common_length += 1
    nested_boundary = nested.control_path[common_length]
    if common_length < len(standalone.control_path):
        standalone_boundary = standalone.control_path[common_length]
        standalone_parent = standalone_boundary.parent
        standalone_index = standalone_boundary.owner_index
    else:
        standalone_parent = standalone.parent
        standalone_index = standalone.statement_index
    if nested_boundary.parent_statements_id != id(standalone_parent):
        return False
    if nested_boundary.owner_index >= standalone_index:
        return False
    statements = standalone_parent.statements
    if not isinstance(statements, list):
        return False
    intervening = statements[nested_boundary.owner_index + 1 : standalone_index]
    return not any(
        isinstance(item, (structured_c.CBreak, structured_c.CGoto, structured_c.CReturn))
        for item in intervening
    )
