"""Locate proven structured carriers for binary call-argument joins.

Layer: Structuring.
Responsibility: Match Alias-owned incoming constants to one existing C branch
carrier and prove that the carrier dominates its call without redefinition.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.
This module owns structured AST shape only; it does not recover aliases,
types, call signatures, or semantics from rendered text.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CFunctionCall,
    CIfElse,
    CStatements,
    CTypeCast,
    CVariable,
)

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616, _same_c_expression_8616

__all__ = ["branch_dominates_call_8616", "unique_branch_carrier_8616"]


def _constant_value_8616(expression: object) -> int | None:
    """Return an exact integer C constant after transparent typed casts."""
    while isinstance(expression, CTypeCast):
        expression = expression.expr
    if not isinstance(expression, CConstant):
        return None
    value = expression.value
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _assignments_of_value_8616(node: object, value: int) -> tuple[CAssignment, ...]:
    """Collect exact constant assignments in one already structured arm."""
    return tuple(
        candidate
        for candidate in _iter_c_nodes_deep_8616(node)
        if isinstance(candidate, CAssignment) and _constant_value_8616(candidate.rhs) == value
    )


def _branch_carrier_8616(branch: CIfElse, values: tuple[int, int]) -> CVariable | None:
    """Return the unique lvalue assigned both incoming values by distinct arms."""
    arms = tuple(node for _condition, node in branch.condition_and_nodes if node is not None)
    if branch.else_node is not None:
        arms += (branch.else_node,)
    if len(arms) < 2:
        return None
    assignments_by_value = tuple(
        tuple(
            (arm_index, assignment)
            for arm_index, arm in enumerate(arms)
            for assignment in _assignments_of_value_8616(arm, value)
        )
        for value in values
    )
    if any(len(assignments) != 1 for assignments in assignments_by_value):
        return None
    (left_arm, left_assignment), (right_arm, right_assignment) = (
        assignments[0] for assignments in assignments_by_value
    )
    left_lhs = left_assignment.lhs
    right_lhs = right_assignment.lhs
    if (
        left_arm == right_arm
        or not isinstance(left_lhs, CVariable)
        or not isinstance(right_lhs, CVariable)
        or not _same_c_expression_8616(left_lhs, right_lhs)
    ):
        return None
    return left_lhs


def unique_branch_carrier_8616(
    root: object,
    values: tuple[int, int],
) -> tuple[CIfElse, CVariable] | None:
    """Find one unambiguous structured binary branch carrying both values."""
    matches = tuple(
        (node, carrier)
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CIfElse)
        if (carrier := _branch_carrier_8616(node, values)) is not None
    )
    return matches[0] if len(matches) == 1 else None


def _contains_node_8616(root: object, target: object) -> bool:
    """Return whether one AST subtree contains the exact target node."""
    return any(node is target for node in _iter_c_nodes_deep_8616(root))


def _assigns_carrier_8616(root: object, carrier: CVariable) -> bool:
    """Return whether one subtree redefines the selected branch carrier."""
    return any(
        isinstance(node, CAssignment) and _same_c_expression_8616(node.lhs, carrier)
        for node in _iter_c_nodes_deep_8616(root)
    )


def branch_dominates_call_8616(
    root: object,
    branch: CIfElse,
    carrier: CVariable,
    call: CFunctionCall,
) -> bool:
    """Prove statement order and no carrier redefinition before the call."""
    placements = 0
    for container in _iter_c_nodes_deep_8616(root):
        if not isinstance(container, CStatements):
            continue
        branch_indices = tuple(index for index, statement in enumerate(container.statements) if statement is branch)
        if len(branch_indices) != 1:
            continue
        branch_index = branch_indices[0]
        call_indices = tuple(
            index
            for index, statement in enumerate(container.statements)
            if index > branch_index and _contains_node_8616(statement, call)
        )
        if len(call_indices) != 1:
            continue
        call_index = call_indices[0]
        if any(
            _assigns_carrier_8616(statement, carrier)
            for statement in container.statements[branch_index + 1 : call_index + 1]
        ):
            continue
        placements += 1
    return placements == 1
