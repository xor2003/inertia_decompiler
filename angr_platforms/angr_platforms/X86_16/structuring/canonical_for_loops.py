"""Canonicalize fully proven pre-test induction loops.

Layer: Structuring.
Responsibility: canonicalize a fully proven pre-test induction loop without changing its semantics.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.
Every ambiguous guard, iterator, storage identity, or rendered shape remains unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import pairwise
from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CContinue,
    CDoWhileLoop,
    CExpression,
    CForLoop,
    CIfBreak,
    CIfElse,
    CStatement,
    CStatements,
    CSwitchCase,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)

from ..c_ast_utils import (
    _iter_c_node_children_8616,
    _same_c_expression_8616,
)
from ..ir.condition_ir import inverted_comparison_op_8616
from .induction_comparisons import ordered_comparison_uses_induction_8616 as _ordered_comparison_uses_induction_8616


@dataclass(frozen=True, slots=True)
class CanonicalForLoopRecoveryStats8616:
    """Closed evidence counts for canonical ``for`` loop recovery."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def changed(self) -> bool:
        """Return whether at least one proven loop was materialized."""
        return self.materialized_count > 0


@dataclass(frozen=True, slots=True)
class CanonicalLoopValidationShape8616:
    """Typed semantic projection shared with tail validation."""

    condition: CExpression
    suppressed_control_node_ids: frozenset[int]
    suppressed_body_write_node_ids: frozenset[int]


@dataclass(slots=True)
class _RecoveryCounts8616:
    """Mutable accumulator used while walking one C AST."""

    raw: int = 0
    normalized: int = 0
    classified: int = 0
    materialized: int = 0
    failures: int = 0


@dataclass(frozen=True, slots=True)
class _StatementLocation8616:
    """Identity-stable location of one leaf in nested sequence containers."""

    parent: CStatements
    statement: CStatement


class _CFunctionBoundary8616(Protocol):
    """Owned view of the C function root consumed by this pass."""

    statements: CStatement


class _CodegenBoundary8616(Protocol):
    """Typed boundary for the angr codegen fields owned by this pass."""

    cfunc: _CFunctionBoundary8616
    _inertia_canonical_for_loop_recovery_stats_8616: CanonicalForLoopRecoveryStats8616


def _unconditional_while_8616(loop: CWhileLoop) -> bool:
    """Return whether a structured while loop has an unconditional header."""
    condition = loop.condition
    return condition is None or (
        isinstance(condition, CConstant)
        and isinstance(condition.value, (bool, int))
        and bool(condition.value)
    )


def _same_variable_8616(lhs: object, rhs: object) -> bool:
    """Compare two induction variables by structured storage identity."""
    return isinstance(lhs, CVariable) and isinstance(rhs, CVariable) and _same_c_expression_8616(lhs, rhs)


def _affine_self_update_8616(assignment: CAssignment, induction: CVariable) -> bool:
    """Prove that an assignment is an affine update of one induction variable."""
    if not _same_variable_8616(assignment.lhs, induction):
        return False
    rhs = assignment.rhs
    if not isinstance(rhs, CBinaryOp) or rhs.op not in {"Add", "Sub"}:
        return False
    if rhs.op == "Sub":
        return _same_variable_8616(rhs.lhs, induction) and isinstance(rhs.rhs, CConstant)
    return (
        _same_variable_8616(rhs.lhs, induction)
        and isinstance(rhs.rhs, CConstant)
    ) or (
        isinstance(rhs.lhs, CConstant)
        and _same_variable_8616(rhs.rhs, induction)
    )


def _pretest_break_condition_8616(statement: CStatement) -> CExpression | None:
    """Extract the condition from one exact structured conditional break."""
    if isinstance(statement, CIfBreak):
        return cast(CExpression, statement.condition)
    if (
        not isinstance(statement, CIfElse)
        or statement.else_node is not None
        or len(statement.condition_and_nodes) != 1
    ):
        return None
    condition, branch = statement.condition_and_nodes[0]
    if isinstance(branch, CBreak):
        return cast(CExpression, condition)
    if not isinstance(branch, CStatements) or len(branch.statements) != 1:
        return None
    if not isinstance(branch.statements[0], CBreak):
        return None
    return cast(CExpression, condition)


def _zero_constant_8616(expression: object) -> bool:
    """Return whether an expression is the typed integer constant zero."""
    return (
        isinstance(expression, CConstant)
        and isinstance(expression.value, (bool, int))
        and not bool(expression.value)
    )


def _zero_break_induction_8616(condition: CExpression) -> CVariable | None:
    """Recover the induction variable from an exact structured zero test."""
    if isinstance(condition, CUnaryOp) and condition.op == "Not":
        if isinstance(condition.operand, CVariable):
            return condition.operand
        if isinstance(condition.operand, CBinaryOp) and condition.operand.op == "CmpNE":
            comparison = condition.operand
        else:
            return None
    elif isinstance(condition, CBinaryOp) and condition.op == "CmpEQ":
        comparison = condition
    else:
        return None
    if isinstance(comparison.lhs, CVariable) and _zero_constant_8616(comparison.rhs):
        return comparison.lhs
    if _zero_constant_8616(comparison.lhs) and isinstance(comparison.rhs, CVariable):
        return comparison.rhs
    return None


def _nonzero_loop_induction_8616(condition: CExpression) -> CVariable | None:
    """Recover the induction variable from an exact structured nonzero test."""
    if isinstance(condition, CVariable):
        return condition
    if isinstance(condition, CUnaryOp) and condition.op == "Not":
        operand = condition.operand
        if not isinstance(operand, CBinaryOp) or operand.op != "CmpEQ":
            return None
        comparison = operand
    elif isinstance(condition, CBinaryOp) and condition.op == "CmpNE":
        comparison = condition
    else:
        return None
    if isinstance(comparison.lhs, CVariable) and _zero_constant_8616(comparison.rhs):
        return comparison.lhs
    if _zero_constant_8616(comparison.lhs) and isinstance(comparison.rhs, CVariable):
        return comparison.rhs
    return None


def _pretest_continuation_condition_8616(
    break_condition: CExpression,
    induction: CVariable,
) -> CExpression | None:
    """Invert one exact leading break into the loop continuation condition."""
    zero_induction = _zero_break_induction_8616(break_condition)
    if zero_induction is not None:
        return induction if _same_variable_8616(zero_induction, induction) else None
    ordered_condition = break_condition
    invert_comparison = True
    if isinstance(break_condition, CUnaryOp) and break_condition.op == "Not":
        operand = break_condition.operand
        if not isinstance(operand, CExpression):
            return None
        ordered_condition = operand
        invert_comparison = False
    if not isinstance(ordered_condition, CBinaryOp) or not _ordered_comparison_uses_induction_8616(
        ordered_condition,
        induction,
    ):
        return None
    if not invert_comparison:
        return ordered_condition
    inverted_op = inverted_comparison_op_8616(ordered_condition.op)
    if inverted_op is None:
        return None
    return CBinaryOp(
        inverted_op,
        ordered_condition.lhs,
        ordered_condition.rhs,
        codegen=ordered_condition.codegen,
        tags=dict(ordered_condition.tags),
    )


def _contains_current_loop_continue_8616(statement: CStatement | None) -> bool:
    """Find a continue targeting the candidate loop, stopping at nested loops."""
    if statement is None:
        return False
    if isinstance(statement, CContinue):
        return True
    if isinstance(statement, (CWhileLoop, CDoWhileLoop, CForLoop)):
        return False
    if isinstance(statement, CStatements):
        return any(_contains_current_loop_continue_8616(child) for child in statement.statements)
    if isinstance(statement, CIfElse):
        return any(
            _contains_current_loop_continue_8616(child)
            for _condition, child in statement.condition_and_nodes
        ) or _contains_current_loop_continue_8616(statement.else_node)
    if isinstance(statement, CSwitchCase):
        return any(
            _contains_current_loop_continue_8616(child)
            for child in _iter_c_node_children_8616(statement.cases)
            if isinstance(child, CStatement)
        ) or _contains_current_loop_continue_8616(statement.default)
    return False


def _break_control_node_ids_8616(statement: CStatement) -> frozenset[int]:
    """Collect control nodes consumed by one proven pre-test break guard."""
    node_ids = {id(statement)}
    if not isinstance(statement, CIfElse):
        return frozenset(node_ids)
    for _condition, branch in statement.condition_and_nodes:
        if isinstance(branch, CBreak):
            node_ids.add(id(branch))
        elif isinstance(branch, CStatements):
            node_ids.update(id(child) for child in branch.statements if isinstance(child, CBreak))
    return frozenset(node_ids)


def _pretest_loop_components_8616(
    loop: CWhileLoop,
) -> tuple[CVariable, CExpression, CStatement | None, CAssignment] | None:
    """Prove a direct or break-guarded pretest with an affine iterator."""
    if not isinstance(loop.body, CStatements):
        return None
    body_locations = _linear_statement_locations_8616(loop.body)
    if not body_locations:
        return None
    iterator = body_locations[-1].statement
    if (
        not isinstance(iterator, CAssignment)
        or not isinstance(iterator.lhs, CVariable)
        or not _affine_self_update_8616(iterator, iterator.lhs)
    ):
        return None
    induction = iterator.lhs
    guard = body_locations[0].statement
    guard_condition = _pretest_break_condition_8616(guard)
    if guard_condition is None and not _unconditional_while_8616(loop):
        condition = loop.condition
        if not isinstance(condition, CExpression):
            return None
        nonzero = _nonzero_loop_induction_8616(condition)
        if (
            (nonzero is not None
            and _same_variable_8616(nonzero, induction))
            or _ordered_comparison_uses_induction_8616(condition, induction)
        ):
            return induction, condition, None, iterator
    if len(body_locations) < 2:
        return None
    if not isinstance(guard_condition, CExpression):
        return None
    continuation = _pretest_continuation_condition_8616(
        guard_condition,
        induction,
    )
    if continuation is None:
        return None
    if not _unconditional_while_8616(loop):
        if not isinstance(loop.condition, CExpression) or not _same_c_expression_8616(
            loop.condition,
            continuation,
        ):
            return None
        continuation = loop.condition
    return induction, continuation, guard, iterator


def _for_loop_induction_8616(loop: CForLoop) -> CVariable | None:
    """Prove the iterator and continuation share one induction storage."""
    condition = loop.condition
    iterator = loop.iterator
    if (
        not isinstance(condition, CExpression)
        or not isinstance(iterator, CAssignment)
        or not isinstance(iterator.lhs, CVariable)
        or not _affine_self_update_8616(iterator, iterator.lhs)
    ):
        return None
    induction = iterator.lhs
    nonzero = _nonzero_loop_induction_8616(condition)
    if nonzero is not None:
        return induction if _same_variable_8616(nonzero, induction) else None
    return (
        induction
        if _ordered_comparison_uses_induction_8616(condition, induction)
        else None
    )


def canonical_loop_validation_shape_8616(
    loop: CWhileLoop | CForLoop,
) -> CanonicalLoopValidationShape8616 | None:
    """Prove the canonical semantic surface shared by while and for forms."""
    if isinstance(loop, CForLoop):
        initializer = loop.initializer
        condition = loop.condition
        induction = _for_loop_induction_8616(loop)
        if induction is None or _contains_current_loop_continue_8616(loop.body):
            return None
        if initializer is not None and (
            not isinstance(initializer, CAssignment)
            or not isinstance(initializer.lhs, CVariable)
            or not _same_variable_8616(initializer.lhs, induction)
        ):
            return None
        return CanonicalLoopValidationShape8616(
            cast(CExpression, condition),
            frozenset(),
            frozenset(),
        )
    components = _pretest_loop_components_8616(loop)
    if components is None or _contains_current_loop_continue_8616(loop.body):
        return None
    induction, continuation, guard, iterator = components
    return CanonicalLoopValidationShape8616(
        condition=continuation,
        suppressed_control_node_ids=(
            _break_control_node_ids_8616(guard) if guard is not None else frozenset()
        ),
        suppressed_body_write_node_ids=frozenset({id(iterator)}),
    )


def _linear_statement_locations_8616(container: CStatements) -> list[_StatementLocation8616]:
    """Project nested sequence containers without crossing control-flow nodes."""
    locations: list[_StatementLocation8616] = []
    for statement in container.statements:
        if isinstance(statement, CStatements):
            locations.extend(_linear_statement_locations_8616(statement))
        elif isinstance(statement, CStatement):
            locations.append(_StatementLocation8616(container, statement))
    return locations


def _identity_index_8616(location: _StatementLocation8616) -> int | None:
    """Resolve a statement location after nearby sequence mutations."""
    return next(
        (
            index
            for index, statement in enumerate(location.parent.statements)
            if statement is location.statement
        ),
        None,
    )


def _materialize_canonical_for_loop_8616(
    initializer_location: _StatementLocation8616,
    loop_location: _StatementLocation8616,
    codegen: _CodegenBoundary8616,
    counts: _RecoveryCounts8616,
) -> bool:
    """Replace one projected initializer-loop pair after complete proof."""
    initializer = initializer_location.statement
    loop = loop_location.statement
    if not isinstance(initializer, CAssignment):
        return False
    if isinstance(loop, CForLoop):
        if loop.initializer is not None:
            return False
        counts.raw += 1
        induction = _for_loop_induction_8616(loop)
        iterator = loop.iterator
        if (
            not isinstance(initializer.lhs, CVariable)
            or induction is None
            or not isinstance(iterator, CAssignment)
            or not _same_variable_8616(initializer.lhs, induction)
            or not _affine_self_update_8616(iterator, induction)
        ):
            return False
        counts.normalized += 1
        if _contains_current_loop_continue_8616(loop.body):
            return False
        counts.classified += 1
        initializer_index = _identity_index_8616(initializer_location)
        if initializer_index is None:
            counts.failures += 1
            return False
        loop.initializer = initializer
        del initializer_location.parent.statements[initializer_index]
        counts.materialized += 1
        return True
    if not isinstance(loop, CWhileLoop):
        return False
    if not isinstance(loop.body, CStatements):
        return False
    body_locations = _linear_statement_locations_8616(loop.body)
    if not body_locations:
        return False
    iterator_location = body_locations[-1]
    iterator = iterator_location.statement
    if not isinstance(iterator, CAssignment):
        return False
    counts.raw += 1
    components = _pretest_loop_components_8616(loop)
    induction = components[0] if components is not None else None
    continuation = components[1] if components is not None else None
    guard = components[2] if components is not None else None
    guard_location = next(
        (location for location in body_locations if location.statement is guard),
        None,
    )
    if (
        not isinstance(initializer.lhs, CVariable)
        or induction is None
        or not _same_variable_8616(initializer.lhs, induction)
        or continuation is None
        or not _affine_self_update_8616(iterator, initializer.lhs)
    ):
        return False
    counts.normalized += 1
    if _contains_current_loop_continue_8616(loop.body):
        return False
    counts.classified += 1
    try:
        canonical = CForLoop(
            initializer,
            continuation,
            iterator,
            loop.body,
            codegen=cast(Any, codegen),
        )
    except (AttributeError, TypeError, ValueError):
        counts.failures += 1
        return False
    location_indexes = (
        _identity_index_8616(initializer_location),
        _identity_index_8616(loop_location),
        _identity_index_8616(iterator_location),
    )
    if any(index is None for index in location_indexes):
        counts.failures += 1
        return False
    loop_index = cast(int, location_indexes[1])
    loop_location.parent.statements[loop_index] = canonical
    consumed_locations = [initializer_location, iterator_location]
    if guard_location is not None:
        consumed_locations.append(guard_location)
    for location in consumed_locations:
        index = _identity_index_8616(location)
        if index is None:
            counts.failures += 1
            return False
        del location.parent.statements[index]
    counts.materialized += 1
    return True


def _recover_nested_loops_8616(
    statement: CStatement | None,
    codegen: _CodegenBoundary8616,
    counts: _RecoveryCounts8616,
) -> None:
    """Walk statement containers and recover loops from the inside out."""
    if statement is None:
        return
    if isinstance(statement, CStatements):
        _recover_statement_list_8616(statement, codegen, counts)
        return
    if isinstance(statement, (CWhileLoop, CDoWhileLoop, CForLoop)):
        _recover_nested_loops_8616(statement.body, codegen, counts)
        return
    if isinstance(statement, CIfElse):
        for _condition, child in statement.condition_and_nodes:
            _recover_nested_loops_8616(child, codegen, counts)
        _recover_nested_loops_8616(statement.else_node, codegen, counts)
        return
    if isinstance(statement, CSwitchCase):
        for child in _iter_c_node_children_8616(statement.cases):
            if isinstance(child, CStatement):
                _recover_nested_loops_8616(child, codegen, counts)
        _recover_nested_loops_8616(statement.default, codegen, counts)


def _recover_statement_list_8616(
    container: CStatements,
    codegen: _CodegenBoundary8616,
    counts: _RecoveryCounts8616,
) -> None:
    """Recover adjacent initializer and while-loop pairs in one container."""
    for statement in tuple(container.statements):
        _recover_nested_loops_8616(statement, codegen, counts)
    while True:
        visible = _linear_statement_locations_8616(container)
        materialized = False
        for initializer, loop in pairwise(visible):
            if _materialize_canonical_for_loop_8616(initializer, loop, codegen, counts):
                materialized = True
                break
        if not materialized:
            return


def recover_canonical_for_loops_8616(codegen: object) -> bool:
    """Recover proven canonical ``for`` loops from a structured C AST."""
    typed_codegen = cast(_CodegenBoundary8616, codegen)
    counts = _RecoveryCounts8616()
    root = typed_codegen.cfunc.statements
    if isinstance(root, CStatements):
        _recover_statement_list_8616(root, typed_codegen, counts)
    stats = CanonicalForLoopRecoveryStats8616(
        raw_fact_count=counts.raw,
        normalized_fact_count=counts.normalized,
        classified_fact_count=counts.classified,
        materialized_count=counts.materialized,
        failure_count=counts.failures,
    )
    typed_codegen._inertia_canonical_for_loop_recovery_stats_8616 = stats
    return stats.changed


__all__ = [
    "CanonicalForLoopRecoveryStats8616",
    "CanonicalLoopValidationShape8616",
    "canonical_loop_validation_shape_8616",
    "recover_canonical_for_loops_8616",
]
