"""Materialize early exits from stored call-return conditions.

Layer: Structuring.
Responsibility: bind exact Lowering-owned call-return stack conditions to
terminal branch placeholders while preserving the continuation body.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Consumes typed condition/storage evidence and semantic branch-return effects.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here. Call discovery,
source/COD/name evidence, rendered text, and guessed return values are forbidden.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CExpression,
    CIfElse,
    CReturn,
    CStatements,
)

from ..c_ast_utils import _iter_c_nodes_deep_8616, _same_c_expression_8616
from ..lowering.call_return_stack_conditions import (
    StoredCallReturnConditionEvidence8616,
    classify_stored_call_return_condition_8616,
)
from .branch_return_expressions import (
    branch_target_preserves_return_registers_8616,
    recover_branch_target_return_expression_8616,
    sole_return_statement_8616,
)
from .call_return_conditions import structured_condition_key_8616
from .stored_call_return_operands import stored_return_operand_8616

__all__ = [
    "StoredCallReturnEarlyExitEvidence8616",
    "StoredCallReturnEarlyExitResult8616",
    "StoredCallReturnEarlyExitStatus8616",
    "materialize_stored_call_return_early_exit_8616",
]


class StoredCallReturnEarlyExitStatus8616(StrEnum):
    """Outcome of one stored call-return early-exit decision."""

    NOT_APPLICABLE = "not_applicable"
    REFUSED = "refused"
    ALREADY_MATERIALIZED = "already_materialized"
    MATERIALIZED = "materialized"


@dataclass(frozen=True, slots=True)
class StoredCallReturnEarlyExitEvidence8616:
    """Closed evidence accounting for one early-exit materialization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class StoredCallReturnEarlyExitResult8616:
    """Typed result of one early-exit Structuring pass."""

    changed: bool
    status: StoredCallReturnEarlyExitStatus8616
    evidence: StoredCallReturnEarlyExitEvidence8616


class _StoredReturnCFunction8616(Protocol):
    """Structured function root consumed by this pass."""

    statements: object


class _StoredReturnCodegen8616(Protocol):
    """Owned codegen fields consumed and published by this pass."""

    cfunc: _StoredReturnCFunction8616
    _inertia_stored_call_return_early_exit_result_8616: StoredCallReturnEarlyExitResult8616


def _terminal_return_8616(body: object) -> CReturn | None:
    """Return one unique return occupying the continuation's terminal leaf."""
    returns = tuple(
        node
        for node in (body, *_iter_c_nodes_deep_8616(body))
        if isinstance(node, CReturn)
    )
    if len({id(node): node for node in returns}) != 1:
        return None
    current = body
    for _depth in range(12):
        if isinstance(current, CReturn):
            return current if current is returns[0] else None
        if not isinstance(current, CStatements):
            return None
        statements = tuple(current.statements or ())
        if not statements:
            return None
        current = statements[-1]
    return None


def _statement_container_8616(root: CStatements, statement: object) -> tuple[CStatements, int] | None:
    """Return the unique direct statement container and index."""
    matches: dict[tuple[int, int], tuple[CStatements, int]] = {}
    for candidate in (root, *_iter_c_nodes_deep_8616(root)):
        if not isinstance(candidate, CStatements):
            continue
        for index, child in enumerate(tuple(candidate.statements or ())):
            if child is statement:
                matches[(id(candidate), index)] = (candidate, index)
    return next(iter(matches.values())) if len(matches) == 1 else None


def _terminal_return_after_8616(container: CStatements, index: int) -> CReturn | None:
    """Return the unique terminal return after one flattened early-exit branch."""
    suffix = tuple(container.statements or ())[index + 1 :]
    returns = tuple(
        node
        for statement in suffix
        for node in (statement, *_iter_c_nodes_deep_8616(statement))
        if isinstance(node, CReturn)
    )
    if len({id(node): node for node in returns}) != 1 or not suffix:
        return None
    current = suffix[-1]
    for _depth in range(12):
        if isinstance(current, CReturn):
            return current if current is returns[0] else None
        if not isinstance(current, CStatements):
            return None
        statements = tuple(current.statements or ())
        if not statements:
            return None
        current = statements[-1]
    return None


def _matching_candidate_8616(
    project: object,
    codegen: object,
    root: CStatements,
) -> tuple[CIfElse, CExpression, StoredCallReturnConditionEvidence8616] | None:
    """Return one unique structured branch backed by exact stored-return evidence."""
    candidates: list[tuple[CIfElse, CExpression, StoredCallReturnConditionEvidence8616]] = []
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CIfElse) or len(node.condition_and_nodes) != 1:
            continue
        condition, _body = node.condition_and_nodes[0]
        key = structured_condition_key_8616(condition)
        if key is None:
            continue
        evidence = classify_stored_call_return_condition_8616(
            project,
            codegen,
            jcc_addr=key[0],
            block_addr=key[1],
        )
        if evidence is not None:
            candidates.append((node, condition, evidence))
    return candidates[0] if len(candidates) == 1 else None


def _result_8616(
    codegen: _StoredReturnCodegen8616,
    status: StoredCallReturnEarlyExitStatus8616,
    evidence: StoredCallReturnEarlyExitEvidence8616,
    *,
    changed: bool = False,
) -> StoredCallReturnEarlyExitResult8616:
    """Publish one typed Structuring result on the codegen owner."""
    result = StoredCallReturnEarlyExitResult8616(changed, status, evidence)
    codegen._inertia_stored_call_return_early_exit_result_8616 = result
    return result


def _refused_result_8616(
    codegen: _StoredReturnCodegen8616,
) -> StoredCallReturnEarlyExitResult8616:
    """Publish one closed refusal for incomplete or conflicting evidence."""
    return _result_8616(
        codegen,
        StoredCallReturnEarlyExitStatus8616.REFUSED,
        StoredCallReturnEarlyExitEvidence8616(1, 1, 0, 0, 1),
    )


@dataclass(slots=True)
class _EarlyExitPrelude8616:
    """Validated boundary evidence for one stored-call early exit."""

    typed_codegen: _StoredReturnCodegen8616
    branch: CIfElse
    return_operand: CExpression
    true_body: object
    true_return: CReturn | None
    statement_container: CStatements
    branch_index: int
    final_expression: CExpression
    true_ready: bool


def _not_applicable_result_8616(
    typed_codegen: _StoredReturnCodegen8616,
) -> StoredCallReturnEarlyExitResult8616:
    """Publish one empty not-applicable result for a missing boundary."""
    return _result_8616(
        typed_codegen,
        StoredCallReturnEarlyExitStatus8616.NOT_APPLICABLE,
        StoredCallReturnEarlyExitEvidence8616(),
    )


def _early_exit_prelude_8616(
    project: object,
    codegen: object,
) -> _EarlyExitPrelude8616 | StoredCallReturnEarlyExitResult8616:
    """Resolve and validate the early-exit boundary or produce the result."""
    typed_codegen = cast(_StoredReturnCodegen8616, codegen)
    try:
        root = typed_codegen.cfunc.statements
    except AttributeError:
        return _not_applicable_result_8616(typed_codegen)
    if not isinstance(root, CStatements):
        return _not_applicable_result_8616(typed_codegen)
    candidate = _matching_candidate_8616(project, codegen, root)
    if candidate is None:
        return _not_applicable_result_8616(typed_codegen)
    branch, condition, stored_evidence = candidate
    return_operand = stored_return_operand_8616(
        condition,
        stored_evidence,
        project,
        codegen,
    )
    true_body = branch.condition_and_nodes[0][1]
    true_return = sole_return_statement_8616(true_body)
    taken_target = stored_evidence.condition.taken_target
    fallthrough_target = stored_evidence.condition.fallthrough_target
    container = _statement_container_8616(root, branch)
    if (
        return_operand is None
        or not isinstance(taken_target, int)
        or not isinstance(fallthrough_target, int)
        or container is None
    ):
        return _refused_result_8616(typed_codegen)
    statement_container, branch_index = container
    error_expression = recover_branch_target_return_expression_8616(
        project,
        codegen,
        fallthrough_target,
    )
    final_expression = recover_branch_target_return_expression_8616(
        project,
        codegen,
        taken_target,
    )
    error_ready = isinstance(error_expression, CExpression) and _same_c_expression_8616(
        error_expression,
        return_operand,
    )
    if not error_ready:
        error_ready = branch_target_preserves_return_registers_8616(
            project,
            fallthrough_target,
        )
    if (
        not error_ready
        or not isinstance(final_expression, CExpression)
    ):
        return _refused_result_8616(typed_codegen)
    true_ready = true_return is not None and (
        true_return.retval is return_operand
        or _same_c_expression_8616(true_return.retval, return_operand)
    )
    return _EarlyExitPrelude8616(
        typed_codegen=typed_codegen,
        branch=branch,
        return_operand=return_operand,
        true_body=true_body,
        true_return=true_return,
        statement_container=statement_container,
        branch_index=branch_index,
        final_expression=final_expression,
        true_ready=true_ready,
    )


def _materialize_flattened_exit_8616(
    prelude: _EarlyExitPrelude8616,
) -> StoredCallReturnEarlyExitResult8616:
    """Materialize or validate the flattened early exit without an else node."""
    typed_codegen = prelude.typed_codegen
    true_body = prelude.true_body
    true_return = prelude.true_return
    statement_container = prelude.statement_container
    branch_index = prelude.branch_index
    final_expression = prelude.final_expression
    final_return = _terminal_return_after_8616(statement_container, branch_index)
    suffix = tuple(statement_container.statements or ())[branch_index + 1 :]
    has_suffix_return = any(
        isinstance(node, CReturn)
        for statement in suffix
        for node in (statement, *_iter_c_nodes_deep_8616(statement))
    )
    if true_return is None:
        if not isinstance(true_body, CStatements) or tuple(true_body.statements or ()):
            return _refused_result_8616(typed_codegen)
    elif not prelude.true_ready:
        return _refused_result_8616(typed_codegen)
    if final_return is None and has_suffix_return:
        return _refused_result_8616(typed_codegen)
    if final_return is not None and not _same_c_expression_8616(
        final_return.retval,
        final_expression,
    ):
        return _refused_result_8616(typed_codegen)
    if true_return is not None and final_return is not None:
        return _result_8616(
            typed_codegen,
            StoredCallReturnEarlyExitStatus8616.ALREADY_MATERIALIZED,
            StoredCallReturnEarlyExitEvidence8616(1, 1, 1, 1, 0),
        )
    if true_return is None:
        assert isinstance(true_body, CStatements)
        true_body.statements = [CReturn(prelude.return_operand, codegen=typed_codegen)]
    if final_return is None:
        statements = list(statement_container.statements or ())
        statements.append(CReturn(final_expression, codegen=typed_codegen))
        statement_container.statements = statements
    return _result_8616(
        typed_codegen,
        StoredCallReturnEarlyExitStatus8616.MATERIALIZED,
        StoredCallReturnEarlyExitEvidence8616(1, 1, 1, 1, 0),
        changed=True,
    )


def _materialize_spliced_exit_8616(
    prelude: _EarlyExitPrelude8616,
) -> StoredCallReturnEarlyExitResult8616:
    """Splice the proven continuation out of an else-body early exit."""
    typed_codegen = prelude.typed_codegen
    branch = prelude.branch
    else_node = branch.else_node
    true_return = prelude.true_return
    if not isinstance(else_node, CStatements) or true_return is None:
        return _refused_result_8616(typed_codegen)
    false_return = _terminal_return_8616(else_node)
    if false_return is None:
        return _refused_result_8616(typed_codegen)
    false_ready = _same_c_expression_8616(false_return.retval, prelude.final_expression)
    if true_return.retval is not None and not prelude.true_ready:
        return _refused_result_8616(typed_codegen)
    if false_return.retval is not None and not false_ready:
        return _refused_result_8616(typed_codegen)
    true_return.retval = prelude.return_operand
    false_return.retval = prelude.final_expression
    continuation = tuple(else_node.statements or ())
    branch.else_node = None
    statements = list(prelude.statement_container.statements or ())
    statements[prelude.branch_index : prelude.branch_index + 1] = [branch, *continuation]
    prelude.statement_container.statements = statements
    return _result_8616(
        typed_codegen,
        StoredCallReturnEarlyExitStatus8616.MATERIALIZED,
        StoredCallReturnEarlyExitEvidence8616(1, 1, 1, 1, 0),
        changed=True,
    )


def materialize_stored_call_return_early_exit_8616(
    project: object,
    codegen: object,
) -> StoredCallReturnEarlyExitResult8616:
    """Materialize a stored error return and its proven continuation return."""
    prelude = _early_exit_prelude_8616(project, codegen)
    if isinstance(prelude, StoredCallReturnEarlyExitResult8616):
        return prelude
    if prelude.branch.else_node is None:
        return _materialize_flattened_exit_8616(prelude)
    return _materialize_spliced_exit_8616(prelude)
