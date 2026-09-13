"""Atomically materialize pure wide-stack predicate return graphs.

Layer: Structuring.
Responsibility: Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence. Classify two CFG return leaves, consume a complete typed wide
predicate graph, and replace the C AST only after all evidence is available.

Instruction side-effect analysis is supplied as an earlier semantic verdict;
this module never decodes instructions or inspects rendered C.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CExpression,
    CIfElse,
    CReturn,
    CStatements,
    CUnaryOp,
)

from ..ir.condition_ir import ConditionIR
from .condition_chain_provenance import bind_condition_chain_provenance_8616
from .wide_stack_condition_chains import WideStackPairProver8616
from .wide_stack_predicate_graphs import (
    WidePredicateExpr8616,
    WidePredicateGraphStatus8616,
    WidePredicateLeaf8616,
    WidePredicateNot8616,
    recover_wide_stack_predicate_graph_8616,
    wide_predicate_exit_targets_8616,
)

type WideReturnRecoverer8616 = Callable[[int], CExpression | None]
type WideReturnComparator8616 = Callable[[CExpression, CExpression], bool]
type WideConditionMaterializer8616 = Callable[[ConditionIR], CExpression | None]


class WideStackReturnPredicateStatus8616(Enum):
    """Typed terminal states for atomic wide-return predicate recovery."""

    MATERIALIZED = "materialized"
    EFFECTS_UNPROVEN = "effects_unproven"
    INCOMPLETE_CFG = "incomplete_cfg"
    PAIR_PROOF_FAILED = "pair_proof_failed"
    RETURN_PROOF_FAILED = "return_proof_failed"
    EXPRESSION_MATERIALIZATION_FAILED = "expression_materialization_failed"


@dataclass(frozen=True, slots=True)
class WideStackReturnPredicateStats8616:
    """Closed evidence accounting for one complete predicate graph."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class WideStackReturnPredicateResult8616:
    """Report the atomic predicate materialization outcome."""

    status: WideStackReturnPredicateStatus8616
    stats: WideStackReturnPredicateStats8616
    wide_condition_count: int = 0

    @property
    def changed(self) -> bool:
        """Return whether the generated C AST was replaced."""
        return self.status is WideStackReturnPredicateStatus8616.MATERIALIZED


class _CFunctionSurface8616(Protocol):
    """Mutable C function root required by the atomic materializer."""

    statements: object


class _CodegenSurface8616(Protocol):
    """Owned metadata attached to the dynamic angr codegen boundary."""

    cfunc: _CFunctionSurface8616
    _inertia_wide_stack_return_predicate_result_8616: WideStackReturnPredicateResult8616


def _record_result_8616(
    boundary: _CodegenSurface8616,
    result: WideStackReturnPredicateResult8616,
) -> WideStackReturnPredicateResult8616:
    """Persist one typed result and optionally expose its evidence accounting."""
    boundary._inertia_wide_stack_return_predicate_result_8616 = result
    if os.environ.get("INERTIA_DEBUG_WIDE_STACK_RETURN_PREDICATE") == "1":
        logging.getLogger(__name__).warning(
            "[wide-stack-return-predicate] status=%s stats=%r wide_conditions=%d",
            result.status.value,
            result.stats,
            result.wide_condition_count,
        )
    return result


def wide_stack_return_predicate_materialized_8616(codegen: object) -> bool:
    """Return whether the canonical owner still owns the active C root."""
    boundary = cast(_CodegenSurface8616, codegen)
    try:
        result = boundary._inertia_wide_stack_return_predicate_result_8616
        root_tags = cast(Any, boundary.cfunc.statements).tags
    except AttributeError:
        return False
    if result.status is not WideStackReturnPredicateStatus8616.MATERIALIZED:
        return False
    return isinstance(root_tags, dict) and root_tags.get("inertia_structuring_wide_stack_return_predicate_8616") is True


def _refused_8616(
    status: WideStackReturnPredicateStatus8616,
    raw_count: int,
    *,
    normalized_count: int = 0,
    classified_count: int = 0,
) -> WideStackReturnPredicateResult8616:
    """Build one closed refusal result."""
    return WideStackReturnPredicateResult8616(
        status,
        WideStackReturnPredicateStats8616(
            raw_fact_count=raw_count,
            normalized_fact_count=normalized_count,
            classified_fact_count=classified_count,
            failure_count=1,
        ),
        normalized_count,
    )


def _materialize_predicate_8616(
    expression: WidePredicateExpr8616,
    materialize_condition: WideConditionMaterializer8616,
    codegen: object,
) -> CExpression | None:
    """Lower one fully proved predicate tree to the active C AST."""
    if isinstance(expression, WidePredicateLeaf8616):
        return materialize_condition(expression.condition)
    if isinstance(expression, WidePredicateNot8616):
        operand = _materialize_predicate_8616(
            expression.operand,
            materialize_condition,
            codegen,
        )
        return CUnaryOp("Not", operand, codegen=codegen) if operand is not None else None
    lhs = _materialize_predicate_8616(expression.lhs, materialize_condition, codegen)
    rhs = _materialize_predicate_8616(expression.rhs, materialize_condition, codegen)
    if lhs is None or rhs is None:
        return None
    op = "LogicalAnd" if expression.op == "and" else "LogicalOr"
    return CBinaryOp(op, lhs, rhs, codegen=codegen)


def materialize_wide_stack_return_predicate_8616(
    codegen: object,
    conditions: tuple[ConditionIR, ...],
    successors: dict[int, tuple[int, ...]],
    prove_pair: WideStackPairProver8616,
    recover_return: WideReturnRecoverer8616,
    same_return: WideReturnComparator8616,
    materialize_condition: WideConditionMaterializer8616,
    *,
    effects_are_safe: bool,
) -> WideStackReturnPredicateResult8616:
    """Atomically replace one complete pure comparison/return CFG."""
    raw_count = len(conditions)
    boundary = cast(_CodegenSurface8616, codegen)
    try:
        previous = boundary._inertia_wide_stack_return_predicate_result_8616
    except AttributeError:
        previous = None
    root = boundary.cfunc.statements
    root_tags = cast(Any, root).tags if root is not None else None
    if (
        isinstance(previous, WideStackReturnPredicateResult8616)
        and previous.status is WideStackReturnPredicateStatus8616.MATERIALIZED
        and isinstance(root_tags, dict)
        and root_tags.get("inertia_structuring_wide_stack_return_predicate_8616") is True
    ):
        return previous
    if not effects_are_safe:
        result = _refused_8616(
            WideStackReturnPredicateStatus8616.EFFECTS_UNPROVEN,
            raw_count,
        )
        return _record_result_8616(boundary, result)
    return_cache: dict[int, CExpression | None] = {}

    def returned(target: int) -> CExpression | None:
        """Cache one classified return leaf expression."""
        if target not in return_cache:
            return_cache[target] = recover_return(target)
        return return_cache[target]

    exits = wide_predicate_exit_targets_8616(conditions)
    returns = tuple((target, returned(target)) for target in exits)
    if any(expression is None for _target, expression in returns):
        result = _refused_8616(
            WideStackReturnPredicateStatus8616.RETURN_PROOF_FAILED,
            raw_count,
        )
        return _record_result_8616(boundary, result)
    unique_returns: list[CExpression] = []
    for _target, expression in returns:
        assert expression is not None
        if not any(same_return(expression, prior) for prior in unique_returns):
            unique_returns.append(expression)
    if len(unique_returns) != 2:
        result = _refused_8616(
            WideStackReturnPredicateStatus8616.RETURN_PROOF_FAILED,
            raw_count,
        )
        return _record_result_8616(boundary, result)
    selected_return, alternate_return = unique_returns

    def classify_exit(target: int) -> bool | None:
        """Classify an exit against the deterministic selected return class."""
        expression = returned(target)
        return same_return(expression, selected_return) if expression is not None else None

    graph = recover_wide_stack_predicate_graph_8616(
        conditions,
        successors,
        prove_pair,
        classify_exit,
    )
    if graph.status is not WidePredicateGraphStatus8616.RECOVERED or graph.expression is None:
        status = (
            WideStackReturnPredicateStatus8616.PAIR_PROOF_FAILED
            if graph.status is WidePredicateGraphStatus8616.PAIR_PROOF_FAILED
            else WideStackReturnPredicateStatus8616.INCOMPLETE_CFG
        )
        result = _refused_8616(
            status,
            raw_count,
            normalized_count=graph.wide_condition_count,
        )
        return _record_result_8616(boundary, result)
    materialized = _materialize_predicate_8616(
        graph.expression,
        materialize_condition,
        codegen,
    )
    if materialized is None or bind_condition_chain_provenance_8616(materialized, conditions) is None:
        result = _refused_8616(
            WideStackReturnPredicateStatus8616.EXPRESSION_MATERIALIZATION_FAILED,
            raw_count,
            normalized_count=graph.wide_condition_count,
            classified_count=raw_count,
        )
        return _record_result_8616(boundary, result)
    materialized.tags = {
        **dict(materialized.tags or {}),
        "inertia_structuring_wide_stack_return_predicate_8616": True,
    }
    true_body = CStatements(
        [CReturn(selected_return, codegen=codegen)],
        codegen=codegen,
    )
    boundary.cfunc.statements = CStatements(
        [
            CIfElse(
                [(materialized, true_body)],
                else_node=None,
                cstyle_ifs=True,
                codegen=codegen,
            ),
            CReturn(alternate_return, codegen=codegen),
        ],
        codegen=codegen,
    )
    cast(Any, boundary.cfunc.statements).tags = {
        "inertia_structuring_wide_stack_return_predicate_8616": True,
    }
    result = WideStackReturnPredicateResult8616(
        WideStackReturnPredicateStatus8616.MATERIALIZED,
        WideStackReturnPredicateStats8616(
            raw_count,
            graph.wide_condition_count,
            raw_count,
            raw_count,
            0,
        ),
        graph.wide_condition_count,
    )
    return _record_result_8616(boundary, result)


def wide_stack_return_predicate_validation_delta_is_proven_8616(
    result: WideStackReturnPredicateResult8616 | None,
    validation: dict[str, object],
) -> bool:
    """Accept only the validation delta proven by a complete predicate graph.

    A pre-existing structuring tree can lose one return leaf before this pass.
    Reintroducing that leaf is a valid precision improvement, but only when
    the graph proof consumed every condition and the delta contains no memory,
    register, global, or call effect. Removed return effects remain unsafe.
    """
    if result is None or result.status is not WideStackReturnPredicateStatus8616.MATERIALIZED:
        return False
    stats = result.stats
    if not (
        stats.raw_fact_count > 0
        and 0 < stats.normalized_fact_count <= stats.raw_fact_count
        and stats.raw_fact_count == stats.classified_fact_count
        and stats.raw_fact_count == stats.materialized_count
        and stats.failure_count == 0
    ):
        return False
    delta = validation.get("delta")
    if not isinstance(delta, dict):
        return False
    for field_name in (
        "global_writes",
        "helper_calls",
        "register_writes",
        "segmented_writes",
        "stack_writes",
    ):
        field_delta = delta.get(field_name)
        if not isinstance(field_delta, dict):
            continue
        if field_delta.get("added") or field_delta.get("removed"):
            return False
    return_delta = delta.get("returns")
    return not (isinstance(return_delta, dict) and return_delta.get("removed"))


__all__ = [
    "WideStackReturnPredicateResult8616",
    "WideStackReturnPredicateStats8616",
    "WideStackReturnPredicateStatus8616",
    "materialize_wide_stack_return_predicate_8616",
    "wide_stack_return_predicate_materialized_8616",
    "wide_stack_return_predicate_validation_delta_is_proven_8616",
]
