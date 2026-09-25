"""Build typed condition expressions for predecessor-indexed call values.

Layer: Structuring.
Responsibility: Prove that one ConditionIR decision tree partitions every
direct predecessor of a shared call block, then materialize value expressions
on that call-executing domain.  This module consumes CFG and typed condition
evidence only; it does not inspect instructions or rendered C.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CITE, CConstant, CExpression
from angr.sim_type import SimTypeShort

from ..callsite_summary import CallsiteSummary8616
from ..ir.condition_ir import ConditionIR
from .condition_materialization import (
    condition_chain_successors_8616,
    materialize_condition_ir_expression_8616,
)

__all__ = [
    "CallArgumentPathConditionResult8616",
    "CallArgumentPathConditionStatus8616",
    "materialize_call_argument_path_expressions_8616",
]


class _PathConditionCodegen8616(Protocol):
    """Owned typed condition carrier consumed at the codegen boundary."""

    _inertia_typed_conditions: object


class CallArgumentPathConditionStatus8616(Enum):
    """Typed outcome of path decision-tree materialization."""

    MATERIALIZED = "materialized"
    REFUSED_TOPOLOGY = "refused_topology"
    REFUSED_CONDITION = "refused_condition"


@dataclass(frozen=True, slots=True)
class CallArgumentPathConditionResult8616:
    """Return materialized lane expressions or one exact refusal category."""

    status: CallArgumentPathConditionStatus8616
    expressions: tuple[CExpression, ...] = ()


@dataclass(frozen=True, slots=True)
class _PathLeaf8616:
    """One direct call-block predecessor selected by the decision tree."""

    predecessor_addr: int


class _NoCallPath8616(Enum):
    """A selector edge proven not to enter the shared call block."""

    VALUE = "no_call"


@dataclass(frozen=True, slots=True)
class _PathDecision8616:
    """One typed branch and its recursively classified CFG edges."""

    condition: ConditionIR
    taken: _PathNode8616
    fallthrough: _PathNode8616


type _PathNode8616 = _PathLeaf8616 | _PathDecision8616 | _NoCallPath8616


def _call_block_predecessors_8616(
    summary: CallsiteSummary8616,
    successors: dict[int, tuple[int, ...]],
) -> frozenset[int] | None:
    """Return the exact direct predecessors of the block owning the callsite."""
    candidates = tuple(addr for addr in successors if addr <= summary.callsite_addr)
    if not candidates:
        return None
    call_block = max(candidates)
    return frozenset(source for source, targets in successors.items() if call_block in targets)


def _conditions_by_block_8616(codegen: object) -> dict[int, ConditionIR] | None:
    """Return one unambiguous typed condition for each condition block."""
    typed_codegen = cast(_PathConditionCodegen8616, codegen)
    try:
        conditions = tuple(
            condition
            for condition in cast(tuple[object, ...], typed_codegen._inertia_typed_conditions)
            if isinstance(condition, ConditionIR) and isinstance(condition.block_addr, int)
        )
    except (AttributeError, TypeError):
        return None
    grouped: dict[int, list[ConditionIR]] = {}
    for condition in conditions:
        grouped.setdefault(cast(int, condition.block_addr), []).append(condition)
    if any(len(group) != 1 for group in grouped.values()):
        return None
    return {block: group[0] for block, group in grouped.items()}


def _resolve_path_target_8616(
    target: int,
    *,
    trace_predecessors: frozenset[int],
    conditions: dict[int, ConditionIR],
    successors: dict[int, tuple[int, ...]],
    visited: frozenset[int],
) -> _PathNode8616 | None:
    """Follow one edge through unique non-condition blocks to a typed frontier."""
    current = target
    walked = set(visited)
    while current not in walked:
        if current in trace_predecessors:
            return _PathLeaf8616(current)
        if current in conditions:
            return _build_path_decision_8616(
                conditions[current],
                trace_predecessors=trace_predecessors,
                conditions=conditions,
                successors=successors,
                visited=frozenset(walked),
            )
        walked.add(current)
        next_blocks = successors.get(current, ())
        if not next_blocks:
            return _NoCallPath8616.VALUE
        if len(next_blocks) != 1:
            return None
        current = next_blocks[0]
    return None


def _path_decision_key_8616(
    condition: ConditionIR,
    successors: dict[int, tuple[int, ...]],
    visited: frozenset[int],
) -> tuple[int, int, int] | None:
    """Return the proven ``(block, taken, fallthrough)`` int triple or None."""
    block_addr = condition.block_addr
    taken_target = condition.taken_target
    fallthrough_target = condition.fallthrough_target
    if not (
        isinstance(block_addr, int)
        and block_addr not in visited
        and isinstance(taken_target, int)
        and isinstance(fallthrough_target, int)
    ):
        return None
    if (
        taken_target == fallthrough_target
        or set(successors.get(block_addr, ())) != {taken_target, fallthrough_target}
    ):
        return None
    return block_addr, taken_target, fallthrough_target


def _build_path_decision_8616(
    condition: ConditionIR,
    *,
    trace_predecessors: frozenset[int],
    conditions: dict[int, ConditionIR],
    successors: dict[int, tuple[int, ...]],
    visited: frozenset[int],
) -> _PathDecision8616 | None:
    """Build one acyclic decision from exact typed branch successors."""
    key = _path_decision_key_8616(condition, successors, visited)
    if key is None:
        return None
    block_addr, taken_target, fallthrough_target = key
    next_visited = visited | {block_addr}
    taken = _resolve_path_target_8616(
        taken_target,
        trace_predecessors=trace_predecessors,
        conditions=conditions,
        successors=successors,
        visited=next_visited,
    )
    fallthrough = _resolve_path_target_8616(
        fallthrough_target,
        trace_predecessors=trace_predecessors,
        conditions=conditions,
        successors=successors,
        visited=next_visited,
    )
    if taken is None or fallthrough is None:
        return None
    return _PathDecision8616(condition, taken, fallthrough)


def _trace_leaves_8616(node: _PathNode8616) -> tuple[int, ...]:
    """Return predecessor leaves reached by one partial decision tree."""
    if isinstance(node, _PathLeaf8616):
        return (node.predecessor_addr,)
    if isinstance(node, _PathDecision8616):
        return _trace_leaves_8616(node.taken) + _trace_leaves_8616(node.fallthrough)
    return ()


def _select_path_tree_8616(
    conditions: dict[int, ConditionIR],
    trace_predecessors: frozenset[int],
    successors: dict[int, tuple[int, ...]],
) -> _PathDecision8616 | None:
    """Select the unique root partitioning every call predecessor path."""
    matches: list[_PathDecision8616] = []
    for condition in conditions.values():
        tree = _build_path_decision_8616(
            condition,
            trace_predecessors=trace_predecessors,
            conditions=conditions,
            successors=successors,
            visited=frozenset(),
        )
        if tree is None:
            continue
        leaves = _trace_leaves_8616(tree)
        if (
            len(leaves) == len(trace_predecessors)
            and frozenset(leaves) == trace_predecessors
            and _trace_leaves_8616(tree.taken)
            and _trace_leaves_8616(tree.fallthrough)
        ):
            matches.append(tree)
    return matches[0] if len(matches) == 1 else None


def _materialize_path_expression_8616(
    project: object,
    codegen: object,
    node: _PathNode8616,
    values: dict[int, int],
) -> CExpression | None:
    """Materialize a value expression on the proven call-executing domain."""
    if isinstance(node, _PathLeaf8616):
        return CConstant(values[node.predecessor_addr], SimTypeShort(False), codegen=codegen)
    if node is _NoCallPath8616.VALUE:
        return None
    taken = _materialize_path_expression_8616(project, codegen, node.taken, values)
    fallthrough = _materialize_path_expression_8616(project, codegen, node.fallthrough, values)
    if taken is None:
        return fallthrough
    if fallthrough is None:
        return taken
    condition = materialize_condition_ir_expression_8616(project, codegen, node.condition)
    if condition is None:
        return None
    return CITE(condition, taken, fallthrough, codegen=codegen)


def materialize_call_argument_path_expressions_8616(
    project: object,
    codegen: object,
    summary: CallsiteSummary8616,
    values_by_predecessor: dict[int, tuple[int, ...]],
    varying_lanes: tuple[int, ...],
) -> CallArgumentPathConditionResult8616:
    """Materialize one expression per varying lane from an exact path tree."""
    successors = condition_chain_successors_8616(project, codegen)
    trace_predecessors = frozenset(values_by_predecessor)
    if _call_block_predecessors_8616(summary, successors) != trace_predecessors:
        return CallArgumentPathConditionResult8616(
            CallArgumentPathConditionStatus8616.REFUSED_TOPOLOGY
        )
    conditions = _conditions_by_block_8616(codegen)
    tree = (
        _select_path_tree_8616(conditions, trace_predecessors, successors)
        if conditions is not None
        else None
    )
    if tree is None:
        return CallArgumentPathConditionResult8616(
            CallArgumentPathConditionStatus8616.REFUSED_CONDITION
        )
    expressions: list[CExpression] = []
    for value_index, _physical_lane in enumerate(varying_lanes):
        values = {
            predecessor: lane_values[value_index]
            for predecessor, lane_values in values_by_predecessor.items()
        }
        expression = _materialize_path_expression_8616(project, codegen, tree, values)
        if expression is None:
            return CallArgumentPathConditionResult8616(
                CallArgumentPathConditionStatus8616.REFUSED_CONDITION
            )
        expressions.append(expression)
    return CallArgumentPathConditionResult8616(
        CallArgumentPathConditionStatus8616.MATERIALIZED,
        tuple(expressions),
    )
