"""Recover boolean graphs from complete wide-stack condition chains.

Layer: Structuring.
Responsibility: Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence. Collapse Widening-proven word comparison subgraphs and compose
their typed boolean predicate from explicit CFG exits.

This module is independent of C AST materialization and instruction decoding.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.
Every word condition must have one exact wide-pair owner or recovery refuses.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from enum import Enum
from typing import Literal, cast

from ..ir.condition_ir import ConditionIR, ConditionOp
from ..ir.core import IRValue
from .wide_stack_condition_chains import (
    WideStackOperandPair8616,
    WideStackPairProver8616,
    candidate_wide_stack_operand_pairs_8616,
    candidate_wide_stack_ops_8616,
    relation_for_wide_stack_condition_8616,
    wide_stack_operator_result_8616,
)

type WidePredicateExitClassifier8616 = Callable[[int], bool | None]


class WidePredicateGraphStatus8616(Enum):
    """Typed outcomes for complete wide predicate graph recovery."""

    RECOVERED = "recovered"
    INCOMPLETE_CFG = "incomplete_cfg"
    PAIR_PROOF_FAILED = "pair_proof_failed"
    EXIT_PROOF_FAILED = "exit_proof_failed"


@dataclass(frozen=True, slots=True)
class WidePredicateLeaf8616:
    """One proven wide comparison in a boolean predicate."""

    condition: ConditionIR


@dataclass(frozen=True, slots=True)
class WidePredicateNot8616:
    """One boolean negation that could not be folded into a leaf."""

    operand: WidePredicateExpr8616


@dataclass(frozen=True, slots=True)
class WidePredicateBinary8616:
    """One short-circuit boolean combination."""

    op: Literal["and", "or"]
    lhs: WidePredicateExpr8616
    rhs: WidePredicateExpr8616


type WidePredicateExpr8616 = (
    WidePredicateLeaf8616 | WidePredicateNot8616 | WidePredicateBinary8616
)


@dataclass(frozen=True, slots=True)
class WidePredicateGraphResult8616:
    """Return a complete predicate or one structured refusal."""

    status: WidePredicateGraphStatus8616
    expression: WidePredicateExpr8616 | None = None
    raw_condition_count: int = 0
    wide_condition_count: int = 0


@dataclass(frozen=True, slots=True)
class _CollapsedWideCondition8616:
    """One complete word-comparison subgraph and its two exits."""

    condition: ConditionIR
    true_target: int
    false_target: int


_INVERT_OP_8616: dict[ConditionOp, ConditionOp] = {
    "eq": "ne",
    "ne": "eq",
    "slt": "sge",
    "sle": "sgt",
    "sgt": "sle",
    "sge": "slt",
    "ult": "uge",
    "ule": "ugt",
    "ugt": "ule",
    "uge": "ult",
}
_SWAP_OP_8616: dict[ConditionOp, ConditionOp] = {
    "eq": "eq",
    "ne": "ne",
    "slt": "sgt",
    "sle": "sge",
    "sgt": "slt",
    "sge": "sle",
    "ult": "ugt",
    "ule": "uge",
    "ugt": "ult",
    "uge": "ule",
}


def wide_predicate_exit_targets_8616(
    conditions: tuple[ConditionIR, ...],
) -> tuple[int, ...]:
    """Return deterministic CFG targets outside the typed condition blocks."""
    blocks = frozenset(
        condition.block_addr
        for condition in conditions
        if isinstance(condition.block_addr, int)
    )
    return tuple(
        sorted(
            {
                int(target)
                for condition in conditions
                for target in (condition.taken_target, condition.fallthrough_target)
                if isinstance(target, int) and target not in blocks
            }
        )
    )


def _matches_pair_8616(
    condition: ConditionIR,
    pair: WideStackOperandPair8616,
) -> bool:
    """Return whether a word condition uses either side of one wide pair."""
    return relation_for_wide_stack_condition_8616(condition, pair, 1, 1) is not None


def _pair_path_outcome_8616(
    root: ConditionIR,
    pair: WideStackOperandPair8616,
    conditions_by_block: dict[int, ConditionIR],
    true_target: int,
    false_target: int,
    high_relation: int,
    low_relation: int,
) -> bool | None:
    """Evaluate one pair-local decision graph for an abstract ordering."""
    condition = root
    visited: set[int] = set()
    while len(visited) < 12:
        relation = relation_for_wide_stack_condition_8616(
            condition, pair, high_relation, low_relation
        )
        if relation is None:
            return None
        decision = wide_stack_operator_result_8616(condition.op, relation)
        if decision is None:
            return None
        target = condition.taken_target if decision else condition.fallthrough_target
        if target == true_target:
            return True
        if target == false_target:
            return False
        if not isinstance(target, int) or target in visited:
            return None
        visited.add(target)
        next_condition = conditions_by_block.get(target)
        if next_condition is None:
            return None
        condition = next_condition
    return None


def _swappable_bp_offsets_8616(lhs: object, rhs: object) -> bool:
    """Return whether both operands are int-offset ``bp`` values in descending order."""
    return (
        isinstance(lhs, IRValue)
        and isinstance(rhs, IRValue)
        and lhs.name == rhs.name == "bp"
        and isinstance(lhs.offset, int)
        and isinstance(rhs.offset, int)
        and lhs.offset > rhs.offset
    )


def _canonical_condition_8616(condition: ConditionIR) -> ConditionIR:
    """Prefer ascending stack offsets while preserving comparison meaning."""
    lhs = condition.lhs
    rhs = condition.rhs
    if _swappable_bp_offsets_8616(lhs, rhs):
        return replace(condition, op=_SWAP_OP_8616[condition.op], lhs=rhs, rhs=lhs)
    return condition


def _collapse_pair_8616(
    pair: WideStackOperandPair8616,
    conditions: tuple[ConditionIR, ...],
) -> _CollapsedWideCondition8616 | None:
    """Collapse one complete high/low decision subgraph by exhaustive proof."""
    by_block = {
        condition.block_addr: condition
        for condition in conditions
        if isinstance(condition.block_addr, int)
    }
    blocks = frozenset(by_block)
    incoming = {
        target
        for condition in conditions
        for target in (condition.taken_target, condition.fallthrough_target)
        if target in blocks
    }
    entries = tuple(condition for condition in conditions if condition.block_addr not in incoming)
    exits = tuple(
        sorted(
            {
                int(target)
                for condition in conditions
                for target in (condition.taken_target, condition.fallthrough_target)
                if isinstance(target, int) and target not in blocks
            }
        )
    )
    if len(entries) != 1 or len(exits) != 2:
        return None
    root = entries[0]
    preferred_target = (
        root.taken_target
        if root.taken_target in exits
        else root.fallthrough_target
        if root.fallthrough_target in exits
        else exits[0]
    )
    if not isinstance(preferred_target, int):
        return None
    other_target = exits[1] if exits[0] == preferred_target else exits[0]
    outcomes: dict[tuple[int, int], bool] = {}
    for high_relation in (-1, 0, 1):
        for low_relation in (-1, 0, 1):
            outcome = _pair_path_outcome_8616(
                root,
                pair,
                by_block,
                preferred_target,
                other_target,
                high_relation,
                low_relation,
            )
            if outcome is None:
                return None
            outcomes[(high_relation, low_relation)] = outcome
    matching = tuple(
        op
        for op in candidate_wide_stack_ops_8616(pair.signed)
        if all(
            wide_stack_operator_result_8616(
                op, high_relation if high_relation != 0 else low_relation
            )
            == outcome
            for (high_relation, low_relation), outcome in outcomes.items()
        )
    )
    if len(matching) != 1:
        return None
    condition = _canonical_condition_8616(
        replace(
            root,
            op=matching[0],
            lhs=replace(pair.low_left, size=4),
            rhs=replace(pair.low_right, size=4),
            width_bits=32,
            # The derived operands no longer denote the source CMP registers.
            producer_semantics=None,
            register_bindings=(),
            taken_target=preferred_target,
            fallthrough_target=other_target,
            source=(*root.source, "wide-stack-predicate-graph"),
        )
    )
    return _CollapsedWideCondition8616(condition, preferred_target, other_target)


def _negate_8616(expression: WidePredicateExpr8616) -> WidePredicateExpr8616:
    """Fold a boolean negation into a comparison whenever possible."""
    if isinstance(expression, WidePredicateLeaf8616):
        return WidePredicateLeaf8616(
            replace(expression.condition, op=_INVERT_OP_8616[expression.condition.op])
        )
    if isinstance(expression, WidePredicateNot8616):
        return expression.operand
    return WidePredicateNot8616(expression)


def _combine_8616(
    condition: WidePredicateLeaf8616,
    taken: WidePredicateExpr8616 | bool,
    fallthrough: WidePredicateExpr8616 | bool,
) -> WidePredicateExpr8616 | bool:
    """Build a reduced predicate for reaching one selected exit class."""
    if isinstance(taken, bool) and isinstance(fallthrough, bool):
        if taken == fallthrough:
            return taken
        return condition if taken else _negate_8616(condition)
    if taken is True:
        return WidePredicateBinary8616("or", condition, cast(WidePredicateExpr8616, fallthrough))
    if fallthrough is True:
        return WidePredicateBinary8616("or", _negate_8616(condition), cast(WidePredicateExpr8616, taken))
    if taken is False:
        return WidePredicateBinary8616(
            "and",
            _negate_8616(condition),
            cast(WidePredicateExpr8616, fallthrough),
        )
    if fallthrough is False:
        return WidePredicateBinary8616("and", condition, taken)
    return WidePredicateBinary8616(
        "or",
        WidePredicateBinary8616("and", condition, taken),
        WidePredicateBinary8616(
            "and", _negate_8616(condition), fallthrough
        ),
    )


def _collapsed_pair_conditions_8616(
    conditions: tuple[ConditionIR, ...],
    pairs: tuple[WideStackOperandPair8616, ...],
    raw_count: int,
) -> tuple[_CollapsedWideCondition8616, ...] | WidePredicateGraphResult8616:
    """Group conditions under their unique proven pair, or refuse."""
    grouped: list[list[ConditionIR]] = [[] for _pair in pairs]
    for condition in conditions:
        owners = tuple(index for index, pair in enumerate(pairs) if _matches_pair_8616(condition, pair))
        if len(owners) != 1:
            return WidePredicateGraphResult8616(
                WidePredicateGraphStatus8616.PAIR_PROOF_FAILED,
                raw_condition_count=raw_count,
                wide_condition_count=len(pairs),
            )
        grouped[owners[0]].append(condition)
    collapsed = tuple(
        _collapse_pair_8616(pair, tuple(group))
        for pair, group in zip(pairs, grouped, strict=True)
    )
    if not collapsed or any(item is None for item in collapsed):
        return WidePredicateGraphResult8616(
            WidePredicateGraphStatus8616.PAIR_PROOF_FAILED,
            raw_condition_count=raw_count,
            wide_condition_count=len(pairs),
        )
    return cast(tuple[_CollapsedWideCondition8616, ...], collapsed)


def _single_graph_root_8616(
    proven: tuple[_CollapsedWideCondition8616, ...],
) -> int | None:
    """Return the unique predicate-graph entry block, or None."""
    by_entry = {
        item.condition.block_addr: item
        for item in proven
        if isinstance(item.condition.block_addr, int)
    }
    incoming_entries = {
        target
        for item in proven
        for target in (item.true_target, item.false_target)
        if target in by_entry
    }
    roots = tuple(entry for entry in by_entry if entry not in incoming_entries)
    return roots[0] if len(roots) == 1 else None


def recover_wide_stack_predicate_graph_8616(
    conditions: tuple[ConditionIR, ...],
    successors: dict[int, tuple[int, ...]],
    prove_pair: WideStackPairProver8616,
    classify_exit: WidePredicateExitClassifier8616,
) -> WidePredicateGraphResult8616:
    """Recover one complete boolean predicate over all typed condition blocks."""
    raw_count = len(conditions)
    by_block = {
        condition.block_addr: condition
        for condition in conditions
        if isinstance(condition.block_addr, int)
    }
    if raw_count < 2 or len(by_block) != raw_count:
        return WidePredicateGraphResult8616(
            WidePredicateGraphStatus8616.INCOMPLETE_CFG,
            raw_condition_count=raw_count,
        )
    pairs = candidate_wide_stack_operand_pairs_8616(conditions, prove_pair)
    proven = _collapsed_pair_conditions_8616(conditions, pairs, raw_count)
    if isinstance(proven, WidePredicateGraphResult8616):
        return proven
    root_entry = _single_graph_root_8616(proven)
    if root_entry is None:
        return WidePredicateGraphResult8616(
            WidePredicateGraphStatus8616.INCOMPLETE_CFG,
            raw_condition_count=raw_count,
            wide_condition_count=len(proven),
        )
    by_entry = {
        item.condition.block_addr: item
        for item in proven
        if isinstance(item.condition.block_addr, int)
    }
    visited_entries: set[int] = set()

    def build(address: int, active: frozenset[int]) -> WidePredicateExpr8616 | bool | None:
        """Build a predicate from the collapsed acyclic CFG."""
        outcome = classify_exit(address)
        if outcome is not None:
            return outcome
        item = by_entry.get(address)
        if item is None or address in active:
            next_addrs = successors.get(address, ())
            return build(next_addrs[0], active | {address}) if len(next_addrs) == 1 else None
        visited_entries.add(address)
        taken = build(item.true_target, active | {address})
        fallthrough = build(item.false_target, active | {address})
        if taken is None or fallthrough is None:
            return None
        return _combine_8616(WidePredicateLeaf8616(item.condition), taken, fallthrough)

    expression = build(root_entry, frozenset())
    if not isinstance(
        expression,
        (WidePredicateLeaf8616, WidePredicateNot8616, WidePredicateBinary8616),
    ) or visited_entries != set(by_entry):
        return WidePredicateGraphResult8616(
            WidePredicateGraphStatus8616.EXIT_PROOF_FAILED,
            raw_condition_count=raw_count,
            wide_condition_count=len(proven),
        )
    return WidePredicateGraphResult8616(
        WidePredicateGraphStatus8616.RECOVERED,
        expression,
        raw_count,
        len(proven),
    )


__all__ = [
    "WidePredicateBinary8616",
    "WidePredicateExpr8616",
    "WidePredicateGraphResult8616",
    "WidePredicateGraphStatus8616",
    "WidePredicateLeaf8616",
    "WidePredicateNot8616",
    "recover_wide_stack_predicate_graph_8616",
    "wide_predicate_exit_targets_8616",
]
