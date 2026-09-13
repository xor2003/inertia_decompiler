"""Recover wide comparisons for structured single-return branches.

Layer: Structuring.
Responsibility: prove when a typed word-condition CFG reaches one structured
return body and lower the complete decision graph to one 32-bit comparison.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.

Every accepted comparison matches all nine high/low ordering combinations.
Branch exits are classified by recovered return expressions, not by a shared
``ret`` instruction address or rendered text.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

from ..ir.condition_ir import ConditionIR, ConditionOp
from .wide_stack_condition_chains import (
    WideStackConditionChainResult8616,
    WideStackConditionChainStats8616,
    WideStackOperandPair8616,
    WideStackPairProver8616,
    candidate_wide_stack_operand_pairs_8616,
    candidate_wide_stack_ops_8616,
    reachable_wide_stack_conditions_8616,
    relation_for_wide_stack_condition_8616,
    wide_stack_operator_result_8616,
)

type WideStackExitClassifier8616 = Callable[[int], bool | None]


def _candidate_implies_root_outcome_8616(
    op: ConditionOp,
    root: ConditionIR,
    pair: WideStackOperandPair8616,
    required_root_outcome: bool | None,
) -> bool:
    """Require every true wide outcome to enter the structured root side."""
    if required_root_outcome is None:
        return True
    for high_relation in (-1, 0, 1):
        for low_relation in (-1, 0, 1):
            direct_result = wide_stack_operator_result_8616(
                op, high_relation if high_relation != 0 else low_relation
            )
            root_relation = relation_for_wide_stack_condition_8616(
                root, pair, high_relation, low_relation
            )
            if root_relation is None:
                return False
            root_result = wide_stack_operator_result_8616(root.op, root_relation)
            if direct_result is True and root_result is not required_root_outcome:
                return False
    return True


def _single_body_outcome_8616(
    root: ConditionIR,
    pair: WideStackOperandPair8616,
    conditions_by_block: dict[int, ConditionIR],
    successors: dict[int, tuple[int, ...]],
    classify_exit: WideStackExitClassifier8616,
    predecessor_counts: dict[int, int],
    high_relation: int,
    low_relation: int,
) -> bool | None:
    """Evaluate whether one abstract operand ordering reaches the owned body."""
    condition = root
    visited: set[int] = set()
    while len(visited) < 24:
        relation = relation_for_wide_stack_condition_8616(
            condition, pair, high_relation, low_relation
        )
        if relation is None:
            return False
        decision = wide_stack_operator_result_8616(condition.op, relation)
        if decision is None:
            return None
        target = condition.taken_target if decision else condition.fallthrough_target
        while isinstance(target, int) and target not in visited:
            visited.add(target)
            exit_outcome = classify_exit(target)
            if exit_outcome is not None:
                return exit_outcome
            if predecessor_counts.get(target, 0) > 1:
                return False
            next_condition = conditions_by_block.get(target)
            if next_condition is not None:
                if (
                    relation_for_wide_stack_condition_8616(
                        next_condition, pair, high_relation, low_relation
                    )
                    is None
                ):
                    return False
                condition = next_condition
                break
            next_addrs = successors.get(target, ())
            if len(next_addrs) != 1:
                return None
            target = next_addrs[0]
        else:
            return None
    return None


def recover_wide_stack_single_body_condition_8616(
    root: ConditionIR,
    conditions_by_block: dict[int, ConditionIR],
    successors: dict[int, tuple[int, ...]],
    prove_pair: WideStackPairProver8616,
    classify_exit: WideStackExitClassifier8616,
    *,
    required_root_outcome: bool | None = None,
) -> WideStackConditionChainResult8616:
    """Recover one direct wide condition whose true side owns one return body."""
    conditions = reachable_wide_stack_conditions_8616(root, conditions_by_block, successors)
    pairs = candidate_wide_stack_operand_pairs_8616(conditions, prove_pair)
    if len(pairs) != 1:
        return WideStackConditionChainResult8616(
            None,
            WideStackConditionChainStats8616(len(conditions), len(conditions), 0, 0, 0),
        )
    pair = pairs[0]
    predecessor_counts: dict[int, int] = {}
    for targets in successors.values():
        for target in targets:
            predecessor_counts[target] = predecessor_counts.get(target, 0) + 1
    outcomes: dict[tuple[int, int], bool] = {}
    for high_relation in (-1, 0, 1):
        for low_relation in (-1, 0, 1):
            outcome = _single_body_outcome_8616(
                root,
                pair,
                conditions_by_block,
                successors,
                classify_exit,
                predecessor_counts,
                high_relation,
                low_relation,
            )
            if outcome is None:
                return WideStackConditionChainResult8616(
                    None,
                    WideStackConditionChainStats8616(
                        len(conditions), len(conditions), 1, 0, 1
                    ),
                )
            outcomes[(high_relation, low_relation)] = outcome

    matching_ops: list[ConditionOp] = []
    for op in candidate_wide_stack_ops_8616(pair.signed):
        exact_match = all(
            wide_stack_operator_result_8616(
                op, high_relation if high_relation != 0 else low_relation
            )
            == outcome
            for (high_relation, low_relation), outcome in outcomes.items()
        )
        root_orientation_match = _candidate_implies_root_outcome_8616(
            op,
            root,
            pair,
            required_root_outcome,
        )
        if exact_match and root_orientation_match:
            matching_ops.append(op)
    if len(matching_ops) != 1:
        return WideStackConditionChainResult8616(
            None,
            WideStackConditionChainStats8616(len(conditions), len(conditions), 1, 0, 1),
        )
    condition = replace(
        root,
        op=matching_ops[0],
        lhs=replace(pair.low_left, size=4),
        rhs=replace(pair.low_right, size=4),
        width_bits=32,
        # Keep source addresses, but not obsolete word-register operand bindings.
        producer_semantics=None,
        register_bindings=(),
        source=(*root.source, "wide-stack-single-body"),
    )
    return WideStackConditionChainResult8616(
        condition,
        WideStackConditionChainStats8616(len(conditions), len(conditions), 1, 1, 0),
    )
