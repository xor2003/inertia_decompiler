"""Recover direct wide comparisons from typed word-condition CFG chains.

Layer: Structuring.
Responsibility: prove that a target-directed ``ConditionIR`` decision graph is
exactly one 32-bit comparison over Widening-proven stack pairs.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.

Recovery evaluates every high-word and low-word ordering combination against
the typed CFG and accepts only one matching comparison operator. It performs no
instruction decoding, rendered-text matching, or function-specific recovery.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace

from ..alias.condition_register_bindings import (
    condition_operand_storage_binding_8616,
)
from ..ir.condition_ir import ConditionIR, ConditionOp
from ..ir.core import IRValue
from . import wide_condition_ordering

type WideStackPairProver8616 = Callable[[IRValue, IRValue], bool]

_WORD_BYTES: int = 2
_MAX_EVALUATED_BLOCKS: int = 24
_MAX_DISCOVERED_BLOCKS: int = 48


@dataclass(frozen=True, slots=True)
class WideStackConditionChainStats8616:
    """Account for wide-condition classification and materialization."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class WideStackConditionChainResult8616:
    """Return one proven wide condition plus its evidence accounting."""

    condition: ConditionIR | None
    stats: WideStackConditionChainStats8616


@dataclass(frozen=True, slots=True)
class WideStackOperandPair8616:
    """Describe one anchored high/low operand pairing for CFG proof."""

    high_left: IRValue
    low_left: IRValue
    high_right: IRValue
    low_right: IRValue
    signed: bool | None
    left_pair_proven: bool
    right_pair_proven: bool


_SIGNED_OPS_8616: frozenset[ConditionOp] = frozenset({"slt", "sle", "sgt", "sge"})
_UNSIGNED_OPS_8616: frozenset[ConditionOp] = frozenset({"ult", "ule", "ugt", "uge"})


def _stack_word_8616(value: object) -> IRValue | None:
    """Return one exact typed BP-relative stack word."""
    if not isinstance(value, IRValue):
        return None
    if value.name != "bp" or value.size != _WORD_BYTES:
        return None
    return value


def _condition_signedness_8616(condition: ConditionIR) -> bool | None:
    """Return the ordering family of one comparison condition."""
    if condition.op in _SIGNED_OPS_8616:
        return True
    if condition.op in _UNSIGNED_OPS_8616:
        return False
    return None


def _adjacent_stack_words_8616(high: IRValue, low: IRValue) -> bool:
    """Require exact typed adjacency before propagating a peer widening proof."""
    return (
        isinstance(high.offset, int)
        and isinstance(low.offset, int)
        and high.offset == low.offset + _WORD_BYTES
    )


def candidate_wide_stack_operand_pairs_8616(
    conditions: tuple[ConditionIR, ...],
    prove_pair: WideStackPairProver8616,
) -> tuple[WideStackOperandPair8616, ...]:
    """Collect pairs anchored by Widening; peer propagation requires CFG proof."""
    candidates: list[WideStackOperandPair8616] = []
    for high_condition in conditions:
        high_left = _stack_word_8616(
            condition_operand_storage_binding_8616(
                high_condition, high_condition.lhs
            )
        )
        high_right = _stack_word_8616(
            condition_operand_storage_binding_8616(
                high_condition, high_condition.rhs
            )
        )
        if high_left is None or high_right is None:
            continue
        signed = _condition_signedness_8616(high_condition)
        for low_condition in conditions:
            if low_condition.op in _SIGNED_OPS_8616:
                continue
            low_left = _stack_word_8616(
                condition_operand_storage_binding_8616(
                    low_condition, low_condition.lhs
                )
            )
            low_right = _stack_word_8616(
                condition_operand_storage_binding_8616(
                    low_condition, low_condition.rhs
                )
            )
            if low_left is None or low_right is None:
                continue
            _pair_orientations_8616(
                high_left,
                high_right,
                low_left,
                low_right,
                signed,
                prove_pair,
                candidates,
            )
    return tuple(candidates)


def _pair_orientations_8616(
    high_left: IRValue,
    high_right: IRValue,
    low_left: IRValue,
    low_right: IRValue,
    signed: bool | None,
    prove_pair: WideStackPairProver8616,
    candidates: list[WideStackOperandPair8616],
) -> None:
    """Append proven oriented candidates for one (high, low) word pair."""
    for paired_left, paired_right in ((low_left, low_right), (low_right, low_left)):
        if not _adjacent_stack_words_8616(
            high_left, paired_left
        ) or not _adjacent_stack_words_8616(high_right, paired_right):
            continue
        left_pair_proven = prove_pair(high_left, paired_left)
        right_pair_proven = prove_pair(high_right, paired_right)
        if not left_pair_proven and not right_pair_proven:
            continue
        _merge_candidate_8616(
            candidates,
            WideStackOperandPair8616(
                high_left=high_left,
                low_left=paired_left,
                high_right=high_right,
                low_right=paired_right,
                signed=signed,
                left_pair_proven=left_pair_proven,
                right_pair_proven=right_pair_proven,
            ),
        )


def _merge_candidate_8616(
    candidates: list[WideStackOperandPair8616],
    candidate: WideStackOperandPair8616,
) -> None:
    """Append or replace one candidate while preserving operand dedup."""
    same_operands = next(
        (
            index
            for index, existing in enumerate(candidates)
            if existing.high_left == candidate.high_left
            and existing.low_left == candidate.low_left
            and existing.high_right == candidate.high_right
            and existing.low_right == candidate.low_right
        ),
        None,
    )
    if same_operands is None:
        candidates.append(candidate)
    elif candidates[same_operands].signed is None and candidate.signed is not None:
        candidates[same_operands] = candidate
    elif (
        candidate.signed is not None
        and candidates[same_operands].signed is not None
        and candidates[same_operands].signed != candidate.signed
    ):
        candidates.append(candidate)


def relation_for_wide_stack_condition_8616(
    condition: ConditionIR,
    pair: WideStackOperandPair8616,
    high_relation: int,
    low_relation: int,
) -> int | None:
    """Map one condition to the abstract relation of its proven word pair."""
    operands = (
        condition_operand_storage_binding_8616(condition, condition.lhs),
        condition_operand_storage_binding_8616(condition, condition.rhs),
    )
    if operands == (pair.high_left, pair.high_right):
        return high_relation
    if operands == (pair.high_right, pair.high_left):
        return -high_relation
    if operands == (pair.low_left, pair.low_right):
        return low_relation
    if operands == (pair.low_right, pair.low_left):
        return -low_relation
    return None


def wide_stack_operator_result_8616(op: ConditionOp, relation: int) -> bool | None:
    """Evaluate a typed comparison operator over an abstract relation."""
    return wide_condition_ordering.wide_operator_result_8616(op, relation)


def _chain_outcome_8616(
    root: ConditionIR,
    pair: WideStackOperandPair8616,
    conditions_by_block: dict[int, ConditionIR],
    successors: dict[int, tuple[int, ...]],
    true_target: int,
    false_target: int,
    high_relation: int,
    low_relation: int,
) -> bool | None:
    """Evaluate one typed CFG chain without materializing a C expression."""
    condition = root
    visited: set[int] = set()
    while len(visited) < _MAX_EVALUATED_BLOCKS:
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
        verdict, next_condition = _chain_step_8616(
            target,
            conditions_by_block,
            successors,
            true_target,
            false_target,
        )
        if verdict is not None:
            return verdict
        if next_condition is None:
            return None
        condition = next_condition
    return None


def _chain_step_8616(
    target: int,
    conditions_by_block: dict[int, ConditionIR],
    successors: dict[int, tuple[int, ...]],
    true_target: int,
    false_target: int,
) -> tuple[bool | None, ConditionIR | None]:
    """Resolve one chain hop to ``(verdict, next)``; ``(None, None)`` refuses."""
    next_condition = conditions_by_block.get(target)
    if next_condition is not None:
        return None, next_condition
    next_addrs = successors.get(target, ())
    if len(next_addrs) != 1:
        return None, None
    hop = next_addrs[0]
    if hop == true_target:
        return True, None
    if hop == false_target:
        return False, None
    return None, conditions_by_block.get(hop)


def candidate_wide_stack_ops_8616(signed: bool | None) -> tuple[ConditionOp, ...]:
    """Return possible direct operators for one high-word family."""
    return wide_condition_ordering.candidate_wide_ops_8616(signed)


def reachable_wide_stack_conditions_8616(
    root: ConditionIR,
    conditions_by_block: dict[int, ConditionIR],
    successors: dict[int, tuple[int, ...]],
    *,
    stop_targets: frozenset[int] = frozenset(),
) -> tuple[ConditionIR, ...]:
    """Collect typed conditions before proven decision-surface exits."""
    pending = [root]
    result: list[ConditionIR] = []
    seen_conditions: set[int] = set()
    visited: set[int] = set()
    while pending and len(visited) < _MAX_DISCOVERED_BLOCKS:
        condition = pending.pop()
        condition_identity = id(condition)
        if condition_identity in seen_conditions:
            continue
        seen_conditions.add(condition_identity)
        result.append(condition)
        for initial_target in (condition.taken_target, condition.fallthrough_target):
            target = initial_target
            while (
                isinstance(target, int)
                and target not in visited
                and target not in stop_targets
            ):
                visited.add(target)
                next_condition = conditions_by_block.get(target)
                if next_condition is not None:
                    pending.append(next_condition)
                    break
                next_addrs = successors.get(target, ())
                if len(next_addrs) != 1:
                    break
                target = next_addrs[0]
    return tuple(result)


def recover_wide_stack_condition_chain_8616(
    root: ConditionIR,
    conditions_by_block: dict[int, ConditionIR],
    successors: dict[int, tuple[int, ...]],
    true_target: int,
    false_target: int,
    prove_pair: WideStackPairProver8616,
) -> WideStackConditionChainResult8616:
    """Recover one direct wide comparison only after exhaustive CFG proof."""
    conditions = reachable_wide_stack_conditions_8616(
        root,
        conditions_by_block,
        successors,
        stop_targets=frozenset((true_target, false_target)),
    )
    pairs = candidate_wide_stack_operand_pairs_8616(conditions, prove_pair)
    if len(pairs) != 1:
        return WideStackConditionChainResult8616(
            condition=None,
            stats=WideStackConditionChainStats8616(len(conditions), len(conditions), 0, 0, 0),
        )
    pair = pairs[0]
    operator = wide_condition_ordering.prove_wide_ordering_operator_8616(
        pair.signed,
        lambda high, low: _chain_outcome_8616(
            root, pair, conditions_by_block, successors,
            true_target, false_target, high, low,
        ),
    )
    if operator is None:
        return WideStackConditionChainResult8616(
            condition=None,
            stats=WideStackConditionChainStats8616(len(conditions), len(conditions), 1, 0, 1),
        )

    condition = replace(
        root,
        op=operator,
        lhs=replace(pair.low_left, size=4),
        rhs=replace(pair.low_right, size=4),
        width_bits=32,
        # Keep source addresses, but not obsolete word-register operand bindings.
        producer_semantics=None,
        register_bindings=(),
        source=(*root.source, "wide-stack-condition-chain"),
    )
    return WideStackConditionChainResult8616(
        condition=condition,
        stats=WideStackConditionChainStats8616(len(conditions), len(conditions), 1, 1, 0),
    )
