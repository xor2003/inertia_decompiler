# cython: language_level=3, infer_types=True
"""Find direct wide-comparison boundaries inside larger condition CFGs.

Layer: Structuring.
Responsibility: isolate one Widening-proven stack comparison from surrounding
typed conditions, then delegate its exhaustive truth-table proof to the direct
wide-condition owner. This module does not inspect instructions or rendered C.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass

from inertia.ir.condition_ir import ConditionIR

from .wide_stack_condition_chains import (
    WideStackConditionChainStats8616,
    WideStackOperandPair8616,
    WideStackPairProver8616,
    candidate_wide_stack_operand_pairs_8616,
    reachable_wide_stack_conditions_8616,
    recover_wide_stack_condition_chain_8616,
    relation_for_wide_stack_condition_8616,
)
import dataclasses
import operator


@dataclasses.dataclass(frozen=True, )
class LocalWideStackConditionChainResult8616:
    """One direct wide condition and the exact local CFG surface it consumed."""

    condition: ConditionIR | None
    consumed_conditions: object
    true_target: int | None
    false_target: int | None
    stats: WideStackConditionChainStats8616


@cython.ccall
def _condition_uses_pair_8616(
    condition: ConditionIR,
    pair: WideStackOperandPair8616,
) -> cython.bint:
    """Return whether one condition compares either word of a candidate pair."""
    return relation_for_wide_stack_condition_8616(condition, pair, 0, 0) is not None


@cython.ccall
def _external_target_8616(
    target: object,
    local_blocks: object,
    conditions_by_block: object,
    successors: object,
) -> int | None:
    """Resolve one edge through linear bridges to a local or external owner."""
    next_addrs: object
    visited: set[cython.longlong] = set()
    while isinstance(target, int) and target not in visited:
        visited.add(target)
        if target in local_blocks:
            return None
        if target in conditions_by_block:
            return target
        next_addrs = successors.get(target, ())
        if len(next_addrs) != 1:
            return target
        target = next_addrs[0]
    return None


def recover_local_wide_stack_condition_chain_8616(
    root: ConditionIR,
    conditions_by_block: object,
    successors: object,
    prove_pair: WideStackPairProver8616,
) -> LocalWideStackConditionChainResult8616:
    """Recover one direct wide comparison embedded in a larger typed CFG."""
    pair: object
    reachable = reachable_wide_stack_conditions_8616(
        root,
        conditions_by_block,
        successors,
    )
    candidates = candidate_wide_stack_operand_pairs_8616(reachable, prove_pair)
    successes: list[LocalWideStackConditionChainResult8616] = []
    for pair in candidates:
        local_conditions = tuple(
            condition
            for condition in iter(reachable)
            if _condition_uses_pair_8616(condition, pair)
        )
        if all(condition is not root for condition in iter(local_conditions)):
            continue
        local_blocks = frozenset(
            condition.block_addr
            for condition in iter(local_conditions)
            if isinstance(condition.block_addr, int)
        )
        if operator.ne(len(local_blocks), len(local_conditions)):
            continue
        external_targets = frozenset(
            boundary
            for condition in iter(local_conditions)
            for target in iter((condition.taken_target, condition.fallthrough_target))
            if (
                boundary := _external_target_8616(
                    target,
                    local_blocks,
                    conditions_by_block,
                    successors,
                )
            )
            is not None
        )
        if len(external_targets) != 2:
            continue
        true_target, false_target = sorted(external_targets)
        result = recover_wide_stack_condition_chain_8616(
            root,
            conditions_by_block,
            successors,
            true_target,
            false_target,
            prove_pair,
        )
        if result.condition is not None:
            successes.append(
                LocalWideStackConditionChainResult8616(
                    result.condition,
                    local_conditions,
                    true_target,
                    false_target,
                    result.stats,
                )
            )
    if len(successes) == 1:
        return successes[0]
    return LocalWideStackConditionChainResult8616(
        None,
        (),
        None,
        None,
        WideStackConditionChainStats8616(
            raw_fact_count=len(reachable),
            normalized_fact_count=len(reachable),
            classified_fact_count=0,
            materialized_count=0,
            failure_count=1 if successes else 0,
        ),
    )


__all__ = [
    "LocalWideStackConditionChainResult8616",
    "recover_local_wide_stack_condition_chain_8616",
]
