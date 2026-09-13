"""Prove wide call-predicate polarity without constructing scalar C operands.

Layer: Structuring.
Responsibility: classify a complete typed DX:AX comparison decision graph.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence. Call identity and storage ownership require independent
Alias and Types/Lowering proof before materializing the resulting plan.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from ..ir.condition_ir import ConditionIR, ConditionOp
from ..ir.core import IRValue
from ..ir.ssa_function import SSAFunctionArtifact
from ..lowering.call_output_stack_objects import select_wide_call_return_condition_chain_8616
from .condition_exit_normalization import transparent_condition_exit_8616
from .wide_condition_ordering import prove_wide_ordering_operator_8616
from .wide_stack_condition_chains import WideStackOperandPair8616, _chain_outcome_8616


@dataclass(frozen=True, slots=True)
class WideCallConditionPlan8616:
    """Target-directed ordering proof; not a call-placement or storage proof."""

    operator: ConditionOp
    conditions: tuple[ConditionIR, ConditionIR, ConditionIR]
    high_stack: IRValue
    low_stack: IRValue


def _normalize_chain_exits(
    chain: tuple[ConditionIR, ...],
    successors: dict[int, tuple[int, ...]],
    artifact: SSAFunctionArtifact | None,
    retained: frozenset[int],
) -> dict[int, ConditionIR] | None:
    """Collapse only SSA-proven empty paths, preserving original condition facts."""
    normalized: dict[int, ConditionIR] = {}
    for condition in chain:
        targets: list[int] = []
        for target in (condition.taken_target, condition.fallthrough_target):
            if not isinstance(target, int):
                return None
            endpoint = transparent_condition_exit_8616(
                artifact, target, successors, stop_at=None, retained_targets=retained,
            )
            if endpoint not in retained:
                return None
            targets.append(endpoint)
        assert isinstance(condition.block_addr, int)
        normalized[condition.block_addr] = replace(
            condition, taken_target=targets[0], fallthrough_target=targets[1],
        )
    return normalized


def plan_wide_call_condition_8616(
    root: ConditionIR,
    conditions_by_block: dict[int, ConditionIR],
    successors: dict[int, tuple[int, ...]],
    true_target: int,
    false_target: int,
    *,
    artifact: SSAFunctionArtifact | None = None,
) -> WideCallConditionPlan8616 | None:
    """Require one complete chain and a unique operator for all nine orders."""
    chain = select_wide_call_return_condition_chain_8616(root, tuple(conditions_by_block.values()))
    if chain is None or true_target == false_target:
        return None
    for condition in chain:
        if not isinstance(condition.block_addr, int):
            return None
        if set(successors.get(condition.block_addr, ())) != {condition.taken_target, condition.fallthrough_target}:
            return None
    high, _equality, low = chain
    operands = (high.lhs, low.lhs, high.rhs, low.rhs)
    if not all(isinstance(operand, IRValue) for operand in operands):
        return None
    assert isinstance(high.lhs, IRValue) and isinstance(low.lhs, IRValue)
    assert isinstance(high.rhs, IRValue) and isinstance(low.rhs, IRValue)
    pair = WideStackOperandPair8616(high.lhs, low.lhs, high.rhs, low.rhs, True, False, False)
    retained = frozenset((*conditions_by_block, true_target, false_target))
    normalized = _normalize_chain_exits(chain, successors, artifact, retained)
    if normalized is None:
        return None
    assert isinstance(root.block_addr, int)
    normalized_root = normalized[root.block_addr]
    operator = prove_wide_ordering_operator_8616(
        pair.signed,
        lambda high_order, low_order: _chain_outcome_8616(
            normalized_root, pair, normalized, {},
            true_target, false_target, high_order, low_order,
        ),
    )
    if operator is None:
        return None
    return WideCallConditionPlan8616(operator, chain, high.rhs, low.rhs)
