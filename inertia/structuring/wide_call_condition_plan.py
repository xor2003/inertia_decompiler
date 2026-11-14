# cython: language_level=3, infer_types=True
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
import typing
import cython

from dataclasses import dataclass, replace

from inertia.ir.condition_ir import ConditionIR, ConditionOp
from inertia.ir.core import IRValue
from inertia.ir.ssa_function import SSAFunctionArtifact
from inertia.lowering.call_output_stack_objects import select_wide_call_return_condition_chain_8616

from .condition_exit_normalization import transparent_condition_exit_8616
from .wide_condition_ordering import prove_wide_ordering_operator_8616
from .wide_stack_condition_chains import WideStackOperandPair8616, _chain_outcome_8616
import dataclasses


@dataclasses.dataclass(frozen=True, )
class WideCallConditionPlan8616:
    """Target-directed ordering proof; not a call-placement or storage proof."""

    operator: ConditionOp
    conditions: object
    high_stack: IRValue
    low_stack: IRValue


@cython.ccall
def _normalize_chain_exits(
    chain: object,
    successors: object,
    artifact: SSAFunctionArtifact | None,
    retained: object,
) -> object:
    """Collapse only SSA-proven empty paths, preserving original condition facts."""
    condition: object
    target: object
    normalized: dict[cython.longlong, ConditionIR] = {}
    for condition in chain:
        targets: list[cython.longlong] = []
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
    conditions_by_block: object,
    successors: object,
    true_target: cython.longlong,
    false_target: cython.longlong,
    *,
    artifact: SSAFunctionArtifact | None = None,
) -> WideCallConditionPlan8616 | None:
    """Require one complete chain and a unique operator for all nine orders."""
    chain: object
    normalized: object
    operator: object
    condition: object
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
    if not all(isinstance(operand, IRValue) for operand in iter(operands)):
        return None
    assert isinstance(high.lhs, IRValue) and isinstance(low.lhs, IRValue)
    assert isinstance(high.rhs, IRValue) and isinstance(low.rhs, IRValue)
    pair = WideStackOperandPair8616(high.lhs, low.lhs, high.rhs, low.rhs, True, False, False)
    retained = frozenset(tuple(conditions_by_block) + (true_target, false_target))
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
