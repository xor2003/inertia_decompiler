"""Lower typed CFG conditions that select branch-carried call arguments.

Layer: Structuring.
Responsibility: bind one Alias-owned register join to the unique ConditionIR
whose taken and fallthrough targets are exactly the join predecessors.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CITE, CConstant, CExpression
from angr.sim_type import SimTypeShort
from inertia.semantics.callsite_summary import CallsitePushSourceKind8616

from inertia.alias.callsite_stack_merge import CallsiteRegisterJoin8616, CallsiteSource8616
from inertia.ir.condition_ir import ConditionIR

from .condition_materialization import materialize_condition_ir_expression_8616

__all__ = [
    "conditional_call_argument_join_expression_8616",
    "exact_call_argument_immediate_8616",
]


class _CallArgumentJoinConditionCodegen8616(Protocol):
    """Typed condition facts consumed across the angr codegen boundary."""

    _inertia_typed_conditions: object


def exact_call_argument_immediate_8616(source: CallsiteSource8616 | None) -> int | None:
    """Return an exact immediate from one Alias source fact."""
    if not isinstance(source, tuple) or len(source) != 2:
        return None
    kind, value = source
    if kind != CallsitePushSourceKind8616.IMMEDIATE.value:
        return None
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _join_values_by_predecessor_8616(join: CallsiteRegisterJoin8616) -> dict[int, int] | None:
    """Map every unique join predecessor to its exact incoming value."""
    values: dict[int, int] = {}
    for trace in join.traces:
        value = exact_call_argument_immediate_8616(trace.source)
        if value is None or trace.predecessor_addr in values:
            return None
        values[trace.predecessor_addr] = value
    return values if len(values) == len(join.traces) else None


def _select_join_condition_8616(
    conditions: tuple[ConditionIR, ...],
    predecessor_addrs: frozenset[int],
) -> ConditionIR | None:
    """Select one condition whose two CFG edges are the join predecessors."""
    matches = tuple(
        condition
        for condition in conditions
        if isinstance(condition.taken_target, int)
        and isinstance(condition.fallthrough_target, int)
        and condition.taken_target != condition.fallthrough_target
        and frozenset((condition.taken_target, condition.fallthrough_target)) == predecessor_addrs
    )
    return matches[0] if len(matches) == 1 else None


def conditional_call_argument_join_expression_8616(
    project: object,
    codegen: object,
    join: CallsiteRegisterJoin8616,
) -> CExpression | None:
    """Build an exact C conditional expression for one typed register join."""
    typed_codegen = cast(_CallArgumentJoinConditionCodegen8616, codegen)
    try:
        conditions = tuple(
            condition
            for condition in cast(tuple[object, ...], typed_codegen._inertia_typed_conditions)
            if isinstance(condition, ConditionIR)
        )
    except (AttributeError, TypeError):
        return None
    values_by_predecessor = _join_values_by_predecessor_8616(join)
    if values_by_predecessor is None or len(values_by_predecessor) != 2:
        return None
    condition = _select_join_condition_8616(conditions, frozenset(values_by_predecessor))
    if condition is None:
        return None
    taken_target = condition.taken_target
    fallthrough_target = condition.fallthrough_target
    if not isinstance(taken_target, int) or not isinstance(fallthrough_target, int):
        return None
    condition_expression = materialize_condition_ir_expression_8616(project, codegen, condition)
    if condition_expression is None:
        return None
    value_type = SimTypeShort(False)
    return CITE(
        condition_expression,
        CConstant(values_by_predecessor[taken_target], value_type, codegen=codegen),
        CConstant(values_by_predecessor[fallthrough_target], value_type, codegen=codegen),
        codegen=codegen,
    )
