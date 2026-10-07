from __future__ import annotations

from dataclasses import replace

from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import IRBinaryValue, IRValue, MemSpace
from inertia.lowering.condition_fact_arbitration import (
    resolve_condition_fact_conflicts_8616,
)


def _stack_word(offset: int) -> IRValue:
    return IRValue(space=MemSpace.SS, name="bp", offset=offset, size=2)


def _condition(lhs_offset: int, rhs_offset: int) -> ConditionIR:
    return ConditionIR(
        op="ule",
        lhs=_stack_word(lhs_offset),
        rhs=_stack_word(rhs_offset),
        width_bits=16,
        source=("cmp", "jbe"),
        src_insn=0x1021,
        block_addr=0x101E,
        taken_target=0x1026,
        fallthrough_target=0x1023,
    )


def test_condition_fact_arbitration_prefers_unique_non_self_comparison() -> None:
    result = resolve_condition_fact_conflicts_8616(
        [_condition(8, 8), _condition(8, 4)]
    )

    assert result.conditions == (_condition(8, 4),)
    assert result.raw_fact_count == 2
    assert result.normalized_fact_count == 1
    assert result.failure_count == 1


def test_condition_fact_arbitration_refuses_two_non_self_operand_pairs() -> None:
    result = resolve_condition_fact_conflicts_8616(
        [_condition(8, 4), _condition(8, 6)]
    )

    assert result.conditions == ()
    assert result.failure_count == 2


def test_condition_fact_arbitration_prefers_bound_stack_pair_over_register_carrier() -> None:
    bound = _condition(8, 4)
    carrier = replace(
        bound,
        rhs=IRValue(space=MemSpace.REG, name="ax", offset=0, size=2),
    )

    result = resolve_condition_fact_conflicts_8616([carrier, bound])

    assert result.conditions == (bound,)
    assert result.raw_fact_count == 2
    assert result.normalized_fact_count == 1
    assert result.failure_count == 1


def test_condition_fact_arbitration_scores_composite_ir_operands_without_aborting() -> None:
    bound = replace(
        _condition(8, 4),
        lhs=IRBinaryValue("join", _stack_word(10), _stack_word(8), size=4),
        rhs=IRBinaryValue("join", _stack_word(6), _stack_word(4), size=4),
        width_bits=32,
    )
    carrier = replace(
        bound,
        rhs=IRBinaryValue(
            "join",
            IRValue(space=MemSpace.REG, name="dx", size=2),
            IRValue(space=MemSpace.REG, name="ax", size=2),
            size=4,
        ),
    )

    result = resolve_condition_fact_conflicts_8616([carrier, bound])

    assert result.conditions == (bound,)
    assert result.raw_fact_count == 2
    assert result.normalized_fact_count == 1
    assert result.failure_count == 1


def test_condition_fact_arbitration_keeps_uncontested_self_comparison() -> None:
    condition = _condition(8, 8)
    result = resolve_condition_fact_conflicts_8616([condition])

    assert result.conditions == (condition,)
    assert result.failure_count == 0
