"""Tests for typed Alias liveness across condition-only CFG edges."""

from dataclasses import dataclass

from inertia.ir.condition_ir import (
    ConditionIR,
    ConditionRegisterBindingIR,
)
from inertia.ir.condition_register_bindings import (
    snapshot_condition_register_bindings_8616,
)
from inertia.ir.core import IRValue, MemSpace

from inertia.alias.condition_register_liveness import (
    ConditionRegisterTopology8616,
    normalize_condition_register_liveness_8616,
)


@dataclass(frozen=True)
class _RegisterState:
    value: IRValue
    next_addr: int


def _condition(
    block_addr: int,
    *,
    producer_insn: int,
    src_insn: int,
    taken_target: int,
    fallthrough_target: int,
    lhs: IRValue,
    rhs: IRValue,
    semantics: tuple[object, ...],
) -> ConditionIR:
    return ConditionIR(
        op="sgt",
        lhs=lhs,
        rhs=rhs,
        source=("cmp", "jg"),
        src_insn=src_insn,
        block_addr=block_addr,
        producer_insn=producer_insn,
        taken_target=taken_target,
        fallthrough_target=fallthrough_target,
        producer_semantics=semantics,
    )


def test_register_identity_survives_complete_condition_only_chain() -> None:
    high_x = IRValue(MemSpace.SS, name="bp", offset=6, size=2)
    high_limit = IRValue(MemSpace.SS, name="bp", offset=14, size=2)
    high_upper = IRValue(MemSpace.SS, name="bp", offset=22, size=2)
    dx = IRValue(MemSpace.REG, name="dx", size=2)
    first = _condition(
        0x1000,
        producer_insn=0x1009,
        src_insn=0x100C,
        taken_target=0x1045,
        fallthrough_target=0x100E,
        lhs=high_limit,
        rhs=high_x,
        semantics=("cmp_mem_reg16", ("bp", 14, 14), "dx"),
    )
    shared_flags = _condition(
        0x100E,
        producer_insn=0x1009,
        src_insn=0x100E,
        taken_target=0x1015,
        fallthrough_target=0x1010,
        lhs=high_limit,
        rhs=high_x,
        semantics=("cmp_mem_reg16", ("bp", 14, 14), "dx"),
    )
    upper = _condition(
        0x1015,
        producer_insn=0x1015,
        src_insn=0x1018,
        taken_target=0x1045,
        fallthrough_target=0x101A,
        lhs=dx,
        rhs=high_upper,
        semantics=("cmp_reg_mem16", "dx", ("bp", 22, 22)),
    )
    topology = ConditionRegisterTopology8616(
        {
            0x1000: frozenset(),
            0x100E: frozenset({0x1000}),
            0x1015: frozenset({0x100E}),
        },
        frozenset({0x1000, 0x100E, 0x1015}),
    )

    result = normalize_condition_register_liveness_8616(
        (first, shared_flags, upper), topology
    )

    by_block = {condition.block_addr: condition for condition in result.conditions}
    assert by_block[0x1015].lhs == high_x
    assert result.stats.classified_fact_count == 1
    assert result.stats.materialized_count == 1
    assert result.stats.failure_count == 0


def test_condition_producer_snapshot_seeds_unused_register_for_low_word_cmp() -> None:
    low_x = IRValue(MemSpace.SS, name="bp", offset=4, size=2)
    high_x = IRValue(MemSpace.SS, name="bp", offset=6, size=2)
    low_limit = IRValue(MemSpace.SS, name="bp", offset=12, size=2)
    high_limit = IRValue(MemSpace.SS, name="bp", offset=14, size=2)
    ax = IRValue(MemSpace.REG, name="ax", size=2)
    first = ConditionIR(
        op="sgt",
        lhs=high_limit,
        rhs=high_x,
        source=("cmp", "jg"),
        src_insn=0x100C,
        block_addr=0x1000,
        producer_insn=0x1009,
        taken_target=0x1045,
        fallthrough_target=0x1010,
        producer_semantics=("cmp_mem_reg16", ("bp", 14, 14), "dx"),
        register_bindings=(
            ConditionRegisterBindingIR("ax", low_x),
            ConditionRegisterBindingIR("dx", high_x),
        ),
    )
    low = ConditionIR(
        op="ugt",
        lhs=low_limit,
        rhs=ax,
        source=("cmp", "ja"),
        src_insn=0x1013,
        block_addr=0x1010,
        producer_insn=0x1010,
        taken_target=0x1045,
        fallthrough_target=0x1015,
        producer_semantics=("cmp_mem_reg16", ("bp", 12, 12), "ax"),
    )
    topology = ConditionRegisterTopology8616(
        {0x1000: frozenset(), 0x1010: frozenset({0x1000})},
        frozenset({0x1010}),
    )

    result = normalize_condition_register_liveness_8616((first, low), topology)

    by_block = {condition.block_addr: condition for condition in result.conditions}
    assert by_block[0x1010].rhs == low_x
    assert result.stats.classified_fact_count == 1
    assert result.stats.materialized_count == 1
    assert result.stats.failure_count == 0


def test_register_binding_snapshot_is_valid_at_producer_and_deterministic() -> None:
    ax_value = IRValue(MemSpace.SS, name="bp", offset=4, size=2)
    dx_value = IRValue(MemSpace.SS, name="bp", offset=6, size=2)
    states = {
        (0x1000, "dx"): _RegisterState(dx_value, 0x1007),
        (0x1000, "ax"): _RegisterState(ax_value, 0x1004),
        (0x1000, "cx"): _RegisterState(ax_value, 0x1010),
        (0x2000, "bx"): _RegisterState(ax_value, 0x1001),
    }

    bindings = snapshot_condition_register_bindings_8616(states, 0x1000, 0x1009)

    assert bindings == (
        ConditionRegisterBindingIR("ax", ax_value),
        ConditionRegisterBindingIR("dx", dx_value),
    )


def test_register_identity_flows_from_logical_self_test_into_decrement_dispatch() -> None:
    argument = IRValue(MemSpace.SS, name="bp", offset=4, size=2)
    ax = IRValue(MemSpace.REG, name="ax", size=2)
    one = IRValue(MemSpace.CONST, const=1, size=2)
    root = ConditionIR(
        op="zero",
        lhs=argument,
        source=("test", "je"),
        src_insn=0x105E,
        block_addr=0x105C,
        producer_insn=0x105C,
        taken_target=0x1036,
        fallthrough_target=0x1060,
        producer_semantics=("or_reg_reg16", "ax", "ax"),
    )
    decremented = ConditionIR(
        op="eq",
        lhs=ax,
        rhs=one,
        source=("cmp", "je"),
        src_insn=0x1061,
        block_addr=0x1060,
        producer_insn=0x1060,
        taken_target=0x1010,
        fallthrough_target=0x1063,
        producer_semantics=("dec_reg16", "ax", 1),
    )
    topology = ConditionRegisterTopology8616(
        {0x105C: frozenset(), 0x1060: frozenset({0x105C})},
        frozenset({0x105C, 0x1060}),
    )

    result = normalize_condition_register_liveness_8616((root, decremented), topology)

    by_block = {condition.block_addr: condition for condition in result.conditions}
    assert by_block[0x1060].lhs == argument
    assert result.stats.classified_fact_count == 1
    assert result.stats.materialized_count == 1
    assert result.stats.failure_count == 0


def test_register_identity_refuses_incomplete_predecessor_join() -> None:
    high_x = IRValue(MemSpace.SS, name="bp", offset=6, size=2)
    high_limit = IRValue(MemSpace.SS, name="bp", offset=14, size=2)
    high_upper = IRValue(MemSpace.SS, name="bp", offset=22, size=2)
    dx = IRValue(MemSpace.REG, name="dx", size=2)
    first = _condition(
        0x1000,
        producer_insn=0x1009,
        src_insn=0x100C,
        taken_target=0x1015,
        fallthrough_target=0x100E,
        lhs=high_limit,
        rhs=high_x,
        semantics=("cmp_mem_reg16", ("bp", 14, 14), "dx"),
    )
    upper = _condition(
        0x1015,
        producer_insn=0x1015,
        src_insn=0x1018,
        taken_target=0x1045,
        fallthrough_target=0x101A,
        lhs=dx,
        rhs=high_upper,
        semantics=("cmp_reg_mem16", "dx", ("bp", 22, 22)),
    )
    topology = ConditionRegisterTopology8616(
        {
            0x1000: frozenset(),
            0x1015: frozenset({0x1000, 0x1008}),
        },
        frozenset({0x1000, 0x1015}),
    )

    result = normalize_condition_register_liveness_8616((first, upper), topology)

    by_block = {condition.block_addr: condition for condition in result.conditions}
    assert by_block[0x1015].lhs == dx
    assert result.stats.classified_fact_count == 0
    assert result.stats.materialized_count == 0


def test_register_identity_refuses_an_intervening_instruction_gap() -> None:
    high_x = IRValue(MemSpace.SS, name="bp", offset=6, size=2)
    high_limit = IRValue(MemSpace.SS, name="bp", offset=14, size=2)
    high_upper = IRValue(MemSpace.SS, name="bp", offset=22, size=2)
    dx = IRValue(MemSpace.REG, name="dx", size=2)
    first = _condition(
        0x1000,
        producer_insn=0x1009,
        src_insn=0x100C,
        taken_target=0x1015,
        fallthrough_target=0x100E,
        lhs=high_limit,
        rhs=high_x,
        semantics=("cmp_mem_reg16", ("bp", 14, 14), "dx"),
    )
    upper = _condition(
        0x1015,
        producer_insn=0x1017,
        src_insn=0x101A,
        taken_target=0x1045,
        fallthrough_target=0x101C,
        lhs=dx,
        rhs=high_upper,
        semantics=("cmp_reg_mem16", "dx", ("bp", 22, 22)),
    )
    topology = ConditionRegisterTopology8616(
        {0x1000: frozenset(), 0x1015: frozenset({0x1000})},
        frozenset({0x1000}),
    )

    result = normalize_condition_register_liveness_8616((first, upper), topology)

    by_block = {condition.block_addr: condition for condition in result.conditions}
    assert by_block[0x1015].lhs == dx
    assert result.stats.classified_fact_count == 0
    assert result.stats.materialized_count == 0
