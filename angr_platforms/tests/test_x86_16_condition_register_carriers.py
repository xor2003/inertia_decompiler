"""Tests for typed alias propagation across decrement dispatch chains."""

from dataclasses import replace

import pytest
from angr_platforms.X86_16.alias.condition_register_carriers import (
    normalize_condition_register_carriers_8616,
)
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import IRValue, MemSpace
from angr_platforms.X86_16.lowering.condition_transfer import (
    _condition_matches_current_owner_8616,
    _ConditionBlockOwner8616,
)


def _root_condition(lhs: IRValue) -> ConditionIR:
    return ConditionIR(
        op="zero",
        lhs=lhs,
        source=("test", "je"),
        src_insn=0x1012,
        block_addr=0x1010,
        producer_insn=0x1010,
        taken_target=0x1100,
        fallthrough_target=0x1020,
    )


def _dec_condition(
    block_addr: int,
    *,
    fallthrough_target: int,
    register_name: str = "ax",
    op: str = "eq",
    taken_target: int | None = None,
) -> ConditionIR:
    return ConditionIR(
        op=op,
        lhs=IRValue(MemSpace.REG, name=register_name, size=2),
        rhs=IRValue(MemSpace.CONST, const=1, size=2),
        source=("cmp", "je" if op == "eq" else "jne"),
        src_insn=block_addr + 1,
        block_addr=block_addr,
        producer_insn=block_addr,
        taken_target=block_addr + 0x100 if taken_target is None else taken_target,
        fallthrough_target=fallthrough_target,
        producer_semantics=("dec_reg16", register_name, 1),
    )


@pytest.mark.parametrize("post_update", [False, True])
def test_decrement_dispatch_binds_cases_to_proven_stack_carrier(post_update: bool) -> None:
    argument = IRValue(MemSpace.SS, name="bp", offset=4, size=2)
    register = IRValue(MemSpace.REG, name="ax", size=2)
    first = _dec_condition(0x1020, fallthrough_target=0x1030)
    second = _dec_condition(0x1030, fallthrough_target=0x1040)
    if post_update:
        first = replace(first, op="zero", rhs=None, operand_bind_insn=first.src_insn, source=("test", "je"))
        second = replace(second, op="zero", rhs=None, operand_bind_insn=second.src_insn, source=("test", "je"))

    result = normalize_condition_register_carriers_8616(
        (_root_condition(argument), _root_condition(register), first, second)
    )

    by_source = {condition.src_insn: condition for condition in result.conditions}
    assert by_source[0x1021].lhs == argument
    assert by_source[0x1021].op == "eq"
    assert by_source[0x1021].operand_bind_insn is None
    assert by_source[0x1021].rhs == IRValue(MemSpace.CONST, const=1, size=2)
    assert by_source[0x1031].lhs == argument
    assert by_source[0x1031].rhs == IRValue(MemSpace.CONST, const=2, size=2)
    assert result.stats.raw_fact_count == 4
    assert result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == 2
    assert result.stats.materialized_count == 2
    assert result.stats.failure_count == 0


@pytest.mark.parametrize("mnemonic,op", [("je", "zero"), ("jne", "nonzero")])
def test_normalized_dispatch_retains_decoded_branch_ownership(mnemonic, op):
    """Historical TEST provenance cannot invalidate an Alias-normalized comparison."""
    argument = IRValue(MemSpace.SS, name="bp", offset=4, size=2)
    register = IRValue(MemSpace.REG, name="ax", size=2)
    candidate = replace(
        _dec_condition(0x1020, fallthrough_target=0x1023),
        op=op, rhs=None, operand_bind_insn=0x1021, source=("test", mnemonic),
    )
    result = normalize_condition_register_carriers_8616(
        (_root_condition(argument), _root_condition(register), candidate),
    )
    normalized = next(condition for condition in result.conditions if condition.src_insn == candidate.src_insn)
    owner = _ConditionBlockOwner8616(0x1020, 0x1021, mnemonic, candidate.taken_target, 0x1023)
    assert normalized.source == candidate.source
    assert normalized.op == ("eq" if op == "zero" else "ne")
    assert _condition_matches_current_owner_8616(normalized, owner)
    assert _condition_matches_current_owner_8616(candidate, owner)
    opposite = replace(normalized, op="ne" if normalized.op == "eq" else "eq")
    assert not _condition_matches_current_owner_8616(opposite, owner)
    assert not _condition_matches_current_owner_8616(replace(normalized, taken_target=0x9999), owner)


@pytest.mark.parametrize("binding", [None, 0x1020, 0x1022])
@pytest.mark.parametrize("op", ["zero", "nonzero"])
def test_result_test_refuses_missing_or_inexact_jcc_binding(binding, op) -> None:
    """A result comparison needs proof of the register's branch-time value."""
    argument = IRValue(MemSpace.SS, name="bp", offset=4, size=2)
    register = IRValue(MemSpace.REG, name="ax", size=2)
    candidate = replace(
        _dec_condition(0x1020, fallthrough_target=0x1030),
        op=op, rhs=None, operand_bind_insn=binding,
    )
    result = normalize_condition_register_carriers_8616(
        (_root_condition(argument), _root_condition(register), candidate)
    )
    assert candidate in result.conditions
    assert result.stats.classified_fact_count == 0
    assert result.stats.materialized_count == 0
    assert result.stats.failure_count == 1


def test_decrement_dispatch_follows_unique_taken_or_fallthrough_successor() -> None:
    """Accumulate a mixed JE/JNE dispatch chain on typed CFG successors."""
    argument = IRValue(MemSpace.DS, offset=0x7002, size=2)
    register = IRValue(MemSpace.REG, name="ax", size=2)
    first = _dec_condition(0x1020, fallthrough_target=0x1030)
    second = _dec_condition(
        0x1030,
        op="ne",
        taken_target=0x1040,
        fallthrough_target=0x1200,
    )
    third = _dec_condition(
        0x1040,
        op="ne",
        taken_target=0x1050,
        fallthrough_target=0x1210,
    )

    result = normalize_condition_register_carriers_8616(
        (_root_condition(argument), _root_condition(register), first, second, third)
    )

    by_source = {condition.src_insn: condition for condition in result.conditions}
    assert by_source[0x1021].rhs == IRValue(MemSpace.CONST, const=1, size=2)
    assert by_source[0x1031].rhs == IRValue(MemSpace.CONST, const=2, size=2)
    assert by_source[0x1041].rhs == IRValue(MemSpace.CONST, const=3, size=2)
    assert result.stats.classified_fact_count == 3
    assert result.stats.materialized_count == 3
    assert result.stats.failure_count == 0


def test_decrement_dispatch_seeds_from_typed_logical_self_test() -> None:
    """Use the producer contract when conflict resolution already chose storage."""
    selector = IRValue(MemSpace.DS, offset=0x7002, size=2)
    root = ConditionIR(
        op="zero",
        lhs=selector,
        source=("test", "je"),
        src_insn=0x1012,
        block_addr=0x1010,
        producer_insn=0x1010,
        taken_target=0x1100,
        fallthrough_target=0x1020,
        producer_semantics=("or_reg_reg16", "ax", "ax"),
    )
    first = _dec_condition(0x1020, fallthrough_target=0x1030)
    second = _dec_condition(
        0x1030,
        op="ne",
        taken_target=0x1040,
        fallthrough_target=0x1200,
    )
    third = _dec_condition(0x1040, fallthrough_target=0x1050)

    result = normalize_condition_register_carriers_8616((root, first, second, third))

    by_source = {condition.src_insn: condition for condition in result.conditions}
    assert by_source[0x1021].lhs == selector
    assert by_source[0x1021].rhs == IRValue(MemSpace.CONST, const=1, size=2)
    assert by_source[0x1031].rhs == IRValue(MemSpace.CONST, const=2, size=2)
    assert by_source[0x1041].rhs == IRValue(MemSpace.CONST, const=3, size=2)
    assert result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == 3
    assert result.stats.materialized_count == 3
    assert result.stats.failure_count == 0


@pytest.mark.parametrize("taken_continuation", [False, True])
def test_signed_decrement_chain_starts_on_either_proven_root_edge(taken_continuation):
    """JGE/JG must compare the original selector against accumulated decrements."""
    selector = IRValue(MemSpace.SS, name="bp", offset=4, size=2)
    root = replace(_root_condition(selector), producer_semantics=("or_reg_reg16", "ax", "ax"))
    if taken_continuation:
        root = replace(root, op="nonzero", source=("test", "jne"),
                       taken_target=0x1020, fallthrough_target=0x1100)
    first = replace(_dec_condition(0x1020, op="sge", taken_target=0x1030,
                                   fallthrough_target=0x1200), source=("cmp", "jge"))
    second = replace(_dec_condition(0x1030, op="sgt", taken_target=0x1040,
                                    fallthrough_target=0x1210), source=("cmp", "jg"))
    third = _dec_condition(0x1040, op="ne", taken_target=0x1220, fallthrough_target=0x1230)

    result = normalize_condition_register_carriers_8616((root, first, second, third))
    conditions = {condition.src_insn: condition for condition in result.conditions}
    for original, threshold in ((first, 1), (second, 2), (third, 3)):
        normalized = conditions[original.src_insn]
        assert normalized.lhs == selector
        assert normalized.rhs.const == threshold
        assert normalized.op == original.op
    assert result.stats.failure_count == 0


def test_root_refuses_two_compatible_decrement_successors():
    selector = IRValue(MemSpace.SS, name="bp", offset=4, size=2)
    root = replace(_root_condition(selector), taken_target=0x1030,
                   producer_semantics=("or_reg_reg16", "ax", "ax"))
    left = _dec_condition(0x1020, fallthrough_target=0x1200)
    right = _dec_condition(0x1030, fallthrough_target=0x1300)
    result = normalize_condition_register_carriers_8616((root, left, right))
    by_source = {condition.src_insn: condition for condition in result.conditions}
    assert by_source[left.src_insn] == left
    assert by_source[right.src_insn] == right
    assert result.stats.classified_fact_count == 0
    assert result.stats.failure_count > 0


def test_decrement_dispatch_refuses_two_compatible_successors() -> None:
    """Do not guess a chain continuation when both branch edges qualify."""
    argument = IRValue(MemSpace.SS, name="bp", offset=4, size=2)
    register = IRValue(MemSpace.REG, name="ax", size=2)
    first = _dec_condition(0x1020, fallthrough_target=0x1030, taken_target=0x1040)
    left = _dec_condition(0x1030, fallthrough_target=0x1050)
    right = _dec_condition(0x1040, fallthrough_target=0x1060)

    result = normalize_condition_register_carriers_8616(
        (_root_condition(argument), _root_condition(register), first, left, right)
    )

    by_source = {condition.src_insn: condition for condition in result.conditions}
    assert by_source[0x1021].lhs == argument
    assert by_source[0x1031] == left
    assert by_source[0x1041] == right
    assert result.stats.classified_fact_count == 1
    assert result.stats.materialized_count == 1
    assert result.stats.failure_count == 1


def test_decrement_dispatch_refuses_ambiguous_storage_identity() -> None:
    stack_argument = IRValue(MemSpace.SS, name="bp", offset=4, size=2)
    global_value = IRValue(MemSpace.DS, offset=0x2200, size=2)
    register = IRValue(MemSpace.REG, name="ax", size=2)
    branch = _dec_condition(0x1020, fallthrough_target=0x1030)

    result = normalize_condition_register_carriers_8616(
        (
            _root_condition(stack_argument),
            _root_condition(global_value),
            _root_condition(register),
            branch,
        )
    )

    by_source = {condition.src_insn: condition for condition in result.conditions}
    assert by_source[0x1021] == branch
    assert result.stats.normalized_fact_count == 0
    assert result.stats.classified_fact_count == 0
    assert result.stats.materialized_count == 0
    assert result.stats.failure_count == 1


def test_decrement_dispatch_refuses_a_different_register() -> None:
    argument = IRValue(MemSpace.SS, name="bp", offset=4, size=2)
    register = IRValue(MemSpace.REG, name="ax", size=2)
    branch = _dec_condition(
        0x1020,
        fallthrough_target=0x1030,
        register_name="bx",
    )

    result = normalize_condition_register_carriers_8616(
        (_root_condition(argument), _root_condition(register), branch)
    )

    by_source = {condition.src_insn: condition for condition in result.conditions}
    assert by_source[0x1021] == branch
    assert result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == 0
    assert result.stats.materialized_count == 0
    assert result.stats.failure_count == 1
