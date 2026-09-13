"""A typed wide return is usable only while both register definitions survive."""

from dataclasses import replace

import pytest
from angr_platforms.X86_16.lowering.call_output_stack_objects import lower_wide_call_return_condition_chain_8616
from test_x86_16_call_output_stack_objects import _wide_condition_fixture
from x86_16_condition_definition_fixtures import install_condition_definition_block


@pytest.mark.parametrize("intervening", [b"\x90", b"\xb8\x01\x00", b"\xba\x01\x00", b"\xb2\x01", b"\xe8\x00\x00"])
def test_wide_condition_requires_both_unclobbered_call_results(monkeypatch, intervening):
    codegen, expression, conditions, call, wide = _wide_condition_fixture()
    call_address = 0x1000
    call_size = 3
    boundary = call_address + call_size + len(intervening)
    install_condition_definition_block(
        monkeypatch, codegen.project, address=call_address,
        data=b"\xe8\x00\x00" + intervening + b"\x3d\x00\x00",
    )
    conditions = tuple(replace(condition, producer_insn=boundary) for condition in conditions)

    result = lower_wide_call_return_condition_chain_8616(codegen, expression, conditions)

    if intervening == b"\x90":
        assert result.consumed_call is call
        assert result.stats.materialized_count == 1
    else:
        assert result.expression is expression
        assert result.consumed_call is None
        assert result.stats.classified_fact_count == 0
        assert result.stats.materialized_count == 0
        assert result.stats.failure_count == 1
        assert wide.variable_type.signed is False


def test_wide_condition_refuses_missing_binary_inventory():
    codegen, expression, conditions, _call, _wide = _wide_condition_fixture()
    result = lower_wide_call_return_condition_chain_8616(codegen, expression, conditions)
    assert result.expression is expression
    assert result.consumed_call is None
    assert result.stats.materialized_count == 0


def test_later_low_word_clobber_cannot_reuse_high_word_proof(monkeypatch):
    codegen, expression, conditions, _call, _wide = _wide_condition_fixture()
    install_condition_definition_block(
        monkeypatch, codegen.project, address=0x1000,
        data=b"\xe8\x00\x00\x3b\x56\xfe\xb8\x01\x00\x3b\x46\xfc",
    )
    high, equality, low = conditions
    conditions = (
        replace(high, producer_insn=0x1003),
        replace(equality, producer_insn=0x1003),
        replace(low, producer_insn=0x1009),
    )
    result = lower_wide_call_return_condition_chain_8616(codegen, expression, conditions)
    assert result.expression is expression
    assert result.consumed_call is None
    assert result.stats.materialized_count == 0
