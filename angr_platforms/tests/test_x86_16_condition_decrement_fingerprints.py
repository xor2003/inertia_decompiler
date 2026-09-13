"""Unit-decrement zero tests retain exact equality without ordered rewrites."""

import pytest
from angr_platforms.X86_16.ir.condition_ir import normalize_condition_fingerprint_algebraic_8616 as normalize


@pytest.mark.parametrize("operator", ["CmpEQ", "CmpNE"])
@pytest.mark.parametrize("prefix", ["", "if:"])
@pytest.mark.parametrize("swapped", [False, True])
def test_unit_decrement_zero_matches_one_comparison(operator, prefix, swapped):
    value = "Add(reg:ax,const:-27)"
    arguments = f"const:-1,{value}" if swapped else f"{value},const:-1"
    actual = normalize(f"{prefix}{operator}(Add({arguments}),const:0)")
    expected = normalize(f"{prefix}{operator}({value},const:1)")
    assert actual == expected
    assert normalize(actual) == actual


@pytest.mark.parametrize("operator", ["CmpLT", "CmpLE", "CmpGT", "CmpGE"])
def test_ordered_comparison_does_not_move_wrapping_decrement(operator):
    assert normalize(f"{operator}(Add(reg:ax,const:-1),const:0)") == f"{operator}(Sub(reg:ax,const:1),const:0)"


def test_increment_zero_does_not_guess_a_width_for_minus_one():
    value = "CmpEQ(Add(reg:ax,const:1),const:0)"
    assert normalize(value) == value
