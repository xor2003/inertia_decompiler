"""Target-directed comparison proof must precede any C materialization."""

import operator

import pytest
from angr_platforms.X86_16.structuring.wide_condition_ordering import (
    ORDERING_RELATIONS8616,
    prove_wide_ordering_operator_8616,
)

WORD_MODULUS = 1 << 16


@pytest.mark.parametrize("signed,prefix", [(True, "s"), (False, "u")])
@pytest.mark.parametrize("name,compare", [
    ("lt", operator.lt), ("le", operator.le),
    ("gt", operator.gt), ("ge", operator.ge),
    ("eq", operator.eq), ("ne", operator.ne),
])
def test_proves_every_ordering_and_checks_all_pairs(signed, prefix, name, compare):
    observed = []

    def evaluate(high, low):
        observed.append((high, low))
        return compare(high * WORD_MODULUS + low, 0)

    result = prove_wide_ordering_operator_8616(signed, evaluate)

    assert result == (name if name in {"eq", "ne"} else prefix + name)
    assert observed == [(high, low) for high in ORDERING_RELATIONS8616 for low in ORDERING_RELATIONS8616]


@pytest.mark.parametrize("unknown", [(high, low) for high in ORDERING_RELATIONS8616 for low in ORDERING_RELATIONS8616])
def test_any_unknown_cfg_outcome_refuses(unknown):
    def evaluate(high, low):
        return None if (high, low) == unknown else high * WORD_MODULUS + low > 0

    assert prove_wide_ordering_operator_8616(True, evaluate) is None


@pytest.mark.parametrize("signed", [True, False, None])
@pytest.mark.parametrize("evaluate", [lambda high, low: high > 0, lambda high, low: True, lambda high, low: False])
def test_incomplete_or_constant_comparison_is_not_a_wide_operator(signed, evaluate):
    assert prove_wide_ordering_operator_8616(signed, evaluate) is None


@pytest.mark.parametrize("name,compare", [("eq", operator.eq), ("ne", operator.ne)])
def test_unknown_signedness_only_allows_equality(name, compare):
    assert prove_wide_ordering_operator_8616(None, lambda high, low: compare(high * WORD_MODULUS + low, 0)) == name
    assert prove_wide_ordering_operator_8616(None, lambda high, low: high * WORD_MODULUS + low > 0) is None
