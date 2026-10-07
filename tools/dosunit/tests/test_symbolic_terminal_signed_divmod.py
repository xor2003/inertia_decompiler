"""Negative IDIV divisors must retain architectural effects before a fault."""

import pytest
from tools.dosunit.tests.test_symbolic_terminal import compare_pe

from tools.dosunit.compare.symbolic_terminal import TerminalComparisonStatus


@pytest.mark.parametrize("corrupt", [False, True], ids=["equivalent", "corrupt"])
def test_negative_divisor_prefix_before_matching_fault(corrupt: bool) -> None:
    """A later matching #DE cannot hide wrong quotient/remainder registers."""
    prefix = bytes.fromhex("b8faffffff baffffffff bbffffffff")
    terminal = bytes.fromhex("31c9f7f1")
    oracle = prefix + bytes.fromhex("f7fb") + b"\x90" * 5 + terminal
    replacement = "31c0 bafaffffff" if corrupt else "b806000000 31d2"
    candidate = prefix + bytes.fromhex(replacement) + terminal
    result = compare_pe(oracle, candidate)
    expected = (
        TerminalComparisonStatus.COUNTEREXAMPLE
        if corrupt else TerminalComparisonStatus.EQUIVALENT
    )
    assert result.status is expected, result
    if corrupt:
        assert {"eax", "edx"}.issubset(result.diverged)
