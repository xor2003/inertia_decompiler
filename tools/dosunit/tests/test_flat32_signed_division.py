"""Native IDIV admission requires both zero and signed-quotient range proofs."""

import pytest

from tools.dosunit.compare.flat32_call_composition import compare_functions_with_calls
from tools.dosunit.tests.test_flat32_comparator_lane import BASE, DriverLane, _project
from tools.dosunit.tests.test_flat32_comparator_lane import lane as lane

pytestmark = pytest.mark.ssa_z3


def _code(width: int, dividend: int, divisor: int) -> str:
    mask = (1 << width) - 1
    if width == 8:
        return "66b8" + (dividend & 0xffff).to_bytes(2, "little").hex() + "b1" + bytes([divisor & mask]).hex() + "f6f9c3"
    prefix = "66" if width == 16 else ""
    def imm(value: int) -> str:
        return (value & mask).to_bytes(width // 8, "little").hex()
    return prefix + "b8" + imm(dividend) + prefix + "ba" + imm(dividend >> width) + prefix + "b9" + imm(divisor) + prefix + "f7f9c3"


def _compare(lane: DriverLane, left: str, right: str):
    with lane.adapter.installed(region=True):
        return compare_functions_with_calls(
            _project(left, BASE), _project(right, BASE), oracle_entry=BASE, candidate_entry=BASE,
            oracle_functions={BASE: len(bytes.fromhex(left))}, candidate_functions={BASE: len(bytes.fromhex(right))},
            outputs=lane.adapter.GPRS, timeout_ms=10000,
        )


@pytest.mark.parametrize("width", [8, 16, 32])
@pytest.mark.parametrize("case", ["positive", "negative", "minimum", "maximum", "positive_overflow", "negative_overflow", "zero",
                                 "positive_remainder", "negative_remainder", "negative_remainder_overflow",
                                 "negative_divisor", "double_minimum_overflow"])
def test_signed_division_fault_boundaries(lane: DriverLane, width: int, case: str) -> None:
    limit = 1 << (width - 1)
    dividend, divisor, safe = {
        "positive": (7, 3, True), "negative": (-7, 3, True),
        "minimum": (-limit, 1, True), "maximum": (limit - 1, 1, True),
        "positive_overflow": (-limit, -1, False),
        "negative_overflow": (-limit - 1, 1, False), "zero": (1, 0, False),
        "positive_remainder": (limit * 3 - 1, 3, True),
        "negative_remainder": (-limit * 3 - 2, 3, True),
        "negative_remainder_overflow": (-limit * 3 - 3, 3, False),
        "negative_divisor": (limit * 3 + 2, -3, True),
        "double_minimum_overflow": (-(1 << (2 * width - 1)), -1, False),
    }[case]
    code = _code(width, dividend, divisor)
    result = _compare(lane, code, code)
    assert result["status"] == ("passed" if safe else "refused"), result
    if safe:
        assert result["unreachable_exception_proofs"]["oracle"], result


@pytest.mark.parametrize("mutation", ["quotient", "memory"])
def test_signed_division_keeps_real_differences(lane: DriverLane, mutation: str) -> None:
    left = _code(32, -7, 3)
    right = _code(32, -7, 2) if mutation == "quotient" else "c70601000000" + left
    assert _compare(lane, left, right)["status"] == "failed"


@pytest.mark.parametrize("extend", [True, False])
def test_symbolic_signed_dividend_needs_correct_high_half(lane: DriverLane, extend: bool) -> None:
    code = ("99" if extend else "") + "b902000000f7f9c3"
    result = _compare(lane, code, code)
    assert result["status"] == ("passed" if extend else "refused"), result
